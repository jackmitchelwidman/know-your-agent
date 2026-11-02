package traceable
import cats.effect.Async
import cats.implicits._
import org.http4s._
import org.http4s.client.Client
import org.typelevel.ci.CIString
import scala.collection.mutable.ArrayBuffer

/**
 * OpenTimestamps for the Sheaf ledger.
 *
 * A ledger head (the newest row_hash) is submitted as a raw 32-byte digest to public OTS calendars.
 * Each calendar folds it into a Merkle tree whose root it commits to Bitcoin within a few hours.
 * What comes back is the standard detached proof file (`.ots`) that the public `ots` client reads,
 * so a customer verifies the anchor against Bitcoin with Sheaf nowhere in the loop:
 *
 *   ots info anchor.ots                   the digest it commits, and the Bitcoin block once confirmed
 *   ots verify -d <row_hash> anchor.ots   checks the proof against a Bitcoin node
 *
 * The wire format is the one python-opentimestamps defines. Only the parts the calendar→Bitcoin path
 * uses are here: varuint/varbytes, the append/prepend/sha256 ops, pending and Bitcoin attestations,
 * and the tree serialisation order (attestations then ops, each sorted) so a proof we upgrade matches
 * what `ots upgrade` writes.
 */
object Ots {
  // b'\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94'
  val HeaderMagic: Array[Byte] = hex("004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294")
  val PendingTag: Array[Byte]  = hex("83dfe30d2ef90c8e")
  val BitcoinTag: Array[Byte]  = hex("0588960d73d71901")
  val Version: Long = 1L

  def hex(s: String): Array[Byte] = s.grouped(2).map(Integer.parseInt(_, 16).toByte).toArray
  def toHex(b: Array[Byte]): String = b.map("%02x".format(_)).mkString
  private def digest(alg: String, b: Array[Byte]): Array[Byte] = java.security.MessageDigest.getInstance(alg).digest(b)
  private def same(a: Array[Byte], b: Array[Byte]): Boolean = java.util.Arrays.equals(a, b)
  /** Unsigned lexicographic compare, the way Python compares `bytes`. */
  private def cmpBytes(a: Array[Byte], b: Array[Byte]): Int = {
    val n = math.min(a.length, b.length)
    var i = 0
    while (i < n) { val d = (a(i) & 0xff) - (b(i) & 0xff); if (d != 0) return d; i += 1 }
    a.length - b.length
  }

  sealed trait Attestation { def tag: Array[Byte]; def payload: Array[Byte] }
  final case class Pending(uri: String) extends Attestation {
    val tag: Array[Byte] = PendingTag
    def payload: Array[Byte] = { val w = new Writer; w.varbytes(uri.getBytes("UTF-8")); w.result }
  }
  final case class Bitcoin(height: Long) extends Attestation {
    val tag: Array[Byte] = BitcoinTag
    def payload: Array[Byte] = { val w = new Writer; w.varuint(height); w.result }
  }
  final case class Unknown(tag: Array[Byte], payload: Array[Byte]) extends Attestation

  private def sameAttestation(a: Attestation, b: Attestation): Boolean = same(a.tag, b.tag) && same(a.payload, b.payload)
  // python: different classes order by TAG bytes; Pending by uri, Bitcoin by height, Unknown by payload.
  private def attestationLt(a: Attestation, b: Attestation): Boolean = (a, b) match {
    case (Pending(x), Pending(y)) => x < y
    case (Bitcoin(x), Bitcoin(y)) => x < y
    case (Unknown(_, x), Unknown(_, y)) => cmpBytes(x, y) < 0
    case _ => cmpBytes(a.tag, b.tag) < 0
  }

  /** One operation. `arg` is empty for unary ops. */
  final case class Op(tag: Int, arg: Array[Byte]) {
    def isBinary: Boolean = tag == 0xf0 || tag == 0xf1
    /** Evaluate on a message; None for hash ops the JDK lacks (they never occur on a calendar→Bitcoin path). */
    def apply(msg: Array[Byte]): Option[Array[Byte]] = tag match {
      case 0x02 => Some(digest("SHA-1", msg))
      case 0x08 => Some(digest("SHA-256", msg))
      case 0xf0 => Some(msg ++ arg)
      case 0xf1 => Some(arg ++ msg)
      case 0xf2 => Some(msg.reverse)
      case 0xf3 => Some(toHex(msg).getBytes("US-ASCII"))
      case _    => None  // 0x03 ripemd160, 0x67 keccak256
    }
    def sameAs(o: Op): Boolean = tag == o.tag && same(arg, o.arg)
  }
  private def opLt(a: Op, b: Op): Boolean = if (a.tag != b.tag) a.tag < b.tag else cmpBytes(a.arg, b.arg) < 0

  /** A node of the proof tree. `msg` is the value committed at this node, known when every op above it evaluates. */
  final class Timestamp(val msg: Option[Array[Byte]]) {
    val attestations: ArrayBuffer[Attestation] = ArrayBuffer.empty
    val ops: ArrayBuffer[(Op, Timestamp)] = ArrayBuffer.empty

    def allAttestations: List[Attestation] = attestations.toList ++ ops.toList.flatMap(_._2.allAttestations)
    /** Pending attestations whose commitment we can compute: (commitment, node, attestation). */
    def pending: List[(Array[Byte], Timestamp, Pending)] =
      attestations.toList.collect { case p: Pending if msg.isDefined => (msg.get, this, p) } ++ ops.toList.flatMap(_._2.pending)
    def bitcoinHeights: List[Long] = allAttestations.collect { case Bitcoin(h) => h }
    def pendingUris: List[String] = allAttestations.collect { case Pending(u) => u }

    /** Fold another tree rooted at the same message into this one. True if anything was added. */
    def merge(other: Timestamp): Boolean = {
      var changed = false
      other.attestations.foreach { a => if (!attestations.exists(sameAttestation(_, a))) { attestations += a; changed = true } }
      other.ops.foreach { case (op, child) =>
        ops.find(_._1.sameAs(op)) match {
          case Some((_, mine)) => if (mine.merge(child)) changed = true
          case None            => ops += ((op, child)); changed = true
        }
      }
      changed
    }
  }

  final class Reader(val b: Array[Byte]) {
    var pos = 0
    private def need(n: Int): Unit = if (pos + n > b.length) throw new IllegalArgumentException("truncated proof")
    def byte(): Int = { need(1); val v = b(pos) & 0xff; pos += 1; v }
    def bytes(n: Int): Array[Byte] = { need(n); val r = java.util.Arrays.copyOfRange(b, pos, pos + n); pos += n; r }
    def varuint(): Long = {
      var v = 0L; var shift = 0; var more = true
      while (more) { val x = byte(); v |= (x & 0x7f).toLong << shift; more = (x & 0x80) != 0; shift += 7; if (shift > 63) throw new IllegalArgumentException("varuint too long") }
      v
    }
    def varbytes(max: Int = 1 << 20): Array[Byte] = { val n = varuint(); if (n > max) throw new IllegalArgumentException("varbytes too long"); bytes(n.toInt) }
    def expect(a: Array[Byte], what: String): Unit = if (!same(bytes(a.length), a)) throw new IllegalArgumentException(s"bad $what")
  }

  final class Writer {
    private val out = new java.io.ByteArrayOutputStream()
    def byte(i: Int): Unit = out.write(i)
    def bytes(a: Array[Byte]): Unit = out.write(a)
    def varuint(v: Long): Unit = { var x = v; while ((x & ~0x7fL) != 0) { byte(((x & 0x7f) | 0x80).toInt); x >>>= 7 }; byte(x.toInt) }
    def varbytes(a: Array[Byte]): Unit = { varuint(a.length.toLong); bytes(a) }
    def result: Array[Byte] = out.toByteArray
  }

  def readAttestation(r: Reader): Attestation = {
    val tag = r.bytes(8); val payload = r.varbytes(8192)
    if (same(tag, PendingTag)) Pending(new String(new Reader(payload).varbytes(4096), "UTF-8"))
    else if (same(tag, BitcoinTag)) Bitcoin(new Reader(payload).varuint())
    else Unknown(tag, payload)
  }
  def readOp(r: Reader, tag: Int): Op = tag match {
    case 0xf0 | 0xf1                                  => Op(tag, r.varbytes(4096))
    case 0x02 | 0x03 | 0x08 | 0x67 | 0xf2 | 0xf3      => Op(tag, Array.empty)
    case t => throw new IllegalArgumentException(f"unknown op tag 0x$t%02x")
  }
  def readTimestamp(r: Reader, msg: Option[Array[Byte]]): Timestamp = {
    val ts = new Timestamp(msg)
    def one(tag: Int): Unit =
      if (tag == 0x00) ts.attestations += readAttestation(r)
      else { val op = readOp(r, tag); ts.ops += ((op, readTimestamp(r, msg.flatMap(op.apply)))) }
    var tag = r.byte()
    while (tag == 0xff) { one(r.byte()); tag = r.byte() }
    one(tag)
    ts
  }

  def writeAttestation(w: Writer, a: Attestation): Unit = { w.bytes(a.tag); w.varbytes(a.payload) }
  def writeOp(w: Writer, op: Op): Unit = { w.byte(op.tag); if (op.isBinary) w.varbytes(op.arg) }
  def writeTimestamp(w: Writer, ts: Timestamp): Unit = {
    val atts = ts.attestations.toList.sortWith(attestationLt)
    val ops  = ts.ops.toList.sortWith((x, y) => opLt(x._1, y._1))
    if (atts.isEmpty && ops.isEmpty) throw new IllegalArgumentException("empty timestamp")
    if (atts.size > 1) atts.dropRight(1).foreach { a => w.byte(0xff); w.byte(0x00); writeAttestation(w, a) }
    if (ops.isEmpty) { w.byte(0x00); writeAttestation(w, atts.last) }
    else {
      if (atts.nonEmpty) { w.byte(0xff); w.byte(0x00); writeAttestation(w, atts.last) }
      ops.dropRight(1).foreach { case (op, c) => w.byte(0xff); writeOp(w, op); writeTimestamp(w, c) }
      val (lo, lc) = ops.last; writeOp(w, lo); writeTimestamp(w, lc)
    }
  }

  /** A detached proof file: the digest it is about, and the tree that commits it. */
  final case class Proof(digest: Array[Byte], ts: Timestamp) {
    def bitcoinHeights: List[Long] = ts.bitcoinHeights
    def pendingUris: List[String] = ts.pendingUris
  }
  def parseFile(b: Array[Byte]): Proof = {
    val r = new Reader(b)
    r.expect(HeaderMagic, "header")
    val v = r.varuint(); if (v != Version) throw new IllegalArgumentException(s"unsupported proof version $v")
    val hashTag = r.byte(); if (hashTag != 0x08) throw new IllegalArgumentException("only sha256 proofs are supported")
    val digest = r.bytes(32)
    Proof(digest, readTimestamp(r, Some(digest)))
  }
  /** The file for a fresh calendar response: header + digest, then the calendar's bytes verbatim. */
  def buildFile(digest: Array[Byte], calendarBytes: Array[Byte]): Array[Byte] = {
    val w = new Writer; w.bytes(HeaderMagic); w.varuint(Version); w.byte(0x08); w.bytes(digest); w.bytes(calendarBytes); w.result
  }
  def writeFile(p: Proof): Array[Byte] = {
    val w = new Writer; w.bytes(HeaderMagic); w.varuint(Version); w.byte(0x08); w.bytes(p.digest); writeTimestamp(w, p.ts); w.result
  }
}

/** HTTP side: submit a digest, and later ask the calendars for the Bitcoin path. */
class OtsClient[F[_]: Async](http: Client[F], val calendars: List[String]) {
  import Ots._
  private val accept = Header.Raw(CIString("Accept"), "application/vnd.opentimestamps.v1")
  private val ua     = Header.Raw(CIString("User-Agent"), "sheaf-ledger-anchor/1.0")
  private def noSlash(u: String) = u.stripSuffix("/")

  /** POST the raw digest to the first calendar that accepts it. Returns (calendar, detached proof file). */
  def stamp(digest: Array[Byte]): F[Either[String, (String, Array[Byte])]] = {
    if (digest.length != 32) return Async[F].pure(Left("digest must be 32 bytes"))
    def one(cal: String): F[Either[String, (String, Array[Byte])]] =
      Uri.fromString(s"${noSlash(cal)}/digest").leftMap(e => new IllegalArgumentException(e.message)).liftTo[F].flatMap { uri =>
        http.run(Request[F](Method.POST, uri, headers = Headers(accept, ua)).withEntity(digest)).use { resp =>
          resp.body.compile.to(Array).map { body =>
            if (!resp.status.isSuccess) Left(s"$cal returned HTTP ${resp.status.code}")
            else scala.util.Try(readTimestamp(new Reader(body), Some(digest))).toEither
              .leftMap(e => s"$cal: unreadable proof: ${e.getMessage}")
              .flatMap { ts => if (ts.pending.isEmpty) Left(s"$cal: proof carries no pending attestation") else Right((cal, buildFile(digest, body))) }
          }
        }
      }.attempt.map(_.leftMap(e => s"$cal: ${e.getMessage}").flatten)
    calendars.foldLeftM[F, Either[String, (String, Array[Byte])]](Left("no calendars configured")) {
      case (ok @ Right(_), _) => Async[F].pure(ok)
      case (Left(prev), cal)  => one(cal).map(_.leftMap(e => if (prev == "no calendars configured") e else s"$prev; $e"))
    }
  }

  /** Ask each pending calendar for the rest of the path. Right(Some(file, heights)) when the proof grew. */
  def upgrade(file: Array[Byte]): F[Either[String, Option[(Array[Byte], List[Long])]]] =
    Async[F].delay(parseFile(file)).attempt.flatMap {
      case Left(e) => Async[F].pure(Left(s"unreadable proof: ${e.getMessage}"))
      case Right(proof) =>
        val pend = proof.ts.pending
        if (pend.isEmpty) Async[F].pure(Right(None))
        else pend.traverse { case (commitment, node, Pending(uri)) => fetch(uri, commitment).map(r => (node, r)) }.map { rs =>
          var changed = false
          rs.foreach { case (node, Right(Some(sub))) => if (node.merge(sub)) changed = true; case _ => () }
          val errs = rs.collect { case (_, Left(e)) => e }
          if (changed) Right(Some((writeFile(proof), proof.ts.bitcoinHeights)))
          else if (errs.nonEmpty && errs.size == rs.size) Left(errs.mkString("; "))
          else Right(None)
        }
    }

  private def fetch(cal: String, commitment: Array[Byte]): F[Either[String, Option[Timestamp]]] =
    Uri.fromString(s"${noSlash(cal)}/timestamp/${toHex(commitment)}").leftMap(e => new IllegalArgumentException(e.message)).liftTo[F].flatMap { uri =>
      http.run(Request[F](Method.GET, uri, headers = Headers(accept, ua))).use { resp =>
        resp.body.compile.to(Array).map { body =>
          if (resp.status.code == 404) Right(None)                    // not in Bitcoin yet
          else if (!resp.status.isSuccess) Left(s"$cal returned HTTP ${resp.status.code}")
          else scala.util.Try(readTimestamp(new Reader(body), Some(commitment))).toEither.leftMap(e => s"$cal: unreadable upgrade: ${e.getMessage}").map(Some(_))
        }
      }
    }.attempt.map(_.leftMap(e => s"$cal: ${e.getMessage}").flatten)
}

object OtsClient {
  val DefaultCalendars: List[String] = List(
    "https://a.pool.opentimestamps.org",
    "https://b.pool.opentimestamps.org",
    "https://finney.calendar.eternitywall.com")
  def apply[F[_]: Async](http: Client[F]): OtsClient[F] = {
    val cals = sys.env.get("OTS_CALENDARS").map(_.split(",").map(_.trim).filter(_.nonEmpty).toList).filter(_.nonEmpty).getOrElse(DefaultCalendars)
    new OtsClient[F](http, cals)
  }
}
