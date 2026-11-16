package traceable
import io.circe.{Json, Printer}
import org.bouncycastle.crypto.params.{Ed25519PrivateKeyParameters, Ed25519PublicKeyParameters}
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.security.SecureRandom

/**
 * Traceable Agents (know-your-agent.org): the keys and identifiers behind every agent's ID.
 *
 *   owner     a customer's root key. Every agent ID ends at one. The owner signs each agent's
 *             descriptor, which is what makes the agent "identified" rather than a key anyone
 *             could have minted.
 *   agent     a key pair per agent. The agent never holds its private key: Sheaf signs on its
 *             behalf, so a copy of the agent cannot take its record with it.
 *   receipt   one per ledger row the agent caused, hash-chained per agent and signed by the agent
 *             key. The receipt carries hashes and verdicts only. What the agent did stays with the owner.
 *
 * The ID is the public key, written as a W3C did:key (multicodec 0xed01 + 32 key bytes, base58btc,
 * multibase 'z'). Any verifier can check a signature from the ID alone. A 16-hex fingerprint of
 * the key is the short form people read and paste.
 */
object TraceableAgents {

  val canonical: Printer = Printer(dropNullValues = false, indent = "", sortKeys = true)
  def canonicalBytes(j: Json): Array[Byte] = canonical.print(j).getBytes("UTF-8")
  def sha256(b: Array[Byte]): Array[Byte] = java.security.MessageDigest.getInstance("SHA-256").digest(b)
  def hex(b: Array[Byte]): String = b.map("%02x".format(_)).mkString
  def b64(b: Array[Byte]): String = java.util.Base64.getEncoder.encodeToString(b)
  def unb64(s: String): Array[Byte] = java.util.Base64.getDecoder.decode(s)

  final case class KeyPair(publicKey: Array[Byte], privateKey: Array[Byte])

  def generate(): KeyPair = {
    val priv = new Ed25519PrivateKeyParameters(new SecureRandom())
    KeyPair(priv.generatePublicKey().getEncoded, priv.getEncoded)
  }

  def sign(privateKey: Array[Byte], message: Array[Byte]): Array[Byte] = {
    val s = new Ed25519Signer()
    s.init(true, new Ed25519PrivateKeyParameters(privateKey, 0))
    s.update(message, 0, message.length)
    s.generateSignature()
  }

  def verify(publicKey: Array[Byte], message: Array[Byte], signature: Array[Byte]): Boolean =
    scala.util.Try {
      val v = new Ed25519Signer()
      v.init(false, new Ed25519PublicKeyParameters(publicKey, 0))
      v.update(message, 0, message.length)
      v.verifySignature(signature)
    }.getOrElse(false)

  /** did:key for an Ed25519 public key. */
  def didKey(publicKey: Array[Byte]): String =
    "did:key:z" + Base58.encode(Array(0xed.toByte, 0x01.toByte) ++ publicKey)

  /** The public key inside a did:key, if it is an Ed25519 one. */
  def publicKeyOf(did: String): Option[Array[Byte]] =
    if (!did.startsWith("did:key:z")) None
    else Base58.decode(did.stripPrefix("did:key:z")).filter(b => b.length == 34 && b(0) == 0xed.toByte && b(1) == 0x01.toByte).map(_.drop(2))

  /** Short form for people: the first 16 hex characters of sha256(public key). */
  def fingerprint(publicKey: Array[Byte]): String = hex(sha256(publicKey)).take(16)

  /** The Record Score: one number from the Record of Action, recomputable by anyone from the receipts.
    * None until the agent has acted. The formula is published on the format page; change both together. */
  val ScoreFormula = "100, less 30 x (held / actions), less 50 x (rejected / actions), less 10 if rejected in the last 90 days, less 10 if fewer than 20 actions; kept between 0 and 100; no score before the first action"
  def recordScore(actions: Long, held: Long, rejected: Long, rejected90: Long): Option[Int] =
    if (actions <= 0) None
    else {
      val raw = 100.0 - 30.0 * held / actions - 50.0 * rejected / actions - (if (rejected90 > 0) 10 else 0) - (if (actions < 20) 10 else 0)
      Some(math.round(raw).toInt.max(0).min(100))
    }
  def scoreWords(s: Option[Int]): String = s match {
    case None => "no score yet: the agent has not acted"
    case Some(x) if x >= 90 => "a clean record"
    case Some(x) if x >= 75 => "a sound record with some holds"
    case Some(x) if x >= 50 => "a record with holds or rejections worth reading"
    case Some(_) => "a record with serious rejections"
  }

  /** The field a request or proof carries the challenge in. "challenge" is the word; "nonce" (the older
    * name for the same thing) is still read, so proofs and clients made before Oct 19 2026 keep working. */
  val ChallengeField = "challenge"
  val LegacyChallengeField = "nonce"
  def challengeOf(c: io.circe.ACursor): Option[String] =
    c.get[String](ChallengeField).toOption.orElse(c.get[String](LegacyChallengeField).toOption).map(_.trim).filter(_.nonEmpty)

  /** What an agent signs to prove it holds its key: the counterparty's challenge (a fresh random value),
    * who asked, and when. Signed by Sheaf with the agent's key, which never leaves Sheaf. */
  def proofDoc(agentDid: String, challenge: String, audience: Option[String], at: String, field: String = ChallengeField): Json =
    Json.obj("v" -> Json.fromInt(1), "type" -> Json.fromString("traceable-proof"), "id" -> Json.fromString(agentDid),
      field -> Json.fromString(challenge), "audience" -> audience.fold(Json.Null)(Json.fromString), "at" -> Json.fromString(at))

  /** Check a proof a counterparty presented. Right(did) when the signature is the key's, the challenge is the
    * one we issued (when we issued one), and it is fresh. The reasons are plain words for the agent. */
  def checkProof(proof: Json, expectedChallenge: Option[String], nowMillis: Long = System.currentTimeMillis(), maxAgeSeconds: Long = 600,
                 expectedAudience: Option[String] = None): Either[String, String] = {
    val c = proof.hcursor
    val field = if (c.downField(ChallengeField).succeeded) ChallengeField else LegacyChallengeField
    for {
      _     <- if (c.get[String]("type").toOption.contains("request-proof")) Left("this is a request proof, which answers no challenge") else Right(())
      did   <- c.get[String]("id").left.map(_ => "the proof names no id")
      chal  <- c.get[String](field).left.map(_ => "the proof has no challenge")
      at    <- c.get[String]("at").left.map(_ => "the proof has no time")
      sig   <- c.get[String]("signature").left.map(_ => "the proof has no signature")
      aud    = c.get[Option[String]]("audience").toOption.flatten
      pk    <- publicKeyOf(did).toRight("the id is not a did:key this register understands")
      _     <- expectedChallenge.filter(_ != chal).fold[Either[String, Unit]](Right(()))(_ => Left("the challenge is not the one you issued"))
      _     <- audienceMatches(expectedAudience, aud)
      atMs  <- scala.util.Try(java.time.Instant.parse(at).toEpochMilli).toEither.left.map(_ => "the time is not readable")
      _     <- if (math.abs(nowMillis - atMs) > maxAgeSeconds * 1000) Left("the proof is stale") else Right(())
      ok     = scala.util.Try(verify(pk, canonicalBytes(proofDoc(did, chal, aud, at, field)), unb64(sig))).getOrElse(false)
      _     <- if (ok) Right(()) else Left("the signature does not match the id")
    } yield did
  }

  /** When the checker says who the proof must be for, the proof has to name exactly that. A proof that
    * names nobody, or somebody else, is refused: it could have been made for another checker and replayed here. */
  private def audienceMatches(expected: Option[String], named: Option[String]): Either[String, Unit] = expected match {
    case None => Right(())
    case Some(e) => named match {
      case Some(n) if n == e => Right(())
      case Some(_) => Left("the proof was made for someone else")
      case None => Left("the proof does not say who it is for")
    }
  }

  /** A request proof: what an agent sends with an ordinary web request, in the KYA-Proof header, to show
    * who it is. Nobody challenged it, so it carries its own random value, the exact address it is calling,
    * and the time. It has its own signed type, so a challenge answer ("traceable-proof") can never be passed
    * off as one, whatever audience it names. */
  val RequestProofType = "request-proof"
  val RequestProofHeader = "KYA-Proof"
  val RequestProofMaxAgeSeconds = 60L
  /** How far ahead of the checker's clock a proof's time may be. */
  val RequestProofAheadSeconds = 10L

  def requestProofDoc(agentDid: String, audience: String, nonce: String, at: String): Json =
    Json.obj("v" -> Json.fromInt(1), "type" -> Json.fromString(RequestProofType), "id" -> Json.fromString(agentDid),
      "audience" -> Json.fromString(audience), "nonce" -> Json.fromString(nonce), "at" -> Json.fromString(at))

  /** The one written form of an address a request proof is bound to: scheme, host and path. The scheme and
    * host are lower case, a default port (80 for http, 443 for https) is dropped, an empty path is "/", and
    * the query and fragment are left out. The path is kept exactly as sent. */
  def canonicalAudience(url: String): Option[String] =
    scala.util.Try(new java.net.URI(url.trim)).toOption.flatMap { u =>
      for {
        scheme <- Option(u.getScheme).map(_.toLowerCase).filter(s => s == "http" || s == "https")
        host   <- Option(u.getHost).map(_.toLowerCase).filter(_.nonEmpty)
      } yield {
        val port = u.getPort
        val dflt = if (scheme == "https") 443 else 80
        val portPart = if (port == -1 || port == dflt) "" else s":$port"
        val path = Option(u.getRawPath).filter(_.nonEmpty).getOrElse("/")
        s"$scheme://$host$portPart$path"
      }
    }

  /** The header value is the signed proof as JSON, base64url without padding. */
  def decodeRequestProofHeader(value: String): Either[String, Json] =
    scala.util.Try(new String(java.util.Base64.getUrlDecoder.decode(value.trim), "UTF-8")).toEither.left.map(_ => "the header is not base64url")
      .flatMap(t => io.circe.parser.parse(t).left.map(_ => "the header does not hold JSON")).filterOrElse(_.isObject, "the header does not hold a proof")

  /** Check a request proof. `expectedAudience` is the checker's own address for this request, built from its
    * own configuration (never from the request's Host header), in the canonical form. Right(did) when the
    * signature is the key's, the proof is for exactly that address, and it is fresh. A checker that wants a
    * proof to work once keeps the signatures it has seen for the proof's lifetime. */
  def checkRequestProof(proof: Json, expectedAudience: String, nowMillis: Long = System.currentTimeMillis(),
                        maxAgeSeconds: Long = RequestProofMaxAgeSeconds, aheadSeconds: Long = RequestProofAheadSeconds): Either[String, String] = {
    val c = proof.hcursor
    for {
      _     <- c.get[String]("type").toOption.filter(_ == RequestProofType).toRight("this is not a request proof")
      did   <- c.get[String]("id").left.map(_ => "the proof names no id")
      aud   <- c.get[String]("audience").left.map(_ => "the proof does not say who it is for")
      nonce <- c.get[String]("nonce").left.map(_ => "the proof has no random value")
      at    <- c.get[String]("at").left.map(_ => "the proof has no time")
      sig   <- c.get[String]("signature").left.map(_ => "the proof has no signature")
      pk    <- publicKeyOf(did).toRight("the id is not a did:key this register understands")
      _     <- if (aud == expectedAudience) Right(()) else Left("the proof was made for another address")
      atMs  <- scala.util.Try(java.time.Instant.parse(at).toEpochMilli).toEither.left.map(_ => "the time is not readable")
      _     <- if (nowMillis - atMs > maxAgeSeconds * 1000) Left("the proof is stale") else Right(())
      _     <- if (atMs - nowMillis > aheadSeconds * 1000) Left("the proof is dated in the future") else Right(())
      ok     = scala.util.Try(verify(pk, canonicalBytes(requestProofDoc(did, aud, nonce, at)), unb64(sig))).getOrElse(false)
      _     <- if (ok) Right(()) else Left("the signature does not match the id")
    } yield did
  }

  /** Either kind of proof, as a checker sends it to the register. A request proof needs the audience. */
  def checkAnyProof(proof: Json, challenge: Option[String], audience: Option[String], nowMillis: Long = System.currentTimeMillis()): Either[String, String] =
    if (proof.hcursor.get[String]("type").toOption.contains(RequestProofType))
      audience.toRight("send the audience: the address the request was made to").flatMap(a => checkRequestProof(proof, a, nowMillis))
    else checkProof(proof, challenge, nowMillis, expectedAudience = audience)

  /** The descriptor an owner signs. Canonical JSON, so the signature is checkable anywhere. */
  def descriptor(agentDid: String, ownerDid: String, name: String, kind: String, issuedAt: String, expiresAt: String,
                 parentDid: Option[String] = None, environment: String = "test"): Json = {
    // `environment` is production or test. It is signed, so a test agent says so to everyone, forever.
    val base = Json.obj(
      "v" -> Json.fromInt(1), "type" -> Json.fromString("traceable-agent"),
      "id" -> Json.fromString(agentDid), "owner" -> Json.fromString(ownerDid),
      "name" -> Json.fromString(name), "kind" -> Json.fromString(kind), "environment" -> Json.fromString(environment),
      "issuedAt" -> Json.fromString(issuedAt), "expiresAt" -> Json.fromString(expiresAt))
    // A child names its parent. The owner signs the descriptor, and so does the parent's key: the parent vouches.
    parentDid.fold(base)(p => base.deepMerge(Json.obj("parent" -> Json.fromString(p))))
  }

  /** What a receipt commits to. The action itself appears only as a hash. */
  def receiptPreimage(agentDid: String, seq: Long, atIso: String, kind: String, decision: String,
                      runId: Option[String], actionHash: Option[String], ledgerRowHash: String, prevHash: String): Array[Byte] = {
    val o = (v: Option[String]) => v.fold(Json.Null)(Json.fromString)
    canonicalBytes(Json.arr(Json.fromString("traceable-receipt"), Json.fromString(agentDid), Json.fromLong(seq), Json.fromString(atIso),
      Json.fromString(kind), Json.fromString(decision), o(runId), o(actionHash), Json.fromString(ledgerRowHash), Json.fromString(prevHash)))
  }

  val Genesis = "0" * 64

  object Base58 {
    private val Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    private val Index: Map[Char, Int] = Alphabet.zipWithIndex.toMap

    def encode(bytes: Array[Byte]): String = {
      val zeros = bytes.takeWhile(_ == 0).length
      var n = new java.math.BigInteger(1, bytes)
      val sb = new StringBuilder
      val base = java.math.BigInteger.valueOf(58)
      while (n.signum() > 0) {
        val qr = n.divideAndRemainder(base)
        sb.append(Alphabet(qr(1).intValue()))
        n = qr(0)
      }
      ("1" * zeros) + sb.reverse.toString
    }

    def decode(s: String): Option[Array[Byte]] =
      if (s.isEmpty || !s.forall(Index.contains)) None
      else {
        val zeros = s.takeWhile(_ == '1').length
        val n = s.foldLeft(java.math.BigInteger.ZERO)((acc, c) => acc.multiply(java.math.BigInteger.valueOf(58)).add(java.math.BigInteger.valueOf(Index(c))))
        val body = n.toByteArray.dropWhile(_ == 0)
        Some(Array.fill[Byte](zeros)(0) ++ body)
      }
  }
}
