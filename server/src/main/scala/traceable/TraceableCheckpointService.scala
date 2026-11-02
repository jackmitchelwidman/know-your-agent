package traceable
import cats.effect.Async
import cats.implicits._
import io.circe.Json
import io.circe.syntax._
import io.circe.parser
import org.typelevel.log4cats.Logger

import TraceableAgents._

/**
 * The public checkpoint. Once an hour the register takes the head of every agent's receipt chain,
 * sorts them by agent ID, folds them into one Merkle root, and submits the hash of a short
 * statement about that root to OpenTimestamps calendars, which commit it to Bitcoin within a few
 * hours. After that, not even the keeper of the register can change a receipt under a checkpoint
 * without the published hash ceasing to match. Anyone keeping copies of the checkpoints can check.
 *
 *   leaf       sha256 of canonical ["traceable-checkpoint-leaf", did, headSeq, headHash]
 *   node       sha256(left ++ right); an odd last node is paired with itself
 *   statement  canonical {v:1, type:"traceable-checkpoint", at, agents, receipts, root, prevRoot}
 *   anchored   sha256(statement bytes), as a 32-byte digest, to the calendars
 */
class TraceableCheckpointService[F[_]: Async: Logger](repo: TraceableAgentsRepository[F], ots: OtsClient[F], otsEnabled: Boolean, baseUrl: String = "https://traceableagents.org") {

  def leafHash(did: String, seq: Long, hash: String): Array[Byte] =
    sha256(canonicalBytes(Json.arr(Json.fromString("traceable-checkpoint-leaf"), Json.fromString(did), Json.fromLong(seq), Json.fromString(hash))))

  /** The root and, for one leaf index, the path of sibling hashes up to it. */
  def merkle(leaves: List[Array[Byte]], index: Option[Int] = None): (Array[Byte], List[(String, String)]) = {
    if (leaves.isEmpty) return (sha256(Array.empty[Byte]), Nil)
    var level = leaves.toVector; var i = index.getOrElse(0); var path = List.empty[(String, String)]
    while (level.size > 1) {
      val next = level.grouped(2).map { g => val l = g(0); val r = if (g.size == 2) g(1) else g(0); sha256(l ++ r) }.toVector
      if (index.isDefined) {
        val sib = if (i % 2 == 0) (if (i + 1 < level.size) level(i + 1) else level(i)) else level(i - 1)
        path = path :+ ((if (i % 2 == 0) "right" else "left"), hex(sib))
        i = i / 2
      }
      level = next
    }
    (level.head, path)
  }

  def statementJson(at: String, agents: Int, receipts: Long, root: String, prevRoot: Option[String]): Json = Json.obj(
    "v" -> Json.fromInt(1), "type" -> Json.fromString("traceable-checkpoint"), "at" -> Json.fromString(at),
    "agents" -> Json.fromInt(agents), "receipts" -> Json.fromLong(receipts), "root" -> Json.fromString(root),
    "prevRoot" -> prevRoot.fold(Json.Null)(Json.fromString))

  /** Take a checkpoint now, unless nothing has moved since the last one. Some(seq) when one was written. */
  def take: F[Option[Long]] =
    (repo.allHeads, repo.latestCheckpoint).tupled.flatMap { case (heads, prev) =>
      if (heads.isEmpty) Async[F].pure(None)
      else {
        val root = hex(merkle(heads.map { case (d, s, h) => leafHash(d, s, h) })._1)
        if (prev.exists(_.root == root)) Async[F].pure(None)
        else {
          val at = java.time.Instant.now().toString.replaceAll("\\.\\d+Z$", "Z")
          val receipts = heads.map(_._2).sum
          val st = statementJson(at, heads.size, receipts, root, prev.map(_.root))
          val stBytes = canonicalBytes(st); val stHash = hex(sha256(stBytes))
          val leaves = Json.arr(heads.map { case (d, s, h) => Json.arr(Json.fromString(d), Json.fromLong(s), Json.fromString(h)) }*)
          (if (otsEnabled) ots.stamp(sha256(stBytes)) else Async[F].pure(Left("anchoring is off"))).flatMap { anchored =>
            anchored.left.toOption.fold(Async[F].unit)(e => Logger[F].warn(s"[register-checkpoint] anchor skipped: $e")) >>
            repo.insertCheckpoint(at, heads.size, receipts, root, prev.map(_.root), new String(stBytes, "UTF-8"), stHash,
              canonical.print(leaves), anchored.toOption.map(_._1), anchored.toOption.map(_._2)).flatMap {
                case Some(seq) => Logger[F].info(s"[register-checkpoint] #$seq: ${heads.size} agent(s), $receipts receipt(s), root ${root.take(16)}…, ${if (anchored.isRight) "submitted to " + anchored.toOption.get._1 else "not anchored"}").as(Some(seq))
                case None => Async[F].pure(None)
              }
          }
        }
      }
    }

  /** Ask the calendars for the Bitcoin path on pending checkpoints. (confirmed, attempted). */
  def upgradePending(olderThanMinutes: Int, limit: Int): F[(Int, Int)] =
    repo.pendingCheckpoints(olderThanMinutes, limit).flatMap { ps =>
      ps.traverse { case (seq, proof) =>
        ots.upgrade(proof).flatMap {
          case Left(e)               => repo.checkpointAttempt(seq, Some(e)).as(false)
          case Right(None)           => repo.checkpointAttempt(seq, None).as(false)
          case Right(Some((f, Nil))) => repo.checkpointProgress(seq, f).as(false)
          case Right(Some((f, hs)))  => repo.checkpointConfirmed(seq, f, hs.min) >> Logger[F].info(s"[register-checkpoint] #$seq confirmed in Bitcoin block ${hs.min}").as(true)
        }
      }.map(rs => (rs.count(identity), rs.size))
    }

  def rowJson(c: TaCheckpointRow): Json = Json.obj(
    "seq" -> c.seq.asJson, "at" -> c.atIso.asJson, "agents" -> c.agents.asJson, "receipts" -> c.receipts.asJson,
    "root" -> c.root.asJson, "prevRoot" -> c.prevRoot.asJson, "statementHash" -> c.statementHash.asJson,
    "status" -> c.status.asJson, "bitcoinBlock" -> c.bitcoinHeight.asJson, "confirmedAt" -> c.confirmedAt.asJson,
    "calendar" -> c.calendarUrl.asJson, "proofUrl" -> s"${baseUrl.stripSuffix("/")}/api/v1/register/checkpoints/${c.seq}/proof.ots".asJson,
    "words" -> words(c).asJson)

  def words(c: TaCheckpointRow): String = c.status match {
    case "confirmed" => s"Checkpoint ${c.seq}, taken ${c.atIso.take(16).replace('T', ' ')} UTC, is written into Bitcoin block ${c.bitcoinHeight.getOrElse(0L)}."
    case "pending"   => s"Checkpoint ${c.seq}, taken ${c.atIso.take(16).replace('T', ' ')} UTC, has been submitted for anchoring in Bitcoin; a block usually follows within a few hours."
    case _           => s"Checkpoint ${c.seq}, taken ${c.atIso.take(16).replace('T', ' ')} UTC, is published here; it could not be submitted for anchoring and will be covered by the next one."
  }

  /** For one agent: the newest checkpoint that covers it, which head it covers, and the Merkle path to the root. */
  def coverage(did: String): F[Option[Json]] =
    repo.latestCheckpointCovering(did).flatMap {
      case None => Async[F].pure(None)
      case Some(c) => repo.checkpointLeaves(c.seq).map { lj =>
        val leaves = lj.flatMap(parser.parse(_).toOption).flatMap(_.asArray).map(_.toList).getOrElse(Nil)
          .flatMap(j => j.asArray.flatMap(a => (a.lift(0).flatMap(_.asString), a.lift(1).flatMap(_.asNumber).flatMap(_.toLong), a.lift(2).flatMap(_.asString)).tupled))
        val idx = leaves.indexWhere(_._1 == did)
        if (idx < 0) None else {
          val (seq, head) = (leaves(idx)._2, leaves(idx)._3)
          val (root, path) = merkle(leaves.map { case (d, s, h) => leafHash(d, s, h) }, Some(idx))
          Some(rowJson(c).deepMerge(Json.obj("coversHeadSeq" -> seq.asJson, "coversHeadHash" -> head.asJson,
            "leaf" -> hex(leafHash(did, seq, head)).asJson, "leafIndex" -> idx.asJson, "path" -> path.map { case (side, h) => Json.obj("side" -> side.asJson, "hash" -> h.asJson) }.asJson,
            "rootRecomputed" -> hex(root).asJson,
            "words" -> (s"Receipts 1 to $seq of this agent are under checkpoint ${c.seq}. " + words(c)).asJson)))
        }
      }
    }
}
