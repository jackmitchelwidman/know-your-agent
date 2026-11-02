package traceable

import cats.effect.Async
import cats.implicits._
import io.circe.Json
import io.circe.parser
import io.circe.syntax._
import TraceableAgents._

/** Recomputes an agent's whole chain from the public keys: the owner's signature over the descriptor, the parent's
  * signature for a child, and every receipt's hash, link and signature. The same check for every issuer. */
object ChainVerify {
  private def unhex(s: String): Array[Byte] = s.grouped(2).map(Integer.parseInt(_, 16).toByte).toArray

  def verify[F[_]: Async](repo: TraceableAgentsRepository[F], a: TaAgentRow): F[Json] = {
    val pub = unb64(a.publicKey)
    val parsed = parser.parse(a.descriptorJson).toOption
    val descOk = parsed.exists { d =>
      d.hcursor.get[String]("owner").toOption.flatMap(publicKeyOf).exists(opub => TraceableAgents.verify(opub, canonicalBytes(d), unb64(a.ownerSignature))) &&
        d.hcursor.get[String]("id").toOption.contains(a.did)
    }
    val parentProblem: Option[String] = (a.parentDid, parsed) match {
      case (None, Some(d)) if d.hcursor.get[String]("parent").toOption.nonEmpty => Some("descriptor names a parent the register does not record")
      case (Some(pd), Some(d)) =>
        if (!d.hcursor.get[String]("parent").toOption.contains(pd)) Some("descriptor's parent does not match the register")
        else if (!a.parentSignature.exists(ps => publicKeyOf(pd).exists(ppub => TraceableAgents.verify(ppub, canonicalBytes(d), unb64(ps))))) Some("parent's signature over the descriptor does not verify")
        else None
      case _ => None
    }
    def walk(after: Long, prev: String, checked: Long, problems: List[String]): F[(Long, List[String])] =
      repo.receiptsAsc(a.agentId, after, 1000).flatMap { rs =>
        if (rs.isEmpty) Async[F].pure((checked, problems))
        else {
          val (p, _, bad) = rs.foldLeft((prev, prev, problems)) { case ((expectPrev, _, probs), r) =>
            val pre = receiptPreimage(a.did, r.seq, r.atIso, r.kind, r.decision, r.runId, r.actionHash, r.ledgerRowHash, r.prevHash)
            val rh = hex(sha256(pre))
            val errs = List(
              if (r.prevHash != expectPrev) Some(s"receipt ${r.seq}: chain broken") else None,
              if (rh != r.receiptHash) Some(s"receipt ${r.seq}: hash does not match") else None,
              if (!TraceableAgents.verify(pub, unhex(r.receiptHash), unb64(r.agentSignature))) Some(s"receipt ${r.seq}: signature does not verify") else None
            ).flatten
            (r.receiptHash, r.receiptHash, probs ++ errs)
          }
          if (rs.size < 1000) Async[F].pure((checked + rs.size, bad)) else walk(rs.last.seq, p, checked + rs.size, bad)
        }
      }
    walk(0L, Genesis, 0L, (if (descOk) Nil else List("owner signature over the descriptor does not verify")) ++ parentProblem.toList).map { case (n, probs) =>
      Json.obj("ok" -> probs.isEmpty.asJson, "descriptorSigned" -> descOk.asJson, "parentSigned" -> a.parentDid.map(_ => parentProblem.isEmpty).asJson,
        "receiptsChecked" -> n.asJson, "problems" -> probs.asJson)
    }
  }
}
