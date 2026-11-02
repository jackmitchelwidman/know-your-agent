package traceable
import cats.effect.Async
import cats.implicits._
import io.circe.Json
import io.circe.syntax._
import java.util.UUID

import TraceableAgents._

/**
 * The open door: another system issues IDs and writes receipts on the register, in the same
 * format Sheaf uses. The register never holds that system's keys. It checks every signature from
 * the public keys and keeps the chain rules, so an entry written through this door verifies
 * exactly like one Sheaf wrote.
 *
 *   verifier   the other system. It registers once with its key; every write it sends is signed
 *              over the canonical body (sorted keys, no whitespace) minus the `signature` field.
 *   owner      a company or person the verifier signs for. Its key is its own.
 *   agent      a descriptor the owner signed, exactly as on the format page.
 *   receipt    the agent's chain, one at a time, in order, each signed by the agent's key.
 *
 * A verifier may write only to owners and agents it brought. Public counts and search include a
 * verifier's entries only once the register has approved it; direct lookup by ID works at once.
 */
class TraceableVerifierService[F[_]: Async](repo: TraceableAgentsRepository[F], verification: Option[TraceableVerificationService[F]] = None) {

  private def nowIso: String = java.time.Instant.now().toString

  /** The body with `signature` removed, as the verifier signed it. */
  private def unsigned(body: Json): Json = body.mapObject(_.remove("signature"))

  /** Right(verifier) when the body is signed by a registered verifier named in `verifier`. */
  private def authed(body: Json): F[Either[String, TaVerifierRow]] = {
    val c = body.hcursor
    (c.get[String]("verifier").toOption, c.get[String]("signature").toOption, c.get[String]("at").toOption) match {
      case (Some(did), Some(sig), Some(at)) =>
        val fresh = scala.util.Try(java.time.Instant.parse(at).toEpochMilli).toOption.exists(t => math.abs(System.currentTimeMillis() - t) < 600000L)
        if (!fresh) Async[F].pure(Left("`at` must be the current time in ISO form; the register accepts a write for ten minutes"))
        else repo.verifier(did).map {
          case None => Left("this verifier is not registered; register it first")
          case Some(v) if v.status == "suspended" => Left("this verifier is suspended")
          case Some(v) =>
            val ok = scala.util.Try(verify(unb64(v.publicKey), canonicalBytes(unsigned(body)), unb64(sig))).getOrElse(false)
            if (ok) Right(v) else Left("the signature is not the verifier's over this body (canonical JSON, sorted keys, no whitespace, without `signature`)")
        }
      case _ => Async[F].pure(Left("send verifier (its did:key), at (ISO time) and signature (base64)"))
    }
  }

  /** Register a verifier: {type:'traceable-verifier', id, name, website?, at, signature}. The signature is the
    * verifier's own key over the body, which is how it proves it holds the key it registers. */
  def register(body: Json): F[Either[String, TaVerifierRow]] = {
    val c = body.hcursor
    (c.get[String]("id").toOption, c.get[String]("name").toOption.map(_.trim).filter(_.nonEmpty), c.get[String]("signature").toOption) match {
      case (Some(did), Some(name), Some(sig)) =>
        publicKeyOf(did) match {
          case None => Async[F].pure(Left("id must be a did:key for an Ed25519 key"))
          case Some(pk) =>
            if (!scala.util.Try(verify(pk, canonicalBytes(unsigned(body)), unb64(sig))).getOrElse(false)) Async[F].pure(Left("the signature is not this key's over the body"))
            else {
              val row = TaVerifierRow(did, b64(pk), name.take(120), c.get[String]("website").toOption.map(_.take(200)), "registered", nowIso)
              repo.insertVerifier(row) >> repo.verifier(did).map(_.toRight("could not store the verifier"))
            }
        }
      case _ => Async[F].pure(Left("send id (did:key), name, website?, and signature"))
    }
  }

  /** An entry: {verifier, at, owner:{id, name, listed?}, agent:{descriptor, ownerSignature, parentSignature?}, signature}. */
  def entry(body: Json): F[Either[String, TaAgentRow]] = authed(body).flatMap {
    case Left(e) => Async[F].pure(Left(e))
    case Right(v) => entryFor(v, body)
  }

  /** The direct door: an owner enters its own agent in one call, with no system in between.
    *   {type:'traceable-join', at, owner:{id, name, website?, listed?}, agent:{descriptor, ownerSignature, parentSignature?}, signature}
    * The signature is the owner key's over the body. The owner becomes the issuing system for itself (a verifier
    * row with status `self`, trusted by the public counts at once): from then on it writes receipts and standing
    * for its own agents through the same calls as any system, naming its own id as `verifier`. An owner that
    * holds both keys reports on itself, so the lookup says so. */
  def join(body: Json): F[Either[String, TaAgentRow]] = {
    val c = body.hcursor; val oc = c.downField("owner")
    (oc.get[String]("id").toOption, oc.get[String]("name").toOption.map(_.trim).filter(_.nonEmpty), c.get[String]("signature").toOption, c.get[String]("at").toOption) match {
      case (Some(did), Some(name), Some(sig), Some(at)) =>
        val fresh = scala.util.Try(java.time.Instant.parse(at).toEpochMilli).toOption.exists(t => math.abs(System.currentTimeMillis() - t) < 600000L)
        publicKeyOf(did) match {
          case None => Async[F].pure(Left("owner.id must be a did:key for an Ed25519 key"))
          case Some(_) if !fresh => Async[F].pure(Left("`at` must be the current time in ISO form; the register accepts a write for ten minutes"))
          case Some(pk) =>
            val ok = scala.util.Try(verify(pk, canonicalBytes(unsigned(body)), unb64(sig))).getOrElse(false)
            if (!ok) Async[F].pure(Left("the signature is not the owner key's over this body (canonical JSON, sorted keys, no whitespace, without `signature`)"))
            else repo.verifier(did).flatMap {
              case Some(v) if v.status == "suspended" => Async[F].pure(Left("this owner is suspended"))
              case Some(v) if v.status != "self" => Async[F].pure(Left("this key is registered as a system; write its entries through /entries"))
              case existing =>
                val row = TaVerifierRow(did, b64(pk), name.take(120), oc.get[String]("website").toOption.map(_.take(200)), "self", nowIso)
                (if (existing.isEmpty) repo.insertVerifier(row).void else Async[F].unit) >> repo.verifier(did).flatMap {
                  case None => Async[F].pure(Left("could not record the owner"))
                  case Some(v) => entryFor(v, body)
                }
            }
        }
      case _ => Async[F].pure(Left("send owner {id (did:key), name}, agent {descriptor, ownerSignature}, at (ISO time) and signature (base64, the owner key's)"))
    }
  }

  /** A body signed by an owner's own key: {owner (did:key), at, signature, …}. The owner must be on the register. */
  private def ownerSigned(body: Json): F[Either[String, TaOwnerRow]] = {
    val c = body.hcursor
    (c.get[String]("owner").toOption, c.get[String]("signature").toOption, c.get[String]("at").toOption) match {
      case (Some(did), Some(sig), Some(at)) =>
        val fresh = scala.util.Try(java.time.Instant.parse(at).toEpochMilli).toOption.exists(t => math.abs(System.currentTimeMillis() - t) < 600000L)
        if (!fresh) Async[F].pure(Left("`at` must be the current time in ISO form; the register accepts a write for ten minutes"))
        else repo.ownerByDid(did).map {
          case None => Left("that owner is not on the register")
          case Some(o) =>
            val ok = scala.util.Try(verify(unb64(o.publicKey), canonicalBytes(unsigned(body)), unb64(sig))).getOrElse(false)
            if (ok) Right(o) else Left("the signature is not the owner key's over this body (canonical JSON, sorted keys, no whitespace, without `signature`)")
        }
      case _ => Async[F].pure(Left("send owner (did:key), at (ISO time) and signature (base64, the owner key's)"))
    }
  }

  /** Owner verification by the owner itself: {type:'traceable-verify', owner, domain, at, signature} claims a domain and
    * returns the token to place in DNS or at /.well-known/kya.txt. */
  def verifyDomain(body: Json): F[Either[String, Json]] = verification match {
    case None => Async[F].pure(Left("owner verification is not configured on this register"))
    case Some(vs) => ownerSigned(body).flatMap {
      case Left(e) => Async[F].pure(Left(e))
      case Right(o) => body.hcursor.get[String]("domain").toOption.map(_.trim).filter(_.nonEmpty) match {
        case None => Async[F].pure(Left("domain is missing"))
        case Some(d) => vs.claimDomain(o.customerId, d).map(_.map(j => Json.obj("owner" -> o.did.asJson, "verification" -> j,
          "next" -> "Put the token in a DNS TXT record at _kya.<domain> as kya-verify=<token>, or serve it as a line at https://<domain>/.well-known/kya.txt. Then call /owners/verify/check.".asJson)))
      }
    }
  }

  /** {type:'traceable-verify-check', owner, at, signature}: look for the token now. */
  def verifyCheck(body: Json): F[Either[String, Json]] = verification match {
    case None => Async[F].pure(Left("owner verification is not configured on this register"))
    case Some(vs) => ownerSigned(body).flatMap {
      case Left(e) => Async[F].pure(Left(e))
      case Right(o) => vs.check(o.customerId).flatMap(r => repo.ownerByDid(o.did).map(now => r.map(j => Json.obj("owner" -> o.did.asJson, "verification" -> j, "tier" -> now.map(_.verification).asJson))))
    }
  }

  private def entryFor(v: TaVerifierRow, body: Json): F[Either[String, TaAgentRow]] = {
      val c = body.hcursor
      val oc = c.downField("owner"); val ac = c.downField("agent")
      val desc = ac.downField("descriptor").focus.filter(_.isObject)
      val dc = desc.map(_.hcursor)
      val fields = for {
        ownerDid <- oc.get[String]("id").toOption.toRight("owner.id is missing")
        ownerPk  <- publicKeyOf(ownerDid).toRight("owner.id must be a did:key for an Ed25519 key")
        ownerName = oc.get[String]("name").toOption.map(_.trim).filter(_.nonEmpty).getOrElse("An owner on record")
        listed    = oc.get[Boolean]("listed").toOption.getOrElse(false)
        d        <- desc.toRight("agent.descriptor is missing")
        h        <- dc.toRight("agent.descriptor is missing")
        ownerSig <- ac.get[String]("ownerSignature").toOption.toRight("agent.ownerSignature is missing")
        agentDid <- h.get[String]("id").toOption.toRight("descriptor.id is missing")
        agentPk  <- publicKeyOf(agentDid).toRight("descriptor.id must be a did:key for an Ed25519 key")
        _        <- if (h.get[String]("owner").toOption.contains(ownerDid)) Right(()) else Left("descriptor.owner must equal owner.id")
        _        <- if (h.get[String]("type").toOption.contains("traceable-agent") && h.get[Int]("v").toOption.contains(1)) Right(()) else Left("descriptor must have v:1 and type:'traceable-agent'")
        name     <- h.get[String]("name").toOption.map(_.trim).filter(_.nonEmpty).toRight("descriptor.name is missing")
        kind     <- h.get[String]("kind").toOption.map(_.trim).filter(_.nonEmpty).toRight("descriptor.kind is missing")
        env      <- h.get[String]("environment").toOption.filter(e => e == "production" || e == "test").toRight("descriptor.environment must be production or test")
        issued   <- h.get[String]("issuedAt").toOption.flatMap(x => scala.util.Try(java.time.Instant.parse(x)).toOption.map(_ => x)).toRight("descriptor.issuedAt must be an ISO time")
        expires  <- h.get[String]("expiresAt").toOption.flatMap(x => scala.util.Try(java.time.Instant.parse(x)).toOption.map(_ => x)).toRight("descriptor.expiresAt must be an ISO time")
        _        <- if (scala.util.Try(verify(ownerPk, canonicalBytes(d), unb64(ownerSig))).getOrElse(false)) Right(()) else Left("ownerSignature does not verify over the canonical descriptor with owner.id's key")
        parentDid = h.get[String]("parent").toOption
        parentSig = ac.get[String]("parentSignature").toOption
      } yield (ownerDid, ownerPk, ownerName, listed, d, ownerSig, agentDid, agentPk, name, kind, env, issued, expires, parentDid, parentSig)
      fields match {
        case Left(e) => Async[F].pure(Left(e))
        case Right((ownerDid, ownerPk, ownerName, listed, d, ownerSig, agentDid, agentPk, name, kind, env, issued, expires, parentDid, parentSig)) =>
          repo.agentByDid(agentDid).flatMap {
            case Some(a) => Async[F].pure(Left(s"that agent ID is already on the register, issued through ${a.verifierDid.getOrElse("this register")}"))
            case None => repo.ownerByDid(ownerDid).flatMap { existing =>
              val ownerF: F[Either[String, TaOwnerRow]] = existing match {
                case Some(o) if o.verifierDid.contains(v.did) => repo.setOwnerListing(o.customerId, listed, ownerName.take(120)) >> repo.ownerByDid(ownerDid).map(_.toRight("owner vanished"))
                case Some(o) => Async[F].pure(Left(s"that owner is on the register through ${o.verifierDid.getOrElse("this register")}; only that system may write for it"))
                case None =>
                  val row = TaOwnerRow(UUID.randomUUID(), ownerDid, b64(ownerPk), "", "", ownerName.take(120), "unverified", None, None, "active", nowIso, listed, Some(nowIso), Some(v.did))
                  repo.insertExternalOwner(row, listed) >> repo.ownerByDid(ownerDid).map(_.toRight("could not store the owner"))
              }
              ownerF.flatMap {
                case Left(e) => Async[F].pure(Left(e))
                case Right(o) =>
                  // A child must name a parent on the register, under the same owner, and carry the parent key's signature over the same bytes.
                  val parentF: F[Either[String, Option[TaAgentRow]]] = parentDid match {
                    case None => Async[F].pure(Right(None))
                    case Some(pd) => repo.agentByDid(pd).map {
                      case None => Left("descriptor.parent is not on the register")
                      case Some(p) if p.customerId != o.customerId => Left("descriptor.parent belongs to another owner")
                      case Some(p) =>
                        val ok = parentSig.exists(ps => scala.util.Try(verify(unb64(p.publicKey), canonicalBytes(d), unb64(ps))).getOrElse(false))
                        if (ok) Right(Some(p)) else Left("parentSignature does not verify over the descriptor with the parent's key")
                    }
                  }
                  parentF.flatMap {
                    case Left(e) => Async[F].pure(Left(e))
                    case Right(parent) =>
                      val row = TaAgentRow(UUID.randomUUID(), o.customerId, agentDid, fingerprint(agentPk), b64(agentPk), "", "",
                        canonical.print(d), ownerSig, name.take(120), kind.take(60), "issued", None, None, issued, expires,
                        parent.map(_.did), parentSig.filter(_ => parent.isDefined), parent.fold(0)(_.depth + 1), env, Some(v.did))
                      repo.insertAgent(row) >> repo.agentByDid(agentDid).map(_.toRight("could not store the agent"))
                  }
              }
            }
          }
      }
  }

  /** Receipts, in order: {verifier, at, agent, receipts:[{seq, at, kind, decision, runId?, actionHash?, ledgerRowHash, prevHash, hash, signature}], signature}.
    * Each must continue the chain and carry the agent key's signature over its hash. Replays of receipts already
    * on the register are accepted when identical and refused when not. */
  def receipts(body: Json): F[Either[String, Json]] = authed(body).flatMap {
    case Left(e) => Async[F].pure(Left(e))
    case Right(v) =>
      val c = body.hcursor
      c.get[String]("agent").toOption match {
        case None => Async[F].pure(Left("agent (did:key) is missing"))
        case Some(agentDid) => repo.agentByDid(agentDid).flatMap {
          case None => Async[F].pure(Left("that agent is not on the register; submit its entry first"))
          case Some(a) if !a.verifierDid.contains(v.did) => Async[F].pure(Left(s"that agent was issued through ${a.verifierDid.getOrElse("this register")}; only that system may write its receipts"))
          case Some(a) =>
            val items = c.downField("receipts").focus.flatMap(_.asArray).map(_.toList).getOrElse(Nil)
            if (items.isEmpty) Async[F].pure(Left("receipts is empty"))
            else if (items.size > 500) Async[F].pure(Left("send at most 500 receipts in one call"))
            else {
              val pub = unb64(a.publicKey)
              def one(j: Json): F[Either[String, Int]] = {
                val h = j.hcursor
                val parsed = for {
                  seq  <- h.get[Long]("seq").toOption.toRight("a receipt has no seq")
                  at   <- h.get[String]("at").toOption.toRight(s"receipt $seq has no at")
                  kind <- h.get[String]("kind").toOption.toRight(s"receipt $seq has no kind")
                  dec  <- h.get[String]("decision").toOption.toRight(s"receipt $seq has no decision")
                  lrh  <- h.get[String]("ledgerRowHash").toOption.toRight(s"receipt $seq has no ledgerRowHash")
                  prev <- h.get[String]("prevHash").toOption.toRight(s"receipt $seq has no prevHash")
                  rh   <- h.get[String]("hash").toOption.toRight(s"receipt $seq has no hash")
                  sig  <- h.get[String]("signature").toOption.toRight(s"receipt $seq has no signature")
                  runId = h.get[String]("runId").toOption
                  ah    = h.get[String]("actionHash").toOption
                } yield (seq, at, kind, dec, lrh, prev, rh, sig, runId, ah)
                parsed match {
                  case Left(e) => Async[F].pure(Left(e))
                  case Right((seq, at, kind, dec, lrh, prev, rh, sig, runId, ah)) =>
                    repo.receiptHead(a.agentId).flatMap { head =>
                      val expectSeq = head.fold(1L)(_._1 + 1); val expectPrev = head.fold(Genesis)(_._2)
                      val computed = hex(sha256(receiptPreimage(a.did, seq, at, kind, dec, runId, ah, lrh, prev)))
                      if (seq < expectSeq) repo.receiptAt(a.agentId, seq).map {
                        case Some(stored) if stored == rh => Right(0)
                        case _ => Left(s"receipt $seq is already on the register with a different hash")
                      }
                      else if (seq != expectSeq) Async[F].pure(Left(s"receipt $seq is out of order; the next is $expectSeq"))
                      else if (prev != expectPrev) Async[F].pure(Left(s"receipt $seq: prevHash must be $expectPrev"))
                      else if (computed != rh) Async[F].pure(Left(s"receipt $seq: hash does not match the preimage (expected $computed)"))
                      else if (!scala.util.Try(verify(pub, unhex(rh), unb64(sig))).getOrElse(false)) Async[F].pure(Left(s"receipt $seq: signature is not the agent key's over the hash"))
                      else repo.insertExternalReceipt(TaReceiptRow(a.agentId, seq, a.customerId, 0L, at, kind, dec, runId, ah, lrh, prev, rh, sig), v.did).map(Right(_))
                    }
                }
              }
              items.foldLeftM[F, Either[String, Int]](Right(0)) {
                case (Left(e), _) => Async[F].pure(Left(e))
                case (Right(n), j) => one(j).map(_.map(_ + n))
              }.flatMap {
                case Left(e) => Async[F].pure(Left(e))
                case Right(n) => repo.receiptHead(a.agentId).map(head => Right(Json.obj("accepted" -> n.asJson, "headSeq" -> head.map(_._1).asJson, "headHash" -> head.map(_._2).asJson)))
              }
            }
        }
      }
  }

  /** Retire or revoke an agent the verifier issued: {verifier, at, agent, status, reason?, signature}. */
  def status(body: Json): F[Either[String, TaAgentRow]] = authed(body).flatMap {
    case Left(e) => Async[F].pure(Left(e))
    case Right(v) =>
      val c = body.hcursor
      (c.get[String]("agent").toOption, c.get[String]("status").toOption.filter(s => s == "retired" || s == "revoked")) match {
        case (Some(did), Some(st)) => repo.agentByDid(did).flatMap {
          case None => Async[F].pure(Left("that agent is not on the register"))
          case Some(a) if !a.verifierDid.contains(v.did) => Async[F].pure(Left("only the system that issued this agent may change its standing"))
          case Some(a) => repo.setAgentStatus(a.agentId, st, c.get[String]("reason").toOption.map(_.take(200)).orElse(Some(s"$st by its owner"))) >>
            repo.agentByDid(did).map(_.toRight("agent vanished"))
        }
        case _ => Async[F].pure(Left("send agent (did:key) and status (retired or revoked)"))
      }
  }

  private def unhex(s: String): Array[Byte] = s.grouped(2).map(Integer.parseInt(_, 16).toByte).toArray
}
