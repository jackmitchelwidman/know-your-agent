package traceable
import cats.effect.Async
import cats.implicits._
import org.http4s._
import org.http4s.dsl.Http4sDsl
import org.http4s.circe._
import org.http4s.server.middleware.CORS
import io.circe._
import io.circe.syntax._
import io.circe.parser
import java.time.Instant


/**
 * The public register (traceableagents.org). No account, no key. Answers one question about an
 * agent: who owns it, is it in standing, and what does its record hold. The answer carries
 * hashes, counts, verdict kinds, timestamps and signatures. Never the content of an action.
 */
object TraceableAgentsRoutes {

  /** Registers that talk to each other. This register's own name, address and (optional) id, and the peers it asks
    * when an ID is not on it. An answer from a peer is used only after this register has re-checked the owner's
    * signature over the descriptor from the public keys in the answer, so a peer can report but cannot vouch. */
  final case class Federation[F[_]](client: org.http4s.client.Client[F], selfUrl: String, selfName: String, selfDid: Option[String], peers: List[String])

  def routes[F[_]: Async](repo: TraceableAgentsRepository[F],
                          verifiers: Option[TraceableVerifierService[F]] = None,
                          checkpoints: Option[TraceableCheckpointService[F]] = None,
                          federation: Option[Federation[F]] = None): HttpRoutes[F] = {
    val dsl = new Http4sDsl[F] {}
    import dsl._
    import scala.concurrent.duration._

    // The open door's writes: a small per-IP limiter, sixty signed writes in ten minutes.
    val writeHits = cats.effect.Ref.unsafe[F, Map[String, List[Long]]](Map.empty)
    def allowWrite(ip: String): F[Boolean] = writeHits.modify { m =>
      val now = System.currentTimeMillis(); val keep = m.getOrElse(ip, Nil).filter(_ > now - 600000L)
      if (keep.size >= 60) (m.updated(ip, keep), false) else (m.updated(ip, now :: keep), true)
    }
    def ipOf(req: Request[F]): String = req.headers.get(org.typelevel.ci.CIString("x-forwarded-for")).map(_.head.value.split(",")(0).trim)
      .orElse(req.remoteAddr.map(_.toString)).getOrElse("?")

    def jsonResp(status: Status, j: Json): F[Response[F]] = Async[F].pure(Response[F](status = status).withEntity(j))
    def fail(status: Status, msg: String): F[Response[F]] = jsonResp(status, Json.obj("ok" -> false.asJson, "error" -> msg.asJson))

    val lk: TraceableAgentsLookup[F] = new TraceableAgentsLookup[F](repo)
    import lk.*
    val fedDec: EntityDecoder[F, Json] = jsonOf[F, Json]
    def selfJson: Json = federation.fold(Json.Null)(f => Json.obj("id" -> f.selfDid.asJson, "name" -> f.selfName.asJson, "url" -> f.selfUrl.asJson))

    /** A peer's answer is accepted only if its own proof block verifies here: the descriptor names the queried agent,
      * descriptor.owner is the key in ownerPublicKey, and ownerSignature is that key's over the canonical descriptor. */
    def verifiedPeerAnswer(queried: String, j: Json): Boolean = {
      import TraceableAgents._
      val c = j.hcursor
      val pr = c.downField("proof"); val ag = c.downField("agent")
      val ok = for {
        d       <- pr.downField("descriptor").focus.filter(_.isObject)
        dc       = d.hcursor
        did     <- dc.get[String]("id").toOption
        owner   <- dc.get[String]("owner").toOption
        sig     <- pr.get[String]("ownerSignature").toOption
        ownerPk <- pr.get[String]("ownerPublicKey").toOption
        agentPk <- publicKeyOf(did)
        fp       = fingerprint(agentPk)
        _       <- Option(()).filter(_ => queried == did || queried == fp || ag.get[String]("id").toOption.contains(did))
        pk      <- publicKeyOf(owner).filter(_.sameElements(scala.util.Try(unb64(ownerPk)).getOrElse(Array.empty[Byte])))
      } yield scala.util.Try(verify(pk, canonicalBytes(d), unb64(sig))).getOrElse(false)
      ok.contains(true) && c.get[String]("status").toOption.contains("identified")
    }

    /** The lookup, here first and then one hop to each peer. `local` stops the hop, so peers never re-forward. */
    def lookupFed(id: String, local: Boolean): F[(Boolean, Json)] =
      lk.lookupJson(id).flatMap {
        case (true, j) => Async[F].pure((true, if (federation.isDefined) j.deepMerge(Json.obj("register" -> selfJson)) else j))
        case (false, j) =>
          federation.filter(_ => !local).filter(_.peers.nonEmpty) match {
            case None => Async[F].pure((false, j))
            case Some(f) =>
              def ask(peer: String): F[Option[Json]] = {
                val uri = org.http4s.Uri.unsafeFromString(peer.stripSuffix("/") + "/api/v1/register/lookup").withQueryParam("id", id).withQueryParam("local", "1")
                Async[F].timeout(f.client.expect[Json](uri)(fedDec), 4.seconds).attempt.map {
                  case Right(pj) if verifiedPeerAnswer(id, pj) =>
                    val pname = pj.hcursor.downField("register").get[String]("name").toOption
                    Some(pj.deepMerge(Json.obj("register" -> Json.obj("url" -> peer.asJson, "name" -> pname.asJson, "id" -> pj.hcursor.downField("register").get[String]("id").toOption.asJson),
                      "federated" -> true.asJson, "verifiedHere" -> true.asJson, "askedBy" -> selfJson)))
                  case _ => None
                }
              }
              f.peers.foldLeftM[F, Option[Json]](None) { case (acc, peer) => acc.fold(ask(peer))(a => Async[F].pure(Some(a))) }.map {
                case Some(pj) => (true, pj)
                case None => (false, j.deepMerge(Json.obj("register" -> selfJson, "peersAsked" -> f.peers.asJson)))
              }
          }
      }

    def lookup(id: String, local: Boolean = false): F[Response[F]] =
      lookupFed(id, local).flatMap { case (found, j) =>
        // The public checkpoint that covers this agent, if any: proof that its receipts predate a Bitcoin block.
        val withCp: F[Json] = (checkpoints, j.hcursor.downField("agent").get[String]("id").toOption) match {
          case (Some(cp), Some(did)) if found => cp.coverage(did).map(c => j.deepMerge(Json.obj("checkpoint" -> c.asJson)))
          case _ => Async[F].pure(j)
        }
        withCp.flatMap(jj => jsonResp(if (found) Status.Ok else Status.NotFound, jj)) }

    // The handshake, public side: anyone may check an agent. With a proof (the agent signed the challenge
    // you sent it), the answer also says whether that proof is the agent's.
    implicit val checkDec: EntityDecoder[F, Json] = jsonOf[F, Json]
    def check(body: Json): F[Response[F]] = {
      val c = body.hcursor
      val proof = c.downField("proof").focus.filter(_.isObject)
      val challenge = TraceableAgents.challengeOf(c)
      val id = c.get[String]("id").toOption.map(_.trim).filter(_.nonEmpty)
      val checked: Either[String, String] = proof match {
        case Some(pr) => TraceableAgents.checkProof(pr, challenge)
        case None => id.toRight("send an id, or the proof the agent gave you")
      }
      val lookupId = checked.toOption.orElse(proof.flatMap(_.hcursor.get[String]("id").toOption)).orElse(id)
      lookupId match {
        case None => fail(Status.BadRequest, "Send {id} or {proof, challenge}.")
        case Some(i) => lookupFed(i, local = false).flatMap { case (found, j) =>
          val pj = Json.obj("checked" -> proof.isDefined.asJson, "valid" -> (proof.isDefined && checked.isRight).asJson,
            "reason" -> (if (proof.isDefined) Some(checked.fold(identity, _ => "the proof is the agent's")) else None).asJson)
          val words = lk.plainWords(j) + (if (proof.isDefined) " Identity proof: " + checked.fold(r => s"NOT valid, $r.", _ => "valid.") else "")
          jsonResp(if (found) Status.Ok else Status.NotFound, j.deepMerge(Json.obj("identityProof" -> pj, "summary" -> words.asJson)))
        }
      }
    }

    /** One signed write through the open door: limiter, JSON body, the service, a plain answer. */
    def verifierWrite(req: Request[F])(f: (TraceableVerifierService[F], Json) => F[Either[String, Json]]): F[Response[F]] =
      verifiers match {
        case None => fail(Status.ServiceUnavailable, "The open door is not configured on this register.")
        case Some(vs) => allowWrite(ipOf(req)).flatMap {
          case false => fail(Status.TooManyRequests, "Too many writes from this address. Sixty in ten minutes is the limit.")
          case true => req.attemptAs[Json].value.flatMap {
            case Left(_) => fail(Status.BadRequest, "The body is not JSON.")
            case Right(body) => f(vs, body).flatMap {
              case Left(e) => fail(Status.BadRequest, e)
              case Right(j) => jsonResp(Status.Ok, Json.obj("ok" -> true.asJson).deepMerge(j))
            }
          }
        }
      }

    def receiptJson(r: TaReceiptRow): Json = Json.obj(
      "seq" -> r.seq.asJson, "at" -> r.atIso.asJson, "kind" -> r.kind.asJson, "decision" -> r.decision.asJson,
      "runId" -> r.runId.asJson, "actionHash" -> r.actionHash.asJson, "ledgerRowHash" -> r.ledgerRowHash.asJson,
      "prevHash" -> r.prevHash.asJson, "hash" -> r.receiptHash.asJson, "signature" -> r.agentSignature.asJson)

    object IdQ extends QueryParamDecoderMatcher[String]("id")
    object LocalQ extends OptionalQueryParamDecoderMatcher[String]("local")
    object BeforeQ extends OptionalQueryParamDecoderMatcher[Long]("before")
    object LimitQ extends OptionalQueryParamDecoderMatcher[Int]("limit")
    object QQ extends QueryParamDecoderMatcher[String]("q")

    val r = HttpRoutes.of[F] {
      case GET -> Root / "api" / "v1" / "register" / "lookup" :? IdQ(id) +& LocalQ(local) => lookup(id, local.exists(v => v == "1" || v == "true"))
      // this register, by name, address and id; and the registers it asks
      case GET -> Root / "api" / "v1" / "register" / "self" =>
        jsonResp(Status.Ok, Json.obj("ok" -> true.asJson, "v" -> 1.asJson, "register" -> selfJson,
          "peers" -> federation.fold(List.empty[String])(_.peers).asJson,
          "note" -> "A lookup that finds nothing here is asked, once, of each peer. A peer's answer is used only after this register has re-checked the owner's signature over the descriptor from the public keys in the answer. Pass local=1 to stop the hop.".asJson))
      case req @ POST -> Root / "api" / "v1" / "register" / "check" =>
        req.attemptAs[Json].value.flatMap {
          case Left(_) => fail(Status.BadRequest, "Send JSON: {id} or {proof, challenge}.")
          case Right(b) => check(b)
        }
      case GET -> Root / "api" / "v1" / "register" / "agents" / id => lookup(id)

      case GET -> Root / "api" / "v1" / "register" / "agents" / id / "receipts" :? BeforeQ(before) +& LimitQ(limit) =>
        repo.agentByAnyId(id).flatMap {
          case None => fail(Status.NotFound, "No agent with this ID is on the register.")
          case Some(a) => repo.receipts(a.agentId, before, limit.getOrElse(50).max(1).min(500)).flatMap(rs =>
            jsonResp(Status.Ok, Json.obj("ok" -> true.asJson, "id" -> a.did.asJson, "fingerprint" -> a.fingerprint.asJson, "receipts" -> rs.map(receiptJson).asJson)))
        }

      // The Record of Action on its own, with a timeline of the last 30 days.
      case GET -> Root / "api" / "v1" / "register" / "agents" / id / "record" =>
        repo.agentByAnyId(id).flatMap {
          case None => fail(Status.NotFound, "No agent with this ID is on the register.")
          case Some(a) => (repo.record(a.agentId, a.did), repo.receiptHead(a.agentId), repo.timeline(a.agentId, 30)).tupled.flatMap { case (rec, head, tl) =>
            jsonResp(Status.Ok, Json.obj("ok" -> true.asJson, "id" -> a.did.asJson, "fingerprint" -> a.fingerprint.asJson, "name" -> a.name.asJson,
              "recordOfAction" -> lk.recordOfActionJson(a, rec, head),
              "timeline" -> Json.fromValues(tl.map { case (day, kind, n) => Json.obj("day" -> day.asJson, "kind" -> kind.asJson, "count" -> n.asJson) })))
          }
        }

      case GET -> Root / "api" / "v1" / "register" / "agents" / id / "verify" =>
        repo.agentByAnyId(id).flatMap {
          case None => fail(Status.NotFound, "No agent with this ID is on the register.")
          case Some(a) => ChainVerify.verify(repo, a).flatMap(v => jsonResp(Status.Ok, v.deepMerge(Json.obj("id" -> a.did.asJson, "fingerprint" -> a.fingerprint.asJson))))
        }

      // The directory: owners that chose to show their name. Everyone else is reachable by ID only.
      case GET -> Root / "api" / "v1" / "register" / "owners" :? LimitQ(limit) =>
        repo.directory(limit.getOrElse(200).max(1).min(1000)).flatMap { os =>
          jsonResp(Status.Ok, Json.obj("ok" -> true.asJson, "owners" -> os.map(o => Json.obj(
            "id" -> o.did.asJson, "name" -> o.displayName.asJson, "verification" -> o.verification.asJson, "since" -> o.joinedAt.asJson,
            "agents" -> o.agents.asJson, "agentsInStanding" -> o.inStanding.asJson, "receipts" -> o.receipts.asJson)).asJson))
        }

      // Search: an ID of any form resolves to its page; a name matches listed owners and their agents only.
      case GET -> Root / "api" / "v1" / "register" / "search" :? QQ(q) =>
        val term = q.trim
        if (term.isEmpty) jsonResp(Status.Ok, Json.obj("ok" -> true.asJson, "query" -> "".asJson, "hits" -> Json.arr()))
        else repo.agentByAnyId(term).flatMap {
          case Some(a) => jsonResp(Status.Ok, Json.obj("ok" -> true.asJson, "query" -> term.take(200).asJson, "exact" -> Json.obj(
            "kind" -> "agent".asJson, "id" -> a.did.asJson, "fingerprint" -> a.fingerprint.asJson, "url" -> ("/a/" + a.fingerprint).asJson), "hits" -> Json.arr()))
          case None => repo.ownerByDid(term).flatMap {
            case Some(o) => jsonResp(Status.Ok, Json.obj("ok" -> true.asJson, "query" -> term.take(200).asJson, "exact" -> Json.obj(
              "kind" -> "owner".asJson, "id" -> o.did.asJson, "url" -> ("/o/" + o.did).asJson), "hits" -> Json.arr()))
            case None if term.length < 2 => jsonResp(Status.Ok, Json.obj("ok" -> true.asJson, "query" -> term.asJson, "hits" -> Json.arr()))
            case None => repo.search(term, 50).flatMap { hs =>
              jsonResp(Status.Ok, Json.obj("ok" -> true.asJson, "query" -> term.take(200).asJson, "hits" -> hs.map(h => Json.obj(
                "kind" -> h.kind.asJson, "id" -> h.id.asJson, "fingerprint" -> h.fingerprint.asJson, "name" -> h.name.asJson,
                "owner" -> Json.obj("id" -> h.ownerDid.asJson, "name" -> h.ownerName.asJson), "status" -> h.status.asJson,
                "environment" -> h.environment.asJson,
                "url" -> (if (h.kind == "owner") "/o/" + h.id else "/a/" + h.fingerprint.getOrElse(h.id)).asJson)).asJson,
                "note" -> "Names match only owners who chose to show them. An owner that did not is still on the register and can be looked up by ID.".asJson))
            }
          }
        }

      case GET -> Root / "api" / "v1" / "register" / "owners" / did =>
        repo.ownerByDid(did).flatMap {
          case None => fail(Status.NotFound, "No owner with this ID is on the register.")
          case Some(o) if !o.joined && o.createdAt.nonEmpty =>
            repo.agentsOfOwner(o.customerId).flatMap { as =>
              if (as.isEmpty) fail(Status.NotFound, "No owner with this ID is on the register.")
              else jsonResp(Status.Ok, Json.obj("ok" -> true.asJson, "owner" -> ownerJson(o, Some(as.size.toLong)),
                "agents" -> Json.arr(), "agentsInStanding" -> as.count(x => standing(x)._1 == "good").asJson,
                "note" -> "This owner has left the register. The agents it signed for keep their records and can be looked up by ID.".asJson,
                "ownerPublicKey" -> o.publicKey.asJson))
            }
          case Some(o) => repo.agentsOfOwner(o.customerId).flatMap(as =>
            jsonResp(Status.Ok, Json.obj("ok" -> true.asJson, "owner" -> ownerJson(o, Some(as.size.toLong)),
              "agents" -> (if (o.listed) as.map(agentJson(_, true)) else Nil).asJson,
              "agentsInStanding" -> as.count(x => standing(x)._1 == "good").asJson,
              "note" -> (if (o.listed) Json.Null else "This owner has not opted in to listing its agents. Look each agent up by its ID.".asJson),
              "ownerPublicKey" -> o.publicKey.asJson)))
        }

      case GET -> Root / "api" / "v1" / "register" / "stats" =>
        // The headline counts are production. Test agents are counted beside them, never folded in.
        repo.stats.flatMap { st =>
          jsonResp(Status.Ok, Json.obj("ok" -> true.asJson, "owners" -> st.owners.asJson, "agents" -> st.agents.asJson,
            "agentsInStanding" -> st.agentsInStanding.asJson, "receipts" -> st.receipts.asJson,
            "test" -> Json.obj("agents" -> st.testAgents.asJson, "agentsInStanding" -> st.testAgentsInStanding.asJson, "receipts" -> st.testReceipts.asJson),
            "all" -> Json.obj("agents" -> (st.agents + st.testAgents).asJson, "agentsInStanding" -> (st.agentsInStanding + st.testAgentsInStanding).asJson,
                              "receipts" -> (st.receipts + st.testReceipts).asJson)))
        }

      // ── the public checkpoint ──
      case GET -> Root / "api" / "v1" / "register" / "checkpoints" :? LimitQ(limit) => checkpoints match {
        case None => fail(Status.ServiceUnavailable, "Checkpoints are not configured on this register.")
        case Some(cp) => repo.checkpoints(limit.getOrElse(50).max(1).min(500)).flatMap(cs => jsonResp(Status.Ok, Json.obj("ok" -> true.asJson, "checkpoints" -> cs.map(cp.rowJson).asJson,
          "how" -> "Hourly, when anything moved: every agent's chain head, sorted by ID, folded into one Merkle root; sha256 of the statement is submitted to OpenTimestamps and written into Bitcoin. Check a proof with: ots verify -d <statementHash> checkpoint-<seq>.ots".asJson)))
      }
      case GET -> Root / "api" / "v1" / "register" / "checkpoints" / LongVar(seq) => checkpoints match {
        case None => fail(Status.ServiceUnavailable, "Checkpoints are not configured on this register.")
        case Some(cp) => (repo.checkpoint(seq), repo.checkpointLeaves(seq)).tupled.flatMap {
          case (Some(c), leaves) => jsonResp(Status.Ok, Json.obj("ok" -> true.asJson).deepMerge(cp.rowJson(c)).deepMerge(Json.obj(
            "statement" -> parser.parse(c.statement).getOrElse(Json.Null), "leaves" -> leaves.flatMap(parser.parse(_).toOption).getOrElse(Json.arr()),
            "leafRule" -> "sha256 of canonical [\"traceable-checkpoint-leaf\", id, headSeq, headHash]; nodes sha256(left ++ right); an odd last node pairs with itself".asJson)))
          case _ => fail(Status.NotFound, "No such checkpoint.")
        }
      }
      case GET -> Root / "api" / "v1" / "register" / "checkpoints" / LongVar(seq) / "proof.ots" =>
        repo.checkpointProof(seq).flatMap {
          case None => fail(Status.NotFound, "No proof for that checkpoint yet.")
          case Some(bytes) => Async[F].pure(Response[F](Status.Ok).withEntity(bytes).withHeaders(
            org.http4s.headers.`Content-Type`(MediaType.application.`octet-stream`),
            org.http4s.headers.`Content-Disposition`("attachment", Map(org.typelevel.ci.CIString("filename") -> s"checkpoint-$seq.ots"))))
        }
      case GET -> Root / "api" / "v1" / "register" / "agents" / id / "checkpoint" => checkpoints match {
        case None => fail(Status.ServiceUnavailable, "Checkpoints are not configured on this register.")
        case Some(cp) => repo.agentByAnyId(id).flatMap {
          case None => fail(Status.NotFound, "No agent with this ID is on the register.")
          case Some(a) => cp.coverage(a.did).flatMap {
            case None => jsonResp(Status.Ok, Json.obj("ok" -> true.asJson, "covered" -> false.asJson, "words" -> "No checkpoint covers this agent yet. The next hourly checkpoint will, once it has a receipt.".asJson))
            case Some(c) => jsonResp(Status.Ok, Json.obj("ok" -> true.asJson, "covered" -> true.asJson).deepMerge(c))
          }
        }
      }

      // ── the open door: another system issues IDs and writes receipts ──
      case GET -> Root / "api" / "v1" / "register" / "verifiers" =>
        (repo.verifiers, repo.selfIssuers).tupled.flatMap { case (vs, selfN) =>
          jsonResp(Status.Ok, Json.obj("ok" -> true.asJson, "verifiers" -> (Json.obj("id" -> "sheaf".asJson, "name" -> "Sheaf".asJson, "website" -> "https://sheaf.one".asJson, "status" -> "approved".asJson, "since" -> "2026-10-18".asJson) ::
            vs.filter(_.status != "self").map(v => Json.obj("id" -> v.did.asJson, "name" -> v.name.asJson, "website" -> v.website.asJson, "status" -> v.status.asJson, "since" -> v.createdAt.take(10).asJson))).asJson,
            "ownersIssuingDirectly" -> selfN.asJson,
            "note" -> "Entries from a registered verifier can be looked up by ID at once. They enter the public counts, search and the owners page once the register has approved the verifier. Owners that enter their own agents through /join can be looked up and searched at once; they join the owners page and the public counts once they have proved their domain. Their lookups say the owner issued the ID itself.".asJson))
        }
      case req @ POST -> Root / "api" / "v1" / "register" / "verifiers" => verifierWrite(req)(_.register(_).map(_.map(v =>
        Json.obj("verifier" -> Json.obj("id" -> v.did.asJson, "name" -> v.name.asJson, "website" -> v.website.asJson, "status" -> v.status.asJson)))))
      case req @ POST -> Root / "api" / "v1" / "register" / "entries" => verifierWrite(req)(_.entry(_).map(_.map(a =>
        Json.obj("agent" -> Json.obj("id" -> a.did.asJson, "fingerprint" -> a.fingerprint.asJson, "name" -> a.name.asJson, "environment" -> a.environment.asJson,
          "status" -> a.status.asJson, "lookup" -> ("https://traceableagents.org/a/" + a.fingerprint).asJson)))))
      // the direct door: an owner enters its own agent, no system in between
      case req @ POST -> Root / "api" / "v1" / "register" / "join" => verifierWrite(req)(_.join(_).map(_.map(a =>
        Json.obj("agent" -> Json.obj("id" -> a.did.asJson, "fingerprint" -> a.fingerprint.asJson, "name" -> a.name.asJson, "environment" -> a.environment.asJson,
          "status" -> a.status.asJson, "lookup" -> ("https://traceableagents.org/a/" + a.fingerprint).asJson),
          "note" -> "The owner is now the issuing system for its own agents. Write receipts to /receipts and standing to /entries/status with verifier = the owner's id, signed by the owner key.".asJson))))
      // owner verification by the owner itself, signed with the owner key
      case req @ POST -> Root / "api" / "v1" / "register" / "owners" / "verify" => verifierWrite(req)(_.verifyDomain(_))
      case req @ POST -> Root / "api" / "v1" / "register" / "owners" / "verify" / "check" => verifierWrite(req)(_.verifyCheck(_))
      case req @ POST -> Root / "api" / "v1" / "register" / "receipts" => verifierWrite(req)(_.receipts(_))
      case req @ POST -> Root / "api" / "v1" / "register" / "entries" / "status" => verifierWrite(req)(_.status(_).map(_.map(a =>
        Json.obj("agent" -> Json.obj("id" -> a.did.asJson, "fingerprint" -> a.fingerprint.asJson, "status" -> a.status.asJson)))))

      case GET -> Root / "api" / "v1" / "register" / "format" =>
        jsonResp(Status.Ok, Json.obj("ok" -> true.asJson, "v" -> 1.asJson,
          "id" -> "did:key (Ed25519, multicodec 0xed01, base58btc)".asJson,
          "fingerprint" -> "first 16 hex of sha256(public key)".asJson,
          "descriptor" -> "{v,type:'traceable-agent',id,owner,name,kind,environment,issuedAt,expiresAt,parent?} canonical JSON; environment is production or test, chosen by the owner at issue and fixed, signed by the owner key; a child (parent set) is signed by the parent agent's key as well".asJson,
          "lineage" -> "a child's descriptor names its parent; standing inherits: a revoked, retired or expired ancestor puts every descendant out of standing".asJson,
          "receipt" -> "sha256 of canonical [\"traceable-receipt\", id, seq, at, kind, decision, runId, actionHash, ledgerRowHash, prevHash], signed by the agent key; prevHash chains receipts, genesis is 64 zeros".asJson,
          "actionHash" -> "sha256(subject + \"\\n\" + input) kept by the owner; the register never holds the content".asJson,
          "lookup" -> "GET /api/v1/register/lookup?id=<did | fingerprint>".asJson,
          "check" -> "POST /api/v1/register/check {id} or {proof, challenge}: the lookup plus identityProof {checked, valid, reason} and a plain summary".asJson,
          "recordOfAction" -> "GET /api/v1/register/agents/<id>/record: the Record of Action (counts, last 90 days, sub-agents, checks, proofs), the Record Score, the story in plain words, and a 30-day timeline".asJson,
          "recordScore" -> TraceableAgents.ScoreFormula.asJson,
          "proof" -> "{v:1,type:'traceable-proof',id,challenge,audience?,at} canonical JSON signed by the agent key (Ed25519, base64); the challenge is the fresh random value the counterparty sent (the field may also be named nonce, its older name); valid for 10 minutes; the agent's verifier signs it on the agent's behalf, so the runtime never holds the key".asJson,
          "search" -> "GET /api/v1/register/search?q=<id | name>; names match listed owners only".asJson,
          "owners" -> "GET /api/v1/register/owners: the listed owners".asJson,
          "canonicalJson" -> "every signed body is JSON with keys sorted (recursively), no whitespace, UTF-8; signatures are Ed25519 over those bytes, base64".asJson,
          "self" -> "GET /api/v1/register/self: this register's name, address and id, and the peer registers it asks".asJson,
          "federation" -> "a lookup that finds nothing here is asked, once, of each peer register (GET <peer>/api/v1/register/lookup?id=…&local=1); the answer is used only after this register re-checks ownerSignature over the canonical descriptor with ownerPublicKey, which must be the key of descriptor.owner; the answer then carries register {url, name, id}, federated:true and verifiedHere:true".asJson,
          "verifiers" -> "GET /api/v1/register/verifiers: the systems that issue IDs and write receipts here, and whether the register has approved them".asJson,
          "registerVerifier" -> "POST /api/v1/register/verifiers {type:'traceable-verifier', id (did:key), name, website?, at, signature}: signature is the key named in id over the body minus signature".asJson,
          "entry" -> "POST /api/v1/register/entries {verifier, at, owner:{id, name, listed?}, agent:{descriptor, ownerSignature, parentSignature?}, signature}: the descriptor exactly as above, signed by the owner's key; the whole body signed by the verifier's key".asJson,
          "ownerVerify" -> "POST /api/v1/register/owners/verify {type:'traceable-verify', owner (did:key), domain, at, signature}: the owner key signs; returns the token to place in DNS (_traceableagents.<domain> TXT traceableagents-verify=<token>) or at /.well-known/traceable-agents.txt. Then POST /api/v1/register/owners/verify/check {type:'traceable-verify-check', owner, at, signature}".asJson,
          "join" -> "POST /api/v1/register/join {type:'traceable-join', at, owner:{id, name, website?, listed?}, agent:{descriptor, ownerSignature, parentSignature?}, signature}: the direct door, no system in between; the body is signed by the owner's key; the owner then writes receipts and standing for its own agents with verifier = its own id".asJson,
          "receipts" -> "POST /api/v1/register/receipts {verifier, at, agent, receipts:[{seq, at, kind, decision, runId?, actionHash?, ledgerRowHash, prevHash, hash, signature}], signature}: in chain order, seq from 1, prevHash the previous hash or 64 zeros, hash = sha256 of the receipt preimage, signature = the agent key over the hash bytes".asJson,
          "entryStatus" -> "POST /api/v1/register/entries/status {verifier, at, agent, status: retired|revoked, reason?, signature}".asJson,
          "verify" -> "GET /api/v1/register/agents/<id>/verify: recomputes the chain and checks every signature from the public keys; the same check for every verifier".asJson,
          "checkpoint" -> "hourly: every chain head (id, headSeq, headHash) sorted by id; leaf = sha256 of canonical [\"traceable-checkpoint-leaf\", id, headSeq, headHash]; Merkle root with sha256(left ++ right), odd last node paired with itself; statement {v:1,type:'traceable-checkpoint',at,agents,receipts,root,prevRoot}; sha256(statement) anchored in Bitcoin through OpenTimestamps. GET /api/v1/register/checkpoints, /checkpoints/<seq>, /checkpoints/<seq>/proof.ots, /agents/<id>/checkpoint".asJson))
    }
    CORS.policy.withAllowOriginAll.withAllowMethodsAll.withAllowHeadersAll.apply(r)
  }
}

/** The register's read side: standing, lineage, the owner card and the full lookup answer. Shared by the
  * public routes and by the agents' own check tool, so both say the same thing. */
class TraceableAgentsLookup[F[_]: Async](repo: TraceableAgentsRepository[F]) {
    def isExpired(expiresAt: String): Boolean =
      scala.util.Try(Instant.parse(expiresAt.take(19).replace(' ', 'T') + "Z").isBefore(Instant.now())).getOrElse(false)
    def standing(a: TaAgentRow): (String, String) = {
      a.status match {
        case "revoked" => ("revoked", "This ID was revoked by its owner. The record stays.")
        case "retired" => ("retired", "This ID was retired by its owner. The record stays.")
        case "pending" => ("pending", "Not yet issued: the owner holds its own key and has not signed this agent's descriptor.")
        case _ if isExpired(a.expiresAt) => ("expired", "This ID has not been renewed by its owner.")
        case _ => ("good", "In good standing.")
      }
    }
    /** Standing inherits: a child whose ancestor is out of standing is out of standing too. */
    def standingWith(a: TaAgentRow, ancestors: List[TaLineageRow]): (String, String) = {
      val own = standing(a)
      if (own._1 != "good") own
      else ancestors.collectFirst {
        case p if p.status == "revoked" => ("revoked", s"An ancestor's ID (${p.fingerprint}) was revoked. Nothing stands behind this agent.")
        case p if p.status == "retired" => ("retired", s"An ancestor's ID (${p.fingerprint}) was retired.")
        case p if isExpired(p.expiresAt) => ("expired", s"An ancestor's ID (${p.fingerprint}) has not been renewed.")
      }.getOrElse(own)
    }
    def lineageJson(l: TaLineageRow, listed: Boolean): Json = Json.obj(
      "id" -> l.did.asJson, "fingerprint" -> l.fingerprint.asJson, "name" -> (if (listed) l.name else "Agent " + l.fingerprint).asJson,
      "status" -> l.status.asJson, "depth" -> l.depth.asJson)

    // Names are shown only when the owner has opted in. Everything that proves identity and standing
    // is public regardless; what the owner calls itself and its agents is the owner's to disclose.
    // What the owner proved. The domain and company name are shown only when the owner shows its name at all.
    def proofJson(o: TaOwnerRow): Json = {
      val p = OwnerVerification.parseProofs(o.verifiedBy)
      Json.obj("kinds" -> p.kinds.asJson,
        "domain" -> (if (o.listed) p.domain else None).asJson,
        "company" -> (if (o.listed) p.company.map { case (n, num) => Json.obj("name" -> n.asJson, "number" -> num.asJson, "registry" -> "Companies House".asJson) } else None).asJson,
        "reviewed" -> p.reviewedAt.nonEmpty.asJson, "reviewedAt" -> p.reviewedAt.asJson,
        "email" -> p.emailAt.nonEmpty.asJson, "emailConfirmedAt" -> p.emailAt.asJson)   // the fact and the date, never the address
    }
    def ownerJson(o: TaOwnerRow, agentsIssued: Option[Long]): Json = Json.obj(
      "id" -> o.did.asJson, "name" -> (if (o.listed) o.displayName else "An owner on record").asJson, "listed" -> o.listed.asJson,
      "verification" -> o.verification.asJson, "proof" -> proofJson(o),
      "verifiedBy" -> (if (o.listed) o.verifiedBy else Some(OwnerVerification.parseProofs(o.verifiedBy).kinds.mkString(", ")).filter(_.nonEmpty)).asJson,
      "verifiedAt" -> o.verifiedAt.asJson, "since" -> o.joinedAt.getOrElse(o.createdAt).asJson,
      "onRegister" -> o.joined.asJson,
      "agentsIssued" -> agentsIssued.asJson)

    def agentJson(a: TaAgentRow, listed: Boolean, ancestors: List[TaLineageRow] = Nil): Json = {
      val (st, note) = standingWith(a, ancestors)
      Json.obj("id" -> a.did.asJson, "fingerprint" -> a.fingerprint.asJson, "name" -> (if (listed) a.name else "Agent " + a.fingerprint).asJson, "kind" -> a.kind.asJson,
        "status" -> a.status.asJson, "standing" -> st.asJson, "standingNote" -> note.asJson, "environment" -> a.environment.asJson,
        "issuedAt" -> a.issuedAt.asJson, "expiresAt" -> a.expiresAt.asJson, "statusAt" -> a.statusAt.asJson, "statusReason" -> a.statusReason.asJson,
        "parent" -> a.parentDid.asJson, "depth" -> a.depth.asJson)
    }

    def answer(a: TaAgentRow, o: Option[TaOwnerRow], ancestors: List[TaLineageRow] = Nil): (String, String) = {
      val (st, _) = standingWith(a, ancestors)
      o match {
        case None => ("identified", "Identified. No owner on record.")
        case Some(ow) if st != "good" => ("identified", s"Identified, but the ID is $st.")
        case Some(ow) if ow.verification == "verified" =>
          val p = OwnerVerification.parseProofs(ow.verifiedBy)
          val how = (if (ow.listed) p.domain.map(d => s"controls $d") else p.domain.map(_ => "controls its domain")).toList ++
            (if (ow.listed) p.company.map { case (n, _) => s"Companies House: $n" } else p.company.map(_ => "a company entry on record")).toList ++
            p.reviewedAt.map(_ => "reviewed by the register").toList
          ("identified", "Identified. Owner verified" + (if (how.isEmpty) "." else s" (${how.mkString("; ")})."))
        case Some(ow) if !ow.joined => ("identified", "Identified. The owner has since left the register; the record stays.")
        case Some(ow) if ow.verification == OwnerVerification.EmailTier => ("identified", "Identified. Owner on record with a confirmed email address; not yet verified.")
        case Some(_) => ("identified", "Identified. Owner on record, not yet verified.")
      }
    }

    /** (found, answer). Not found is still an answer: "unknown". */
    def lookupJson(id: String): F[(Boolean, Json)] =
      repo.agentByAnyId(id).flatMap {
        case None => Async[F].pure((false, Json.obj("ok" -> true.asJson, "status" -> "unknown".asJson,
          "answer" -> "Unknown. No agent with this ID is on the register.".asJson, "query" -> id.take(200).asJson)))
        case Some(a) =>
          (repo.owner(a.customerId), repo.summary(a.agentId), repo.receiptHead(a.agentId), repo.ancestors(a.did), repo.children(a.did), repo.record(a.agentId, a.did),
           a.verifierDid.fold(Async[F].pure(Option.empty[TaVerifierRow]))(repo.verifier)).tupled.flatMap { case (o, s, head, ups, kids, rec, ver) =>
            val self = ver.exists(_.status == "self")
            val issuedThrough = Json.obj("id" -> (if (self) "owner" else a.verifierDid.getOrElse("sheaf")).asJson,
              "name" -> (if (self) "Its owner" else ver.map(_.name).getOrElse("Sheaf")).asJson,
              "approved" -> ver.fold(true)(v => v.status == "approved" || v.status == "self").asJson,
              "self" -> self.asJson)
            val (status, ans) = answer(a, o, ups)
            val listed = o.exists(_.listed)
            o.fold(Async[F].pure(Option.empty[Long]))(ow => repo.agentsOfOwner(ow.customerId).map(l => Some(l.size.toLong))).map { n =>
              (true, Json.obj(
                "ok" -> true.asJson, "status" -> status.asJson, "answer" -> ans.asJson,
                "agent" -> agentJson(a, listed, ups).deepMerge(Json.obj("issuedThrough" -> issuedThrough)),
                "owner" -> o.map(ownerJson(_, n)).asJson,
                "lineage" -> Json.obj(
                  "depth" -> a.depth.asJson,
                  "parent" -> ups.headOption.map(lineageJson(_, listed)).asJson,
                  "ancestors" -> ups.map(lineageJson(_, listed)).asJson,
                  "root" -> ups.lastOption.map(lineageJson(_, listed)).asJson,
                  "children" -> kids.map(lineageJson(_, listed)).asJson),
                "record" -> Json.obj(
                  "receipts" -> s.receipts.asJson, "held" -> s.held.asJson, "released" -> s.released.asJson, "rejected" -> s.rejected.asJson,
                  "runs" -> s.runs.asJson, "firstAt" -> s.firstAt.asJson, "lastAt" -> s.lastAt.asJson, "lastHeldAt" -> s.lastHeldAt.asJson,
                  "headSeq" -> head.map(_._1).asJson, "headHash" -> head.map(_._2).asJson),
                "recordOfAction" -> recordOfActionJson(a, rec, head),
                "proof" -> Json.obj(
                  "descriptor" -> parser.parse(a.descriptorJson).getOrElse(Json.Null),
                  "ownerSignature" -> a.ownerSignature.asJson,
                  "parentSignature" -> a.parentSignature.asJson,
                  "ownerPublicKey" -> o.map(_.publicKey).asJson,
                  "agentPublicKey" -> a.publicKey.asJson,
                  "signatureAlgorithm" -> "Ed25519".asJson, "hashAlgorithm" -> "sha256".asJson,
                  "descriptorCanonicalisation" -> "JSON, sorted keys, no whitespace (RFC 8785 style)".asJson,
                  "receiptPreimage" -> "[\"traceable-receipt\", id, seq, at, kind, decision, runId, actionHash, ledgerRowHash, prevHash]".asJson)))
            }
          }
      }

    /** The Record of Action: the numbers, the score, and the career in plain words. */
    def recordOfActionJson(a: TaAgentRow, r: TaRecord, head: Option[(Long, String)]): Json = {
      val score = TraceableAgents.recordScore(r.receipts, r.held, r.rejected, r.rejected90)
      Json.obj(
        "score" -> score.asJson, "scoreWords" -> TraceableAgents.scoreWords(score).asJson,
        "scoreFormula" -> TraceableAgents.ScoreFormula.asJson,
        "story" -> story(a, r, score).asJson,
        "actions" -> r.receipts.asJson, "held" -> r.held.asJson, "released" -> r.released.asJson, "rejected" -> r.rejected.asJson,
        "runs" -> r.runs.asJson, "subAgents" -> r.subAgents.asJson, "checksOfOthers" -> r.checks.asJson, "proofsGiven" -> r.proofs.asJson,
        "last90" -> Json.obj("actions" -> r.acts90.asJson, "held" -> r.held90.asJson, "rejected" -> r.rejected90.asJson),
        "firstAt" -> r.firstAt.asJson, "lastAt" -> r.lastAt.asJson, "lastHeldAt" -> r.lastHeldAt.asJson, "lastRejectedAt" -> r.lastRejectedAt.asJson,
        "headSeq" -> head.map(_._1).asJson, "headHash" -> head.map(_._2).asJson)
    }

    /** The career in one paragraph, the way a person would tell it. */
    def story(a: TaAgentRow, r: TaRecord, score: Option[Int]): String = {
      def month(iso: String): String = scala.util.Try {
        val d = java.time.Instant.parse(iso.take(19).replace(' ', 'T') + "Z").atZone(java.time.ZoneOffset.UTC)
        d.getMonth.getDisplayName(java.time.format.TextStyle.FULL, java.util.Locale.UK) + " " + d.getYear
      }.getOrElse(iso.take(10))
      val who = if (a.environment == "test") s"${a.name} (a test agent)" else a.name
      if (r.receipts == 0) s"$who was issued in ${month(a.issuedAt)} and has not yet acted through a verifier. There is nothing on its record, for or against it."
      else {
        val sb = new StringBuilder
        sb ++= s"$who has acted ${r.receipts} time${if (r.receipts == 1) "" else "s"} on record since ${r.firstAt.map(month).getOrElse("it was issued")}"
        sb ++= (if (r.held == 0) ", and has never been held for a person" else s", and was held for a person ${r.held} time${if (r.held == 1) "" else "s"}")
        if (r.held > 0) sb ++= s": ${r.released} released, ${r.rejected} rejected"
        sb ++= ". "
        if (r.rejected > 0 && r.rejected90 == 0) sb ++= "No rejection in the last 90 days. "
        else if (r.rejected90 > 0) sb ++= s"${r.rejected90} rejection${if (r.rejected90 == 1) "" else "s"} in the last 90 days. "
        if (r.subAgents > 0) sb ++= s"It has started ${r.subAgents} sub-agent${if (r.subAgents == 1) "" else "s"} of its own. "
        if (r.checks > 0) sb ++= s"It checked other agents' records ${r.checks} time${if (r.checks == 1) "" else "s"} before dealing with them. "
        if (r.proofs > 0) sb ++= s"It proved its identity to others ${r.proofs} time${if (r.proofs == 1) "" else "s"}. "
        sb ++= s"Record Score ${score.getOrElse(0)}: ${TraceableAgents.scoreWords(score)}."
        sb.toString
      }
    }

    /** The lookup in a few plain sentences, for an agent that is deciding whether to deal with another. */
    def plainWords(j: Json): String = {
      val c = j.hcursor
      if (c.get[String]("status").toOption.contains("unknown")) c.get[String]("answer").getOrElse("Unknown.")
      else {
        val a = c.downField("agent"); val o = c.downField("owner"); val l = c.downField("lineage")
        val name = a.get[String]("name").getOrElse("?"); val fp = a.get[String]("fingerprint").getOrElse("?")
        val st = a.get[String]("standing").getOrElse("?"); val note = a.get[String]("standingNote").getOrElse("")
        val env = a.get[String]("environment").toOption.filter(_ == "test").fold("")(_ => " This is a TEST agent, so marked by its owner.")
        val self = a.downField("issuedThrough").get[Boolean]("self").toOption.contains(true)
        val owner = o.get[String]("name").toOption.map(n => s"owned by $n (" + OwnerVerification.tierLabel(o.get[String]("verification").getOrElse("?")) + ")").getOrElse("no owner on record") +
          (if (self) ". The owner issued this ID itself and holds the agent's key, so its receipts are the owner's own report" else "")
        val depth = l.get[Int]("depth").getOrElse(0)
        val root = l.downField("root").get[String]("name").toOption
        val roa = c.downField("recordOfAction")
        val story = roa.get[String]("story").getOrElse("")
        s"$name ($fp): standing $st. $note$env $owner. " + (if (depth > 0) s"A sub-agent at depth $depth" + root.fold("")(n => s" under $n") + ". " else "") + s"Record of Action: $story"
      }
    }

}
