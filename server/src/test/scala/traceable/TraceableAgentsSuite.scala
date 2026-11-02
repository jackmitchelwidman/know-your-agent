package traceable
import munit.FunSuite
import io.circe.parser
import TraceableAgents._
import io.circe.syntax._
import io.circe.Json

/** Keys, IDs and the double-signed descriptor of a child agent. Pure; no database. */
class TraceableAgentsSuite extends FunSuite {

  test("did:key round-trips the public key and the fingerprint is 16 hex") {
    val kp = generate()
    val did = didKey(kp.publicKey)
    assert(did.startsWith("did:key:z6Mk"), did)
    assertEquals(publicKeyOf(did).map(_.toSeq), Some(kp.publicKey.toSeq))
    assert(fingerprint(kp.publicKey).matches("[0-9a-f]{16}"))
  }

  test("a child's descriptor names its parent and verifies under both the owner's and the parent's key") {
    val owner = generate(); val parent = generate(); val child = generate()
    val ownerDid = didKey(owner.publicKey); val parentDid = didKey(parent.publicKey); val childDid = didKey(child.publicKey)
    val desc = descriptor(childDid, ownerDid, "worker-7", "agent", "2026-10-18T12:00:00Z", "2027-10-18T12:00:00Z", Some(parentDid))
    assertEquals(desc.hcursor.get[String]("parent").toOption, Some(parentDid))
    val bytes = canonicalBytes(desc)
    val ownerSig = sign(owner.privateKey, bytes)
    val parentSig = sign(parent.privateKey, bytes)
    assert(verify(publicKeyOf(ownerDid).get, bytes, ownerSig), "owner signature")
    assert(verify(publicKeyOf(parentDid).get, bytes, parentSig), "parent signature")
    // A stranger's key does not vouch for it.
    assert(!verify(generate().publicKey, bytes, parentSig))
    // The canonical form is stable: re-parsing and re-printing gives the same bytes, so a verifier can recompute them.
    val again = canonicalBytes(parser.parse(new String(bytes, "UTF-8")).toOption.get)
    assertEquals(again.toSeq, bytes.toSeq)
  }

  test("a root agent's descriptor has no parent field, and says whether it is production or test") {
    val owner = generate(); val a = generate()
    val desc = descriptor(didKey(a.publicKey), didKey(owner.publicKey), "root", "agent", "2026-10-18T12:00:00Z", "2027-10-18T12:00:00Z")
    assert(desc.hcursor.get[String]("parent").toOption.isEmpty)
    assertEquals(desc.hcursor.get[String]("environment").toOption, Some("test"))
    val prod = descriptor(didKey(a.publicKey), didKey(owner.publicKey), "root", "agent", "2026-10-18T12:00:00Z", "2027-10-18T12:00:00Z", None, "production")
    assertEquals(prod.hcursor.get[String]("environment").toOption, Some("production"))
  }
}

class HostedProgressSuite extends FunSuite {
  import io.circe.generic.auto._
  import HostedAgentService.Progress
  test("old progress JSON without stoppedBecause or incomplete decodes") {
    val old = """{"task":"t","steps":[],"done":false,"answer":null,"heldActionId":null}"""
    val p = parser.parse(old).flatMap(_.as[Progress])
    assert(p.isRight, p.toString)
    assertEquals(p.toOption.get.stoppedBecause, None)
    assertEquals(p.toOption.get.incomplete, false)
  }
  test("a stopped run is done, incomplete, and carries the reason") {
    val p = HostedAgentService.stopped(Progress("t", Nil, done = false, None, None), "Stopped before step 3: cap reached.")
    assert(p.done && p.incomplete)
    assertEquals(p.stoppedBecause, Some("Stopped before step 3: cap reached."))
    val again = parser.parse(p.asJson.noSpaces).flatMap(_.as[Progress])
    assertEquals(again.toOption.map(_.stoppedBecause), Some(Some("Stopped before step 3: cap reached.")))
  }
}

/** The handshake's proof: signed by the agent key, bound to the challenge the counterparty issued, fresh. */
class TraceableProofSuite extends FunSuite {
  import TraceableAgents._
  private def proofFor(kp: KeyPair, challenge: String, at: String = java.time.Instant.now().toString, field: String = ChallengeField): Json = {
    val did = didKey(kp.publicKey)
    val doc = proofDoc(did, challenge, Some("did:key:zAudience"), at, field)
    doc.deepMerge(Json.obj("signature" -> Json.fromString(b64(sign(kp.privateKey, canonicalBytes(doc))))))
  }
  test("a proof checks out against the challenge the counterparty sent") {
    val kp = generate()
    assertEquals(checkProof(proofFor(kp, "n-123"), Some("n-123")), Right(didKey(kp.publicKey)))
  }
  test("a proof for another challenge, a stale proof, and a stranger's signature are all refused") {
    val kp = generate()
    assertEquals(checkProof(proofFor(kp, "n-123"), Some("n-999")), Left("the challenge is not the one you issued"))
    val old = java.time.Instant.now().minusSeconds(3600).toString
    assertEquals(checkProof(proofFor(kp, "n-123", old), Some("n-123")), Left("the proof is stale"))
    val forged = proofFor(kp, "n-123").deepMerge(Json.obj("id" -> Json.fromString(didKey(generate().publicKey))))
    assertEquals(checkProof(forged, Some("n-123")), Left("the signature does not match the id"))
  }
  test("without an expected challenge the proof is still checked for signature and freshness") {
    val kp = generate()
    assert(checkProof(proofFor(kp, "whatever"), None).isRight)
  }
  test("a proof signed under the older field name, nonce, still checks out") {
    val kp = generate()
    assert(checkProof(proofFor(kp, "n-old", field = LegacyChallengeField), Some("n-old")).isRight)
    assertEquals(checkProof(proofFor(kp, "n-old", field = LegacyChallengeField), Some("n-new")), Left("the challenge is not the one you issued"))
  }
}
