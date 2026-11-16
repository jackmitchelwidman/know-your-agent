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
  test("when the checker says who the proof must be for, a proof for anyone else is refused") {
    val kp = generate()
    assert(checkProof(proofFor(kp, "n-1"), Some("n-1"), expectedAudience = Some("did:key:zAudience")).isRight)
    assertEquals(checkProof(proofFor(kp, "n-1"), Some("n-1"), expectedAudience = Some("did:key:zOther")), Left("the proof was made for someone else"))
    val did = didKey(kp.publicKey)
    val bare = proofDoc(did, "n-1", None, java.time.Instant.now().toString)
    val nobody = bare.deepMerge(Json.obj("signature" -> Json.fromString(b64(sign(kp.privateKey, canonicalBytes(bare))))))
    assert(checkProof(nobody, Some("n-1")).isRight)
    assertEquals(checkProof(nobody, Some("n-1"), expectedAudience = Some("did:key:zAudience")), Left("the proof does not say who it is for"))
  }
  private val door = "https://tools.example.com/pay"
  private def requestProofFor(kp: KeyPair, audience: String = door, at: String = java.time.Instant.now().toString): Json = {
    val doc = requestProofDoc(didKey(kp.publicKey), audience, "0123456789abcdef", at)
    doc.deepMerge(Json.obj("signature" -> Json.fromString(b64(sign(kp.privateKey, canonicalBytes(doc))))))
  }
  test("a request proof is good at the address it names, for a minute") {
    val kp = generate()
    assertEquals(checkRequestProof(requestProofFor(kp), door), Right(didKey(kp.publicKey)))
    assertEquals(checkRequestProof(requestProofFor(kp), "https://tools.example.com/refund"), Left("the proof was made for another address"))
    assertEquals(checkRequestProof(requestProofFor(kp), "https://other.example.com/pay"), Left("the proof was made for another address"))
    val old = java.time.Instant.now().minusSeconds(61).toString
    assertEquals(checkRequestProof(requestProofFor(kp, at = old), door), Left("the proof is stale"))
    val ahead = java.time.Instant.now().plusSeconds(30).toString
    assertEquals(checkRequestProof(requestProofFor(kp, at = ahead), door), Left("the proof is dated in the future"))
    val forged = requestProofFor(kp).deepMerge(Json.obj("id" -> Json.fromString(didKey(generate().publicKey))))
    assertEquals(checkRequestProof(forged, door), Left("the signature does not match the id"))
  }
  test("a challenge answer cannot be passed off as a request proof, even when it names the door") {
    val kp = generate()
    val did = didKey(kp.publicKey)
    val doc = proofDoc(did, "0123456789abcdef", Some(door), java.time.Instant.now().toString)
    val answer = doc.deepMerge(Json.obj("signature" -> Json.fromString(b64(sign(kp.privateKey, canonicalBytes(doc))))))
    assertEquals(checkRequestProof(answer, door), Left("this is not a request proof"))
    // relabelled as a request proof, its signature no longer covers what is checked
    val relabelled = answer.deepMerge(Json.obj("type" -> Json.fromString(RequestProofType), "nonce" -> Json.fromString("0123456789abcdef")))
    assertEquals(checkRequestProof(relabelled, door), Left("the signature does not match the id"))
    // and a request proof is no answer to a challenge
    assertEquals(checkProof(requestProofFor(kp), None), Left("this is a request proof, which answers no challenge"))
  }
  test("checkAnyProof sends each kind to its own check, and a request proof needs the audience") {
    val kp = generate()
    assertEquals(checkAnyProof(requestProofFor(kp), None, Some(door)), Right(didKey(kp.publicKey)))
    assertEquals(checkAnyProof(requestProofFor(kp), None, None), Left("send the audience: the address the request was made to"))
    assert(checkAnyProof(proofFor(kp, "n-1"), Some("n-1"), None).isRight)
    assertEquals(checkAnyProof(proofFor(kp, "n-1"), Some("n-1"), Some("did:key:zOther")), Left("the proof was made for someone else"))
  }
  test("the header value is the signed proof, base64url") {
    val kp = generate()
    val p = requestProofFor(kp)
    val value = java.util.Base64.getUrlEncoder.withoutPadding.encodeToString(p.noSpaces.getBytes("UTF-8"))
    assertEquals(decodeRequestProofHeader(value), Right(p))
    assert(decodeRequestProofHeader("not base64 !!").isLeft)
  }
  test("an address has one written form") {
    assertEquals(canonicalAudience("HTTPS://Tools.Example.com:443/Pay?x=1#frag"), Some("https://tools.example.com/Pay"))
    assertEquals(canonicalAudience("http://localhost:8080"), Some("http://localhost:8080/"))
    assertEquals(canonicalAudience("http://example.com:80/a/"), Some("http://example.com/a/"))
    assertEquals(canonicalAudience("ftp://example.com/a"), None)
    assertEquals(canonicalAudience("not a url"), None)
  }
  test("a proof signed under the older field name, nonce, still checks out") {
    val kp = generate()
    assert(checkProof(proofFor(kp, "n-old", field = LegacyChallengeField), Some("n-old")).isRight)
    assertEquals(checkProof(proofFor(kp, "n-old", field = LegacyChallengeField), Some("n-new")), Left("the challenge is not the one you issued"))
  }
}
