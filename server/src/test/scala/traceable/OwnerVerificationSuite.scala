package traceable
import munit.FunSuite
import java.net.InetAddress
import OwnerVerification._

/** The pure parts of owner verification: what may be claimed, what the checker refuses, how a match is read. */
class OwnerVerificationSuite extends FunSuite {

  test("a plain domain is accepted and normalised; schemes, paths, ports, IPs and single labels are not") {
    assertEquals(normaliseHost(" Example.COM. "), Right("example.com"))
    assertEquals(normaliseHost("https://sheaf.one/"), Right("sheaf.one"))
    assertEquals(normaliseHost("bücher.example"), Right("xn--bcher-kva.example"))
    assert(normaliseHost("example.com/path").isLeft)
    assert(normaliseHost("example.com:8443").isLeft)
    assert(normaliseHost("user@example.com").isLeft)
    assert(normaliseHost("localhost").isLeft)
    assert(normaliseHost("10.0.0.1").isLeft)
    assert(normaliseHost("169.254.169.254").isLeft)
    assert(normaliseHost("").isLeft)
    assert(normaliseHost("-bad.example.com").isLeft)
  }

  test("private, loopback, link-local and metadata addresses are refused; public ones pass") {
    List("127.0.0.1", "10.0.0.1", "172.16.5.5", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fc00::1", "fe80::1")
      .foreach(a => assert(isForbidden(InetAddress.getByName(a)), a))
    List("8.8.8.8", "3.136.82.174", "2606:4700::1111").foreach(a => assert(!isForbidden(InetAddress.getByName(a)), a))
  }

  test("the TXT record matches quoted, split and spaced forms, and nothing else") {
    val tok = "0123456789abcdef0123456789abcdef"
    assert(txtMatches(List("\"traceableagents-verify=" + tok + "\""), tok))
    assert(txtMatches(List("other", "traceableagents-verify=" + tok), tok))
    assert(txtMatches(List("\"traceableagents-verify=0123456789abcdef\" \"0123456789abcdef\""), tok))
    assert(!txtMatches(List("traceableagents-verify=" + tok + "ff"), tok))
    assert(!txtMatches(Nil, tok))
    assertEquals(recordName("example.com"), "_traceableagents.example.com")
  }

  test("the well-known file matches the token line with BOM and whitespace, and not a different token") {
    val tok = "abc123"
    assert(fileMatches("﻿traceableagents-verify=abc123\r\n", tok))
    assert(fileMatches("# ours\n  abc123  \n", tok))
    assert(!fileMatches("traceableagents-verify=abc124", tok))
    assert(!fileMatches("<html>abc123</html>", tok))
  }

  test("Companies House numbers are padded to eight digits; prefixed forms are kept; junk is refused") {
    assertEquals(normaliseCompanyNumber("1234567"), Right("01234567"))
    assertEquals(normaliseCompanyNumber(" sc123456 "), Right("SC123456"))
    assertEquals(normaliseCompanyNumber("12345678"), Right("12345678"))
    assert(normaliseCompanyNumber("123456789").isLeft)
    assert(normaliseCompanyNumber("Sheaf Labs").isLeft)
    assert(normaliseCompanyNumber("").isLeft)
  }

  test("the proof summary round-trips through verified_by and says when an owner counts as verified") {
    val p = Proofs(Some("sheaf.one"), Some(("Sheaf Labs Ltd", "12345678")), Some("2026-10-21"))
    assertEquals(parseProofs(Some(p.encode)), p)
    assertEquals(p.kinds, List("domain", "company", "reviewed"))
    assert(Proofs(None, None, Some("2026-10-21")).verified)
    assert(Proofs(Some("x.com"), None, None).verified)
    assert(!Proofs(None, Some(("A", "1")), None).verified)
    assertEquals(parseProofs(None), Proofs(None, None, None))
    assertEquals(parseProofs(Some("garbage")), Proofs(None, None, None))
    // a company name with the separator characters cannot break the encoding
    val q = Proofs(None, Some(("Odd|Name#Ltd", "SC000001")), Some("2026-01-01"))
    assertEquals(parseProofs(Some(q.encode)).company.map(_._2), Some("SC000001"))
  }
}
