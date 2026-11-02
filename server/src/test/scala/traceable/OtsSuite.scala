package traceable
import cats.effect.IO
import munit.CatsEffectSuite
import org.http4s.ember.client.EmberClientBuilder

/**
 * OpenTimestamps wire format. The pure tests run offline. The live test submits a throwaway digest
 * to the public calendars and writes the proof to OTS_OUT (if set) so the reference `ots` client can
 * be run on what this code produces; that is the check that matters.
 */
class OtsSuite extends CatsEffectSuite {
  private def sha(s: String) = java.security.MessageDigest.getInstance("SHA-256").digest(s.getBytes("UTF-8"))

  test("varuint round-trips like LEB128") {
    for (v <- List(0L, 1L, 127L, 128L, 300L, 16384L, 912345L, Long.MaxValue)) {
      val w = new Ots.Writer; w.varuint(v)
      assertEquals(new Ots.Reader(w.result).varuint(), v, s"v=$v")
    }
    val w = new Ots.Writer; w.varuint(300L)
    assertEquals(Ots.toHex(w.result), "ac02")   // 300 = 0xAC 0x02 in LEB128
  }

  test("a fresh proof file parses back to its digest and a pending attestation, and re-serialises byte-identical") {
    val digest = sha("fixture")
    // A hand-built calendar response: sha256 op, then append(x), then a pending attestation at a.pool.
    val w = new Ots.Writer
    w.byte(0x08)
    w.byte(0xf0); w.varbytes(Ots.hex("0102030405"))
    w.byte(0x00); Ots.writeAttestation(w, Ots.Pending("https://a.pool.opentimestamps.org"))
    val calendarBytes = w.result
    val file = Ots.buildFile(digest, calendarBytes)
    val p = Ots.parseFile(file)
    assert(java.util.Arrays.equals(p.digest, digest))
    assertEquals(p.pendingUris, List("https://a.pool.opentimestamps.org"))
    assertEquals(p.bitcoinHeights, Nil)
    // The commitment the calendar attests: sha256(digest) ++ 0102030405
    val expectedCommit = java.security.MessageDigest.getInstance("SHA-256").digest(digest) ++ Ots.hex("0102030405")
    assert(p.ts.pending.exists { case (c, _, _) => java.util.Arrays.equals(c, expectedCommit) })
    assert(java.util.Arrays.equals(Ots.writeFile(p), file), "serialiser must reproduce the file byte for byte")
  }

  test("merging a Bitcoin path into the pending node yields a proof with a block height, ordered like the reference client") {
    val digest = sha("fixture2")
    val w = new Ots.Writer
    w.byte(0x08); w.byte(0x00); Ots.writeAttestation(w, Ots.Pending("https://b.pool.opentimestamps.org"))
    val p = Ots.parseFile(Ots.buildFile(digest, w.result))
    val (commit, node, _) = p.ts.pending.head
    // What the calendar's /timestamp/<commit> would return: prepend(y) → sha256 → Bitcoin attestation.
    val up = new Ots.Writer
    up.byte(0xf1); up.varbytes(Ots.hex("aa")); up.byte(0x08); up.byte(0x00); Ots.writeAttestation(up, Ots.Bitcoin(912345L))
    val sub = Ots.readTimestamp(new Ots.Reader(up.result), Some(commit))
    assert(node.merge(sub))
    assertEquals(p.bitcoinHeights, List(912345L))
    val out = Ots.parseFile(Ots.writeFile(p))          // must still parse
    assertEquals(out.bitcoinHeights, List(912345L))
    assertEquals(out.pendingUris, List("https://b.pool.opentimestamps.org"))
    // Reference ordering at a node with both an attestation and ops: ff 00 <attestation> then the op.
    val bytes = Ots.writeFile(p)
    val afterDigest = bytes.drop(Ots.HeaderMagic.length + 1 + 1 + 32)
    assertEquals(afterDigest(0) & 0xff, 0x08)                    // sha256 op from the digest
    assertEquals(afterDigest(1) & 0xff, 0xff); assertEquals(afterDigest(2) & 0xff, 0x00)  // then: pending attestation first, more follows
  }

  test("FIXTURE: a real, complete proof re-serialises byte-identical (set OTS_FIXTURES=<dir of .ots files>)") {
    val dir = sys.env.get("OTS_FIXTURES")
    assume(dir.isDefined, "set OTS_FIXTURES to run")
    val files = java.nio.file.Files.list(java.nio.file.Paths.get(dir.get)).toArray.map(_.toString).filter(_.endsWith(".ots")).sorted
    assert(files.nonEmpty, "no .ots fixtures found")
    files.foreach { f =>
      val bytes = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(f))
      val p = Ots.parseFile(bytes)
      val out = Ots.writeFile(p)
      println(s"[ots-fixture] ${f.split('/').last}: bitcoin=${p.bitcoinHeights.mkString(",")} pending=${p.pendingUris.size} identical=${java.util.Arrays.equals(out, bytes)}")
      assert(java.util.Arrays.equals(out, bytes), s"$f: re-serialisation differs")
    }
  }

  test("LIVE: the public calendars accept a digest and the proof we build carries their pending attestation") {
    val out = sys.env.get("OTS_OUT")
    assume(out.isDefined, "set OTS_OUT=<path> to run the live calendar test")
    val digest = sha(s"sheaf-ots-live-${System.currentTimeMillis()}")
    EmberClientBuilder.default[IO].build.use { http =>
      new OtsClient[IO](http, OtsClient.DefaultCalendars).stamp(digest).map {
        case Left(e) => fail(s"no calendar accepted: $e")
        case Right((cal, file)) =>
          val p = Ots.parseFile(file)
          assert(java.util.Arrays.equals(p.digest, digest))
          assert(p.pendingUris.nonEmpty, "pending attestation expected")
          assert(java.util.Arrays.equals(Ots.writeFile(p), file), "re-serialising the calendar's real response must be byte-identical")
          java.nio.file.Files.write(java.nio.file.Paths.get(out.get), file)
          java.nio.file.Files.write(java.nio.file.Paths.get(out.get + ".digest"), Ots.toHex(digest).getBytes)
          println(s"[ots-live] $cal accepted; pending at ${p.pendingUris.mkString(",")}; wrote ${out.get}")
      }
    }
  }
}
