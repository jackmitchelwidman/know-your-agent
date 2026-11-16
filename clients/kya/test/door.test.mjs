// Run: node --test clients/kya/test/
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { createServer } from "node:http";
import { door, proofHeader, requestProof, checkRequestProof, canonicalAudience, decodeHeader, HEADER } from "../lib/door.mjs";

const key = () => generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "pem" });
const ORIGIN = "https://tools.acme.example";
const URL_PAY = ORIGIN + "/pay";
// A register that knows the agents it is told about.
const registerOf = entries => { const calls = []; const f = async url => { calls.push(url); const id = decodeURIComponent(String(url).split("id=")[1]); const e = entries[id];
  return e === "down" ? Promise.reject(new Error("down")) : e ? { status: 200, json: async () => ({ status: "identified", agent: { id, standing: e.standing || "good", name: "a" }, owner: { verification: e.verification || "unverified" } }) } : { status: 404, json: async () => ({ status: "unknown" }) }; };
  f.calls = calls; return f; };
const idOf = k => requestProof(k, URL_PAY).id;

test("an address has one written form", () => {
  assert.equal(canonicalAudience("HTTPS://Tools.Example.com:443/Pay?x=1#frag"), "https://tools.example.com/Pay");
  assert.equal(canonicalAudience("http://localhost:8080"), "http://localhost:8080/");
  assert.equal(canonicalAudience("http://example.com:80/a/"), "http://example.com/a/");
  assert.equal(canonicalAudience("ftp://example.com/a"), null);
  assert.equal(canonicalAudience("not a url"), null);
});

test("a proof is good at the address it names, for a minute", () => {
  const k = key(), p = requestProof(k, URL_PAY + "?invoice=7");
  assert.equal(p.audience, URL_PAY);
  assert.deepEqual(checkRequestProof(p, URL_PAY), { ok: true, id: p.id });
  assert.equal(checkRequestProof(p, ORIGIN + "/refund").reason, "the proof was made for another address");
  assert.equal(checkRequestProof(p, "https://other.example/pay").reason, "the proof was made for another address");
  assert.equal(checkRequestProof(p, URL_PAY, { now: Date.now() + 62_000 }).reason, "the proof is stale");
  assert.equal(checkRequestProof(p, URL_PAY, { now: Date.now() - 30_000 }).reason, "the proof is dated in the future");
  assert.equal(checkRequestProof({ ...p, id: idOf(key()) }, URL_PAY).reason, "the signature does not match the id");
  assert.equal(checkRequestProof({ ...p, type: "traceable-proof" }, URL_PAY).reason, "this is not a request proof");
  assert.deepEqual(decodeHeader(proofHeader(k, URL_PAY)).audience, URL_PAY);
  assert.equal(decodeHeader("%%%"), null);
});

test("the door lets in an agent on the register and refuses one with no header, a wrong address or a used proof", async () => {
  const k = key(), reg = registerOf({ [idOf(k)]: {} });
  const d = door({ origin: ORIGIN, fetch: reg });
  assert.equal((await d.check({ path: "/pay", headers: {} })).decision, "refuse");
  const h = proofHeader(k, URL_PAY);
  const first = await d.check({ path: "/pay?invoice=7", headers: { "kya-proof": h } });
  assert.equal(first.decision, "allow"); assert.equal(first.id, idOf(k));
  const again = await d.check({ path: "/pay", headers: { "KYA-Proof": h } });
  assert.equal(again.decision, "refuse"); assert.equal(again.reason, "this proof was already used");
  const elsewhere = await d.check({ path: "/refund", headers: { [HEADER]: proofHeader(k, URL_PAY) } });
  assert.equal(elsewhere.reason, "the proof was made for another address");
  // a proof made for another service is refused whatever Host the request claims
  const other = door({ origin: "https://other.example", fetch: reg });
  assert.equal((await other.check({ path: "/pay", headers: { host: "tools.acme.example", [HEADER]: proofHeader(k, URL_PAY) } })).decision, "refuse");
  // the register is asked once a minute for one agent
  await d.check({ path: "/pay", headers: { [HEADER]: proofHeader(k, URL_PAY) } });
  assert.equal(reg.calls.length, 1);
});

test("unknown, unverified and revoked agents; approval; holding", async () => {
  const known = key(), stranger = key(), revoked = key(), verified = key();
  const reg = registerOf({ [idOf(known)]: {}, [idOf(revoked)]: { standing: "revoked" }, [idOf(verified)]: { verification: "verified" } });
  const go = (d, k) => d.check({ path: "/pay", headers: { [HEADER]: proofHeader(k, URL_PAY) } });
  const plain = door({ origin: ORIGIN, fetch: reg });
  assert.equal((await go(plain, stranger)).reason, "it is not on the register");
  assert.equal((await go(plain, revoked)).reason, "the register says this agent is revoked");
  const strict = door({ origin: ORIGIN, require: "verified", fetch: reg });
  assert.equal((await go(strict, known)).reason, "its owner is not verified");
  assert.equal((await go(strict, verified)).decision, "allow");
  const held = []; const approved = new Set();
  const holding = door({ origin: ORIGIN, require: "verified", fetch: reg, approved, onHold: h => held.push(h) });
  const h1 = await go(holding, known);
  assert.equal(h1.decision, "hold"); assert.equal(held.length, 1); assert.equal(held[0].id, idOf(known));
  approved.add(idOf(known));
  assert.equal((await go(holding, known)).decision, "allow");
  approved.add(idOf(revoked));
  assert.equal((await go(holding, revoked)).decision, "refuse");
  assert.equal((await go(door({ origin: ORIGIN, require: "proof", fetch: reg }), stranger)).decision, "allow");
});

test("when the register cannot be reached the door refuses, except for approved agents", async () => {
  const k = key(), reg = registerOf({ [idOf(k)]: "down" });
  const go = d => d.check({ path: "/pay", headers: { [HEADER]: proofHeader(k, URL_PAY) } });
  assert.equal((await go(door({ origin: ORIGIN, fetch: reg }))).decision, "refuse");
  assert.equal((await go(door({ origin: ORIGIN, fetch: reg, approved: [idOf(k)] }))).decision, "allow");
});

test("the origin is the service's own setting", () => {
  assert.throws(() => door({}));
  assert.throws(() => door({ origin: "https://tools.acme.example/api" }));
  assert.equal(door({ origin: "HTTPS://Tools.Acme.Example:443" }).origin, ORIGIN);
});

test("as middleware on a Node server", async () => {
  const k = key();
  const srv = createServer();
  await new Promise(r => srv.listen(0, "127.0.0.1", r));
  const origin = "http://127.0.0.1:" + srv.address().port;
  const guard = door({ origin, fetch: registerOf({ [idOf(k)]: {} }) }).middleware();
  srv.on("request", (req, res) => guard(req, res, () => { res.writeHead(200, { "content-type": "text/plain" }); res.end("hello " + req.kya.id); }));
  try {
    const no = await fetch(origin + "/pay");
    assert.equal(no.status, 401); assert.equal((await no.json()).expected.audience, origin + "/pay");
    const yes = await fetch(origin + "/pay?x=1", { headers: { [HEADER]: proofHeader(k, origin + "/pay?x=1") } });
    assert.equal(yes.status, 200); assert.equal(await yes.text(), "hello " + idOf(k));
  } finally { srv.close(); }
});
