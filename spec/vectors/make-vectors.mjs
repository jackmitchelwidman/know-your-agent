// Makes spec/vectors/vectors.json: fixed keys and signed objects any implementation can check.
// Run: node make-vectors.mjs   (deterministic: keys are derived from fixed seeds)
import { createPrivateKey, createPublicKey, sign, createHash } from "node:crypto";
import { writeFileSync } from "node:fs";

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const b58 = bytes => { let n = BigInt("0x" + Buffer.from(bytes).toString("hex")), s = ""; while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; } for (const b of bytes) { if (b !== 0) break; s = "1" + s; } return s; };
const canonical = v => Array.isArray(v) ? "[" + v.map(canonical).join(",") + "]"
  : v && typeof v === "object" ? "{" + Object.keys(v).sort().map(k => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}"
  : JSON.stringify(v);
const sha256 = buf => createHash("sha256").update(buf).digest();
// An Ed25519 private key from a 32-byte seed: PKCS#8 prefix + seed.
const PKCS8 = Buffer.from("302e020100300506032b657004220420", "hex");
const keyFromSeed = seedHex => {
  const priv = createPrivateKey({ key: Buffer.concat([PKCS8, Buffer.from(seedHex, "hex")]), format: "der", type: "pkcs8" });
  const pub = Buffer.from(createPublicKey(priv).export({ format: "jwk" }).x, "base64url");
  return { priv, pub, seed: seedHex, publicKeyHex: pub.toString("hex"), did: "did:key:z" + b58(Buffer.concat([Buffer.from([0xed, 0x01]), pub])), fingerprint: sha256(pub).toString("hex").slice(0, 16) };
};
const signB64 = (k, bytes) => sign(null, bytes, k.priv).toString("base64");
const signedBody = (k, body) => ({ ...body, signature: signB64(k, Buffer.from(canonical(body), "utf8")) });

const owner = keyFromSeed("0000000000000000000000000000000000000000000000000000000000000001");
const agent = keyFromSeed("0000000000000000000000000000000000000000000000000000000000000002");
const child = keyFromSeed("0000000000000000000000000000000000000000000000000000000000000003");
const stranger = keyFromSeed("0000000000000000000000000000000000000000000000000000000000000004");

const descriptor = { v: 1, type: "traceable-agent", id: agent.did, owner: owner.did, name: "vector-agent", kind: "agent", environment: "test", issuedAt: "2026-11-02T10:00:00Z", expiresAt: "2027-11-02T10:00:00Z" };
const descriptorCanonical = canonical(descriptor);
const ownerSignature = signB64(owner, Buffer.from(descriptorCanonical, "utf8"));

const childDescriptor = { ...descriptor, id: child.did, name: "vector-child", parent: agent.did };
const childBytes = Buffer.from(canonical(childDescriptor), "utf8");

const GENESIS = "0".repeat(64);
let prev = GENESIS; const receipts = [];
const rows = [[1, "2026-11-02T10:01:00Z", "run_started", "start", "run-1", null], [2, "2026-11-02T10:02:00Z", "held", "hold", "run-1", sha256(Buffer.from("pay invoice\nINV-1 100")).toString("hex")], [3, "2026-11-02T10:03:00Z", "released", "release", "run-1", sha256(Buffer.from("pay invoice\nINV-1 100")).toString("hex")]];
for (const [seq, at, kind, decision, runId, actionHash] of rows) {
  const ledgerRowHash = sha256(Buffer.from("ledger-row-" + seq)).toString("hex");
  const preimage = canonical(["traceable-receipt", agent.did, seq, at, kind, decision, runId, actionHash, ledgerRowHash, prev]);
  const hash = sha256(Buffer.from(preimage, "utf8")).toString("hex");
  receipts.push({ seq, at, kind, decision, runId, actionHash, ledgerRowHash, prevHash: prev, hash, preimage, signature: signB64(agent, Buffer.from(hash, "hex")) });
  prev = hash;
}

const challenge = "5f3a9c0e1b2d4a6f8c7e9d0b1a2c3d4e";
const proofBody = { v: 1, type: "traceable-proof", id: agent.did, challenge, audience: null, at: "2026-11-02T10:05:00Z" };
const proof = signedBody(agent, proofBody);
const forged = { ...proof, challenge: "00000000000000000000000000000000" };           // signature no longer covers the body
const strangers = signedBody(stranger, { ...proofBody, id: agent.did });              // signed by another key, claims the agent's id

const leaf = sha256(Buffer.from(canonical(["traceable-checkpoint-leaf", agent.did, 3, prev]), "utf8")).toString("hex");
const root = sha256(Buffer.concat([Buffer.from(leaf, "hex"), Buffer.from(leaf, "hex")])).toString("hex"); // one leaf: paired with itself
const statement = { v: 1, type: "traceable-checkpoint", at: "2026-11-02T11:00:00Z", agents: 1, receipts: 3, root, prevRoot: null };

const join = signedBody(owner, { type: "traceable-join", at: "2026-11-02T10:00:00Z", owner: { id: owner.did, name: "Vector Owner", listed: true }, agent: { descriptor, ownerSignature } });

const out = {
  note: "Deterministic vectors for the Traceable Agents format v1. Keys are Ed25519 from the seeds shown; never use them for anything real. `at` values are fixed, so a live register will refuse the join and proof bodies as stale: check the signatures, not the clock.",
  canonicalJson: "keys sorted recursively, no whitespace, UTF-8; JSON.stringify for strings and numbers",
  keys: { owner: { seed: owner.seed, publicKeyHex: owner.publicKeyHex, did: owner.did }, agent: { seed: agent.seed, publicKeyHex: agent.publicKeyHex, did: agent.did, fingerprint: agent.fingerprint }, child: { seed: child.seed, publicKeyHex: child.publicKeyHex, did: child.did, fingerprint: child.fingerprint }, stranger: { seed: stranger.seed, publicKeyHex: stranger.publicKeyHex, did: stranger.did } },
  descriptor: { object: descriptor, canonical: descriptorCanonical, ownerSignature },
  childDescriptor: { object: childDescriptor, canonical: canonical(childDescriptor), ownerSignature: signB64(owner, childBytes), parentSignature: signB64(agent, childBytes) },
  receipts: { genesis: GENESIS, chain: receipts, headSeq: 3, headHash: prev },
  proofs: { challenge, valid: proof, forgedChallenge: { proof: forged, expect: "invalid: signature does not cover this body" }, strangersKey: { proof: strangers, expect: "invalid: signed by a key other than the id's" } },
  checkpoint: { leaf, root, statement, statementCanonical: canonical(statement), statementHash: sha256(Buffer.from(canonical(statement), "utf8")).toString("hex") },
  join,
  recordScore: { formula: "100, less 30 x (held / actions), less 50 x (rejected / actions), less 10 if rejected in the last 90 days, less 10 if fewer than 20 actions; kept between 0 and 100; no score before the first action",
    cases: [{ actions: 0, held: 0, rejected: 0, rejected90: 0, score: null }, { actions: 3, held: 1, rejected: 0, rejected90: 0, score: 80 }, { actions: 20, held: 0, rejected: 0, rejected90: 0, score: 100 }, { actions: 10, held: 2, rejected: 1, rejected90: 1, score: 69 }] }
};
writeFileSync(new URL("./vectors.json", import.meta.url), JSON.stringify(out, null, 2) + "\n");
console.log("wrote vectors.json", agent.did, "head", prev.slice(0, 16));
