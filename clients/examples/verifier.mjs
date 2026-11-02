// A worked client for the register's open door: another system issuing an ID and writing receipts.
// Uses only Node's built-in Ed25519. Run: node verifier.mjs [https://traceableagents.org]
import { generateKeyPairSync, sign, createHash, randomBytes } from "node:crypto";

const BASE = process.argv[2] || "https://traceableagents.org";
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const b58 = bytes => { let n = BigInt("0x" + Buffer.from(bytes).toString("hex")), s = ""; while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; } for (const b of bytes) { if (b !== 0) break; s = "1" + s; } return s; };
const canonical = v => Array.isArray(v) ? "[" + v.map(canonical).join(",") + "]"
  : v && typeof v === "object" ? "{" + Object.keys(v).sort().map(k => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}"
  : JSON.stringify(v);
const sha256 = buf => createHash("sha256").update(buf).digest();
const keypair = () => { const kp = generateKeyPairSync("ed25519"); const pub = Buffer.from(kp.publicKey.export({ format: "jwk" }).x, "base64url"); return { ...kp, pub, did: "did:key:z" + b58(Buffer.concat([Buffer.from([0xed, 0x01]), pub])) }; };
const signB64 = (kp, bytes) => sign(null, bytes, kp.privateKey).toString("base64");
const signed = (kp, body) => ({ ...body, signature: signB64(kp, Buffer.from(canonical(body), "utf8")) });
const post = async (path, body) => { const r = await fetch(BASE + path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }); const j = await r.json(); if (!j.ok) throw new Error(path + ": " + j.error); return j; };
const now = () => new Date().toISOString().replace(/\.\d{3}Z$/, "Z");

// 1. The system registers with its own key.
const verifier = keypair();
const reg = await post("/api/v1/register/verifiers", signed(verifier, { type: "traceable-verifier", id: verifier.did, name: "Example Runtime", website: "https://example.com", at: now() }));
console.log("registered verifier", reg.verifier.id, reg.verifier.status);

// 2. An owner and an agent. The owner signs the agent's descriptor; the system signs the whole write.
const owner = keypair(), agent = keypair();
const issued = now(), expires = new Date(Date.now() + 365 * 86400e3).toISOString().replace(/\.\d{3}Z$/, "Z");
const descriptor = { v: 1, type: "traceable-agent", id: agent.did, owner: owner.did, name: "Example Agent", kind: "agent", environment: "test", issuedAt: issued, expiresAt: expires };
const ownerSignature = signB64(owner, Buffer.from(canonical(descriptor), "utf8"));
const entry = await post("/api/v1/register/entries", signed(verifier, { verifier: verifier.did, at: now(),
  owner: { id: owner.did, name: "Example Owner", listed: true }, agent: { descriptor, ownerSignature } }));
console.log("entry", entry.agent.fingerprint, entry.agent.lookup);

// 3. Two receipts, chained. The agent's key signs each hash. The action itself stays with the owner.
let prev = "0".repeat(64); const receipts = [];
for (const [seq, kind, decision] of [[1, "run_started", "start"], [2, "held", "hold"]]) {
  const at = now(), ledgerRowHash = sha256(randomBytes(32)).toString("hex"), actionHash = sha256(Buffer.from("subject\ninput")).toString("hex");
  const pre = canonical(["traceable-receipt", agent.did, seq, at, kind, decision, null, actionHash, ledgerRowHash, prev]);
  const hash = sha256(Buffer.from(pre, "utf8")).toString("hex");
  receipts.push({ seq, at, kind, decision, actionHash, ledgerRowHash, prevHash: prev, hash, signature: signB64(agent, Buffer.from(hash, "hex")) });
  prev = hash;
}
const rc = await post("/api/v1/register/receipts", signed(verifier, { verifier: verifier.did, at: now(), agent: agent.did, receipts }));
console.log("receipts accepted", rc.accepted, "head", rc.headSeq);

// 4. The register's own check, the same one Sheaf's entries get.
const v = await (await fetch(BASE + "/api/v1/register/agents/" + entry.agent.fingerprint + "/verify")).json();
console.log("verify:", JSON.stringify(v));
// 5. The handshake from the outside: the agent proves it holds its key, the register confirms it.
const challenge = randomBytes(16).toString("hex");
const proof = { v: 1, type: "traceable-proof", id: agent.did, challenge, audience: null, at: now() };
const check = await post("/api/v1/register/check", { proof: { ...proof, signature: signB64(agent, Buffer.from(canonical(proof), "utf8")) }, challenge });
console.log("handshake:", check.identityProof, "|", check.summary);
