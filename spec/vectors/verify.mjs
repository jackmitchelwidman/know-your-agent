// Conformance check: recomputes every hash and verifies every signature in vectors.json.
// Run: node verify.mjs [path/to/vectors.json]. Exit 0 and "PASS" when everything holds.
import { createPublicKey, verify, createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const unb58 = s => { let n = 0n; for (const c of s) n = n * 58n + BigInt(B58.indexOf(c)); let h = n.toString(16); if (h.length % 2) h = "0" + h; let b = Buffer.from(h, "hex"); let z = 0; for (const c of s) { if (c !== "1") break; z++; } return Buffer.concat([Buffer.alloc(z), b]); };
const canonical = v => Array.isArray(v) ? "[" + v.map(canonical).join(",") + "]"
  : v && typeof v === "object" ? "{" + Object.keys(v).sort().map(k => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}"
  : JSON.stringify(v);
const sha256 = buf => createHash("sha256").update(buf).digest();
const pubFromDid = did => { const raw = unb58(did.slice("did:key:z".length)); if (raw[0] !== 0xed || raw[1] !== 0x01 || raw.length !== 34) throw new Error("not an Ed25519 did:key: " + did); return createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw.subarray(2)]), format: "der", type: "spki" }); };
const ok = (did, bytes, sigB64) => { try { return verify(null, bytes, pubFromDid(did), Buffer.from(sigB64, "base64")); } catch { return false; } };
const unsigned = o => { const { signature, ...rest } = o; return rest; };
const score = (a, h, r, r90) => a <= 0 ? null : Math.max(0, Math.min(100, Math.round(100 - 30 * h / a - 50 * r / a - (r90 > 0 ? 10 : 0) - (a < 20 ? 10 : 0))));

const V = JSON.parse(readFileSync(process.argv[2] || new URL("./vectors.json", import.meta.url), "utf8"));
let fails = 0; const check = (name, cond) => { console.log((cond ? "ok   " : "FAIL ") + name); if (!cond) fails++; };

check("canonical descriptor matches", canonical(V.descriptor.object) === V.descriptor.canonical);
check("owner signature over descriptor", ok(V.keys.owner.did, Buffer.from(V.descriptor.canonical, "utf8"), V.descriptor.ownerSignature));
check("descriptor.id is the agent did", V.descriptor.object.id === V.keys.agent.did);
check("fingerprint = first 16 hex of sha256(public key)", sha256(Buffer.from(V.keys.agent.publicKeyHex, "hex")).toString("hex").slice(0, 16) === V.keys.agent.fingerprint);
check("child: owner signature", ok(V.keys.owner.did, Buffer.from(V.childDescriptor.canonical, "utf8"), V.childDescriptor.ownerSignature));
check("child: parent signature over the same bytes", ok(V.keys.agent.did, Buffer.from(V.childDescriptor.canonical, "utf8"), V.childDescriptor.parentSignature));
let prev = V.receipts.genesis;
for (const r of V.receipts.chain) {
  const pre = canonical(["traceable-receipt", V.keys.agent.did, r.seq, r.at, r.kind, r.decision, r.runId, r.actionHash, r.ledgerRowHash, r.prevHash]);
  const hash = sha256(Buffer.from(pre, "utf8")).toString("hex");
  check(`receipt ${r.seq}: prevHash chains`, r.prevHash === prev);
  check(`receipt ${r.seq}: hash = sha256(preimage)`, hash === r.hash && pre === r.preimage);
  check(`receipt ${r.seq}: agent signature over hash bytes`, ok(V.keys.agent.did, Buffer.from(r.hash, "hex"), r.signature));
  prev = r.hash;
}
check("chain head", prev === V.receipts.headHash && V.receipts.chain.length === V.receipts.headSeq);
const p = V.proofs;
check("proof: valid signature", ok(p.valid.id, Buffer.from(canonical(unsigned(p.valid)), "utf8"), p.valid.signature) && p.valid.challenge === p.challenge);
check("proof: forged challenge fails", !ok(p.forgedChallenge.proof.id, Buffer.from(canonical(unsigned(p.forgedChallenge.proof)), "utf8"), p.forgedChallenge.proof.signature));
check("proof: stranger's key fails", !ok(p.strangersKey.proof.id, Buffer.from(canonical(unsigned(p.strangersKey.proof)), "utf8"), p.strangersKey.proof.signature));
const c = V.checkpoint;
check("checkpoint leaf", sha256(Buffer.from(canonical(["traceable-checkpoint-leaf", V.keys.agent.did, V.receipts.headSeq, V.receipts.headHash]), "utf8")).toString("hex") === c.leaf);
check("checkpoint root (one leaf pairs with itself)", sha256(Buffer.concat([Buffer.from(c.leaf, "hex"), Buffer.from(c.leaf, "hex")])).toString("hex") === c.root);
check("checkpoint statement hash", sha256(Buffer.from(canonical(c.statement), "utf8")).toString("hex") === c.statementHash && canonical(c.statement) === c.statementCanonical);
check("join body signed by the owner", ok(V.join.owner.id, Buffer.from(canonical(unsigned(V.join)), "utf8"), V.join.signature));
for (const k of V.recordScore.cases) check(`record score ${k.actions}/${k.held}/${k.rejected}/${k.rejected90} = ${k.score}`, score(k.actions, k.held, k.rejected, k.rejected90) === k.score);
console.log(fails ? `${fails} FAILED` : "PASS"); process.exit(fails ? 1 : 0);
