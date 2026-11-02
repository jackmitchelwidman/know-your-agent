#!/usr/bin/env node
// kya: Know Your Agent. Put an AI agent on the Know Your Agent register, prove who it is,
// write its record, and check other agents before dealing with them.
//
// Needs Node 18 or later and nothing else. Keys are made here and never leave this machine
// except as public keys and signatures. The register is https://know-your-agent.org; set
// KYA_REGISTER to use another one. Keys live in ~/.config/kya; set KYA_HOME to move them.
import { generateKeyPairSync, createPrivateKey, sign, createHash, randomBytes } from "node:crypto";
import { readFileSync, writeFileSync, existsSync, mkdirSync, readdirSync, chmodSync } from "node:fs";
import { join as pathJoin } from "node:path";
import { homedir } from "node:os";

const REGISTER = (process.env.KYA_REGISTER || "https://know-your-agent.org").replace(/\/$/, "");
const HOME = process.env.KYA_HOME || pathJoin(process.env.XDG_CONFIG_HOME || pathJoin(homedir(), ".config"), "kya");
const AGENTS = pathJoin(HOME, "agents");

// ── the format ──────────────────────────────────────────────────────────────────────────────
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const b58 = bytes => { let n = BigInt("0x" + Buffer.from(bytes).toString("hex")), s = ""; while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; } for (const b of bytes) { if (b !== 0) break; s = "1" + s; } return s; };
const canonical = v => Array.isArray(v) ? "[" + v.map(canonical).join(",") + "]"
  : v && typeof v === "object" ? "{" + Object.keys(v).filter(k => v[k] !== undefined).sort().map(k => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}"
  : JSON.stringify(v);
const sha256 = buf => createHash("sha256").update(buf).digest();
const pubOf = priv => Buffer.from(createPrivateKey(priv).export({ format: "jwk" }).x, "base64url");
const didOf = priv => "did:key:z" + b58(Buffer.concat([Buffer.from([0xed, 0x01]), pubOf(priv)]));
const fingerprintOf = priv => sha256(pubOf(priv)).toString("hex").slice(0, 16);
const signB64 = (priv, bytes) => sign(null, bytes, createPrivateKey(priv)).toString("base64");
const signed = (priv, body) => ({ ...body, signature: signB64(priv, Buffer.from(canonical(body), "utf8")) });
const now = () => new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
const GENESIS = "0".repeat(64);

// ── files ───────────────────────────────────────────────────────────────────────────────────
const ownerKeyPath = pathJoin(HOME, "owner.key"), ownerPath = pathJoin(HOME, "owner.json");
const agentKeyPath = n => pathJoin(AGENTS, n + ".key"), agentPath = n => pathJoin(AGENTS, n + ".json");
const readJson = p => JSON.parse(readFileSync(p, "utf8"));
const writeJson = (p, v) => writeFileSync(p, JSON.stringify(v, null, 2) + "\n", { mode: 0o600 });
const writeKey = (p, kp) => { writeFileSync(p, kp.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 }); chmodSync(p, 0o600); };
const owner = () => { if (!existsSync(ownerKeyPath)) die("No owner key yet. Run: kya init --owner \"Your name or company\""); return { key: readFileSync(ownerKeyPath), ...readJson(ownerPath) }; };
const agent = n => { if (!existsSync(agentKeyPath(n))) die(`No agent called "${n}" here. Run: kya join ${n}`); return { key: readFileSync(agentKeyPath(n)), ...readJson(agentPath(n)) }; };
const safeName = n => { if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/.test(n || "")) die("An agent name is 1 to 80 letters, digits, dots, dashes or underscores."); return n; };

// ── the wire ────────────────────────────────────────────────────────────────────────────────
async function post(path, body) {
  const r = await fetch(REGISTER + path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  const j = await r.json().catch(() => ({}));
  if (!j.ok) die(`${REGISTER}${path} said: ${j.error || j.message || r.status}`);
  return j;
}
async function get(path) { const r = await fetch(REGISTER + path); return r.json(); }

// ── arguments ───────────────────────────────────────────────────────────────────────────────
const argv = process.argv.slice(2);
const flags = {}, words = [];
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a.startsWith("--")) { const k = a.slice(2); const v = argv[i + 1]; if (v !== undefined && !v.startsWith("--")) { flags[k] = v; i++; } else flags[k] = true; }
  else words.push(a);
}
const [cmd, ...rest] = words;
function die(msg) { console.error(msg); process.exit(1); }
function out(v) { console.log(typeof v === "string" ? v : JSON.stringify(v, null, 2)); }

const HELP = `kya: Know Your Agent. The Know Your Agent from the command line.

  kya init --owner "Name" [--website https://…] [--hidden]
        Make your owner key. You sign for your agents with it. Keep it; a lost key cannot be replaced.
  kya join <agent> [--kind agent] [--test] [--parent <agent>]
        Make a key for the agent, sign its ID as its owner, and enter it on the register.
  kya whoami
        Your owner ID and the agents you have entered.
  kya prove <agent> <challenge> [--audience <did>]
        Answer another agent's challenge: a proof signed with this agent's key, as JSON.
  kya check <id or fingerprint> [--proof '<json>' --challenge <c>]
        Look another agent up. With a proof and the challenge you sent, also checks the proof is theirs.
  kya challenge
        A fresh random challenge to send to another agent.
  kya receipt <agent> --kind <kind> --decision <decision> [--action "<text>"] [--run <id>]
        Add one action to the agent's record. Kinds and decisions are yours to name, for example
        payment / approved or email / sent. Three kinds have meaning for the Record Score: held (a person
        stopped it), released (a person let it go), rejected (a person refused it). The register keeps
        a hash of the action, never the text.
  kya verify <domain>                    Claim your domain: prints the token to put in DNS or on your site.
  kya verify-check                       Ask the register to look for the token. Passing makes you a verified owner.
  kya retire <agent> [--reason "…"]      End the agent's life. Its record stays.
  kya revoke <agent> [--reason "…"]      Withdraw the agent for cause. Its record stays.
  kya record <agent>                     The agent's Record of Action and Record Score, from the register.

Register: ${REGISTER}   Keys: ${HOME}
The format, with every call: ${REGISTER}/format.html`;

// ── commands ────────────────────────────────────────────────────────────────────────────────
async function init() {
  const name = (flags.owner || "").trim();
  if (!name) die('Who signs for these agents? kya init --owner "Your name or company"');
  mkdirSync(AGENTS, { recursive: true, mode: 0o700 });
  if (existsSync(ownerKeyPath)) die(`${ownerKeyPath} already exists. Your owner ID is ${didOf(readFileSync(ownerKeyPath))}. Move the file away first if you mean to start over; agents signed by the old key stay with it.`);
  const kp = generateKeyPairSync("ed25519");
  writeKey(ownerKeyPath, kp);
  const o = { name: name.slice(0, 120), website: flags.website || undefined, listed: !flags.hidden, createdAt: now() };
  writeJson(ownerPath, o);
  out(`Owner key written to ${ownerKeyPath}. Keep it private and backed up.`);
  out(`Owner ID: ${didOf(readFileSync(ownerKeyPath))}`);
  out(`Next: kya join <agent-name>`);
}

async function join() {
  const name = safeName(rest[0]);
  const o = owner();
  mkdirSync(AGENTS, { recursive: true, mode: 0o700 });
  if (existsSync(agentKeyPath(name))) die(`"${name}" already has a key here (${readJson(agentPath(name)).id}). Pick another name.`);
  const kind = (flags.kind || "agent").toString().slice(0, 60);
  const environment = flags.test ? "test" : "production";
  const parent = flags.parent ? agent(flags.parent) : null;
  if (parent && parent.environment === "test" && environment !== "test") die("A child of a test agent is a test agent. Add --test.");
  const kp = generateKeyPairSync("ed25519");
  const priv = kp.privateKey.export({ type: "pkcs8", format: "pem" });
  const issuedAt = now(), expiresAt = new Date(Date.now() + 365 * 86400e3).toISOString().replace(/\.\d{3}Z$/, "Z");
  const descriptor = { v: 1, type: "traceable-agent", id: didOf(priv), owner: didOf(o.key), name, kind, environment: parent ? parent.environment : environment, issuedAt, expiresAt };
  if (parent) descriptor.parent = parent.id;
  const bytes = Buffer.from(canonical(descriptor), "utf8");
  const entry = { descriptor, ownerSignature: signB64(o.key, bytes) };
  if (parent) entry.parentSignature = signB64(parent.key, bytes);
  const body = signed(o.key, { type: "traceable-join", at: now(), owner: { id: didOf(o.key), name: o.name, website: o.website, listed: o.listed !== false }, agent: entry });
  const r = await post("/api/v1/register/join", body);
  writeKey(agentKeyPath(name), kp);
  writeJson(agentPath(name), { id: descriptor.id, fingerprint: fingerprintOf(priv), name, kind, environment: descriptor.environment, parent: descriptor.parent, parentName: parent ? parent.name : undefined, descriptor, issuedAt, expiresAt, lookup: r.agent.lookup, seq: 0, prevHash: GENESIS });
  out(`${name} is on the register.`);
  out(`ID:          ${descriptor.id}`);
  out(`Fingerprint: ${fingerprintOf(priv)}`);
  out(`Look it up:  ${REGISTER}/a/${fingerprintOf(priv)}`);
  out(`Key:         ${agentKeyPath(name)}  (the agent proves who it is with this; keep it private)`);
}

async function whoami() {
  const o = owner();
  out(`Owner: ${o.name}${o.listed === false ? " (name hidden)" : ""}`);
  out(`ID:    ${didOf(o.key)}`);
  out(`Page:  ${REGISTER}/o/${didOf(o.key)}`);
  const names = existsSync(AGENTS) ? readdirSync(AGENTS).filter(f => f.endsWith(".json")).map(f => f.slice(0, -5)) : [];
  if (!names.length) { out("Agents: none yet. kya join <agent-name>"); return; }
  out("Agents:");
  for (const n of names) { const a = readJson(agentPath(n)); out(`  ${n.padEnd(24)} ${a.fingerprint}  ${a.environment}${a.parent ? "  child of " + (a.parentName || a.parent) : ""}  ${REGISTER}/a/${a.fingerprint}`); }
}

async function prove() {
  const a = agent(safeName(rest[0]));
  const challenge = rest[1];
  if (!challenge) die("kya prove <agent> <challenge>: the challenge is the value the other agent sent you.");
  const proof = { v: 1, type: "traceable-proof", id: a.id, challenge, audience: flags.audience || null, at: now() };
  out(signed(a.key, proof));
}

async function check() {
  const id = rest[0];
  if (!id) die("kya check <id or fingerprint>");
  let r;
  if (flags.proof) {
    let proof; try { proof = JSON.parse(flags.proof); } catch { die("--proof must be the proof JSON exactly as the other agent gave it."); }
    if (!flags.challenge) die("--challenge is the value you sent; the register checks the proof is over it.");
    r = await post("/api/v1/register/check", { proof, challenge: flags.challenge });
  } else {
    r = await post("/api/v1/register/check", { id });
  }
  out(r.summary || r.answer || r);
  if (flags.json) out(r);
}

async function challenge() { out(randomBytes(16).toString("hex")); }

async function headOf(a) {
  const j = await get(`/api/v1/register/agents/${a.id}`);
  const rec = j && j.record ? j.record : {};
  return { seq: rec.headSeq || 0, prevHash: rec.headHash || GENESIS };
}

async function receipt() {
  const name = safeName(rest[0]); const a = agent(name); const o = owner();
  const kind = flags.kind, decision = flags.decision;
  if (!kind || !decision) die('kya receipt <agent> --kind <kind> --decision <decision> [--action "<text>"] [--run <id>]');
  const head = await headOf(a);
  const seq = head.seq + 1, prevHash = head.prevHash, at = now();
  const actionHash = flags.action ? sha256(Buffer.from(String(flags.action), "utf8")).toString("hex") : null;
  const ledgerRowHash = sha256(Buffer.from(canonical({ at, kind, decision, actionHash, run: flags.run || null, seq }), "utf8")).toString("hex");
  const runId = flags.run ? String(flags.run) : null;
  const hash = sha256(Buffer.from(canonical(["traceable-receipt", a.id, seq, at, kind, decision, runId, actionHash, ledgerRowHash, prevHash]), "utf8")).toString("hex");
  const rc = { seq, at, kind, decision, runId, actionHash, ledgerRowHash, prevHash, hash, signature: signB64(a.key, Buffer.from(hash, "hex")) };
  const r = await post("/api/v1/register/receipts", signed(o.key, { verifier: didOf(o.key), at: now(), agent: a.id, receipts: [rc] }));
  writeJson(agentPath(name), { ...a, key: undefined, seq: r.headSeq, prevHash: r.headHash });
  out(`Receipt ${r.headSeq} on ${name}'s record: ${kind} / ${decision}. ${REGISTER}/a/${a.fingerprint}`);
}

async function standing(status) {
  const name = safeName(rest[0]); const a = agent(name); const o = owner();
  const r = await post("/api/v1/register/entries/status", signed(o.key, { verifier: didOf(o.key), at: now(), agent: a.id, status, reason: flags.reason ? String(flags.reason).slice(0, 200) : undefined }));
  out(`${name} is ${r.agent.status}. Its record stays at ${REGISTER}/a/${a.fingerprint}`);
}

async function verify() {
  const o = owner(); const domain = rest[0];
  if (!domain) die("kya verify <domain>: the domain you control, for example acme.example");
  const r = await post("/api/v1/register/owners/verify", signed(o.key, { type: "traceable-verify", owner: didOf(o.key), domain, at: now() }));
  const d = (r.verification || {}).domain || {}; const rec = d.record || {}; const file = d.file || {};
  out(`Claimed ${domain}. Put this where only the domain's controller can:`);
  out(`  DNS:  ${rec.name || "_kya." + domain}  TXT  "${rec.value || ""}"`);
  out(`  or:   ${file.url || "https://" + domain + "/.well-known/kya.txt"} containing the line ${file.content || rec.value || ""}`);
  out(`Then run: kya verify-check`);
  if (flags.json) out(r);
}

async function verifyCheck() {
  const o = owner();
  const r = await post("/api/v1/register/owners/verify/check", signed(o.key, { type: "traceable-verify-check", owner: didOf(o.key), at: now() }));
  out(r.tier === "verified" ? `Verified. You are a verified owner on the register. ${REGISTER}/o/${didOf(o.key)}` : `Not verified yet (${r.tier || "unverified"}).`);
  if (flags.json) out(r);
}

async function record() {
  const a = agent(safeName(rest[0]));
  const j = await get(`/api/v1/register/agents/${a.id}/record`);
  if (!j || !j.ok) die("The register did not answer.");
  out(j.story || j.recordOfAction?.story || j);
  if (flags.json) out(j);
}

const run = { init, join, whoami, prove, check, challenge, receipt, record, verify, "verify-check": verifyCheck, retire: () => standing("retired"), revoke: () => standing("revoked") };
if (!cmd || cmd === "help" || flags.help) { out(HELP); process.exit(0); }
if (!run[cmd]) die(`Unknown command "${cmd}".\n\n${HELP}`);
run[cmd]().catch(e => die(e && e.message ? e.message : String(e)));
