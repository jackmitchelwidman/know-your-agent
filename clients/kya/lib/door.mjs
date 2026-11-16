// The Door: an agent shows who it is on an ordinary web request, and a service checks it before letting it in.
//
// The agent adds one header, KYA-Proof, to its request. The header is a proof signed with the agent's key.
// It names the exact address being called and is good for 60 seconds, so it cannot be used anywhere else
// or kept for later. The service checks the signature here, with no network call, then asks the Know Your
// Agent register who owns the agent and whether it is in good standing.
//
// Needs Node 18 or later and nothing else.
import { createPrivateKey, createPublicKey, sign, verify, randomBytes } from "node:crypto";

export const HEADER = "KYA-Proof";
export const PROOF_TYPE = "request-proof";
export const MAX_AGE_SECONDS = 60;
export const AHEAD_SECONDS = 10;
const DEFAULT_REGISTER = "https://know-your-agent.org";

// ── the format ──────────────────────────────────────────────────────────────────────────────
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const b58 = bytes => { let n = BigInt("0x" + (Buffer.from(bytes).toString("hex") || "0")), s = ""; while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; } for (const b of bytes) { if (b !== 0) break; s = "1" + s; } return s; };
const unb58 = s => { let n = 0n; for (const c of s) { const i = B58.indexOf(c); if (i < 0) throw new Error("not base58"); n = n * 58n + BigInt(i); } let h = n.toString(16); if (h.length % 2) h = "0" + h; let z = 0; for (const c of s) { if (c !== "1") break; z++; } return Buffer.concat([Buffer.alloc(z), Buffer.from(h, "hex")]); };
const canonical = v => Array.isArray(v) ? "[" + v.map(canonical).join(",") + "]"
  : v && typeof v === "object" ? "{" + Object.keys(v).filter(k => v[k] !== undefined).sort().map(k => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}"
  : JSON.stringify(v);
const SPKI = Buffer.from("302a300506032b6570032100", "hex");
const pubFromDid = did => {
  if (typeof did !== "string" || !did.startsWith("did:key:z")) throw new Error("not a did:key");
  const raw = unb58(did.slice("did:key:z".length));
  if (raw.length !== 34 || raw[0] !== 0xed || raw[1] !== 0x01) throw new Error("not an Ed25519 did:key");
  return createPublicKey({ key: Buffer.concat([SPKI, raw.subarray(2)]), format: "der", type: "spki" });
};
const didOfKey = priv => "did:key:z" + b58(Buffer.concat([Buffer.from([0xed, 0x01]), Buffer.from(createPrivateKey(priv).export({ format: "jwk" }).x, "base64url")]));

/** The one written form of an address a proof is bound to: scheme, host and path. The scheme and host are
  * lower case, a default port is dropped, an empty path is "/", and the query and fragment are left out.
  * The path is kept exactly as sent. Returns null when the address is not http or https. */
export function canonicalAudience(url) {
  const m = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/([^/?#]*)([^?#]*)/.exec(String(url).trim());
  if (!m) return null;
  const scheme = m[1].toLowerCase();
  if (scheme !== "http" && scheme !== "https") return null;
  let authority = m[2].toLowerCase();
  if (!authority || authority.includes("@")) return null;
  const pm = /^(.*):(\d+)$/.exec(authority);
  if (pm) { const dflt = scheme === "https" ? "443" : "80"; authority = String(Number(pm[2])) === dflt ? pm[1] : pm[1] + ":" + Number(pm[2]); }
  if (!authority) return null;
  return scheme + "://" + authority + (m[3] || "/");
}

// ── the agent's side ────────────────────────────────────────────────────────────────────────
/** A signed proof for one request to `url`. `privateKey` is the agent's key (PEM, as kya keeps it). */
export function requestProof(privateKey, url, { now = Date.now() } = {}) {
  const audience = canonicalAudience(url);
  if (!audience) throw new Error("The address must be a full http or https URL.");
  const body = { v: 1, type: PROOF_TYPE, id: didOfKey(privateKey), audience, nonce: randomBytes(16).toString("hex"), at: new Date(now).toISOString().replace(/\.\d{3}Z$/, "Z") };
  return { ...body, signature: sign(null, Buffer.from(canonical(body), "utf8"), createPrivateKey(privateKey)).toString("base64") };
}
/** The value of the KYA-Proof header for one request to `url`: fetch(url, { headers: { "KYA-Proof": proofHeader(key, url) } }) */
export function proofHeader(privateKey, url, opts) {
  return Buffer.from(JSON.stringify(requestProof(privateKey, url, opts)), "utf8").toString("base64url");
}

// ── the service's side ──────────────────────────────────────────────────────────────────────
export function decodeHeader(value) {
  try { const p = JSON.parse(Buffer.from(String(value).trim(), "base64url").toString("utf8")); return p && typeof p === "object" && !Array.isArray(p) ? p : null; } catch { return null; }
}

/** Check a request proof with no network call. `audience` is the service's own address for this request,
  * in the canonical form. Returns { ok: true, id } or { ok: false, reason }. */
export function checkRequestProof(proof, audience, { now = Date.now(), maxAgeSeconds = MAX_AGE_SECONDS, aheadSeconds = AHEAD_SECONDS } = {}) {
  const no = reason => ({ ok: false, reason });
  if (!proof || typeof proof !== "object") return no("there is no proof");
  if (proof.type !== PROOF_TYPE) return no("this is not a request proof");
  for (const [k, why] of [["id", "the proof names no id"], ["audience", "the proof does not say who it is for"], ["nonce", "the proof has no random value"], ["at", "the proof has no time"], ["signature", "the proof has no signature"]])
    if (typeof proof[k] !== "string" || !proof[k]) return no(why);
  let pub; try { pub = pubFromDid(proof.id); } catch { return no("the id is not a did:key this checker understands"); }
  if (proof.audience !== audience) return no("the proof was made for another address");
  const at = Date.parse(proof.at);
  if (Number.isNaN(at)) return no("the time is not readable");
  if (now - at > maxAgeSeconds * 1000) return no("the proof is stale");
  if (at - now > aheadSeconds * 1000) return no("the proof is dated in the future");
  const body = { v: 1, type: PROOF_TYPE, id: proof.id, audience: proof.audience, nonce: proof.nonce, at: proof.at };
  let good = false; try { good = verify(null, Buffer.from(canonical(body), "utf8"), pub, Buffer.from(proof.signature, "base64")); } catch { good = false; }
  return good ? { ok: true, id: proof.id } : no("the signature does not match the id");
}

/** A door for one service.
  *
  *   origin     The service's own public address, for example "https://tools.acme.example". Set it yourself.
  *              It is never read from the request, so a proof made for another service is refused here.
  *   require    Who may come in:
  *                "identified"  on the register and in good standing (the default)
  *                "verified"    the same, and the owner has proved a domain or been reviewed
  *                "proof"       anyone with a valid proof; the register is not asked
  *   approved   Agent IDs a person has approved: an array, a Set, or a function (id) => true/false (may be
  *              async). An approved agent comes in whatever `require` says, unless the register says it
  *              is revoked, retired or expired.
  *   onHold     If set, an agent with a valid proof that does not meet `require` is held instead of refused,
  *              and this function is called with the details so a person can decide. To let it in next
  *              time, add its ID to `approved`.
  *   register   The register to ask. The default is https://know-your-agent.org.
  *
  * door.check({ path, headers }) answers { decision: "allow" | "hold" | "refuse", reason, id, agent, owner }.
  * door.middleware() is the same check for Node's http server, Express and Connect.
  *
  * Each proof works once: the door remembers the proofs it has seen for their 60 seconds. That memory is
  * per process. Behind several processes, pass `seen` (has/add, may be async) backed by a shared store. */
export function door({ origin, require: req = "identified", approved, onHold, register = DEFAULT_REGISTER, lookupSeconds = 60, seen, fetch: fetchFn = globalThis.fetch, now = () => Date.now() } = {}) {
  const base = canonicalAudience(origin);
  if (!base || !/^https?:\/\/[^/]+\/$/.test(base)) throw new Error('door({ origin }): set origin to this service\'s own address, for example "https://tools.acme.example".');
  if (!["identified", "verified", "proof"].includes(req)) throw new Error('door({ require }): "identified", "verified" or "proof".');
  const root = base.slice(0, -1), reg = String(register).replace(/\/$/, "");
  const used = new Map(), looked = new Map();
  const sweep = t => { for (const [k, exp] of used) if (exp <= t) used.delete(k); for (const [k, v] of looked) if (v.exp <= t) looked.delete(k); };
  const isApproved = async id => !approved ? false : typeof approved === "function" ? !!(await approved(id)) : approved instanceof Set ? approved.has(id) : Array.isArray(approved) && approved.includes(id);
  const lookup = async id => {
    const t = now(), hit = looked.get(id);
    if (hit && hit.exp > t) return hit.value;
    let value;
    try {
      const r = await fetchFn(reg + "/api/v1/register/lookup?id=" + encodeURIComponent(id));
      const j = await r.json();
      value = r.status === 404 || j.status === "unknown" ? { known: false } : (j && j.agent) ? { known: true, agent: j.agent, owner: j.owner || null } : { down: true };
    } catch { value = { down: true }; }
    if (!value.down) looked.set(id, { exp: t + lookupSeconds * 1000, value });
    return value;
  };

  async function check({ path, url, headers } = {}) {
    const t = now();
    const p = String(path ?? url ?? "/").replace(/[?#].*$/, "") || "/";
    const audience = root + (p.startsWith("/") ? p : "/" + p);
    const get = name => { if (!headers) return undefined; if (typeof headers.get === "function") return headers.get(name) ?? undefined; const k = Object.keys(headers).find(h => h.toLowerCase() === name.toLowerCase()); const v = k ? headers[k] : undefined; return Array.isArray(v) ? v[0] : v; };
    const raw = get(HEADER);
    if (!raw) return { decision: "refuse", reason: "the request carries no KYA-Proof header", audience };
    const proof = decodeHeader(raw);
    if (!proof) return { decision: "refuse", reason: "the KYA-Proof header could not be read", audience };
    const c = checkRequestProof(proof, audience, { now: t });
    if (!c.ok) return { decision: "refuse", reason: c.reason, id: typeof proof.id === "string" ? proof.id : undefined, audience };
    sweep(t);
    const id = c.id, key = proof.signature;
    if (seen ? await seen.has(key) : used.has(key)) return { decision: "refuse", reason: "this proof was already used", id, audience };
    if (seen) await seen.add(key, MAX_AGE_SECONDS + AHEAD_SECONDS); else used.set(key, t + (MAX_AGE_SECONDS + AHEAD_SECONDS) * 1000);

    const ok = await isApproved(id);
    if (req === "proof" && !ok) return { decision: "allow", reason: "its proof is valid", id, audience };
    const l = await lookup(id);
    const out = (decision, reason) => ({ decision, reason, id, audience, agent: l.agent, owner: l.owner });
    const standing = l.known ? l.agent.standing : undefined;
    if (l.known && standing !== "good") return out("refuse", `the register says this agent is ${standing || "not in good standing"}`);
    if (ok) return out("allow", l.down ? "a person approved it; the register could not be reached" : "a person approved it");
    if (req === "proof") return out("allow", "its proof is valid");
    if (l.down) return out("refuse", "the register could not be reached, so the agent could not be looked up");
    let why = null;
    if (!l.known) why = "it is not on the register";
    else if (req === "verified" && !(l.owner && l.owner.verification === "verified")) why = "its owner is not verified";
    if (!why) return out("allow", req === "verified" ? "it is in good standing with a verified owner" : "it is on the register and in good standing");
    if (!onHold) return out("refuse", why);
    const held = out("hold", why + "; held for a person to decide");
    try { await onHold(held); } catch { /* the hold stands whatever the callback does */ }
    return held;
  }

  function middleware() {
    return async (request, response, next) => {
      let r;
      try { r = await check({ path: request.originalUrl || request.url, headers: request.headers }); }
      catch { r = { decision: "refuse", reason: "the check failed" }; }
      request.kya = r;
      if (r.decision === "allow") return typeof next === "function" ? next() : undefined;
      const status = r.decision === "hold" ? 403 : 401;
      const body = JSON.stringify({ ok: false, decision: r.decision, reason: r.reason, expected: { header: HEADER, audience: r.audience }, how: reg + "/format.html" });
      response.writeHead(status, { "content-type": "application/json", "www-authenticate": HEADER });
      response.end(body);
    };
  }
  return { check, middleware, origin: root };
}
