#!/usr/bin/env python3
"""kya.py: a reference client for the Register of Traceable Agents, in Python.

Needs Python 3.9+ and the `cryptography` package (pip install cryptography). Nothing else.

  python kya.py init --owner "Name"           make an owner key in ~/.config/kya-py
  python kya.py join <agent> [--test]          make an agent key, sign its ID as owner, enter it
  python kya.py prove <agent> <challenge>      answer a challenge with this agent's key
  python kya.py check <id> [--proof JSON --challenge C]
  python kya.py receipt <agent> --kind K --decision D [--action TEXT]
  python kya.py whoami

Register: $KYA_REGISTER (default https://traceableagents.org). Keys: $KYA_HOME (default ~/.config/kya-py).
The exact bytes signed are the canonical JSON: keys sorted recursively, no whitespace, UTF-8.
"""
import argparse, base64, hashlib, json, os, secrets, sys, urllib.request
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

REGISTER = os.environ.get("KYA_REGISTER", "https://traceableagents.org").rstrip("/")
HOME = os.environ.get("KYA_HOME") or os.path.join(os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config")), "kya-py")
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
GENESIS = "0" * 64

def b58(b: bytes) -> str:
    n = int.from_bytes(b, "big"); s = ""
    while n: n, r = divmod(n, 58); s = B58[r] + s
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + s

def canonical(v) -> str:
    if isinstance(v, dict): return "{" + ",".join(json.dumps(k) + ":" + canonical(v[k]) for k in sorted(v)) + "}"
    if isinstance(v, list): return "[" + ",".join(canonical(x) for x in v) + "]"
    return json.dumps(v, ensure_ascii=False, separators=(",", ":"))

def sha256(b: bytes) -> bytes: return hashlib.sha256(b).digest()
def now() -> str: return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
def pub(k: Ed25519PrivateKey) -> bytes: return k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
def did(k) -> str: return "did:key:z" + b58(b"\xed\x01" + pub(k))
def fingerprint(k) -> str: return sha256(pub(k)).hex()[:16]
def sig(k, b: bytes) -> str: return base64.b64encode(k.sign(b)).decode()
def signed(k, body: dict) -> dict: return {**body, "signature": sig(k, canonical(body).encode())}

def save_key(path, k):
    pem = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as f: f.write(pem)
def load_key(path): return serialization.load_pem_private_key(open(path, "rb").read(), password=None)
def rj(p): return json.load(open(p))
def wj(p, v):
    with open(os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f: json.dump(v, f, indent=2)
def owner():
    p = os.path.join(HOME, "owner.key")
    if not os.path.exists(p): sys.exit('No owner key yet. Run: kya.py init --owner "Name"')
    return load_key(p), rj(os.path.join(HOME, "owner.json"))
def agent(name):
    p = os.path.join(HOME, "agents", name + ".key")
    if not os.path.exists(p): sys.exit(f'No agent called "{name}". Run: kya.py join {name}')
    return load_key(p), rj(os.path.join(HOME, "agents", name + ".json"))

def post(path, body):
    req = urllib.request.Request(REGISTER + path, data=json.dumps(body).encode(), headers={"content-type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req) as r: j = json.load(r)
    except urllib.error.HTTPError as e: j = json.load(e)
    if not j.get("ok"): sys.exit(f"{REGISTER}{path} said: {j.get('error') or j}")
    return j
def get(path):
    with urllib.request.urlopen(REGISTER + path) as r: return json.load(r)

def cmd_init(a):
    os.makedirs(os.path.join(HOME, "agents"), exist_ok=True); os.chmod(HOME, 0o700)
    p = os.path.join(HOME, "owner.key")
    if os.path.exists(p): sys.exit(f"{p} already exists. Owner ID: {did(load_key(p))}")
    k = Ed25519PrivateKey.generate(); save_key(p, k)
    wj(os.path.join(HOME, "owner.json"), {"name": a.owner[:120], "website": a.website, "listed": not a.hidden})
    print(f"Owner key written to {p}. Keep it private and backed up.\nOwner ID: {did(k)}")

def cmd_join(a):
    ok, o = owner(); os.makedirs(os.path.join(HOME, "agents"), exist_ok=True)
    kp = os.path.join(HOME, "agents", a.agent + ".key")
    if os.path.exists(kp): sys.exit(f'"{a.agent}" already has a key here.')
    k = Ed25519PrivateKey.generate()
    issued = now(); expires = (datetime.now(timezone.utc) + timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%SZ")
    d = {"v": 1, "type": "traceable-agent", "id": did(k), "owner": did(ok), "name": a.agent, "kind": a.kind, "environment": "test" if a.test else "production", "issuedAt": issued, "expiresAt": expires}
    own = {"id": did(ok), "name": o["name"], "listed": o.get("listed", True)}
    if o.get("website"): own["website"] = o["website"]
    body = signed(ok, {"type": "traceable-join", "at": now(), "owner": own, "agent": {"descriptor": d, "ownerSignature": sig(ok, canonical(d).encode())}})
    r = post("/api/v1/register/join", body)
    save_key(kp, k); wj(os.path.join(HOME, "agents", a.agent + ".json"), {"id": d["id"], "fingerprint": fingerprint(k), "name": a.agent, "environment": d["environment"], "descriptor": d})
    print(f"{a.agent} is on the register.\nID:          {d['id']}\nFingerprint: {fingerprint(k)}\nLook it up:  {REGISTER}/a/{fingerprint(k)}")

def cmd_prove(a):
    k, meta = agent(a.agent)
    print(json.dumps(signed(k, {"v": 1, "type": "traceable-proof", "id": meta["id"], "challenge": a.challenge, "audience": a.audience, "at": now()})))

def cmd_check(a):
    r = post("/api/v1/register/check", {"proof": json.loads(a.proof), "challenge": a.challenge} if a.proof else {"id": a.id})
    print(r.get("summary") or r.get("answer") or json.dumps(r, indent=2))

def cmd_receipt(a):
    k, meta = agent(a.agent); ok, _ = owner()
    rec = get(f"/api/v1/register/agents/{meta['id']}").get("record", {})
    seq = (rec.get("headSeq") or 0) + 1; prev = rec.get("headHash") or GENESIS; at = now()
    action_hash = sha256(a.action.encode()).hex() if a.action else None
    ledger_row_hash = sha256(canonical({"at": at, "kind": a.kind, "decision": a.decision, "actionHash": action_hash, "seq": seq}).encode()).hex()
    h = sha256(canonical(["traceable-receipt", meta["id"], seq, at, a.kind, a.decision, a.run, action_hash, ledger_row_hash, prev]).encode()).hex()
    rc = {"seq": seq, "at": at, "kind": a.kind, "decision": a.decision, "runId": a.run, "actionHash": action_hash, "ledgerRowHash": ledger_row_hash, "prevHash": prev, "hash": h, "signature": base64.b64encode(k.sign(bytes.fromhex(h))).decode()}
    r = post("/api/v1/register/receipts", signed(ok, {"verifier": did(ok), "at": now(), "agent": meta["id"], "receipts": [rc]}))
    print(f"Receipt {r['headSeq']} on {a.agent}'s record: {a.kind} / {a.decision}. {REGISTER}/a/{meta['fingerprint']}")

def cmd_whoami(a):
    ok, o = owner(); print(f"Owner: {o['name']}\nID:    {did(ok)}")
    d = os.path.join(HOME, "agents")
    for f in sorted(os.listdir(d)) if os.path.isdir(d) else []:
        if f.endswith(".json"): m = rj(os.path.join(d, f)); print(f"  {m['name']:24} {m['fingerprint']}  {m['environment']}  {REGISTER}/a/{m['fingerprint']}")

if __name__ == "__main__":
    P = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter); sub = P.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("init"); s.add_argument("--owner", required=True); s.add_argument("--website"); s.add_argument("--hidden", action="store_true"); s.set_defaults(f=cmd_init)
    s = sub.add_parser("join"); s.add_argument("agent"); s.add_argument("--kind", default="agent"); s.add_argument("--test", action="store_true"); s.set_defaults(f=cmd_join)
    s = sub.add_parser("prove"); s.add_argument("agent"); s.add_argument("challenge"); s.add_argument("--audience"); s.set_defaults(f=cmd_prove)
    s = sub.add_parser("check"); s.add_argument("id"); s.add_argument("--proof"); s.add_argument("--challenge"); s.set_defaults(f=cmd_check)
    s = sub.add_parser("receipt"); s.add_argument("agent"); s.add_argument("--kind", required=True); s.add_argument("--decision", required=True); s.add_argument("--action"); s.add_argument("--run"); s.set_defaults(f=cmd_receipt)
    s = sub.add_parser("whoami"); s.set_defaults(f=cmd_whoami)
    a = P.parse_args(); a.f(a)
