// The owner key tool: hold your own key for the Register of Traceable Agents.
//   node owner.mjs keygen            makes owner.key (keep it private) and prints your owner ID (did:key)
//   node owner.mjs id                prints the owner ID of owner.key
//   node owner.mjs sign              reads a descriptor (the exact text the console shows) from stdin, prints the signature
// Uses only Node's built-in Ed25519. Nothing leaves this machine.
import { generateKeyPairSync, createPrivateKey, sign } from "node:crypto";
import { readFileSync, writeFileSync, existsSync } from "node:fs";

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const b58 = bytes => { let n = BigInt("0x" + Buffer.from(bytes).toString("hex")), s = ""; while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; } return s; };
const didOf = priv => { const pub = Buffer.from(createPrivateKey(priv).export({ format: "jwk" }).x, "base64url"); return "did:key:z" + b58(Buffer.concat([Buffer.from([0xed, 0x01]), pub])); };
const FILE = process.env.OWNER_KEY || "owner.key";
const cmd = process.argv[2];

if (cmd === "keygen") {
  if (existsSync(FILE)) { console.error(FILE + " already exists. Move it away first; a lost key cannot be replaced."); process.exit(1); }
  const { privateKey } = generateKeyPairSync("ed25519");
  writeFileSync(FILE, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  console.log("Owner key written to " + FILE + ". Keep it private and backed up.");
  console.log("Owner ID: " + didOf(readFileSync(FILE)));
} else if (cmd === "id") {
  console.log(didOf(readFileSync(FILE)));
} else if (cmd === "sign") {
  const text = readFileSync(0, "utf8").trim();
  JSON.parse(text); // must be the descriptor exactly as shown; the signature is over these bytes
  console.log(sign(null, Buffer.from(text, "utf8"), createPrivateKey(readFileSync(FILE))).toString("base64"));
} else {
  console.log("usage: node owner.mjs keygen | id | sign < descriptor.json");
}
