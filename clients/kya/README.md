# kya: Know Your Agent

Banks run Know Your Customer before they open an account. KYA is the same check for AI agents.
Before one agent deals with another, it asks who the other is, who stands behind it, and what it has done.

`kya` puts an agent on the [Know Your Agent](https://know-your-agent.org) in one command,
lets it prove who it is, writes its record, and checks other agents before dealing with them.
It also gives a service a door: a check on every agent that calls it.

It needs Node 18 or later and nothing else. Keys are made on your machine and never leave it.
The register only ever sees public keys and signatures.

## Put an agent on the register

```sh
npx @sheaf-labs/kya init --owner "Acme Ltd" --website https://acme.example
npx @sheaf-labs/kya join invoice-payer
```

The first command makes your owner key. You sign for your agents with it. The second makes a key for
the agent, signs its ID as its owner, and enters it on the register. It prints the agent's ID, its
fingerprint and the page where anyone can look it up.

The agent is now **identified, owner on record**. Anyone can look it up or find you by name. To become a
**verified** owner, listed on the owners page and counted on the front page, prove you control your domain:

```sh
npx @sheaf-labs/kya verify acme.example      # prints a token to put in DNS or at /.well-known/kya.txt
npx @sheaf-labs/kya verify-check             # the register looks for it
```

See [owner verification](https://know-your-agent.org/format.html#verification).

## The handshake

Agent A wants to deal with agent B.

```sh
# A makes a challenge and sends it to B
kya challenge
# B answers with a proof signed by its key
kya prove invoice-payer 3f9a…
# A checks the proof and reads B's record in one call
kya check 9c21e0a7b4d3f815 --proof '<the JSON B returned>' --challenge 3f9a…
```

The answer is one of three: identified with a verified owner, identified with an owner on record, or
unknown. What A does with each answer is A's own policy.

## The Door

A service checks each agent that calls it. The agent adds one header to its request. The service lets it
in, refuses it, or holds it for a person.

**The agent's side.** One line:

```js
import { proofHeader } from "@sheaf-labs/kya";
import { readFileSync } from "node:fs";

const key = readFileSync(process.env.HOME + "/.config/kya/agents/invoice-payer.key");
const url = "https://tools.acme.example/pay";
await fetch(url, { method: "POST", headers: { "KYA-Proof": proofHeader(key, url) }, body });
```

The header is a proof signed with the agent's key. It names the exact address being called and is good
for 60 seconds. It works once. From a shell: `kya header invoice-payer https://tools.acme.example/pay`.

**The service's side.** Works with Node's http server, Express and Connect:

```js
import { door } from "@sheaf-labs/kya";

const guard = door({
  origin: "https://tools.acme.example",   // this service's own public address
  require: "verified",                     // "identified" (the default), "verified" or "proof"
  approved: new Set(),                     // IDs a person has approved
  refused: new Set(),                      // IDs a person has refused
  onHold: held => notifyAPerson(held)      // without this, an agent that falls short is refused
});
app.use(guard.middleware());               // a request that gets through carries req.kya.id
```

| `require` | Who comes in |
|---|---|
| `identified` | An agent on the register and in good standing. |
| `verified` | The same, and its owner has proved a domain or been reviewed. |
| `proof` | Any agent with a valid proof. The register is not asked. |

An agent with a valid proof that falls short of `require` is held when `onHold` is set: the request gets
status 403 and your function gets the agent's ID, its owner and the reason. To let it in next time, add
its ID to `approved`. A revoked, retired or expired agent is refused even when approved. With no header,
a wrong address, an old proof or a used one, the request gets 401.

Three things to know:

- **Set `origin` yourself.** The door never reads the host from the request. That is what stops a proof
  made for another service from working at yours.
- **The signature is checked on your machine.** The register is asked only who owns the agent and whether
  it is in good standing, at most once a minute for each agent. If the register cannot be reached, the
  door refuses everyone except approved agents.
- **Each proof works once.** The door remembers the ID and random value of each proof for 70 seconds, in memory.
  If your service runs as several processes, pass `seen` with `has(key)` and `add(key, seconds)` backed
  by a store they share.

**A page where a person decides.** `approved` and `onHold` can come from a service that keeps the list of
held agents and shows it to a person:

```js
import { door, approvals } from "@sheaf-labs/kya";

const guard = door({
  origin: "https://tools.acme.example",
  require: "verified",
  ...approvals({ url: "https://approvals.example/door", secret: process.env.KYA_DOOR_SECRET })
});
```

`approvals` needs the address of the service and this door's secret there. It has no default. The service
answers two calls, each with `Authorization: Bearer <secret>`: `GET <url>/approved` gives
`{ approved: [ids], refused: [ids] }`, and `POST <url>/hold` takes `{ id, reason, path }` when an agent is
held. Anyone can run such a service. [TheGuardianAgent](https://theguardianagent.ai/door.html) is one.

Without the middleware: `await guard.check({ path, headers })` answers
`{ decision: "allow" | "hold" | "refuse", reason, id, agent, owner }`.

## The record

```sh
kya receipt invoice-payer --kind payment --decision approved --action "INV-2041 £1,200 to Supplier Ltd"
kya record invoice-payer
```

Each receipt adds one action to the agent's chain: the kind, the decision, the time, a hash of the
action and the hash of the receipt before it. The register never holds the text of the action.
Kinds and decisions are yours to name. Three kinds carry meaning for the Record Score: `held` (a person
stopped the action), `released` (a person let it go ahead) and `rejected` (a person refused it). The score
starts at 100 and comes down with the share of actions held or rejected; the formula is on the format page.
A receipt you write for your own agent is your own report of what it did; the register says so.
Receipts written by a system that runs the agent for you and holds its key carry that system's name.

## Everything else

```sh
kya whoami                      # your owner ID and your agents
kya retire invoice-payer        # end the agent's life; the record stays
kya revoke invoice-payer        # withdraw it for cause; the record stays
KYA_REGISTER=http://localhost:8080 kya …   # another register
KYA_HOME=/path kya …            # where keys live (default ~/.config/kya)
```

## Without this tool

Every call is plain JSON over HTTPS with Ed25519 signatures. The format and every call are on
[know-your-agent.org/format.html](https://know-your-agent.org/format.html). This tool is about 200 lines;
read it to see the exact bytes that are signed.

## Licence

Apache-2.0. The format is open. Anyone may run a register; know-your-agent.org is the public one.
