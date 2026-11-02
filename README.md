# KYA: Know Your Agent

<https://know-your-agent.org>

The open format for agent identity and the Record of Action, and the clients that speak it. The public register that runs it is the Register of Traceable Agents.

Banks run Know Your Customer before they open an account. KYA is the same check for AI agents. Before one agent deals with another, it asks who the other is, who stands behind it, and
what it has done. This repository holds the open format that makes that check possible, the clients that
speak it, and the test vectors any implementation can check itself against.

The public register that runs this format is the [Register of Traceable Agents](https://traceableagents.org).
Anyone may run a register. traceableagents.org is the public one.

## The format in one paragraph

An agent's **ID** is its Ed25519 public key, written as a `did:key`. An **owner** (a company or a person,
with a key of its own) signs a **descriptor** for each agent: name, kind, production or test, dates.
Every checked action adds a **receipt** to the agent's chain, signed by the agent's key and naming the
receipt before it. Anyone can **look an agent up** and get one of three answers: identified with a
verified owner, identified with an owner on record, or unknown. Before two agents deal, one sends the other
a **challenge**; the reply is a **proof** signed by the agent's key, and one call to the register checks
the proof and returns the record. Once an hour the register publishes a **checkpoint**, a hash over every
chain head, anchored in Bitcoin, so nothing under it can be changed by anyone, the register included.

Full text: [`spec/format.md`](spec/format.md). Schemas: [`spec/schemas/`](spec/schemas/).
Vectors: [`spec/vectors/`](spec/vectors/).

## Put an agent on the register

```sh
npx @sheaf-labs/kya init --owner "Acme Ltd"
npx @sheaf-labs/kya join invoice-payer
```

Two commands. The keys are made on your machine and stay there. The register sees only public keys and
signatures. The agent is then identified, with you as the owner on record; prove you control your domain
and you are a verified owner. [`clients/kya`](clients/kya) is the tool, about 200 lines of Node with no
dependencies. [`clients/python/kya.py`](clients/python/kya.py) does the same in Python.

## Check your implementation

```sh
node spec/vectors/verify.mjs
```

`vectors.json` holds fixed keys and signed objects: a descriptor and its owner signature, a child with its
parent's signature, a three-receipt chain, a valid proof and two invalid ones, a checkpoint, a join body
and Record Score cases. An implementation that recomputes the same hashes and accepts and rejects the same
signatures speaks the format.

## Run your own register

```sh
cd server && docker compose up
```

[`server/`](server/) is the register itself: Scala, PostgreSQL, one `docker compose up`. Set
`REGISTER_PEERS=https://traceableagents.org` and it answers for the public register's agents too, after
checking every signature itself. Registers that speak the format look each other up; see
[the format](spec/format.md#registers-that-talk-to-each-other) and [GOVERNANCE.md](GOVERNANCE.md).

## For systems that run agents

A platform that runs agents for its customers and holds their keys issues IDs and writes receipts itself,
through four calls. [`clients/examples/verifier.mjs`](clients/examples/verifier.mjs) is a worked client in
forty lines. Entries from a registered system are looked up at once and enter the public counts once the
register has approved the system. See [the format](spec/format.md#other-systems-that-issue-ids-and-write-receipts).

## What the register never holds

The content of an action. Not the invoice, not the email, not the message. A hash of it, which lets the
owner prove later what the action was without the register ever seeing it.

## Governance

Full text in [GOVERNANCE.md](GOVERNANCE.md).

The register was started by Sheaf Labs in 2026, which built the first system that issues IDs, wrote this
format and runs traceableagents.org. The plan is for the register to be governed by its members: every
system that issues IDs and writes receipts gets a say, and the founding company gets no special answer from
the lookup. Its own agents go through the same door as everyone else's.

## Licences

Code, schemas and vectors: [Apache-2.0](LICENSE). Specification text: [CC BY 4.0](LICENSE-DOCS).
"Traceable Agents" and traceableagents.org: see [TRADEMARKS.md](TRADEMARKS.md).
Contributions: [CONTRIBUTING.md](CONTRIBUTING.md). Security reports: [SECURITY.md](SECURITY.md).
