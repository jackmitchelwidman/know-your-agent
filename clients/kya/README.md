# kya: Know Your Agent

Banks run Know Your Customer before they open an account. KYA is the same check for AI agents.
Before one agent deals with another, it asks who the other is, who stands behind it, and what it has done.

`kya` puts an agent on the [Know Your Agent](https://know-your-agent.org) in one command,
lets it prove who it is, writes its record, and checks other agents before dealing with them.

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
