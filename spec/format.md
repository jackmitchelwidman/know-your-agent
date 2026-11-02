# The Traceable Agents format, version 1

This is the format behind KYA, Know Your Agent, as served by the [Register of Traceable Agents](https://traceableagents.org)
at <https://traceableagents.org/format.html>. The register's own `GET /api/v1/register/format` returns the same definitions
as JSON. JSON Schemas for each object are in [`schemas/`](schemas/) and signed test vectors in [`vectors/`](vectors/).

Text: CC BY 4.0. Schemas and vectors: Apache-2.0.


Four things: an ID, a descriptor the owner signs, a receipt the agent signs, and a lookup anyone can call. Everything is plain JSON and standard cryptography, so a verifier can check a record without talking to this site.

## The ID

An agent's ID is its Ed25519 public key, written as a W3C `did:key`: the two multicodec bytes `0xed 0x01`, then the 32 key bytes, base58btc encoded with the multibase prefix `z`.

    did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK

The short form people read is the **fingerprint**: the first 16 hex characters of sha256 over the 32 key bytes. The lookup accepts either.

Owners have an ID of the same shape. An agent built on the Agent Passport System (APS) or holding any Ed25519 DID can keep its key: the register binds the record to the key itself, whoever issued it.

## The descriptor

What the owner signs. Canonical JSON: keys sorted, no whitespace (RFC 8785 style). The signature is Ed25519 over the UTF-8 bytes of that text, by the owner's key.

    {"expiresAt":"2027-10-18T00:12:09Z","id":"did:key:z6Mk…agent","issuedAt":"2026-10-18T00:12:09Z",
     "kind":"agent","name":"turkey-news-emailer","owner":"did:key:z6Mk…owner","type":"traceable-agent","v":1}

A descriptor with a valid owner signature makes the agent **identified**. Changing the agent's name or kind is an event in the record, never a new ID.

## Production or test

Every descriptor carries `environment`: `production` or `test`, chosen by the owner when the ID is issued and fixed from then on, because it is inside what the owner signed. A test agent is a full entry: the same ID, the same receipts, the same standing. It simply says what it is, to everyone, forever. A sub-agent takes its parent's environment. An owner whose test agent has done its job retires it: the ID reads `retired`, the record stays.

## The receipt

One per checked action. The receipt commits to a JSON array, canonicalised the same way; the receipt hash is sha256 over those bytes and the agent's key signs the 32 hash bytes.

    ["traceable-receipt", id, seq, at, kind, decision, runId, actionHash, ledgerRowHash, prevHash]

`runId` is null for an action the agent took directly with its key, outside a run. Every key is one agent's credential, so such an action is still the agent's.

  - id  
    the agent's did:key
  - seq  
    1, 2, 3… per agent, no gaps
  - at  
    when the action was checked, ISO 8601 UTC
  - kind, decision  
    what sort of event and what the verdict was, for example `held / hold`, `released / release`, `run_started / start`
  - runId  
    the run the action belonged to, or null
  - actionHash  
    sha256 of the action's subject and input, kept by the owner; null when there was none. The register never holds the content.
  - ledgerRowHash  
    the hash of the verifier's own ledger row, so the receipt can be matched to the verifier's evidence
  - prevHash  
    the hash of the receipt before it; the first receipt names 64 zeros

## Lineage

An agent made by another agent is a child. Its descriptor carries one more field, `parent`, the parent's ID, and it is signed twice: by the owner's key and by the parent agent's key. Both signatures are over the same canonical bytes. The parent's key, like every agent key, is held by the verifier that issued it, so the parent's signature says the verifier saw this child issued under that parent. A child made in the course of a run also leaves a receipt on the parent's record. Standing runs down the line: if an ancestor is revoked, retired or lapses, every agent below it is out of standing with it. Lineage is fixed at birth and never changes.

Because each receipt names the one before it, nothing can be removed or reordered without the chain breaking. The receipt format is compatible in spirit with APS receipts; a verifier that reads those can read these.

## The lookup

Free, no account. All responses are JSON and allow cross-origin reads.

    GET https://traceableagents.org/api/v1/register/lookup?id=<did or fingerprint>
    GET https://traceableagents.org/api/v1/register/agents/<id>
    GET https://traceableagents.org/api/v1/register/agents/<id>/receipts?limit=50&before=<seq>
    GET https://traceableagents.org/api/v1/register/agents/<id>/verify
    GET https://traceableagents.org/api/v1/register/owners/<owner did>
    GET https://traceableagents.org/api/v1/register/stats
    GET https://traceableagents.org/api/v1/register/format

The lookup answers with `status` (`identified` or `unknown`), a one-line `answer`, the agent, the owner with its verification state, the record's counts and chain head, and a `proof` block with the descriptor, the owner's signature and both public keys. `verify` recomputes the whole chain on the server and reports any problem; you can do the same yourself from `receipts`.

## The handshake

Before agent A acts for or with agent B, two calls settle who B is and what its record holds.

1.  **A sends B a challenge.** Any fresh random string, used once. B asks its verifier to sign it with B's key: the key stays with the verifier, so B's runtime never holds it. B hands the signed proof back to A.
2.  **A checks the proof and reads the record.** One call to the register, with the proof and the challenge A issued. The answer is the lookup above, plus whether the proof is B's.

<!-- end list -->

    POST https://traceableagents.org/api/v1/register/check
    {"proof": {…the document B gave A…}, "challenge": "…what A sent B…"}
    POST https://traceableagents.org/api/v1/register/check
    {"id": "<did or fingerprint>"}            (a lookup without a proof)

The proof is `{v:1, type:"traceable-proof", id, challenge, audience?, at}` in canonical JSON, signed by the agent key (Ed25519, base64 in `signature`), good for ten minutes. The answer adds `identityProof` (`checked`, `valid`, `reason`) and a one-paragraph `summary` in plain words. What A does with the answer is A's own policy; a verifier that runs A records the check on A's record, so a counterparty check is itself an act the record shows.

## The Record of Action and the Record Score

An agent's Record of Action is its chain of receipts read as a history: how many times it acted through a verifier, how many times a person held it, released it or rejected it, the last 90 days on their own, the sub-agents it started, the other agents it checked before dealing with them, and the identity proofs it gave. `GET /api/v1/register/agents/<id>/record` returns the numbers, a one-paragraph story in plain words, and a 30-day timeline.

The **Record Score** is one number from those receipts, by a formula anyone can recompute: start at 100; subtract 30 times the share of actions that were held; subtract 50 times the share that were rejected; subtract 10 if there was a rejection in the last 90 days; subtract 10 if there are fewer than 20 actions; keep it between 0 and 100. There is no score before the first action. The score is a reading of the record, not a judgement by the register: the receipts behind it are public and the formula will only change with notice on this page.

## Standing

  - good  
    issued, not retired, not revoked, renewal date in the future
  - expired  
    the owner has not renewed; the record stays
  - retired  
    the owner ended the agent's life; the record stays, the ID is never reissued
  - revoked  
    the owner or the register withdrew it for cause; the record stays

## The public checkpoint

Once an hour, when anything has moved, the register takes the head of every agent's chain and publishes one hash that commits to all of them. After that, a receipt under the checkpoint cannot be changed by anyone, the keeper of the register included, without the published hash ceasing to match. Anyone who keeps copies of the checkpoints can catch it.

  - leaf  
    sha256 of canonical `["traceable-checkpoint-leaf", id, headSeq, headHash]`, one per agent that has a receipt, sorted by id
  - root  
    a Merkle tree over the leaves: each node is sha256(left ++ right); an odd last node is paired with itself
  - statement  
    canonical `{v:1, type:"traceable-checkpoint", at, agents, receipts, root, prevRoot}`; each checkpoint names the root before it
  - anchor  
    sha256 of the statement bytes is submitted to OpenTimestamps calendars, which commit it to Bitcoin within a few hours. The proof file is published; `ots verify -d <statementHash> checkpoint-<seq>.ots` checks it against a Bitcoin node with no trust in this site
  - calls  
    `GET /api/v1/register/checkpoints`, `/checkpoints/<seq>` (statement and every leaf), `/checkpoints/<seq>/proof.ots`, and `/agents/<id>/checkpoint`, which gives the newest checkpoint covering an agent and the path of sibling hashes from its leaf to the root

## Entering your own agents

An owner does not need a system in between. One call enters an agent under the owner's own key, and the owner then writes the agent's receipts and standing itself through the calls in the next section, naming its own ID as the `verifier`.

  - Join  
    `POST /api/v1/register/join` with `{type:"traceable-join", at, owner:{id, name, website, listed}, agent:{descriptor, ownerSignature, parentSignature}, signature}`. The descriptor is exactly the one above, signed by the owner's key; the whole body is signed by the owner's key too. The owner's ID is its did:key. On the first call the owner is recorded; every later call adds another agent under the same owner.
  - What the lookup says  
    Identified, owner on record, not yet verified. The lookup also says the owner issued the ID itself and holds the agent's key, so the agent's receipts are the owner's own report. The agent can be looked up and the owner searched by name at once. An owner that proves its domain (below) becomes verified and from then on appears on the owners page and in the public counts; a system that runs the agent and holds its key out of the owner's reach writes under its own name instead.
  - The tool  
    `npx @sheaf-labs/kya init --owner "Name"` then `npx @sheaf-labs/kya join <agent-name>`. About two hundred lines of Node with no dependencies; it also answers challenges (`prove`), checks other agents (`check`), writes receipts (`receipt`) and ends an agent's life (`retire`, `revoke`). Apache-2.0.

## Other systems that issue IDs and write receipts

Sheaf is one system that issues IDs and writes receipts. Any other system can do the same, in the format above, through four calls. The register never holds that system's keys. It checks every signature from the public keys and keeps the chain rules, so an entry written this way verifies exactly like one Sheaf wrote, with the same `/verify` call.

Every write is one JSON body, signed by the writing system's key over the canonical form of the body without its `signature` field. Canonical means keys sorted at every level, no whitespace, UTF-8. Each body carries `at`, the current time, and is accepted for ten minutes.

  - Register  
    `POST /api/v1/register/verifiers` with `{type:"traceable-verifier", id, name, website, at, signature}`. `id` is the system's did:key. The signature is that key's, which is how the system proves it holds it. The system is then registered. The register approves it separately; until then its entries can be looked up by ID but do not enter the public counts, search or the owners page.
  - Entry  
    `POST /api/v1/register/entries` with `{verifier, at, owner:{id, name, listed}, agent:{descriptor, ownerSignature, parentSignature}, signature}`. The descriptor is exactly the one above, signed by the owner's key. A child names its parent, who must already be on the register under the same owner, and carries the parent key's signature over the same bytes. An owner can be written to only by the system that brought it.
  - Receipts  
    `POST /api/v1/register/receipts` with `{verifier, at, agent, receipts:[…], signature}`. Each receipt is `{seq, at, kind, decision, runId, actionHash, ledgerRowHash, prevHash, hash, signature}`, in chain order. The register recomputes each hash from the preimage above, checks `prevHash` against its head, and checks the agent key's signature over the hash. One bad receipt refuses the call and nothing after it is written. Sending a receipt again is accepted when it is identical and refused when it is not.
  - Standing  
    `POST /api/v1/register/entries/status` with `{verifier, at, agent, status, reason, signature}`, status `retired` or `revoked`.
  - Who issued what  
    `GET /api/v1/register/verifiers` lists the systems and whether the register has approved them, and how many owners have entered their own agents. Every lookup says which system issued the agent, or that the owner did.

A worked client in forty lines of Node, using only the built-in Ed25519, is at [clients/examples/verifier.mjs](https://github.com/jackmitchelwidman/traceable-agents/blob/main/clients/examples/verifier.mjs) in the open repository, with the format as Markdown, JSON Schemas, signed test vectors and the register server itself. It registers a system, writes an owner and an agent, writes two receipts, and calls `/verify`.

## Registers that talk to each other

Anyone may run a register from the published server. Registers that speak this format answer each other's lookups, so an agent entered on one can be checked from another. Each register publishes who it is and whom it asks:

  - Self  
    `GET /api/v1/register/self` returns `{register:{id, name, url}, peers:[…]}`. `id` is the register's own did:key, when it has one.
  - The hop  
    A lookup that finds nothing on this register is asked, once, of each peer: `GET <peer>/api/v1/register/lookup?id=…&local=1`. The `local` flag stops the peer from asking its own peers, so a question travels one hop and never loops.
  - Trust  
    A peer can report; it cannot vouch. This register uses a peer's answer only after it has re-checked, from the public keys inside the answer, that `ownerSignature` is the owner key's over the canonical descriptor and that `descriptor.owner` is that key. An answer that fails the check is treated as not found. The standing, counts and Record Score in a forwarded answer are the peer's report and are marked as such.
  - What the answer says  
    Every answer carries `register:{url, name, id}`, the register that holds the entry. A forwarded answer also carries `federated:true`, `verifiedHere:true` and `askedBy`, the register you asked.

The register at traceableagents.org is the canonical one: the instance systems check by default. A second operator joins by publishing its `self` and asking the existing operators to list it as a peer. How that is decided is in the [governance note](https://github.com/jackmitchelwidman/traceable-agents/blob/main/GOVERNANCE.md).

## Owner verification

An owner is **verified** when it has proved control of a domain, or when the register's keeper has reviewed it. The proof of a domain is a token the register gives the owner, placed where only the domain's controller can put it:

  - A DNS record  
    `_traceableagents.<domain>`  TXT  `"traceableagents-verify=<token>"`
  - Or a file  
    `https://<domain>/.well-known/traceable-agents.txt` containing the line `traceableagents-verify=<token>`

Beneath verified sits a weaker mark, **email confirmed**: the owner signed in with a code sent to its email address, so the register knows the address is real and in the owner's hands. It says nothing about who the owner is. The address itself is never shown. An owner with no domain and no company, an individual for instance, carries this mark until it proves a domain or is reviewed.

An owner that entered its own agents claims and checks its domain with two signed calls: `POST /api/v1/register/owners/verify` with `{type:"traceable-verify", owner, domain, at, signature}` returns the token; `POST /api/v1/register/owners/verify/check` with `{type:"traceable-verify-check", owner, at, signature}` looks for it. The tool does this as `kya verify <domain>` and `kya verify-check`.

The register checks the record when the owner asks and again every day. A domain whose record disappears keeps its mark for 45 days, then loses it until the record is back. Once a domain is proved, the owner may attach a **Companies House** entry by number; the register fetches the registered name from Companies House and shows it beside the domain. The domain proof shows the owner controls that domain. The company entry shows which registered company the owner says it is; the two are tied together by the keeper's review, which is the third mark. A lookup says which of the three an owner holds, in the `proof` field of the owner.

## What is not in version 1

Incarnations (a session key per run, including a run restored from a saved context) and yearly renewal. These are designed and come next. The ID and receipt formats above will not change under them.
