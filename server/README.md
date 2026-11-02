# The register server

A standalone Know Your Agent: the same code that runs know-your-agent.org, with nothing of
Sheaf in it. Scala 3, http4s, PostgreSQL. It issues nothing itself and never holds a private key: owners
enter their agents through `/join` (the `kya` tool) and systems that run agents write through the verifier
door, all with signatures the register checks from public keys.

## Run it

```sh
docker compose up
```

Postgres plus the register on <http://localhost:8080>, pages included. Then, from another terminal:

```sh
KYA_REGISTER=http://localhost:8080 npx @sheaf-labs/kya init --owner "Me"
KYA_REGISTER=http://localhost:8080 npx @sheaf-labs/kya join first-agent
```

Without Docker: `sbt run` with `DATABASE_URL` set (see `Main.scala` for every setting), or
`sbt assembly` and `java -jar target/scala-3.3.3/register.jar`.

## The pages

`site/` is a copy of know-your-agent.org's pages. The masthead takes your register's name from
`REGISTER_NAME` at load, but the About page, the footer ("Kept by Sheaf Labs") and the Join text describe
the canonical register. Replace them with your own before you publish: the names and seal of the canonical
register are not yours to use (see [TRADEMARKS.md](../TRADEMARKS.md)). Set `SITE_DIR=` empty to serve the
API alone and put your own site in front.

## Settings

| Variable | Meaning | Default |
|---|---|---|
| `DATABASE_URL` | `postgresql://user:pass@host:5432/db` | required |
| `PORT` | listen port | 8080 |
| `SITE_DIR` | the pages to serve at `/`; empty serves the API only | `site` |
| `REGISTER_NAME` | the register's name, carried in every answer | A register of traceable agents |
| `REGISTER_SELF_URL` | its public address | `http://localhost:PORT` |
| `REGISTER_DID` | its own did:key, if it has one | none |
| `REGISTER_PEERS` | registers to ask when an ID is not here, comma-separated | none |
| `OTS_ENABLED` | anchor the hourly checkpoint in Bitcoin via OpenTimestamps | true |
| `OTS_CALENDARS` | calendar servers, comma-separated | the public ones |
| `COMPANIES_HOUSE_API_KEY` | the UK company mark on owners | off |

The tables are created at startup; every statement is idempotent.

## Join the network

Set `REGISTER_PEERS=https://know-your-agent.org` and your register answers for every agent on the
public one as well as its own, after re-checking each signature itself. To be asked in return, publish
your `GET /api/v1/register/self` and write to register@know-your-agent.org; see
[GOVERNANCE.md](../GOVERNANCE.md).

## What is in here

| File | What |
|---|---|
| `TraceableAgents.scala` | keys, did:key, canonical JSON, descriptors, receipts, proofs |
| `TraceableVerifierService.scala` | the doors: `/join`, `/verifiers`, `/entries`, `/receipts`, `/entries/status`, owner verification |
| `TraceableAgentsRoutes.scala` | the public API, the lookup and the handshake, register-to-register lookup |
| `ChainVerify.scala` | `/verify`: recompute a whole chain from public keys |
| `TraceableVerificationService.scala`, `OwnerVerification.scala` | domain proof (DNS or well-known file), Companies House, review |
| `TraceableCheckpointService.scala`, `Ots.scala` | the hourly Merkle checkpoint and its Bitcoin anchor |
| `TraceableAgentsRepository.scala`, `Migrations.scala` | PostgreSQL |
| `Site.scala` | the pages in `site/` |

Tests: `sbt test`. Conformance: `node ../spec/vectors/verify.mjs`.
