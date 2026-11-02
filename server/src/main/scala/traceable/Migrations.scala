package traceable

import cats.effect.Async
import cats.implicits._
import doobie._
import doobie.implicits._

/** The register's tables, created or extended at startup. Every statement is idempotent, so the server can start
  * against an empty database or one from an earlier version. The same statements the register at traceableagents.org runs. */
object Migrations {
  def run[F[_]: Async](xa: Transactor[F]): F[Unit] = (for {
      _ <- sql"SELECT 1".query[Int].unique
      _ <- sql"""CREATE TABLE IF NOT EXISTS ta_owners (
                   customer_id    UUID PRIMARY KEY,
                   did            TEXT NOT NULL UNIQUE,
                   public_key     TEXT NOT NULL,
                   private_key_ct TEXT NOT NULL,
                   private_key_iv TEXT NOT NULL,
                   display_name   TEXT NOT NULL,
                   verification   TEXT NOT NULL DEFAULT 'unverified',   -- unverified | verified
                   verified_by    TEXT,
                   verified_at    TIMESTAMPTZ,
                   status         TEXT NOT NULL DEFAULT 'active',
                   created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
                 )""".update.run
      _ <- sql"ALTER TABLE ta_owners ADD COLUMN IF NOT EXISTS listed BOOLEAN NOT NULL DEFAULT false".update.run   // opt-in: names shown publicly
      _ <- sql"ALTER TABLE ta_owners ADD COLUMN IF NOT EXISTS joined_at TIMESTAMPTZ".update.run                   // opt-in: on the register at all (Oct 18 2026)
      _ <- sql"CREATE TABLE IF NOT EXISTS ta_meta (key TEXT PRIMARY KEY, at TIMESTAMPTZ NOT NULL DEFAULT NOW())".update.run
      // Owner verification (Oct 21 2026): the domain claim + token, the company registry match, the keeper's review.
      // Summarised into ta_owners.verification / verified_by / verified_at, which the public pages read.
      _ <- sql"""CREATE TABLE IF NOT EXISTS ta_owner_verification (
                   customer_id           UUID PRIMARY KEY,
                   domain                TEXT,
                   domain_token          TEXT,
                   domain_method         TEXT,          -- dns | file
                   domain_verified_at    TIMESTAMPTZ,
                   domain_checked_at     TIMESTAMPTZ,
                   domain_last_ok_at     TIMESTAMPTZ,
                   domain_last_error     TEXT,
                   company_number        TEXT,
                   company_name          TEXT,
                   company_registry      TEXT,          -- companies-house
                   company_checked_at    TIMESTAMPTZ,
                   reviewed_at           TIMESTAMPTZ,
                   reviewed_by           TEXT,
                   review_note           TEXT,
                   last_check_request_at TIMESTAMPTZ
                 )""".update.run
      _ <- sql"""CREATE TABLE IF NOT EXISTS ta_agents (
                   agent_id        UUID PRIMARY KEY,                    -- the register's own id for the agent
                   customer_id     UUID NOT NULL,
                   did             TEXT NOT NULL UNIQUE,
                   fingerprint     TEXT NOT NULL UNIQUE,
                   public_key      TEXT NOT NULL,
                   private_key_ct  TEXT NOT NULL,
                   private_key_iv  TEXT NOT NULL,
                   descriptor_json TEXT NOT NULL,
                   owner_signature TEXT NOT NULL,
                   name            TEXT NOT NULL,
                   kind            TEXT NOT NULL,
                   status          TEXT NOT NULL DEFAULT 'issued',      -- issued | retired | revoked
                   status_at       TIMESTAMPTZ,
                   status_reason   TEXT,
                   issued_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                   expires_at      TIMESTAMPTZ NOT NULL
                 )""".update.run
      _ <- sql"CREATE INDEX IF NOT EXISTS idx_ta_agents_customer ON ta_agents(customer_id)".update.run
      // Lineage (Oct 18 2026): a child's descriptor names its parent and carries the parent's signature too.
      _ <- sql"ALTER TABLE ta_agents ADD COLUMN IF NOT EXISTS parent_did TEXT".update.run
      _ <- sql"ALTER TABLE ta_agents ADD COLUMN IF NOT EXISTS environment TEXT NOT NULL DEFAULT 'test'".update.run        // production | test, fixed at birth (Oct 18 2026)
      _ <- sql"ALTER TABLE ta_agents ADD COLUMN IF NOT EXISTS parent_signature TEXT".update.run
      _ <- sql"ALTER TABLE ta_agents ADD COLUMN IF NOT EXISTS depth INT NOT NULL DEFAULT 0".update.run
      _ <- sql"CREATE INDEX IF NOT EXISTS idx_ta_agents_parent ON ta_agents(parent_did)".update.run
      _ <- sql"""CREATE TABLE IF NOT EXISTS ta_receipts (
                   agent_id        UUID NOT NULL,
                   seq             BIGINT NOT NULL,
                   customer_id     UUID NOT NULL,
                   ledger_seq      BIGINT NOT NULL,
                   at_iso          TEXT NOT NULL,
                   kind            TEXT NOT NULL,
                   decision        TEXT NOT NULL,
                   run_id          UUID,
                   action_hash     TEXT,
                   ledger_row_hash TEXT NOT NULL,
                   prev_hash       TEXT NOT NULL,
                   receipt_hash    TEXT NOT NULL,
                   agent_signature TEXT NOT NULL,
                   created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                   PRIMARY KEY (agent_id, seq),
                   UNIQUE (customer_id, ledger_seq)
                 )""".update.run
      _ <- sql"""CREATE TABLE IF NOT EXISTS ta_cursor (
                   customer_id UUID PRIMARY KEY,
                   last_seq    BIGINT NOT NULL
                 )""".update.run
      _ <- sql"ALTER TABLE ta_cursor ADD COLUMN IF NOT EXISTS claimed_until TIMESTAMPTZ".update.run
      // Oct 24 2026: a key is an agent's credential. Every key binds to one agent; every ledger row written under a
      // key names that agent (attribution column, outside the row hash so existing rows still verify).
      _ <- sql"""CREATE TABLE IF NOT EXISTS ta_verifiers (
                   did        TEXT PRIMARY KEY,
                   public_key TEXT NOT NULL,
                   name       TEXT NOT NULL,
                   website    TEXT,
                   status     TEXT NOT NULL DEFAULT 'registered',   -- registered | approved | suspended
                   created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                 )""".update.run
      _ <- sql"ALTER TABLE ta_owners   ADD COLUMN IF NOT EXISTS verifier_did TEXT".update.run
      _ <- sql"ALTER TABLE ta_agents   ADD COLUMN IF NOT EXISTS verifier_did TEXT".update.run
      _ <- sql"ALTER TABLE ta_receipts ADD COLUMN IF NOT EXISTS verifier_did TEXT".update.run
      _ <- sql"CREATE INDEX IF NOT EXISTS idx_ta_agents_verifier ON ta_agents(verifier_did)".update.run
      // The public checkpoint (Oct 19 2026): hourly, every chain head folded into one Merkle root, anchored in Bitcoin via OpenTimestamps.
      _ <- sql"""CREATE TABLE IF NOT EXISTS ta_checkpoints (
                   seq              BIGINT PRIMARY KEY,
                   at_iso           TEXT NOT NULL,
                   agents           INT NOT NULL,
                   receipts         BIGINT NOT NULL,
                   root             TEXT NOT NULL,
                   prev_root        TEXT,
                   statement        TEXT NOT NULL,
                   statement_hash   TEXT NOT NULL,
                   leaves_json      TEXT NOT NULL,
                   calendar_url     TEXT,
                   proof            BYTEA,
                   status           TEXT NOT NULL DEFAULT 'pending',   -- pending | confirmed | unanchored
                   bitcoin_height   BIGINT,
                   confirmed_at     TIMESTAMPTZ,
                   upgrade_attempts INT NOT NULL DEFAULT 0,
                   last_error       TEXT,
                   created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
                 )""".update.run
    } yield ()).transact(xa).void
}
