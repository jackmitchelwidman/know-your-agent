package traceable
import cats.effect._
import cats.implicits._
import doobie._
import doobie.implicits._
import doobie.postgres.implicits._
import java.util.UUID

/**
 * Traceable Agents storage: owners (one per customer), agent IDs,
 * the per-agent receipt chain, and the ledger cursor the tailing job advances.
 * Tables are created in DiscursaServer.ensureCoreConversationColumns.
 */
final case class TaOwnerRow(customerId: UUID, did: String, publicKey: String, privateKeyCt: String, privateKeyIv: String,
  displayName: String, verification: String, verifiedBy: Option[String], verifiedAt: Option[String], status: String, createdAt: String,
  listed: Boolean, joinedAt: Option[String], verifierDid: Option[String] = None) {
  /** On the register: the owner asked to be, and has not left. Nothing is issued or written for anyone else. */
  def joined: Boolean = joinedAt.nonEmpty
}

/** One row of the public owners directory: listed owners only. */
final case class TaOwnerCard(did: String, displayName: String, verification: String, joinedAt: String, agents: Long, inStanding: Long, receipts: Long)

/** One search hit: an owner or an agent, by name, among listed owners only. */
final case class TaSearchHit(kind: String, id: String, fingerprint: Option[String], name: String, ownerDid: String, ownerName: String, status: Option[String], environment: Option[String])
final case class TaStats(owners: Long, agents: Long, agentsInStanding: Long, receipts: Long,
                         testAgents: Long, testAgentsInStanding: Long, testReceipts: Long)

final case class TaAgentRow(agentId: UUID, customerId: UUID, did: String, fingerprint: String, publicKey: String,
  privateKeyCt: String, privateKeyIv: String, descriptorJson: String, ownerSignature: String, name: String, kind: String,
  status: String, statusAt: Option[String], statusReason: Option[String], issuedAt: String, expiresAt: String,
  parentDid: Option[String], parentSignature: Option[String], depth: Int, environment: String = "test", verifierDid: Option[String] = None)

/** A system that issues IDs and writes receipts through the open door. Sheaf itself has no row. */
final case class TaVerifierRow(did: String, publicKey: String, name: String, website: Option[String], status: String, createdAt: String)

/** One public checkpoint: every chain head at one moment, folded into one root. */
final case class TaCheckpointRow(seq: Long, atIso: String, agents: Int, receipts: Long, root: String, prevRoot: Option[String],
  statement: String, statementHash: String, calendarUrl: Option[String], status: String, bitcoinHeight: Option[Long],
  confirmedAt: Option[String], upgradeAttempts: Int, lastError: Option[String])

/** One link of a lineage: enough to show and link, nothing private. */
final case class TaLineageRow(did: String, fingerprint: String, name: String, status: String, expiresAt: String, depth: Int)

final case class TaReceiptRow(agentId: UUID, seq: Long, customerId: UUID, ledgerSeq: Long, atIso: String, kind: String,
  decision: String, runId: Option[String], actionHash: Option[String], ledgerRowHash: String, prevHash: String,
  receiptHash: String, agentSignature: String)

final case class TaSummary(receipts: Long, held: Long, released: Long, rejected: Long, firstAt: Option[String],
  lastAt: Option[String], lastHeldAt: Option[String], runs: Long)
/** The Record of Action in numbers: everything the score and the plain summary are computed from. */
final case class TaRecord(receipts: Long, held: Long, released: Long, rejected: Long, firstAt: Option[String], lastAt: Option[String],
  lastHeldAt: Option[String], lastRejectedAt: Option[String], runs: Long, acts90: Long, held90: Long, rejected90: Long,
  checks: Long, proofs: Long, subAgents: Long)

/** A ledger row as the tailing job sees it: everything it needs, nothing it must not keep. */
final case class TaLedgerRow(seq: Long, atIso: String, kind: String, decision: String, runId: Option[UUID],
  rowHash: String, subject: Option[String], inputJson: Option[String], agentId: Option[UUID] = None)

class TraceableAgentsRepository[F[_]: Async](xa: Transactor[F]) {

  // ── owners ──
  def owner(customerId: UUID): F[Option[TaOwnerRow]] =
    (fr"SELECT" ++ ownerCols ++ fr"FROM ta_owners WHERE customer_id = $customerId").query[TaOwnerRow].option.transact(xa)
  def ownerByDid(did: String): F[Option[TaOwnerRow]] =
    (fr"SELECT" ++ ownerCols ++ fr"FROM ta_owners WHERE did = $did").query[TaOwnerRow].option.transact(xa)
  private val ownerCols = fr"customer_id, did, public_key, private_key_ct, private_key_iv, display_name, verification, verified_by, verified_at::text, status, created_at::text, listed, joined_at::text, verifier_did"
  /** Opt in (or out) of showing the owner's name and its agents' names on the public register. */
  def setListed(customerId: UUID, listed: Boolean): F[Int] =
    sql"UPDATE ta_owners SET listed = $listed WHERE customer_id = $customerId".update.run.transact(xa)
  /** Join the register: from now on this account's agents get IDs and its checked actions get receipts.
    * A first join starts the cursor at 0, so the agents' whole history goes on the record (each receipt
    * carries the action's original time); a rejoin keeps the cursor where it was, so nothing is receipted
    * twice. Returns 1 when
    * this call did the joining (the row was not joined before), 0 when it already was: with two tasks
    * running the job, only the caller that gets 1 writes the "joined" ledger row. Names show on join. */
  def join(customerId: UUID): F[Int] =
    (for {
      n <- sql"UPDATE ta_owners SET listed = TRUE, joined_at = NOW() WHERE customer_id = $customerId AND joined_at IS NULL".update.run
      _ <- sql"""INSERT INTO ta_cursor (customer_id, last_seq) VALUES ($customerId, 0)
                ON CONFLICT (customer_id) DO NOTHING""".update.run
    } yield n).transact(xa)
  /** Has the one-time clean start of Oct 18 2026 run? Joining waits for it, or the join would be wiped minutes later. */
  def cleanStartDone: F[Boolean] =
    sql"SELECT COUNT(*) FROM ta_meta WHERE key = ${TraceableAgentsRepository.CleanStartKey}".query[Long].unique.transact(xa).map(_ > 0)
  /** Leave: no new IDs, no new receipts. Everything already on the record stays. */
  def leave(customerId: UUID): F[Int] =
    sql"UPDATE ta_owners SET joined_at = NULL, listed = false WHERE customer_id = $customerId".update.run.transact(xa)
  def insertOwner(r: TaOwnerRow): F[Int] =
    sql"""INSERT INTO ta_owners (customer_id, did, public_key, private_key_ct, private_key_iv, display_name, listed)
          VALUES (${r.customerId}, ${r.did}, ${r.publicKey}, ${r.privateKeyCt}, ${r.privateKeyIv}, ${r.displayName}, ${r.listed})
          ON CONFLICT (customer_id) DO NOTHING""".update.run.transact(xa)
  /** An owner another verifier signs for. Its key is its own; the register holds only the public half. */
  def insertExternalOwner(r: TaOwnerRow, listed: Boolean): F[Int] =
    sql"""INSERT INTO ta_owners (customer_id, did, public_key, private_key_ct, private_key_iv, display_name, listed, joined_at, verifier_did)
          VALUES (${r.customerId}, ${r.did}, ${r.publicKey}, '', '', ${r.displayName}, $listed, NOW(), ${r.verifierDid})
          ON CONFLICT (customer_id) DO NOTHING""".update.run.transact(xa)
  def setOwnerListing(customerId: UUID, listed: Boolean, name: String): F[Int] =
    sql"UPDATE ta_owners SET listed = $listed, display_name = $name WHERE customer_id = $customerId".update.run.transact(xa)

  // ── verifiers ──
  private val verifierCols = fr"did, public_key, name, website, status, created_at::text"
  def verifier(did: String): F[Option[TaVerifierRow]] =
    (fr"SELECT" ++ verifierCols ++ fr"FROM ta_verifiers WHERE did = $did").query[TaVerifierRow].option.transact(xa)
  def insertVerifier(r: TaVerifierRow): F[Int] =
    sql"""INSERT INTO ta_verifiers (did, public_key, name, website, status) VALUES (${r.did}, ${r.publicKey}, ${r.name}, ${r.website}, ${r.status})
          ON CONFLICT (did) DO UPDATE SET name = EXCLUDED.name, website = EXCLUDED.website""".update.run.transact(xa)
  /** Owners that entered their own agents through the direct door. */
  def selfIssuers: F[Long] = sql"SELECT COUNT(*) FROM ta_verifiers WHERE status = 'self'".query[Long].unique.transact(xa)
  def verifiers: F[List[TaVerifierRow]] =
    (fr"SELECT" ++ verifierCols ++ fr"FROM ta_verifiers ORDER BY created_at").query[TaVerifierRow].to[List].transact(xa)
  /** Who the public counts and the owners page trust: Sheaf's own entries (NULL), approved systems', and an owner
    * issuing for itself once it has proved who it is (verification = 'verified'). Name search is wider: it shows an owner issuing for itself at once (inline in `search`). */
  private val trusted = fr"""(a.verifier_did IS NULL OR a.verifier_did IN (SELECT did FROM ta_verifiers WHERE status = 'approved')
                              OR (a.verifier_did IN (SELECT did FROM ta_verifiers WHERE status = 'self')
                                  AND EXISTS (SELECT 1 FROM ta_owners ov WHERE ov.customer_id = a.customer_id AND ov.verification = 'verified')))"""

  /** The public directory: owners that joined and chose to show their name, newest first. */
  def directory(limit: Int): F[List[TaOwnerCard]] =
    sql"""SELECT o.did, o.display_name, o.verification, o.joined_at::text,
                 (SELECT COUNT(*) FROM ta_agents a WHERE a.customer_id = o.customer_id),
                 (SELECT COUNT(*) FROM ta_agents a WHERE a.customer_id = o.customer_id AND a.status = 'issued' AND a.expires_at > NOW()),
                 (SELECT COUNT(*) FROM ta_receipts r WHERE r.customer_id = o.customer_id)
          FROM ta_owners o WHERE o.joined_at IS NOT NULL AND o.listed
            AND (o.verifier_did IS NULL OR o.verifier_did IN (SELECT did FROM ta_verifiers WHERE status = 'approved')
                 OR (o.verifier_did IN (SELECT did FROM ta_verifiers WHERE status = 'self') AND o.verification = 'verified'))
          ORDER BY o.joined_at DESC LIMIT $limit"""
      .query[TaOwnerCard].to[List].transact(xa)
  /** Search by name among listed owners and their agents. Unlisted owners never match. */
  def search(q: String, limit: Int): F[List[TaSearchHit]] = {
    val pat = "%" + q.trim.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    sql"""(SELECT 'owner', o.did, NULL::text, o.display_name, o.did, o.display_name, NULL::text, NULL::text
            FROM ta_owners o WHERE o.joined_at IS NOT NULL AND o.listed AND o.display_name ILIKE $pat
              AND (o.verifier_did IS NULL OR o.verifier_did IN (SELECT did FROM ta_verifiers WHERE status IN ('approved', 'self'))))
          UNION ALL
          (SELECT 'agent', a.did, a.fingerprint, a.name, o.did, o.display_name, a.status, a.environment
            FROM ta_agents a JOIN ta_owners o ON o.customer_id = a.customer_id
            WHERE o.joined_at IS NOT NULL AND o.listed AND a.name ILIKE $pat
              AND (a.verifier_did IS NULL OR a.verifier_did IN (SELECT did FROM ta_verifiers WHERE status IN ('approved', 'self'))))
          LIMIT $limit""".query[TaSearchHit].to[List].transact(xa)
  }

  // ── agents ──
  private val agentCols = fr"""agent_id, customer_id, did, fingerprint, public_key, private_key_ct, private_key_iv, descriptor_json, owner_signature,
                              name, kind, status, status_at::text, status_reason, issued_at::text, expires_at::text, parent_did, parent_signature, depth, environment, verifier_did"""
  def agentByDid(did: String): F[Option[TaAgentRow]] =
    (fr"SELECT" ++ agentCols ++ fr"FROM ta_agents WHERE did = $did").query[TaAgentRow].option.transact(xa)
  /** Parent, grandparent, ... up to the root (nearest first). Capped so a bad row cannot loop. */
  def ancestors(did: String): F[List[TaLineageRow]] =
    sql"""WITH RECURSIVE up AS (
            SELECT a.did, a.fingerprint, a.name, a.status, a.expires_at::text, a.depth, a.parent_did, 1 AS n
            FROM ta_agents a WHERE a.did = (SELECT parent_did FROM ta_agents WHERE did = $did)
            UNION ALL
            SELECT a.did, a.fingerprint, a.name, a.status, a.expires_at::text, a.depth, a.parent_did, up.n + 1
            FROM ta_agents a JOIN up ON a.did = up.parent_did WHERE up.n < 1000)
          SELECT did, fingerprint, name, status, expires_at, depth FROM up ORDER BY n""".query[TaLineageRow].to[List].transact(xa)
  def children(did: String): F[List[TaLineageRow]] =
    sql"""SELECT did, fingerprint, name, status, expires_at::text, depth FROM ta_agents WHERE parent_did = $did ORDER BY issued_at"""
      .query[TaLineageRow].to[List].transact(xa)
  def agent(agentId: UUID): F[Option[TaAgentRow]] =
    (fr"SELECT" ++ agentCols ++ fr"FROM ta_agents WHERE agent_id = $agentId").query[TaAgentRow].option.transact(xa)
  /** Look an agent up by any form of its ID: the did:key, the 16-hex fingerprint, or the Sheaf UUID. */
  def agentByAnyId(s: String): F[Option[TaAgentRow]] = {
    val id = s.trim
    val asUuid = scala.util.Try(UUID.fromString(id)).toOption
    (fr"SELECT" ++ agentCols ++ fr"FROM ta_agents WHERE did = $id OR fingerprint = ${id.toLowerCase} OR agent_id = ${asUuid.getOrElse(new UUID(0L, 0L))}")
      .query[TaAgentRow].option.transact(xa)
  }
  def insertAgent(r: TaAgentRow): F[Int] =
    sql"""INSERT INTO ta_agents (agent_id, customer_id, did, fingerprint, public_key, private_key_ct, private_key_iv, descriptor_json, owner_signature,
                                 name, kind, status, issued_at, expires_at, parent_did, parent_signature, depth, environment, verifier_did)
          VALUES (${r.agentId}, ${r.customerId}, ${r.did}, ${r.fingerprint}, ${r.publicKey}, ${r.privateKeyCt}, ${r.privateKeyIv}, ${r.descriptorJson},
                  ${r.ownerSignature}, ${r.name}, ${r.kind}, ${r.status}, ${r.issuedAt}::timestamptz, ${r.expiresAt}::timestamptz,
                  ${r.parentDid}, ${r.parentSignature}, ${r.depth}, ${r.environment}, ${r.verifierDid})
          ON CONFLICT (agent_id) DO NOTHING""".update.run.transact(xa)
  def setAgentStatus(agentId: UUID, status: String, reason: Option[String]): F[Int] =
    sql"""UPDATE ta_agents SET status = $status, status_at = NOW(), status_reason = $reason
          WHERE agent_id = $agentId AND status <> $status""".update.run.transact(xa)
  def agentsOfOwner(customerId: UUID): F[List[TaAgentRow]] =
    (fr"SELECT" ++ agentCols ++ fr"FROM ta_agents WHERE customer_id = $customerId ORDER BY issued_at DESC").query[TaAgentRow].to[List].transact(xa)
  // ── what the OS has that the register does not yet ──
  /** Two backend tasks run the job. A short lease on the cursor row means one of them syncs a customer per cycle. */
  def claim(customerId: UUID): F[Boolean] =
    sql"""UPDATE ta_cursor SET claimed_until = NOW() + INTERVAL '2 minutes'
          WHERE customer_id = $customerId AND (claimed_until IS NULL OR claimed_until < NOW())""".update.run.transact(xa).map(_ == 1)
  def release(customerId: UUID): F[Int] =
    sql"UPDATE ta_cursor SET claimed_until = NULL WHERE customer_id = $customerId".update.run.transact(xa)
  // ── the ledger cursor ──
  def resetCursor(customerId: UUID): F[Int] =
    sql"UPDATE ta_cursor SET last_seq = 0 WHERE customer_id = $customerId".update.run.transact(xa)
  def cursor(customerId: UUID): F[Long] =
    sql"SELECT last_seq FROM ta_cursor WHERE customer_id = $customerId".query[Long].option.transact(xa).map(_.getOrElse(0L))
  def setCursor(customerId: UUID, seq: Long): F[Int] =
    sql"""INSERT INTO ta_cursor (customer_id, last_seq) VALUES ($customerId, $seq)
          ON CONFLICT (customer_id) DO UPDATE SET last_seq = GREATEST(ta_cursor.last_seq, EXCLUDED.last_seq)""".update.run.transact(xa)
  // ── checkpoints ──
  /** Every chain head: (agent did, head seq, head hash), sorted by did so the tree is the same for everyone. */
  def allHeads: F[List[(String, Long, String)]] =
    sql"""SELECT a.did, r.seq, r.receipt_hash FROM ta_receipts r JOIN ta_agents a ON a.agent_id = r.agent_id
          WHERE r.seq = (SELECT MAX(seq) FROM ta_receipts x WHERE x.agent_id = r.agent_id) ORDER BY a.did"""
      .query[(String, Long, String)].to[List].transact(xa)
  private val cpCols = fr"seq, at_iso, agents, receipts, root, prev_root, statement, statement_hash, calendar_url, status, bitcoin_height, confirmed_at::text, upgrade_attempts, last_error"
  def latestCheckpoint: F[Option[TaCheckpointRow]] =
    (fr"SELECT" ++ cpCols ++ fr"FROM ta_checkpoints ORDER BY seq DESC LIMIT 1").query[TaCheckpointRow].option.transact(xa)
  def checkpoint(seq: Long): F[Option[TaCheckpointRow]] =
    (fr"SELECT" ++ cpCols ++ fr"FROM ta_checkpoints WHERE seq = $seq").query[TaCheckpointRow].option.transact(xa)
  def checkpoints(limit: Int): F[List[TaCheckpointRow]] =
    (fr"SELECT" ++ cpCols ++ fr"FROM ta_checkpoints ORDER BY seq DESC LIMIT $limit").query[TaCheckpointRow].to[List].transact(xa)
  def checkpointLeaves(seq: Long): F[Option[String]] =
    sql"SELECT leaves_json FROM ta_checkpoints WHERE seq = $seq".query[String].option.transact(xa)
  def checkpointProof(seq: Long): F[Option[Array[Byte]]] =
    sql"SELECT proof FROM ta_checkpoints WHERE seq = $seq AND proof IS NOT NULL".query[Array[Byte]].option.transact(xa)
  /** The newest checkpoint whose leaves include this agent. */
  def latestCheckpointCovering(did: String): F[Option[TaCheckpointRow]] =
    (fr"SELECT" ++ cpCols ++ fr"FROM ta_checkpoints WHERE leaves_json LIKE ${"%" + did + "%"} ORDER BY seq DESC LIMIT 1").query[TaCheckpointRow].option.transact(xa)
  /** Insert as the next seq. Two tasks taking a checkpoint at once: one wins on the key, the other gets 0. */
  def insertCheckpoint(atIso: String, agents: Int, receipts: Long, root: String, prevRoot: Option[String], statement: String, statementHash: String,
                       leavesJson: String, calendar: Option[String], proof: Option[Array[Byte]]): F[Option[Long]] =
    sql"""INSERT INTO ta_checkpoints (seq, at_iso, agents, receipts, root, prev_root, statement, statement_hash, leaves_json, calendar_url, proof, status)
          SELECT COALESCE(MAX(seq), 0) + 1, $atIso, $agents, $receipts, $root, $prevRoot, $statement, $statementHash, $leavesJson, $calendar, $proof,
                 ${if (proof.isDefined) "pending" else "unanchored"}
          FROM ta_checkpoints
          ON CONFLICT (seq) DO NOTHING RETURNING seq""".query[Long].option.transact(xa)
  def pendingCheckpoints(olderThanMinutes: Int, limit: Int): F[List[(Long, Array[Byte])]] =
    sql"""SELECT seq, proof FROM ta_checkpoints WHERE status = 'pending' AND proof IS NOT NULL
          AND created_at < NOW() - ($olderThanMinutes * INTERVAL '1 minute') AND upgrade_attempts < 1000 ORDER BY seq LIMIT $limit"""
      .query[(Long, Array[Byte])].to[List].transact(xa)
  def checkpointConfirmed(seq: Long, proof: Array[Byte], height: Long): F[Unit] =
    sql"""UPDATE ta_checkpoints SET proof = $proof, status = 'confirmed', bitcoin_height = $height, confirmed_at = NOW(),
          upgrade_attempts = upgrade_attempts + 1, last_error = NULL WHERE seq = $seq""".update.run.transact(xa).void
  def checkpointProgress(seq: Long, proof: Array[Byte]): F[Unit] =
    sql"UPDATE ta_checkpoints SET proof = $proof, upgrade_attempts = upgrade_attempts + 1, last_error = NULL WHERE seq = $seq".update.run.transact(xa).void
  def checkpointAttempt(seq: Long, error: Option[String]): F[Unit] =
    sql"UPDATE ta_checkpoints SET upgrade_attempts = upgrade_attempts + 1, last_error = ${error.map(_.take(500))} WHERE seq = $seq".update.run.transact(xa).void

  // ── receipts ──
  private val receiptCols = fr"agent_id, seq, customer_id, ledger_seq, at_iso, kind, decision, run_id::text, action_hash, ledger_row_hash, prev_hash, receipt_hash, agent_signature"
  def receiptHead(agentId: UUID): F[Option[(Long, String)]] =
    sql"SELECT seq, receipt_hash FROM ta_receipts WHERE agent_id = $agentId ORDER BY seq DESC LIMIT 1".query[(Long, String)].option.transact(xa)
  def insertReceipt(r: TaReceiptRow): F[Int] =
    sql"""INSERT INTO ta_receipts (agent_id, seq, customer_id, ledger_seq, at_iso, kind, decision, run_id, action_hash, ledger_row_hash, prev_hash, receipt_hash, agent_signature)
          VALUES (${r.agentId}, ${r.seq}, ${r.customerId}, ${r.ledgerSeq}, ${r.atIso}, ${r.kind}, ${r.decision}, ${r.runId.map(UUID.fromString)}, ${r.actionHash},
                  ${r.ledgerRowHash}, ${r.prevHash}, ${r.receiptHash}, ${r.agentSignature})
          ON CONFLICT (customer_id, ledger_seq) DO NOTHING""".update.run.transact(xa)
  /** A receipt another verifier wrote. ledger_seq is the owner's next number, assigned here, so two of the
    * owner's agents never collide. Returns 0 when (agent, seq) is already there. */
  def insertExternalReceipt(r: TaReceiptRow, verifierDid: String): F[Int] =
    sql"""INSERT INTO ta_receipts (agent_id, seq, customer_id, ledger_seq, at_iso, kind, decision, run_id, action_hash, ledger_row_hash, prev_hash, receipt_hash, agent_signature, verifier_did)
          SELECT ${r.agentId}, ${r.seq}, ${r.customerId}, COALESCE(MAX(ledger_seq), 0) + 1, ${r.atIso}, ${r.kind}, ${r.decision}, ${r.runId.flatMap(x => scala.util.Try(UUID.fromString(x)).toOption)}, ${r.actionHash},
                 ${r.ledgerRowHash}, ${r.prevHash}, ${r.receiptHash}, ${r.agentSignature}, $verifierDid
          FROM ta_receipts WHERE customer_id = ${r.customerId}
          ON CONFLICT (agent_id, seq) DO NOTHING""".update.run.transact(xa)
  def receiptAt(agentId: UUID, seq: Long): F[Option[String]] =
    sql"SELECT receipt_hash FROM ta_receipts WHERE agent_id = $agentId AND seq = $seq".query[String].option.transact(xa)
  def receipts(agentId: UUID, before: Option[Long], limit: Int): F[List[TaReceiptRow]] = {
    val cut = before.fold(Fragment.empty)(b => fr"AND seq < $b")
    (fr"SELECT" ++ receiptCols ++ fr"FROM ta_receipts WHERE agent_id = $agentId" ++ cut ++ fr"ORDER BY seq DESC LIMIT $limit")
      .query[TaReceiptRow].to[List].transact(xa)
  }
  def receiptsAsc(agentId: UUID, afterSeq: Long, limit: Int): F[List[TaReceiptRow]] =
    (fr"SELECT" ++ receiptCols ++ fr"FROM ta_receipts WHERE agent_id = $agentId AND seq > $afterSeq ORDER BY seq ASC LIMIT $limit")
      .query[TaReceiptRow].to[List].transact(xa)
  def summary(agentId: UUID): F[TaSummary] =
    sql"""SELECT COUNT(*), COUNT(*) FILTER (WHERE kind = 'held'), COUNT(*) FILTER (WHERE kind = 'released'),
                 COUNT(*) FILTER (WHERE kind = 'rejected'), MIN(at_iso), MAX(at_iso), MAX(at_iso) FILTER (WHERE kind = 'held'),
                 COUNT(DISTINCT run_id)
          FROM ta_receipts WHERE agent_id = $agentId""".query[TaSummary].unique.transact(xa)

  def record(agentId: UUID, did: String): F[TaRecord] =
    sql"""SELECT COUNT(*), COUNT(*) FILTER (WHERE kind = 'held'), COUNT(*) FILTER (WHERE kind = 'released'),
                 COUNT(*) FILTER (WHERE kind = 'rejected'), MIN(at_iso), MAX(at_iso), MAX(at_iso) FILTER (WHERE kind = 'held'),
                 MAX(at_iso) FILTER (WHERE kind = 'rejected'), COUNT(DISTINCT run_id),
                 COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '90 days'),
                 COUNT(*) FILTER (WHERE kind = 'held' AND created_at > NOW() - INTERVAL '90 days'),
                 COUNT(*) FILTER (WHERE kind = 'rejected' AND created_at > NOW() - INTERVAL '90 days'),
                 COUNT(*) FILTER (WHERE kind = 'counterparty_check'), COUNT(*) FILTER (WHERE kind = 'identity_proved'),
                 (SELECT COUNT(*) FROM ta_agents c WHERE c.parent_did = $did)
          FROM ta_receipts WHERE agent_id = $agentId""".query[TaRecord].unique.transact(xa)
  /** Receipts per day and kind over the last `days` days, oldest first: (day, kind, count). */
  def timeline(agentId: UUID, days: Int): F[List[(String, String, Long)]] =
    sql"""SELECT to_char(date_trunc('day', created_at), 'YYYY-MM-DD'), kind, COUNT(*)
          FROM ta_receipts WHERE agent_id = $agentId AND created_at > NOW() - ($days * INTERVAL '1 day')
          GROUP BY 1, 2 ORDER BY 1 ASC""".query[(String, String, Long)].to[List].transact(xa)

  /** Front-page counts. Production and test are counted apart, so the headline numbers are about
    * agents doing real work and the test agents are shown beside them, never hidden. */
  def stats: F[TaStats] =
    (fr"""SELECT (SELECT COUNT(*) FROM ta_owners a WHERE joined_at IS NOT NULL AND """ ++ trusted ++ fr"""),
                 (SELECT COUNT(*) FROM ta_agents a WHERE environment = 'production' AND """ ++ trusted ++ fr"""),
                 (SELECT COUNT(*) FROM ta_agents a WHERE environment = 'production' AND status = 'issued' AND expires_at > NOW() AND """ ++ trusted ++ fr"""),
                 (SELECT COUNT(*) FROM ta_receipts r JOIN ta_agents a ON a.agent_id = r.agent_id WHERE a.environment = 'production' AND """ ++ trusted ++ fr"""),
                 (SELECT COUNT(*) FROM ta_agents a WHERE environment <> 'production' AND """ ++ trusted ++ fr"""),
                 (SELECT COUNT(*) FROM ta_agents a WHERE environment <> 'production' AND status = 'issued' AND expires_at > NOW() AND """ ++ trusted ++ fr"""),
                 (SELECT COUNT(*) FROM ta_receipts r JOIN ta_agents a ON a.agent_id = r.agent_id WHERE a.environment <> 'production' AND """ ++ trusted ++ fr""")"""
      ).query[TaStats].unique.transact(xa)
}

object TraceableAgentsRepository {
  val CleanStartKey = "reset-2026-10-18-opt-in"
  /** Clear the register once, keyed so it never runs twice. One transaction: the marker and the
    * truncates stand or fall together, so two tasks starting at once cannot both wipe. */
  def resetOnce(key: String): ConnectionIO[Boolean] =
    for {
      n <- sql"INSERT INTO ta_meta (key) VALUES ($key) ON CONFLICT (key) DO NOTHING".update.run
      _ <- if (n == 1) sql"TRUNCATE ta_receipts, ta_agents, ta_owners, ta_cursor".update.run else 0.pure[ConnectionIO]
    } yield n == 1

  def apply[F[_]: Async](xa: Transactor[F]): TraceableAgentsRepository[F] = new TraceableAgentsRepository[F](xa)
}
