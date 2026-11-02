package traceable
import cats.effect._
import doobie._
import doobie.implicits._
import doobie.postgres.implicits._
import java.util.UUID

/** One owner's verification state: the domain claim and its token, the company registry match, the keeper's review. */
final case class TaOwnerVerificationRow(customerId: UUID, domain: Option[String], domainToken: Option[String], domainMethod: Option[String],
                                        domainVerifiedAt: Option[String], domainCheckedAt: Option[String], domainLastOkAt: Option[String], domainLastError: Option[String],
                                        companyNumber: Option[String], companyName: Option[String], companyRegistry: Option[String], companyCheckedAt: Option[String],
                                        reviewedAt: Option[String], reviewedBy: Option[String], reviewNote: Option[String], lastCheckRequestAt: Option[String]) {
  def domainVerified: Boolean = domainVerifiedAt.nonEmpty
}

/** An owner as the keeper sees it: account, register state, verification. */
final case class TaOwnerAdminRow(customerId: UUID, displayName: String, email: Option[String], verification: String, verifiedBy: Option[String],
                                 listed: Boolean, joinedAt: Option[String], agents: Long, v: Option[TaOwnerVerificationRow],
                                 emailConfirmedAt: Option[String] = None)

/** Table ta_owner_verification (created in DiscursaServer.ensureCoreConversationColumns). The summary of each row is
  * written into ta_owners.verification / verified_by / verified_at, which is what the public pages read. */
class TraceableVerificationRepository[F[_]: Async](xa: Transactor[F]) {
  private val cols = fr"""customer_id, domain, domain_token, domain_method, domain_verified_at::text, domain_checked_at::text, domain_last_ok_at::text, domain_last_error,
                          company_number, company_name, company_registry, company_checked_at::text, reviewed_at::text, reviewed_by, review_note, last_check_request_at::text"""

  def get(cid: UUID): F[Option[TaOwnerVerificationRow]] =
    (fr"SELECT" ++ cols ++ fr"FROM ta_owner_verification WHERE customer_id = $cid").query[TaOwnerVerificationRow].option.transact(xa)

  /** A new domain claim: a fresh token; any earlier domain proof and company match are void. */
  def claimDomain(cid: UUID, domain: String, token: String): F[Int] =
    sql"""INSERT INTO ta_owner_verification (customer_id, domain, domain_token) VALUES ($cid, $domain, $token)
          ON CONFLICT (customer_id) DO UPDATE SET domain = EXCLUDED.domain, domain_token = EXCLUDED.domain_token, domain_method = NULL,
            domain_verified_at = NULL, domain_checked_at = NULL, domain_last_ok_at = NULL, domain_last_error = NULL,
            company_number = NULL, company_name = NULL, company_registry = NULL, company_checked_at = NULL""".update.run.transact(xa)

  def withdrawDomain(cid: UUID): F[Int] =
    sql"""UPDATE ta_owner_verification SET domain = NULL, domain_token = NULL, domain_method = NULL, domain_verified_at = NULL, domain_checked_at = NULL,
          domain_last_ok_at = NULL, domain_last_error = NULL, company_number = NULL, company_name = NULL, company_registry = NULL, company_checked_at = NULL
          WHERE customer_id = $cid""".update.run.transact(xa)

  def markCheckRequested(cid: UUID): F[Int] =
    sql"UPDATE ta_owner_verification SET last_check_request_at = NOW() WHERE customer_id = $cid".update.run.transact(xa)

  def domainOk(cid: UUID, method: String): F[Int] =
    sql"""UPDATE ta_owner_verification SET domain_method = $method, domain_verified_at = COALESCE(domain_verified_at, NOW()),
          domain_last_ok_at = NOW(), domain_checked_at = NOW(), domain_last_error = NULL WHERE customer_id = $cid""".update.run.transact(xa)

  def domainFailed(cid: UUID, err: String): F[Int] =
    sql"UPDATE ta_owner_verification SET domain_checked_at = NOW(), domain_last_error = ${err.take(300)} WHERE customer_id = $cid".update.run.transact(xa)

  /** The record has been gone past the grace period: the proof lapses; the claim and token stay so the owner can put it back. */
  def domainLapsed(cid: UUID): F[Int] =
    sql"""UPDATE ta_owner_verification SET domain_verified_at = NULL, domain_method = NULL, company_name = NULL, company_checked_at = NULL
          WHERE customer_id = $cid""".update.run.transact(xa)

  def setCompany(cid: UUID, number: String, name: String, registry: String): F[Int] =
    sql"""UPDATE ta_owner_verification SET company_number = $number, company_name = $name, company_registry = $registry, company_checked_at = NOW()
          WHERE customer_id = $cid""".update.run.transact(xa)

  def clearCompany(cid: UUID): F[Int] =
    sql"UPDATE ta_owner_verification SET company_number = NULL, company_name = NULL, company_registry = NULL, company_checked_at = NULL WHERE customer_id = $cid".update.run.transact(xa)

  def setReview(cid: UUID, reviewed: Boolean, by: String, note: Option[String]): F[Int] =
    (if (reviewed)
      sql"""INSERT INTO ta_owner_verification (customer_id, reviewed_at, reviewed_by, review_note) VALUES ($cid, NOW(), $by, $note)
            ON CONFLICT (customer_id) DO UPDATE SET reviewed_at = NOW(), reviewed_by = EXCLUDED.reviewed_by, review_note = EXCLUDED.review_note"""
    else sql"UPDATE ta_owner_verification SET reviewed_at = NULL, reviewed_by = NULL, review_note = $note WHERE customer_id = $cid").update.run.transact(xa)

  /** When the account confirmed its email address by signing in with an emailed code; the date part only. */
  def emailConfirmedAt(cid: UUID): F[Option[String]] = Async[F].pure(None)   // the email tier is a Sheaf-account mark; a standalone register has none

  /** The summary the public pages read: the tier (unverified | email | verified) and the proofs behind it. */
  def writeSummary(cid: UUID, tier: String, by: Option[String]): F[Int] = {
    val verified = tier == OwnerVerification.Verified
    sql"""UPDATE ta_owners SET verification = $tier, verified_by = $by,
          verified_at = CASE WHEN ${verified} THEN COALESCE(verified_at, NOW()) ELSE NULL END WHERE customer_id = $cid""".update.run.transact(xa)
  }

  /** Verified domains not checked in the last day. */
  def dueRechecks(limit: Int): F[List[TaOwnerVerificationRow]] =
    (fr"SELECT" ++ cols ++ fr"""FROM ta_owner_verification WHERE domain_verified_at IS NOT NULL
          AND (domain_checked_at IS NULL OR domain_checked_at < NOW() - INTERVAL '1 day') ORDER BY domain_checked_at NULLS FIRST LIMIT $limit""")
      .query[TaOwnerVerificationRow].to[List].transact(xa)

}
