package traceable
import cats.effect._
import cats.implicits._
import cats.effect.syntax.all._
import scala.concurrent.duration._
import io.circe.Json
import io.circe.syntax._
import org.http4s._
import org.http4s.client.Client
import org.http4s.headers.{Authorization, Location}
import org.typelevel.ci.CIString
import org.typelevel.log4cats.Logger
import java.net.InetAddress
import java.util.UUID

import OwnerVerification._

/**
 * Owner verification on the register: the checks. Three proofs, each recorded separately and
 * summarised into ta_owners.verified_by:
 *   domain   the owner placed a token in a DNS TXT record or a well-known file on its site;
 *   company  a Companies House entry the owner named, fetched from the registry (needs the domain proof first);
 *   reviewed the register's keeper looked at documents and marked the owner reviewed.
 * An owner is "verified" when it has the domain proof or the review. Verified domains are rechecked
 * daily and lapse after GraceDays without a passing check. Beneath "verified" sits a weaker mark, "email":
 * the owner confirmed an email address by signing in with an emailed code (a Sheaf-account mark; a standalone register has none),
 * so an individual with no domain still has something on the record.
 */
class TraceableVerificationService[F[_]: Async: Logger](repo: TraceableVerificationRepository[F], owners: TraceableAgentsRepository[F],
                                                        client: Client[F], companiesHouseKey: Option[String]) {

  private val CompaniesHouse = "https://api.company-information.service.gov.uk/company/"

  // ── what the console and the keeper see ──

  def status(cid: UUID): F[Json] = (repo.get(cid), repo.emailConfirmedAt(cid)).mapN(statusJson)

  def statusJson(v: Option[TaOwnerVerificationRow], emailAt: Option[String]): Json = (v match {
    case None => Json.obj("domain" -> Json.Null, "company" -> Json.Null, "reviewed" -> false.asJson, "verified" -> false.asJson,
                          "companiesHouse" -> companiesHouseKey.nonEmpty.asJson)
    case Some(r) => Json.obj(
      "verified" -> (r.domainVerified || r.reviewedAt.nonEmpty).asJson,
      "domain" -> r.domain.map(d => Json.obj("name" -> d.asJson, "verified" -> r.domainVerified.asJson, "method" -> r.domainMethod.asJson,
        "verifiedAt" -> r.domainVerifiedAt.asJson, "checkedAt" -> r.domainCheckedAt.asJson, "lastOkAt" -> r.domainLastOkAt.asJson, "lastError" -> r.domainLastError.asJson,
        "record" -> Json.obj("name" -> recordName(d).asJson, "type" -> "TXT".asJson, "value" -> r.domainToken.map(recordValue).asJson),
        "file" -> Json.obj("url" -> ("https://" + d + WellKnownPath).asJson, "content" -> r.domainToken.map(recordValue).asJson))).asJson,
      "company" -> r.companyName.map(n => Json.obj("name" -> n.asJson, "number" -> r.companyNumber.asJson, "registry" -> r.companyRegistry.asJson, "checkedAt" -> r.companyCheckedAt.asJson)).asJson,
      "reviewed" -> r.reviewedAt.nonEmpty.asJson, "reviewedAt" -> r.reviewedAt.asJson, "reviewNote" -> r.reviewNote.asJson,
      "companiesHouse" -> companiesHouseKey.nonEmpty.asJson)
  }).deepMerge(Json.obj("email" -> emailAt.nonEmpty.asJson, "emailConfirmedAt" -> emailAt.asJson,
    "tier" -> Proofs(v.filter(_.domainVerified).flatMap(_.domain), None, v.flatMap(_.reviewedAt), emailAt).tier.asJson))

  /** The sign-in route calls this once an account has confirmed its email: the summary picks the tier up. */
  def refresh(cid: UUID): F[Unit] = summarise(cid)

  // ── the owner's side ──

  /** Claim a domain: a token to place. Any earlier proof for another domain is void. */
  def claimDomain(cid: UUID, raw: String): F[Either[String, Json]] =
    normaliseHost(raw) match {
      case Left(e) => Async[F].pure(Left(e))
      case Right(host) => repo.claimDomain(cid, host, token()) >> summarise(cid) >> status(cid).map(Right(_))
    }

  def withdrawDomain(cid: UUID): F[Json] = repo.withdrawDomain(cid) >> summarise(cid) >> status(cid)

  /** Look for the token: the DNS record first, then the file. At most one check every 20 seconds per owner. */
  def check(cid: UUID): F[Either[String, Json]] =
    repo.get(cid).flatMap {
      case Some(r) if r.domain.nonEmpty && r.domainToken.nonEmpty =>
        val recent = r.lastCheckRequestAt.flatMap(parseTs).exists(_.isAfter(java.time.Instant.now().minusSeconds(20)))
        if (recent) Async[F].pure(Left("Checked a moment ago. Give the record a few seconds and try again."))
        else repo.markCheckRequested(cid) >> runCheck(r.domain.get, r.domainToken.get).flatMap {
          case Right(method) => repo.domainOk(cid, method) >> summarise(cid) >> status(cid).map(Right(_))
          case Left(err) => repo.domainFailed(cid, err) >> Async[F].pure(Left(err))
        }
      case _ => Async[F].pure(Left("Claim a domain first."))
    }

  /** Attach a Companies House entry. The domain proof must already hold; the registry's name is what gets shown. */
  def company(cid: UUID, raw: String): F[Either[String, Json]] =
    repo.get(cid).flatMap {
      case Some(r) if r.domainVerified => normaliseCompanyNumber(raw) match {
        case Left(e) => Async[F].pure(Left(e))
        case Right(num) => companiesHouseKey match {
          case None => Async[F].pure(Left("The Companies House lookup is not set up on this register yet."))
          case Some(key) => fetchCompany(key, num).flatMap {
            case Left(e) => Async[F].pure(Left(e))
            case Right((name, st)) =>
              repo.setCompany(cid, num, name + (if (st == "active" || st.isEmpty) "" else s" ($st)"), "companies-house") >> summarise(cid) >> status(cid).map(Right(_))
          }
        }
      }
      case _ => Async[F].pure(Left("Verify your domain first; then the company entry can be attached to it."))
    }

  def clearCompany(cid: UUID): F[Json] = repo.clearCompany(cid) >> summarise(cid) >> status(cid)

  // ── the keeper's side ──

  def review(cid: UUID, reviewed: Boolean, by: String, note: Option[String]): F[Either[String, Json]] =
    owners.owner(cid).flatMap {
      case None => Async[F].pure(Left("No owner record for that account."))
      case Some(_) => repo.setReview(cid, reviewed, by, note) >> summarise(cid) >> status(cid).map(Right(_))
    }

  // ── the daily recheck ──

  def sweep: F[Unit] =
    repo.dueRechecks(50).flatMap(_.traverse_ { r =>
      runCheck(r.domain.get, r.domainToken.getOrElse("")).flatMap {
        case Right(m) => repo.domainOk(r.customerId, m).void
        case Left(err) =>
          val lastOk = r.domainLastOkAt.flatMap(parseTs).orElse(r.domainVerifiedAt.flatMap(parseTs))
          val lapsed = lastOk.forall(_.isBefore(java.time.Instant.now().minus(java.time.Duration.ofDays(GraceDays.toLong))))
          repo.domainFailed(r.customerId, err) >>
            (if (lapsed) Logger[F].warn(s"[register] domain proof lapsed for ${r.domain.get}") >> repo.domainLapsed(r.customerId) >> summarise(r.customerId) else Async[F].unit)
      }.handleErrorWith(e => Logger[F].warn(s"[register] recheck failed for ${r.domain.getOrElse("?")}: ${e.getMessage}"))
    })

  def startSweep: F[Fiber[F, Throwable, Unit]] =
    (Async[F].sleep(3.minutes) >> (sweep.handleErrorWith(e => Logger[F].warn(s"[register] sweep error: ${e.getMessage}")) >> Async[F].sleep(6.hours)).foreverM).start

  // ── internals ──

  private def parseTs(s: String): Option[java.time.Instant] =
    scala.util.Try(java.time.OffsetDateTime.parse(s.replace(" ", "T").replaceAll("(\\+\\d\\d)$", "$1:00")).toInstant).toOption
      .orElse(scala.util.Try(java.time.Instant.parse(s)).toOption)

  /** Write the summary the public pages read. */
  private def summarise(cid: UUID): F[Unit] =
    (repo.get(cid), repo.emailConfirmedAt(cid)).tupled.flatMap { case (v, emailAt) =>
      val p = Proofs(v.filter(_.domainVerified).flatMap(_.domain),
        v.filter(_.domainVerified).flatMap(r => (r.companyName, r.companyNumber).tupled),
        v.flatMap(_.reviewedAt).map(_.take(10)), emailAt)
      repo.writeSummary(cid, p.tier, Some(p.encode).filter(_.nonEmpty)).void
    }

  private def runCheck(host: String, tok: String): F[Either[String, String]] =
    lookupTxt(recordName(host)).attempt.flatMap {
      case Right(vs) if txtMatches(vs, tok) => Async[F].pure(Right("dns"))
      case dnsOutcome => fetchWellKnown(host).map {
        case Right(body) if fileMatches(body, tok) => Right("file")
        case Right(_) => Left(s"Found no ${recordName(host)} TXT record with the token, and the file at ${WellKnownPath} does not contain it.")
        case Left(fileErr) => dnsOutcome match {
          case Left(e) => Left(s"DNS lookup failed (${e.getMessage}); $fileErr")
          case Right(Nil) => Left(s"No TXT record at ${recordName(host)} yet, and $fileErr")
          case Right(_) => Left(s"The TXT record at ${recordName(host)} exists but does not carry this token, and $fileErr")
        }
      }
    }

  /** TXT records through the JDK's resolver, with a short timeout so a dead resolver cannot hang the request. */
  private def lookupTxt(name: String): F[List[String]] = Async[F].blocking {
    import javax.naming.directory.InitialDirContext
    val env = new java.util.Hashtable[String, String]()
    env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory")
    env.put("java.naming.provider.url", "dns:")
    env.put("com.sun.jndi.dns.timeout.initial", "3000")
    env.put("com.sun.jndi.dns.timeout.retries", "1")
    val ctx = new InitialDirContext(env)
    try {
      val attrs = ctx.getAttributes(name, Array("TXT"))
      val a = attrs.get("TXT")
      if (a == null) Nil
      else { val e = a.getAll; val b = scala.collection.mutable.ListBuffer[String](); while (e.hasMore) b += String.valueOf(e.next()); b.toList }
    } catch { case _: javax.naming.NameNotFoundException => Nil }
    finally ctx.close()
  }.timeout(8.seconds)

  /** The well-known file over HTTPS only, after checking the host does not resolve to anything private; two redirects at most,
    * each re-checked; the first 8 KB only; five seconds. */
  private def fetchWellKnown(host: String): F[Either[String, String]] = {
    def resolveSafe(h: String): F[Either[String, Unit]] = Async[F].blocking(scala.util.Try(InetAddress.getAllByName(h).toList)).map {
      case scala.util.Failure(_) => Left(s"$h does not resolve")
      case scala.util.Success(Nil) => Left(s"$h does not resolve")
      case scala.util.Success(as) if as.exists(isForbidden) => Left(s"$h resolves to a private address")
      case _ => Right(())
    }
    def go(uri: Uri, hops: Int): F[Either[String, String]] =
      uri.host.map(_.value) match {
        case None => Async[F].pure(Left("bad redirect"))
        case Some(h) => normaliseHost(h) match {
          case Left(e) => Async[F].pure(Left(e))
          case Right(hh) => resolveSafe(hh).flatMap {
            case Left(e) => Async[F].pure(Left(e))
            case Right(_) =>
              val req = Request[F](Method.GET, uri).putHeaders(Header.Raw(CIString("User-Agent"), "traceableagents.org owner check"))
              client.run(req).use { resp =>
                if (resp.status.isSuccess) resp.body.take(8192).through(fs2.text.utf8.decode).compile.string.map(Right(_))
                else if (resp.status.code / 100 == 3) resp.headers.get[Location].map(_.uri) match {
                  case Some(l) if hops < 2 && l.scheme.exists(_.value == "https") => Async[F].pure(Left("redirect:" + l.renderString))
                  case _ => Async[F].pure(Left(s"the site redirected ${WellKnownPath} somewhere the check will not follow"))
                }
                else Async[F].pure(Left(s"the site answered ${resp.status.code} for ${WellKnownPath}"))
              }.timeout(5.seconds).attempt.map(_.leftMap(e => s"could not fetch https://$hh${WellKnownPath} (${e.getMessage})").flatten).flatMap {
                case Left(r) if r.startsWith("redirect:") => Uri.fromString(r.drop(9)).toOption.fold[F[Either[String, String]]](Async[F].pure(Left("bad redirect")))(go(_, hops + 1))
                case other => Async[F].pure(other)
              }
          }
        }
      }
    Uri.fromString("https://" + host + WellKnownPath).toOption.fold[F[Either[String, String]]](Async[F].pure(Left("bad host")))(go(_, 0))
  }

  /** Companies House: the company's registered name and status, by number. Basic auth with the key as the username. */
  private def fetchCompany(key: String, number: String): F[Either[String, (String, String)]] = {
    val uri = Uri.unsafeFromString(CompaniesHouse + number)
    val req = Request[F](Method.GET, uri).putHeaders(Authorization(BasicCredentials(key, "")))
    client.run(req).use { resp =>
      resp.bodyText.compile.string.map { body =>
        if (resp.status.code == 404) Left(s"Companies House has no company numbered $number.")
        else if (!resp.status.isSuccess) Left(s"Companies House answered ${resp.status.code}.")
        else io.circe.parser.parse(body).toOption.flatMap { j =>
          val c = j.hcursor
          c.get[String]("company_name").toOption.map(n => (n, c.get[String]("company_status").toOption.getOrElse("")))
        }.toRight("Companies House sent an answer the register could not read.")
      }
    }.timeout(8.seconds).attempt.map(_.leftMap(e => s"Could not reach Companies House (${e.getMessage}).").flatten)
  }
}
