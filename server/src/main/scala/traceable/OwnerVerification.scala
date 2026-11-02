package traceable
import java.net.{IDN, InetAddress}

/**
 * Owner verification on the register (Oct 21 2026): the pure parts. An owner proves it controls a
 * domain by placing a token where only the domain's controller can (a DNS TXT record or a file on
 * the site); it may then attach a company registry entry; the register's keeper may mark an owner
 * reviewed after looking at documents. The outcome is summarised in ta_owners.verified_by so every
 * public page reads it without another query.
 */
object OwnerVerification {
  /** The DNS record the owner adds: `_kya.<domain>  TXT  "kya-verify=<token>"`. */
  val RecordPrefix = "_kya."
  val ValuePrefix  = "kya-verify="
  /** The file the owner can place instead: `https://<domain>/.well-known/kya.txt` with the same line. */
  val WellKnownPath = "/.well-known/kya.txt"
  /** The names used before Nov 2 2026, when the register lived at traceableagents.org. Still honoured. */
  val LegacyRecordPrefix = "_traceableagents."
  val LegacyValuePrefix  = "traceableagents-verify="
  val LegacyWellKnownPath = "/.well-known/traceable-agents.txt"
  /** A verified domain is rechecked daily; it is dropped only after this long without a passing check. */
  val GraceDays = 45

  private val label = "^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$".r

  /** A hostname an owner may claim: lowercase ASCII, at least two labels, no scheme, path, port, userinfo or IP literal. */
  def normaliseHost(raw: String): Either[String, String] = {
    val s0 = raw.trim.toLowerCase.stripPrefix("https://").stripPrefix("http://").stripSuffix("/").stripSuffix(".")
    if (s0.isEmpty) Left("Enter your company's domain, like example.com.")
    else if (s0.exists(c => c.isWhitespace || "/:@?#\\".indexOf(c) >= 0)) Left("Enter just the domain, like example.com, with no path or port.")
    else scala.util.Try(IDN.toASCII(s0)).toOption match {
      case None => Left("That is not a valid domain name.")
      case Some(h) =>
        val parts = h.split('.').toList
        if (parts.size < 2) Left("Enter a full domain, like example.com.")
        else if (h.length > 253 || parts.exists(p => label.findFirstIn(p).isEmpty)) Left("That is not a valid domain name.")
        else if (parts.last.forall(_.isDigit)) Left("An IP address cannot be verified. Use the domain name.")
        else Right(h)
    }
  }

  /** Addresses the checker must never connect to: loopback, private, link-local (the cloud metadata range lives
    * there), carrier NAT, multicast, unspecified, and IPv6 unique-local. */
  def isForbidden(a: InetAddress): Boolean =
    a.isLoopbackAddress || a.isSiteLocalAddress || a.isLinkLocalAddress || a.isAnyLocalAddress || a.isMulticastAddress || {
      val b = a.getAddress
      (b.length == 4 && (((b(0) & 0xff) == 100 && (b(1) & 0xc0) == 64) || (b(0) & 0xff) == 0)) ||
      (b.length == 16 && (b(0) & 0xfe) == 0xfc)
    }

  def token(): String = { val r = new java.security.SecureRandom(); val b = new Array[Byte](16); r.nextBytes(b); b.map("%02x".format(_)).mkString }
  def recordName(host: String): String = RecordPrefix + host
  def legacyRecordName(host: String): String = LegacyRecordPrefix + host
  def recordValue(tok: String): String = ValuePrefix + tok
  private def accepted(tok: String): Set[String] = Set(ValuePrefix + tok, LegacyValuePrefix + tok)

  /** A TXT answer as the resolver gives it: possibly quoted, possibly split into several quoted strings. */
  def txtMatches(values: List[String], tok: String): Boolean = {
    val want = accepted(tok)
    values.exists(v => want(v.replace("\"", "").replaceAll("\\s+", "")))
  }

  /** The well-known file: the line `kya-verify=<token>` (the old `traceableagents-verify=` form, or the bare token, also pass); BOM and whitespace tolerated. */
  def fileMatches(body: String, tok: String): Boolean =
    body.replace("﻿", "").linesIterator.map(_.trim).exists(l => accepted(tok)(l) || l == tok)

  /** Companies House numbers are 8 characters: digit-only ones are padded with leading zeros, letter prefixes (SC, NI, OC, ...) kept. */
  def normaliseCompanyNumber(raw: String): Either[String, String] = {
    val s = raw.trim.toUpperCase.replaceAll("\\s", "")
    if (s.isEmpty) Left("Enter the company number as Companies House shows it.")
    else if (s.forall(_.isDigit) && s.length <= 8) Right(("0" * (8 - s.length)) + s)
    else if (s.matches("[A-Z]{2}[0-9A-Z]{6}")) Right(s)
    else Left("That does not look like a Companies House number (8 characters, like 12345678 or SC123456).")
  }

  /** The three states of ta_owners.verification. `email`: the owner confirmed an email address (signed in by
    * emailed code) and nothing more. It is a weaker mark than verified; the register shows it as "email confirmed". */
  val Unverified = "unverified"; val EmailTier = "email"; val Verified = "verified"
  def tierLabel(t: String): String = t match { case Verified => "verified"; case EmailTier => "email confirmed"; case _ => "unverified" }

  /** The summary kept in ta_owners.verified_by, e.g. `domain=example.com|company=Example Ltd#12345678|reviewed=2026-10-21|email=2026-10-27`. */
  final case class Proofs(domain: Option[String], company: Option[(String, String)], reviewedAt: Option[String], emailAt: Option[String] = None) {
    def verified: Boolean = domain.nonEmpty || reviewedAt.nonEmpty
    def tier: String = if (verified) Verified else if (emailAt.nonEmpty) EmailTier else Unverified
    def kinds: List[String] = domain.map(_ => "domain").toList ++ company.map(_ => "company").toList ++ reviewedAt.map(_ => "reviewed").toList ++ emailAt.map(_ => "email").toList
    def encode: String = (domain.map("domain=" + _).toList ++
      company.map { case (n, num) => "company=" + n.replace("|", " ").replace("#", " ") + "#" + num }.toList ++
      reviewedAt.map("reviewed=" + _).toList ++ emailAt.map("email=" + _).toList).mkString("|")
  }
  def parseProofs(s: Option[String]): Proofs = {
    val parts = s.getOrElse("").split('|').toList.map(_.trim).filter(_.nonEmpty)
    def v(k: String) = parts.collectFirst { case p if p.startsWith(k + "=") => p.drop(k.length + 1) }.filter(_.nonEmpty)
    Proofs(v("domain"), v("company").flatMap { c => val i = c.lastIndexOf('#'); if (i > 0) Some((c.take(i), c.drop(i + 1))) else None }, v("reviewed"), v("email"))
  }
}
