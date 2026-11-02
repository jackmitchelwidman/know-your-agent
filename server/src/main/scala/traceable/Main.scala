package traceable

import cats.effect._
import cats.implicits._
import com.comcast.ip4s._
import doobie.hikari.HikariTransactor
import org.http4s.ember.client.EmberClientBuilder
import org.http4s.ember.server.EmberServerBuilder
import org.http4s.server.middleware.CORS
import org.typelevel.log4cats.Logger
import org.typelevel.log4cats.slf4j.Slf4jLogger
import scala.concurrent.duration._

/** The Register of Traceable Agents, standalone. Configuration is the environment:
  *   DATABASE_URL        postgresql://user:pass@host:5432/db   (required)
  *   PORT                8080
  *   SITE_DIR            ./site  (the pages; empty string serves the API only)
  *   REGISTER_NAME       the register's name, shown in every answer
  *   REGISTER_SELF_URL   its public address
  *   REGISTER_DID        its own did:key, if it has one
  *   REGISTER_PEERS      comma-separated base URLs of registers to ask when an ID is not here
  *   OTS_ENABLED         true: anchor the hourly checkpoint in Bitcoin through OpenTimestamps (default true)
  *   OTS_CALENDARS       comma-separated calendar URLs (default: the public ones)
  *   COMPANIES_HOUSE_API_KEY  optional, for the UK company mark on owners
  */
object Main extends IOApp.Simple {
  implicit val logger: Logger[IO] = Slf4jLogger.getLogger[IO]
  private val env = sys.env
  private def opt(k: String): Option[String] = env.get(k).map(_.trim).filter(_.nonEmpty)

  /** postgresql://user:pass@host:port/db → (jdbc url, user, pass). A plain jdbc: url is passed through with DB_USER/DB_PASSWORD. */
  private def db: (String, String, String) = {
    val raw = opt("DATABASE_URL").getOrElse(throw new IllegalArgumentException("DATABASE_URL is not set"))
    if (raw.startsWith("jdbc:")) (raw, opt("DB_USER").getOrElse(""), opt("DB_PASSWORD").getOrElse(""))
    else {
      val u = new java.net.URI(raw)
      val Array(user, pass) = Option(u.getUserInfo).getOrElse(":").split(":", 2).padTo(2, "")
      val port = if (u.getPort > 0) u.getPort else 5432
      (s"jdbc:postgresql://${u.getHost}:$port${u.getPath}" + Option(u.getQuery).fold("")("?" + _), java.net.URLDecoder.decode(user, "UTF-8"), java.net.URLDecoder.decode(pass, "UTF-8"))
    }
  }

  def run: IO[Unit] = {
    val (jdbc, user, pass) = db
    val port = opt("PORT").flatMap(_.toIntOption).getOrElse(8080)
    val siteDir = env.get("SITE_DIR").map(_.trim).getOrElse("site")
    val selfUrl = opt("REGISTER_SELF_URL").getOrElse(s"http://localhost:$port")
    val name = opt("REGISTER_NAME").getOrElse("A register of traceable agents")
    val peers = opt("REGISTER_PEERS").toList.flatMap(_.split(",")).map(_.trim).filter(_.nonEmpty)
    val ots = !opt("OTS_ENABLED").exists(_.equalsIgnoreCase("false"))
    val resources = for {
      ec <- ExecutionContexts.fixed[IO](8)
      xa <- HikariTransactor.newHikariTransactor[IO]("org.postgresql.Driver", jdbc, user, pass, ec)
      client <- EmberClientBuilder.default[IO].withTimeout(20.seconds).build
    } yield (xa, client)
    resources.use { case (xa, client) =>
      val repo = TraceableAgentsRepository[IO](xa)
      val vrepo = TraceableVerificationRepository[IO](xa)
      val verification = new TraceableVerificationService[IO](vrepo, repo, client, opt("COMPANIES_HOUSE_API_KEY"))
      val verifiers = new TraceableVerifierService[IO](repo, Some(verification))
      val checkpoints = new TraceableCheckpointService[IO](repo, OtsClient[IO](client), ots)
      val federation = TraceableAgentsRoutes.Federation[IO](client, selfUrl, name, opt("REGISTER_DID"), peers)
      val api = TraceableAgentsRoutes.routes[IO](repo, Some(verifiers), Some(checkpoints), Some(federation))
      val app = (if (siteDir.isEmpty) api else api <+> Site.routes[IO](siteDir)).orNotFound
      val hourly: IO[Unit] = (IO.sleep(1.minute) >> (checkpoints.take.attempt >> checkpoints.upgradePending(30, 50).attempt).void >> IO.sleep(59.minutes)).foreverM
      for {
        _ <- Migrations.run[IO](xa)
        _ <- logger.info(s"[register] $name at $selfUrl; peers: ${if (peers.isEmpty) "none" else peers.mkString(", ")}; checkpoints ${if (ots) "anchored in Bitcoin" else "unanchored"}")
        _ <- (hourly.start, verification.startSweep).tupled.flatMap { case (h, s) =>
          EmberServerBuilder.default[IO].withHost(ipv4"0.0.0.0").withPort(Port.fromInt(port).get).withHttpApp(CORS.policy.withAllowOriginAll(app)).build
            .use(_ => IO.never).guarantee(h.cancel >> s.cancel)
        }
      } yield ()
    }
  }
}

object ExecutionContexts {
  def fixed[F[_]: Sync](n: Int): Resource[F, scala.concurrent.ExecutionContext] =
    Resource.make(Sync[F].delay(java.util.concurrent.Executors.newFixedThreadPool(n)))(e => Sync[F].delay(e.shutdown()))
      .map(scala.concurrent.ExecutionContext.fromExecutor)
}
