package traceable

import cats.effect.Async
import cats.implicits._
import org.http4s._
import org.http4s.dsl.Http4sDsl

/** The register's pages, served from a directory: / → index.html, /a/<id> → agent.html, /o/<did> → owner.html,
  * anything else → the file of that name, else 404.html. The same mapping know-your-agent.org uses. */
object Site {
  def routes[F[_]: Async](dir: String): HttpRoutes[F] = {
    val dsl = new Http4sDsl[F] {}
    import dsl._
    def file(name: String, req: Request[F], status: Status = Status.Ok): F[Response[F]] =
      StaticFile.fromPath(fs2.io.file.Path(dir).resolve(name), Some(req)).map(_.withStatus(status)).getOrElseF(
        if (name == "404.html") NotFound("Not found") else StaticFile.fromPath(fs2.io.file.Path(dir).resolve("404.html"), Some(req)).map(_.withStatus(Status.NotFound)).getOrElseF(NotFound("Not found")))
    HttpRoutes.of[F] {
      case req @ GET -> Root => file("index.html", req)
      case req @ GET -> Root / "a" / _ => file("agent.html", req)
      case req @ GET -> Root / "o" / _ => file("owner.html", req)
      case req @ GET -> Root / name if !name.contains("..") && !name.startsWith(".") => file(name, req)
    }
  }
}
