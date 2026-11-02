// The Register of Traceable Agents: a standalone server for the KYA format.
val Http4sVersion = "0.23.27"
val CirceVersion  = "0.14.7"
val DoobieVersion = "1.0.0-RC4"

ThisBuild / scalaVersion := "3.3.3"
ThisBuild / organization := "org.traceableagents"

lazy val root = (project in file("."))
  .settings(
    name := "traceable-agents-register",
    version := "1.0.0",
    libraryDependencies ++= Seq(
      "org.http4s"    %% "http4s-ember-server" % Http4sVersion,
      "org.http4s"    %% "http4s-ember-client" % Http4sVersion,
      "org.http4s"    %% "http4s-circe"        % Http4sVersion,
      "org.http4s"    %% "http4s-dsl"          % Http4sVersion,
      "io.circe"      %% "circe-core"          % CirceVersion,
      "io.circe"      %% "circe-parser"        % CirceVersion,
      "io.circe"      %% "circe-generic"       % CirceVersion,
      "org.tpolecat"  %% "doobie-core"         % DoobieVersion,
      "org.tpolecat"  %% "doobie-hikari"       % DoobieVersion,
      "org.tpolecat"  %% "doobie-postgres"     % DoobieVersion,
      "org.typelevel" %% "log4cats-slf4j"      % "2.7.0",
      "org.bouncycastle" % "bcprov-jdk18on"     % "1.78.1",
      "ch.qos.logback" % "logback-classic"     % "1.5.6",
      "org.scalameta" %% "munit"               % "1.0.0" % Test,
      "org.typelevel" %% "munit-cats-effect"   % "2.0.0" % Test
    ),
    Compile / run / fork := true,
    assembly / assemblyJarName := "register.jar",
    assembly / mainClass := Some("traceable.Main"),
    assembly / assemblyMergeStrategy := {
      case PathList("META-INF", "versions", _*) => MergeStrategy.first
      case PathList("META-INF", xs @ _*) if xs.lastOption.exists(n => n.endsWith(".SF") || n.endsWith(".DSA") || n.endsWith(".RSA")) => MergeStrategy.discard
      case PathList("META-INF", _*) => MergeStrategy.first
      case "module-info.class" => MergeStrategy.discard
      case x if x.endsWith("module-info.class") => MergeStrategy.discard
      case _ => MergeStrategy.first
    }
  )
