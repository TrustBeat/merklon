ThisBuild / scalaVersion := "3.3.4" // Scala 3 LTS
ThisBuild / version      := "0.1.0-SNAPSHOT"

// Maven groupId — uses the trustbeat.eu domain (verify domain ownership on Sonatype Central).
ThisBuild / organization := "eu.trustbeat"

val zioVersion     = "2.1.24"
val zioHttpVersion = "3.10.0"
val munitVersion   = "1.0.0"

lazy val commonSettings = Seq(
  scalacOptions ++= Seq(
    "-deprecation",
    "-feature",
    "-unchecked",
    "-Wunused:all"
  )
)

// Pure Merkle core: no I/O, no frameworks, no effects.
lazy val core = project
  .in(file("modules/core"))
  .settings(
    commonSettings,
    name := "merklon-core",
    libraryDependencies += "org.scalameta" %% "munit" % munitVersion % Test
  )

// HTTP log server: ZIO + ZIO HTTP. Depends on core; keeps core pure.
lazy val server = project
  .in(file("modules/server"))
  .dependsOn(core, storagePg, verifier % Test)
  .settings(
    commonSettings,
    name := "merklon-server",
    libraryDependencies ++= Seq(
      "dev.zio"      %% "zio"      % zioVersion,
      "dev.zio"      %% "zio-http" % zioHttpVersion,
      "org.scalameta" %% "munit"   % munitVersion % Test
    )
  )

// Postgres StorageBackend: plain JDBC over the core interface. The default backend for
// operating a log (DESIGN.md); library users and verifiers never need it.
lazy val storagePg = project
  .in(file("modules/storage-pg"))
  .dependsOn(core)
  .settings(
    commonSettings,
    name := "merklon-storage-pg",
    libraryDependencies ++= Seq(
      "org.postgresql" % "postgresql" % "42.7.7", // BSD-2-Clause
      "org.scalameta" %% "munit"      % munitVersion % Test
    )
  )

// Independent verifier: library + CLI. Depends on core only; uses JDK java.net.http for HTTP.
lazy val verifier = project
  .in(file("modules/verifier"))
  .dependsOn(core)
  .settings(
    commonSettings,
    name := "merklon-verifier",
    libraryDependencies += "org.scalameta" %% "munit" % munitVersion % Test
  )

lazy val root = project
  .in(file("."))
  .aggregate(core, storagePg, server, verifier)
  .settings(name := "merklon")
