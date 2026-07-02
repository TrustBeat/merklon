ThisBuild / scalaVersion := "3.3.4" // Scala 3 LTS
ThisBuild / version      := "0.1.0-SNAPSHOT"

// Maven groupId — uses the trustbeat.eu domain (verify domain ownership on Sonatype Central).
ThisBuild / organization := "eu.trustbeat"

val zioVersion     = "2.1.24"
val zioHttpVersion = "3.10.0"
val munitVersion   = "1.0.0"
// Bouncy Castle (MIT-style licence): ASN.1 + RFC 3161 timestamp protocol only —
// never crypto primitives the JDK already provides.
val bcVersion = "1.80"

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
  .dependsOn(core, storagePg, verifier % "test->compile;test->test")
  .settings(
    commonSettings,
    name := "merklon-server",
    libraryDependencies ++= Seq(
      "dev.zio"            %% "zio"            % zioVersion,
      "dev.zio"            %% "zio-http"       % zioHttpVersion,
      "org.bouncycastle"    % "bcpkix-jdk18on" % bcVersion, // RFC 3161 TSA client
      "org.scalameta"      %% "munit"          % munitVersion % Test
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

// Independent verifier: library + CLI. Depends on core; JDK java.net.http for HTTP and
// Bouncy Castle for RFC 3161 timestamp-token verification in proof bundles.
lazy val verifier = project
  .in(file("modules/verifier"))
  .dependsOn(core)
  .settings(
    commonSettings,
    name := "merklon-verifier",
    libraryDependencies ++= Seq(
      "org.bouncycastle" % "bcpkix-jdk18on" % bcVersion, // RFC 3161 token verification
      "org.scalameta"   %% "munit"          % munitVersion % Test
    )
  )

lazy val root = project
  .in(file("."))
  .aggregate(core, storagePg, server, verifier)
  .settings(name := "merklon")
