ThisBuild / scalaVersion := "3.3.4" // Scala 3 LTS
ThisBuild / version      := "0.1.0"

// Maven groupId — uses the trustbeat.eu domain (namespace verified on Sonatype Central).
ThisBuild / organization := "eu.trustbeat"

// ── Maven Central publishing (Central Portal; see RELEASING.md) ──────────────
// Published artifacts: merklon-core, merklon-verifier, merklon-java. The server and
// storage backend are operator-side components, obtained from the repo, not Central.
ThisBuild / versionScheme    := Some("early-semver")
ThisBuild / homepage         := Some(url("https://github.com/TrustBeat/merklon"))
ThisBuild / licenses         := List("Apache-2.0" -> url("https://www.apache.org/licenses/LICENSE-2.0"))
ThisBuild / developers       := List(
  Developer("trustbeat", "Trustbeat s.r.o.", "radim.dejmek@trustbeat.eu", url("https://trustbeat.eu"))
)
ThisBuild / scmInfo := Some(
  ScmInfo(url("https://github.com/TrustBeat/merklon"), "scm:git:git@github.com:TrustBeat/merklon.git")
)
ThisBuild / sonatypeCredentialHost := xerial.sbt.Sonatype.sonatypeCentralHost
ThisBuild / publishTo              := sonatypePublishToBundle.value

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
    name        := "merklon-core",
    description := "Pure RFC 9162 Merkle transparency-log core: hashing, inclusion/consistency proofs, signed checkpoints, witnessing",
    libraryDependencies += "org.scalameta" %% "munit" % munitVersion % Test
  )

// HTTP log server: ZIO + ZIO HTTP. Depends on core; keeps core pure.
lazy val server = project
  .in(file("modules/server"))
  .dependsOn(core, storagePg, verifier % "test->compile;test->test")
  .settings(
    commonSettings,
    name           := "merklon-server",
    publish / skip := true, // operator-side application, not a library
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
    name           := "merklon-storage-pg",
    publish / skip := true, // operator-side backend, obtained from the repo
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
    name        := "merklon-verifier",
    description := "Independent verifier for merklon transparency logs: proofs, checkpoints, witness policies, offline bundles",
    libraryDependencies ++= Seq(
      "org.bouncycastle" % "bcpkix-jdk18on" % bcVersion, // RFC 3161 token verification
      "org.scalameta"   %% "munit"          % munitVersion % Test
    ),
    // Distributable fat JAR: `sbt verifier/assembly` → merklon-verify.jar, runnable with a
    // plain `java -jar` on any JDK 17+ (the independent verifier must not need sbt or a repo).
    assembly / mainClass     := Some("merklon.verifier.merklon_verify"),
    assembly / assemblyJarName := "merklon-verify.jar",
    assembly / assemblyMergeStrategy := {
      // Bouncy Castle ships as a signed jar; its signature files are invalid inside a
      // repacked fat jar and must be dropped, but keep service registrations intact.
      case PathList("META-INF", "MANIFEST.MF")              => MergeStrategy.discard
      case PathList("META-INF", "services", _*)             => MergeStrategy.concat
      case p if p.endsWith(".SF") || p.endsWith(".DSA") || p.endsWith(".RSA") =>
        MergeStrategy.discard
      case _ => MergeStrategy.first
    }
  )

// Java-friendly facade over the pure core: java.util types only in every signature, so Java
// (and Kotlin) teams can embed merklon without touching Scala collections. The plain-Java
// smoke test in src/test/java stops compiling if a Scala type ever leaks into the facade.
lazy val javaApi = project
  .in(file("modules/java"))
  .dependsOn(core)
  .settings(
    commonSettings,
    name        := "merklon-java",
    description := "Java-friendly facade over the merklon transparency-log core (java.util types only)",
    libraryDependencies += "org.scalameta" %% "munit" % munitVersion % Test
  )

lazy val root = project
  .in(file("."))
  .aggregate(core, storagePg, server, verifier, javaApi)
  .settings(name := "merklon", publish / skip := true)
