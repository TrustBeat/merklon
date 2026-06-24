ThisBuild / scalaVersion := "3.3.4" // Scala 3 LTS
ThisBuild / version      := "0.1.0-SNAPSHOT"

// Maven groupId — uses the trustbeat.eu domain (verify domain ownership on Sonatype Central).
ThisBuild / organization := "eu.trustbeat"

lazy val root = (project in file("."))
  .settings(
    name := "merklon",
    libraryDependencies += "org.scalameta" %% "munit" % "1.0.0" % Test,
    scalacOptions ++= Seq(
      "-deprecation",
      "-feature",
      "-unchecked",
      "-Wunused:all"
    )
  )
