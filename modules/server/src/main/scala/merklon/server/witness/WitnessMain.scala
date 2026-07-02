// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon.server.witness

import merklon.*
import merklon.server.LogKeyStore
import zio.*
import zio.http.*

import java.nio.file.Paths
import java.security.{KeyPair, KeyPairGenerator}

/** Standalone witness service entrypoint.
  *
  * Environment:
  *   - `MERKLON_WITNESS_NAME` — this witness's signed-note key name (default
  *     `merklon.example/witness`)
  *   - `MERKLON_WITNESS_PORT` — listen port (default 8081)
  *   - `MERKLON_WITNESS_KEY_DIR` — persisted Ed25519 key directory (ephemeral key + warning without
  *     it)
  *   - `MERKLON_WITNESS_STATE_DIR` — durable last-cosigned-checkpoint state (in-memory + warning
  *     without it; an in-memory witness silently re-TOFUs on restart)
  *   - `MERKLON_WITNESS_LOGS` — comma-separated `origin=hex(ed25519 public key)` entries for the
  *     logs this witness watches (required)
  */
object WitnessMain extends ZIOAppDefault:

  private val name = sys.env.getOrElse("MERKLON_WITNESS_NAME", "merklon.example/witness")
  private val port = sys.env.get("MERKLON_WITNESS_PORT").flatMap(_.toIntOption).getOrElse(8081)
  private val keyDir = sys.env.get("MERKLON_WITNESS_KEY_DIR")
  private val stateDir = sys.env.get("MERKLON_WITNESS_STATE_DIR")
  private val logsSpec = sys.env.get("MERKLON_WITNESS_LOGS")

  override def run: ZIO[Any, Throwable, Nothing] =
    for
      logs <- ZIO
        .fromEither(parseLogs(logsSpec.getOrElse("")))
        .mapError(e => IllegalArgumentException(s"MERKLON_WITNESS_LOGS: $e"))
      _ <- ZIO
        .fail(IllegalArgumentException("MERKLON_WITNESS_LOGS must not be empty"))
        .when(logs.isEmpty)
      keyPair <- makeKeyPair
      store <- makeStore
      pub = keyPair.getPublic.getEncoded.takeRight(32)
      _ <- ZIO.logInfo(s"merklon witness")
      _ <- ZIO.logInfo(s"  name:       $name")
      _ <- ZIO.logInfo(s"  port:       $port")
      _ <- ZIO.logInfo(s"  public key: ${MerkleTree.toHex(pub)}")
      _ <- ZIO.foreachDiscard(logs)(l =>
        ZIO.logInfo(s"  watching:   ${l.origin} (key ${MerkleTree.toHex(l.publicKey).take(16)}…)")
      )
      exit <- Server
        .serve(WitnessServer.make(name, keyPair, logs, store))
        .provide(Server.defaultWithPort(port))
    yield exit

  /** Parse `origin=hexkey,origin=hexkey`; keys are raw 32-byte Ed25519 public keys in hex. */
  def parseLogs(spec: String): Either[String, List[WitnessedLog]] =
    val entries = spec.split(',').toList.map(_.trim).filter(_.nonEmpty)
    val (errs, logs) = entries
      .map { e =>
        e.split("=", 2) match
          case Array(origin, hex) if origin.nonEmpty =>
            parseHex32(hex).map(WitnessedLog(origin, _)).toRight(s"invalid key for '$origin'")
          case _ => Left(s"malformed entry '$e' (want origin=hexkey)")
      }
      .partitionMap(identity)
    if errs.nonEmpty then Left(errs.head) else Right(logs)

  private def parseHex32(hex: String): Option[Array[Byte]] =
    if hex.length != 64 || !hex.forall(c => c.isDigit || ('a' <= c.toLower && c.toLower <= 'f'))
    then None
    else Some(hex.grouped(2).map(Integer.parseInt(_, 16).toByte).toArray)

  private def makeKeyPair: ZIO[Any, Throwable, KeyPair] =
    keyDir match
      case Some(dir) =>
        ZIO
          .attemptBlocking(LogKeyStore.loadOrCreate(Paths.get(dir)))
          .tap(_ => ZIO.logInfo(s"  key dir:    $dir (persisted Ed25519 key)"))
      case None =>
        ZIO.logWarning(
          "MERKLON_WITNESS_KEY_DIR not set — using an EPHEMERAL key; cosignatures will not " +
            "verify across restarts"
        ) *> ZIO.succeed(KeyPairGenerator.getInstance("Ed25519").generateKeyPair())

  private def makeStore: ZIO[Any, Throwable, WitnessStateStore] =
    stateDir match
      case Some(dir) =>
        ZIO
          .attemptBlocking(FileWitnessStateStore(Paths.get(dir)))
          .tap(_ => ZIO.logInfo(s"  state dir:  $dir"))
      case None =>
        ZIO.logWarning(
          "MERKLON_WITNESS_STATE_DIR not set — witness state is IN-MEMORY; a restart silently " +
            "resets to trust-on-first-use"
        ) *> ZIO.succeed(InMemoryWitnessStateStore())
