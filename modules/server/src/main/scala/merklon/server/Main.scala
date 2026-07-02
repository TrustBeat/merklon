// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon.server

import merklon.*
import merklon.storage.pg.PostgresStorageBackend
import zio.*
import zio.http.*

object Main extends ZIOAppDefault:

  private val origin = sys.env.getOrElse("MERKLON_ORIGIN", "merklon.example/log")
  private val port = sys.env.get("MERKLON_PORT").flatMap(_.toIntOption).getOrElse(8080)
  private val keyDir = sys.env.get("MERKLON_KEY_DIR")
  private val dbUrl = sys.env.get("MERKLON_DB_URL")
  // Comma-separated witness base URLs; each published checkpoint is submitted to all of them.
  private val witnessUrls =
    sys.env.get("MERKLON_WITNESSES").toList.flatMap(_.split(',')).map(_.trim).filter(_.nonEmpty)
  // Checkpoint batching cadence: at most one checkpoint (and one witness round) per interval.
  private val batchMs =
    sys.env.get("MERKLON_BATCH_MS").flatMap(_.toLongOption).getOrElse(1000L)
  // RFC 3161 TSA endpoint; when set, exported proof bundles are sealed with a qualified timestamp.
  private val tsaUrl = sys.env.get("MERKLON_TSA_URL")

  override def run: ZIO[Any, Throwable, Nothing] =
    for
      attestor <- makeAttestor
      storage <- makeStorage
      seq = Sequencer(origin, storage, attestor)
      witnesses = witnessUrls.map(WitnessClient(_))
      publisher <- CheckpointPublisher.make(seq, storage, witnesses, batchMs.milliseconds)
      _ <- ZIO.logInfo(s"merklon log server")
      _ <- ZIO.logInfo(s"  origin:     $origin")
      _ <- ZIO.logInfo(s"  port:       $port")
      _ <- ZIO.logInfo(s"  public key: ${MerkleTree.toHex(attestor.publicKey)}")
      _ <- ZIO.logInfo(s"  batching:   checkpoint every ${batchMs}ms")
      _ <- ZIO.foreachDiscard(witnessUrls)(u => ZIO.logInfo(s"  witness:    $u"))
      _ <- ZIO.foreachDiscard(tsaUrl)(u => ZIO.logInfo(s"  tsa:        $u (RFC 3161)"))
      _ <- publisher.run.fork
      exit <- Server
        .serve(LogServer.make(seq, storage, publisher, tsaUrl.map(TsaClient(_))))
        .provide(Server.defaultWithPort(port))
    yield exit

  /** Postgres from MERKLON_DB_URL (+ MERKLON_DB_USER / MERKLON_DB_PASSWORD); without it, an
    * in-memory backend (dev only — the log is lost on restart).
    */
  private def makeStorage: ZIO[Any, Throwable, StorageBackend] =
    dbUrl match
      case Some(url) =>
        val user = sys.env.getOrElse("MERKLON_DB_USER", "postgres")
        val password = sys.env.getOrElse("MERKLON_DB_PASSWORD", "")
        ZIO
          .attemptBlocking(PostgresStorageBackend(url, user, password))
          .tap(_ => ZIO.logInfo(s"  storage:    postgres ($url)"))
      case None =>
        ZIO.logWarning(
          "MERKLON_DB_URL not set — using IN-MEMORY storage; the log is lost on restart"
        ) *> ZIO.succeed(InMemoryStorageBackend())

  /** Persisted key from MERKLON_KEY_DIR; without it, an ephemeral key (dev only — checkpoints
    * become unverifiable across restarts).
    */
  private def makeAttestor: ZIO[Any, Throwable, CheckpointAttestor] =
    keyDir match
      case Some(dir) =>
        ZIO
          .attemptBlocking(LogKeyStore.loadOrCreate(java.nio.file.Paths.get(dir)))
          .map(CheckpointAttestor.ed25519(origin, _))
          .tap(_ => ZIO.logInfo(s"  key dir:    $dir (persisted Ed25519 key)"))
      case None =>
        ZIO.logWarning(
          "MERKLON_KEY_DIR not set — using an EPHEMERAL Ed25519 key; " +
            "checkpoints will not verify across restarts"
        ) *> ZIO.succeed(CheckpointAttestor.generateEd25519(origin))
