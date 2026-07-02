// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon.server

import merklon.*
import zio.*

/** Publishes checkpoints on a timed cadence instead of once per append.
  *
  * A single background fiber (`run`) ticks every `interval`: if the tree has grown since the last
  * published checkpoint it snapshots and signs a new one, submits it to all configured witnesses in
  * parallel, persists the cosigned note, and only then wakes appenders waiting on coverage. One
  * checkpoint — and one witness round — therefore covers every entry appended during the interval,
  * however many there were.
  *
  * `append` returns once a published checkpoint integrates the entry, so callers can immediately
  * fetch proofs against the returned tree size.
  */
final class CheckpointPublisher private (
    sequencer: Sequencer,
    storage: StorageBackend,
    witnesses: Seq[WitnessClient],
    interval: Duration,
    awaitTimeout: Duration,
    // Last fully announced (published + witnessed) checkpoint, and the signal completed when the
    // next one lands. Appenders wait on this, NOT on storage.latestCheckpoint(): the sequencer
    // saves the un-cosigned note first, and appenders must not observe that intermediate state.
    state: Ref[(Option[Checkpoint], Promise[Nothing, Checkpoint])]
):
  import CheckpointPublisher.NotIntegrated

  /** Append an entry and wait for the checkpoint that integrates it; returns the entry's 0-based
    * leaf index and that checkpoint. Fails with [[CheckpointPublisher.NotIntegrated]] if no
    * checkpoint covers the entry within `awaitTimeout` (publisher fiber not running or overloaded);
    * the entry itself is durably appended either way.
    */
  def append(data: Array[Byte]): Task[(Long, Checkpoint)] =
    for
      idx <- ZIO.attemptBlocking(sequencer.append(data))
      cp <- awaitCoverage(idx)
    yield (idx, cp)

  /** Wait for an announced checkpoint whose tree size covers leaf `idx`, across ticks if needed. */
  private def awaitCoverage(idx: Long): Task[Checkpoint] =
    def loop: Task[Checkpoint] =
      state.get.flatMap {
        case (Some(cp), _) if cp.treeSize > idx => ZIO.succeed(cp)
        case (_, signal)                        => signal.await *> loop
      }
    loop.timeoutFail(NotIntegrated(idx, awaitTimeout))(awaitTimeout)

  /** Publish (and witness) one checkpoint if the tree grew since the last one; otherwise do
    * nothing. Never fails: publish errors are logged and retried on the next tick. Exposed so tests
    * can drive the cadence deterministically.
    */
  def tick: UIO[Unit] =
    (for
      last <- state.get.map(_._1.map(_.treeSize).getOrElse(0L))
      size <- ZIO.attemptBlocking(storage.size)
      _ <- publishNow.when(size > last)
    yield ()).catchAll(e => ZIO.logError(s"checkpoint publish failed: ${e.getMessage}"))

  /** Tick forever on the configured cadence. Fork exactly once, alongside the HTTP server. */
  def run: UIO[Nothing] =
    (tick *> ZIO.sleep(interval)).forever

  private def publishNow: Task[Unit] =
    for
      signed <- ZIO.attemptBlocking(sequencer.publishCheckpoint())
      cp <- gatherCosignatures(signed)
      next <- Promise.make[Nothing, Checkpoint]
      signal <- state.modify { case (_, old) => (old, (Some(cp), next)) }
      _ <- signal.succeed(cp)
    yield ()

  /** Submit `cp` to every witness in parallel; persist the note with whatever cosignatures came
    * back. Best-effort by design: witness failures are logged, never fatal — availability of the
    * log must not depend on any single witness; clients enforce their own N-of-M policy.
    */
  private def gatherCosignatures(cp: Checkpoint): UIO[Checkpoint] =
    if witnesses.isEmpty then ZIO.succeed(cp)
    else
      val proofFrom: Long => List[Array[Byte]] = old =>
        MerkleTree.consistencyProofFromHashes(
          old.toInt,
          storage.leafHashes(0L, cp.treeSize).toList
        )
      ZIO
        .foreachPar(witnesses) { w =>
          ZIO.attemptBlocking(w.submit(cp, proofFrom)).flatMap {
            case Right(sig) => ZIO.succeed(Some(sig))
            case Left(err)  => ZIO.logWarning(s"witness cosign failed: $err").as(None)
          }
        }
        .flatMap { results =>
          val cosigs = results.flatten
          if cosigs.isEmpty then ZIO.succeed(cp)
          else
            val cosigned = cp.copy(signatures = cp.signatures ++ cosigs)
            ZIO.attemptBlocking(storage.saveCheckpoint(cosigned)).as(cosigned)
        }
        .catchAll(e => ZIO.logWarning(s"witness cosigning: ${e.getMessage}").as(cp))

object CheckpointPublisher:

  /** The appended entry was not integrated by any checkpoint within the await timeout. */
  final case class NotIntegrated(leafIndex: Long, waited: Duration)
      extends RuntimeException(
        s"entry $leafIndex appended but no checkpoint integrated it within ${waited.render}"
      )

  def make(
      sequencer: Sequencer,
      storage: StorageBackend,
      witnesses: Seq[WitnessClient] = Nil,
      interval: Duration = 1.second,
      awaitTimeout: Duration = 30.seconds
  ): Task[CheckpointPublisher] =
    for
      last <- ZIO.attemptBlocking(storage.latestCheckpoint())
      signal <- Promise.make[Nothing, Checkpoint]
      state <- Ref.make((last, signal))
    yield new CheckpointPublisher(sequencer, storage, witnesses, interval, awaitTimeout, state)
