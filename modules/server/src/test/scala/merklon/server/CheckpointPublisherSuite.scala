// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon.server

import merklon.*
import zio.*

/** Deterministic tests for the timed-batching publisher: ticks are driven manually (the interval is
  * set far beyond the test's lifetime) so batching behavior is asserted without sleeps.
  */
class CheckpointPublisherSuite extends munit.FunSuite:

  private val origin = "test.merklon/log"

  private def runZ[A](z: Task[A]): A =
    Unsafe.unsafe(implicit u => Runtime.default.unsafe.run(z).getOrThrow())

  /** Counts saveCheckpoint calls so tests can assert how many checkpoints a tick produced. */
  private final class CountingStorage extends StorageBackend:
    private val inner = InMemoryStorageBackend()
    @volatile var checkpointsSaved: Int = 0
    def append(leafHash: Array[Byte], data: Array[Byte]): Long = inner.append(leafHash, data)
    def getEntry(index: Long): Option[LogEntry] = inner.getEntry(index)
    def getEntries(from: Long, until: Long): Vector[LogEntry] = inner.getEntries(from, until)
    def findLeafIndex(leafHash: Array[Byte]): Option[Long] = inner.findLeafIndex(leafHash)
    def size: Long = inner.size
    def leafHashes(from: Long, until: Long): Vector[Array[Byte]] = inner.leafHashes(from, until)
    def saveCheckpoint(cp: Checkpoint): Unit =
      checkpointsSaved += 1
      inner.saveCheckpoint(cp)
    def latestCheckpoint(): Option[Checkpoint] = inner.latestCheckpoint()

  private def fixture(): (CountingStorage, Sequencer, CheckpointPublisher) =
    val storage = CountingStorage()
    val seq = Sequencer(origin, storage, CheckpointAttestor.generateEd25519(origin))
    val publisher = runZ(
      CheckpointPublisher.make(seq, storage, interval = 1.hour, awaitTimeout = 30.seconds)
    )
    (storage, seq, publisher)

  test("tick publishes nothing on an empty log") {
    val (storage, _, publisher) = fixture()
    runZ(publisher.tick)
    assertEquals(storage.latestCheckpoint(), None)
    assertEquals(storage.checkpointsSaved, 0)
  }

  test("one tick batches every entry appended since the last checkpoint") {
    val (storage, seq, publisher) = fixture()
    (1 to 3).foreach(i => seq.append(s"entry-$i".getBytes("UTF-8")))
    runZ(publisher.tick)
    assertEquals(storage.latestCheckpoint().map(_.treeSize), Some(3L))
    assertEquals(storage.checkpointsSaved, 1)

    (4 to 5).foreach(i => seq.append(s"entry-$i".getBytes("UTF-8")))
    runZ(publisher.tick)
    assertEquals(storage.latestCheckpoint().map(_.treeSize), Some(5L))
    assertEquals(storage.checkpointsSaved, 2)
  }

  test("tick without growth republishes nothing") {
    val (storage, seq, publisher) = fixture()
    seq.append("only-entry".getBytes("UTF-8"))
    runZ(publisher.tick)
    runZ(publisher.tick)
    runZ(publisher.tick)
    assertEquals(storage.checkpointsSaved, 1)
  }

  test("append blocks until a tick integrates the entry, then returns its checkpoint") {
    val (storage, _, publisher) = fixture()
    val (idx, cp) = runZ(
      for
        fiber <- publisher.append("waited-for".getBytes("UTF-8")).fork
        _ <- ZIO.attemptBlocking(storage.size).repeatUntil(_ == 1L)
        _ <- publisher.tick
        result <- fiber.join
      yield result
    )
    assertEquals(idx, 0L)
    assertEquals(cp.treeSize, 1L)
  }

  test("concurrent appends are all covered by a single batched checkpoint") {
    val (storage, _, publisher) = fixture()
    val results = runZ(
      for
        fibers <- ZIO.foreach(1 to 5)(i => publisher.append(s"conc-$i".getBytes("UTF-8")).fork)
        _ <- ZIO.attemptBlocking(storage.size).repeatUntil(_ == 5L)
        _ <- publisher.tick
        results <- ZIO.foreach(fibers)(_.join)
      yield results
    )
    assertEquals(results.map(_._1).sorted, Vector(0L, 1L, 2L, 3L, 4L))
    // Every appender got the same size-5 checkpoint from one publish, not five.
    results.foreach((_, cp) => assertEquals(cp.treeSize, 5L))
    assertEquals(storage.checkpointsSaved, 1)
  }

  test("append waits for the announced checkpoint, not for raw storage state") {
    // The sequencer saves the un-cosigned note before witnessing; an appender must not observe
    // that intermediate save. Only the publisher's announcement (post-witnessing) releases it.
    val (storage, seq, publisher) = fixture()
    runZ(
      for
        fiber <- publisher.append("gated".getBytes("UTF-8")).fork
        _ <- ZIO.attemptBlocking(storage.size).repeatUntil(_ == 1L)
        // Simulate the intermediate state: a covering checkpoint is in storage, unannounced.
        _ <- ZIO.attemptBlocking(seq.publishCheckpoint())
        _ <- ZIO.sleep(200.millis)
        early <- fiber.poll
        _ = assert(early.isEmpty, "append must not return before the announcement")
        _ <- publisher.tick
        result <- fiber.join
        (idx, cp) = result
        _ = assertEquals(idx, 0L)
        _ = assertEquals(cp.treeSize, 1L)
      yield ()
    )
  }

  test("a resumed publisher does not republish a checkpoint the log already has") {
    val storage = CountingStorage()
    val seq = Sequencer(origin, storage, CheckpointAttestor.generateEd25519(origin))
    seq.append("pre-restart".getBytes("UTF-8"))
    seq.publishCheckpoint()
    assertEquals(storage.checkpointsSaved, 1)
    // A new publisher over existing state (as after a server restart) seeds from storage.
    val publisher = runZ(CheckpointPublisher.make(seq, storage, interval = 1.hour))
    runZ(publisher.tick)
    assertEquals(storage.checkpointsSaved, 1)
  }

  test("append fails with NotIntegrated when no tick ever covers it") {
    val (_, _, publisher) = {
      val storage = CountingStorage()
      val seq = Sequencer(origin, storage, CheckpointAttestor.generateEd25519(origin))
      val p = runZ(
        CheckpointPublisher.make(seq, storage, interval = 1.hour, awaitTimeout = 200.millis)
      )
      (storage, seq, p)
    }
    val exit = Unsafe.unsafe { implicit u =>
      Runtime.default.unsafe.run(publisher.append("orphan".getBytes("UTF-8")).exit).getOrThrow()
    }
    exit match
      case Exit.Failure(cause) =>
        assert(
          cause.failures.exists(_.isInstanceOf[CheckpointPublisher.NotIntegrated]),
          s"expected NotIntegrated, got: $cause"
        )
      case Exit.Success(v) => fail(s"append should not have completed: $v")
  }
