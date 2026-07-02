// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon.storage.pg

import merklon.*

import java.security.KeyPairGenerator
import java.sql.DriverManager
import java.util.Arrays
import scala.concurrent.duration.*
import scala.sys.process.*

/** Integration tests against a real PostgreSQL started via Docker (postgres:16-alpine, fsync off —
  * throwaway test data). All tests are skipped with `assume` when Docker is unavailable.
  *
  * Includes the Phase 1 "done" bar from docs/DESIGN.md: append 100k entries across restarts, every
  * checkpoint chains consistently. Entry count is overridable via MERKLON_PG_TEST_ENTRIES.
  */
class PostgresStorageBackendSuite extends munit.FunSuite:

  override def munitTimeout: Duration = 10.minutes

  private val containerName = s"merklon-pg-test-${ProcessHandle.current().pid()}"
  private val user = "postgres"
  private val password = "merklon"
  private var jdbcUrl: Option[String] = None

  override def beforeAll(): Unit =
    if dockerAvailable then
      Seq(
        "docker",
        "run",
        "-d",
        "--rm",
        "--name",
        containerName,
        "-e",
        s"POSTGRES_PASSWORD=$password",
        "-e",
        "POSTGRES_DB=merklon",
        "-p",
        "127.0.0.1:0:5432",
        "postgres:16-alpine",
        "-c",
        "fsync=off",
        "-c",
        "synchronous_commit=off"
      ).!!(silent)
      val mapped = Seq("docker", "port", containerName, "5432/tcp").!!.trim
      val port = mapped.linesIterator.next().split(':').last
      val url = s"jdbc:postgresql://127.0.0.1:$port/merklon"
      awaitReady(url)
      jdbcUrl = Some(url)

  override def afterAll(): Unit =
    if jdbcUrl.isDefined then Seq("docker", "stop", containerName).!(silent)

  private def silent = ProcessLogger(_ => (), _ => ())

  private def dockerAvailable: Boolean =
    try Seq("docker", "info").!(silent) == 0
    catch case _: Exception => false

  private def awaitReady(url: String): Unit =
    val deadline = System.nanoTime() + 60.seconds.toNanos
    var ready = false
    while !ready do
      try
        DriverManager.getConnection(url, user, password).close()
        ready = true
      catch
        case e: Exception =>
          if System.nanoTime() > deadline then throw e
          Thread.sleep(250)

  /** Fresh backend over truncated tables; closes it after the test body. */
  private def withFreshBackend[A](body: PostgresStorageBackend => A): A =
    assume(jdbcUrl.isDefined, "docker unavailable — skipping Postgres integration tests")
    val backend = PostgresStorageBackend(jdbcUrl.get, user, password)
    truncate()
    try body(backend)
    finally backend.close()

  private def truncate(): Unit =
    val conn = DriverManager.getConnection(jdbcUrl.get, user, password)
    try
      val st = conn.createStatement()
      try st.execute("TRUNCATE entries, checkpoints RESTART IDENTITY CASCADE")
      finally st.close()
    finally conn.close()

  private def hex(b: Array[Byte]): String = MerkleTree.toHex(b)

  test("append / getEntry / size / leafHashes round-trip") {
    withFreshBackend { backend =>
      val data = Vector("alfa", "bravo", "charlie").map(_.getBytes("UTF-8"))
      val hashes = data.map(MerkleTree.leafHash)
      val indices = data.zip(hashes).map((d, h) => backend.append(h, d))
      assertEquals(indices, Vector(0L, 1L, 2L))
      assertEquals(backend.size, 3L)
      val e1 = backend.getEntry(1L).getOrElse(fail("entry 1 missing"))
      assertEquals(e1.index, 1L)
      assertEquals(hex(e1.leafHash), hex(hashes(1)))
      assertEquals(new String(e1.data, "UTF-8"), "bravo")
      assert(e1.submittedAt > 0L)
      assertEquals(backend.getEntry(3L), None)
      assertEquals(backend.getEntry(-1L), None)
      assertEquals(backend.leafHashes(0L, 3L).map(hex), hashes.map(hex))
      assertEquals(backend.leafHashes(1L, 2L).map(hex), Vector(hex(hashes(1))))
    }
  }

  test("getEntries range and findLeafIndex (first occurrence wins on duplicates)") {
    withFreshBackend { backend =>
      val data = Vector("one", "two", "two", "three").map(_.getBytes("UTF-8"))
      val hashes = data.map(MerkleTree.leafHash)
      data.zip(hashes).foreach((d, h) => backend.append(h, d))

      val page = backend.getEntries(1L, 3L)
      assertEquals(page.map(_.index), Vector(1L, 2L))
      assertEquals(page.map(e => new String(e.data, "UTF-8")), Vector("two", "two"))

      // "two" appears at indices 1 and 2 — the lowest index must win, deterministically.
      assertEquals(backend.findLeafIndex(hashes(1)), Some(1L))
      assertEquals(backend.findLeafIndex(hashes(0)), Some(0L))
      assertEquals(backend.findLeafIndex(MerkleTree.leafHash("absent".getBytes("UTF-8"))), None)
    }
  }

  test("checkpoint save / latest round-trip preserves signatures in order") {
    withFreshBackend { backend =>
      assertEquals(backend.latestCheckpoint(), None)
      val sigs = Vector(
        NoteSignature("log.example/a", Array[Byte](1, 2, 3, 4), Array.fill[Byte](64)(7)),
        NoteSignature("witness.example/b", Array[Byte](5, 6, 7, 8), Array.fill[Byte](64)(9))
      )
      val cp1 = Checkpoint("merklon.test/pg", 5L, Array.fill[Byte](32)(1), 111L, sigs.take(1))
      val cp2 = Checkpoint("merklon.test/pg", 9L, Array.fill[Byte](32)(2), 222L, sigs)
      backend.saveCheckpoint(cp1)
      backend.saveCheckpoint(cp2)
      val latest = backend.latestCheckpoint().getOrElse(fail("no checkpoint"))
      assertEquals(latest.origin, cp2.origin)
      assertEquals(latest.treeSize, 9L)
      assertEquals(hex(latest.rootHash), hex(cp2.rootHash))
      assertEquals(latest.signedAt, 222L)
      assertEquals(latest.signatures.map(_.keyName), sigs.map(_.keyName))
      assertEquals(latest.signatures.map(s => hex(s.keyId)), sigs.map(s => hex(s.keyId)))
      assertEquals(latest.signatures.map(s => hex(s.sig)), sigs.map(s => hex(s.sig)))
    }
  }

  test("saveCheckpoint refuses a shrinking tree_size") {
    withFreshBackend { backend =>
      backend.saveCheckpoint(
        Checkpoint("merklon.test/pg", 10L, Array.fill[Byte](32)(1), 1L, Vector())
      )
      intercept[IllegalArgumentException] {
        backend.saveCheckpoint(
          Checkpoint("merklon.test/pg", 9L, Array.fill[Byte](32)(2), 2L, Vector())
        )
      }
    }
  }

  test("Phase 1 done bar: 100k entries across restarts, every checkpoint chains consistently") {
    assume(jdbcUrl.isDefined, "docker unavailable — skipping Postgres integration tests")
    truncate()

    val total =
      sys.env.get("MERKLON_PG_TEST_ENTRIES").flatMap(_.toIntOption).getOrElse(100_000)
    val restarts = 4
    val perChunk = total / restarts
    val origin = "merklon.test/pg"
    // One persisted log identity across all "restarts" (as MERKLON_KEY_DIR provides in prod).
    val keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()

    val localHashes = Vector.newBuilder[Array[Byte]]
    var checkpoints = Vector.empty[Checkpoint]

    for chunk <- 0 until restarts do
      // Each chunk is a separate backend instance over the same database — a process restart.
      val backend = PostgresStorageBackend(jdbcUrl.get, user, password)
      try
        val seq = Sequencer(origin, backend, CheckpointAttestor.ed25519(origin, keyPair))
        assertEquals(backend.size, chunk.toLong * perChunk, "size must survive restart")
        for i <- (chunk * perChunk) until ((chunk + 1) * perChunk) do
          val data = s"entry-$i".getBytes("UTF-8")
          localHashes += MerkleTree.leafHash(data)
          assertEquals(seq.append(data), i.toLong)
        checkpoints :+= seq.publishCheckpoint()
      finally backend.close()

    val backend = PostgresStorageBackend(jdbcUrl.get, user, password)
    try
      // The stored leaf hashes must be exactly what we computed locally, in order.
      val stored = backend.leafHashes(0L, total.toLong)
      val local = localHashes.result()
      assertEquals(stored.size, total)
      stored.indices.foreach { i =>
        if !Arrays.equals(stored(i), local(i)) then
          fail(s"leaf hash mismatch at index $i: ${hex(stored(i))} != ${hex(local(i))}")
      }

      // Every adjacent checkpoint pair must verify as append-only via a consistency proof.
      val all = stored.toList
      checkpoints.sliding(2).foreach {
        case Vector(prev, next) =>
          val proof = MerkleTree.consistencyProofFromHashes(
            prev.treeSize.toInt,
            all.take(next.treeSize.toInt)
          )
          assert(
            MerkleTree.verifyConsistency(
              prev.treeSize.toInt,
              next.treeSize.toInt,
              prev.rootHash,
              next.rootHash,
              proof
            ),
            s"checkpoint ${prev.treeSize} → ${next.treeSize} failed consistency verification"
          )
        case _ => ()
      }

      // The latest persisted checkpoint must match an independent root recomputation.
      val latest = backend.latestCheckpoint().getOrElse(fail("no checkpoint persisted"))
      assertEquals(latest.treeSize, total.toLong)
      assertEquals(hex(latest.rootHash), hex(MerkleTree.rootFromHashes(all)))
    finally backend.close()
  }
