// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon.server

import merklon.*
import merklon.server.witness.{WitnessServer, WitnessedLog}
import zio.*
import zio.http.*

import java.net.{InetSocketAddress, ServerSocket, Socket, URI}
import java.net.http.{HttpClient as JHttpClient, HttpRequest, HttpResponse}
import java.security.KeyPairGenerator

/** Full-loop end-to-end test: a log server configured with two witness servers. Every appended
  * entry produces a checkpoint that is submitted to the witnesses, and GET /checkpoint serves a
  * note satisfying a client 2-of-2 witness policy — the complete Phase 3 story.
  */
class WitnessedLogSuite extends munit.FunSuite:

  private val origin = "test.merklon/log"

  private val logAttestor = CheckpointAttestor.generateEd25519(origin)
  private val w1Keys = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
  private val w2Keys = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()

  private val trusted = Seq(
    TrustedWitness("test.merklon/witness-1", w1Keys.getPublic.getEncoded.takeRight(32)),
    TrustedWitness("test.merklon/witness-2", w2Keys.getPublic.getEncoded.takeRight(32))
  )

  private var logPort: Int = _
  private var fibers: List[Fiber.Runtime[Throwable, Any]] = Nil
  private val http = JHttpClient.newHttpClient()

  override def beforeAll(): Unit =
    val w1Port = freePort()
    val w2Port = freePort()
    logPort = freePort()

    val watched = Seq(WitnessedLog(origin, logAttestor.publicKey))
    val w1 = Server
      .serve(
        WitnessServer.make("test.merklon/witness-1", w1Keys, watched, InMemoryWitnessStateStore())
      )
      .provide(Server.defaultWithPort(w1Port))
    val w2 = Server
      .serve(
        WitnessServer.make("test.merklon/witness-2", w2Keys, watched, InMemoryWitnessStateStore())
      )
      .provide(Server.defaultWithPort(w2Port))

    val storage = InMemoryStorageBackend()
    val seq = Sequencer(origin, storage, logAttestor)
    val witnesses = List(
      WitnessClient(s"http://localhost:$w1Port"),
      WitnessClient(s"http://localhost:$w2Port")
    )
    val log = Server
      .serve(LogServer.make(seq, storage, witnesses))
      .provide(Server.defaultWithPort(logPort))

    Unsafe.unsafe { implicit u =>
      fibers = List(w1, w2, log).map(Runtime.default.unsafe.fork(_))
    }
    List(w1Port, w2Port, logPort).foreach(awaitPort(_))

  override def afterAll(): Unit =
    Unsafe.unsafe { implicit u =>
      fibers.foreach(f => Runtime.default.unsafe.run(f.interrupt))
    }

  private def freePort(): Int =
    val ss = ServerSocket(0)
    try ss.getLocalPort
    finally ss.close()

  private def awaitPort(port: Int, timeoutMs: Long = 5000): Unit =
    val deadline = java.lang.System.currentTimeMillis() + timeoutMs
    var connected = false
    while !connected && java.lang.System.currentTimeMillis() < deadline do
      val sock = Socket()
      try
        sock.connect(InetSocketAddress("localhost", port), 100)
        connected = true
      catch case _: Exception => Thread.sleep(25)
      finally sock.close()
    if !connected then fail(s"server did not start on port $port within ${timeoutMs}ms")

  private def appendEntry(data: String): Int =
    val req = HttpRequest
      .newBuilder(URI.create(s"http://localhost:$logPort/entries"))
      .POST(HttpRequest.BodyPublishers.ofString(data))
      .build()
    http.send(req, HttpResponse.BodyHandlers.ofString()).statusCode()

  private def latestCheckpoint(): Checkpoint =
    val req =
      HttpRequest.newBuilder(URI.create(s"http://localhost:$logPort/checkpoint")).GET().build()
    val resp = http.send(req, HttpResponse.BodyHandlers.ofString())
    assertEquals(resp.statusCode(), 200)
    CheckpointNote.parse(resp.body()).fold(e => fail(s"parse: $e"), identity)

  test("served checkpoints carry cosignatures satisfying a 2-of-2 witness policy") {
    assertEquals(appendEntry("first-entry"), 200)
    val cp1 = latestCheckpoint()
    assertEquals(cp1.treeSize, 1L)
    assert(
      WitnessPolicy.satisfied(cp1, trusted, threshold = 2),
      s"cosigners: ${WitnessPolicy.validCosigners(cp1, trusted)}"
    )

    // The witnesses follow the growing log via consistency proofs, not blind re-signing.
    assertEquals(appendEntry("second-entry"), 200)
    assertEquals(appendEntry("third-entry"), 200)
    val cp3 = latestCheckpoint()
    assertEquals(cp3.treeSize, 3L)
    assert(WitnessPolicy.satisfied(cp3, trusted, threshold = 2))
  }

  test("the log signature and the cosignatures are all on the same served note") {
    appendEntry("another-entry")
    val cp = latestCheckpoint()
    // 1 log signature + 2 witness cosignatures.
    assert(cp.signatures.exists(s => s.keyName == origin), "log signature present")
    assertEquals(WitnessPolicy.validCosigners(cp, trusted).size, 2)
    assert(
      cp.signatures.forall(s => s.keyName == origin || CosignatureV1.timestampOf(s).exists(_ > 0L)),
      "witness lines carry non-zero cosignature timestamps"
    )
  }
