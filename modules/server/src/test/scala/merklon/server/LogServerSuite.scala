// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon.server

import merklon.*
import merklon.verifier.*
import zio.*
import zio.http.*

import java.net.{InetSocketAddress, ServerSocket, Socket, URI}
import java.net.http.{HttpClient as JHttpClient, HttpRequest, HttpResponse}

/** Integration tests: start a real ZIO HTTP server, exercise the API with java.net.http, and verify
  * correctness end-to-end — including round-trip proof verification.
  */
class LogServerSuite extends munit.FunSuite:

  private def freePort(): Int =
    val ss = ServerSocket(0)
    try ss.getLocalPort
    finally ss.close()

  /** Poll until `port` accepts a TCP connection, or fail after `timeoutMs`. Replaces a fixed sleep
    * so the first request can't race the server's bind.
    */
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

  private var testPort: Int = _
  private var testFiber: Fiber.Runtime[Throwable, Any] = _
  private var testAttestor: CheckpointAttestor = _
  private val http = JHttpClient.newHttpClient()

  override def beforeAll(): Unit =
    testPort = freePort()
    val storage = InMemoryStorageBackend()
    testAttestor = CheckpointAttestor.generateEd25519("test.merklon/log")
    val seq = Sequencer("test.merklon/log", storage, testAttestor)
    // Fast cadence so each POST /entries (which waits for its covering checkpoint) stays snappy.
    val serve = for
      publisher <- CheckpointPublisher.make(seq, storage, interval = 25.millis)
      _ <- publisher.run.fork
      exit <- Server
        .serve(LogServer.make(seq, storage, publisher))
        .provide(Server.defaultWithPort(testPort))
    yield exit
    Unsafe.unsafe { implicit u =>
      testFiber = Runtime.default.unsafe.fork(serve)
    }
    awaitPort(testPort) // poll until the ZIO HTTP server is accepting connections

  override def afterAll(): Unit =
    Unsafe.unsafe { implicit u =>
      Runtime.default.unsafe.run(testFiber.interrupt)
    }

  private def get(path: String): (Int, String) =
    val req = HttpRequest.newBuilder(URI.create(s"http://localhost:$testPort$path")).GET().build()
    val resp = http.send(req, HttpResponse.BodyHandlers.ofString())
    (resp.statusCode(), resp.body())

  private def postBytes(path: String, body: Array[Byte]): (Int, String) =
    val req = HttpRequest
      .newBuilder(URI.create(s"http://localhost:$testPort$path"))
      .POST(HttpRequest.BodyPublishers.ofByteArray(body))
      .build()
    val resp = http.send(req, HttpResponse.BodyHandlers.ofString())
    (resp.statusCode(), resp.body())

  test("GET /checkpoint returns 404 before any entry is submitted") {
    val (status, _) = get("/checkpoint")
    assertEquals(status, 404)
  }

  test("POST /entries returns 200 with leaf_index 0 for the first entry") {
    val (status, body) = postBytes("/entries", "hello merklon".getBytes("UTF-8"))
    assertEquals(status, 200)
    assert(body.contains("\"leaf_index\""), s"body: $body")
    assert(body.contains(":0") || body.contains(": 0"), s"expected leaf_index 0 in: $body")
  }

  test("GET /checkpoint returns 200 with signed note after an entry is submitted") {
    postBytes("/entries", "entry-for-checkpoint".getBytes("UTF-8"))
    val (status, body) = get("/checkpoint")
    assertEquals(status, 200)
    assert(body.startsWith("test.merklon/log"), s"body: $body")
    assert(body.contains("—"), "must contain em-dash signature line")
  }

  test("GET /checkpoint signature verifies with attestor public key") {
    postBytes("/entries", "sig-test".getBytes("UTF-8"))
    val (_, noteText) = get("/checkpoint")
    val cp = CheckpointParser.parse(noteText).fold(e => fail(s"parse: $e"), identity)
    assert(LogVerifier.verifyCheckpointSignature(cp, testAttestor.publicKey))
  }

  test("GET /proof/inclusion returns audit_path and verifies end-to-end") {
    val data = "verify-me".getBytes("UTF-8")
    val (_, appendBody) = postBytes("/entries", data)
    val leafIndex = raw""""leaf_index"\s*:\s*(\d+)""".r
      .findFirstMatchIn(appendBody)
      .map(_.group(1).toLong)
      .getOrElse(fail(s"no leaf_index in: $appendBody"))
    val (_, cpText) = get("/checkpoint")
    val cp = CheckpointParser.parse(cpText).fold(e => fail(s"parse: $e"), identity)
    val (status, body) = get(s"/proof/inclusion?leaf_index=$leafIndex&tree_size=${cp.treeSize}")
    assertEquals(status, 200)
    assert(body.contains("audit_path"), s"body: $body")
    val proof = ProofParser.parseInclusion(body).fold(e => fail(s"proof parse: $e"), identity)
    assert(LogVerifier.verifyInclusion(data, proof, cp), "inclusion proof must verify")
  }

  test("GET /proof/consistency returns 200 with proof_path") {
    postBytes("/entries", "consistency-entry".getBytes("UTF-8"))
    val (_, cpText) = get("/checkpoint")
    val cp = CheckpointParser.parse(cpText).fold(e => fail(s"parse: $e"), identity)
    val (status, body) = get(s"/proof/consistency?first=0&second=${cp.treeSize}")
    assertEquals(status, 200)
    assert(body.contains("proof_path"), s"body: $body")
  }

  test("GET /proof/consistency verifies end-to-end between two checkpoints") {
    // Snapshot an older checkpoint, append more, then prove the newer extends the older.
    postBytes("/entries", "older-1".getBytes("UTF-8"))
    val (_, olderText) = get("/checkpoint")
    val older = CheckpointParser.parse(olderText).fold(e => fail(s"parse: $e"), identity)

    postBytes("/entries", "newer-1".getBytes("UTF-8"))
    postBytes("/entries", "newer-2".getBytes("UTF-8"))
    val (_, newerText) = get("/checkpoint")
    val newer = CheckpointParser.parse(newerText).fold(e => fail(s"parse: $e"), identity)
    assert(newer.treeSize > older.treeSize, "newer checkpoint must be larger")

    val (status, body) = get(s"/proof/consistency?first=${older.treeSize}&second=${newer.treeSize}")
    assertEquals(status, 200)
    val proof = ProofParser.parseConsistency(body).fold(e => fail(s"proof parse: $e"), identity)
    assert(
      LogVerifier.verifyConsistency(older, newer, proof),
      "consistency proof must verify the newer checkpoint extends the older"
    )
  }

  test("GET /proof/inclusion returns 400 for out-of-range leaf_index") {
    postBytes("/entries", "range-test".getBytes("UTF-8"))
    val (_, cpText) = get("/checkpoint")
    val cp = CheckpointParser.parse(cpText).fold(e => fail(s"parse: $e"), identity)
    val (status, _) = get(s"/proof/inclusion?leaf_index=${cp.treeSize}&tree_size=${cp.treeSize}")
    assertEquals(status, 400)
  }

  test("GET /proof/inclusion returns 400 when leaf_index is missing") {
    val (status, _) = get("/proof/inclusion?tree_size=1")
    assertEquals(status, 400)
  }
