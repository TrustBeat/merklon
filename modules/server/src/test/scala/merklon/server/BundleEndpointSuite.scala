// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon.server

import com.sun.net.httpserver.HttpServer
import merklon.*
import merklon.server.witness.{WitnessServer, WitnessedLog}
import merklon.verifier.{BundleVerifier, TestTsa}
import zio.*
import zio.http.*

import java.net.{InetSocketAddress, ServerSocket, Socket, URI}
import java.net.http.{HttpClient as JHttpClient, HttpRequest, HttpResponse}
import java.security.KeyPairGenerator

/** The Phase 4 "done" bar end-to-end: a log server with a witness and an RFC 3161 TSA (an
  * in-process stub speaking the real DER protocol over HTTP) exports a proof bundle, and the
  * standalone verifier verifies it fully offline — entry inclusion, log signature, witness policy,
  * and the qualified timestamp.
  */
class BundleEndpointSuite extends munit.FunSuite:

  private val origin = "test.merklon/log"
  private val logAttestor = CheckpointAttestor.generateEd25519(origin)
  private val witnessKeys = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
  private val trusted = Seq(
    TrustedWitness("test.merklon/witness-1", witnessKeys.getPublic.getEncoded.takeRight(32))
  )
  private val tsa = TestTsa()

  private var logPort: Int = _
  private var tsaServer: HttpServer = _
  private var fibers: List[Fiber.Runtime[Throwable, Any]] = Nil
  private val http = JHttpClient.newHttpClient()

  override def beforeAll(): Unit =
    // RFC 3161 TSA stub: DER request in, DER response out, signed by the test TSA.
    tsaServer = HttpServer.create(InetSocketAddress("localhost", 0), 0)
    tsaServer.createContext(
      "/tsa",
      exchange =>
        val response = tsa.respond(exchange.getRequestBody.readAllBytes())
        exchange.getResponseHeaders.set("Content-Type", "application/timestamp-reply")
        exchange.sendResponseHeaders(200, response.length)
        exchange.getResponseBody.write(response)
        exchange.close()
    )
    tsaServer.start()
    val tsaUrl = s"http://localhost:${tsaServer.getAddress.getPort}/tsa"

    val witnessPort = freePort()
    logPort = freePort()
    val watched = Seq(WitnessedLog(origin, logAttestor.publicKey))
    val witness = Server
      .serve(
        WitnessServer
          .make("test.merklon/witness-1", witnessKeys, watched, InMemoryWitnessStateStore())
      )
      .provide(Server.defaultWithPort(witnessPort))

    val storage = InMemoryStorageBackend()
    val seq = Sequencer(origin, storage, logAttestor)
    val log = for
      publisher <- CheckpointPublisher.make(
        seq,
        storage,
        List(WitnessClient(s"http://localhost:$witnessPort")),
        interval = 25.millis
      )
      _ <- publisher.run.fork
      exit <- Server
        .serve(LogServer.make(seq, storage, publisher, Some(TsaClient(tsaUrl))))
        .provide(Server.defaultWithPort(logPort))
    yield exit

    Unsafe.unsafe { implicit u =>
      fibers = List(witness, log).map(Runtime.default.unsafe.fork(_))
    }
    List(witnessPort, logPort).foreach(awaitPort(_))

  override def afterAll(): Unit =
    Unsafe.unsafe { implicit u =>
      fibers.foreach(f => Runtime.default.unsafe.run(f.interrupt))
    }
    tsaServer.stop(0)

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

  private def get(path: String): (Int, String) =
    val req = HttpRequest.newBuilder(URI.create(s"http://localhost:$logPort$path")).GET().build()
    val resp = http.send(req, HttpResponse.BodyHandlers.ofString())
    (resp.statusCode(), resp.body())

  private def post(path: String, body: String): (Int, String) =
    val req = HttpRequest
      .newBuilder(URI.create(s"http://localhost:$logPort$path"))
      .POST(HttpRequest.BodyPublishers.ofString(body))
      .build()
    val resp = http.send(req, HttpResponse.BodyHandlers.ofString())
    (resp.statusCode(), resp.body())

  test("GET /bundle returns 404 before any checkpoint exists") {
    val (status, _) = get("/bundle?leaf_index=0")
    assertEquals(status, 404)
  }

  test("exported bundle verifies fully offline: inclusion + witness policy + qualified TS") {
    for i <- 0 until 3 do assertEquals(post("/entries", s"bundled-entry-$i")._1, 200)
    val (status, json) = get("/bundle?leaf_index=1")
    assertEquals(status, 200)

    // Everything below is offline: no URL, only the bundle document and trust anchors.
    val report = BundleVerifier
      .verify(
        json,
        logAttestor.publicKey,
        witnesses = trusted,
        threshold = 1,
        tsaCert = Some(tsa.certificate)
      )
      .fold(e => fail(s"offline verification failed: $e"), identity)
    assertEquals(report.leafIndex, 1L)
    assert(report.checkpoint.treeSize >= 3L)
    assertEquals(report.cosigners, Set("test.merklon/witness-1"))
    val ts = report.timestamp.getOrElse(fail("bundle must carry a qualified timestamp"))
    assert(ts.signerVerified, "TSA signature must verify against the TSA certificate")

    // The bundle also matches the entry bytes the submitter knows.
    val bundle = ProofBundleCodec.parse(json).toOption.get
    assertEquals(String(bundle.entry, "UTF-8"), "bundled-entry-1")
  }

  test("a tampered bundle is rejected offline") {
    post("/entries", "tamper-target")
    val (_, json) = get("/bundle?leaf_index=0")
    val tampered = json.replaceFirst(""""leaf_index": \d+""", """"leaf_index": 2""")
    assert(
      BundleVerifier.verify(tampered, logAttestor.publicKey).isLeft,
      "verification must fail after tampering with the leaf index"
    )
  }

  test("GET /bundle returns 404 for a leaf beyond the latest checkpoint") {
    post("/entries", "another")
    val (status, _) = get("/bundle?leaf_index=999999")
    assertEquals(status, 404)
  }

  test("GET /bundle returns 400 without leaf_index") {
    val (status, _) = get("/bundle")
    assertEquals(status, 400)
  }

  test("GET /tlog-proof exports c2sp.org/tlog-proof@v1 that verifies offline") {
    val (postStatus, postBody) = post("/entries", "tlog-proof-entry")
    assertEquals(postStatus, 200)
    val idx = raw""""leaf_index":(\d+)""".r
      .findFirstMatchIn(postBody)
      .map(_.group(1).toLong)
      .getOrElse(fail(s"no leaf_index in: $postBody"))

    val (status, text) = get(s"/tlog-proof?leaf_index=$idx")
    assertEquals(status, 200)
    assert(text.startsWith(merklon.TlogProofCodec.Header + "\n"), text.take(40))

    // Offline: only the document, the entry bytes (held out of band), and trust anchors.
    val report = merklon.verifier.TlogProofVerifier
      .verify(
        text,
        "tlog-proof-entry".getBytes("UTF-8"),
        logAttestor.publicKey,
        witnesses = trusted,
        threshold = 1
      )
      .fold(e => fail(s"offline verification failed: $e"), identity)
    assertEquals(report.leafIndex, idx)
    assertEquals(report.cosigners, Set("test.merklon/witness-1"))

    // The wrong entry bytes must not verify against the same document.
    assert(
      merklon.verifier.TlogProofVerifier
        .verify(text, "wrong-entry".getBytes("UTF-8"), logAttestor.publicKey)
        .isLeft
    )
  }

  test("GET /tlog-proof returns 404 beyond the latest checkpoint and 400 without leaf_index") {
    assertEquals(get("/tlog-proof?leaf_index=999999")._1, 404)
    assertEquals(get("/tlog-proof")._1, 400)
  }
