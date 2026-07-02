// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon.server.witness

import merklon.*
import zio.*
import zio.http.*

import java.net.{InetSocketAddress, ServerSocket, Socket, URI}
import java.net.http.{HttpClient as JHttpClient, HttpRequest, HttpResponse}
import java.nio.file.Files
import java.security.KeyPairGenerator
import java.util.Base64

/** End-to-end c2sp.org/tlog-witness protocol tests against a real witness server, including the
  * Phase 3 "done" criterion: a deliberately equivocating log (split view) is detected — here, over
  * HTTP with the spec's status codes.
  */
class WitnessServerSuite extends munit.FunSuite:

  private val origin = "test.merklon/log"
  private val witnessName = "test.merklon/witness"
  private val fixedTime = 1751444000L

  private val logAttestor = CheckpointAttestor.generateEd25519(origin)
  private val witnessKeys = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
  private val witnessPub = witnessKeys.getPublic.getEncoded.takeRight(32)
  private val stateDir = Files.createTempDirectory("merklon-witness-state")

  private var testPort: Int = _
  private var testFiber: Fiber.Runtime[Throwable, Any] = _
  private val http = JHttpClient.newHttpClient()

  override def beforeAll(): Unit =
    testPort = freePort()
    val routes = WitnessServer.make(
      witnessName,
      witnessKeys,
      Seq(WitnessedLog(origin, logAttestor.publicKey)),
      FileWitnessStateStore(stateDir),
      clock = () => fixedTime
    )
    val serve = Server.serve(routes).provide(Server.defaultWithPort(testPort))
    Unsafe.unsafe { implicit u =>
      testFiber = Runtime.default.unsafe.fork(serve)
    }
    awaitPort(testPort)

  override def afterAll(): Unit =
    Unsafe.unsafe { implicit u =>
      Runtime.default.unsafe.run(testFiber.interrupt)
    }

  // --- helpers ---------------------------------------------------------------

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
    if !connected then fail(s"witness did not start on port $port within ${timeoutMs}ms")

  private def post(path: String, body: String): HttpResponse[String] =
    val req = HttpRequest
      .newBuilder(URI.create(s"http://localhost:$testPort$path"))
      .POST(HttpRequest.BodyPublishers.ofString(body))
      .build()
    http.send(req, HttpResponse.BodyHandlers.ofString())

  private def get(path: String): HttpResponse[String] =
    val req = HttpRequest.newBuilder(URI.create(s"http://localhost:$testPort$path")).GET().build()
    http.send(req, HttpResponse.BodyHandlers.ofString())

  /** Render a signed checkpoint note for `entries` under `signer` (default: the trusted log). */
  private def note(
      entries: Seq[String],
      signer: CheckpointAttestor = logAttestor,
      noteOrigin: String = origin
  ): String =
    val hashes = entries.map(e => MerkleTree.leafHash(e.getBytes("UTF-8"))).toList
    val root = MerkleTree.rootFromHashes(hashes)
    val body = CheckpointNote.noteBody(noteOrigin, entries.size.toLong, root)
    val sig = NoteSignature(signer.keyName, signer.keyId, signer.sign(body.getBytes("UTF-8")))
    CheckpointNote.render(Checkpoint(noteOrigin, entries.size.toLong, root, 0L, Vector(sig)))

  private def proofLines(oldSize: Int, entries: Seq[String]): Seq[String] =
    val hashes = entries.map(e => MerkleTree.leafHash(e.getBytes("UTF-8"))).toList
    MerkleTree.consistencyProofFromHashes(oldSize, hashes).map(Base64.getEncoder.encodeToString)

  private def request(old: Long, proof: Seq[String], noteText: String): String =
    s"old $old\n" + proof.map(_ + "\n").mkString + "\n" + noteText

  private val e4 = Seq("a", "b", "c", "d")
  private val e6 = e4 ++ Seq("e", "f")

  // --- protocol happy path (ordered: state accumulates across tests) ----------

  test("first add-checkpoint (old 0) returns 200 with a verifying cosignature/v1 line") {
    val n = note(e4)
    val resp = post("/add-checkpoint", request(0, Nil, n))
    assertEquals(resp.statusCode(), 200)
    val line = resp.body()
    assert(line.startsWith(s"— $witnessName "), s"got: $line")

    // The returned line, attached to the note, must satisfy the client witness policy.
    val cosigned = CheckpointNote.parse(n.stripSuffix("\n") + "\n" + line).toOption.get
    assert(WitnessPolicy.satisfied(cosigned, Seq(TrustedWitness(witnessName, witnessPub)), 1))
    val cosig = cosigned.signatures.last
    assertEquals(CosignatureV1.timestampOf(cosig), Some(fixedTime))
  }

  test("consistent extension (old 4 + proof) returns 200") {
    val resp = post("/add-checkpoint", request(4, proofLines(4, e6), note(e6)))
    assertEquals(resp.statusCode(), 200, s"body: ${resp.body()}")
  }

  test("monitoring endpoint serves the latest cosigned note under sha256(origin)") {
    val hash = java.security.MessageDigest
      .getInstance("SHA-256")
      .digest(origin.getBytes("UTF-8"))
      .map(b => f"${b & 0xff}%02x")
      .mkString
    val resp = get(s"/$hash/checkpoint")
    assertEquals(resp.statusCode(), 200)
    assert(resp.body().startsWith(origin), s"body: ${resp.body()}")
    assert(resp.body().contains(s"— $witnessName "), "must contain the witness cosignature")
    assertEquals(get("/" + "0" * 64 + "/checkpoint").statusCode(), 404)
  }

  // --- refusals ---------------------------------------------------------------

  test("409 with latest size when old does not match the witness's cosigned size") {
    val resp = post("/add-checkpoint", request(3, proofLines(3, e6), note(e6)))
    assertEquals(resp.statusCode(), 409)
    assertEquals(resp.body(), "6\n") // witness has cosigned size 6 by now
    assertEquals(resp.headers().firstValue("content-type").orElse(""), "text/x.tlog.size")
  }

  test("split view: same size, different root returns 409 (Phase 3 done criterion over HTTP)") {
    val forged = Seq("a", "b", "c", "d", "e", "FORGED")
    val resp = post("/add-checkpoint", request(6, Nil, note(forged)))
    assertEquals(resp.statusCode(), 409)
  }

  test("history rewrite: bad consistency proof returns 422") {
    val forged = Seq("a", "TAMPERED", "c", "d", "e", "f", "g", "h")
    val resp = post("/add-checkpoint", request(6, proofLines(6, forged), note(forged)))
    assertEquals(resp.statusCode(), 422)
  }

  test("unknown origin returns 404") {
    val other = CheckpointAttestor.generateEd25519("unknown.example/log")
    val resp =
      post(
        "/add-checkpoint",
        request(0, Nil, note(e4, signer = other, noteOrigin = "unknown.example/log"))
      )
    assertEquals(resp.statusCode(), 404)
  }

  test("note signed by an untrusted key returns 403") {
    val rogue = CheckpointAttestor.generateEd25519(origin) // right origin, wrong key
    val resp = post(
      "/add-checkpoint",
      request(6, proofLines(6, e6 ++ Seq("g")), note(e6 ++ Seq("g"), signer = rogue))
    )
    assertEquals(resp.statusCode(), 403)
  }

  test("old size exceeding the checkpoint size returns 400") {
    val resp = post("/add-checkpoint", request(9, Nil, note(e6)))
    assertEquals(resp.statusCode(), 400)
  }

  test("malformed bodies return 400") {
    assertEquals(post("/add-checkpoint", "not a request").statusCode(), 400)
    assertEquals(post("/add-checkpoint", "old x\n\n" + note(e6)).statusCode(), 400)
    assertEquals(post("/add-checkpoint", "old 6\nnot-base64!\n\n" + note(e6)).statusCode(), 400)
    assertEquals(post("/add-checkpoint", "old 6\n" + note(e6)).statusCode(), 400) // no blank line
  }

  test("witness state survives a restart: a second server over the same state dir enforces it") {
    val port2 = freePort()
    val routes = WitnessServer.make(
      witnessName,
      witnessKeys,
      Seq(WitnessedLog(origin, logAttestor.publicKey)),
      FileWitnessStateStore(stateDir), // same directory — durable state
      clock = () => fixedTime
    )
    val fiber = Unsafe.unsafe { implicit u =>
      Runtime.default.unsafe.fork(
        Server.serve(routes).provide(Server.defaultWithPort(port2))
      )
    }
    try
      awaitPort(port2)
      val req = HttpRequest
        .newBuilder(URI.create(s"http://localhost:$port2/add-checkpoint"))
        .POST(HttpRequest.BodyPublishers.ofString(request(0, Nil, note(e4))))
        .build()
      val resp = http.send(req, HttpResponse.BodyHandlers.ofString())
      // Not trust-on-first-use again: the restarted witness remembers size 6.
      assertEquals(resp.statusCode(), 409)
      assertEquals(resp.body(), "6\n")
    finally
      Unsafe.unsafe { implicit u =>
        Runtime.default.unsafe.run(fiber.interrupt)
      }
  }
