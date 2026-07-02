// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon.verifier

import merklon.*

import java.security.KeyPairGenerator

/** Offline bundle verification against a real in-memory log: signed checkpoint, witness
  * cosignature, inclusion proof, and RFC 3161 tokens from the in-process test TSA.
  */
class BundleVerifierSuite extends munit.FunSuite:

  private val origin = "test.merklon/log"
  private val attestor = CheckpointAttestor.generateEd25519(origin)
  private val witnessName = "test.merklon/witness-1"
  private val witnessKeys = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
  private val trustedWitness =
    TrustedWitness(witnessName, witnessKeys.getPublic.getEncoded.takeRight(32))
  private val tsa = TestTsa()

  private val entries = (0 until 5).map(i => s"entry-$i".getBytes("UTF-8")).toList

  // One log for the whole suite: 5 entries, a cosigned checkpoint, a bundle for leaf 2.
  private val (checkpoint, bundleJson) =
    val storage = InMemoryStorageBackend()
    val seq = Sequencer(origin, storage, attestor)
    entries.foreach(seq.append)
    val signed = seq.publishCheckpoint()
    val cosig = CosignatureV1.sign(
      witnessName,
      witnessKeys,
      CheckpointNote.noteBody(signed),
      timestamp = System.currentTimeMillis() / 1000
    )
    val cp = signed.copy(signatures = signed.signatures :+ cosig)
    val proof =
      MerkleTree.inclusionProofFromHashes(2, storage.leafHashes(0L, cp.treeSize).toList)
    val bundle = ProofBundle(
      entry = entries(2),
      leafIndex = 2L,
      inclusionProof = proof,
      checkpointNote = CheckpointNote.render(cp),
      rfc3161Tst = Some(tsa.token(ProofBundleCodec.timestampImprint(cp)))
    )
    (cp, ProofBundleCodec.render(bundle))

  private def verified(
      json: String = bundleJson,
      witnesses: Seq[TrustedWitness] = Nil,
      threshold: Int = 0,
      tsaCert: Option[java.security.cert.X509Certificate] = None
  ) = BundleVerifier.verify(json, attestor.publicKey, witnesses, threshold, tsaCert)

  test("verifies fully offline: signature + inclusion, token untouched without a TSA cert") {
    val report = verified().fold(e => fail(s"verify: $e"), identity)
    assertEquals(report.leafIndex, 2L)
    assertEquals(report.checkpoint.treeSize, 5L)
    assertEquals(report.timestamp.map(_.signerVerified), Some(false))
  }

  test("verifies the RFC 3161 token against the TSA certificate (Phase 4 done bar)") {
    val report =
      verified(tsaCert = Some(tsa.certificate)).fold(e => fail(s"verify: $e"), identity)
    val ts = report.timestamp.getOrElse(fail("timestamp expected"))
    assert(ts.signerVerified)
    val ageMs = math.abs(System.currentTimeMillis() - ts.genTime.toEpochMilli)
    assert(ageMs < 5 * 60 * 1000L, s"genTime should be recent, was ${ts.genTime}")
  }

  test("enforces the witness policy on the embedded note") {
    val report = verified(witnesses = Seq(trustedWitness), threshold = 1)
      .fold(e => fail(s"verify: $e"), identity)
    assertEquals(report.cosigners, Set(witnessName))
  }

  test("fails the witness policy when the trusted witness never cosigned") {
    val stranger = TrustedWitness(
      "test.merklon/stranger",
      KeyPairGenerator.getInstance("Ed25519").generateKeyPair().getPublic.getEncoded.takeRight(32)
    )
    verified(witnesses = Seq(stranger), threshold = 1) match
      case Left(err) => assert(err.contains("witness policy"), err)
      case Right(_)  => fail("must fail: no valid cosignature from the trusted witness")
  }

  test("rejects a tampered entry (inclusion proof mismatch)") {
    val tampered = bundleJson.replace(
      java.util.Base64.getEncoder.encodeToString(entries(2)),
      java.util.Base64.getEncoder.encodeToString("entry-X".getBytes("UTF-8"))
    )
    verified(json = tampered) match
      case Left(err) => assert(err.contains("inclusion proof"), err)
      case Right(_)  => fail("must fail: entry bytes were tampered")
  }

  test("rejects a bundle signed by an unknown log key") {
    val otherKey = CheckpointAttestor.generateEd25519(origin).publicKey
    BundleVerifier.verify(bundleJson, otherKey) match
      case Left(err) => assert(err.contains("checkpoint signature"), err)
      case Right(_)  => fail("must fail: wrong log key")
  }

  test("rejects a token that covers a different checkpoint (imprint mismatch)") {
    val wrongImprint = java.security.MessageDigest
      .getInstance("SHA-256")
      .digest("something else entirely".getBytes("UTF-8"))
    val bundle = ProofBundleCodec.parse(bundleJson).toOption.get
    val swapped = bundle.copy(rfc3161Tst = Some(tsa.token(wrongImprint)))
    verified(json = ProofBundleCodec.render(swapped), tsaCert = Some(tsa.certificate)) match
      case Left(err) => assert(err.contains("imprint mismatch"), err)
      case Right(_)  => fail("must fail: token covers a different message")
  }

  test("rejects a token when verified against the wrong TSA certificate") {
    verified(tsaCert = Some(TestTsa("CN=some other TSA").certificate)) match
      case Left(err) => assert(err.contains("timestamp token invalid"), err)
      case Right(_)  => fail("must fail: token signer is not the supplied TSA")
  }

  test("fails closed when a TSA cert is supplied but the bundle has no token") {
    val bundle = ProofBundleCodec.parse(bundleJson).toOption.get
    val stripped = ProofBundleCodec.render(bundle.copy(rfc3161Tst = None))
    verified(json = stripped, tsaCert = Some(tsa.certificate)) match
      case Left(err) => assert(err.contains("no timestamp token"), err)
      case Right(_)  => fail("must fail: TSA verification was requested but token is absent")
  }

  test("structured-event codec: log hashes the canonical form and the verifier matches it") {
    val storage = InMemoryStorageBackend()
    val seq = Sequencer(origin, storage, attestor, LeafCodec.StructuredEventJsonV1)
    // Deliberately non-canonical on the wire: odd order + whitespace.
    val submitted = """{ "time": 5, "source": "s", "action": "login", "actor": "alice" }"""
    seq.append(submitted.getBytes("UTF-8"))
    val cp = seq.publishCheckpoint()
    val proof = MerkleTree.inclusionProofFromHashes(0, storage.leafHashes(0L, 1L).toList)
    val json = ProofBundleCodec.render(
      ProofBundle(submitted.getBytes("UTF-8"), 0L, proof, CheckpointNote.render(cp), None)
    )
    val report = BundleVerifier
      .verify(json, attestor.publicKey, codec = LeafCodec.StructuredEventJsonV1)
      .fold(e => fail(s"verify with matching codec: $e"), identity)
    assertEquals(report.leafIndex, 0L)
    // The wrong codec recomputes a different leaf hash and must fail.
    BundleVerifier.verify(json, attestor.publicKey) match
      case Left(err) => assert(err.contains("inclusion proof"), err)
      case Right(_)  => fail("identity codec must not verify a structured-event log")
  }

  test("rejects an out-of-range leaf index") {
    val bundle = ProofBundleCodec.parse(bundleJson).toOption.get
    val oob = ProofBundleCodec.render(bundle.copy(leafIndex = 5L))
    verified(json = oob) match
      case Left(err) => assert(err.contains("out of range"), err)
      case Right(_)  => fail("must fail: leaf index beyond tree size")
  }
