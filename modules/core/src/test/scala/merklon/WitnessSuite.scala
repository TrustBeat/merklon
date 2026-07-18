// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon

import java.security.{KeyPair, KeyPairGenerator}

/** Phase 3 witnessing: cosigning, N-of-M policy, and — the DESIGN.md "done" criterion — detection
  * of a deliberately equivocating log (split view) and of history rewrites.
  */
class WitnessSuite extends munit.FunSuite:

  private val origin = "merklon.test/witness"

  private def keyPair(): KeyPair =
    KeyPairGenerator.getInstance("Ed25519").generateKeyPair()

  /** A tiny in-test log operator: appends entries and produces signed checkpoints + proofs. */
  private final class TestLog(val attestor: CheckpointAttestor):
    private var entries = List.empty[Array[Byte]]

    def append(data: String*): Unit =
      entries = entries ++ data.map(_.getBytes("UTF-8"))

    def leafHashes: List[Array[Byte]] = entries.map(MerkleTree.leafHash)

    def checkpoint(): Checkpoint =
      val root = MerkleTree.rootFromHashes(leafHashes)
      sign(origin, entries.size.toLong, root)

    def consistencyProofFrom(first: Long): List[Array[Byte]] =
      MerkleTree.consistencyProofFromHashes(first.toInt, leafHashes)

    private def sign(o: String, size: Long, root: Array[Byte]): Checkpoint =
      val body = CheckpointNote.noteBody(o, size, root).getBytes("UTF-8")
      val sig = NoteSignature(attestor.keyName, attestor.keyId, attestor.sign(body))
      Checkpoint(o, size, root, System.currentTimeMillis(), Vector(sig))

  private def freshLog(): TestLog =
    TestLog(CheckpointAttestor.generateEd25519(origin))

  test("witness cosigns first checkpoint (TOFU) and consistent extensions") {
    val log = freshLog()
    val witness = Witness("witness.test/w1", keyPair(), origin, log.attestor.publicKey)

    log.append("a", "b", "c")
    val cp1 = log.checkpoint()
    val sig1 = witness.observe(cp1, Nil)
    assert(sig1.isRight, s"first observation must cosign, got $sig1")

    log.append("d", "e")
    val cp2 = log.checkpoint()
    val sig2 = witness.observe(cp2, log.consistencyProofFrom(cp1.treeSize))
    assert(sig2.isRight, s"consistent extension must cosign, got $sig2")

    // The cosignature is a valid cosignature/v1 over the checkpoint body.
    val body = CheckpointNote.noteBody(cp2)
    assert(CosignatureV1.verify(witness.name, witness.publicKey, body, sig2.toOption.get))
    assertEquals(witness.latestCosigned.map(_.treeSize), Some(cp2.treeSize))
  }

  test("witness state survives a restart via a shared durable store") {
    val log = freshLog()
    val store = InMemoryWitnessStateStore()
    val wKeys = keyPair()
    val w1 = Witness("witness.test/w1", wKeys, origin, log.attestor.publicKey, store)
    log.append("a", "b", "c", "d")
    assert(w1.observe(log.checkpoint(), Nil).isRight)

    // "Restart": a fresh Witness over the same store must keep enforcing consistency,
    // not fall back to trust-on-first-use.
    val w2 = Witness("witness.test/w1", wKeys, origin, log.attestor.publicKey, store)
    assertEquals(w2.latestCosigned.map(_.treeSize), Some(4L))
    val forged = TestLog(log.attestor)
    forged.append("a", "b", "X", "d")
    assert(w2.observe(forged.checkpoint(), Nil) match
      case Left(WitnessRefusal.SplitView(_, _)) => true
      case _                                    => false
    )
  }

  test("witness re-cosigns an identical checkpoint at the same size") {
    val log = freshLog()
    val witness = Witness("witness.test/w1", keyPair(), origin, log.attestor.publicKey)
    log.append("a", "b")
    val cp = log.checkpoint()
    assert(witness.observe(cp, Nil).isRight)
    assert(witness.observe(log.checkpoint(), Nil).isRight) // same size, same root
  }

  test("split view is detected: same size, different root refused with evidence") {
    // One log key, two divergent histories — a deliberately equivocating operator.
    val attestor = CheckpointAttestor.generateEd25519(origin)
    val honest = TestLog(attestor)
    val forged = TestLog(attestor)
    honest.append("a", "b", "c", "d")
    forged.append("a", "b", "X", "d") // rewrites entry 2, same size

    val witness = Witness("witness.test/w1", keyPair(), origin, attestor.publicKey)
    assert(witness.observe(honest.checkpoint(), Nil).isRight)

    witness.observe(forged.checkpoint(), Nil) match
      case Left(WitnessRefusal.SplitView(cosigned, presented)) =>
        // The evidence is transferable: two same-size, different-root checkpoints, both
        // carrying valid signatures from the same log key.
        assertEquals(cosigned.treeSize, presented.treeSize)
        assertNotEquals(MerkleTree.toHex(cosigned.rootHash), MerkleTree.toHex(presented.rootHash))
        val cBody = CheckpointNote.noteBody(cosigned).getBytes("UTF-8")
        val pBody = CheckpointNote.noteBody(presented).getBytes("UTF-8")
        assert(Ed25519.verify(attestor.publicKey, cBody, cosigned.signatures.head.sig))
        assert(Ed25519.verify(attestor.publicKey, pBody, presented.signatures.head.sig))
      case other => fail(s"expected SplitView refusal, got $other")

    // The witness's trusted view is unchanged by the refused checkpoint.
    assertEquals(
      witness.latestCosigned.map(c => MerkleTree.toHex(c.rootHash)),
      Some(MerkleTree.toHex(honest.checkpoint().rootHash))
    )
  }

  test("history rewrite is detected: larger tree that is not an extension is refused") {
    val attestor = CheckpointAttestor.generateEd25519(origin)
    val honest = TestLog(attestor)
    honest.append("a", "b", "c", "d")
    val witness = Witness("witness.test/w1", keyPair(), origin, attestor.publicKey)
    assert(witness.observe(honest.checkpoint(), Nil).isRight)

    // The operator rewrites history and keeps appending: entry 1 changed, size grows to 6.
    val forged = TestLog(attestor)
    forged.append("a", "TAMPERED", "c", "d", "e", "f")
    val refusal = witness.observe(forged.checkpoint(), forged.consistencyProofFrom(4L))
    refusal match
      case Left(WitnessRefusal.InconsistentHistory(cosigned, presented)) =>
        assertEquals(cosigned.treeSize, 4L)
        assertEquals(presented.treeSize, 6L)
      case other => fail(s"expected InconsistentHistory refusal, got $other")
  }

  test("shrinking tree is refused") {
    val log = freshLog()
    val witness = Witness("witness.test/w1", keyPair(), origin, log.attestor.publicKey)
    log.append("a", "b", "c")
    assert(witness.observe(log.checkpoint(), Nil).isRight)
    val shrunk = TestLog(log.attestor)
    shrunk.append("a", "b")
    assert(witness.observe(shrunk.checkpoint(), Nil) match
      case Left(WitnessRefusal.InconsistentHistory(_, _)) => true
      case _                                              => false
    )
  }

  test("size-zero checkpoint must carry the empty-tree root (tlog-witness)") {
    val attestor = CheckpointAttestor.generateEd25519(origin)
    def signed(root: Array[Byte]): Checkpoint =
      val body = CheckpointNote.noteBody(origin, 0L, root).getBytes("UTF-8")
      val sig = NoteSignature(attestor.keyName, attestor.keyId, attestor.sign(body))
      Checkpoint(origin, 0L, root, 0L, Vector(sig))

    val witness = Witness("witness.test/w1", keyPair(), origin, attestor.publicKey)
    assert(witness.observe(signed(Array.fill[Byte](32)(0x42)), Nil) match
      case Left(WitnessRefusal.InvalidCheckpoint(_, _)) => true
      case _                                            => false
    )
    // With the genuine empty-tree root it is cosignable (TOFU).
    assert(witness.observe(signed(MerkleTree.emptyRoot), Nil).isRight)
  }

  test("non-empty consistency proof is refused when none is possible (tlog-witness)") {
    val log = freshLog()
    val bogusProof = List(Array.fill[Byte](32)(0x01))

    // First observation: nothing cosigned yet, so no proof can exist.
    val w1 = Witness("witness.test/w1", keyPair(), origin, log.attestor.publicKey)
    log.append("a", "b")
    assert(w1.observe(log.checkpoint(), bogusProof) match
      case Left(WitnessRefusal.InvalidCheckpoint(_, _)) => true
      case _                                            => false
    )
    assert(w1.observe(log.checkpoint(), Nil).isRight)

    // Extending from cosigned size 0: the empty tree is a prefix of every tree — no proof.
    val emptyLog = freshLog()
    val w2 = Witness("witness.test/w2", keyPair(), origin, emptyLog.attestor.publicKey)
    assert(w2.observe(emptyLog.checkpoint(), Nil).isRight) // size 0, empty root
    emptyLog.append("a", "b", "c")
    assert(w2.observe(emptyLog.checkpoint(), bogusProof) match
      case Left(WitnessRefusal.InvalidCheckpoint(_, _)) => true
      case _                                            => false
    )
    assert(w2.observe(emptyLog.checkpoint(), Nil).isRight)
  }

  test("a failing signature line matching the trusted key's name and ID poisons the note") {
    val log = freshLog()
    val witness = Witness("witness.test/w1", keyPair(), origin, log.attestor.publicKey)
    log.append("a", "b")
    val cp = log.checkpoint()

    // Valid log signature + a forged line under the SAME key name and ID: strict signed-note
    // validation must reject the whole note, even though one signature verifies.
    val forged =
      NoteSignature(log.attestor.keyName, log.attestor.keyId, Array.fill[Byte](64)(0x13))
    val poisoned = cp.copy(signatures = cp.signatures :+ forged)
    assert(witness.observe(poisoned, Nil) match
      case Left(WitnessRefusal.InvalidLogSignature(_)) => true
      case _                                           => false
    )

    // A line with the same name but a DIFFERENT key ID is an unknown key: ignored, note accepted.
    val unknownId = NoteSignature(
      log.attestor.keyName,
      Array[Byte](0x00, 0x01, 0x02, 0x03),
      Array.fill[Byte](64)(0x13)
    )
    assert(witness.observe(cp.copy(signatures = cp.signatures :+ unknownId), Nil).isRight)
  }

  test("checkpoint without a valid log signature is refused") {
    val log = freshLog()
    val witness = Witness("witness.test/w1", keyPair(), origin, log.attestor.publicKey)
    log.append("a")
    val cp = log.checkpoint()
    // Root tampered after signing → the log signature no longer covers the body.
    val tampered = cp.copy(rootHash = Array.fill[Byte](32)(0x42))
    assert(witness.observe(tampered, Nil) match
      case Left(WitnessRefusal.InvalidLogSignature(_)) => true
      case _                                           => false
    )
  }

  test("checkpoint for a different origin is refused") {
    val log = freshLog()
    val witness = Witness("witness.test/w1", keyPair(), origin, log.attestor.publicKey)
    log.append("a")
    val cp = log.checkpoint()
    val foreign = cp.copy(origin = "someone.else/log")
    assert(witness.observe(foreign, Nil) match
      case Left(WitnessRefusal.WrongOrigin(expected, _)) => expected == origin
      case _                                             => false
    )
  }

  test("N-of-M policy: satisfied only with enough distinct trusted cosigners") {
    val log = freshLog()
    val w1 = Witness("witness.test/w1", keyPair(), origin, log.attestor.publicKey)
    val w2 = Witness("witness.test/w2", keyPair(), origin, log.attestor.publicKey)
    val w3 = Witness("witness.test/w3", keyPair(), origin, log.attestor.publicKey)
    val trusted = Seq(
      TrustedWitness(w1.name, w1.publicKey),
      TrustedWitness(w2.name, w2.publicKey),
      TrustedWitness(w3.name, w3.publicKey)
    )

    log.append("a", "b")
    val cp = log.checkpoint()
    val sig1 = w1.observe(cp, Nil).toOption.get
    val sig2 = w2.observe(cp, Nil).toOption.get

    val onceCosigned = cp.copy(signatures = cp.signatures :+ sig1)
    val twiceCosigned = cp.copy(signatures = cp.signatures :+ sig1 :+ sig2)

    assert(WitnessPolicy.satisfied(twiceCosigned, trusted, threshold = 2))
    assert(!WitnessPolicy.satisfied(onceCosigned, trusted, threshold = 2))
    assertEquals(WitnessPolicy.validCosigners(twiceCosigned, trusted), Set(w1.name, w2.name))
  }

  test("N-of-M policy: duplicate and untrusted signatures do not inflate the count") {
    val log = freshLog()
    val w1 = Witness("witness.test/w1", keyPair(), origin, log.attestor.publicKey)
    val rogue = Witness("witness.test/rogue", keyPair(), origin, log.attestor.publicKey)
    val trusted = Seq(TrustedWitness(w1.name, w1.publicKey))

    log.append("a", "b")
    val cp = log.checkpoint()
    val sig1 = w1.observe(cp, Nil).toOption.get
    val rogueSig = rogue.observe(cp, Nil).toOption.get

    // Same witness twice + an untrusted cosigner: still only 1 valid distinct cosigner.
    val padded = cp.copy(signatures = cp.signatures :+ sig1 :+ sig1 :+ rogueSig)
    assertEquals(WitnessPolicy.validCosigners(padded, trusted).size, 1)
    assert(!WitnessPolicy.satisfied(padded, trusted, threshold = 2))
  }

  test("N-of-M policy: a forged signature under a trusted witness's name does not count") {
    val log = freshLog()
    val w1 = Witness("witness.test/w1", keyPair(), origin, log.attestor.publicKey)
    val trusted = Seq(TrustedWitness(w1.name, w1.publicKey))

    log.append("a")
    val cp = log.checkpoint()
    // An attacker who doesn't hold w1's key fabricates a cosignature line with w1's name and ID.
    val forged = NoteSignature(
      w1.name,
      CosignatureV1.keyId(w1.name, w1.publicKey),
      Array.fill[Byte](72)(0x13)
    )
    val cpForged = cp.copy(signatures = cp.signatures :+ forged)
    assert(!WitnessPolicy.satisfied(cpForged, trusted, threshold = 1))
  }
