// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon

import java.security.{KeyFactory, Signature as JSignature}
import java.security.spec.X509EncodedKeySpec
import java.util.Arrays

class SequencerSuite extends munit.FunSuite:

  private def pubKeyFromRaw(raw: Array[Byte]): java.security.PublicKey =
    val header = Array(
      0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
    ).map(_.toByte)
    KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(header ++ raw))

  private def freshSeq(): (InMemoryStorageBackend, CheckpointAttestor, Sequencer) =
    val storage = InMemoryStorageBackend()
    val attestor = CheckpointAttestor.generateEd25519("test.merklon/log")
    val seq = Sequencer("test.merklon/log", storage, attestor)
    (storage, attestor, seq)

  test("append returns sequential 0-based indices") {
    val (_, _, seq) = freshSeq()
    assertEquals(seq.append("a".getBytes), 0L)
    assertEquals(seq.append("b".getBytes), 1L)
    assertEquals(seq.append("c".getBytes), 2L)
  }

  test("publishCheckpoint treeSize equals number of appended entries") {
    val (_, _, seq) = freshSeq()
    Seq("x", "y", "z").foreach(e => seq.append(e.getBytes))
    assertEquals(seq.publishCheckpoint().treeSize, 3L)
  }

  test("checkpoint root matches MerkleTree.root of the same entries") {
    val (_, _, seq) = freshSeq()
    val entries = List("alpha", "beta", "gamma").map(_.getBytes)
    entries.foreach(seq.append)
    val cp = seq.publishCheckpoint()
    val expected = MerkleTree.root(entries)
    assert(Arrays.equals(cp.rootHash, expected))
  }

  test("rootFromHashes and root agree on the same entries") {
    val entries = List("a", "b", "c", "d").map(_.getBytes)
    val fromData = MerkleTree.root(entries)
    val fromHash = MerkleTree.rootFromHashes(entries.map(MerkleTree.leafHash))
    assert(Arrays.equals(fromData, fromHash))
  }

  test("checkpoint signature verifies with attestor public key") {
    val (_, attestor, seq) = freshSeq()
    seq.append("entry".getBytes)
    val cp = seq.publishCheckpoint()
    val noteSig = cp.signatures.head
    val body = CheckpointNote.noteBody(cp).getBytes("UTF-8")
    val jSig = JSignature.getInstance("Ed25519")
    jSig.initVerify(pubKeyFromRaw(attestor.publicKey))
    jSig.update(body)
    assert(jSig.verify(noteSig.sig))
  }

  test("sequential checkpoints are consistency-proof valid") {
    val (storage, _, seq) = freshSeq()
    (1 to 5).foreach(i => seq.append(s"entry-$i".getBytes))
    val cp1 = seq.publishCheckpoint()
    (6 to 8).foreach(i => seq.append(s"entry-$i".getBytes))
    val cp2 = seq.publishCheckpoint()
    val hashes = storage.leafHashes(0L, cp2.treeSize).toList
    val proof = MerkleTree.consistencyProofFromHashes(cp1.treeSize.toInt, hashes)
    assert(
      MerkleTree.verifyConsistency(
        cp1.treeSize.toInt,
        cp2.treeSize.toInt,
        cp1.rootHash,
        cp2.rootHash,
        proof
      )
    )
  }

  test("sequencer reconstructs correct state after restart (new instance, same storage)") {
    val storage = InMemoryStorageBackend()
    val attestor = CheckpointAttestor.generateEd25519("test.merklon/log")
    val seq1 = Sequencer("test.merklon/log", storage, attestor)
    (1 to 4).foreach(i => seq1.append(s"e$i".getBytes))
    val cp1 = seq1.publishCheckpoint()

    val seq2 = Sequencer("test.merklon/log", storage, attestor)
    assertEquals(seq2.append("e5".getBytes), 4L)
    val cp2 = seq2.publishCheckpoint()
    assertEquals(cp2.treeSize, 5L)

    val hashes = storage.leafHashes(0L, cp2.treeSize).toList
    val proof = MerkleTree.consistencyProofFromHashes(cp1.treeSize.toInt, hashes)
    assert(
      MerkleTree.verifyConsistency(
        cp1.treeSize.toInt,
        cp2.treeSize.toInt,
        cp1.rootHash,
        cp2.rootHash,
        proof
      )
    )
  }

  test("latestCheckpoint is empty before any publish, then returns last published") {
    val (_, _, seq) = freshSeq()
    assert(seq.latestCheckpoint().isEmpty)
    seq.append("x".getBytes)
    seq.publishCheckpoint()
    seq.append("y".getBytes)
    seq.publishCheckpoint()
    assertEquals(seq.latestCheckpoint().map(_.treeSize), Some(2L))
  }

  test("inclusionProofFromHashes verifies against checkpoint root") {
    val (storage, _, seq) = freshSeq()
    val entries = (0 until 8).map(i => s"leaf-$i".getBytes).toList
    entries.foreach(seq.append)
    val cp = seq.publishCheckpoint()
    val hashes = storage.leafHashes(0L, cp.treeSize).toList
    for idx <- 0 until 8 do
      val lh = hashes(idx)
      val proof = MerkleTree.inclusionProofFromHashes(idx, hashes)
      assert(
        MerkleTree.verifyInclusion(idx, cp.treeSize.toInt, lh, proof, cp.rootHash),
        s"inclusion proof for leaf $idx must verify"
      )
  }
