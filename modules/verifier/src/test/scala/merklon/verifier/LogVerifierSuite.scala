// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon.verifier

import merklon.*

class LogVerifierSuite extends munit.FunSuite:

  private def freshLog(
      entries: List[String]
  ): (InMemoryStorageBackend, CheckpointAttestor, Checkpoint) =
    val storage = InMemoryStorageBackend()
    val attestor = CheckpointAttestor.generateEd25519("test.merklon/log")
    val seq = Sequencer("test.merklon/log", storage, attestor)
    entries.foreach(e => seq.append(e.getBytes("UTF-8")))
    (storage, attestor, seq.publishCheckpoint())

  test("verifyCheckpointSignature passes for a valid signature") {
    val (_, attestor, cp) = freshLog(List("a", "b", "c"))
    assert(LogVerifier.verifyCheckpointSignature(cp, attestor.publicKey))
  }

  test("verifyCheckpointSignature fails for wrong public key") {
    val (_, _, cp) = freshLog(List("a"))
    val wrongKey = CheckpointAttestor.generateEd25519("other").publicKey
    assert(!LogVerifier.verifyCheckpointSignature(cp, wrongKey))
  }

  test("verifyCheckpointSignature fails for tampered tree_size") {
    val (_, attestor, cp) = freshLog(List("a"))
    val tampered = cp.copy(treeSize = cp.treeSize + 1)
    assert(!LogVerifier.verifyCheckpointSignature(tampered, attestor.publicKey))
  }

  test("verifyCheckpointSignature fails for truncated public key bytes") {
    val (_, attestor, cp) = freshLog(List("a"))
    assert(!LogVerifier.verifyCheckpointSignature(cp, attestor.publicKey.take(16)))
  }

  test("verifyInclusion passes for every leaf in an 8-entry tree") {
    val entries = List("alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta")
    val (storage, _, cp) = freshLog(entries)
    val hashes = storage.leafHashes(0L, cp.treeSize).toList
    entries.zipWithIndex.foreach { (entry, idx) =>
      val proof =
        InclusionProof(idx.toLong, cp.treeSize, MerkleTree.inclusionProofFromHashes(idx, hashes))
      assert(LogVerifier.verifyInclusion(entry.getBytes("UTF-8"), proof, cp), s"index $idx failed")
    }
  }

  test("verifyInclusion fails for wrong entry bytes") {
    val (storage, _, cp) = freshLog(List("alpha"))
    val hashes = storage.leafHashes(0L, cp.treeSize).toList
    val proof = InclusionProof(0L, cp.treeSize, MerkleTree.inclusionProofFromHashes(0, hashes))
    assert(!LogVerifier.verifyInclusion("wrong".getBytes("UTF-8"), proof, cp))
  }

  test("verifyInclusion fails for wrong audit_path") {
    val (storage, _, cp) = freshLog(List("a", "b"))
    val hashes = storage.leafHashes(0L, cp.treeSize).toList
    val proof = InclusionProof(0L, cp.treeSize, MerkleTree.inclusionProofFromHashes(0, hashes))
    val corruptedPath =
      proof.copy(auditPath = proof.auditPath.map(h => h.map(b => (b ^ 0xff).toByte)))
    assert(!LogVerifier.verifyInclusion("a".getBytes("UTF-8"), corruptedPath, cp))
  }

  test("verifyConsistency passes for consecutive checkpoints") {
    val storage = InMemoryStorageBackend()
    val attestor = CheckpointAttestor.generateEd25519("test.merklon/log")
    val seq = Sequencer("test.merklon/log", storage, attestor)
    List("a", "b", "c").foreach(e => seq.append(e.getBytes("UTF-8")))
    val cp1 = seq.publishCheckpoint()
    List("d", "e").foreach(e => seq.append(e.getBytes("UTF-8")))
    val cp2 = seq.publishCheckpoint()
    val hashes = storage.leafHashes(0L, cp2.treeSize).toList
    val proof = ConsistencyProof(
      first = cp1.treeSize,
      second = cp2.treeSize,
      proofPath = MerkleTree.consistencyProofFromHashes(cp1.treeSize.toInt, hashes)
    )
    assert(LogVerifier.verifyConsistency(cp1, cp2, proof))
  }

  test("verifyConsistency fails for checkpoints from unrelated logs") {
    val (_, _, cp1) = freshLog(List("a", "b", "c"))
    val (_, _, cp2) = freshLog(List("x", "y", "z", "w", "v")) // different log
    val fakeProof = ConsistencyProof(3L, 5L, Nil)
    assert(!LogVerifier.verifyConsistency(cp1, cp2, fakeProof))
  }
