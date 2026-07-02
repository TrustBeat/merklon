// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon.verifier

import merklon.{Checkpoint, CheckpointNote, Ed25519, MerkleTree}

/** Pure independent verifier — no server trust required.
  *
  * All operations recompute hashes locally from the proof and the trusted checkpoint root. A lying
  * server cannot produce a valid proof without being detected.
  */
object LogVerifier:

  /** Verify that at least one signature in `cp` was produced by `rawPublicKey` over the note body.
    *
    * @param rawPublicKey
    *   raw 32-byte Ed25519 public key (not DER-wrapped)
    */
  def verifyCheckpointSignature(cp: Checkpoint, rawPublicKey: Array[Byte]): Boolean =
    val body = CheckpointNote.noteBody(cp).getBytes("UTF-8")
    cp.signatures.exists(sig => Ed25519.verify(rawPublicKey, body, sig.sig))

  /** Verify that `entry` (the raw submitted bytes) is included at `proof.leafIndex` in `cp`. */
  def verifyInclusion(entry: Array[Byte], proof: InclusionProof, cp: Checkpoint): Boolean =
    MerkleTree.verifyInclusion(
      leafIndex = proof.leafIndex.toInt,
      treeSize = proof.treeSize.toInt,
      leafHash = MerkleTree.leafHash(entry),
      proof = proof.auditPath,
      expectedRoot = cp.rootHash
    )

  /** Verify that `older` is an append-only prefix of `newer` according to `proof`. */
  def verifyConsistency(older: Checkpoint, newer: Checkpoint, proof: ConsistencyProof): Boolean =
    MerkleTree.verifyConsistency(
      first = older.treeSize.toInt,
      second = newer.treeSize.toInt,
      firstRoot = older.rootHash,
      secondRoot = newer.rootHash,
      proof = proof.proofPath
    )
