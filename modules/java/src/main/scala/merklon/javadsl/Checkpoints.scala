// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon.javadsl

import merklon.{Checkpoint, CheckpointNote}

/** A parsed checkpoint (signed note) with Java-friendly accessors. Obtain via
  * [[Checkpoints.parse]]; the original note text is retained for signature verification.
  */
final class CheckpointInfo private[javadsl] (cp: Checkpoint):
  /** The log identity from the note's origin line. */
  def origin(): String = cp.origin

  /** Number of leaves in the checkpointed tree. */
  def treeSize(): Long = cp.treeSize

  /** The 32-byte RFC 9162 Merkle Tree Hash this checkpoint commits to (defensive copy). */
  def rootHash(): Array[Byte] = cp.rootHash.clone()

  /** Lowercase hex of [[rootHash]]. */
  def rootHashHex(): String = merklon.MerkleTree.toHex(cp.rootHash)

  private[javadsl] def underlying: Checkpoint = cp

/** Java-friendly facade over checkpoint (signed note) parsing and verification.
  *
  * A checkpoint is the log's signed commitment to `(tree_size, root_hash)` in the
  * c2sp.org/tlog-checkpoint + signed-note wire format; see SPEC.md §3.
  */
object Checkpoints:

  /** Parse a checkpoint note (the `text/plain` body of `GET /checkpoint`).
    *
    * @throws IllegalArgumentException
    *   if the note is not a well-formed signed checkpoint
    */
  def parse(noteText: String): CheckpointInfo =
    CheckpointNote.parse(noteText) match
      case Right(cp) => CheckpointInfo(cp)
      case Left(err) => throw IllegalArgumentException(s"invalid checkpoint note: $err")

  /** Verify the log's signature on a checkpoint note under the strict signed-note rule: at least
    * one signature line from the trusted key must verify, and any line claiming the trusted key
    * that fails to verify rejects the whole note.
    *
    * @param rawEd25519PublicKey
    *   the log's raw 32-byte Ed25519 public key (not DER-wrapped)
    */
  def verifySignature(noteText: String, rawEd25519PublicKey: Array[Byte]): Boolean =
    CheckpointNote.parse(noteText) match
      case Right(cp) => CheckpointNote.verifyLogSignatures(cp, rawEd25519PublicKey)
      case Left(_)   => false
