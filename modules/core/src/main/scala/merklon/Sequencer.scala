// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon

/** Integrates entries into the Merkle log and publishes signed checkpoints.
  *
  * append adds an entry to storage; publishCheckpoint takes a consistent snapshot of the current
  * tree, computes the root, signs a checkpoint note, persists it, and returns it. Time-based
  * batching cadence is wired up by the outer layer (Phase 2, ZIO scheduler).
  */
final class Sequencer(
    origin: String,
    storage: StorageBackend,
    attestor: CheckpointAttestor,
    codec: LeafCodec = LeafCodec.Identity,
    authorizer: AppendAuthorizer = AppendAuthorizer.NoOp
):
  /** Encode, hash, and append an entry; returns its 0-based leaf index. */
  def append(data: Array[Byte]): Long =
    require(authorizer.authorize(data), "entry rejected by authorizer")
    val canonical = codec.encode(data)
    val lh = MerkleTree.leafHash(canonical)
    storage.append(lh, data)

  /** Snapshot the current tree, compute its root, sign and persist a checkpoint.
    *
    * The snapshot is taken atomically by reading storage.size once, then fetching exactly that many
    * leaf hashes. Concurrent appends after the size read are not included — they will appear in the
    * next checkpoint.
    */
  def publishCheckpoint(): Checkpoint =
    val n = storage.size
    val hashes = storage.leafHashes(0L, n).toList
    val rootHash = MerkleTree.rootFromHashes(hashes)
    val body = CheckpointNote.noteBody(origin, n, rootHash)
    val sig = attestor.sign(body.getBytes("UTF-8"))
    val noteSig = NoteSignature(attestor.keyName, attestor.keyId.clone(), sig)
    val cp = Checkpoint(origin, n, rootHash, System.currentTimeMillis(), Vector(noteSig))
    storage.saveCheckpoint(cp)
    cp

  def latestCheckpoint(): Option[Checkpoint] = storage.latestCheckpoint()
