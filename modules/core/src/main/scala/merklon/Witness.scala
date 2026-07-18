// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon

import java.security.KeyPair
import java.util.Arrays

/** Why a witness refused to cosign. `SplitView` and `InconsistentHistory` carry both signed
  * checkpoints — together they are transferable cryptographic evidence of log misbehavior (two
  * conflicting statements signed by the same log key).
  */
enum WitnessRefusal:
  /** The checkpoint is not for the origin this witness watches. */
  case WrongOrigin(expected: String, presented: Checkpoint)

  /** No signature on the checkpoint verifies under the log's public key. */
  case InvalidLogSignature(presented: Checkpoint)

  /** Same tree size as a previously cosigned checkpoint, but a different root — the log is showing
    * different histories to different observers (equivocation).
    */
  case SplitView(cosigned: Checkpoint, presented: Checkpoint)

  /** The supplied consistency proof does not prove the cosigned checkpoint is a prefix of the
    * presented one (history rewrite), or the presented tree is smaller than one already cosigned.
    */
  case InconsistentHistory(cosigned: Checkpoint, presented: Checkpoint)

  /** The checkpoint or submission violates a tlog-witness protocol rule that carries no misbehavior
    * evidence: a size-zero checkpoint whose root is not the empty-tree root, or a consistency proof
    * supplied where none is possible (nothing cosigned yet). HTTP 422.
    */
  case InvalidCheckpoint(reason: String, presented: Checkpoint)

/** An independent witness (Phase 3, c2sp.org/tlog-witness model): before cosigning a checkpoint it
  * verifies (1) the log's signature and (2) that the new tree is an append-only extension of the
  * last checkpoint it cosigned. A client that requires N witness cosignatures is protected from
  * split-view attacks by any N-1 colluding witnesses + the log.
  *
  * Cosignatures use the c2sp.org/tlog-cosignature "cosignature/v1" format ([[CosignatureV1]]).
  *
  * The first observed checkpoint is cosigned on trust (trust-on-first-use) — a witness attests to
  * *consistency over time*, which begins at its first observation.
  *
  * State (the last cosigned checkpoint) lives behind [[WitnessStateStore]]; pass a durable store to
  * survive restarts — the in-memory default is for tests and embedding.
  */
final class Witness(
    val name: String,
    keyPair: KeyPair,
    origin: String,
    logPublicKey: Array[Byte],
    store: WitnessStateStore = InMemoryWitnessStateStore(),
    clock: () => Long = () => System.currentTimeMillis() / 1000L
):
  val publicKey: Array[Byte] = keyPair.getPublic.getEncoded.takeRight(32)

  /** The last checkpoint this witness cosigned, if any. */
  def latestCosigned: Option[Checkpoint] = synchronized(store.latest(origin))

  /** Verify `cp` (log signature + append-only consistency with the last cosigned checkpoint via
    * `consistencyProof`) and return this witness's cosignature, or the reason for refusal.
    *
    * `consistencyProof` is the RFC 9162 proof from the last cosigned size to `cp.treeSize`. It MUST
    * be empty for the first observation and when extending from size zero (the empty tree is a
    * prefix of every tree, so no proof is possible) — per c2sp.org/tlog-witness a non-empty proof
    * there is refused, not ignored.
    *
    * The log's signature lines are validated strictly (c2sp.org/signed-note): any line whose key ID
    * matches the trusted key under its own claimed name MUST verify — one failing such line
    * invalidates the whole note.
    */
  def observe(
      cp: Checkpoint,
      consistencyProof: List[Array[Byte]]
  ): Either[WitnessRefusal, NoteSignature] = synchronized {
    if cp.origin != origin then Left(WitnessRefusal.WrongOrigin(origin, cp))
    else if !CheckpointNote.verifyLogSignatures(cp, logPublicKey) then
      Left(WitnessRefusal.InvalidLogSignature(cp))
    else if cp.treeSize == 0L && !Arrays.equals(cp.rootHash, MerkleTree.emptyRoot) then
      Left(
        WitnessRefusal.InvalidCheckpoint(
          "a size-zero checkpoint must carry the empty-tree root",
          cp
        )
      )
    else
      store.latest(origin) match
        case None =>
          if consistencyProof.nonEmpty then
            Left(
              WitnessRefusal.InvalidCheckpoint(
                "consistency proof must be empty when nothing has been cosigned yet",
                cp
              )
            )
          else Right(cosign(cp))
        case Some(prev) =>
          if cp.treeSize < prev.treeSize then Left(WitnessRefusal.InconsistentHistory(prev, cp))
          else if cp.treeSize == prev.treeSize then
            if Arrays.equals(cp.rootHash, prev.rootHash) then Right(cosign(cp))
            else Left(WitnessRefusal.SplitView(prev, cp))
          else if prev.treeSize == 0L && consistencyProof.nonEmpty then
            Left(
              WitnessRefusal.InvalidCheckpoint(
                "consistency proof must be empty when extending from size zero",
                cp
              )
            )
          else if MerkleTree.verifyConsistency(
              prev.treeSize.toInt,
              cp.treeSize.toInt,
              prev.rootHash,
              cp.rootHash,
              consistencyProof
            )
          then Right(cosign(cp))
          else Left(WitnessRefusal.InconsistentHistory(prev, cp))
  }

  private def cosign(cp: Checkpoint): NoteSignature =
    val sig = CosignatureV1.sign(name, keyPair, CheckpointNote.noteBody(cp), clock())
    // Store the checkpoint with the cosignature appended: the stored note is then directly
    // servable (monitoring endpoint) and is self-contained split-view evidence.
    store.save(cp.copy(signatures = cp.signatures :+ sig))
    sig
