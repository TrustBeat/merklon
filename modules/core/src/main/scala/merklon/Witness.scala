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

/** An independent witness (Phase 3, transparency.dev model): before cosigning a checkpoint it
  * verifies (1) the log's signature and (2) that the new tree is an append-only extension of the
  * last checkpoint it cosigned. A client that requires N witness cosignatures is protected from
  * split-view attacks by any N-1 colluding witnesses + the log.
  *
  * The first observed checkpoint is cosigned on trust (trust-on-first-use) — a witness attests to
  * *consistency over time*, which begins at its first observation.
  *
  * State is one checkpoint deep and in-memory; durable witness state is an operational concern
  * layered on top (same seam as `StorageBackend` for the log).
  */
final class Witness(
    val name: String,
    keyPair: KeyPair,
    origin: String,
    logPublicKey: Array[Byte]
):
  private val attestor = CheckpointAttestor.ed25519(name, keyPair)
  private var cosigned: Option[Checkpoint] = None

  def publicKey: Array[Byte] = attestor.publicKey

  /** The last checkpoint this witness cosigned, if any. */
  def latestCosigned: Option[Checkpoint] = synchronized(cosigned)

  /** Verify `cp` (log signature + append-only consistency with the last cosigned checkpoint via
    * `consistencyProof`) and return this witness's cosignature, or the reason for refusal.
    *
    * `consistencyProof` is the RFC 9162 proof from the last cosigned size to `cp.treeSize`; it is
    * ignored for the first observation and when the size is unchanged.
    */
  def observe(
      cp: Checkpoint,
      consistencyProof: List[Array[Byte]]
  ): Either[WitnessRefusal, NoteSignature] = synchronized {
    if cp.origin != origin then Left(WitnessRefusal.WrongOrigin(origin, cp))
    else if !hasValidLogSignature(cp) then Left(WitnessRefusal.InvalidLogSignature(cp))
    else
      cosigned match
        case None => Right(cosign(cp))
        case Some(prev) =>
          if cp.treeSize < prev.treeSize then Left(WitnessRefusal.InconsistentHistory(prev, cp))
          else if cp.treeSize == prev.treeSize then
            if Arrays.equals(cp.rootHash, prev.rootHash) then Right(cosign(cp))
            else Left(WitnessRefusal.SplitView(prev, cp))
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

  private def hasValidLogSignature(cp: Checkpoint): Boolean =
    val body = CheckpointNote.noteBody(cp).getBytes("UTF-8")
    cp.signatures.exists(s => Ed25519.verify(logPublicKey, body, s.sig))

  private def cosign(cp: Checkpoint): NoteSignature =
    val body = CheckpointNote.noteBody(cp).getBytes("UTF-8")
    val sig = attestor.sign(body)
    cosigned = Some(cp)
    NoteSignature(attestor.keyName, attestor.keyId.clone(), sig)
