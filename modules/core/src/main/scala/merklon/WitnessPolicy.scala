// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon

/** A witness a client chooses to trust: its signed-note key name and raw Ed25519 public key. */
final case class TrustedWitness(name: String, publicKey: Array[Byte])

/** Client-side N-of-M cosignature policy (Phase 3).
  *
  * A checkpoint satisfies the policy when at least `threshold` *distinct* trusted witnesses have a
  * valid Ed25519 signature over its note body. With N honest-majority witnesses required, a log
  * cannot present diverging histories (split view) without collusion of N witnesses.
  */
object WitnessPolicy:

  /** Names of the distinct trusted witnesses with a valid signature on `cp`. */
  def validCosigners(cp: Checkpoint, trusted: Seq[TrustedWitness]): Set[String] =
    val body = CheckpointNote.noteBody(cp).getBytes("UTF-8")
    val byKeyName = trusted.groupBy(_.name)
    cp.signatures
      .flatMap { sig =>
        byKeyName.getOrElse(sig.keyName, Nil).find { w =>
          // Match the signature line to the witness key via the signed-note key ID, then verify.
          java.util.Arrays.equals(sig.keyId, CheckpointNote.keyId(w.name, w.publicKey)) &&
          Ed25519.verify(w.publicKey, body, sig.sig)
        }
      }
      .map(_.name)
      .toSet

  /** True when at least `threshold` distinct trusted witnesses cosigned `cp`. */
  def satisfied(cp: Checkpoint, trusted: Seq[TrustedWitness], threshold: Int): Boolean =
    require(threshold >= 0, s"threshold must be >= 0, got $threshold")
    validCosigners(cp, trusted).size >= threshold
