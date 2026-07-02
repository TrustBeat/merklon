// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon

/** A witness a client chooses to trust: its signed-note key name and raw Ed25519 public key. */
final case class TrustedWitness(name: String, publicKey: Array[Byte])

/** Client-side N-of-M cosignature policy (Phase 3).
  *
  * A checkpoint satisfies the policy when at least `threshold` *distinct* trusted witnesses have a
  * valid cosignature/v1 ([[CosignatureV1]]) over its note body. With N honest-majority witnesses
  * required, a log cannot present diverging histories (split view) without collusion of N
  * witnesses.
  */
object WitnessPolicy:

  /** Names of the distinct trusted witnesses with a valid cosignature on `cp`. */
  def validCosigners(cp: Checkpoint, trusted: Seq[TrustedWitness]): Set[String] =
    val body = CheckpointNote.noteBody(cp)
    val byKeyName = trusted.groupBy(_.name)
    cp.signatures
      .flatMap { sig =>
        byKeyName
          .getOrElse(sig.keyName, Nil)
          .find(w => CosignatureV1.verify(w.name, w.publicKey, body, sig))
      }
      .map(_.name)
      .toSet

  /** True when at least `threshold` distinct trusted witnesses cosigned `cp`. */
  def satisfied(cp: Checkpoint, trusted: Seq[TrustedWitness], threshold: Int): Boolean =
    require(threshold >= 0, s"threshold must be >= 0, got $threshold")
    validCosigners(cp, trusted).size >= threshold
