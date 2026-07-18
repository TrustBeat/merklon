// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon.verifier

import merklon.*

/** What a successfully verified tlog-proof established. `cosigners` is empty when no witnesses were
  * configured; `extra` is the document's unauthenticated opaque extra data, if any.
  */
final case class TlogProofReport(
    checkpoint: Checkpoint,
    leafIndex: Long,
    cosigners: Set[String],
    extra: Option[Array[Byte]]
)

/** Fully offline verification of a c2sp.org/tlog-proof@v1 document — never contacts the log.
  *
  * Unlike a `merklon-bundle/v1`, a tlog-proof does not carry the entry bytes: the caller supplies
  * them out of band. Checks, in order: document syntax, the embedded checkpoint's log signature
  * (strict signed-note rule), the N-of-M witness policy (when witnesses are given), and the
  * inclusion proof of the supplied entry bytes. The `extra` data is NOT authenticated (per spec)
  * and is only reported back.
  */
object TlogProofVerifier:

  def verify(
      proofText: String,
      entry: Array[Byte],
      logPublicKey: Array[Byte],
      witnesses: Seq[TrustedWitness] = Nil,
      threshold: Int = 0,
      codec: LeafCodec = LeafCodec.Identity
  ): Either[String, TlogProofReport] =
    for
      doc <- TlogProofCodec.parse(proofText)
      cp <- CheckpointNote.parse(doc.checkpointNote).left.map(e => s"embedded checkpoint: $e")
      _ <- check(
        LogVerifier.verifyCheckpointSignature(cp, logPublicKey),
        "checkpoint signature did not verify against the trusted log key"
      )
      cosigners = WitnessPolicy.validCosigners(cp, witnesses)
      _ <- check(
        witnesses.isEmpty || cosigners.size >= threshold,
        s"witness policy: ${cosigners.size} valid cosignature(s), need $threshold"
      )
      _ <- check(
        doc.leafIndex >= 0 && doc.leafIndex < cp.treeSize,
        s"index ${doc.leafIndex} out of range for tree_size ${cp.treeSize}"
      )
      proof = InclusionProof(doc.leafIndex, cp.treeSize, doc.inclusionProof)
      _ <- check(
        LogVerifier.verifyInclusion(entry, proof, cp, codec),
        s"inclusion proof for index ${doc.leafIndex} did not verify"
      )
    yield TlogProofReport(cp, doc.leafIndex, cosigners, doc.extra)

  private def check(ok: Boolean, err: => String): Either[String, Unit] =
    if ok then Right(()) else Left(err)
