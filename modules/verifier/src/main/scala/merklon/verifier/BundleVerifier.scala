// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon.verifier

import merklon.*

import java.security.cert.X509Certificate

/** What a successfully verified bundle established. `cosigners` is empty when no witnesses were
  * configured; `timestamp` is None when the bundle carries no RFC 3161 token.
  */
final case class BundleReport(
    checkpoint: Checkpoint,
    leafIndex: Long,
    cosigners: Set[String],
    timestamp: Option[TimestampInfo]
)

/** Fully offline verification of a `merklon-bundle/v1` document (SPEC.md §8) — never contacts the
  * log. Checks, in order: bundle syntax, embedded checkpoint signature against the trusted log key,
  * the N-of-M witness policy (when witnesses are given), the inclusion proof of the entry bytes,
  * and the RFC 3161 timestamp token (when present; fails if a TSA certificate was supplied but the
  * bundle has no token).
  */
object BundleVerifier:

  def verify(
      bundleJson: String,
      logPublicKey: Array[Byte],
      witnesses: Seq[TrustedWitness] = Nil,
      threshold: Int = 0,
      tsaCert: Option[X509Certificate] = None,
      codec: LeafCodec = LeafCodec.Identity
  ): Either[String, BundleReport] =
    for
      bundle <- ProofBundleCodec.parse(bundleJson)
      cp <- CheckpointNote.parse(bundle.checkpointNote).left.map(e => s"embedded checkpoint: $e")
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
        bundle.leafIndex >= 0 && bundle.leafIndex < cp.treeSize,
        s"leaf_index ${bundle.leafIndex} out of range for tree_size ${cp.treeSize}"
      )
      proof = InclusionProof(bundle.leafIndex, cp.treeSize, bundle.inclusionProof)
      _ <- check(
        LogVerifier.verifyInclusion(bundle.entry, proof, cp, codec),
        s"inclusion proof for leaf ${bundle.leafIndex} did not verify"
      )
      timestamp <- verifyTimestamp(bundle, cp, tsaCert)
    yield BundleReport(cp, bundle.leafIndex, cosigners, timestamp)

  private def verifyTimestamp(
      bundle: ProofBundle,
      cp: Checkpoint,
      tsaCert: Option[X509Certificate]
  ): Either[String, Option[TimestampInfo]] =
    bundle.rfc3161Tst match
      case None if tsaCert.isDefined =>
        Left("a TSA certificate was supplied but the bundle carries no timestamp token")
      case None => Right(None)
      case Some(der) =>
        TimestampVerifier.verify(der, ProofBundleCodec.timestampImprint(cp), tsaCert).map(Some(_))

  private def check(ok: Boolean, err: => String): Either[String, Unit] =
    if ok then Right(()) else Left(err)
