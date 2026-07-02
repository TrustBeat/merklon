// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon.verifier

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder
import org.bouncycastle.tsp.TimeStampToken

import java.security.cert.X509Certificate
import java.time.Instant

/** The verified content of an RFC 3161 timestamp token. `signerVerified` is false when no TSA
  * certificate was supplied: the imprint binding was checked but the token's signature was not.
  */
final case class TimestampInfo(genTime: Instant, tsa: String, signerVerified: Boolean)

/** RFC 3161 timestamp-token verification (Bouncy Castle — protocol parsing only, no home-made
  * crypto). Two independent checks:
  *
  *   1. always — the token's SHA-256 message imprint equals `expectedImprint`, i.e. the token
  *      covers exactly this checkpoint and nothing else; 2. with a TSA certificate — the CMS
  *      signature verifies against it, the certificate matches the token's ESSCertID, carries the
  *      (critical) timestamping EKU, and was valid at genTime (Bouncy Castle's
  *      `TimeStampToken.validate`).
  */
object TimestampVerifier:

  def verify(
      tokenDer: Array[Byte],
      expectedImprint: Array[Byte],
      tsaCert: Option[X509Certificate]
  ): Either[String, TimestampInfo] =
    try
      val token = TimeStampToken(CMSSignedData(tokenDer))
      val info = token.getTimeStampInfo
      if info.getMessageImprintAlgOID != NISTObjectIdentifiers.id_sha256 then
        Left(s"timestamp token imprint algorithm is not SHA-256: ${info.getMessageImprintAlgOID}")
      else if !java.util.Arrays.equals(info.getMessageImprintDigest, expectedImprint) then
        Left("timestamp token does not cover this checkpoint (message imprint mismatch)")
      else
        val tsaName = Option(info.getTsa).map(_.toString).getOrElse("(unnamed TSA)")
        tsaCert match
          case Some(cert) =>
            token.validate(JcaSimpleSignerInfoVerifierBuilder().build(cert)) // throws on failure
            Right(TimestampInfo(info.getGenTime.toInstant, tsaName, signerVerified = true))
          case None =>
            Right(TimestampInfo(info.getGenTime.toInstant, tsaName, signerVerified = false))
    catch case e: Exception => Left(s"timestamp token invalid: ${e.getMessage}")
