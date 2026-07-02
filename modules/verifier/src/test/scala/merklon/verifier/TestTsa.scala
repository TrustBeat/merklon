// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon.verifier

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.{AlgorithmIdentifier, ExtendedKeyUsage, Extension, KeyPurposeId}
import org.bouncycastle.cert.jcajce.{
  JcaCertStore,
  JcaX509CertificateConverter,
  JcaX509v3CertificateBuilder
}
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder
import org.bouncycastle.operator.jcajce.{
  JcaContentSignerBuilder,
  JcaDigestCalculatorProviderBuilder
}
import org.bouncycastle.tsp.*

import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.cert.X509Certificate
import java.util.Date
import java.util.concurrent.atomic.AtomicLong

/** A miniature in-process RFC 3161 TSA for tests: a self-signed certificate with the (critical)
  * timestamping EKU and a Bouncy Castle response generator. `respond` speaks the DER
  * request/response protocol so it can sit behind an HTTP stub; `token` shortcuts straight to a
  * signed TimeStampToken.
  */
final class TestTsa(dn: String = "CN=merklon test TSA"):

  private val keyPair =
    val kpg = KeyPairGenerator.getInstance("RSA")
    kpg.initialize(2048)
    kpg.generateKeyPair()

  val certificate: X509Certificate =
    val name = X500Name(dn)
    val now = System.currentTimeMillis()
    val builder = JcaX509v3CertificateBuilder(
      name,
      BigInteger.ONE,
      Date(now - 3600_000L),
      Date(now + 24 * 3600_000L),
      name,
      keyPair.getPublic
    )
    // RFC 3161 §2.3: the TSA certificate MUST have id-kp-timeStamping as its only EKU, critical.
    builder.addExtension(
      Extension.extendedKeyUsage,
      true,
      ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping)
    )
    val signer = JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate)
    JcaX509CertificateConverter().getCertificate(builder.build(signer))

  private val responseGen =
    val signerInfo =
      JcaSimpleSignerInfoGeneratorBuilder().build("SHA256withRSA", keyPair.getPrivate, certificate)
    val certDigest = JcaDigestCalculatorProviderBuilder()
      .build()
      .get(AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256))
    val tokenGen =
      TimeStampTokenGenerator(signerInfo, certDigest, ASN1ObjectIdentifier("1.3.6.1.4.1.99999.1"))
    tokenGen.addCertificates(JcaCertStore(java.util.List.of(certificate)))
    TimeStampResponseGenerator(tokenGen, TSPAlgorithms.ALLOWED)

  private val serial = AtomicLong(1L)

  /** DER TimeStampResponse for a DER TimeStampRequest — wire this behind an HTTP stub. */
  def respond(requestDer: Array[Byte]): Array[Byte] = synchronized {
    val request = TimeStampRequest(requestDer)
    responseGen.generate(request, BigInteger.valueOf(serial.getAndIncrement()), Date()).getEncoded
  }

  /** A signed TimeStampToken (DER) over a SHA-256 `imprint`, skipping the HTTP round-trip. */
  def token(imprint: Array[Byte]): Array[Byte] = synchronized {
    val reqGen = TimeStampRequestGenerator()
    reqGen.setCertReq(true)
    val request = reqGen.generate(TSPAlgorithms.SHA256, imprint)
    responseGen
      .generate(request, BigInteger.valueOf(serial.getAndIncrement()), Date())
      .getTimeStampToken
      .getEncoded
  }
