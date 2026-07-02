// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon

import java.security.spec.X509EncodedKeySpec
import java.security.{KeyFactory, Signature as JSignature}

/** Ed25519 signature verification over raw 32-byte public keys (RFC 8032), via the JDK.
  *
  * Verification-side counterpart of [[CheckpointAttestor]]. Lives in the core because both the
  * witness (Phase 3) and the independent verifier need it, and it is pure computation.
  */
object Ed25519:

  // SubjectPublicKeyInfo DER header for Ed25519 (OID 1.3.101.112). The JDK KeyFactory only
  // accepts DER-wrapped keys; a raw 32-byte key is always this 12-byte header + the key.
  private val SpkiHeader: Array[Byte] =
    Array(0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00).map(_.toByte)

  /** Verify `signature` over `message` with a raw 32-byte Ed25519 public key.
    *
    * Returns false (never throws) on malformed keys or signatures: for a verifier, a proof that
    * cannot be checked is a proof that fails.
    */
  def verify(rawPublicKey: Array[Byte], message: Array[Byte], signature: Array[Byte]): Boolean =
    try
      val pubKey = KeyFactory
        .getInstance("Ed25519")
        .generatePublic(new X509EncodedKeySpec(SpkiHeader ++ rawPublicKey))
      val sig = JSignature.getInstance("Ed25519")
      sig.initVerify(pubKey)
      sig.update(message)
      sig.verify(signature)
    catch case _: Exception => false
