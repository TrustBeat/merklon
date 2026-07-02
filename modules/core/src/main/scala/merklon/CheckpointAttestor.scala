// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon

import java.security.{KeyPair, KeyPairGenerator, Signature as JSignature}

/** Signs checkpoint note bodies and exposes the public key for verifiers.
  *
  * The default implementation is Ed25519 (JDK 15+, no extra dependencies). The key-ID formula
  * follows c2sp.org/signed-note: SHA-256(keyName || 0x0A || 0x01 || ed25519PublicKey)[0:4]
  */
trait CheckpointAttestor:
  def keyName: String
  def keyId: Array[Byte] // 4 bytes
  def publicKey: Array[Byte] // raw 32 bytes (Ed25519)
  def sign(body: Array[Byte]): Array[Byte]

object CheckpointAttestor:
  def ed25519(name: String, keyPair: KeyPair): CheckpointAttestor =
    new Ed25519Attestor(name, keyPair)

  def generateEd25519(name: String): CheckpointAttestor =
    val kpg = KeyPairGenerator.getInstance("Ed25519")
    ed25519(name, kpg.generateKeyPair())

private final class Ed25519Attestor(val keyName: String, keyPair: KeyPair)
    extends CheckpointAttestor:

  // SubjectPublicKeyInfo DER for Ed25519 is always 44 bytes; raw key = last 32
  val publicKey: Array[Byte] = keyPair.getPublic.getEncoded.takeRight(32)
  val keyId: Array[Byte] = CheckpointNote.keyId(keyName, publicKey)

  def sign(body: Array[Byte]): Array[Byte] =
    val sig = JSignature.getInstance("Ed25519")
    sig.initSign(keyPair.getPrivate)
    sig.update(body)
    sig.sign()
