// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon

import java.nio.ByteBuffer
import java.security.{KeyPair, Signature as JSignature}

/** The c2sp.org/tlog-cosignature "cosignature/v1" format used by witnesses.
  *
  * A cosignature is NOT a plain signature over the note body (that is what the log key produces).
  * The signed message is:
  *
  * {{{
  * cosignature/v1
  * time <unix seconds>
  * <note body, including its final newline, without signature lines>
  * }}}
  *
  * and the signature blob carried on the note's signature line is `key_id(4) || timestamp(8,
  * big-endian) || ed25519_signature(64)` — 76 bytes total. The key ID uses signature-type byte 0x04
  * (Ed25519 cosignature/v1): `SHA-256(name || 0x0A || 0x04 || public_key)[:4]`.
  *
  * In [[NoteSignature]] terms, `keyId` holds the 4-byte cosignature key ID and `sig` holds the
  * 72-byte `timestamp || ed25519_signature` remainder, so `keyId ++ sig` is the wire blob.
  */
object CosignatureV1:

  /** Cosignature/v1 key ID: SHA-256(name || 0x0A || 0x04 || ed25519PublicKey)[0:4]. */
  def keyId(name: String, publicKey: Array[Byte]): Array[Byte] =
    val md = java.security.MessageDigest.getInstance("SHA-256")
    md.update(name.getBytes("UTF-8"))
    md.update(0x0a.toByte)
    md.update(0x04.toByte) // Ed25519 cosignature/v1 signature type
    md.update(publicKey)
    md.digest().take(4)

  /** The exact bytes a cosigner signs for `noteBody` at `timestamp` (unix seconds). */
  def message(timestamp: Long, noteBody: String): Array[Byte] =
    s"cosignature/v1\ntime $timestamp\n$noteBody".getBytes("UTF-8")

  /** Cosign `noteBody` at `timestamp`; returns the signed-note signature line content.
    *
    * The spec forbids a zero timestamp for checkpoint cosignatures.
    */
  def sign(name: String, keyPair: KeyPair, noteBody: String, timestamp: Long): NoteSignature =
    require(timestamp != 0L, "cosignature/v1 timestamp must not be zero")
    val signer = JSignature.getInstance("Ed25519")
    signer.initSign(keyPair.getPrivate)
    signer.update(message(timestamp, noteBody))
    val sig = signer.sign()
    val publicKey = keyPair.getPublic.getEncoded.takeRight(32)
    val tsBytes = ByteBuffer.allocate(8).putLong(timestamp).array()
    NoteSignature(name, keyId(name, publicKey), tsBytes ++ sig)

  /** The unix-seconds timestamp embedded in a cosignature, if the blob is well-formed. */
  def timestampOf(sig: NoteSignature): Option[Long] =
    if sig.sig.length != 72 then None
    else Some(ByteBuffer.wrap(sig.sig, 0, 8).getLong)

  /** Verify a cosignature/v1 from cosigner (`name`, raw 32-byte `publicKey`) over `noteBody`.
    *
    * Checks the key ID, blob shape, non-zero timestamp, and the Ed25519 signature over the
    * reconstructed message.
    */
  def verify(
      name: String,
      publicKey: Array[Byte],
      noteBody: String,
      sig: NoteSignature
  ): Boolean =
    sig.keyName == name &&
      java.util.Arrays.equals(sig.keyId, keyId(name, publicKey)) &&
      timestampOf(sig).exists { ts =>
        ts != 0L && Ed25519.verify(publicKey, message(ts, noteBody), sig.sig.drop(8))
      }
