// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon

import java.util.Base64

/** A single signature line in a signed note (c2sp.org/signed-note). */
case class NoteSignature(
    keyName: String,
    keyId: Array[Byte], // 4 bytes
    sig: Array[Byte] // 64 bytes for Ed25519
)

/** A signed commitment to (treeSize, rootHash) at a point in time.
  *
  * Serialises to/from the c2sp.org/tlog-checkpoint + signed-note wire format via CheckpointNote.
  */
case class Checkpoint(
    origin: String,
    treeSize: Long,
    rootHash: Array[Byte],
    signedAt: Long,
    signatures: Vector[NoteSignature]
)

/** Serialisation for the c2sp.org/tlog-checkpoint + signed-note wire format.
  *
  * Note body (signed bytes): <origin>\n<tree_size>\n<base64(root_hash)>\n
  *
  * Full note: <body>\n — <key name> <base64(key_id || signature)>\n [additional signature lines…]
  */
object CheckpointNote:
  // U+2014 EM DASH, required by the signed-note spec
  private val EmDash = "—"
  private val Encoder = Base64.getEncoder

  /** c2sp.org/signed-note key ID: SHA-256(keyName || 0x0A || 0x01 || ed25519PublicKey)[0:4]. 0x01
    * is the Ed25519 signature-type identifier; `publicKey` is the raw 32 bytes.
    */
  def keyId(keyName: String, publicKey: Array[Byte]): Array[Byte] =
    val md = java.security.MessageDigest.getInstance("SHA-256")
    md.update(keyName.getBytes("UTF-8"))
    md.update(0x0a.toByte)
    md.update(0x01.toByte)
    md.update(publicKey)
    md.digest().take(4)

  def noteBody(origin: String, treeSize: Long, rootHash: Array[Byte]): String =
    s"$origin\n$treeSize\n${Encoder.encodeToString(rootHash)}\n"

  def noteBody(cp: Checkpoint): String =
    noteBody(cp.origin, cp.treeSize, cp.rootHash)

  def render(cp: Checkpoint): String =
    val body = noteBody(cp)
    val sigLines = cp.signatures
      .map(s => s"$EmDash ${s.keyName} ${Encoder.encodeToString(s.keyId ++ s.sig)}")
      .mkString("\n")
    s"$body\n$sigLines\n"
