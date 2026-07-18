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

  /** Strict signed-note validation of the log's signature(s) on `cp`, per c2sp.org/signed-note and
    * tlog-witness: a signature line is "from the known key" when its key ID equals the Ed25519
    * key-ID formula over its own key name and the trusted public key — and every such line MUST
    * verify; a single failing one makes the whole note malformed. Lines whose ID does not match are
    * unknown keys and are ignored (this includes cosignature lines, whose IDs use a different type
    * byte). True iff at least one known-key line is present and all of them verify.
    */
  def verifyLogSignatures(cp: Checkpoint, publicKey: Array[Byte]): Boolean =
    val body = noteBody(cp).getBytes("UTF-8")
    val known = cp.signatures.filter { s =>
      java.util.Arrays.equals(s.keyId, keyId(s.keyName, publicKey))
    }
    known.nonEmpty && known.forall(s => Ed25519.verify(publicKey, body, s.sig))

  def noteBody(origin: String, treeSize: Long, rootHash: Array[Byte]): String =
    s"$origin\n$treeSize\n${Encoder.encodeToString(rootHash)}\n"

  def noteBody(cp: Checkpoint): String =
    noteBody(cp.origin, cp.treeSize, cp.rootHash)

  /** One signed-note signature line (without trailing newline). */
  def signatureLine(s: NoteSignature): String =
    s"$EmDash ${s.keyName} ${Encoder.encodeToString(s.keyId ++ s.sig)}"

  def render(cp: Checkpoint): String =
    val body = noteBody(cp)
    val sigLines = cp.signatures.map(signatureLine).mkString("\n")
    s"$body\n$sigLines\n"

  /** Parse a signed-note checkpoint (the inverse of [[render]]).
    *
    * Extension lines (between root_hash and the blank separator) are silently skipped per spec.
    * `signedAt` is not carried on the wire and comes back as 0.
    */
  def parse(note: String): Either[String, Checkpoint] =
    val lines = note.split('\n').toList
    for
      origin <- lines.lift(0).toRight("missing origin line")
      sizeStr <- lines.lift(1).toRight("missing tree_size line")
      treeSize <- sizeStr.toLongOption.toRight(s"invalid tree_size: $sizeStr")
      hashStr <- lines.lift(2).toRight("missing root_hash line")
      rootHash <- decodeBase64(hashStr)
      // Skip optional extension lines; find the first blank line after the mandatory three.
      rest = lines.drop(3)
      blankIdx = rest.indexWhere(_.isEmpty)
      _ <- if blankIdx < 0 then Left("missing blank separator line") else Right(())
      sigLines = rest.drop(blankIdx + 1).filter(_.startsWith(s"$EmDash "))
      sigs <- parseSigs(sigLines)
    yield Checkpoint(origin, treeSize, rootHash, 0L, sigs.toVector)

  private def parseSigs(lines: List[String]): Either[String, List[NoteSignature]] =
    val (errs, sigs) = lines.map(parseSignatureLine).partitionMap(identity)
    if errs.nonEmpty then Left(errs.head) else Right(sigs)

  /** Parse one signature line (`— <key name> <base64(key_id || sig)>`), e.g. a lone cosignature
    * line returned by a witness.
    */
  def parseSignatureLine(line: String): Either[String, NoteSignature] =
    // "— keyName base64(keyId || sig)" — U+2014 is one char, then a space.
    val body = line.drop(2)
    val space = body.indexOf(' ')
    if space < 0 then Left(s"malformed signature line: $line")
    else
      val keyName = body.take(space)
      decodeBase64(body.drop(space + 1)).flatMap { blob =>
        if blob.length < 4 then Left(s"signature blob too short (${blob.length} bytes)")
        else Right(NoteSignature(keyName, blob.take(4), blob.drop(4)))
      }

  private def decodeBase64(s: String): Either[String, Array[Byte]] =
    try Right(Base64.getDecoder.decode(s.trim))
    catch case _: IllegalArgumentException => Left(s"invalid base64: $s")
