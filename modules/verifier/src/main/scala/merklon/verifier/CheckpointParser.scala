// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon.verifier

import merklon.{Checkpoint, NoteSignature}
import java.util.Base64

/** Parses a c2sp.org/tlog-checkpoint + signed-note text into a [[merklon.Checkpoint]].
  *
  * Format: `origin\ntree_size\nbase64(root_hash)\n[extension lines]\n\n— key base64(id||sig)\n...`
  * Extension lines (between root_hash and the blank separator) are silently ignored per spec.
  */
object CheckpointParser:

  private val EmDash = "—" // U+2014, required by c2sp.org/signed-note
  private val Decoder = Base64.getDecoder

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
    val (errs, sigs) = lines.map(parseSig).partitionMap(identity)
    if errs.nonEmpty then Left(errs.head) else Right(sigs)

  private def parseSig(line: String): Either[String, NoteSignature] =
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
    try Right(Decoder.decode(s.trim))
    catch case _: IllegalArgumentException => Left(s"invalid base64: $s")
