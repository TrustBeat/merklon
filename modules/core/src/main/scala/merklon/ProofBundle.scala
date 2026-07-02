// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon

import java.util.Base64

/** A self-contained, offline-verifiable evidence package (SPEC.md §8): the original entry bytes,
  * its inclusion proof, the signed checkpoint note it verifies against (with any witness
  * cosignatures), and optionally an RFC 3161 timestamp token over the checkpoint's note body.
  *
  * A relying party verifies the bundle with the standalone verifier and never contacts the log.
  */
case class ProofBundle(
    entry: Array[Byte],
    leafIndex: Long,
    inclusionProof: List[Array[Byte]],
    checkpointNote: String,
    rfc3161Tst: Option[Array[Byte]]
)

/** Serialisation for the `merklon-bundle/v1` container (SPEC.md §8): one JSON document whose binary
  * fields — including the embedded checkpoint note, to keep newline escaping out of the picture —
  * are base64 (RFC 4648, with padding).
  */
object ProofBundleCodec:

  val Format = "merklon-bundle/v1"

  private val Encoder = Base64.getEncoder
  private val Decoder = Base64.getDecoder

  /** The RFC 3161 message imprint for a checkpoint: SHA-256 over the note *body* (§3 —
    * origin/size/root). Binding the body rather than the full note keeps the attested statement
    * ("this log state existed at this time") independent of which signature lines happen to be
    * attached when the token is requested.
    */
  def timestampImprint(cp: Checkpoint): Array[Byte] =
    java.security.MessageDigest
      .getInstance("SHA-256")
      .digest(CheckpointNote.noteBody(cp).getBytes("UTF-8"))

  def render(b: ProofBundle): String =
    val proof = b.inclusionProof.map(h => s"\"${Encoder.encodeToString(h)}\"").mkString(",")
    val tst = b.rfc3161Tst
      .map(t => s""",\n  "rfc3161_tst": "${Encoder.encodeToString(t)}"""")
      .getOrElse("")
    s"""{
       |  "format": "$Format",
       |  "leaf_index": ${b.leafIndex},
       |  "entry": "${Encoder.encodeToString(b.entry)}",
       |  "inclusion_proof": [$proof],
       |  "checkpoint": "${Encoder.encodeToString(b.checkpointNote.getBytes("UTF-8"))}"$tst
       |}
       |""".stripMargin

  /** Parse a `merklon-bundle/v1` document (the inverse of [[render]]). Regex extraction on the
    * fixed schema, like the proof parsers — no JSON dependency in the core or the verifier.
    */
  def parse(json: String): Either[String, ProofBundle] =
    for
      format <- stringField(json, "format")
      _ <- if format == Format then Right(()) else Left(s"unsupported bundle format: $format")
      leafIndex <- longField(json, "leaf_index")
      entry <- stringField(json, "entry").flatMap(decode("entry"))
      proof <- b64Array(json, "inclusion_proof")
      noteBytes <- stringField(json, "checkpoint").flatMap(decode("checkpoint"))
      tst <- stringField(json, "rfc3161_tst") match
        case Right(s) => decode("rfc3161_tst")(s).map(Some(_))
        case Left(_)  => Right(None) // optional field
    yield ProofBundle(entry, leafIndex, proof, new String(noteBytes, "UTF-8"), tst)

  private def stringField(json: String, key: String): Either[String, String] =
    val pattern = raw""""$key"\s*:\s*"([^"]*)"""".r
    pattern.findFirstMatchIn(json).map(_.group(1)).toRight(s"field '$key' not found")

  private def longField(json: String, key: String): Either[String, Long] =
    val pattern = raw""""$key"\s*:\s*(\d+)""".r
    pattern.findFirstMatchIn(json).map(_.group(1).toLong).toRight(s"field '$key' not found")

  private def b64Array(json: String, key: String): Either[String, List[Array[Byte]]] =
    val pattern = raw""""$key"\s*:\s*\[([^\]]*)\]""".r
    pattern
      .findFirstMatchIn(json)
      .toRight(s"field '$key' not found")
      .flatMap { m =>
        val content = m.group(1).trim
        if content.isEmpty then Right(Nil)
        else
          val strs = content.split(',').map(_.trim.stripPrefix("\"").stripSuffix("\"")).toList
          val (errs, hashes) = strs.map(decode(key)).partitionMap(identity)
          if errs.nonEmpty then Left(errs.head) else Right(hashes)
      }

  private def decode(field: String)(s: String): Either[String, Array[Byte]] =
    try Right(Decoder.decode(s))
    catch case _: IllegalArgumentException => Left(s"invalid base64 in $field")
