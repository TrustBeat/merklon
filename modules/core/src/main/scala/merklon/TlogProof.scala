// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon

import java.util.Base64

/** A c2sp.org/tlog-proof@v1 document: an offline-verifiable statement that the entry at `leafIndex`
  * is included in the checkpointed tree, witnessed by whoever cosigned the embedded checkpoint.
  * Unlike [[ProofBundle]] it does not carry the entry bytes (the verifier supplies them out of
  * band) or an RFC 3161 token; it is the ecosystem interchange format ("transparent signatures"),
  * while `merklon-bundle/v1` is the self-contained evidence container.
  */
case class TlogProof(
    leafIndex: Long,
    inclusionProof: List[Array[Byte]],
    checkpointNote: String,
    extra: Option[Array[Byte]]
)

/** Serialisation for c2sp.org/tlog-proof@v1:
  *
  * {{{
  * c2sp.org/tlog-proof@v1
  * [extra <base64>]                  (omitted when there is no extra data)
  * index <leaf index>
  * <base64 inclusion-proof hash>*    (leaf's sibling first, up to the root's child)
  * <empty line>
  * <checkpoint signed note, verbatim>
  * }}}
  *
  * The checkpoint is embedded byte-for-byte so its signatures keep verifying. Proofs SHOULD be
  * stored with file extension `.tlog-proof`.
  */
object TlogProofCodec:

  val Header = "c2sp.org/tlog-proof@v1"

  private val Encoder = Base64.getEncoder
  private val Decoder = Base64.getDecoder

  def render(p: TlogProof): String =
    val extra = p.extra.map(e => s"extra ${Encoder.encodeToString(e)}\n").getOrElse("")
    val proof = p.inclusionProof.map(h => Encoder.encodeToString(h) + "\n").mkString
    s"$Header\n${extra}index ${p.leafIndex}\n$proof\n${p.checkpointNote}"

  /** Parse a tlog-proof document (the inverse of [[render]]). The checkpoint note is preserved
    * verbatim; validating it is the verifier's job.
    */
  def parse(text: String): Either[String, TlogProof] =
    text.split("\n", -1).toList match
      case header :: rest if header == Header =>
        val (extraResult, afterExtra) = rest match
          case l :: tail if l.startsWith("extra ") =>
            (decodeB64("extra", l.drop(6)).map(Some(_)), tail)
          case other => (Right(None): Either[String, Option[Array[Byte]]], other)
        for
          extra <- extraResult
          index <- afterExtra match
            case l :: _ if l.startsWith("index ") => parseIndex(l.drop(6))
            case l :: _                           => Left(s"expected 'index <n>' line, got: $l")
            case Nil                              => Left("missing index line")
          afterIndex = afterExtra.drop(1)
          blankIdx = afterIndex.indexWhere(_.isEmpty)
          _ <- if blankIdx < 0 then Left("missing blank line before the checkpoint") else Right(())
          proof <- decodeProof(afterIndex.take(blankIdx))
          noteText = afterIndex.drop(blankIdx + 1).mkString("\n")
          _ <- if noteText.isEmpty then Left("missing checkpoint note") else Right(())
        yield TlogProof(index, proof, noteText, extra)
      case header :: _ => Left(s"unsupported tlog-proof header: $header")
      case Nil         => Left("empty document")

  /** ASCII decimal, no leading zeroes (unless the index is exactly "0"). */
  private def parseIndex(s: String): Either[String, Long] =
    val wellFormed = s.nonEmpty && s.forall(_.isDigit) && (s == "0" || !s.startsWith("0"))
    if wellFormed then s.toLongOption.toRight(s"index out of range: $s")
    else Left(s"invalid index: $s")

  private def decodeProof(lines: List[String]): Either[String, List[Array[Byte]]] =
    val (errs, hashes) = lines
      .map { l =>
        decodeB64("inclusion proof", l).flatMap { h =>
          if h.length == 32 then Right(h) else Left(s"proof hash is ${h.length} bytes, want 32")
        }
      }
      .partitionMap(identity)
    if errs.nonEmpty then Left(errs.head) else Right(hashes)

  private def decodeB64(field: String, s: String): Either[String, Array[Byte]] =
    try Right(Decoder.decode(s))
    catch case _: IllegalArgumentException => Left(s"invalid base64 in $field: $s")
