// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon.verifier

import java.util.Base64

/** Data types for SPEC.md §4.1 (inclusion) and §5.1 (consistency) proof payloads. */
case class InclusionProof(leafIndex: Long, treeSize: Long, auditPath: List[Array[Byte]])
case class ConsistencyProof(first: Long, second: Long, proofPath: List[Array[Byte]])

/** Minimal JSON parser for the two proof schemas served by the log API.
  *
  * No external dependencies: uses regex extraction on the fixed, known schemas. Only call this on
  * server-provided JSON; the schemas are document in SPEC.md §4.1 and §5.1.
  */
object ProofParser:

  private val Decoder = Base64.getDecoder

  def parseInclusion(json: String): Either[String, InclusionProof] =
    for
      leafIndex <- longField(json, "leaf_index")
      treeSize <- longField(json, "tree_size")
      hashes <- b64Array(json, "audit_path")
    yield InclusionProof(leafIndex, treeSize, hashes)

  def parseConsistency(json: String): Either[String, ConsistencyProof] =
    for
      first <- longField(json, "first")
      second <- longField(json, "second")
      hashes <- b64Array(json, "proof_path")
    yield ConsistencyProof(first, second, hashes)

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
          val (errs, hashes) = strs
            .map(s =>
              try Right(Decoder.decode(s))
              catch case _: IllegalArgumentException => Left(s"invalid base64 in $key: $s")
            )
            .partitionMap(identity)
          if errs.nonEmpty then Left(errs.head) else Right(hashes)
      }
