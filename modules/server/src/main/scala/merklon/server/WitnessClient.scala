// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon.server

import merklon.{Checkpoint, CheckpointNote, NoteSignature}

import java.net.URI
import java.net.http.{HttpClient as JHttpClient, HttpRequest, HttpResponse}
import java.time.Duration
import java.util.Base64

/** Log-side client for one witness's c2sp.org/tlog-witness `add-checkpoint` endpoint.
  *
  * Tracks the witness's last acknowledged tree size so submissions carry the right `old` line; on a
  * 409 (size mismatch — e.g. after a log restart or a shared witness) it adopts the size from the
  * response body and retries once with a matching consistency proof.
  */
final class WitnessClient(baseUrl: String):

  private val http = JHttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build()
  private val B64 = Base64.getEncoder
  private var lastAcked: Long = 0L

  /** Submit `cp` for cosigning. `proofFrom(old)` must return the RFC 9162 consistency proof from
    * tree size `old` to `cp.treeSize` (empty for `old` 0 or `old == cp.treeSize`).
    */
  def submit(
      cp: Checkpoint,
      proofFrom: Long => List[Array[Byte]]
  ): Either[String, NoteSignature] = synchronized {
    postOnce(cp, lastAcked, proofFrom) match
      case Retry(witnessSize) if witnessSize != lastAcked =>
        lastAcked = witnessSize
        postOnce(cp, witnessSize, proofFrom) match
          case Ok(sig)     => acked(cp, sig)
          case Retry(s)    => Left(s"witness $baseUrl: still conflicting (has size $s)")
          case Err(reason) => Left(reason)
      case Ok(sig)     => acked(cp, sig)
      case Retry(s)    => Left(s"witness $baseUrl: conflicting at our own size (has size $s)")
      case Err(reason) => Left(reason)
  }

  private def acked(cp: Checkpoint, sig: NoteSignature): Either[String, NoteSignature] =
    lastAcked = cp.treeSize
    Right(sig)

  private sealed trait Outcome
  private case class Ok(sig: NoteSignature) extends Outcome
  private case class Retry(witnessSize: Long) extends Outcome
  private case class Err(reason: String) extends Outcome

  private def postOnce(
      cp: Checkpoint,
      old: Long,
      proofFrom: Long => List[Array[Byte]]
  ): Outcome =
    try
      val proof = if old == 0L || old == cp.treeSize then Nil else proofFrom(old)
      val body =
        s"old $old\n" + proof.map(h => B64.encodeToString(h) + "\n").mkString + "\n" +
          CheckpointNote.render(cp)
      val req = HttpRequest
        .newBuilder(URI.create(s"$baseUrl/add-checkpoint"))
        .timeout(Duration.ofSeconds(10))
        .POST(HttpRequest.BodyPublishers.ofString(body))
        .build()
      val resp = http.send(req, HttpResponse.BodyHandlers.ofString())
      resp.statusCode() match
        case 200 =>
          val line = resp.body().linesIterator.toList.headOption.getOrElse("")
          CheckpointNote.parseSignatureLine(line) match
            case Right(sig) => Ok(sig)
            case Left(err)  => Err(s"witness $baseUrl: unparseable cosignature: $err")
        case 409 =>
          resp.body().trim.toLongOption match
            case Some(size) => Retry(size)
            case None       => Err(s"witness $baseUrl: 409 without a parseable size")
        case other => Err(s"witness $baseUrl: HTTP $other: ${resp.body().take(200)}")
    catch case e: Exception => Err(s"witness $baseUrl: ${e.getMessage}")
