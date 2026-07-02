// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon.server.witness

import merklon.*
import zio.*
import zio.http.*

import java.security.{KeyPair, MessageDigest}
import java.util.Base64

/** A log this witness is configured to watch: origin plus the log's raw Ed25519 public key. */
final case class WitnessedLog(origin: String, publicKey: Array[Byte])

/** The c2sp.org/tlog-witness HTTP protocol over [[merklon.Witness]].
  *
  * `POST /add-checkpoint` request body:
  * {{{
  * old <last cosigned tree size>
  * <base64 consistency proof hash>      (0 to 63 lines)
  * <empty line>
  * <checkpoint signed note>
  * }}}
  *
  * Responses:
  *   - 200 — body is this witness's cosignature line(s) (cosignature/v1)
  *   - 400 — malformed request, or `old` exceeds the submitted checkpoint size
  *   - 403 — no valid signature from the log's trusted key
  *   - 404 — unknown origin
  *   - 409 — `old` does not match the witness's latest cosigned size (body: that size, decimal,
  *     newline-terminated, `Content-Type: text/x.tlog.size`), or same size with a different root
  *     (split view)
  *   - 422 — consistency proof does not verify
  *
  * `GET /<sha256(origin) hex>/checkpoint` (monitoring) — the latest cosigned note, or 404.
  */
object WitnessServer:

  private val MaxProofLines = 63
  // A well-formed request is an old line + ≤63 proof hashes + one note — far below this cap.
  private val MaxBodyBytes = 64 * 1024
  private val B64 = Base64.getDecoder

  def make(
      name: String,
      keyPair: KeyPair,
      logs: Seq[WitnessedLog],
      store: WitnessStateStore,
      clock: () => Long = () => java.lang.System.currentTimeMillis() / 1000L
  ): Routes[Any, Nothing] =
    val byOrigin: Map[String, (WitnessedLog, Witness)] =
      logs.map { l =>
        l.origin -> (l, Witness(name, keyPair, l.origin, l.publicKey, store, clock))
      }.toMap
    val originByHash: Map[String, String] =
      logs.map(l => sha256Hex(l.origin) -> l.origin).toMap

    Routes(
      Method.POST / "add-checkpoint" ->
        Handler.fromFunctionZIO[Request] { req =>
          req.body.asArray
            .map { raw =>
              if raw.length > MaxBodyBytes then
                Response(
                  Status.RequestEntityTooLarge,
                  body = Body.fromString(s"request body exceeds $MaxBodyBytes bytes")
                )
              else addCheckpoint(byOrigin, String(raw, "UTF-8"))
            }
            .catchAll(e => ZIO.succeed(Response.badRequest(e.getMessage)))
        },

      // Monitoring endpoint: latest cosigned checkpoint for a watched log.
      Method.GET / string("originHash") / "checkpoint" ->
        Handler.fromFunctionZIO[(String, Request)] { case (originHash, _) =>
          ZIO
            .attempt {
              originByHash.get(originHash).flatMap(store.latest) match
                case Some(cp) => Response.text(CheckpointNote.render(cp))
                case None     => Response.notFound("no cosigned checkpoint for that origin")
            }
            .catchAll(e => ZIO.succeed(Response.internalServerError(e.getMessage)))
        }
    )

  private def addCheckpoint(
      byOrigin: Map[String, (WitnessedLog, Witness)],
      rawBody: String
  ): Response =
    parseRequest(rawBody) match
      case Left(err) => Response.badRequest(err)
      case Right((old, proof, noteText)) =>
        CheckpointNote.parse(noteText) match
          case Left(err) => Response.badRequest(s"unparseable checkpoint note: $err")
          case Right(cp) =>
            byOrigin.get(cp.origin) match
              case None => Response.notFound(s"unknown origin: ${cp.origin}")
              case Some((log, witness)) =>
                if old > cp.treeSize then
                  Response.badRequest(s"old size $old exceeds checkpoint size ${cp.treeSize}")
                else if !hasValidLogSignature(cp, log.publicKey) then
                  Response.forbidden("no valid log signature")
                else
                  val latestSize = witness.latestCosigned.map(_.treeSize).getOrElse(0L)
                  if old != latestSize then conflict(latestSize)
                  else
                    witness.observe(cp, proof) match
                      case Right(sig) =>
                        Response.text(CheckpointNote.signatureLine(sig) + "\n")
                      case Left(WitnessRefusal.SplitView(_, _)) => conflict(latestSize)
                      case Left(WitnessRefusal.InconsistentHistory(_, _)) =>
                        Response(
                          status = Status.UnprocessableEntity,
                          body = Body.fromString("consistency proof does not verify")
                        )
                      case Left(WitnessRefusal.InvalidLogSignature(_)) =>
                        Response.forbidden("no valid log signature")
                      case Left(WitnessRefusal.WrongOrigin(_, _)) =>
                        Response.notFound(s"unknown origin: ${cp.origin}")

  /** 409 Conflict carrying the witness's latest cosigned size, per the tlog-witness spec. */
  private def conflict(latestSize: Long): Response =
    Response(
      status = Status.Conflict,
      headers = Headers(Header.Custom("Content-Type", "text/x.tlog.size")),
      body = Body.fromString(s"$latestSize\n")
    )

  private def hasValidLogSignature(cp: Checkpoint, logPublicKey: Array[Byte]): Boolean =
    val body = CheckpointNote.noteBody(cp).getBytes("UTF-8")
    cp.signatures.exists(s => Ed25519.verify(logPublicKey, body, s.sig))

  /** Split the request into (old size, consistency proof, note text). */
  private def parseRequest(
      body: String
  ): Either[String, (Long, List[Array[Byte]], String)] =
    val lines = body.split("\n", -1).toList
    lines match
      case oldLine :: rest =>
        for
          old <-
            if oldLine.startsWith("old ") then
              val sizeStr = oldLine.drop(4)
              sizeStr.toLongOption
                .filter(n => n >= 0 && !sizeStr.startsWith("+"))
                .toRight(s"invalid old size: $sizeStr")
            else Left("first line must be 'old <size>'")
          blankIdx = rest.indexWhere(_.isEmpty)
          _ <- if blankIdx < 0 then Left("missing blank line after proof") else Right(())
          _ <-
            if blankIdx > MaxProofLines then Left(s"more than $MaxProofLines proof lines")
            else Right(())
          proof <- decodeProof(rest.take(blankIdx))
          noteText = rest.drop(blankIdx + 1).mkString("\n")
          _ <- if noteText.isEmpty then Left("missing checkpoint note") else Right(())
        yield (old, proof, noteText)
      case Nil => Left("empty request body")

  private def decodeProof(lines: List[String]): Either[String, List[Array[Byte]]] =
    val (errs, hashes) = lines
      .map { l =>
        try
          val h = B64.decode(l)
          if h.length == 32 then Right(h) else Left(s"proof hash is ${h.length} bytes, want 32")
        catch case _: IllegalArgumentException => Left(s"invalid base64 proof line: $l")
      }
      .partitionMap(identity)
    if errs.nonEmpty then Left(errs.head) else Right(hashes)

  private def sha256Hex(s: String): String =
    MessageDigest
      .getInstance("SHA-256")
      .digest(s.getBytes("UTF-8"))
      .map(b => f"${b & 0xff}%02x")
      .mkString
