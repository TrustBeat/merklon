// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon.server

import merklon.*
import zio.*
import zio.http.*

import java.util.Base64

/** ZIO HTTP routes for the merklon log API (SPEC.md §6).
  *
  * POST /entries appends and then waits for the next batched checkpoint (published by the
  * [[CheckpointPublisher]] fiber on its timed cadence, witnessed off the request path) before
  * responding, so the proof endpoints work against the returned tree size without polling. The
  * caller must fork `publisher.run` alongside these routes.
  */
object LogServer:

  private val B64 = Base64.getEncoder

  /** Maximum entries returned by one GET /entries page. */
  val MaxEntryPage = 1000L

  def make(
      sequencer: Sequencer,
      storage: StorageBackend,
      publisher: CheckpointPublisher,
      tsa: Option[TsaClient] = None,
      maxEntryBytes: Int = 64 * 1024
  ): Routes[Any, Nothing] =
    Routes(
      // POST /entries — append entry, await the checkpoint that integrates it, return
      // {"leaf_index":N,"tree_size":M}. 413 for oversized entries; 503 if no checkpoint
      // covered it in time (the entry itself is durably appended either way).
      Method.POST / "entries" ->
        Handler.fromFunctionZIO[Request] { req =>
          (for
            data <- req.body.asArray
            _ <- ZIO
              .fail(EntryTooLarge(data.length, maxEntryBytes))
              .when(data.length > maxEntryBytes)
            result <- publisher.append(data)
            (idx, cp) = result
          yield Response.json(s"""{"leaf_index":$idx,"tree_size":${cp.treeSize}}"""))
            .catchAll {
              case e: EntryTooLarge =>
                ZIO.succeed(
                  Response(Status.RequestEntityTooLarge, body = Body.fromString(e.getMessage))
                )
              case e: CheckpointPublisher.NotIntegrated =>
                ZIO.succeed(
                  Response(Status.ServiceUnavailable, body = Body.fromString(e.getMessage))
                )
              case e => ZIO.succeed(Response.badRequest(e.getMessage))
            }
        },

      // GET /entries?start=N&end=N — entries of [start, end) as {leaf_index, data(b64)}, capped
      // at MaxEntryPage per request and clamped to the current size, so monitors and mirrors can
      // replay the log and recompute roots themselves.
      Method.GET / "entries" ->
        Handler.fromFunctionZIO[Request] { req =>
          ZIO
            .attemptBlocking {
              val start = req.url
                .queryParam("start")
                .flatMap(_.toLongOption)
                .getOrElse(throw IllegalArgumentException("start required"))
              val end = req.url
                .queryParam("end")
                .flatMap(_.toLongOption)
                .getOrElse(throw IllegalArgumentException("end required"))
              if start < 0 || end <= start then
                throw IllegalArgumentException(s"invalid range [$start, $end)")
              val entries = storage.getEntries(start, end.min(start + MaxEntryPage))
              val items = entries
                .map(e => s"""{"leaf_index":${e.index},"data":"${B64.encodeToString(e.data)}"}""")
                .mkString(",")
              Response.json(s"""{"entries":[$items]}""")
            }
            .catchAll(e => ZIO.succeed(Response.badRequest(e.getMessage)))
        },

      // GET /checkpoint — latest signed note (text/plain, c2sp.org/tlog-checkpoint).
      Method.GET / "checkpoint" ->
        Handler.fromFunctionZIO[Request] { _ =>
          ZIO
            .attempt(sequencer.latestCheckpoint())
            .map {
              case Some(cp) => Response.text(CheckpointNote.render(cp))
              case None     => Response.notFound("no checkpoint published yet")
            }
            .catchAll(e => ZIO.succeed(Response.internalServerError(e.getMessage)))
        },

      // GET /proof/inclusion?tree_size=N&(leaf_index=N | leaf_hash=HEX)
      // leaf_hash mirrors RFC 9162 get-proof-by-hash: the lowest matching index is resolved and
      // echoed back in the response; 404 when the hash is not in the log.
      Method.GET / "proof" / "inclusion" ->
        Handler.fromFunctionZIO[Request] { req =>
          ZIO
            .attemptBlocking {
              val treeSize = req.url
                .queryParam("tree_size")
                .flatMap(_.toLongOption)
                .getOrElse(throw IllegalArgumentException("tree_size required"))
              val resolved: Either[Response, Long] =
                (req.url.queryParam("leaf_index"), req.url.queryParam("leaf_hash")) match
                  case (Some(i), _) =>
                    Right(
                      i.toLongOption.getOrElse(
                        throw IllegalArgumentException(s"invalid leaf_index: $i")
                      )
                    )
                  case (None, Some(hex)) =>
                    val leafHash =
                      try java.util.HexFormat.of().parseHex(hex)
                      catch
                        case _: Exception =>
                          throw IllegalArgumentException("leaf_hash must be hex-encoded")
                    storage
                      .findLeafIndex(leafHash)
                      .toRight(Response.notFound(s"no entry with leaf_hash $hex"))
                  case (None, None) =>
                    throw IllegalArgumentException("leaf_index or leaf_hash required")
              resolved match
                case Left(notFound) => notFound
                case Right(leafIndex) =>
                  if leafIndex < 0 || leafIndex >= treeSize then
                    throw IllegalArgumentException(
                      s"leaf_index $leafIndex out of range for tree_size $treeSize"
                    )
                  val hashes = storage.leafHashes(0L, treeSize).toList
                  val proof = MerkleTree.inclusionProofFromHashes(leafIndex.toInt, hashes)
                  val path = proof.map(h => s""""${B64.encodeToString(h)}"""").mkString(",")
                  Response.json(
                    s"""{"leaf_index":$leafIndex,"tree_size":$treeSize,"audit_path":[$path]}"""
                  )
            }
            .catchAll(e => ZIO.succeed(Response.badRequest(e.getMessage)))
        },

      // GET /bundle?leaf_index=N — offline-verifiable proof bundle (SPEC §8) for one entry,
      // against the latest checkpoint. Sealed with an RFC 3161 token when a TSA is configured;
      // a TSA failure is a 502, never a silently unsealed bundle.
      Method.GET / "bundle" ->
        Handler.fromFunctionZIO[Request] { req =>
          ZIO
            .attemptBlocking {
              val leafIndex = req.url
                .queryParam("leaf_index")
                .flatMap(_.toLongOption)
                .getOrElse(throw IllegalArgumentException("leaf_index required"))
              if leafIndex < 0 then throw IllegalArgumentException("leaf_index must be >= 0")
              storage.latestCheckpoint() match
                case None => Response.notFound("no checkpoint published yet")
                case Some(cp) if leafIndex >= cp.treeSize =>
                  Response.notFound(
                    s"leaf $leafIndex not yet integrated (latest checkpoint size ${cp.treeSize})"
                  )
                case Some(cp) =>
                  val entry = storage
                    .getEntry(leafIndex)
                    .getOrElse(throw IllegalStateException(s"entry $leafIndex missing"))
                  val hashes = storage.leafHashes(0L, cp.treeSize).toList
                  val proof = MerkleTree.inclusionProofFromHashes(leafIndex.toInt, hashes)
                  val tst = tsa.map(_.tokenFor(cp)) match
                    case Some(Left(err)) => throw TsaUnavailable(err)
                    case Some(Right(t))  => Some(t)
                    case None            => None
                  val bundle =
                    ProofBundle(entry.data, leafIndex, proof, CheckpointNote.render(cp), tst)
                  Response
                    .json(ProofBundleCodec.render(bundle))
            }
            .catchAll {
              case TsaUnavailable(err) =>
                ZIO.succeed(Response(Status.BadGateway, body = Body.fromString(err)))
              case e => ZIO.succeed(Response.badRequest(e.getMessage))
            }
        },

      // GET /tlog-proof?leaf_index=N — c2sp.org/tlog-proof@v1 (text/plain) for one entry against
      // the latest checkpoint: the ecosystem interchange proof format. Unlike /bundle it carries
      // no entry bytes and no RFC 3161 token — relying parties hold the entry out of band.
      Method.GET / "tlog-proof" ->
        Handler.fromFunctionZIO[Request] { req =>
          ZIO
            .attemptBlocking {
              val leafIndex = req.url
                .queryParam("leaf_index")
                .flatMap(_.toLongOption)
                .getOrElse(throw IllegalArgumentException("leaf_index required"))
              if leafIndex < 0 then throw IllegalArgumentException("leaf_index must be >= 0")
              storage.latestCheckpoint() match
                case None => Response.notFound("no checkpoint published yet")
                case Some(cp) if leafIndex >= cp.treeSize =>
                  Response.notFound(
                    s"leaf $leafIndex not yet integrated (latest checkpoint size ${cp.treeSize})"
                  )
                case Some(cp) =>
                  val hashes = storage.leafHashes(0L, cp.treeSize).toList
                  val proof = MerkleTree.inclusionProofFromHashes(leafIndex.toInt, hashes)
                  Response.text(
                    TlogProofCodec.render(
                      TlogProof(leafIndex, proof, CheckpointNote.render(cp), extra = None)
                    )
                  )
            }
            .catchAll(e => ZIO.succeed(Response.badRequest(e.getMessage)))
        },

      // GET /proof/consistency?first=N&second=N
      Method.GET / "proof" / "consistency" ->
        Handler.fromFunctionZIO[Request] { req =>
          ZIO
            .attempt {
              val first = req.url
                .queryParam("first")
                .flatMap(_.toLongOption)
                .getOrElse(throw IllegalArgumentException("first required"))
              val second = req.url
                .queryParam("second")
                .flatMap(_.toLongOption)
                .getOrElse(throw IllegalArgumentException("second required"))
              if first < 0 || first > second then
                throw IllegalArgumentException(s"first $first must be in [0, $second]")
              val hashes = storage.leafHashes(0L, second).toList
              val proof = MerkleTree.consistencyProofFromHashes(first.toInt, hashes)
              val path = proof.map(h => s""""${B64.encodeToString(h)}"""").mkString(",")
              Response.json(s"""{"first":$first,"second":$second,"proof_path":[$path]}""")
            }
            .catchAll(e => ZIO.succeed(Response.badRequest(e.getMessage)))
        }
    )

  /** The configured TSA could not produce a token for the bundle being exported. */
  private final case class TsaUnavailable(err: String) extends RuntimeException(err)

  /** Submitted entry exceeds the configured size cap (HTTP 413). */
  private final case class EntryTooLarge(size: Int, max: Int)
      extends RuntimeException(s"entry is $size bytes; this log accepts at most $max")
