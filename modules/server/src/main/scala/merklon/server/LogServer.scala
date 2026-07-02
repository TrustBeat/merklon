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

  def make(
      sequencer: Sequencer,
      storage: StorageBackend,
      publisher: CheckpointPublisher,
      tsa: Option[TsaClient] = None
  ): Routes[Any, Nothing] =
    Routes(
      // POST /entries — append entry, await the checkpoint that integrates it, return
      // {"leaf_index":N,"tree_size":M}. 503 if no checkpoint covered it in time (the entry
      // itself is durably appended either way).
      Method.POST / "entries" ->
        Handler.fromFunctionZIO[Request] { req =>
          (for
            data <- req.body.asArray
            result <- publisher.append(data)
            (idx, cp) = result
          yield Response.json(s"""{"leaf_index":$idx,"tree_size":${cp.treeSize}}"""))
            .catchAll {
              case e: CheckpointPublisher.NotIntegrated =>
                ZIO.succeed(
                  Response(Status.ServiceUnavailable, body = Body.fromString(e.getMessage))
                )
              case e => ZIO.succeed(Response.badRequest(e.getMessage))
            }
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

      // GET /proof/inclusion?leaf_index=N&tree_size=N
      Method.GET / "proof" / "inclusion" ->
        Handler.fromFunctionZIO[Request] { req =>
          ZIO
            .attempt {
              val leafIndex = req.url
                .queryParam("leaf_index")
                .flatMap(_.toLongOption)
                .getOrElse(throw IllegalArgumentException("leaf_index required"))
              val treeSize = req.url
                .queryParam("tree_size")
                .flatMap(_.toLongOption)
                .getOrElse(throw IllegalArgumentException("tree_size required"))
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
