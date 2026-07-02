// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon.server

import merklon.*
import zio.*
import zio.http.*

import java.util.Base64

/** ZIO HTTP routes for the merklon log API (SPEC.md §6).
  *
  * POST /entries appends and immediately publishes a checkpoint so the proof endpoints work without
  * delay. A production deployment would batch entries on a timed cadence instead.
  */
object LogServer:

  private val B64 = Base64.getEncoder

  def make(sequencer: Sequencer, storage: StorageBackend): Routes[Any, Nothing] =
    Routes(
      // POST /entries — append entry, publish checkpoint, return {"leaf_index":N,"tree_size":M}.
      Method.POST / "entries" ->
        Handler.fromFunctionZIO[Request] { req =>
          (for
            data <- req.body.asArray
            idx <- ZIO.attempt(sequencer.append(data))
            cp <- ZIO.attempt(sequencer.publishCheckpoint())
          yield Response.json(s"""{"leaf_index":$idx,"tree_size":${cp.treeSize}}"""))
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
