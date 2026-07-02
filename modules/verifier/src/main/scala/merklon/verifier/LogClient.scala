// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon.verifier

/** Fetches transparency-log payloads from a running merklon HTTP server. */
trait LogClient:
  def fetchCheckpoint(): String
  def fetchInclusionProof(leafIndex: Long, treeSize: Long): String
  def fetchInclusionProofByHash(leafHashHex: String, treeSize: Long): String
  def fetchConsistencyProof(first: Long, second: Long): String
