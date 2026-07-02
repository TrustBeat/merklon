// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon

/** Persistence interface for the verifiable log.
  *
  * Implementations must make append and getEntry consistent: once append returns an index,
  * getEntry(index) must return the same entry for the lifetime of the backend.
  */
trait StorageBackend:
  /** Atomically append an entry; returns its 0-based index. */
  def append(leafHash: Array[Byte], data: Array[Byte]): Long

  /** Retrieve an entry by its 0-based index. */
  def getEntry(index: Long): Option[LogEntry]

  /** Entries for the half-open range [from, until), in index order. */
  def getEntries(from: Long, until: Long): Vector[LogEntry]

  /** The lowest index whose leaf hash equals `leafHash` (RFC 9162 get-proof-by-hash lookups).
    * Duplicate submissions share a leaf hash; the first occurrence wins deterministically.
    */
  def findLeafIndex(leafHash: Array[Byte]): Option[Long]

  /** Total number of entries committed to the log. */
  def size: Long

  /** Leaf hashes for the half-open range [from, until). */
  def leafHashes(from: Long, until: Long): Vector[Array[Byte]]

  /** Persist a checkpoint (may be called multiple times; latest is authoritative). */
  def saveCheckpoint(cp: Checkpoint): Unit

  /** The most recently persisted checkpoint, if any. */
  def latestCheckpoint(): Option[Checkpoint]
