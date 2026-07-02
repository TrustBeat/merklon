// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon

import scala.collection.mutable

final class InMemoryStorageBackend extends StorageBackend:

  private case class Row(leafHash: Array[Byte], data: Array[Byte], submittedAt: Long)

  private val rows = mutable.ArrayBuffer.empty[Row]
  private var checkpoints = Vector.empty[Checkpoint]

  def append(leafHash: Array[Byte], data: Array[Byte]): Long = synchronized {
    val index = rows.size.toLong
    rows.append(Row(leafHash.clone(), data.clone(), System.currentTimeMillis()))
    index
  }

  def getEntry(index: Long): Option[LogEntry] = synchronized {
    if index < 0 || index >= rows.size then None
    else
      val r = rows(index.toInt)
      Some(LogEntry(index, r.leafHash.clone(), r.data.clone(), r.submittedAt))
  }

  def size: Long = synchronized(rows.size.toLong)

  def leafHashes(from: Long, until: Long): Vector[Array[Byte]] = synchronized {
    rows.slice(from.toInt, until.toInt).map(_.leafHash.clone()).toVector
  }

  def saveCheckpoint(cp: Checkpoint): Unit = synchronized {
    checkpoints = checkpoints :+ cp
  }

  def latestCheckpoint(): Option[Checkpoint] = synchronized(checkpoints.lastOption)
