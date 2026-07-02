// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon.storage.pg

import merklon.{Checkpoint, LogEntry, NoteSignature, StorageBackend}

import java.sql.{Connection, DriverManager, PreparedStatement}

/** PostgreSQL-backed [[merklon.StorageBackend]] — the default persistence for operating a log.
  *
  * Design notes:
  *   - Entries are stored with an explicit contiguous 0-based `idx`; the next index is computed
  *     inside a transaction holding a Postgres advisory lock, so appends are safe even when several
  *     server processes share one database.
  *   - Checkpoints are append-only rows; `saveCheckpoint` rejects a `tree_size` smaller than the
  *     latest persisted one — a shrinking log is exactly the corruption this system exists to
  *     prevent, so storage refuses to record it.
  *   - Plain JDBC over a single connection, `synchronized` like the in-memory backend. Pooling is
  *     an operational concern for later; the sequencer is single-writer by design.
  */
final class PostgresStorageBackend private (conn: Connection) extends StorageBackend, AutoCloseable:

  import PostgresStorageBackend.AdvisoryLockKey

  def append(leafHash: Array[Byte], data: Array[Byte]): Long = synchronized {
    inTransaction {
      exec("SELECT pg_advisory_xact_lock(?)")(_.setLong(1, AdvisoryLockKey))
      val ps = conn.prepareStatement(
        """INSERT INTO entries(idx, leaf_hash, data, submitted_at)
          |SELECT COALESCE(MAX(idx) + 1, 0), ?, ?, ? FROM entries
          |RETURNING idx""".stripMargin
      )
      try
        ps.setBytes(1, leafHash)
        ps.setBytes(2, data)
        ps.setLong(3, System.currentTimeMillis())
        val rs = ps.executeQuery()
        rs.next()
        rs.getLong(1)
      finally ps.close()
    }
  }

  def getEntry(index: Long): Option[LogEntry] = synchronized {
    val ps = conn.prepareStatement(
      "SELECT leaf_hash, data, submitted_at FROM entries WHERE idx = ?"
    )
    try
      ps.setLong(1, index)
      val rs = ps.executeQuery()
      if rs.next() then Some(LogEntry(index, rs.getBytes(1), rs.getBytes(2), rs.getLong(3)))
      else None
    finally ps.close()
  }

  def getEntries(from: Long, until: Long): Vector[LogEntry] = synchronized {
    val ps = conn.prepareStatement(
      """SELECT idx, leaf_hash, data, submitted_at FROM entries
        |WHERE idx >= ? AND idx < ? ORDER BY idx""".stripMargin
    )
    try
      ps.setLong(1, from)
      ps.setLong(2, until)
      val rs = ps.executeQuery()
      val out = Vector.newBuilder[LogEntry]
      while rs.next() do
        out += LogEntry(rs.getLong(1), rs.getBytes(2), rs.getBytes(3), rs.getLong(4))
      out.result()
    finally ps.close()
  }

  def findLeafIndex(leafHash: Array[Byte]): Option[Long] = synchronized {
    val ps = conn.prepareStatement(
      "SELECT idx FROM entries WHERE leaf_hash = ? ORDER BY idx LIMIT 1"
    )
    try
      ps.setBytes(1, leafHash)
      val rs = ps.executeQuery()
      if rs.next() then Some(rs.getLong(1)) else None
    finally ps.close()
  }

  def size: Long = synchronized {
    val ps = conn.prepareStatement("SELECT COUNT(*) FROM entries")
    try
      val rs = ps.executeQuery()
      rs.next()
      rs.getLong(1)
    finally ps.close()
  }

  def leafHashes(from: Long, until: Long): Vector[Array[Byte]] = synchronized {
    val ps = conn.prepareStatement(
      "SELECT leaf_hash FROM entries WHERE idx >= ? AND idx < ? ORDER BY idx"
    )
    try
      ps.setLong(1, from)
      ps.setLong(2, until)
      val rs = ps.executeQuery()
      val out = Vector.newBuilder[Array[Byte]]
      while rs.next() do out += rs.getBytes(1)
      out.result()
    finally ps.close()
  }

  def saveCheckpoint(cp: Checkpoint): Unit = synchronized {
    inTransaction {
      exec("SELECT pg_advisory_xact_lock(?)")(_.setLong(1, AdvisoryLockKey))
      latestCheckpointLocked().foreach { latest =>
        require(
          cp.treeSize >= latest.treeSize,
          s"refusing checkpoint with tree_size ${cp.treeSize} < latest ${latest.treeSize} " +
            "(a transparency log never shrinks)"
        )
      }
      val ps = conn.prepareStatement(
        """INSERT INTO checkpoints(origin, tree_size, root_hash, signed_at)
          |VALUES (?, ?, ?, ?) RETURNING id""".stripMargin
      )
      val id =
        try
          ps.setString(1, cp.origin)
          ps.setLong(2, cp.treeSize)
          ps.setBytes(3, cp.rootHash)
          ps.setLong(4, cp.signedAt)
          val rs = ps.executeQuery()
          rs.next()
          rs.getLong(1)
        finally ps.close()
      val sigPs = conn.prepareStatement(
        """INSERT INTO checkpoint_signatures(checkpoint_id, ord, key_name, key_id, sig)
          |VALUES (?, ?, ?, ?, ?)""".stripMargin
      )
      try
        cp.signatures.zipWithIndex.foreach { case (s, ord) =>
          sigPs.setLong(1, id)
          sigPs.setInt(2, ord)
          sigPs.setString(3, s.keyName)
          sigPs.setBytes(4, s.keyId)
          sigPs.setBytes(5, s.sig)
          sigPs.addBatch()
        }
        sigPs.executeBatch()
      finally sigPs.close()
    }
  }

  def latestCheckpoint(): Option[Checkpoint] = synchronized(latestCheckpointLocked())

  private def latestCheckpointLocked(): Option[Checkpoint] =
    val ps = conn.prepareStatement(
      """SELECT id, origin, tree_size, root_hash, signed_at
        |FROM checkpoints ORDER BY id DESC LIMIT 1""".stripMargin
    )
    try
      val rs = ps.executeQuery()
      if !rs.next() then None
      else
        val id = rs.getLong(1)
        val cp = Checkpoint(rs.getString(2), rs.getLong(3), rs.getBytes(4), rs.getLong(5), Vector())
        Some(cp.copy(signatures = signaturesFor(id)))
    finally ps.close()

  private def signaturesFor(checkpointId: Long): Vector[NoteSignature] =
    val ps = conn.prepareStatement(
      """SELECT key_name, key_id, sig FROM checkpoint_signatures
        |WHERE checkpoint_id = ? ORDER BY ord""".stripMargin
    )
    try
      ps.setLong(1, checkpointId)
      val rs = ps.executeQuery()
      val out = Vector.newBuilder[NoteSignature]
      while rs.next() do out += NoteSignature(rs.getString(1), rs.getBytes(2), rs.getBytes(3))
      out.result()
    finally ps.close()

  def close(): Unit = synchronized(conn.close())

  private def inTransaction[A](body: => A): A =
    conn.setAutoCommit(false)
    try
      val a = body
      conn.commit()
      a
    catch
      case e: Throwable =>
        conn.rollback()
        throw e
    finally conn.setAutoCommit(true)

  private def exec(sql: String)(bind: PreparedStatement => Unit): Unit =
    val ps = conn.prepareStatement(sql)
    try
      bind(ps)
      ps.execute()
    finally ps.close()

object PostgresStorageBackend:

  /** Advisory-lock key guarding append/index assignment; arbitrary but must be stable. */
  private val AdvisoryLockKey: Long = 0x6d65726b6c6f6eL // "merklon"

  private val Schema =
    """CREATE TABLE IF NOT EXISTS entries(
      |  idx          BIGINT PRIMARY KEY,
      |  leaf_hash    BYTEA  NOT NULL,
      |  data         BYTEA  NOT NULL,
      |  submitted_at BIGINT NOT NULL
      |);
      |CREATE INDEX IF NOT EXISTS entries_leaf_hash_idx ON entries(leaf_hash);
      |CREATE TABLE IF NOT EXISTS checkpoints(
      |  id        BIGSERIAL PRIMARY KEY,
      |  origin    TEXT   NOT NULL,
      |  tree_size BIGINT NOT NULL,
      |  root_hash BYTEA  NOT NULL,
      |  signed_at BIGINT NOT NULL
      |);
      |CREATE TABLE IF NOT EXISTS checkpoint_signatures(
      |  checkpoint_id BIGINT NOT NULL REFERENCES checkpoints(id) ON DELETE CASCADE,
      |  ord           INT    NOT NULL,
      |  key_name      TEXT   NOT NULL,
      |  key_id        BYTEA  NOT NULL,
      |  sig           BYTEA  NOT NULL,
      |  PRIMARY KEY (checkpoint_id, ord)
      |);""".stripMargin

  /** Connect and ensure the schema exists. Caller owns the returned backend (`close()`). */
  def apply(jdbcUrl: String, user: String, password: String): PostgresStorageBackend =
    val conn = DriverManager.getConnection(jdbcUrl, user, password)
    val st = conn.createStatement()
    try st.execute(Schema)
    finally st.close()
    new PostgresStorageBackend(conn)
