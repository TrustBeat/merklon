// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon.server.witness

import merklon.{Checkpoint, CheckpointNote, WitnessStateStore}

import java.nio.file.{Files, Path, StandardCopyOption}
import java.security.MessageDigest

/** Durable witness state: one signed-note file per origin, named by the origin's SHA-256 (hex) so
  * arbitrary origin strings cannot influence the path.
  *
  * Writes are atomic (temp file + move) — a crash mid-write leaves the previous state intact. A
  * file that exists but does not parse is treated as corruption and load fails loudly: silently
  * falling back to trust-on-first-use would erase the witness's consistency guarantee.
  */
final class FileWitnessStateStore(dir: Path) extends WitnessStateStore:
  Files.createDirectories(dir)

  def latest(origin: String): Option[Checkpoint] = synchronized {
    val f = fileFor(origin)
    if !Files.exists(f) then None
    else
      CheckpointNote.parse(Files.readString(f)) match
        case Right(cp) => Some(cp)
        case Left(err) =>
          throw IllegalStateException(s"corrupt witness state for '$origin' at $f: $err")
  }

  def save(cp: Checkpoint): Unit = synchronized {
    val target = fileFor(cp.origin)
    val tmp = target.resolveSibling(target.getFileName.toString + ".tmp")
    Files.writeString(tmp, CheckpointNote.render(cp))
    Files.move(
      tmp,
      target,
      StandardCopyOption.ATOMIC_MOVE,
      StandardCopyOption.REPLACE_EXISTING
    )
  }

  private def fileFor(origin: String): Path =
    val digest = MessageDigest.getInstance("SHA-256").digest(origin.getBytes("UTF-8"))
    dir.resolve(digest.map(b => f"${b & 0xff}%02x").mkString + ".note")
