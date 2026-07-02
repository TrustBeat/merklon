// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon.verifier

import merklon.{Checkpoint, CheckpointNote}

/** Parses a c2sp.org/tlog-checkpoint + signed-note text into a [[merklon.Checkpoint]].
  *
  * The implementation lives in the core ([[merklon.CheckpointNote.parse]]) because the witness
  * needs it too; this object remains the verifier-side entry point.
  */
object CheckpointParser:
  def parse(note: String): Either[String, Checkpoint] = CheckpointNote.parse(note)
