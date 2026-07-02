// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon

import scala.collection.mutable

/** Durable state for a witness: the last checkpoint it cosigned, per origin.
  *
  * This is the witness's only trust anchor over time — losing it silently would reset the witness
  * to trust-on-first-use, so operators should treat the store as append-critical. The stored
  * checkpoint keeps its log signature lines: a stored checkpoint is one half of a future split-view
  * evidence pair.
  */
trait WitnessStateStore:
  /** The last cosigned checkpoint for `origin`, if any. */
  def latest(origin: String): Option[Checkpoint]

  /** Record `cp` as the last cosigned checkpoint for its origin. */
  def save(cp: Checkpoint): Unit

/** Non-durable store for tests and library embedding. */
final class InMemoryWitnessStateStore extends WitnessStateStore:
  private val byOrigin = mutable.Map.empty[String, Checkpoint]

  def latest(origin: String): Option[Checkpoint] = synchronized(byOrigin.get(origin))

  def save(cp: Checkpoint): Unit = synchronized {
    byOrigin.update(cp.origin, cp)
  }
