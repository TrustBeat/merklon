// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon

case class LogEntry(
    index: Long,
    leafHash: Array[Byte],
    data: Array[Byte],
    submittedAt: Long
)
