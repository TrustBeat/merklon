// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon

trait AppendAuthorizer:
  def authorize(data: Array[Byte]): Boolean

object AppendAuthorizer:
  val NoOp: AppendAuthorizer = _ => true
