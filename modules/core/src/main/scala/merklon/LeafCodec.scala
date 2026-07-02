// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon

trait LeafCodec:
  def encode(data: Array[Byte]): Array[Byte]

object LeafCodec:
  val Identity: LeafCodec = data => data
