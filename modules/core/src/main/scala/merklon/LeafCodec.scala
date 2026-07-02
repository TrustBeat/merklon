// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon

/** Defines what bytes get leaf-hashed for a submitted entry: `leaf = H(encode(data))`. The original
  * submitted bytes are what gets stored and served; `encode` only shapes the hash input. A verifier
  * must apply the same codec to recompute leaf hashes.
  */
trait LeafCodec:
  /** Canonical hash input for `data`; throws IllegalArgumentException on invalid input. */
  def encode(data: Array[Byte]): Array[Byte]

object LeafCodec:
  val Identity: LeafCodec = data => data

  /** `structured-event/v1` (SPEC.md §9): strictly parses the submitted JSON event and re-emits it
    * canonically, so producers' field order, whitespace, and escape choices cannot change the leaf
    * hash. Invalid events are rejected, never silently normalized.
    */
  val StructuredEventJsonV1: LeafCodec = data =>
    StructuredEvent.parse(String(data, "UTF-8")) match
      case Right(event) => StructuredEvent.canonical(event)
      case Left(err)    => throw IllegalArgumentException(s"invalid structured-event/v1: $err")

  /** Codec selection by wire name — shared by the server (`MERKLON_CODEC`) and the CLI. */
  def named(name: String): Option[LeafCodec] = name match
    case "identity"                                 => Some(Identity)
    case "structured-event" | "structured-event/v1" => Some(StructuredEventJsonV1)
    case _                                          => None
