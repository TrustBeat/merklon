// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon.javadsl

import merklon.MerkleTree

import java.util.List as JList
import scala.jdk.CollectionConverters.*

/** Java-friendly facade over the pure Merkle core ([[merklon.MerkleTree]]).
  *
  * Every signature uses plain `java.util` and array types — no Scala collections, no `Option`, no
  * `Either` — so the library is directly usable from Java (and Kotlin) without touching the Scala
  * standard library. Callable as static methods: `Merkle.root(...)`.
  *
  * Semantics are identical to the core: RFC 9162 (Certificate Transparency 2.0) hashing, inclusion
  * proofs, and consistency proofs, pinned to the RFC 6962 reference test vectors.
  */
object Merkle:

  /** RFC 9162 §2.1.1 leaf hash: SHA-256(0x00 || data). */
  def leafHash(data: Array[Byte]): Array[Byte] =
    MerkleTree.leafHash(data)

  /** Merkle Tree Hash of the empty tree: SHA-256 of the empty string. */
  def emptyRoot(): Array[Byte] =
    MerkleTree.emptyRoot

  /** RFC 9162 Merkle Tree Hash over an ordered list of raw entries. */
  def root(entries: JList[Array[Byte]]): Array[Byte] =
    MerkleTree.root(entries.asScala.toList)

  /** Inclusion proof (audit path, leaf's sibling first) for the entry at `leafIndex`. */
  def inclusionProof(leafIndex: Int, entries: JList[Array[Byte]]): JList[Array[Byte]] =
    MerkleTree.inclusionProof(leafIndex, entries.asScala.toList).asJava

  /** Consistency proof showing the first `firstSize` entries are a prefix of `entries`. */
  def consistencyProof(firstSize: Int, entries: JList[Array[Byte]]): JList[Array[Byte]] =
    MerkleTree.consistencyProof(firstSize, entries.asScala.toList).asJava

  /** Verify an inclusion proof (RFC 9162 §2.1.3.2) without trusting whoever produced it. */
  def verifyInclusion(
      leafIndex: Int,
      treeSize: Int,
      leafHash: Array[Byte],
      proof: JList[Array[Byte]],
      expectedRoot: Array[Byte]
  ): Boolean =
    MerkleTree.verifyInclusion(leafIndex, treeSize, leafHash, proof.asScala.toList, expectedRoot)

  /** Verify a consistency proof (RFC 9162 §2.1.4.2): the size-`firstSize` tree with `firstRoot` is
    * an append-only prefix of the size-`secondSize` tree with `secondRoot`.
    */
  def verifyConsistency(
      firstSize: Int,
      secondSize: Int,
      firstRoot: Array[Byte],
      secondRoot: Array[Byte],
      proof: JList[Array[Byte]]
  ): Boolean =
    MerkleTree.verifyConsistency(firstSize, secondSize, firstRoot, secondRoot, proof.asScala.toList)

  /** Lowercase hex of a hash, for logging and comparison (never compare `byte[]` with ==). */
  def toHex(bytes: Array[Byte]): String =
    MerkleTree.toHex(bytes)
