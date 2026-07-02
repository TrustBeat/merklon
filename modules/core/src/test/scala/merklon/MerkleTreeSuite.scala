// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon

class MerkleTreeSuite extends munit.FunSuite:

  // RFC 6962: the Merkle Tree Hash of an empty list is SHA-256 of the empty input.
  test("empty tree hash == SHA-256(\"\")"):
    assertEquals(
      MerkleTree.toHex(MerkleTree.root(Nil)),
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )

  test("single-entry root == its leaf hash"):
    val d = "hello".getBytes("UTF-8")
    assertEquals(
      MerkleTree.toHex(MerkleTree.root(List(d))),
      MerkleTree.toHex(MerkleTree.leafHash(d))
    )

  test("two-entry root == nodeHash(leaf(a), leaf(b))"):
    val a = "a".getBytes("UTF-8")
    val b = "b".getBytes("UTF-8")
    assertEquals(
      MerkleTree.toHex(MerkleTree.root(List(a, b))),
      MerkleTree.toHex(MerkleTree.nodeHash(MerkleTree.leafHash(a), MerkleTree.leafHash(b)))
    )

  test("root is order-sensitive"):
    val a = "a".getBytes("UTF-8")
    val b = "b".getBytes("UTF-8")
    assertNotEquals(
      MerkleTree.toHex(MerkleTree.root(List(a, b))),
      MerkleTree.toHex(MerkleTree.root(List(b, a)))
    )

  test("leaf/node domain separation: leaf(x) != node(x, empty-ish)"):
    val x = Array[Byte](1, 2, 3)
    assertNotEquals(
      MerkleTree.toHex(MerkleTree.leafHash(x)),
      MerkleTree.toHex(MerkleTree.nodeHash(x, Array.emptyByteArray))
    )
