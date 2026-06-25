// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon

/** Inclusion + consistency proof tests.
  *
  * The pinned expectations are the canonical RFC 6962 reference tree (the well-known 8-entry CT /
  * Trillian test vectors); the Merkle tree is unchanged in RFC 9162, so these vectors remain valid.
  * The hex constants below were produced by an independent from-scratch Python/hashlib oracle, so
  * these tests check the Scala core against an outside reference rather than against itself.
  */
class ProofSuite extends munit.FunSuite:

  // RFC 6962 canonical reference leaves (size-8 test tree).
  private val leaves: List[Array[Byte]] = List(
    "",
    "00",
    "10",
    "2021",
    "3031",
    "40414243",
    "5051525354555657",
    "606162636465666768696a6b6c6d6e6f"
  ).map(fromHex)

  private def fromHex(s: String): Array[Byte] =
    s.grouped(2).filter(_.nonEmpty).map(Integer.parseInt(_, 16).toByte).toArray

  // Roots for tree sizes 0..8 (independent oracle).
  private val roots: Vector[String] = Vector(
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"
  )

  // --- pinned roots --------------------------------------------------------

  test("RFC 6962 reference roots for sizes 0..8"):
    (0 to 8).foreach { n =>
      assertEquals(MerkleTree.toHex(MerkleTree.root(leaves.take(n))), roots(n), s"root size $n")
    }

  // --- inclusion: pinned audit paths ---------------------------------------

  // Expected inclusion proofs for every leaf in the size-8 tree (independent oracle).
  private val inclusion8: Map[Int, List[String]] = Map(
    0 -> List(
      "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
      "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
      "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"
    ),
    1 -> List(
      "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
      "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
      "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"
    ),
    2 -> List(
      "07506a85fd9dd2f120eb694f86011e5bb4662e5c415a62917033d4a9624487e7",
      "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
      "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"
    ),
    3 -> List(
      "0298d122906dcfc10892cb53a73992fc5b9f493ea4c9badb27b791b4127a7fe7",
      "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
      "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"
    ),
    4 -> List(
      "4271a26be0d8a84f0bd54c8c302e7cb3a3b5d1fa6780a40bcce2873477dab658",
      "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
      "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"
    ),
    5 -> List(
      "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
      "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
      "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"
    ),
    6 -> List(
      "46f6ffadd3d06a09ff3c5860d2755c8b9819db7df44251788c7d8e3180de8eb1",
      "0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
      "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"
    ),
    7 -> List(
      "b08693ec2e721597130641e8211e7eedccb4c26413963eee6c1e2ed16ffb1a5f",
      "0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
      "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"
    )
  )

  test("RFC 6962 inclusion proofs match reference (size-8 tree)"):
    inclusion8.foreach { (m, expected) =>
      val proof = MerkleTree.inclusionProof(m, leaves).map(MerkleTree.toHex)
      assertEquals(proof, expected, s"inclusion proof for leaf $m")
    }

  test("generated inclusion proofs verify for every leaf and tree size 1..8"):
    (1 to 8).foreach { n =>
      val sub = leaves.take(n)
      val root = MerkleTree.root(sub)
      (0 until n).foreach { m =>
        val proof = MerkleTree.inclusionProof(m, sub)
        assert(
          MerkleTree.verifyInclusion(m, n, MerkleTree.leafHash(sub(m)), proof, root),
          s"verify inclusion m=$m n=$n"
        )
      }
    }

  test("inclusion verification rejects a tampered leaf"):
    val n = 8
    val root = MerkleTree.root(leaves)
    val proof = MerkleTree.inclusionProof(3, leaves)
    val wrong = MerkleTree.leafHash("not the real leaf".getBytes("UTF-8"))
    assert(!MerkleTree.verifyInclusion(3, n, wrong, proof, root))

  test("inclusion verification rejects a tampered proof node"):
    val n = 8
    val root = MerkleTree.root(leaves)
    val proof = MerkleTree.inclusionProof(3, leaves)
    val bad = proof.head.clone(); bad(0) = (bad(0) ^ 0xff).toByte
    assert(
      !MerkleTree.verifyInclusion(3, n, MerkleTree.leafHash(leaves(3)), bad :: proof.tail, root)
    )

  test("inclusion verification rejects the wrong leaf index"):
    val n = 8
    val root = MerkleTree.root(leaves)
    val proof = MerkleTree.inclusionProof(3, leaves)
    assert(!MerkleTree.verifyInclusion(4, n, MerkleTree.leafHash(leaves(3)), proof, root))

  // --- consistency: pinned proofs ------------------------------------------

  private val consistencyVectors: List[(Int, Int, List[String])] = List(
    (1, 1, Nil),
    (
      1,
      8,
      List(
        "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
        "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
        "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"
      )
    ),
    (
      6,
      8,
      List(
        "0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
        "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
        "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"
      )
    ),
    (
      2,
      5,
      List(
        "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
        "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b"
      )
    ),
    (4, 8, List("6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"))
  )

  test("RFC 6962 consistency proofs match reference"):
    consistencyVectors.foreach { (first, second, expected) =>
      val proof = MerkleTree.consistencyProof(first, leaves.take(second)).map(MerkleTree.toHex)
      assertEquals(proof, expected, s"consistency proof $first -> $second")
    }

  test("generated consistency proofs verify for all 0 <= first <= second <= 8"):
    (0 to 8).foreach { second =>
      val sub = leaves.take(second)
      val sr = MerkleTree.root(sub)
      (0 to second).foreach { first =>
        val fr = MerkleTree.root(leaves.take(first))
        val proof = MerkleTree.consistencyProof(first, sub)
        assert(
          MerkleTree.verifyConsistency(first, second, fr, sr, proof),
          s"verify consistency $first -> $second"
        )
      }
    }

  test("consistency verification rejects a forked (rewritten) history"):
    // Same size, but the size-5 tree was built on a tampered leaf 2.
    val honest = leaves.take(5)
    val tampered = honest.updated(2, "evil".getBytes("UTF-8"))
    val first = 3
    val fr = MerkleTree.root(honest.take(first))
    val proof = MerkleTree.consistencyProof(first, honest)
    val forkedSr = MerkleTree.root(tampered)
    assert(!MerkleTree.verifyConsistency(first, 5, fr, forkedSr, proof))

  test("consistency verification rejects first > second"):
    val fr = MerkleTree.root(leaves.take(5))
    val sr = MerkleTree.root(leaves.take(3))
    assert(!MerkleTree.verifyConsistency(5, 3, fr, sr, Nil))
