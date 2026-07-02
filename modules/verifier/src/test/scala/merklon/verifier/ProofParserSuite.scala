// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon.verifier

import java.util.{Arrays, Base64}

class ProofParserSuite extends munit.FunSuite:

  private val enc = Base64.getEncoder

  test("parseInclusion extracts all fields") {
    val h1 = enc.encodeToString(Array.fill(32)(0x01.toByte))
    val h2 = enc.encodeToString(Array.fill(32)(0x02.toByte))
    val json = s"""{"leaf_index":3,"tree_size":8,"audit_path":["$h1","$h2"]}"""

    val result = ProofParser.parseInclusion(json)
    assert(result.isRight, s"parse failed: $result")
    val p = result.toOption.get
    assertEquals(p.leafIndex, 3L)
    assertEquals(p.treeSize, 8L)
    assertEquals(p.auditPath.size, 2)
    assert(Arrays.equals(p.auditPath.head, Base64.getDecoder.decode(h1)))
  }

  test("parseConsistency extracts all fields") {
    val h = enc.encodeToString(Array.fill(32)(0xab.toByte))
    val json = s"""{"first":4,"second":8,"proof_path":["$h"]}"""

    val result = ProofParser.parseConsistency(json)
    assert(result.isRight, s"parse failed: $result")
    val p = result.toOption.get
    assertEquals(p.first, 4L)
    assertEquals(p.second, 8L)
    assertEquals(p.proofPath.size, 1)
    assert(Arrays.equals(p.proofPath.head, Base64.getDecoder.decode(h)))
  }

  test("parseInclusion handles empty audit_path") {
    val json = """{"leaf_index":0,"tree_size":1,"audit_path":[]}"""
    val result = ProofParser.parseInclusion(json)
    assert(result.isRight, s"parse failed: $result")
    assertEquals(result.toOption.get.auditPath, Nil)
  }

  test("parseConsistency handles empty proof_path") {
    val json = """{"first":0,"second":0,"proof_path":[]}"""
    val result = ProofParser.parseConsistency(json)
    assert(result.isRight, s"parse failed: $result")
    assertEquals(result.toOption.get.proofPath, Nil)
  }

  test("parseInclusion fails when audit_path is missing") {
    assert(ProofParser.parseInclusion("""{"leaf_index":0,"tree_size":8}""").isLeft)
  }

  test("parseConsistency fails when proof_path is missing") {
    assert(ProofParser.parseConsistency("""{"first":0,"second":8}""").isLeft)
  }

  test("parseInclusion fails on invalid base64 in audit_path") {
    val json = """{"leaf_index":0,"tree_size":8,"audit_path":["not!base64"]}"""
    assert(ProofParser.parseInclusion(json).isLeft)
  }
