// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon.verifier

import merklon.*
import java.util.Arrays

class CheckpointParserSuite extends munit.FunSuite:

  private def makeCheckpoint(origin: String, treeSize: Long, root: Array[Byte]): Checkpoint =
    val attestor = CheckpointAttestor.generateEd25519(s"$origin/key")
    val body = CheckpointNote.noteBody(origin, treeSize, root)
    val sig = attestor.sign(body.getBytes("UTF-8"))
    Checkpoint(
      origin,
      treeSize,
      root,
      0L,
      Vector(NoteSignature(attestor.keyName, attestor.keyId, sig))
    )

  test("parse round-trips through CheckpointNote.render") {
    val root = Array.fill(32)(0xab.toByte)
    val cp = makeCheckpoint("test.log", 5L, root)
    val note = CheckpointNote.render(cp)

    val parsed = CheckpointParser.parse(note)
    assert(parsed.isRight, s"parse failed: $parsed")
    val p = parsed.toOption.get
    assertEquals(p.origin, "test.log")
    assertEquals(p.treeSize, 5L)
    assert(Arrays.equals(p.rootHash, root))
    assertEquals(p.signatures.size, 1)
  }

  test("parsed NoteSignature has correct keyId and sig bytes") {
    val root = Array.fill(32)(0xcd.toByte)
    val cp = makeCheckpoint("test.log", 1L, root)
    val note = CheckpointNote.render(cp)

    val p = CheckpointParser.parse(note).toOption.get
    val orig = cp.signatures.head
    val pars = p.signatures.head
    assertEquals(pars.keyName, orig.keyName)
    assert(Arrays.equals(pars.keyId, orig.keyId), "keyId mismatch")
    assert(Arrays.equals(pars.sig, orig.sig), "sig mismatch")
  }

  test("parse handles extension lines between root_hash and blank separator") {
    // Construct a note with extension lines (the spec requires verifiers to ignore them).
    val root = Array.fill(32)(0x01.toByte)
    val cp = makeCheckpoint("ext.log", 2L, root)
    val note = CheckpointNote.render(cp)
    // Insert an extension line between the root hash line and the blank separator.
    val lines = note.linesIterator.toList
    val withExtension = (lines.take(3) ++ List("x-custom: value") ++ lines.drop(3)).mkString("\n")

    val parsed = CheckpointParser.parse(withExtension)
    assert(parsed.isRight, s"should ignore extension line, got: $parsed")
    assertEquals(parsed.toOption.get.treeSize, 2L)
  }

  test("parse fails on empty string") {
    assert(CheckpointParser.parse("").isLeft)
  }

  test("parse fails when tree_size is not a number") {
    assert(CheckpointParser.parse("origin.log\nnot-a-number\nhash\n\n").isLeft)
  }

  test("parse fails when blank separator is missing") {
    assert(CheckpointParser.parse("origin.log\n5\naGVsbG8=\n").isLeft)
  }
