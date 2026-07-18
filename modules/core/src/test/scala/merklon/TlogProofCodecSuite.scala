// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon

/** c2sp.org/tlog-proof@v1 rendering and parsing (SPEC.md §8.4). */
class TlogProofCodecSuite extends munit.FunSuite:

  private val origin = "test.merklon/log"

  /** A realistic embedded checkpoint note: body + log signature line. */
  private def noteText(): String =
    val attestor = CheckpointAttestor.generateEd25519(origin)
    val entries = List("a", "b", "c").map(_.getBytes("UTF-8"))
    val root = MerkleTree.root(entries)
    val body = CheckpointNote.noteBody(origin, entries.size.toLong, root)
    val sig = NoteSignature(attestor.keyName, attestor.keyId, attestor.sign(body.getBytes("UTF-8")))
    CheckpointNote.render(Checkpoint(origin, entries.size.toLong, root, 0L, Vector(sig)))

  private def sampleProof(extra: Option[Array[Byte]]): TlogProof =
    TlogProof(
      leafIndex = 1L,
      inclusionProof = List(Array.fill[Byte](32)(0x01), Array.fill[Byte](32)(0x02)),
      checkpointNote = noteText(),
      extra = extra
    )

  test("round-trips without extra data") {
    val p = sampleProof(None)
    val text = TlogProofCodec.render(p)
    assert(text.startsWith(TlogProofCodec.Header + "\nindex 1\n"), text.take(60))
    val parsed = TlogProofCodec.parse(text).fold(fail(_), identity)
    assertEquals(parsed.leafIndex, p.leafIndex)
    assertEquals(
      parsed.inclusionProof.map(MerkleTree.toHex),
      p.inclusionProof.map(MerkleTree.toHex)
    )
    assertEquals(parsed.checkpointNote, p.checkpointNote)
    assertEquals(parsed.extra, None)
  }

  test("round-trips with extra data (opaque, unauthenticated)") {
    val p = sampleProof(Some("vrf-proof-bytes".getBytes("UTF-8")))
    val parsed = TlogProofCodec.parse(TlogProofCodec.render(p)).fold(fail(_), identity)
    assertEquals(parsed.extra.map(String(_, "UTF-8")), Some("vrf-proof-bytes"))
  }

  test("the embedded checkpoint survives verbatim, signatures included") {
    val p = sampleProof(None)
    val parsed = TlogProofCodec.parse(TlogProofCodec.render(p)).fold(fail(_), identity)
    // Byte-for-byte: the note's own blank line and em-dash signature lines are intact.
    assertEquals(parsed.checkpointNote, p.checkpointNote)
    assert(CheckpointNote.parse(parsed.checkpointNote).isRight)
  }

  test("an empty inclusion proof (single-leaf tree) renders and parses") {
    val p = sampleProof(None).copy(leafIndex = 0L, inclusionProof = Nil)
    val parsed = TlogProofCodec.parse(TlogProofCodec.render(p)).fold(fail(_), identity)
    assertEquals(parsed.inclusionProof, Nil)
  }

  test("malformed documents are rejected") {
    val good = TlogProofCodec.render(sampleProof(None))
    assert(TlogProofCodec.parse("").isLeft, "empty document")
    assert(TlogProofCodec.parse(good.replace("@v1", "@v2")).isLeft, "unknown header")
    assert(TlogProofCodec.parse(good.replace("index 1", "index 01")).isLeft, "leading zero")
    assert(TlogProofCodec.parse(good.replace("index 1", "index -1")).isLeft, "negative index")
    assert(TlogProofCodec.parse(good.replace("index 1", "size 1")).isLeft, "missing index line")
    val badHash = good.replaceFirst(
      java.util.Base64.getEncoder.encodeToString(Array.fill[Byte](32)(0x01)),
      java.util.Base64.getEncoder.encodeToString(Array.fill[Byte](16)(0x01))
    )
    assert(TlogProofCodec.parse(badHash).isLeft, "16-byte proof hash")
  }
