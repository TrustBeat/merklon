// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon

class ProofBundleSuite extends munit.FunSuite:

  private val note =
    "example.org/log\n3\nAAAA\n\n— example.org/log dGVzdHNpZ25hdHVyZQ==\n"

  private def sample(tst: Option[Array[Byte]]) = ProofBundle(
    entry = "hello".getBytes("UTF-8"),
    leafIndex = 2L,
    inclusionProof = List(Array[Byte](1, 2, 3), Array[Byte](4, 5)),
    checkpointNote = note,
    rfc3161Tst = tst
  )

  private def assertRoundTrips(b: ProofBundle): Unit =
    val parsed = ProofBundleCodec.parse(ProofBundleCodec.render(b)) match
      case Right(p)  => p
      case Left(err) => fail(s"parse failed: $err")
    assertEquals(parsed.leafIndex, b.leafIndex)
    assertEquals(MerkleTree.toHex(parsed.entry), MerkleTree.toHex(b.entry))
    assertEquals(
      parsed.inclusionProof.map(MerkleTree.toHex),
      b.inclusionProof.map(MerkleTree.toHex)
    )
    assertEquals(parsed.checkpointNote, b.checkpointNote)
    assertEquals(parsed.rfc3161Tst.map(MerkleTree.toHex), b.rfc3161Tst.map(MerkleTree.toHex))

  test("round-trips without a timestamp token") {
    assertRoundTrips(sample(None))
  }

  test("round-trips with a timestamp token") {
    assertRoundTrips(sample(Some(Array[Byte](9, 8, 7, 6))))
  }

  test("round-trips an empty inclusion proof (single-leaf tree)") {
    assertRoundTrips(sample(None).copy(inclusionProof = Nil, leafIndex = 0L))
  }

  test("embedded checkpoint note survives byte-exactly (em dash, newlines)") {
    val parsed = ProofBundleCodec.parse(ProofBundleCodec.render(sample(None))).toOption.get
    assertEquals(parsed.checkpointNote, note)
    assert(CheckpointNote.parse(parsed.checkpointNote).isRight, "embedded note must stay parseable")
  }

  test("rejects an unknown format identifier") {
    val doc = ProofBundleCodec.render(sample(None)).replace("merklon-bundle/v1", "other/v9")
    assertEquals(ProofBundleCodec.parse(doc), Left("unsupported bundle format: other/v9"))
  }

  test("rejects missing mandatory fields") {
    for key <- List("format", "leaf_index", "entry", "inclusion_proof", "checkpoint") do
      val doc = ProofBundleCodec.render(sample(None)).replace(s""""$key"""", s""""x_$key"""")
      assert(ProofBundleCodec.parse(doc).isLeft, s"parse must fail without '$key'")
  }

  test("rejects invalid base64 in the entry") {
    val doc = ProofBundleCodec
      .render(sample(None))
      .replace(s""""entry": "aGVsbG8="""", s""""entry": "!!not-base64!!"""")
    assertEquals(ProofBundleCodec.parse(doc), Left("invalid base64 in entry"))
  }
