// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon

class StructuredEventSuite extends munit.FunSuite:

  private val codec = LeafCodec.StructuredEventJsonV1

  private def leafHex(json: String): String =
    MerkleTree.toHex(MerkleTree.leafHash(codec.encode(json.getBytes("UTF-8"))))

  test("canonical form is exact and key-ordered") {
    val event = StructuredEvent(
      actor = "alice",
      action = "login",
      source = "auth-svc",
      time = 1750000000000L,
      prevRef = Some(Array[Byte](0x0a, 0x0b)),
      payload = Some("ok")
    )
    assertEquals(
      String(StructuredEvent.canonical(event), "UTF-8"),
      """{"action":"login","actor":"alice","payload":"ok","prev_ref":"0a0b","source":"auth-svc","time":1750000000000}"""
    )
  }

  test("field order, whitespace, and escape variants produce the same leaf hash") {
    val variants = List(
      """{"actor":"alice","action":"login","source":"auth-svc","time":42}""",
      """{ "time": 42, "source": "auth-svc", "action": "login", "actor": "alice" }""",
      "{\n  \"action\": \"login\",\n  \"actor\": \"\\u0061lice\",\n  \"source\": \"auth-svc\",\n  \"time\": 42\n}"
    )
    val hashes = variants.map(leafHex).distinct
    assertEquals(hashes.size, 1, s"all variants must hash identically, got: $hashes")
  }

  test("canonical output re-parses to the same event (fixed point)") {
    val event = StructuredEvent("bob", "delete", "api", 7L, None, Some("id=9\n\"quoted\""))
    val canonical = String(StructuredEvent.canonical(event), "UTF-8")
    val reparsed = StructuredEvent.parse(canonical).fold(e => fail(s"parse: $e"), identity)
    assertEquals(reparsed.copy(prevRef = None), event.copy(prevRef = None))
    assertEquals(String(StructuredEvent.canonical(reparsed), "UTF-8"), canonical)
  }

  test("different events produce different leaf hashes") {
    val a = """{"actor":"alice","action":"login","source":"s","time":1}"""
    val b = """{"actor":"alice","action":"logout","source":"s","time":1}"""
    assertNotEquals(leafHex(a), leafHex(b))
  }

  test("rejects unknown fields (fail closed)") {
    val r =
      StructuredEvent.parse("""{"actor":"a","action":"b","source":"c","time":1,"extra":"x"}""")
    assertEquals(r, Left("unknown field 'extra'"))
  }

  test("rejects duplicate keys") {
    val r =
      StructuredEvent.parse("""{"actor":"a","actor":"b","action":"x","source":"c","time":1}""")
    assert(r.left.exists(_.contains("duplicate field 'actor'")), s"got $r")
  }

  test("rejects missing required fields") {
    val r = StructuredEvent.parse("""{"actor":"a","action":"b","time":1}""")
    assertEquals(r, Left("missing field 'source'"))
  }

  test("rejects nested structures") {
    val r =
      StructuredEvent.parse("""{"actor":"a","action":"b","source":"c","time":1,"payload":{}}""")
    assert(r.left.exists(_.contains("nesting is not allowed")), s"got $r")
  }

  test("rejects fractions, exponents, negative time, and bad prev_ref hex") {
    assert(StructuredEvent.parse("""{"actor":"a","action":"b","source":"c","time":1.5}""").isLeft)
    assert(StructuredEvent.parse("""{"actor":"a","action":"b","source":"c","time":1e3}""").isLeft)
    assert(StructuredEvent.parse("""{"actor":"a","action":"b","source":"c","time":-1}""").isLeft)
    assert(
      StructuredEvent
        .parse("""{"actor":"a","action":"b","source":"c","time":1,"prev_ref":"0A"}""")
        .isLeft,
      "uppercase hex must be rejected"
    )
  }

  test("rejects trailing content and non-object input") {
    assert(
      StructuredEvent.parse("""{"actor":"a","action":"b","source":"c","time":1} tail""").isLeft
    )
    assert(StructuredEvent.parse(""""just a string"""").isLeft)
    assert(StructuredEvent.parse("").isLeft)
  }

  test("codec.encode throws on invalid events (the sequencer turns this into a 400)") {
    intercept[IllegalArgumentException] {
      codec.encode("""{"nope":true}""".getBytes("UTF-8"))
    }
  }

  test("codec is selectable by wire name") {
    assert(LeafCodec.named("structured-event/v1").isDefined)
    assert(LeafCodec.named("structured-event").isDefined)
    assert(LeafCodec.named("identity").isDefined)
    assertEquals(LeafCodec.named("bogus"), None)
  }

  test("unicode payloads survive canonicalization byte-exactly") {
    val json = """{"actor":"ألِس","action":"login","source":"s","time":1,"payload":"data — ✓"}"""
    val canonical = codec.encode(json.getBytes("UTF-8"))
    val reparsed = StructuredEvent.parse(String(canonical, "UTF-8")).toOption.get
    assertEquals(reparsed.actor, "ألِس")
    assertEquals(reparsed.payload, Some("data — ✓"))
  }
