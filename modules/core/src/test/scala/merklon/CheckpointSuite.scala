// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon

import java.security.{KeyFactory, Signature as JSignature}
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

class CheckpointSuite extends munit.FunSuite:

  // Reconstruct a PublicKey from raw 32-byte Ed25519 key bytes by re-wrapping in
  // SubjectPublicKeyInfo DER (always 44 bytes for Ed25519 / OID 1.3.101.112).
  private def pubKeyFromRaw(raw: Array[Byte]): java.security.PublicKey =
    val header = Array(
      0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
    ).map(_.toByte)
    KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(header ++ raw))

  test("noteBody has origin / treeSize / base64-root / trailing newline") {
    val root = Array.fill(32)(0xab.toByte)
    val body = CheckpointNote.noteBody("example.com/log", 42L, root)
    val lines = body.split('\n')
    assertEquals(lines(0), "example.com/log")
    assertEquals(lines(1), "42")
    assertEquals(lines(2), Base64.getEncoder.encodeToString(root))
    assert(body.endsWith("\n"), "body must end with newline")
  }

  test("render contains blank separator line and em-dash signature line") {
    val attestor = CheckpointAttestor.generateEd25519("test.log/key")
    val root = Array.fill(32)(0xcd.toByte)
    val origin = "test.log"
    val body = CheckpointNote.noteBody(origin, 1L, root)
    val sig = attestor.sign(body.getBytes("UTF-8"))
    val cp =
      Checkpoint(origin, 1L, root, 0L, Vector(NoteSignature(attestor.keyName, attestor.keyId, sig)))
    val note = CheckpointNote.render(cp)
    assert(note.contains("\n\n"), "blank line between body and signatures required")
    assert(note.contains("— test.log/key "), "em-dash signature line required")
  }

  test("keyId is exactly 4 bytes") {
    assertEquals(CheckpointAttestor.generateEd25519("any/key").keyId.length, 4)
  }

  test("publicKey is exactly 32 bytes") {
    assertEquals(CheckpointAttestor.generateEd25519("any/key").publicKey.length, 32)
  }

  test("Ed25519 signature verifies with the attestor's public key") {
    val attestor = CheckpointAttestor.generateEd25519("my.log/key")
    val body = "merklon.test/log\n5\naGVsbG8gd29ybGQ=\n"
    val sig = attestor.sign(body.getBytes("UTF-8"))
    val jSig = JSignature.getInstance("Ed25519")
    jSig.initVerify(pubKeyFromRaw(attestor.publicKey))
    jSig.update(body.getBytes("UTF-8"))
    assert(jSig.verify(sig))
  }

  test("signature over different body does not verify") {
    val attestor = CheckpointAttestor.generateEd25519("my.log/key")
    val body = "merklon.test/log\n5\naGVsbG8gd29ybGQ=\n"
    val sig = attestor.sign(body.getBytes("UTF-8"))
    val jSig = JSignature.getInstance("Ed25519")
    jSig.initVerify(pubKeyFromRaw(attestor.publicKey))
    jSig.update("tampered\n1\nXXXX=\n".getBytes("UTF-8"))
    assert(!jSig.verify(sig))
  }

  test("keyId is deterministic for the same key") {
    import java.security.KeyPairGenerator
    val kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
    val a1 = CheckpointAttestor.ed25519("log/k", kp)
    val a2 = CheckpointAttestor.ed25519("log/k", kp)
    assert(java.util.Arrays.equals(a1.keyId, a2.keyId))
    assert(java.util.Arrays.equals(a1.publicKey, a2.publicKey))
  }
