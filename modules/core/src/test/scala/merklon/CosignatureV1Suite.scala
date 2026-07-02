// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon

import java.security.KeyPairGenerator

/** c2sp.org/tlog-cosignature "cosignature/v1" format checks, pinned to the spec's example message
  * construction.
  */
class CosignatureV1Suite extends munit.FunSuite:

  private def keyPair() = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()

  test("signed message bytes match the spec construction exactly") {
    // Body from the c2sp.org/tlog-cosignature example (root abbreviated is fine — the
    // construction, not the tree, is under test here).
    val body =
      "example.com/behind-the-sofa\n20852163\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n"
    val msg = CosignatureV1.message(1679315147L, body)
    val expected =
      "cosignature/v1\ntime 1679315147\n" +
        "example.com/behind-the-sofa\n20852163\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n"
    assertEquals(new String(msg, "UTF-8"), expected)
  }

  test("sign / verify round trip; blob layout is ts(8, big-endian) || sig(64)") {
    val kp = keyPair()
    val body = "merklon.test/log\n7\n" + "A" * 43 + "=\n"
    val ts = 1751444000L
    val sig = CosignatureV1.sign("witness.test/w1", kp, body, ts)
    assertEquals(sig.keyId.length, 4)
    assertEquals(sig.sig.length, 72)
    assertEquals(CosignatureV1.timestampOf(sig), Some(ts))
    assert(
      CosignatureV1.verify("witness.test/w1", kp.getPublic.getEncoded.takeRight(32), body, sig)
    )
  }

  test("verification fails for tampered body, wrong name, wrong key, or tampered timestamp") {
    val kp = keyPair()
    val other = keyPair()
    val body = "merklon.test/log\n7\n" + "A" * 43 + "=\n"
    val pub = kp.getPublic.getEncoded.takeRight(32)
    val sig = CosignatureV1.sign("witness.test/w1", kp, body, 1751444000L)

    assert(!CosignatureV1.verify("witness.test/w1", pub, body.replace("7", "8"), sig))
    assert(!CosignatureV1.verify("witness.test/other", pub, body, sig))
    assert(
      !CosignatureV1.verify("witness.test/w1", other.getPublic.getEncoded.takeRight(32), body, sig)
    )
    // Flip a timestamp byte: the signature must no longer verify (the ts is signed).
    val tampered = sig.copy(sig = sig.sig.updated(7, (sig.sig(7) ^ 1).toByte))
    assert(!CosignatureV1.verify("witness.test/w1", pub, body, tampered))
  }

  test("cosignature key ID differs from the log-signature key ID (0x04 vs 0x01 type byte)") {
    val kp = keyPair()
    val pub = kp.getPublic.getEncoded.takeRight(32)
    assertNotEquals(
      MerkleTree.toHex(CosignatureV1.keyId("k", pub)),
      MerkleTree.toHex(CheckpointNote.keyId("k", pub))
    )
  }

  test("zero timestamp is rejected on signing and on verification") {
    val kp = keyPair()
    val body = "merklon.test/log\n1\n" + "A" * 43 + "=\n"
    intercept[IllegalArgumentException](CosignatureV1.sign("w", kp, body, 0L))
    // A hand-built zero-ts blob must not verify even if the inner signature is valid.
    val pub = kp.getPublic.getEncoded.takeRight(32)
    val signer = java.security.Signature.getInstance("Ed25519")
    signer.initSign(kp.getPrivate)
    signer.update(CosignatureV1.message(0L, body))
    val zeroTs =
      NoteSignature("w", CosignatureV1.keyId("w", pub), Array.fill[Byte](8)(0) ++ signer.sign())
    assert(!CosignatureV1.verify("w", pub, body, zeroTs))
  }
