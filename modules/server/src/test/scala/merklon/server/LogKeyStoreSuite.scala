// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon.server

import merklon.{CheckpointAttestor, InMemoryStorageBackend, MerkleTree, Sequencer}
import merklon.verifier.LogVerifier

import java.nio.file.{Files, Path}
import java.util.Comparator

class LogKeyStoreSuite extends munit.FunSuite:

  private val tempDir = FunFixture[Path](
    setup = _ => Files.createTempDirectory("merklon-keys"),
    teardown =
      dir => Files.walk(dir).sorted(Comparator.reverseOrder()).forEach(p => Files.delete(p))
  )

  tempDir.test("creates a key pair on first load and persists both PEM files") { dir =>
    val pair = LogKeyStore.loadOrCreate(dir)
    assert(Files.exists(dir.resolve("log.key")))
    assert(Files.exists(dir.resolve("log.pub")))
    val keyText = Files.readString(dir.resolve("log.key"))
    assert(keyText.startsWith("-----BEGIN PRIVATE KEY-----"))
    val pubText = Files.readString(dir.resolve("log.pub"))
    assert(pubText.startsWith("-----BEGIN PUBLIC KEY-----"))
    assertEquals(pair.getPublic.getEncoded.length, 44) // Ed25519 SPKI is always 44 bytes
  }

  tempDir.test("reload returns the same key across restarts") { dir =>
    val first = LogKeyStore.loadOrCreate(dir)
    val second = LogKeyStore.loadOrCreate(dir)
    assertEquals(
      MerkleTree.toHex(second.getPublic.getEncoded),
      MerkleTree.toHex(first.getPublic.getEncoded)
    )
  }

  tempDir.test("checkpoints signed before a restart verify with the reloaded key") { dir =>
    val origin = "merklon.test/keystore"
    // First "process": persisted key, publish a checkpoint.
    val storage = InMemoryStorageBackend()
    val attestor1 = CheckpointAttestor.ed25519(origin, LogKeyStore.loadOrCreate(dir))
    val seq1 = Sequencer(origin, storage, attestor1)
    seq1.append("entry-before-restart".getBytes("UTF-8"))
    val cp = seq1.publishCheckpoint()
    // Second "process": reload the key; the old checkpoint must verify against its public key.
    val attestor2 = CheckpointAttestor.ed25519(origin, LogKeyStore.loadOrCreate(dir))
    assertEquals(MerkleTree.toHex(attestor2.publicKey), MerkleTree.toHex(attestor1.publicKey))
    assert(LogVerifier.verifyCheckpointSignature(cp, attestor2.publicKey))
  }

  tempDir.test("mismatched private/public pair is rejected at load") { dir =>
    LogKeyStore.loadOrCreate(dir)
    // Overwrite log.pub with a different key's public half.
    val other = Files.createTempDirectory("merklon-keys-other")
    try
      LogKeyStore.loadOrCreate(other)
      Files.copy(
        other.resolve("log.pub"),
        dir.resolve("log.pub"),
        java.nio.file.StandardCopyOption.REPLACE_EXISTING
      )
      intercept[IllegalArgumentException](LogKeyStore.loadOrCreate(dir))
    finally Files.walk(other).sorted(Comparator.reverseOrder()).forEach(p => Files.delete(p))
  }

  tempDir.test("one PEM file missing is rejected rather than silently regenerated") { dir =>
    LogKeyStore.loadOrCreate(dir)
    Files.delete(dir.resolve("log.pub"))
    intercept[IllegalArgumentException](LogKeyStore.loadOrCreate(dir))
  }

  tempDir.test("garbage in the PEM file is rejected") { dir =>
    LogKeyStore.loadOrCreate(dir)
    Files.writeString(dir.resolve("log.key"), "not a pem file")
    intercept[IllegalArgumentException](LogKeyStore.loadOrCreate(dir))
  }

  tempDir.test("private key file is not world-readable (POSIX)") { dir =>
    LogKeyStore.loadOrCreate(dir)
    try
      val perms = Files.getPosixFilePermissions(dir.resolve("log.key"))
      import java.nio.file.attribute.PosixFilePermission.*
      assert(!perms.contains(GROUP_READ) && !perms.contains(OTHERS_READ), s"perms were $perms")
    catch case _: UnsupportedOperationException => () // non-POSIX FS — nothing to assert
  }
