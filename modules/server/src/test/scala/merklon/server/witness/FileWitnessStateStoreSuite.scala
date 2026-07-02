// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon.server.witness

import merklon.*

import java.nio.file.{Files, Path}
import java.util.Comparator

class FileWitnessStateStoreSuite extends munit.FunSuite:

  private val tempDir = FunFixture[Path](
    setup = _ => Files.createTempDirectory("merklon-witness-store"),
    teardown =
      dir => Files.walk(dir).sorted(Comparator.reverseOrder()).forEach(p => Files.delete(p))
  )

  private def checkpoint(origin: String, size: Long): Checkpoint =
    val attestor = CheckpointAttestor.generateEd25519(origin)
    val root = Array.fill[Byte](32)(size.toByte)
    val body = CheckpointNote.noteBody(origin, size, root)
    val sig = NoteSignature(attestor.keyName, attestor.keyId, attestor.sign(body.getBytes("UTF-8")))
    Checkpoint(origin, size, root, 0L, Vector(sig))

  tempDir.test("save / latest round-trips a checkpoint with its signatures") { dir =>
    val store = FileWitnessStateStore(dir)
    assertEquals(store.latest("merklon.test/a"), None)
    val cp = checkpoint("merklon.test/a", 7L)
    store.save(cp)
    val loaded = store.latest("merklon.test/a").getOrElse(fail("no state"))
    assertEquals(loaded.treeSize, 7L)
    assertEquals(MerkleTree.toHex(loaded.rootHash), MerkleTree.toHex(cp.rootHash))
    assertEquals(loaded.signatures.map(_.keyName), cp.signatures.map(_.keyName))
  }

  tempDir.test("state is per origin and survives a new store instance over the same dir") { dir =>
    val store = FileWitnessStateStore(dir)
    store.save(checkpoint("merklon.test/a", 3L))
    store.save(checkpoint("merklon.test/b", 9L))
    val reopened = FileWitnessStateStore(dir)
    assertEquals(reopened.latest("merklon.test/a").map(_.treeSize), Some(3L))
    assertEquals(reopened.latest("merklon.test/b").map(_.treeSize), Some(9L))
    assertEquals(reopened.latest("merklon.test/c"), None)
  }

  tempDir.test("hostile origin strings cannot escape the state directory") { dir =>
    val store = FileWitnessStateStore(dir)
    store.save(checkpoint("../../../etc/passwd", 1L))
    // Everything written must be inside dir (filenames are sha256(origin)).
    Files.list(dir).forEach(p => assert(p.normalize().startsWith(dir), s"escaped: $p"))
  }

  tempDir.test("a corrupt state file fails loudly instead of resetting to TOFU") { dir =>
    val store = FileWitnessStateStore(dir)
    store.save(checkpoint("merklon.test/a", 3L))
    val file = Files.list(dir).filter(_.toString.endsWith(".note")).findFirst().get()
    Files.writeString(file, "garbage")
    intercept[IllegalStateException](FileWitnessStateStore(dir).latest("merklon.test/a"))
  }
