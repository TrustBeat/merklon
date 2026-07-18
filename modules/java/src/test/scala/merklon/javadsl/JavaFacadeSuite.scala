// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon.javadsl

import merklon.*

/** Runs the plain-Java smoke test (`JavaSmoke.java`): the facade must be fully usable from Java
  * with no Scala types in any signature. The .java file compiling at all is half the test; this
  * suite executes it.
  */
class JavaFacadeSuite extends munit.FunSuite:

  test("Merkle facade: hashing + inclusion + consistency from plain Java") {
    JavaSmoke.run()
  }

  test("Checkpoints facade: parse + strict signature verification from plain Java") {
    val origin = "java.test/log"
    val attestor = CheckpointAttestor.generateEd25519(origin)
    val entries = List("a", "b", "c").map(_.getBytes("UTF-8"))
    val root = MerkleTree.root(entries)
    val body = CheckpointNote.noteBody(origin, entries.size.toLong, root)
    val sig =
      NoteSignature(attestor.keyName, attestor.keyId, attestor.sign(body.getBytes("UTF-8")))
    val note =
      CheckpointNote.render(Checkpoint(origin, entries.size.toLong, root, 0L, Vector(sig)))

    JavaSmoke.verifyCheckpoint(note, attestor.publicKey, origin, entries.size.toLong)
  }

  test("facade results agree with the core") {
    val entries = List("a", "b", "c", "d").map(_.getBytes("UTF-8"))
    val jEntries = java.util.List.of(entries*)
    assertEquals(
      MerkleTree.toHex(Merkle.root(jEntries)),
      MerkleTree.toHex(MerkleTree.root(entries))
    )
    assertEquals(Merkle.toHex(Merkle.emptyRoot()), MerkleTree.toHex(MerkleTree.emptyRoot))
  }
