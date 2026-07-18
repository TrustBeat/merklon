// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon.javadsl;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Plain-Java smoke test for the merklon-java facade. This file is deliberately written in Java
 * and compiled by CI: if a Scala type ever leaks into the facade's signatures, this stops
 * compiling. Executed by {@code JavaFacadeSuite}.
 */
public final class JavaSmoke {

  private JavaSmoke() {}

  /** Exercise hashing, inclusion, and consistency proofs using only java.util types. */
  public static void run() {
    List<byte[]> entries = new ArrayList<>();
    for (String s : List.of("a", "b", "c", "d")) {
      entries.add(s.getBytes(StandardCharsets.UTF_8));
    }

    byte[] root = Merkle.root(entries);
    if (Merkle.toHex(root).length() != 64) {
      throw new AssertionError("root must be 32 bytes");
    }

    byte[] leaf = Merkle.leafHash(entries.get(1));
    List<byte[]> inclusion = Merkle.inclusionProof(1, entries);
    if (!Merkle.verifyInclusion(1, entries.size(), leaf, inclusion, root)) {
      throw new AssertionError("inclusion proof must verify");
    }
    byte[] wrongLeaf = Merkle.leafHash("X".getBytes(StandardCharsets.UTF_8));
    if (Merkle.verifyInclusion(1, entries.size(), wrongLeaf, inclusion, root)) {
      throw new AssertionError("a wrong leaf must not verify");
    }

    byte[] oldRoot = Merkle.root(entries.subList(0, 2));
    List<byte[]> consistency = Merkle.consistencyProof(2, entries);
    if (!Merkle.verifyConsistency(2, entries.size(), oldRoot, root, consistency)) {
      throw new AssertionError("consistency proof must verify");
    }

    if (Merkle.emptyRoot().length != 32) {
      throw new AssertionError("empty root must be 32 bytes");
    }
  }

  /** Parse and verify a signed checkpoint note produced by the (Scala-side) test harness. */
  public static void verifyCheckpoint(
      String noteText, byte[] logPublicKey, String expectedOrigin, long expectedTreeSize) {
    CheckpointInfo cp = Checkpoints.parse(noteText);
    if (!cp.origin().equals(expectedOrigin)) {
      throw new AssertionError("origin: " + cp.origin());
    }
    if (cp.treeSize() != expectedTreeSize) {
      throw new AssertionError("tree size: " + cp.treeSize());
    }
    if (cp.rootHashHex().length() != 64) {
      throw new AssertionError("root hex: " + cp.rootHashHex());
    }
    if (!Checkpoints.verifySignature(noteText, logPublicKey)) {
      throw new AssertionError("log signature must verify");
    }
    byte[] wrongKey = new byte[32];
    if (Checkpoints.verifySignature(noteText, wrongKey)) {
      throw new AssertionError("a wrong key must not verify");
    }
  }
}
