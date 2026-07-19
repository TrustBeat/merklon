# Getting started from Java

merklon is a verifiable, append-only transparency log for the JVM. This guide takes a
Java developer from zero to a working tamper-evident log: embed the Merkle core in
your own service, verify a live log's signed checkpoints, run the full log server
locally, and — because the whole point is *don't trust, verify* — check the published
jars against the RFC test vectors yourself.

No Scala knowledge is needed anywhere in this guide. Everything below is plain Java
on JDK 17+, compiled with `javac`.

## 1. What you're getting

Adding `eu.trustbeat:merklon-java_3:0.1.0` pulls exactly four jars:

| Jar | What it is |
|---|---|
| `merklon-java_3` | Java facade — `java.util` types only in every public signature |
| `merklon-core_3` | the pure RFC 9162 Merkle core (no I/O, no framework, no other deps) |
| `scala3-library_3`, `scala-library` | the Scala runtime — ordinary transitive jars you never interact with |

The facade lives in package `merklon.javadsl`:

- **`Merkle`** — static methods for hashing, inclusion proofs, consistency proofs,
  and their verification (RFC 9162, the Certificate Transparency 2.0 tree).
- **`Checkpoints`** — parse and verify the log's signed checkpoint notes
  (the c2sp.org signed-note format used by the Go checksum DB and Sigstore).

The facade is guarded in CI by a plain-Java smoke test: if a Scala type ever leaked
into a public signature, the build would stop compiling.

## 2. Add the dependency

Maven:

```xml
<dependency>
  <groupId>eu.trustbeat</groupId>
  <artifactId>merklon-java_3</artifactId>
  <version>0.1.0</version>
</dependency>
```

Gradle:

```groovy
implementation 'eu.trustbeat:merklon-java_3:0.1.0'
```

(The `_3` suffix is the standard Maven Central convention for libraries built for
Scala 3 — to your build tool it's just part of the artifact name.)

## 3. Hash, prove, verify — one file

Save as `TransparencyDemo.java`, compile and run with your build tool's classpath
(or `javac -cp <deps> TransparencyDemo.java && java -cp <deps>:. TransparencyDemo`):

```java
import merklon.javadsl.Merkle;

import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

public class TransparencyDemo {
    public static void main(String[] args) {
        // Your audit events — any byte[] works; see SPEC.md §7 for the
        // structured-event/v1 codec if you want canonical key=value entries.
        List<byte[]> entries = new ArrayList<>(List.of(
            "user=42 action=delete target=invoice-9".getBytes(),
            "user=7  action=login".getBytes(),
            "user=42 action=export target=all".getBytes()));

        // The Merkle Tree Hash commits to the entire ordered list.
        byte[] root = Merkle.root(entries);
        System.out.println("root of " + entries.size() + ": " + Merkle.toHex(root));

        // ── Inclusion: prove entry 1 is in the tree ─────────────────────────
        List<byte[]> incl = Merkle.inclusionProof(1, entries);
        boolean present = Merkle.verifyInclusion(
            1, entries.size(), Merkle.leafHash(entries.get(1)), incl, root);
        System.out.println("entry 1 included: " + present);           // true

        // The same proof rejects a tampered entry…
        boolean forged = Merkle.verifyInclusion(
            1, entries.size(),
            Merkle.leafHash("user=7  action=admin-login".getBytes()), incl, root);
        System.out.println("tampered entry accepted: " + forged);     // false

        // ── Consistency: prove the log only ever grew ───────────────────────
        int oldSize = entries.size();
        entries.add("user=9  action=login".getBytes());
        byte[] newRoot = Merkle.root(entries);
        List<byte[]> cons = Merkle.consistencyProof(oldSize, entries);
        boolean appendOnly = Merkle.verifyConsistency(
            oldSize, entries.size(), root, newRoot, cons);
        System.out.println("append-only: " + appendOnly);             // true

        // …and a rewritten history is caught: same sizes, different past.
        List<byte[]> rewritten = new ArrayList<>(entries);
        rewritten.set(0, "user=42 action=read target=invoice-9".getBytes());
        boolean splitView = Merkle.verifyConsistency(
            oldSize, rewritten.size(),
            Merkle.root(rewritten.subList(0, oldSize)),
            newRoot, cons);
        System.out.println("rewritten history accepted: " + splitView); // false

        // ── The math is pinned to the RFC 6962 reference vectors ────────────
        HexFormat hex = HexFormat.of();
        String emptyRoot = Merkle.toHex(Merkle.emptyRoot());
        System.out.println("RFC vector (empty tree): " + emptyRoot.equals(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    }
}
```

What each proof buys you:

- **Inclusion** (`verifyInclusion`) — a specific entry is in the tree with a given
  root. Hand the proof to a third party along with the root; they verify it with
  ~`log2(n)` hashes and zero trust in you.
- **Consistency** (`verifyConsistency`) — the tree at size *N₁* is a strict prefix of
  the tree at size *N₂*. This is the append-only guarantee: verify it on every root
  update and it becomes impossible to silently rewrite, reorder, or drop history.

Both verifiers are pure functions over bytes — no server state, no I/O — so they run
identically in your service, in an auditor's tooling, or offline.

## 4. Verify a live log's signed checkpoint

A real log doesn't just hand out roots — it signs them. A **checkpoint** is the
log's Ed25519-signed commitment to `(tree_size, root_hash)` in the c2sp signed-note
wire format ([SPEC.md](SPEC.md) §3). From Java:

```java
import merklon.javadsl.Checkpoints;
import merklon.javadsl.CheckpointInfo;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.HexFormat;

public class CheckpointDemo {
    public static void main(String[] args) throws Exception {
        // The log's raw 32-byte Ed25519 public key — obtained out of band
        // (the server prints it at startup; in production, pin it in config).
        byte[] logKey = HexFormat.of().parseHex(args[0]);

        String note = HttpClient.newHttpClient().send(
            HttpRequest.newBuilder(URI.create("http://localhost:8080/checkpoint")).build(),
            HttpResponse.BodyHandlers.ofString()).body();

        CheckpointInfo cp = Checkpoints.parse(note);
        boolean signed = Checkpoints.verifySignature(note, logKey);

        System.out.println("log:       " + cp.origin());
        System.out.println("tree size: " + cp.treeSize());
        System.out.println("root:      " + cp.rootHashHex());
        System.out.println("signature: " + (signed ? "VALID" : "INVALID"));
    }
}
```

`cp.rootHash()` is exactly what `Merkle.verifyInclusion` / `verifyConsistency`
expect as the trusted root — so the full client-side loop is: fetch checkpoint,
verify signature, then verify proofs against its root. Keep the last verified
checkpoint and demand a consistency proof to each new one, and you detect any
attempt to rewrite history.

## 5. Run the whole stack locally

The log server is an operator-side component — you run it from the repo rather than
Maven Central. With no configuration it starts a dev log (in-memory storage,
ephemeral key) and prints its public key:

```bash
git clone https://github.com/TrustBeat/merklon && cd merklon
sbt "server/runMain merklon.server.Main"
# …
#   public key: 9f2c…                     ← use this in CheckpointDemo above
```

Append entries and fetch proofs with curl:

```bash
curl -s -XPOST localhost:8080/entries --data-binary 'hello'  # {"leaf_index":0,"tree_size":1}
curl -s -XPOST localhost:8080/entries --data-binary 'world'
curl -s localhost:8080/checkpoint                            # the signed note from §4
```

For production, set `MERKLON_DB_URL` (Postgres storage), `MERKLON_KEY_DIR`
(durable log key), and `MERKLON_ORIGIN` (the log's identity); see `modules/server`
for the full list including witnessing and RFC 3161 timestamping.

And verify from *outside* your own code with the standalone verifier CLI, which
shares no state with the server:

```bash
sbt verifier/assembly   # → modules/verifier/target/scala-3.3.4/merklon-verify.jar

java -jar merklon-verify.jar --pubkey <PUBKEY_HEX> --url http://localhost:8080 \
  inclusion $(printf hello | xxd -p)
```

## 6. Don't trust this guide either — verify the jars

Everything above works the same if you refuse to trust the published artifacts and
check them yourself. Download the core jar straight from Maven Central, confirm its
checksum, and run the RFC 6962 reference vectors against it:

```bash
curl -fsSLO https://repo1.maven.org/maven2/eu/trustbeat/merklon-core_3/0.1.0/merklon-core_3-0.1.0.jar
curl -fsSL  https://repo1.maven.org/maven2/eu/trustbeat/merklon-core_3/0.1.0/merklon-core_3-0.1.0.jar.sha1
sha1sum merklon-core_3-0.1.0.jar   # must match
```

The canonical vectors (RFC 6962 §2.1, unchanged under RFC 9162) are pinned in the
repo's test suite at `modules/core/src/test/scala/merklon/` — the empty-tree root is
`SHA-256("")`, and the 8-leaf reference tree's root is
`5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328`. A dozen lines of
Java against `Merkle.root` (as in §3) reproduce them from the jar alone.

## Where to go next

- **[OVERVIEW.md](OVERVIEW.md)** — how transparency logs work, in plain language.
- **[SPEC.md](SPEC.md)** — every wire format: checkpoint notes, proofs, offline
  bundles, the HTTP API. Self-contained enough to reimplement a verifier from.
- **[DESIGN.md](DESIGN.md)** — architecture, extension points
  (`StorageBackend`, `LeafCodec`, `CheckpointAttestor`, `AppendAuthorizer`),
  witnessing, post-quantum posture.
- Need legally valid, eIDAS-qualified timestamps on your checkpoints?
  See [trustbeat.eu](https://trustbeat.eu).
