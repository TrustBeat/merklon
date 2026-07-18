# merklon

A **verifiable, append-only transparency log** — a tamper-evident Merkle log with
inclusion and consistency proofs that anyone can verify *without trusting the server*.

[![CI](https://github.com/TrustBeat/merklon/actions/workflows/ci.yml/badge.svg)](https://github.com/TrustBeat/merklon/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Scala 3](https://img.shields.io/badge/Scala-3.3%20LTS-de3423.svg)](https://www.scala-lang.org/)
[![RFC 9162](https://img.shields.io/badge/RFC-9162-lightgrey.svg)](https://www.rfc-editor.org/rfc/rfc9162)

*Certificate-Transparency-style verifiable log for the JVM: Merkle tree proofs
(RFC 9162 / RFC 6962), signed checkpoints, N-of-M witness co-signing, RFC 3161
qualified timestamps, and offline-verifiable proof bundles — in pure Scala 3.*

New to transparency logs? Start with the **[plain-language overview](docs/OVERVIEW.md)**.

---

## Why

Most "audit logs" are searchable, not *provable*. A transparency log gives you a
cryptographic guarantee that the log is **append-only** — entries can be added but
history can never be silently rewritten — and lets independent parties **verify**
that guarantee for themselves.

The design follows the model proven by Certificate Transparency (RFC 9162,
which obsoletes RFC 6962), Sigstore's Rekor, and the Go checksum database:

- **Inclusion proofs** — prove a specific entry is in the log.
- **Consistency proofs** — prove the log at size *N₁* is a prefix of the log at
  size *N₂* (nothing was reordered or removed).
- **Signed checkpoints** — the log periodically signs `(tree_size, root_hash)`.
- **Witnessing** — independent witnesses co-sign checkpoints to detect a log that shows
  different histories to different clients (split-view / equivocation).
- **Offline proof bundles** — a single self-contained document (entry, inclusion proof,
  signed+cosigned checkpoint, optional RFC 3161 timestamp) that verifies with no network.

## Don't trust — verify

Correctness *is* the product. merklon ships an **independent verifier** (library + CLI)
that checks every proof against the math, and a test suite pinned to the canonical
**RFC 6962** reference vectors (unchanged under RFC 9162). If the verifier disagrees
with the server, the server is wrong.

## Status

**v0.1.0** — the full Layer-1 log is complete: Merkle core, Postgres persistence,
Ed25519-signed checkpoints, HTTP serving, N-of-M witnessing (split-view detection),
RFC 3161-sealed offline proof bundles, and a standalone independent verifier.

## Quickstart

**Use the core as a library** — compute a Merkle Tree Hash over some entries:

```scala
import merklon.MerkleTree

val entries = List("a", "b", "c").map(_.getBytes("UTF-8"))
val root    = MerkleTree.root(entries)
println(MerkleTree.toHex(root))
```

**Run the log server** and append an entry:

```bash
sbt server/run        # starts the ZIO HTTP log server (see modules/server for env vars)

curl -s -XPOST localhost:8080/entries --data-binary 'hello'   # → {"leaf_index":0,"tree_size":1}
curl -s localhost:8080/checkpoint                             # the signed (size, root) note
```

**Verify independently** — build the standalone verifier, then check a proof without
trusting the server (the CLI shares none of the server's state):

```bash
sbt verifier/assembly   # → modules/verifier/target/scala-3.3.4/merklon-verify.jar

java -jar merklon-verify.jar --pubkey <LOG_PUBKEY_HEX> --url http://localhost:8080 \
  inclusion 68656c6c6f          # hex("hello") — index is looked up by leaf hash
```

`merklon-verify` also checks checkpoint signatures, consistency proofs, witness
cosignature policies (`--witness NAME=HEX --witness-threshold N`), fully offline
proof bundles (`bundle FILE [--tsa-cert PEM]`), and standard
[c2sp.org/tlog-proof](https://c2sp.org/tlog-proof) documents
(`tlog-proof FILE DATA_HEX`). Run it with no arguments for usage.

```bash
sbt test        # runs the full suite, including the RFC 6962 vector checks
```

## Roadmap

All Layer-1 phases are complete as of **v0.1.0**:

- **Phase 0 — Merkle core** *(done)*: leaf/node hashing, Merkle Tree Hash,
  inclusion + consistency proofs, RFC 6962 test vectors.
- **Phase 1 — Persistence + checkpoints** *(done)*: Postgres storage backend,
  Ed25519-signed checkpoints, durable log key, sequencer with timed batching.
- **Phase 2 — Serving + verifier** *(done)*: ZIO HTTP API + standalone CLI verifier.
- **Phase 3 — Witnessing** *(done)*: c2sp tlog-witness service, N-of-M co-signing
  (cosignature/v1), split-view detection.
- **Phase 4 — Pluggable attestation** *(done)*: RFC 3161 qualified timestamps and
  self-contained, offline-verifiable proof bundles.

**Next — post-quantum signatures:** ML-DSA-44 cosignatures (the c2sp `0x06` type), planned
for when the JDK 25 LTS becomes the project baseline — the JDK ships ML-DSA natively, so the
core stays dependency-free. The SHA-256 Merkle proofs themselves are already post-quantum
safe; see the post-quantum posture section in [DESIGN.md](docs/DESIGN.md).

## Design

Hash-agnostic, dependency-light core with clean extension points
(`CheckpointAttestor`, `LeafCodec`, `StorageBackend`, `AppendAuthorizer`) so the log
can be embedded in different contexts without forking.

- **[Overview](docs/OVERVIEW.md)** — how the whole thing works, in plain language.
- **[Design](docs/DESIGN.md)** — architecture, actors, extension points, PQ posture.
- **[Spec](docs/SPEC.md)** — wire formats: checkpoint note, proofs, bundles, HTTP API.

## About

merklon is built and maintained by **[Trustbeat](https://trustbeat.eu)**, makers of
European timestamping and log-anchoring infrastructure. Proof bundles already carry
RFC 3161 timestamps — if you need **legally valid, eIDAS-qualified timestamps** on
your checkpoints and evidence, see **[trustbeat.eu](https://trustbeat.eu)**.

## Security

Found a vulnerability? Please follow [SECURITY.md](SECURITY.md) — do **not** open a
public issue for security reports.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions require a
[Developer Certificate of Origin](https://developercertificate.org/) sign-off
(`git commit -s`).

## License

[Apache License 2.0](LICENSE). Copyright Trustbeat s.r.o.
