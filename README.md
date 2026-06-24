# merklon

> ⚠️ **Early WIP.**

A **verifiable, append-only transparency log** — a tamper-evident Merkle log with
inclusion and consistency proofs that anyone can verify *without trusting the server*.

[![CI](https://github.com/TrustBeat/merklon/actions/workflows/ci.yml/badge.svg)](https://github.com/TrustBeat/merklon/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

---

## Why

Most "audit logs" are searchable, not *provable*. A transparency log gives you a
cryptographic guarantee that the log is **append-only** — entries can be added but
history can never be silently rewritten — and lets independent parties **verify**
that guarantee for themselves.

The design follows the model proven by Certificate Transparency (RFC 6962),
Sigstore's Rekor, and the Go checksum database:

- **Inclusion proofs** — prove a specific entry is in the log.
- **Consistency proofs** — prove the log at size *N₁* is a prefix of the log at
  size *N₂* (nothing was reordered or removed).
- **Signed checkpoints** — the log periodically signs `(tree_size, root_hash)`.
- **Witnessing** *(roadmap)* — independent witnesses co-sign checkpoints to detect a
  log that shows different histories to different clients (split-view / equivocation).

## Don't trust — verify

Correctness *is* the product. merklon ships an **independent verifier** (library + CLI)
that checks every proof against the math, and a test suite pinned to known
**RFC 6962** vectors. If the verifier disagrees with the server, the server is wrong.

## Status

Early. See the roadmap below. The Merkle core (leaf/node hashing, Merkle Tree Hash)
and its tests are the first slice.

## Quickstart

```bash
sbt test        # runs the suite, including RFC 6962 vector checks
```

```scala
import merklon.MerkleTree

val entries = List("a", "b", "c").map(_.getBytes("UTF-8"))
val root    = MerkleTree.root(entries)
println(MerkleTree.toHex(root))
```

## Roadmap

- **Phase 0 — Merkle core** *(in progress)*: leaf/node hashing, Merkle Tree Hash,
  inclusion + consistency proofs, RFC 6962 test vectors.
- **Phase 1 — Persistence + checkpoints**: storage backend, Ed25519-signed checkpoints,
  a sequencer that batches entries on a cadence.
- **Phase 2 — Serving + verifier**: HTTP API + standalone CLI verifier.
- **Phase 3 — Witnessing**: witness service, N-of-M co-signing, split-view detection.
- **Phase 4 — Pluggable attestation**: pluggable checkpoint attestor (incl. RFC 3161
  qualified timestamps) and self-contained, offline-verifiable proof bundles.

## Design

Hash-agnostic, dependency-light core with clean extension points
(`CheckpointAttestor`, `LeafCodec`, `StorageBackend`, `AppendAuthorizer`) so the log
can be embedded in different contexts without forking.

## Security

Found a vulnerability? Please follow [SECURITY.md](SECURITY.md) — do **not** open a
public issue for security reports.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions require a
[Developer Certificate of Origin](https://developercertificate.org/) sign-off
(`git commit -s`).

## License

[Apache License 2.0](LICENSE). Copyright Trustbeat s.r.o.
