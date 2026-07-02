# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Project scaffolding: Apache-2.0 license, README, security policy, contribution
  guide (DCO), code of conduct, CI workflow.
- Phase 0: Merkle core — RFC 9162 (CT 2.0, obsoletes RFC 6962) leaf/node hashing and
  Merkle Tree Hash, plus inclusion (audit path) and consistency proof generation and
  independent verification (RFC 9162 §2.1.3.2 / §2.1.4.2 verify algorithms). Pinned to
  the canonical RFC 6962 reference test vectors (unchanged under RFC 9162), with tamper-
  and fork-rejection coverage.
- Developer tooling: `CLAUDE.md` (agent guidance), scalafmt + `.editorconfig`,
  `.claude/settings.json`, and `docs/DESIGN.md` / `docs/SPEC.md` (draft).
- Verifier CLI: `consistency OLD_SIZE OLD_ROOT_HEX` command — verifies the latest
  checkpoint is an append-only extension of a previously trusted (size, root), so the
  CLI now exposes all three independent-verification operations (checkpoint signature,
  inclusion, consistency).
- Phase 1: persistence + checkpoints — `StorageBackend` interface with in-memory
  implementation, Ed25519 `CheckpointAttestor`, c2sp.org/tlog-checkpoint signed-note
  `Checkpoint` rendering, and the `Sequencer` (append → integrate → publish checkpoint).
  Extension interfaces `LeafCodec` and `AppendAuthorizer` with default implementations.
- Phase 2: serving + independent verifier — ZIO HTTP server (`POST /entries`,
  `GET /checkpoint`, `GET /proof/inclusion`, `GET /proof/consistency`) and a standalone
  verifier (library + JDK-HTTP client + note/proof parsers + CLI) that shares no state
  with the server.
- Multi-module build: split into `modules/core` (pure, dependency-free),
  `modules/storage-pg`, `modules/server` (ZIO HTTP), and `modules/verifier`.
- Durable log identity: `LogKeyStore` persists the operator's Ed25519 key as
  openssl-compatible PEM files (`log.key` PKCS#8 0600, `log.pub` SPKI) with a
  sign/verify pair check at load; wired via `MERKLON_KEY_DIR` (ephemeral key + warning
  without it), so checkpoints verify across restarts.
- Postgres `StorageBackend` (`merklon-storage-pg`): plain-JDBC backend with
  advisory-locked contiguous index assignment and append-only checkpoint persistence
  (a shrinking `tree_size` is refused at the storage layer). Server selects it via
  `MERKLON_DB_URL` / `MERKLON_DB_USER` / `MERKLON_DB_PASSWORD`. Integration suite runs
  against a dockerized `postgres:16`, including the Phase 1 "done" bar: 100k entries
  appended across 4 simulated process restarts with every checkpoint chain verified by
  consistency proofs (skipped automatically when Docker is unavailable).
- Phase 3 witnessing (core): `Witness` verifies the log signature and append-only
  consistency from its last cosigned checkpoint before cosigning; refusals carry
  transferable evidence (`SplitView` = two same-size, different-root checkpoints signed
  by the same log key). `WitnessPolicy` implements the client-side N-of-M distinct
  trusted cosigner check. Split-view, history-rewrite, forged-cosignature, and N-of-M
  tests included. (Witness *service*/distribution is still to come.)
- Core `Ed25519.verify` over raw 32-byte keys and public `CheckpointNote.keyId`
  (signed-note key-ID formula), now shared by the attestor, witness, policy, and
  verifier instead of duplicated.
- Phase 3 complete — witness service and distribution:
  - Witness cosignatures now conform to c2sp.org/tlog-cosignature **cosignature/v1**
    (`merklon.CosignatureV1`): signed message `cosignature/v1\ntime <t>\n<note body>`,
    key-ID type byte 0x04, blob `key_id || timestamp(8,BE) || ed25519_sig`, non-zero
    timestamp enforced. `Witness` and `WitnessPolicy` updated accordingly.
  - Witness HTTP service (`merklon.server.witness.WitnessServer` + `WitnessMain`)
    implementing c2sp.org/tlog-witness `POST /add-checkpoint` with the spec's status
    codes (200 cosignature line, 400/403/404, 409 + latest size as `text/x.tlog.size`,
    422) and the `GET /<sha256(origin)>/checkpoint` monitoring endpoint.
  - Durable witness state: `WitnessStateStore` seam in core (in-memory impl) and
    `FileWitnessStateStore` (atomic writes, origin-hashed filenames, corrupt state
    fails loudly instead of silently resetting to trust-on-first-use).
  - Log-side submission: `WitnessClient` with 409 size negotiation, wired via
    `MERKLON_WITNESSES`; collected cosignatures are appended to the stored and served
    checkpoint note. End-to-end test: log + two witnesses, served note satisfies a
    2-of-2 policy; split-view detection also covered over HTTP.
  - Verifier CLI witness policy: `--witness NAME=HEX_PUBKEY` (repeatable) and
    `--witness-threshold N` (default: all listed) enforced on every command.
  - Checkpoint note parsing moved into core (`CheckpointNote.parse` /
    `parseSignatureLine`); `merklon.verifier.CheckpointParser` delegates to it.

### Fixed
- Server integration test: replaced the fixed `Thread.sleep` startup wait with an active
  port-readiness poll, removing a race where the first request could beat the server's bind.
