# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `docs/GETTING-STARTED-JAVA.md` — a full plain-Java walkthrough: embed the core via
  Maven/Gradle, inclusion/consistency proofs with tamper and split-view rejection,
  signed-checkpoint verification against a live log, running the server + verifier CLI
  locally, and independently verifying the published jars against the RFC 6962 vectors.
  All code blocks are compiled and run against the actual Maven Central artifacts.

### Changed
- README quickstart is now **Java-first**: Maven/Gradle coordinates and a fuller Java
  example (inclusion + consistency) lead; the Scala snippet follows. Java developers are
  the larger JVM audience and `merklon-java` needs no Scala knowledge to use.

## [0.1.0] - 2026-07-19

First public release: a complete, independently verifiable transparency log — Merkle
core, persistence, signed checkpoints, HTTP serving, N-of-M witnessing, offline proof
bundles with optional RFC 3161 timestamps, `c2sp.org/tlog-proof@v1` support, a standalone
verifier (library + CLI), and a Java facade. Published to Maven Central as
`eu.trustbeat:merklon-{core,verifier,java}_3`.

### Added
- **Published to Maven Central**: `eu.trustbeat:merklon-core_3`, `merklon-verifier_3` and
  `merklon-java_3` at `0.1.0` (GPG-signed, with sources and javadoc). Publishing config in
  `build.sbt` (sbt-pgp + sbt-sonatype, Central Portal bundle flow), process in `RELEASING.md`;
  README carries the coordinates and a Maven Central badge. The server and Postgres backend
  stay repo-only by design.
- CI now anchors the `merklon-verify.jar` built from every push to `main` with an
  eIDAS-qualified timestamp via [TrustBeat/anchor-action](https://github.com/TrustBeat/anchor-action)
  (dogfooding): independent, court-grade proof of when each exact verifier binary existed.
  The step is skipped until the `TRUSTBEAT_API_KEY` repository secret is configured.
  The README carries the "Anchored" badge of the first anchored build.
- `merklon-java` (`modules/java`, package `merklon.javadsl`): Java-friendly facade over the
  pure core — `Merkle` (hashing, inclusion/consistency proofs and verification) and
  `Checkpoints` (note parsing + strict signature verification) with only `java.util` types in
  public signatures. A plain-Java smoke test (`JavaSmoke.java`) is compiled and run by CI, so
  any Scala type leaking into the facade breaks the build. README gains a Java quickstart.
- `c2sp.org/tlog-proof@v1` support — the ecosystem's offline proof interchange format
  ("transparent signatures", SPEC §8.4): core render/parse (`merklon.TlogProofCodec`),
  `GET /tlog-proof?leaf_index=N` export on the log server, offline verification in the
  verifier library (`TlogProofVerifier`) and CLI (`tlog-proof FILE DATA_HEX`). Unlike
  `merklon-bundle/v1` it carries no entry bytes and no RFC 3161 token.
- `MerkleTree.emptyRoot` — the RFC 9162 empty-tree hash, and
  `CheckpointNote.verifyLogSignatures` — strict signed-note validation shared by the witness,
  witness server, and verifier.
- `docs/OVERVIEW.md` "How the whole thing works": end-to-end Mermaid architecture
  diagram (submitter → sequencer → Merkle tree → signed checkpoint → witnesses →
  qualified timestamp → offline proof bundle → independent verifier) with a
  step-by-step plain-language walkthrough.
- SPEC §7.5 "Witness deployment requirements": one witness key MUST be served by
  exactly one process (no horizontal replication of a key — replicas can equivocate);
  scale by adding independent witnesses; witnesses counted toward the N-of-M policy
  must be operationally independent of the log operator.
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
- Timed checkpoint batching (`merklon.server.CheckpointPublisher`), closing the Phase 1
  "timed batching cadence" leftover: checkpoints are published by a background fiber at
  most once per `MERKLON_BATCH_MS` (default 1000) instead of once per append, and each
  batched checkpoint is submitted to all witnesses in parallel, off the request path —
  one checkpoint and one witness round per interval regardless of append volume.
  `POST /entries` now waits for the checkpoint that integrates the entry (published and
  witnessed) before responding with `{leaf_index, tree_size}`, so proofs against the
  returned size work immediately; if none arrives within the wait bound it returns 503
  with the entry still durably appended. Appenders are gated on the publisher's
  announcement rather than raw storage, so they can never observe the intermediate
  un-cosigned note the sequencer persists before witnessing.
- Phase 4 — qualified timestamps + offline proof bundles:
  - `merklon-bundle/v1` (SPEC §8): a single-JSON, offline-verifiable evidence package —
    entry bytes, inclusion proof, the embedded signed note (with witness cosignatures)
    base64'd byte-for-byte, and an optional RFC 3161 timestamp token. Rendered/parsed in
    core (`ProofBundle` / `ProofBundleCodec`) with no JSON dependency.
  - `GET /bundle?leaf_index=N` exports a bundle against the latest checkpoint; with
    `MERKLON_TSA_URL` set it is sealed by an RFC 3161 TSA (Bouncy Castle protocol
    client, one TSA round-trip per checkpoint via caching; TSA failure → 502, never a
    silently unsealed bundle).
  - The RFC 3161 message imprint covers the checkpoint note *body* (origin/size/root),
    so the attested statement is independent of attached signature lines; tokens travel
    in the bundle, not the note (cosignature verifiers fail closed on extension lines).
  - Verifier: `BundleVerifier` + `TimestampVerifier` (imprint binding always enforced;
    CMS signature, ESSCertID, timestamping EKU and validity-at-genTime checked when a
    TSA certificate is supplied — which then also makes a token *mandatory*), and the
    offline CLI command `bundle FILE` with `--tsa-cert PEM`; `--url` is now required
    only by the online commands.
  - New dependency: Bouncy Castle `bcpkix-jdk18on` (MIT-style licence) in server and
    verifier — ASN.1/RFC 3161 protocol handling only, never crypto primitives; the core
    stays dependency-free.
  - Tests: an in-process RFC 3161 test TSA (self-signed timestamping certificate,
    real DER request/response protocol) and the Phase 4 done-bar end-to-end — log +
    witness + HTTP TSA stub → exported bundle → full offline verification including
    witness policy and TSA certificate; CLI smoke-tested offline against a real export.

- `structured-event/v1` leaf codec (SPEC §9), completing the last Phase 4 wishlist item:
  a flat JSON event envelope (`actor`/`action`/`source`/`time` + optional
  `prev_ref`/`payload`) strictly parsed by a dependency-free parser and re-emitted
  canonically (fixed key order, minimal escaping), so producers' field order, whitespace,
  and escape choices cannot change the leaf hash; invalid events fail closed with 400.
  Selected via `MERKLON_CODEC` on the server and `--codec` in the CLI;
  `LogVerifier`/`BundleVerifier` recompute leaf hashes through the codec.
- Inclusion lookup by leaf hash (RFC 9162 `get-proof-by-hash` parity, SPEC §6):
  `GET /proof/inclusion?leaf_hash=HEX&tree_size=` resolves the lowest matching index
  (404 when absent); `StorageBackend.findLeafIndex` (in-memory + Postgres with an index
  on `leaf_hash`); CLI `inclusion DATA_HEX` computes the hash locally — the lookup adds
  no server trust because the returned proof still has to verify against the root.
- Entry retrieval `GET /entries?start=&end=` (SPEC §6): pages of
  `{leaf_index, data(base64)}` capped at 1000, so monitors and mirrors can replay the
  log and recompute roots independently; `StorageBackend.getEntries` bulk read.
- Write-path hardening: per-entry size cap on `POST /entries`
  (`MERKLON_MAX_ENTRY_BYTES`, default 65536 → 413) and a 64 KiB body cap on the witness
  `add-checkpoint` endpoint.
- SPEC §6.1 error model documented (plain-text error bodies; 400/404/413/502/503), and
  the resolved §6 TODOs cleared.
- DESIGN: "Post-quantum posture" section — the SHA-256 proof core is PQ-safe as-is;
  Ed25519 signature migration tracks the c2sp specs (ML-DSA-44) behind the existing
  attestor/note seams; long-lived offline evidence is defended by RFC 3161
  time-anchoring plus the reserved re-stamping/LTV hook.
- Distributable verifier CLI: `sbt verifier/assembly` produces a self-contained
  `merklon-verify.jar` runnable with `java -jar` on any JDK 17+, so the independent
  verifier needs neither sbt nor the source tree.

### Changed
- README + DESIGN: explicit ML-DSA-44 roadmap line — planned when the JDK 25 LTS becomes the
  project baseline; accelerated if a shared witness network requires it for onboarding.
- **Witness conformance with c2sp.org/tlog-witness as of 2026-07** (the upstream spec changed
  after the 2026-07-04 version cut; SPEC §7.1/§7.3):
  - a same-size, different-root submission (split view) now returns **422** instead of 409 —
    409 is exclusively the `old`-size negotiation response (upstream change of 2026-07-06);
  - a size-zero checkpoint MUST carry the empty-tree root, else 422;
  - a non-empty consistency proof where none is possible (first observation, or extending from
    cosigned size 0) is refused with 422 instead of being ignored;
  - strict signed-note signature validation: a signature line matching the trusted key's name
    and ID that fails to verify now invalidates the whole note (403), even when another line
    verifies — applied by the witness, the witness server, and the independent verifier;
  - new `WitnessRefusal.InvalidCheckpoint` refusal carrying the protocol-rule reason.
- README: keyword tagline, Scala/RFC badges, docs links (incl. the plain-language
  overview), and an About section linking to [trustbeat.eu](https://trustbeat.eu).
- DESIGN.md: removed the stale pre-Phase-0 "Next step" section; extension-point table
  now shows built/reserved status instead of build-order planning notes.

### Fixed
- Server integration test: replaced the fixed `Thread.sleep` startup wait with an active
  port-readiness poll, removing a race where the first request could beat the server's bind.
