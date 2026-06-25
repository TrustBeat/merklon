# CLAUDE.md — merklon

Guidance for Claude Code (and other agents) working in this repository. These instructions
override default behavior — follow them.

## What this is
**merklon** is a verifiable, append-only **transparency log**: a tamper-evident Merkle log
(RFC 9162 style) with inclusion and consistency proofs that anyone can verify *without
trusting the server*. Open source, Apache-2.0, © Trustbeat s.r.o.

Full architecture and roadmap: `docs/DESIGN.md`. Wire formats: `docs/SPEC.md` (in progress).

## Core philosophy — read before writing code
- **Correctness IS the product.** A transparency log that is subtly wrong is worse than
  useless. Prefer clarity and provable correctness over cleverness or micro-optimization.
- **Don't trust — verify.** Every proof must be checkable by an *independent verifier* that
  shares none of the server's trust assumptions. Keep verification logic free of server state.
- **Conform to standards.** Hashing and proofs follow **RFC 9162** (Certificate Transparency 2.0,
  which obsoletes RFC 6962; the Merkle tree is unchanged between them). Where a standard defines
  test vectors, pin tests to those vectors rather than hand-rolled expectations — the canonical
  RFC 6962 reference tree vectors remain valid under RFC 9162.
- **Never invent crypto primitives.** Use the JDK and vetted libraries (Bouncy Castle for
  ASN.1 / RFC 3161). We implement *protocols and data structures*, never new ciphers/hashes.
- **The core stays pure and dependency-light.** The Merkle core has no I/O, no frameworks, no
  effect system — just functions over bytes. Effects/HTTP/DB belong in outer layers only.

## Architecture (two layers — keep the seam clean)
- **Layer 1 — this repo (open source):** the verifiable log — Merkle core, proofs,
  checkpoints, serving, witnessing, independent verifier.
- **Layer 2 — separate, private, NOT here:** downstream applications built on the core. The core
  exposes extension points (`CheckpointAttestor`, `LeafCodec`, `StorageBackend`,
  `AppendAuthorizer`) so they plug in without forking.
- **Do NOT add to this repo:** multi-tenancy, authenticated ingestion, billing, or
  dashboards/reporting. Those are downstream concerns. (See `docs/DESIGN.md` §"OUT of scope".)

## Tech stack
- **Scala 3.3.4 (LTS)**, sbt, **munit** for tests.
- **scalafmt** for formatting (`sbt scalafmtAll`; CI gates on `scalafmtCheckAll`).
- Outer layers later: ZIO / ZIO HTTP, Bouncy Castle, PostgreSQL — kept out of the pure core.

## Repo layout
- `src/main/scala/merklon/` — library code (package `merklon`)
- `src/test/scala/merklon/` — tests (standard vectors live here)
- `docs/DESIGN.md` — public architecture, scope, roadmap (business strategy split out to the
  gitignored `docs/STRATEGY.private.md` — never publish that file)
- `docs/SPEC.md` — wire formats: checkpoint note, proofs, API (draft)

## Commands
```bash
sbt compile
sbt test               # includes RFC 6962 vector checks
sbt scalafmtAll        # format the codebase
sbt scalafmtCheckAll   # verify formatting (CI gate)
```

## Conventions
- **Tests are mandatory.** Any change to log behavior ships with tests in the same change;
  prefer standard test vectors over invented expectations.
- **DCO sign-off required.** Commit with `git commit -s` (Developer Certificate of Origin —
  see `CONTRIBUTING.md`). There is no CLA.
- **Keep PRs focused;** update `docs/` and `CHANGELOG.md` in the same change when relevant.
- **License hygiene:** Apache-2.0 only; do not add dependencies under incompatible licenses.

## Roadmap (build order — see DESIGN.md for "done" criteria)
0. **Merkle core** — hashing + inclusion/consistency proofs + RFC 6962 vectors *(done)*.
1. **Persistence + checkpoints** — storage backend, Ed25519-signed checkpoints, sequencer *(next)*.
2. **Serving + verifier** — HTTP API + standalone independent verifier (library + CLI).
3. **Witnessing** — N-of-M co-signing; split-view detection.
4. **Pluggable attestation** — RFC 3161 qualified timestamps + offline proof bundles.

## Gotchas (Scala 3 / crypto)
- **Byte-array equality:** never `==` on `Array[Byte]` — compare hex (`toHex`) or use
  `java.util.Arrays.equals`.
- **RFC 9162 split point** `k` = largest power of two **strictly less than** `n`
  (`Integer.highestOneBit(n - 1)`).
- **ASN.1/DER (once the RFC 3161 attestor lands):** build with `ASN1EncodableVector` then
  `.getEncoded()`; `DERSequence(Array(...))` fails on array invariance.

## Commits
**The maintainer handles all commits and pushes — do not commit or push.** Leave changes in
the working tree and let the maintainer commit (with `-s`).
