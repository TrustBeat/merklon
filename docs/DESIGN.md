# merklon — Design Notes (Verifiable Transparency Log)

> Working notes consolidating the architecture discussion. A **standalone, open-source**
> verifiable transparency log, built with clean extension points so downstream applications can
> plug into the core without forking it. Build the core for its own sake (and reputation);
> downstream applications are a deferred, optional layer on top.

---

## 1. Build scope

### Guiding principle: two layers, clean seam

```
┌─────────────────────────────────────────────┐
│  LAYER 2 (downstream): applications built on  │
│  the core — auth, storage policy, custom       │
│  attestation, evidence packaging               │
└───────────────▲─────────────────────────────┘
                │  plugs into extension points
┌───────────────┴─────────────────────────────┐
│  LAYER 1 (this repo, open source): Verifiable │
│  Log — Merkle log · checkpoints · inclusion/   │
│  consistency proofs · serving · witnessing ·   │
│  independent verifier                          │
└─────────────────────────────────────────────┘
```

The core must be usable and verifiable by anyone with **zero knowledge of any downstream
application**. That's what makes it spread on merit. Extension value is invisible until you turn
it on.

### Core components (Layer 1)
1. **Merkle log (heart):** RFC 9162 hashing (`leaf = H(0x00‖data)`, `node = H(0x01‖L‖R)`), append, root.
2. **Proofs:** inclusion (audit path) + **consistency** (tree size N1 is a prefix of N2 → append-only,
   no history rewrite). The cryptographic soul.
3. **Checkpoints:** signed note format (origin, tree size, root hash, signature(s)); Ed25519 log key.
4. **Sequencer:** drains pending entries → integrates into tree → publishes checkpoint on a cadence.
5. **Storage:** behind an interface. Start Postgres-backed; design so a tile-based / static-file
   backend ("tlog-tiles / Sunlight" model — cheap, scalable static serving) can replace it later.
6. **Serving API:** submit entry, get checkpoint, get inclusion proof, get consistency proof, fetch
   nodes/tiles.
7. **Independent verifier (library + CLI):** verifies proofs *without trusting the server*. Correctness-
   critical AND the single best credibility artifact — ship it prominently.
8. **Witnessing:** a witness verifies consistency between checkpoints and co-signs; clients require N
   witness sigs. Defeats split-view/equivocation. The hard, prestigious part.

### Actors & deployment shapes

A transparency log exists because these roles **don't trust each other** — verification is what
substitutes for trust. The core is designed so each role can do its job with the minimum it needs.

| Actor | Who | What they do | Needs |
|---|---|---|---|
| **Log operator** | Whoever runs an instance (platform team, issuing service, internal infra) | Accepts entries, sequences them into the tree, publishes signed checkpoints. | A running server + storage. |
| **Submitter / writer** | Systems producing records worth making tamper-evident (cert issuers, build/release pipelines, event sources) | Append an entry; receive an inclusion proof. | Network access to the serving API. |
| **Verifier / monitor** | Anyone — auditors, clients, third parties | Fetch a checkpoint + proofs and verify inclusion + consistency **without trusting the operator**. | The checkpoint, the proofs, and the log's public key. **No DB, no server trust.** |
| **Witness** *(Phase 3)* | Independent co-signers | Verify each new checkpoint is consistent with the prior one and co-sign; clients can require N signatures to defeat split-view/equivocation. | The checkpoint stream + their own key. |

Three deployment shapes follow from this, each with different infrastructure needs:

- **As a library (the pure core).** Embed the Merkle core + proofs directly; pure functions over
  bytes — **no I/O, no database, no framework.** Useful for building proofs into another system.
- **As a running log (operator).** Server + sequencer + storage behind the `StorageBackend`
  interface. Default is **PostgreSQL**, but the interface anticipates a **tile-based / static-file
  backend** ("tlog-tiles / Sunlight" model) so a log can be served as cheap static files with **no
  database at all**. So storage is required to operate a log, but the *kind* is pluggable.
- **As a verifier (library + CLI).** Consumes checkpoints and proofs over HTTP and verifies them
  locally. **Never needs a database and never trusts the server** — this is the whole value
  proposition, and the single best credibility artifact.

In short: **library use → no DB; operating a log → storage required but pluggable (Postgres default,
static-file/tiled possible); verifying → no DB, no trust.**

### Extension points (design in now)

The core stays generic; downstream applications attach behavior through these hooks instead of
forking. Each is an interface in Layer 1 with a sensible default.

| Hook | What it is | Why a downstream app might need it | Now? |
|---|---|---|---|
| **`CheckpointAttestor`** | Pluggable signer over each checkpoint root. Default = log Ed25519 key. | A stronger attestor — e.g. a qualified RFC 3161 timestamp → "this state existed at this time." | **Build (cheap)** |
| **`LeafCodec`** | Core stores opaque `data`; codec defines `leaf = H(canonical(event))`. | A structured event envelope (actor, action, ts, source, prev_ref). | **Design iface + default JSON codec** |
| **`ProofBundle` export** | Self-contained offline-verifiable package: entry + inclusion proof + checkpoint + witness sigs + attestations. | The artifact a relying party verifies offline (offline-verify experience). | **Build (cheap, high value)** |
| **`StorageBackend`** | Interface over persistence. | Isolated / tiled storage for different deployments. | **Design interface now** |
| **Tenant/origin namespacing** | Each checkpoint carries a log identity/origin. | Multiple independent logs (one per system/origin). | **Reserve field; don't build** |
| **`AppendAuthorizer`** | Pluggable auth on write path. Default = none. | Authenticated ingestion. | **Design iface; default no-op** |
| **Re-stamping / LTV** | Periodic re-timestamp of historical checkpoints. | Logs retained for years must stay verifiable after signing certs expire. | **Design for it; defer build** |

Rule: **interfaces in now, implementation deferred** — except the qualified-TS attestor and the proof
bundle, which are cheap and are exactly what differentiate this log from every generic one.

### Data model (core)
```
LogEntry   { index, leaf_hash, data, submitted_at }
TreeNode   { level, index, hash }              // or tiles
Checkpoint { tree_size, root_hash, signed_at,
             log_signature, attestations[],     // ← CheckpointAttestor output (incl. qualified TS)
             witness_signatures[] }
```

### Build order (each phase ends in something verifiable)
- **Phase 0 — Merkle core.** Append, root, inclusion + consistency proofs. *Done when:* passes known
  RFC 6962 / Go-tlog test vectors; CLI verifier confirms. ✅ **done**
- **Phase 1 — Persistence + checkpoints.** Postgres `StorageBackend`; Ed25519-signed checkpoints;
  sequencer batching on a cadence. *Done when:* append 100k entries across restarts, every checkpoint
  chains consistently. ✅ **done** (Postgres backend + durable Ed25519 log key; 100k-across-restarts
  integration test in `merklon-storage-pg`; timed batching cadence still pending)
- **Phase 2 — Serving + independent verifier.** HTTP API + standalone verifier library/CLI.
  *Done when:* a client that never trusts the server can fetch a checkpoint and verify any entry's
  inclusion + the log's consistency. ✅ **done**
- **Phase 3 — Witnessing.** Witness service + N-of-M cosigning; client policy requiring witness sigs.
  *Done when:* a deliberately equivocating log (split-view test) is detected. *Hard, respected milestone.*
  ✅ **done** (c2sp.org/tlog-witness HTTP service with durable file state + cosignature/v1;
  log-side submission with 409 size negotiation; N-of-M client policy in library + verifier CLI;
  split-view detection tested at the core AND over HTTP with the spec's status codes)
- **Phase 4 — Extension hooks (cheap wins only).** Wire `CheckpointAttestor` → qualified TS; `LeafCodec`
  structured-event default codec; `ProofBundle` export. *Done when:* export an offline evidence bundle
  for an event, sealed with a qualified timestamp, verify it with the CLI offline.

### "v1" (the thing you publish)
Phases 0–2 + cheap Phase-4 hooks: **an open-source verifiable append-only log, with an independent CLI
verifier, that can optionally seal checkpoints with qualified timestamps and export offline-verifiable
proof bundles.** Witnessing (Phase 3) is the headline v1.1 that makes it serious.

### Explicitly OUT of scope (it's downstream, not the core)
Application-level concerns — multi-tenancy, authenticated ingestion, dashboards/reporting, billing,
retention automation — are downstream and out of scope here. All are reachable through the interfaces
above; none are built in this repo.

### Tech & repo
Pure, dependency-light **Scala 3** core; outer layers may use **ZIO / ZIO HTTP, Bouncy Castle,
PostgreSQL**. This is a **standalone repo** so it reads as a clean, focused open-source project. Bake
in test vectors + the independent verifier from day one — for a transparency log, verifiable
correctness *is* the product.

---

## 2. Next step (open)
Two options:
- **(a)** Write the **Phase 0 core** — Merkle tree + inclusion/consistency proofs + test-vector suite.
- **(b)** Draft the **spec** (`docs/SPEC.md`: data formats, checkpoint/note format, API) so wire formats
  and proof semantics are nailed before cutting code. *Recommended first* — the formats are the part you
  don't want to redo.

## 3. Reference points
- RFC 9162 (Certificate Transparency 2.0; obsoletes RFC 6962) — Merkle log hashing, inclusion/consistency proofs
- Trillian (general verifiable log), Sigstore Rekor (transparency log + supply chain)
- "tlog-tiles" / Sunlight (Filippo Valsorda / Let's Encrypt) — static-file tile-based modern CT log
- `golang.org/x/mod/sumdb/tlog` — Go checksum DB transparency log (clean reference)
- transparency.dev — checkpoint (signed note) & witness specs
