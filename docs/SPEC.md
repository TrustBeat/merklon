# merklon — Wire Format & API Specification

> **Status: DRAFT / in progress.** Nail these formats before implementing Phase 1+ — they are
> expensive to change once real data exists. This file is the home for the "spec-first" step.

## 1. Hashing (RFC 6962)
- Leaf hash: `SHA-256(0x00 || data)`
- Interior node hash: `SHA-256(0x01 || left || right)`
- Empty tree (MTH of `{}`): `SHA-256("")`
- Split point: `k` = largest power of two **strictly less than** `n`.
- **TODO:** define what `data` is — raw bytes vs. `LeafCodec`-canonicalized event envelope.

## 2. Checkpoint (signed note)
Goal: a small, line-oriented, signable artifact compatible with the transparency.dev
checkpoint / Go signed-note format, so existing witnesses/tooling interoperate.

- **TODO:** finalize fields and encoding:
  - `origin` (log identity / namespace line)
  - `tree_size` (decimal)
  - `root_hash` (base64)
  - signature block: log Ed25519 signature; optional witness lines; optional attestor lines
    (e.g. RFC 3161 qualified timestamp reference)

## 3. Inclusion proof
- **TODO:** encoding of `{ leaf_index, tree_size, audit_path[] }` and the verification
  algorithm (RFC 6962 §2.1.1).

## 4. Consistency proof
- **TODO:** encoding of `{ size1, size2, proof_path[] }` and the verification algorithm
  (RFC 6962 §2.1.2). This is what proves append-only.

## 5. HTTP API (Phase 2)
- **TODO:** confirm shapes:
  - `POST /entries` → `{ index }`
  - `GET  /checkpoint` → latest signed checkpoint
  - `GET  /proof/inclusion?index=&size=` → inclusion proof
  - `GET  /proof/consistency?from=&to=` → consistency proof
  - tile/node fetch endpoints (if adopting the tiles model)

## 6. Proof bundle (offline-verifiable, Phase 4)
- **TODO:** self-contained `{ entry, inclusion_proof, checkpoint, witness_sigs[],
  qualified_timestamp }` that the CLI verifier checks fully offline.

## References
- RFC 6962 (Certificate Transparency)
- transparency.dev — checkpoint (signed note) & witness specs
- tlog-tiles / Sunlight (static-file tile model)
- `golang.org/x/mod/sumdb/tlog` (Go checksum DB)
