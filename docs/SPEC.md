# merklon — Wire Format & API Specification

> **Status: DRAFT / in progress.** Nail these formats before implementing Phase 1+ — they are
> expensive to change once real data exists and once external witnesses/verifiers depend on them.
> This file is the home for the "spec-first" step.

## 0. Conventions

- The key words **MUST**, **MUST NOT**, **SHOULD**, **MAY** are used per RFC 2119/RFC 8174.
- **Hash function:** SHA-256 (RFC 9162 §2.1.1) for v1. The output is 32 bytes. Hash agility is a
  non-goal for v1; a future version MAY introduce an algorithm identifier.
- **Standard:** the Merkle tree, hashing, and proof structures follow **RFC 9162** (Certificate
  Transparency 2.0, which obsoletes RFC 6962). The tree is unchanged from RFC 6962, so the
  canonical RFC 6962 reference test vectors remain valid.
- **Binary-in-text encoding:**
  - Inside a checkpoint (signed note), the root hash is **standard base64** (RFC 4648, with
    padding), because that is what the checkpoint format mandates.
  - Inside JSON API responses, all hashes are **standard base64** (RFC 4648, with padding) for
    consistency with checkpoints. Tree sizes and indices are JSON numbers (unsigned, decimal).
- **Indexing:** leaves are 0-indexed. "tree size" / `n` is the number of leaves; valid leaf
  indices are `0 .. n-1`.

## 1. Hashing (RFC 9162 §2.1.1)

- Leaf hash: `leaf = SHA-256(0x00 || data)`
- Interior node hash: `node = SHA-256(0x01 || left || right)`
- Empty tree (MTH of `{}`): `SHA-256("")` =
  `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
- Merkle Tree Hash: `MTH(D[n]) = node(MTH(D[0:k]), MTH(D[k:n]))`, where the **split point** `k` is
  the largest power of two **strictly less than** `n`.

The leaf/node domain separation (the `0x00` / `0x01` prefixes) is required for second-preimage
resistance and MUST be preserved.

## 2. Leaf data & `LeafCodec`

The core hashes opaque bytes: the `data` fed to `leaf = SHA-256(0x00 || data)` is the **canonical
byte encoding** of an entry.

- The default codec is the **identity codec**: `data` is the raw submitted bytes, unmodified.
- A downstream application MAY supply a `LeafCodec` that canonicalizes a structured event
  (e.g. a deterministic encoding of `{actor, action, ts, source, prev_ref}`) into `data` before
  hashing. Canonicalization MUST be deterministic: equal events MUST produce identical `data`.

The log stores the original submitted bytes alongside the leaf hash; codecs affect only how `data`
is derived for hashing, never what is retained.

## 3. Checkpoint (signed note)

A checkpoint is merklon's signed commitment to `(tree_size, root_hash)` at a point in time. The
format is the **transparency.dev / C2SP checkpoint** ([c2sp.org/tlog-checkpoint]) carried in a
**signed note** ([c2sp.org/signed-note]), so existing witnesses and verifiers interoperate.

### 3.1 Note body

The body is UTF-8 text with no ASCII control characters except newline (`0x0A`). It consists of,
each terminated by a single `\n`:

```
<origin>
<tree_size>
<base64(root_hash)>
[<extension line>...]
```

1. **origin** — a schema-less, stable identifier for *this log's identity*. It MUST NOT contain
   spaces or `+`. merklon convention: a host/path label, e.g. `merklon.example/log`. (Reserved as
   the per-log "tenant/origin" field from `docs/DESIGN.md`.)
2. **tree_size** — ASCII decimal count of leaves, no leading zeros (`0` for the empty tree).
3. **root_hash** — standard base64 of the 32-byte RFC 9162 Merkle Tree Hash at `tree_size`.
4. **extension lines** *(OPTIONAL)* — opaque additional lines; verifiers that don't understand
   them MUST ignore them. Reserved for future use (e.g. timestamp hints).

### 3.2 Signatures

Per [c2sp.org/signed-note], the body (ending in `\n`) is followed by a **single blank line**, then
one or more signature lines:

```
— <key name> <base64(key_id || signature)>
```

- The line begins with U+2014 (em dash) + space.
- `key_id` = `SHA-256(key_name || 0x0A || 0x01 || ed25519_public_key)[:4]` (first 4 bytes,
  big-endian). `0x01` is the Ed25519 signature-type identifier.
- `ed25519_public_key` is 32 bytes (RFC 8032). `signature` is the 64-byte Ed25519 signature
  (RFC 8032) **over the exact note body bytes** (the text up to and including its final `\n`).
- The **log** signs first (its `CheckpointAttestor`, default = the log Ed25519 key). Additional
  signature lines carry **witness** co-signatures (Phase 3) and other attestors.

### 3.3 Example

A size-8 checkpoint over the RFC 6962 reference tree (root from the test vectors;
`tree_size = 8` ↔ `root = 5dc9da79…4328`). Signature is illustrative:

```
merklon.example/log
8
XcnaeacGWamtVZy3Ad7ZoqudgjqtL0lgz+Nw7/RgQyg=

— merklon.example/log Az3grlgtzPICa5OS8npVmf1Myq/5IZniMp+ZJurmRDeOoRDe4URY…
```

## 4. Inclusion proof

Proves that the leaf at `leaf_index` is included in the tree of size `tree_size` whose root is
published in a checkpoint.

### 4.1 Encoding (JSON)

```json
{
  "leaf_index": 0,
  "tree_size": 8,
  "audit_path": [
    "lqKW0iTyhcZ77pPDD4owkVfw2qNdxbh+QQt4YwoJz8c=",
    "Xwg/ChozygdqlSeYMlgNs+DvRYS9/x9UyKNg9Q3jAx4=",
    "a0eq8p7jwq+a+Im8H7klTavTEXfxYjLdaqsDXKOb9uQ="
  ]
}
```

`audit_path` is ordered **bottom-up**: the sibling closest to the leaf comes first. (This example
is the proof for leaf 0 in the size-8 reference tree.)

### 4.2 Verification

A verifier recomputes the root from the leaf hash and `audit_path` using the **RFC 9162 §2.1.3.2**
algorithm and checks it equals the checkpoint's `root_hash`. The verifier MUST share no state with
the server: inputs are the entry bytes (→ leaf hash), the proof, and the trusted checkpoint.
Implemented by `MerkleTree.verifyInclusion`.

## 5. Consistency proof

Proves that the tree at size `first` is an append-only **prefix** of the tree at size `second`
(nothing reordered, removed, or rewritten).

### 5.1 Encoding (JSON)

```json
{
  "first": 4,
  "second": 8,
  "proof_path": [
    "a0eq8p7jwq+a+Im8H7klTavTEXfxYjLdaqsDXKOb9uQ="
  ]
}
```

(This example is the `4 → 8` consistency proof in the reference tree.)

### 5.2 Verification

A verifier checks, via the **RFC 9162 §2.1.4.2** algorithm, that the size-`first` root and the
size-`second` root are consistent. This is the property that makes the log tamper-evident: a server
cannot rewrite history without producing an invalid consistency proof. Implemented by
`MerkleTree.verifyConsistency`.

## 6. HTTP API (Phase 2)

JSON over HTTPS. The dynamic API below is the primary shape; a **static tile-based layout**
([c2sp.org/tlog-tiles], the Sunlight model) is an alternative deployment that serves the same data
as cacheable static files — reserved for a later iteration.

| Method & path | Purpose | Response |
|---|---|---|
| `POST /entries` | Submit an entry. Body is the raw entry bytes (or `{ "data": base64 }`). | `{ "leaf_index": N }` — the assigned index. Inclusion is provable only once a checkpoint integrates it. |
| `GET /checkpoint` | Latest signed checkpoint. | `text/plain` signed note (§3). |
| `GET /proof/inclusion?leaf_index=&tree_size=` | Inclusion proof against a tree size. | §4.1 |
| `GET /proof/consistency?first=&second=` | Consistency proof between two sizes. | §5.1 |

Notes / TODO:
- **TODO:** inclusion lookup **by leaf hash** (`?hash=`) in addition to by index, mirroring
  RFC 9162 `get-proof-by-hash`.
- **TODO:** entry retrieval (`GET /entries?start=&end=`) and tile/node fetch endpoints if/when the
  tiles backend lands.
- **TODO:** error model (status codes + JSON error body), pagination limits, and whether
  `tree_size` defaults to the latest checkpoint when omitted.

## 7. Proof bundle (offline-verifiable, Phase 4)

A self-contained artifact a relying party verifies **fully offline** with the CLI verifier:

```
{ entry, inclusion_proof, checkpoint, witness_sigs[], qualified_timestamp? }
```

- `entry` — the original bytes (the verifier recomputes the leaf hash).
- `inclusion_proof` — §4.1, against `checkpoint.tree_size`.
- `checkpoint` — the signed note (§3), including log + witness signatures.
- `qualified_timestamp` *(OPTIONAL)* — `CheckpointAttestor` output, e.g. an RFC 3161 token over the
  checkpoint root ("this state existed at this time").
- **TODO:** concrete container encoding (single JSON document vs. a small archive) and the exact
  field names / base64 conventions.

## 8. Versioning

- This spec is versioned with the repository and tracked in `CHANGELOG.md`.
- Wire-format-breaking changes MUST bump a documented format version before any production data
  exists; after that, changes MUST remain backward compatible or define a migration.

## References

- RFC 9162 (Certificate Transparency 2.0; obsoletes RFC 6962) — Merkle log hashing, inclusion /
  consistency proofs and their verification algorithms
- RFC 8032 — Ed25519 signatures
- RFC 4648 — base64 encoding
- [c2sp.org/tlog-checkpoint] — checkpoint format
- [c2sp.org/signed-note] — signed note format (signatures, key IDs)
- [c2sp.org/tlog-tiles] — static tile-based log layout (Sunlight model)
- transparency.dev — checkpoint & witness specs
- `golang.org/x/mod/sumdb/tlog` — Go checksum DB transparency log (clean reference)

[c2sp.org/tlog-checkpoint]: https://c2sp.org/tlog-checkpoint
[c2sp.org/signed-note]: https://c2sp.org/signed-note
[c2sp.org/tlog-tiles]: https://c2sp.org/tlog-tiles
