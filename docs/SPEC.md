# merklon — Wire Format & API Specification

> **Status: implemented (v0.1.0), not yet frozen.** Every format below is implemented and
> tested. Wire-format stability will be declared at v1.0; until then changes are expected to be
> additive only — they are expensive once real data exists and once external
> witnesses/verifiers depend on them.

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

1. **origin** — a schema-less, stable identifier for *this log's identity*. It MUST be non-empty;
   per [c2sp.org/tlog-checkpoint] it SHOULD be a schema-less URL containing neither spaces nor
   `+`. merklon logs always follow that recommendation: a host/path label, e.g.
   `merklon.example/log`. (Reserved as the per-log "tenant/origin" field from `docs/DESIGN.md`.)
2. **tree_size** — ASCII decimal count of leaves, no leading zeros (`0` for the empty tree).
3. **root_hash** — standard base64 of the 32-byte RFC 9162 Merkle Tree Hash at `tree_size`.
4. **extension lines** *(OPTIONAL)* — opaque additional lines; verifiers that don't understand
   them MUST ignore them. Their use is NOT RECOMMENDED upstream (they are not auditable by
   monitors and cosignature semantics exclude them) — merklon never emits any; qualified
   timestamps travel in the proof bundle (§8), not as note lines.

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
  signature lines carry **witness** cosignatures and other attestors. Witness lines use the
  cosignature/v1 format (§7.2), whose signed message and key-ID type byte differ from the plain
  log signature described here.
- **Strict verification** (c2sp.org/signed-note): a signature line is *from a known key* when its
  key ID matches the key-ID formula over its own key name and a trusted public key. Every
  known-key line MUST verify — one failing known-key line makes the whole note invalid — and
  lines from unknown keys are ignored. merklon's witness and verifier both enforce this; a note
  is accepted only if at least one known-key line is present and all of them verify.

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
| `POST /entries` | Submit an entry. Body is the raw entry bytes (or `{ "data": base64 }`). | `{ "leaf_index": N, "tree_size": M }` — the assigned index and the size of the checkpoint that integrated it. The server batches: checkpoints are published on a timed cadence (one checkpoint — and one witness round — per interval, `MERKLON_BATCH_MS`), and the response returns once the entry's covering checkpoint is published and witnessed, so proofs against `M` work immediately. `503` if no checkpoint integrated the entry within the server's wait bound; the entry itself remains durably appended. |
| `GET /entries?start=&end=` | Entries of `[start, end)` so monitors and mirrors can replay the log and recompute roots. | `{ "entries": [ { "leaf_index": N, "data": base64 }, … ] }` — at most **1000** per request (clamp `end` and page). |
| `GET /checkpoint` | Latest signed checkpoint. | `text/plain` signed note (§3). |
| `GET /proof/inclusion?tree_size=&(leaf_index= \| leaf_hash=)` | Inclusion proof against a tree size. `leaf_hash` (hex) mirrors RFC 9162 `get-proof-by-hash`: the lowest matching index is resolved and echoed back; clients compute the hash locally over the codec's canonical form (§9). | §4.1. `404` for an unknown hash. |
| `GET /proof/consistency?first=&second=` | Consistency proof between two sizes. | §5.1 |
| `GET /bundle?leaf_index=` | Offline-verifiable proof bundle for one entry, against the latest checkpoint. | §8. `404` if the leaf is not yet integrated; `502` if a TSA is configured but unreachable (never a silently unsealed bundle). |
| `GET /tlog-proof?leaf_index=` | The same entry's proof as a **c2sp.org/tlog-proof@v1** document (§8.4) — the ecosystem interchange format; carries no entry bytes and no RFC 3161 token. | `text/plain` tlog-proof. `404` if the leaf is not yet integrated. |

### 6.1 Error model

Errors are plain-text bodies (human-readable reason) with these status codes; success bodies are
JSON except `GET /checkpoint` (`text/plain` note). The witness endpoints follow their own protocol
statuses (§7.3).

| Status | Meaning |
|---|---|
| `400` | Malformed or missing parameters; entry rejected by the configured `LeafCodec` (§9) or `AppendAuthorizer`. |
| `404` | No checkpoint published yet; unknown `leaf_hash`; `leaf_index` beyond the latest checkpoint (`/bundle`). |
| `413` | Entry exceeds the log's size cap (`MERKLON_MAX_ENTRY_BYTES`, default 65536). |
| `502` | A TSA is configured but could not produce a token (`/bundle`). |
| `503` | The entry was durably appended but no checkpoint integrated it within the server's wait bound — retry `GET /checkpoint` / `GET /proof/inclusion` later. |

Remaining TODO: tile/node fetch endpoints if/when the tiles backend lands; whether `tree_size`
defaults to the latest checkpoint when omitted.

## 7. Witnessing (Phase 3)

A **witness** is an independent party that attests to the log's *consistency over time*. It
defeats split-view attacks: a log that shows different histories to different observers cannot
get both histories cosigned by the same honest witness.

### 7.1 Witness behavior

For each observed checkpoint, a witness MUST, in order:

1. Check the checkpoint's `origin` is one it watches; otherwise refuse.
2. Validate the log's signature under the **strict** signed-note rule (§3.2): at least one
   known-key line verifies and no known-key line fails; otherwise refuse.
3. If `tree_size` is 0, the root MUST be the empty-tree root (`SHA-256("")`); otherwise refuse.
4. Compare against the last checkpoint it cosigned for this origin:
   - **First observation:** the supplied consistency proof MUST be empty (nothing to prove
     from); cosign (trust-on-first-use — the witness's attestation window starts here).
   - **Same `tree_size`:** the root hashes MUST be identical; a differing root is a
     **split view** and MUST be refused.
   - **Larger `tree_size`:** the log supplies an RFC 9162 consistency proof from the cosigned
     size; the witness verifies it (§5.2) and refuses a failure as a **history rewrite**. From
     cosigned size 0 the proof MUST be empty (the empty tree is a prefix of every tree).
   - **Smaller `tree_size`:** refuse — a transparency log never shrinks.
5. On success, produce a **cosignature/v1** (§7.2) and return its signature line. The log
   appends witness signature lines to the same note after its own.

The witness's last-cosigned checkpoint MUST be durable; losing it silently resets the witness
to trust-on-first-use and erases its consistency guarantee. A refusal for split view or history
rewrite yields **transferable evidence of log misbehavior**: two conflicting checkpoints, each
carrying a valid signature from the same log key. Implemented by `merklon.Witness` (refusals:
`merklon.WitnessRefusal`; durable state: `merklon.WitnessStateStore`).

### 7.2 Cosignature format (c2sp.org/tlog-cosignature, "cosignature/v1")

A witness does NOT sign the bare note body (that is the log's signature). The signed message is:

```
cosignature/v1
time <unix seconds>
<note body (§3.1), including its final newline>
```

The signature line's base64 blob is `key_id(4) || timestamp(8, big-endian) || ed25519_sig(64)`
(76 bytes), and the key ID uses signature-type byte **0x04**:
`SHA-256(key_name || 0x0A || 0x04 || ed25519_public_key)[:4]`. The timestamp MUST NOT be zero.
Implemented by `merklon.CosignatureV1`.

### 7.3 Witness HTTP protocol (c2sp.org/tlog-witness)

`POST <prefix>/add-checkpoint`, request body (each line `\n`-terminated):

```
old <last cosigned tree size>
<base64 consistency proof hash>     (0 to 63 lines)
<empty line>
<checkpoint signed note (§3)>
```

Responses:

| Status | Meaning |
|---|---|
| 200 | Cosigned; body is the witness's cosignature line(s) (§7.2). |
| 400 | Malformed request, or `old` exceeds the submitted checkpoint's size. |
| 403 | No known-key signature on the note verifies, or a known-key line fails to verify (strict rule, §3.2). |
| 404 | The note's origin is not watched by this witness. |
| 409 | `old` differs from the witness's latest cosigned size — body is that size (ASCII decimal + `\n`, `Content-Type: text/x.tlog.size`); the submitter retries with the returned size. |
| 422 | The consistency proof does not verify (history rewrite); a same-size, different-root submission (**split view**); a size-zero checkpoint without the empty-tree root; or a non-empty proof where none is possible (§7.1 steps 3–4). |

(Split view moved from 409 to 422 to track the upstream tlog-witness change of 2026-07-06 —
409 is now exclusively the size-negotiation response.)

Monitoring: `GET <prefix>/<hex(SHA-256(origin))>/checkpoint` returns the latest cosigned note
(log + witness signatures) or 404. Implemented by `merklon.server.witness.WitnessServer`
(service) and `merklon.server.WitnessClient` (log-side submission with 409 size negotiation).

**Deviations / TODO:** the c2sp spec's optional `sign-subtree` endpoint is not implemented;
ML-DSA-44 cosignatures (upstream SHOULD — for witnesses, and per tlog-checkpoint now for log
signatures too) await JDK/BC support — merklon uses Ed25519 cosignature/v1 (a MAY); notes with
extension lines (§3.1) are currently refused by the witness because the body is reconstructed
from parsed fields (fails closed).

### 7.4 Client policy (N-of-M)

A client configures M trusted witnesses (key name + raw Ed25519 public key) and a threshold N.
A checkpoint satisfies the policy when at least **N distinct** trusted witnesses have a valid
cosignature/v1 (§7.2) on it. Duplicate lines from one witness count once; unknown or
unverifiable lines are ignored (consistent with §3.1 tolerance). Implemented by
`merklon.WitnessPolicy`; exposed in the CLI verifier as
`--witness NAME=HEX_PUBKEY … [--witness-threshold N]` (default threshold: all listed).

### 7.5 Witness deployment requirements

**One witness key, one process.** A witness key MUST be served by exactly one process at a
time, holding exclusive ownership of its durable state (§7.1). The append-only guarantee a
witness attests to is enforced by serializing all observations against a single last-cosigned
checkpoint; two replicas of the same key with independent state can each cosign a *different*
root at the same tree size — making the witness itself equivocate, and turning its own
signatures into §7.1-style misbehavior evidence against it.

Consequences:

- A witness MUST NOT be horizontally replicated (e.g. multiple instances of one key behind a
  load balancer). Failover MUST be active/passive with the durable state handed over — never
  two live signers.
- Witnessing scales by adding **more witnesses with distinct keys** — which also strengthens
  the N-of-M policy (§7.4) — never by replicating one key. Throughput is not a concern: a
  witness performs one verification and one signature per checkpoint interval.
- The split-view guarantee of §7.4 additionally assumes witnesses are **operationally
  independent of the log and of each other** (separate operators, infrastructure, and key
  custody). Witnesses run by the log operator protect only against server compromise, not
  against a dishonest operator, and MUST NOT be counted toward N by a client that does not
  trust the operator.

(A replicated single-key witness would require a `WitnessStateStore` backend with an atomic
compare-and-swap; this is deliberately out of scope.)

## 8. Proof bundle (offline-verifiable, Phase 4)

A self-contained artifact a relying party verifies **fully offline** with the CLI verifier
(`merklon-verify --pubkey HEX [--witness …] [--tsa-cert PEM] bundle FILE`). Exported by the log
at `GET /bundle?leaf_index=N` (§6).

### 8.1 Container: `merklon-bundle/v1`

A single JSON document. Every binary field is base64 (RFC 4648, with padding). The checkpoint
note is embedded base64-encoded **byte-for-byte**, so its newlines and em-dashes survive any JSON
tooling and the note's signatures keep verifying:

```json
{
  "format": "merklon-bundle/v1",
  "leaf_index": 5,
  "entry": "<base64: original entry bytes>",
  "inclusion_proof": ["<base64: audit-path hash>", "…"],
  "checkpoint": "<base64: the full signed note (§3), incl. any witness cosignatures>",
  "rfc3161_tst": "<base64: DER-encoded RFC 3161 TimeStampToken>"
}
```

- `format` *(REQUIRED)* — exactly `merklon-bundle/v1`; parsers MUST reject anything else.
- `leaf_index` *(REQUIRED)* — the entry's 0-based index; MUST be `< tree_size` of the checkpoint.
- `entry` *(REQUIRED)* — the original submitted bytes; the verifier recomputes the leaf hash.
- `inclusion_proof` *(REQUIRED)* — the §4.1 audit path against the embedded checkpoint's size.
- `checkpoint` *(REQUIRED)* — the signed note (§3) with the log signature and any cosignatures.
- `rfc3161_tst` *(OPTIONAL)* — an RFC 3161 timestamp token whose SHA-256 **message imprint is the
  checkpoint note body** (§3: origin, tree size, root hash) — "this log state existed at this
  time." Binding the body rather than the full note keeps the attested statement independent of
  which signature lines happen to be attached when the token is requested. Qualified timestamps
  travel in the bundle, not as note lines: cosignature verifiers fail closed on extension lines,
  and multi-kilobyte DER blobs do not belong in the note format.

### 8.2 Verification (fully offline)

Given the trusted log public key, optionally M trusted witnesses + threshold N, and optionally
the TSA certificate, the verifier checks in order — failing closed at the first error:

1. container syntax and `format`;
2. the embedded note parses and its log signature verifies (§3);
3. the witness policy (§7.4), when witnesses are configured;
4. the recomputed leaf hash of `entry` proves inclusion at `leaf_index` (§4.2);
5. when `rfc3161_tst` is present: the token's imprint equals SHA-256 of the note body — and,
   when a TSA certificate is supplied, the token's CMS signature verifies against it (ESSCertID,
   timestamping EKU, certificate validity at genTime). Supplying a TSA certificate for a bundle
   *without* a token is a failure. Without a certificate the token's timestamp is reported as
   imprint-bound but signer-unverified.

Implemented by `merklon.verifier.BundleVerifier` / `TimestampVerifier`; the log is never
contacted.

### 8.3 Export

The server builds bundles against its latest checkpoint. With `MERKLON_TSA_URL` configured, each
bundle is sealed with a token from that RFC 3161 TSA (one TSA round-trip per checkpoint — tokens
are cached and reused until the checkpoint advances). If the TSA cannot produce a token the
export fails with `502` rather than serving an unsealed bundle.

### 8.4 Ecosystem interchange: `c2sp.org/tlog-proof@v1`

Alongside the merklon-native bundle, the log exports the standardized
**[c2sp.org/tlog-proof]** format (`GET /tlog-proof?leaf_index=N`, `text/plain`; files SHOULD
use the `.tlog-proof` extension):

```
c2sp.org/tlog-proof@v1
[extra <base64>]
index <leaf index>
<base64 inclusion-proof hash>...

<checkpoint signed note (§3), verbatim, incl. cosignatures>
```

Differences from `merklon-bundle/v1`: a tlog-proof carries **no entry bytes** (the relying
party supplies them out of band) and **no RFC 3161 token**; the optional `extra` line is opaque
and **not authenticated**. Use the bundle when the artifact must be self-contained legal
evidence; use tlog-proof to interoperate with other transparency-log tooling ("transparent
signatures").

Offline verification (CLI: `tlog-proof FILE DATA_HEX`; library:
`merklon.verifier.TlogProofVerifier`) checks, in order: document syntax; the embedded note's
log signature (strict rule, §3.2); the witness policy (§7.4), when configured; and the
inclusion proof of the supplied entry bytes under the log's codec (§9).

## 9. Structured event codec (`structured-event/v1`)

The core stores opaque bytes; a `LeafCodec` defines what gets leaf-hashed:
`leaf = H(codec.encode(data))`. The submitted bytes are what is stored and served (§6); the codec
only shapes the hash input. The default codec is **identity**. Verifiers MUST apply the log's
codec when recomputing leaf hashes (CLI: `--codec`; server: `MERKLON_CODEC`).

`structured-event/v1` is the built-in codec for structured events: it strictly parses the
submitted JSON and re-emits it **canonically**, so producers' field order, whitespace, and escape
choices cannot change the leaf hash.

### 9.1 Envelope

One flat JSON object; values are strings or non-negative integers only (no nesting):

| Field | Type | Required | Meaning |
|---|---|---|---|
| `actor` | string | yes | Who performed the action. |
| `action` | string | yes | What happened. |
| `source` | string | yes | Which system emitted the event. |
| `time` | integer | yes | Event time, milliseconds since the Unix epoch, `>= 0`. |
| `prev_ref` | string | no | Lowercase hex reference to an earlier leaf hash (event chaining). |
| `payload` | string | no | Free-form content. |

Parsing **fails closed**: unknown fields, duplicate keys, nested values, fractions/exponents,
uppercase or odd-length `prev_ref` hex, and trailing content are errors (HTTP `400` at the API),
never silently normalized.

### 9.2 Canonical form

Keys in lexicographic order (`action`, `actor`, `payload`?, `prev_ref`?, `source`, `time`),
absent optional fields omitted, no whitespace, UTF-8. String escaping is minimal and fixed:
`\"`, `\\`, the two-character escapes for backspace/form-feed/newline/carriage-return/tab,
`\u00xx` (lowercase hex) for other control characters, everything else raw UTF-8:

```json
{"action":"login","actor":"alice","payload":"ok","prev_ref":"0a0b","source":"auth-svc","time":1750000000000}
```

The canonical form is a fixed point: parsing it and re-encoding reproduces it byte-exactly.
Implemented by `merklon.StructuredEvent` / `LeafCodec.StructuredEventJsonV1`.

## 10. Versioning

- This spec is versioned with the repository and tracked in `CHANGELOG.md`.
- Wire-format-breaking changes MUST bump a documented format version before any production data
  exists; after that, changes MUST remain backward compatible or define a migration.

## References

- RFC 9162 (Certificate Transparency 2.0; obsoletes RFC 6962) — Merkle log hashing, inclusion /
  consistency proofs and their verification algorithms
- RFC 8032 — Ed25519 signatures
- RFC 4648 — base64 encoding
- [c2sp.org/tlog-checkpoint] — checkpoint format (pinned upstream as `tlog-checkpoint@v1.0.0`)
- [c2sp.org/signed-note] — signed note format (signatures, key IDs; pinned upstream as
  `signed-note@v1.0.0`)
- [c2sp.org/tlog-cosignature] — cosignature/v1 (and the ML-DSA-44 type merklon does not yet ship)
- [c2sp.org/tlog-witness] — witness HTTP protocol (§7.3; conformance tracked as of 2026-07)
- [c2sp.org/tlog-proof] — offline proof interchange format (§8.4)
- [c2sp.org/tlog-tiles] — static tile-based log layout (Sunlight model)
- transparency.dev — checkpoint & witness specs
- `golang.org/x/mod/sumdb/tlog` — Go checksum DB transparency log (clean reference)

[c2sp.org/tlog-checkpoint]: https://c2sp.org/tlog-checkpoint
[c2sp.org/signed-note]: https://c2sp.org/signed-note
[c2sp.org/tlog-cosignature]: https://c2sp.org/tlog-cosignature
[c2sp.org/tlog-witness]: https://c2sp.org/tlog-witness
[c2sp.org/tlog-proof]: https://c2sp.org/tlog-proof
[c2sp.org/tlog-tiles]: https://c2sp.org/tlog-tiles
