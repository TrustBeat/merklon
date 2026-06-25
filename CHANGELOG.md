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
