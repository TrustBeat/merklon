# Contributing

Thanks for your interest! This project is cryptographic infrastructure, so
**correctness and verifiability come first**.

## Building and testing

```bash
sbt compile
sbt test
```

Every change that touches log behavior **must** come with tests. Where a relevant
standard defines test vectors (e.g. RFC 6962), prefer pinning to those vectors over
hand-rolled expectations.

## Developer Certificate of Origin (DCO)

This project uses the [Developer Certificate of Origin](https://developercertificate.org/)
instead of a CLA. By signing off on your commits you certify that you wrote the code
(or otherwise have the right to submit it under the project's license).

Sign off each commit:

```bash
git commit -s -m "your message"
```

This appends a line like:

```
Signed-off-by: Your Name <you@example.com>
```

Commits without a sign-off cannot be merged.

## Pull requests

- Keep PRs focused; one logical change per PR.
- Include tests and update docs/specs in the same PR.
- Explain *why*, not just *what*, in the description.
- CI (compile + tests) must be green.

## Reporting security issues

Do **not** use public issues or PRs for vulnerabilities — see [SECURITY.md](SECURITY.md).

## Code of conduct

By participating you agree to abide by the [Code of Conduct](CODE_OF_CONDUCT.md).
