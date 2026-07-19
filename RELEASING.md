# Releasing merklon to Maven Central

Published artifacts (Central Portal, namespace `eu.trustbeat`, verified via DNS TXT on
`trustbeat.eu`): **`merklon-core_3`**, **`merklon-verifier_3`**, **`merklon-java_3`**.
The server and Postgres backend are operator-side components and are deliberately
**not** published (`publish / skip := true` in `build.sbt`).

Prerequisites (already set up on the release machine — the same identity that publishes
`eu.trustbeat:trustbeat-sdk`):

- GPG release key `Trustbeat s.r.o. <radim.dejmek@trustbeat.eu>`; passphrase in
  `~/.gnupg/trustbeat-release-key.passphrase`.
- Central Portal user token in `~/.m2/settings.xml` under server id `central`
  (sbt-sonatype reads it from `SONATYPE_USERNAME` / `SONATYPE_PASSWORD` — exported below).

## Cutting a release

1. Bump `ThisBuild / version` in `build.sbt` (Central rejects re-publishing a version;
   never publish `-SNAPSHOT`). Update `CHANGELOG.md`; keep the README dependency
   snippets in sync.
2. Make sure the tree is clean and green: `sbt "scalafmtCheckAll; compile; test"`.
3. Stage signed artifacts and upload the bundle:

```bash
export PGP_PASSPHRASE="$(cat ~/.gnupg/trustbeat-release-key.passphrase)"
export SONATYPE_USERNAME=...   # <username> of the `central` server in ~/.m2/settings.xml
export SONATYPE_PASSWORD=...   # <password> of the same entry

sbt publishSigned          # → target/sonatype-staging/<version>/ (jars, sources, javadoc, .asc)
sbt sonatypeBundleRelease  # uploads the bundle; blocks until state PUBLISHED
```

4. Tag and push: `git tag -a vX.Y.Z -m "..." && git push origin vX.Y.Z`.

Verification: `sonatypeBundleRelease` polls the Portal until the deployment reports
`PUBLISHED`; artifacts resolve from `repo1.maven.org/maven2/eu/trustbeat/` within
minutes (search.maven.org indexing can lag by hours).
