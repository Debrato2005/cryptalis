# Installed-library preview milestone

The 2026-11-01 instruction prioritizes an independently installable library,
a separate fresh-clone Smolink demonstration, reproducible measurements and a
frozen demonstrated revision. All [34 product objectives](BUILD_CHECKLIST.md)
remain required for production. This milestone does not admit additional SQL
operations or qualify any of the seven production gates.

Preparation uses `preview/smolink-20261101` in Cryptalis and
`demo/cryptalis-preview-20261101` in a separate Smolink checkout. Smolink code,
configuration, dependencies and demonstration evidence belong to that checkout,
outside the Cryptalis distribution. Reusable library fixes return to main after
verification; the branches are checkpoints, not separate products.

## Acceptance

| Result | Required evidence |
|---|---|
| Independent package | Repeat-built wheel/sdist, inspected metadata and contents, public API/CLI, clean pip and uv installs outside the checkout on each declared Python environment |
| Small integration | Manifest, external provider and explicit host settings; exact application/code/configuration changes and prerequisites |
| Real application | Pinned fresh Smolink clone, unchanged implemented routes, real PostgreSQL and Redis, API responses and original OpenAPI/Swagger screen |
| Encryption | Independent database observation and authorized application plaintext; no plaintext fallback or test-only crypto path |
| Lifecycle | Current updates, admitted searches, distinct wrapping/payload/search rotation, interruption/recovery, fresh restore, current-value decrypt-back, owned-object removal and restart without the package |
| Matched costs | Same application revision, data, runtime, services and workloads; raw latency/resource/storage samples and lifecycle timings with misses and errors retained |
| Independent adoption | Installed library through another backend's complete bounded journey |
| Reviewable checkpoint | Installation, API, compatibility, limits and troubleshooting docs; exact pushed source/artifact/evidence identities and frozen revisions |

Smolink at `498d24bae999ed53ad85e1c1f1a09ea7fa151aa4` implements URL
creation at `POST /api/v1/urls`. URL read/update/delete and redirect endpoints
are planned in that revision. Existing repository/ORM operations can demonstrate
updates; they must be labelled as those operations. They are not Smolink API
features. Protecting `Url.destination` does not encrypt account fields or the
public short code. Its storage-only profile admits no destination equality/IN
search. Other search evidence must identify its own application and scope.

The retained targets remain added p95 of at most 3 ms for point/equality reads,
8 ms for IN-20 and 2× protected-column-plus-index storage where applicable.
An unavailable workload is unmeasured; an observed miss is a miss. Historical
microbenchmarks are not current Smolink measurements. A local provider deployment
does not qualify production custody, HA, audit or disaster recovery.

## Publication and continuation

Build and inspect artifacts and prepare a **draft** GitHub Release. No public
package-index upload is authorized. A public preview is still a public release:
the single comprehensive public-release policy remains active until explicitly
changed. A tag identifies a verified engineering checkpoint, not security
qualification. Keep recovery keys/readers/backups until their approved retirement.

Production work continues separately against the complete objective ledger:
broader native types and text/JSON search, SQL compatibility, lower-downtime
migration, upgrades, performance, provider/deployment security, subject policy,
tamper-evident auditing and cryptographic-erasure research. Independent human
review and missing deployment evidence remain UNKNOWN.

Current executed results belong in [status](status.md); this document defines
milestone acceptance and boundaries, not a second verification ledger.
