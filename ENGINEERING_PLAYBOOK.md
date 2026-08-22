# Engineering Playbook

This file owns contribution, verification, migration-review, and release process. Product scope is
in [README.md](README.md), design is in the [architecture blueprint](docs/architecture/README.md),
implementation state is in the [backend checklist](docs/backend-build-checklist.md), and competitive
claims are in [prior art](docs/prior-art.md). Research scope and build-versus-integrate decisions are
governed by the [learning-first philosophy](docs/learning-first-research-philosophy.md).

## Working agreement

- Do not describe planned behavior as implemented, implemented behavior as verified, or a vendor
  statement as a Cryptalis measurement.
- State the protected threat, plaintext boundary, leakage capability, and failure behavior for every
  security-relevant change.
- Prefer a typed failure to plaintext fallback, guessed context, silent query reinterpretation, or
  undocumented bypass.
- Never expand search capability merely to make a test pass; capability changes require a leakage
  and migration review.
- Generated schema and migrations are proposals requiring review, not authority to mutate production.
- Preserve the one-owner documentation map; link instead of copying decisions.
- Reject scope that cannot pass a falsifiable prototype or benchmark gate.
- Do not reject work merely because a competitor already implements it. Record learning value,
  reference systems, correctness oracle, maintenance cost, and production/educational classification.
- Keep educational implementations of known constructions and production-approved components
  visibly separate in packaging, configuration, reports, and public claims.
- Treat every documented Cryptalis subsystem as active program scope. Dependencies and evidence
  gates limit integration and claims; they do not impose a semester ceiling or prohibit parallel
  research and isolated experiments.

## Solo manual-typing workflow

Cryptalis has one human builder. AI assistance may directly update documentation only. It does not
create or patch source, tests, migrations, build configuration, containers or CI files.

Implementation help is delivered in conversation one file at a time:

1. explain the file's responsibility, interface, invariant and dependencies;
2. provide one complete test file for the builder to type manually;
3. give the exact command and expected failing result;
4. diagnose the builder's actual output;
5. provide one complete implementation file for manual typing;
6. run the narrow and applicable broader tests;
7. inspect SQL, rows, logs or other evidence; and
8. update documentation/checklist state before moving to the next file.

The next file is withheld until the previous result is understood. Bulk source dumps and autonomous
scaffolding violate the learning goal. See the [complete build guide](docs/cryptalis-build-guide.md).

## Change workflow

1. Read the blueprint section and checklist gate affected by the change.
2. Write the invariant, supported operation, and expected failure first.
3. Add a failing positive control and negative control.
4. Implement the smallest manifest-driven behavior that passes.
5. Run targeted tests, then the full applicable boundary/compatibility suite.
6. Inspect emitted SQL, database rows, logs, errors, traces, audit data, and artifacts for seeded
   plaintext, key material, raw search tokens, and credentials.
7. Update the compatibility matrix, benchmark evidence, checklist, and owning documentation.
8. Commit one reviewable security outcome.

## Pull-request requirements

Every pull request states:

- logical and physical behavior changed;
- manifest/schema/query/key versions affected;
- threat and leakage consequences;
- supported and rejected sync/async/ORM/Core paths;
- migration, rollback, rotation, and shredding impact;
- exact commands and evidence; and
- remaining unknowns or stop-gate implications.

Reviewers block a change when:

- plaintext can reach a protected persistence state through a supported path;
- a known unsupported query silently executes with changed semantics;
- tenant, subject, record, field, normalization, or index domain is guessed;
- remote KMS/Transit I/O occurs invisibly in synchronous ORM hooks or attribute access;
- a cache can outlive its declared fence/lease/TTL model;
- shared search-index residue is omitted from a shredding claim;
- an auto-generated migration hides locks, data motion, coexistence, or irreversible contraction;
- transparent access is claimed to prevent application logging;
- audit/receipt claims exceed their signer and witness model; or
- superiority, performance, compatibility, or compliance lacks reproducible evidence.

## Test layers

Every property requires positive and negative controls. Missing observation is `inconclusive`.

| Layer | Purpose |
|---|---|
| Unit | Manifest validation, canonical encoding, normalization, state machines, error mapping |
| Vectors | Envelope, AAD, KDF, token, signature, receipt, and provider compatibility |
| Property/fuzz | Malformed inputs, parser totality, nonce/context/domain separation |
| ORM semantics | Dirty tracking, flush, rollback, expire, refresh, merge, detach, loaders, serialization |
| Query compatibility | Operator rewrite, aliasing, joins, bulk/Core/raw rejection, sync/async behavior |
| Database | Domains/checks, physical schema, indexes, constraints, drift, emitted SQL and rows |
| Migration | Resume at every phase, dual-read/write windows, cutover, rollback, restore |
| Lifecycle | Rotation, revocation, cache fencing, offline workers, shredding, tombstones |
| Boundary | Production/verification import and build quarantine |
| Verification | Baseline/protected attacks, canaries, exposure oracle, evidence semantics |
| Benchmark | Pinned latency, throughput, storage, cache/provider, and migration measurements |

Tests use synthetic values and fake/local keys. Production personal data, secrets, access tokens, and
key material never enter fixtures.

## Crypto and key-management rules

- Production profiles use established libraries and reviewed constructions; no project-designed
  cipher or insufficiently reviewed ORE/OPE/text-search construction is represented as production
  secure. Independently implemented known constructions are permitted in isolated research profiles.
- Freeze an algorithm suite only with versioned envelope/index formats and test vectors.
- Generate nonces/salts with the chosen library’s required strategy; bind canonical context as AAD.
- Domain-separate encryption, equality, join, migration, audit, and receipt keys.
- Cloud KMS/Vault wraps tenant branch material; normal field crypto is local.
- Provider misses occur in explicit warm/prefetch operations, never hidden attribute access.
- Provider adapters expose actual version, deletion delay, restore, export, outage, and audit
  semantics instead of pretending providers are interchangeable.
- Keys, plaintext, raw search tokens, request bodies, and ciphertext bodies never appear in logs,
  metrics labels, traces, audit events, or receipts.

Any primitive, envelope, AAD, key hierarchy, normalization, index domain, access mode, provider,
cache, rotation, revocation, or shredding change requires architecture review.

## SQLAlchemy rules

- The public logical attribute and hidden physical attributes remain separate.
- Scalar types do not choose row/tenant/subject keys or initiate provider calls.
- The protected-session context establishes validated tenant/key state before local ORM work.
- Comparators explicitly map only declared operators; every other encrypted operation raises.
- Every supported path is named in the compatibility matrix with exact dependency versions.
- Direct drivers and external ETL are outside ORM enforcement and need a separately reviewed path.
- Database domains/checks provide defense in depth but are not proof of authentic Cryptalis output.

## Migration rules

The required phases are inspect, expand, backfill, verify, coexist/cutover, observe, and contract.
Migrations are resumable and idempotent, use immutable cursors, and checkpoint only redacted metadata.

Generated revisions must show:

- physical additions/removals and SQL indexes;
- data volume and lock expectations;
- normalization/index/envelope/key versions;
- plaintext coexistence and telemetry window;
- retry, resume, rollback, and restore behavior;
- verification controls; and
- the point after which rollback cannot recover deleted plaintext.

Autogeneration never applies migrations. Contraction is blocked by incomplete or inconclusive
round-trip, count, index-consistency, canary, drift, and restore evidence.

## Search-capability review

An enabled capability requires:

1. actual application query semantics;
2. a reviewed construction/library;
3. a field-specific leakage statement;
4. physical representation and storage budget;
5. normalization and null semantics;
6. rotation and dual-index migration;
7. subject-shredding treatment;
8. unsupported-operation tests; and
9. a benchmark against the no-search baseline.

`cryptalis plan` may recommend capabilities but never changes the manifest. Equijoin, range/order,
text, fuzzy, and JSON capabilities remain unavailable until their individual gates pass.

## Verification safety

Scanners, payloads, deliberately vulnerable fixtures, test credentials, and destructive scenarios
live outside production packages and built wheels. Verification targets are loopback or a named
disposable network with synthetic data, exact authorization, and strict rate/time/request limits.

The harness reports exploit success, database access, protected extraction, plaintext exposure, and
Cryptalis control outcomes separately. It is not a WAF or proof of universal security. Active
research may implement generic scanner concepts internally, but the product claim remains bounded
to measured findings and protected-data correlation. Public-target scanning, denial of service,
credential attacks, stealth, and persistence are outside scope.

## Release gate

A release candidate is blocked until:

- the supported compatibility matrix passes from a clean checkout;
- schema and migration recovery/restore exercises pass;
- algorithm/provider vectors pass and dependencies/licenses are reviewed;
- key cache, rotation, revocation, and shredding evidence matches documented bounds;
- positive/negative controls validate the verification harness;
- seeded plaintext/secret scans pass across database, logs, traces, audit, receipts, reports, and
  artifacts;
- benchmarks are reproducible and labelled as measurements;
- an independent reviewer has examined cryptographic use and destructive migration behavior;
- prior-art and demand research are current; and
- release notes state limitations, failed experiments, leakage, and incompatible changes.

No release may use “production-ready,” “better,” “more secure,” “zero leakage,” or compliance claims
without a separately reviewable definition and evidence set.
