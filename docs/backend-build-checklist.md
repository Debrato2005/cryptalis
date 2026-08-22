# Backend Build Checklist

This is the sole implementation tracker. Architecture rationale belongs in the
[blueprint](architecture/README.md), and complete learning scope belongs in the
[learning-first philosophy](learning-first-research-philosophy.md). Nothing marked below is
implemented unless `[x]` includes executable evidence.

The flat solo workstream map, dependencies and manual file-by-file workflow are in the
[complete build guide](cryptalis-build-guide.md). This checklist records state; the guide explains
how to advance any workstream.

Markers: `[ ]` not started, `[~]` partial, `[x]` verified, `[-]` rejected/deferred.

## Current status — 2026-08-22

The repository is pre-code. The documentation reset to transparent Model A, a Protection Manifest,
and a local data plane is complete only after the consistency checks at the end of this file pass.

| Workstream | State | Evidence decision |
|---|---|---|
| 0. Architecture and claims | `[~]` | Documents contain one coherent, non-gateway core |
| 1. Fatal-risk prototypes | `[ ]` | Accept, redesign, or reclassify affected capabilities |
| 2. Manifest and equality vertical slice | `[ ]` | One supported ORM path works end to end |
| 3. Schema and migration compiler | `[ ]` | Existing plaintext table migrates safely |
| 4. Subject lifecycle | `[ ]` | Rotation/revocation/shredding survive multi-worker tests |
| 5. Analysis and verification | `[ ]` | Doctor/plan/verify and attack-impact evidence are reproducible |
| 6. Hardening | `[ ]` | Compatibility and claims match measurements |

Workstreams are active in parallel. Numbers provide stable references and expose dependencies; they
do not prevent work in a higher-numbered area. Every workstream must meet its own gate before its
results support an integrated or production-facing claim.

## Workstream 0 — architecture and claims

- [x] Select transparent application values as the primary access model.
- [x] Remove the per-field gateway and mandatory reveal from the primary data path.
- [x] Retain controlled access as a separately justified active field-profile workstream.
- [x] Define the Protection Manifest as the canonical crypto/schema/query/lifecycle IR.
- [x] Establish equality, `IN`, and scoped uniqueness as the first production-candidate search
  profile while keeping advanced search as active research workstreams.
- [x] Document the conflict between tenant-wide search and strict subject shredding.
- [x] Select Web Application Pentesting as the mandatory academic module; keep PCAP, TShark, Zeek
  and Nmap as active networking and evidence workstreams.
- [x] State competitor strengths and project stop conditions.
- [x] Adopt learning value, rather than novelty, as a first-class scope criterion; competitor
  overlap alone is not a rejection reason.
- [ ] Freeze the initial AEAD/HKDF/index suite only after library, misuse-resistance, FIPS need,
  envelope size, and independent-review analysis.
- [ ] Validate product demand with at least five maintainers of real SQLAlchemy applications.
- [ ] Record exact supported Python, SQLAlchemy, Alembic, driver, and PostgreSQL versions.

## Workstream 1 — fatal-risk prototypes

These prototypes are disposable. Other workstreams may proceed, but they cannot use unproven ORM,
query, or lifecycle assumptions as integrated evidence until these risks are answered.

### ORM state semantics

- [ ] Demonstrate immutable application IDs, tenant/subject resolution, and mixed-subject flush.
- [ ] Keep public plaintext separate from hidden ciphertext/search attributes.
- [ ] Test insert, update, autoflush, rollback, retry, expire, refresh, merge, detach, and reload.
- [ ] Test Pydantic/FastAPI serialization and generated log filtering.
- [ ] Prove ciphertext relocation across tenant/subject/table/field/record fails authentication.

### Sync and async behavior

- [ ] Prove no remote provider call occurs in scalar bind/result processors or attribute access.
- [ ] Prototype explicit tenant key warm-up for sync and async protected-session contexts.
- [ ] Measure cold start, cache hit/miss, pool reuse, cancellation, and provider outage.
- [ ] Reject the architecture if transparent async behavior requires hidden event-loop blocking.

### Query and bypass behavior

- [ ] Rewrite `==` and `IN` through a comparator into typed equality-token binds.
- [ ] Reject `LIKE`, `ILIKE`, range, sort, aggregation, and undeclared join semantics before SQL.
- [ ] Catalogue ORM bulk DML, Core, `text()`, executemany, direct driver, migration, and ETL paths.
- [ ] Add a database domain/check that rejects obvious plaintext and missing required index terms.
- [ ] State which bypasses can only be detected operationally rather than blocked.

### Lifecycle feasibility

- [ ] Prototype tenant branch and wrapped subject-key generations without per-subject cloud KMS keys.
- [ ] Fence two worker caches with epochs, leases, acknowledgements, and bounded TTL.
- [ ] Simulate a partitioned/offline worker and verify shredding remains pending.
- [ ] Restore an old database snapshot and prove the external tombstone prevents key resurrection.

### Workstream 1 evidence gate

- [ ] Write an evidence report choosing accept, redesign, isolate as research, integrate existing
  work, or reject each affected capability.
- [ ] Prevent a failed or unbounded capability from making integrated production claims; continue
  independent workstreams whose assumptions remain valid.

## Workstream 2 — manifest and searchable-protection data plane

- [ ] Define canonical manifest schema, validation errors, hash, version, and deterministic names.
- [ ] Compile `protect()` declarations without mutating SQLAlchemy metadata ambiguously.
- [ ] Implement versioned authenticated envelopes and frozen cross-provider test vectors.
- [ ] Implement randomized payload encryption and domain-separated equality tokens.
- [ ] Declare normalization/null/index-domain versions and reject undeclared defaults.
- [ ] Map logical attributes to ciphertext and equality physical columns.
- [ ] Support one sync and one async ORM path with ordinary Python values.
- [ ] Support equality, `IN`, and tenant-scoped uniqueness with fail-loud alternatives.
- [ ] Generate `schema explain` output from the manifest.
- [ ] Prove database-only extraction returns no seeded plaintext for protected columns.

## Workstream 3 — schema and migration compiler

- [ ] Generate reviewable physical schema diffs; never mutate production schema at startup.
- [ ] Implement Alembic custom operations, renderers, and autogenerate comparator integration.
- [ ] Compare manifest, SQLAlchemy metadata, live PostgreSQL schema, and Alembic history.
- [ ] Plan `NOT NULL`, equality-backed `UNIQUE`, and rejection of unsafe `CHECK`/default/generated/FK
  transformations.
- [ ] Implement inspect/expand/backfill/verify/cutover/observe/contract states.
- [ ] Make backfill chunked, resumable, idempotent, redacted, and locally encrypted.
- [ ] Exercise failure and restart at every state transition.
- [ ] Prove plaintext compatibility switches fail closed after cutover.
- [ ] Document rollback before and after plaintext contraction.

## Workstream 4 — subject lifecycle

- [ ] Implement the narrow provider wrap/unwrap/version/status contract.
- [ ] Add deterministic local-development provider and one production provider adapter.
- [ ] Implement tenant and subject generation state machines with idempotency.
- [ ] Bind cache entries to tenant, generation, operation, manifest, TTL, and capacity.
- [ ] Implement rotation, decrypt-old/encrypt-new, and controlled re-encryption.
- [ ] Implement revocation fencing before cache eviction and key-record changes.
- [ ] Implement shredding pending/completed/failed states and multi-worker acknowledgements.
- [ ] Delete subject-owned indexes and report shared index residue.
- [ ] Persist restore-resistant tombstones outside application snapshot authority.
- [ ] Generate signed receipts that state assumptions, gaps, and exact covered resources.
- [ ] Test provider-specific delayed deletion and never report it as immediate destruction.

## Workstream 5 — analysis and verification

### `doctor` and `plan`

- [ ] Detect manifest/model/schema/Alembic drift and unsafe plaintext-compatible storage.
- [ ] Detect known raw/Core/bulk/direct-driver imports and runtime statement shapes.
- [ ] Instrument SQLAlchemy expressions during tests with source locations and redacted operands.
- [ ] Parse pinned Python versions with CPython `ast`; retain spans and generate a stable Cryptalis
  syntax IR.
- [ ] Build module/import indexes, CPython symbol tables, scopes, qualified-name resolution and
  explicit unresolved/dynamic gaps.
- [ ] Implement conservative structural lint rules for raw/Core/bulk/direct-driver bypasses,
  protected-value sinks, unsafe decrypt/reveal, migrations and provider/configuration mistakes.
- [ ] Build per-function CFGs and local definition/use data flow for a labeled fixture corpus.
- [ ] Add typed taint sources, sinks, propagators, transformations and sanitizers for protected
  plaintext, untrusted input, SQL fragments, secrets, ciphertext and search terms.
- [ ] Emit path explanations and classify findings as syntactic, static-modeled, runtime-observed,
  exposure-confirmed or inconclusive.
- [ ] Export/import CodeQL and Semgrep models/results and differentially compare the same fixtures.
- [ ] Recommend minimum observed capabilities without modifying the manifest.
- [ ] Report leakage, storage, migration, rotation, and shredding consequences of each recommendation.

### `verify` and pentesting

- [ ] Quarantine scanners, vulnerable fixtures, payloads, and synthetic credentials from production
  packages and wheels.
- [ ] Pin baseline and protected reference deployments and seed positive/negative controls.
- [ ] Integrate OWASP ZAP Automation Framework for local authorized targets.
- [ ] Build a bounded internal learning prototype for endpoint import, request mutation, response
  differential analysis, deterministic replay and common evidence output.
- [ ] Add deterministic DB-credential, SQL-extraction, bypass, migration, provider-outage, cache,
  shredding/restore, audit-mutation, and artifact-leakage scenarios.
- [ ] Report execution, exploit, DB access, extraction, exposure, and control outcomes independently.
- [ ] Treat missing evidence or controls as inconclusive.
- [ ] Build PCAP/TShark/Zeek ingestion and correlation with explicit TLS observation limits; use
  PyShark only as an evaluated wrapper where it adds measurable value.
- [ ] Use Nmap for deployment exposure and a networking-learning comparison, never as proof of field
  protection.

## Workstream 6 — hardening and evidence

- [ ] Build a versioned compatibility matrix from executable tests.
- [ ] Add malformed-envelope/index fuzzing and property tests.
- [ ] Scan logs, traces, errors, audits, receipts, migrations, reports, and build artifacts for seeded
  plaintext, tokens, keys, and credentials.
- [ ] Benchmark baseline SQLAlchemy, Cryptalis, and `pydantic-encryption` on pinned hardware/software.
- [ ] Measure throughput, p50/p95/p99, CPU, memory, provider calls, cache behavior, migration speed,
  database size, and index growth.
- [ ] Reproduce a CipherStash comparison only where the workload and environment are genuinely
  equivalent.
- [ ] Obtain independent cryptographic and migration review before any production-safety claim.
- [ ] Re-run prior-art, licensing, dependency, regulatory, and product-demand research.
- [ ] Publish limitations and failed experiments alongside successful results.

## Active advanced-research gates

- [ ] Controlled-access fields: require a separate identity/key-authority design and usability study.
- [ ] Equijoin/grouping: require explicit shared-domain leakage and shredding design.
- [ ] Range/order/extrema research: independently study a published construction, vectors, attacks,
  leakage and migration; production use additionally requires reviewed implementation or review.
- [ ] Prefix/text/fuzzy research: require token-leakage, false-positive, storage, rotation and
  comparative evidence.
- [ ] JSON/path research: require path-schema, companion-table, drift and shredding evidence.
- [ ] Doctor depth: stable semantic IR, CFG, call graph, function summaries, interprocedural taint,
  async/FastAPI models, rule DSL and precision/recall benchmarks.
- [ ] Pentest depth: crawler, endpoint/state graph, authentication workflows, payload/mutator engine,
  access-control/IDOR checks, response oracles, minimization and signed scenario packs.
- [ ] Network depth: capture orchestration, TShark/Zeek ingestion, flow/session reconstruction,
  size/timing leakage and protocol/evidence correlation.
- [ ] Acra-inspired experiments: SQL policy/firewall, anomaly reactions, honeytokens and signed audit
  evidence, each bounded to a research question.
- [ ] Explore Django, other databases, multi-language SDKs, admin UI and a general policy DSL as
  active comparative workstreams; require demonstrated core abstractions and learning value before
  committing to supported production integrations.

## Documentation verification

- [x] A terminology scan finds no active gateway-first or mandatory-opaque architecture claims.
- [x] Every local Markdown link resolves.
- [x] Planned, prototyped, measured, and implemented statements remain visibly distinct.
- [x] The architecture, prior-art, checklist, and playbook have no conflicting owners.
