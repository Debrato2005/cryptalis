# Implementation order

**SPECIFIED:** target one comprehensive production-grade first public release for the full SRS and all 34 objectives.
Use the seven baseline slices below as dependency steps, not the complete release scope.
Prioritize complete application journeys. Delegate only when current user or applicable instructions authorize it.
Keep meaningful service-mode PostgreSQL 16 evidence before dependent integration.
Internal development checkpoints do not qualify a partial public release.
Local test success does not mark a full gate PASS or qualify production.
Use the [competitive capability matrix](research/capability-matrix.md) to select high-value work.
The [implementation workflow](../ENGINEERING_PLAYBOOK.md#implementation-workflow) governs source and tests under current authorization.
Do not describe spike code as product code. [Status](status.md) owns recorded evidence and revision limits.

## Seven deciding gates

The full gates are G-ADAPTER, G-CRYPTO, G-QUERY, G-LIFECYCLE, G-PROVIDER, G-POLICY, and G-RELEASE.
All seven remain UNKNOWN. [Status criteria](status.md#missing-evidence-and-promotion-criteria) own promotion requirements.
Build slices are dependency steps, not these seven full qualification gates.
Provider/policy qualification requires selected real authorities. Independent review remains `external-review-required` and UNKNOWN.
Reuse PostgreSQL, SQLAlchemy, library crypto, providers, and the existing deployment system. Do not invent another service.

## Current implementation priority

The baseline slices below are dependency and acceptance contracts, not a claim
that implementation starts at slice 1 again. The current code already has bounded
implementations of all seven. Continue from the [objective ledger](BUILD_CHECKLIST.md#next-critical-path)
and keep changes small: see [KISS](decisions.md#consolidated-requirements-and-kiss-2026-10-31).
Verify the affected native application journey. Complete functional objectives before further
optimization work. Preserve measured performance failures and their acceptance
targets; optimize after the functional requirements are implemented. Correctness,
security and required verification remain active throughout. [Status](status.md)
identifies the tested base.

## Ordered build slices

These slices retain the original text-first dependency order. Current admitted
storage includes TEXT/VARCHAR, Boolean, signed integers, finite Date, naive/aware timestamp, finite NUMERIC and UUID.
Exact codecs, query support and evidence limits belong to the
[type contract](compatibility.md#supported-stack). Remaining types and query
capabilities stay in the full first-release objective ledger.

### 1. Manifest compiler

| Item | Requirement |
|---|---|
| Behavior | Inspect one manifest, mapping, schema, and writer inventory. Emit a deterministic lock and semantic plan without database effects |
| Dependencies | Approved stack and [scope](architecture/README.md#approved-scope). A native PostgreSQL application oracle with app-assigned keys and explicit tenancy |
| Invariants | Admit only the types/codecs in the current compatibility contract. Stable typed identities. No guessed tenancy, silent equivalence change, removed constraint, or plan-time write |
| Tests | Inspect real PostgreSQL mappings for UUID/app-assigned IDs, tenant-column and explicit single-tenant tables, NULL/empty text, deterministic collation and scoped uniqueness. Compare plan facts with native schema |
| Failure cases | Serial/identity/database-default keys, unadmitted protected types, Boolean search and other small-domain searchable fields, missing tenancy/leakage acceptance, unknown writers, unsupported constraints, malformed or ambiguous declarations |
| Definition of done | Freeze exact manifest/lock syntax and typed context descriptors. PostgreSQL acceptance/refusal cases pass. Plan explains every incompatibility plainly and leaves schema/data unchanged |

### 2. Crypto format, KeyProvider, and development provider

| Item | Requirement |
|---|---|
| Behavior | Implement bounded text encoding, CF1 sealing/opening, exact key resolution, KeyProvider wrap/unwrap/rewrap, and an explicitly local development provider |
| Dependencies | Slice 1 descriptors and [security format](security.md#cryptographic-format). Mature AEAD/HKDF/HMAC primitives |
| Invariants | Fresh OS nonces. Exact field/tenant/record context. Independent payload/search roots. Memory-only keys. No header-selected authority or silent algorithm/key fallback |
| Tests | Independent primitive and frozen CF1/KDF/HMAC vectors. Persist actual frames on PostgreSQL, then authenticate/decode exact text/NULLs with expected context. Exercise cold/warm/expired/outage and local rewrap |
| Failure cases | Wrong key/context, relocation, malformed/oversized/trailing frame, changed header/term, missing/retired generation, failed/canceled preparation and fork-inherited material |
| Definition of done | Frozen format tests and PostgreSQL persistence tests pass. Failures release no unauthenticated values. Usage/collision/review gaps remain explicit. Local provider claims remain functional only |

### 3. SQLAlchemy integration, sync and async

| Item | Requirement |
|---|---|
| Behavior | One attachment handles storage/read/write through public hooks while native attributes and ORM state retain their types and behavior |
| Dependencies | Slices 1–2, an inspected session factory, app-assigned row IDs, explicit tenant scope, separate migration/runtime credentials |
| Invariants | Prepare row-bound frames before SQL. Async provider work occurs outside synchronous hooks. No plaintext protected bind, stale cached context, or batch-order guess |
| Tests | Real PostgreSQL entity/scalar/alias/outer-join projections through unprotected keys, relationships, refresh/expiry/merge/autoflush/rollback, batches, failed-flush cleanup, sync/async isolation/cancellation. Compare the native application oracle |
| Failure cases | Opaque SQL/COPY/protocol paths, forged admission metadata, computed/unprepared protected writes, wrong point/tenant/record, unsupported nested grammar, runtime DDL/metadata mutation, reconnecting excluded writers |
| Definition of done | Storage behavior and negative controls pass on the exact PostgreSQL cell. Profile the plaintext-page anomaly and record its cause or remaining UNKNOWN evidence. Record actual application/model/writer/deployment edits |

The earlier million-row range/prefix/page query cost about 127 ms p95 versus 24 ms native.
Its filters are plaintext, but `browse_customers` selects the full Customer including protected email; the former plaintext-only label was incorrect.
Its cause is UNKNOWN. Profile admission, compilation/cache, driver/database work, decoding, and materialization before accepting an explanation.
The [10,000-row receipt](../spikes/revamp/results/gate-write-cost.json) predates the latest DISTINCT change and measures an earlier revision.
Do not describe it or the million-row receipt as current-adapter service evidence.

### 4. Equality, IN, and tenant-scoped uniqueness

| Item | Requirement |
|---|---|
| Behavior | Rewrite declared equality/IN to full keyed terms and enforce tenant-scoped native uniqueness |
| Dependencies | Slices 1–3, independent search roots, qualified exact text/collation and NULL semantics, built-in equality indexes |
| Invariants | Match native result membership/types/pagination. No hidden filtering/refill. Preserve tenant separation and atomic payload/term updates |
| Tests | PostgreSQL typed/reverse/late binds, AND/OR, aliases, NULL/empty/mixed-NULL IN, single-tenant and multi-tenant uniqueness races, duplicate backfill and indexed million-row plans. Measure matched end-to-end p95 and isolated column/index storage |
| Failure cases | Missing leakage opt-in, small domains, protected operations outside the current compatibility matrix, wrong tenant, stale terms, duplicate target values, malformed companions and custom predicate renderers |
| Definition of done | Differential query/constraint tests pass. Meet added p95 ≤ 3 ms point/equality, ≤ 8 ms IN-20, and ≤ 2× column-plus-equality-index storage targets. Record sustained-write observations without inventing a throughput budget |

[Compatibility](compatibility.md#performance-targets-and-recorded-costs) records the earlier latency misses. A microbenchmark cannot replace matched application measurements.

### 5. Plan, apply, and verify

| Item | Requirement |
|---|---|
| Behavior | Bind target/locks/schema/writers, expand shadows, backfill atomic chunks, fully verify, switch database, publish matching deployment policy, contract eligible objects |
| Dependencies | Slices 1–4, PostgreSQL journal/locks, operator-controlled writer exclusion, inspected publication boundary |
| Invariants | Data and chunk marker commit together. Full membership/value/type/NULL/term/generation/schema checks precede switch. No mismatched policy admits traffic |
| Tests | Real PostgreSQL committed-chunk process interruption, independent-process inspected resume, lost COMMIT reply, competing executor/writer, both database/artifact switch faults, pre-switch abort, changed source index and verification mutants |
| Failure cases | Missing/reordered rows, tag/context/term/index mutation, duplicate normalization, SQL/provider faults, real bounded disk/WAL/temp exhaustion, timeout, wrong target, stale plan/policy, unavailable host provenance |
| Definition of done | Completed chunks survive faults. Failed chunks remain atomic. Verification mutants prevent switch. Ambiguous effects remain PENDING/UNKNOWN with a concrete remedy. Publication/provider external gaps stay UNKNOWN |

Generic CHECK/FK/default/collation preservation needs executable deciding evidence. Current capture/restoration mechanisms and their limits are specified in the lifecycle contract and tied to receipts in status.
Pause budgets remain D. Measurements and explicit operator approvals do not create an approved numeric ceiling.

### 6. Decrypt-back and remove

| Item | Requirement |
|---|---|
| Behavior | Transform current active values back to ordinary SQL types, verify, switch, and retire eligible generated objects through the same executor |
| Dependencies | Slice 5, compatible readers/keys, explicit plaintext/WAL/backup exposure approval, retained-copy inventory |
| Invariants | Preserve edits after cutover. No stale snapshot rollback, silent truncation, dropped membership, or premature key/reader retirement |
| Tests | Real PostgreSQL post-cutover edits, interrupted decrypt-back/resume, incompatible prior types/constraints, retained encrypted backup recovery in a fresh independent process, and the original application without Cryptalis imports/attachment |
| Failure cases | Missing recovery key/reader, invalid current frame, prior-type conflict, failed full verification, surviving generated dependency, unknown retained backup disposition |
| Definition of done | Current membership/values/types and native application reads/writes pass. Retained backups have tested recovery or explicit loss disposition. Remove the package last. Recovery remains available until explicit finalization |

### 7. Rotation: three operations

| Item | Requirement |
|---|---|
| Behavior | Keep root rewrap, payload-key rotation, and search-key reindex as separate operations through the same transition executor |
| Dependencies | Slices 1–6, wrapped-root identities, old/new reader inventory, stopped writers and exact generation policy |
| Invariants | Rewrap preserves payload/search bytes. Payload rotation can retain terms. Search rotation rebuilds indexes and reseals authenticated headers with fresh nonces. No mixed-generation uniqueness gap |
| Tests | Real PostgreSQL byte-preserving rewrap, payload generation transition, search query/uniqueness parity, interrupted/resumed rotations, changed wrapper context, fresh-process recovery, retained-backup readers, cold/warm/outage/canceled provider calls |
| Failure cases | Wrong provider/key/context, missing old/new generation, partial reindex, stale companion/header, lost remote reply, unproved retirement/deletion outcome |
| Definition of done | All three functional PostgreSQL operations pass and remain separately observable. Provider custody/native deletion and human review stay UNKNOWN without their required evidence. Rewrap never claims to cure leaked data roots |

## Acceptance evidence

Baseline dependencies retain their real PostgreSQL requirements before dependent admission.
Each addition enters through [six-gate admission](compatibility.md#capability-admission), explicit leakage acceptance, and exact native-query evidence.
The full SRS and all 34 objectives remain release requirements. Safe refusal alone does not complete a feature.
Research algorithms and physical arrays are INTERNAL ONLY.
The full [release gate](../ENGINEERING_PLAYBOOK.md#release-gate) remains mandatory before production claims.

Prioritize this complete journey in pinned independent applications before public release:

1. Install Cryptalis and supply a manifest. Run Doctor for actionable compatibility findings. Plan and apply protection to existing data.
2. Compare protected CRUD, search, uniqueness, tenancy and concurrency with the native baseline. Independently inspect stored data for protected plaintext.
3. Exercise key expiry, wrong keys, corrupted frames and unsupported operations. Complete all rotations, interrupt/resume migration and restore a backup on a fresh cluster.
4. Decrypt latest committed values and retire eligible generated database objects. Uninstall Cryptalis, restart the original application and compare native values, schema semantics and behavior.

Preserve essential cryptographic and failure tests. Add focused lower-level checks for security invariants
and deterministic failures that application E2E cannot establish. Run focused
checks after changes, integrated E2E after meaningful milestones and broader
regressions at release gates.

Use the same backend, data, queries, constraints, driver, and result materialization for matched benchmarks.
Record versions/revisions, selectivity, distributions, p50/p95/p99, throughput, CPU, memory, isolated storage/index sizes, and sustained writes.
Measure provider cold/warm/outage, migration rows/s, WAL/temp space, and total writer pause.
Approved read/storage targets remain targets until measured. Write-throughput and pause budgets remain D.
Count actual business-query, model, writer, deployment, and operator changes. Do not infer zero-cost adoption from one attach call.
No project test suite runs during a documentation-only pass unless a non-documentation file changed.

The PostgreSQL wrapper records Python source hashes before pytest and compares
them after pytest. Keep `src/cryptalis`, `tests`, and `scripts` stable during a run.
Different start/end files force wrapper exit 4, even without a receipt option.
Receipts retain the original pytest exit code and the changed source paths.
Review those changes before a new run. Do not overwrite the failed receipt.
This check compares two snapshots and does not detect an intervening edit that is restored.


## Qualification commands

Use [local development](local-development.md) for source, installed and provider checks.
The [qualification matrix](qualification.md) owns optional original-application and fresh-cluster profiles
and [receipt outcome fields](qualification.md#receipt-outcome-fields).
