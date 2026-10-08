# Implementation order

**SPECIFIED:** implement exactly one slice per run, in the order below.
Each slice needs meaningful tests on real service-mode PostgreSQL 16 before the next slice starts.
Local test success advances build order only. It does not mark a full gate PASS or qualify production.
The [manual workflow](../ENGINEERING_PLAYBOOK.md#manual-workflow) remains the default for source and tests.
Do not describe spike code as product code. [Status](status.md) owns recorded evidence and revision limits.

## Seven deciding gates

The full gates are G-ADAPTER, G-CRYPTO, G-QUERY, G-LIFECYCLE, G-PROVIDER, G-POLICY, and G-RELEASE.
All seven remain UNKNOWN. [Status criteria](status.md#missing-evidence-and-promotion-criteria) own promotion requirements.
Build slices are dependency steps, not these seven full qualification gates.
Provider/policy qualification requires selected real authorities. Independent review remains `external-review-required` and UNKNOWN.
Reuse PostgreSQL, SQLAlchemy, library crypto, providers, and the existing deployment system. Do not invent another service.

## Ordered build slices

### 1. Manifest compiler

| Item | Requirement |
|---|---|
| Behavior | Inspect one manifest, mapping, schema, and writer inventory. Emit a deterministic lock and semantic plan without database effects |
| Dependencies | Approved stack and [scope](architecture/README.md#approved-scope). A native PostgreSQL application oracle with app-assigned keys and explicit tenancy |
| Invariants | Text only. Stable typed identities. No guessed tenancy, silent equivalence change, removed constraint, or plan-time write |
| Tests | Inspect real PostgreSQL mappings for UUID/app-assigned IDs, tenant-column and explicit single-tenant tables, NULL/empty text, deterministic collation and scoped uniqueness. Compare plan facts with native schema |
| Failure cases | Serial/identity/database-default keys, non-text types, small-domain searchable fields, missing tenancy/leakage acceptance, unknown writers, unsupported constraints, malformed or ambiguous declarations |
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

The earlier million-row plaintext range/prefix/page query cost about 127 ms p95 versus 24 ms native, despite containing no protected field.
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
| Failure cases | Missing leakage opt-in, small domains, unsupported inequality/NOT IN/joins/DISTINCT/aggregates/order/patterns, wrong tenant, stale terms, duplicate target values, malformed companions |
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

Generic CHECK/FK/default/collation preservation needs executable deciding evidence. The current spike verifies source index definitions, validity/readiness, and fixture-scoped uniqueness only.
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

No range, order, prefix, or text-search implementation starts before all seven slices pass their real PostgreSQL tests.
Each addition then enters through [six-gate admission](compatibility.md#capability-admission), explicit leakage acceptance, and exact native-query evidence.
Research algorithms and physical arrays are INTERNAL ONLY.
The full [release gate](../ENGINEERING_PLAYBOOK.md#release-gate) remains mandatory before production claims.

Use the same backend, data, queries, constraints, driver, and result materialization for matched benchmarks.
Record versions/revisions, selectivity, distributions, p50/p95/p99, throughput, CPU, memory, isolated storage/index sizes, and sustained writes.
Measure provider cold/warm/outage, migration rows/s, WAL/temp space, and total writer pause.
Approved read/storage targets remain targets until measured. Write-throughput and pause budgets remain D.
Count actual business-query, model, writer, deployment, and operator changes. Do not infer zero-cost adoption from one attach call.
No project test suite runs during a documentation-only pass unless a non-documentation file changed.
