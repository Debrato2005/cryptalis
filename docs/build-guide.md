# Implementation order

**SPECIFIED:** target one comprehensive production-grade first public release for the full SRS and all 34 objectives.
Use the seven baseline slices below as dependency steps, not the complete release scope.
Prioritize complete application journeys and independent workstreams within available agent capacity.
Keep meaningful service-mode PostgreSQL 16 evidence before dependent integration.
Internal development checkpoints do not qualify a partial public release.
Local test success does not mark a full gate PASS or qualify production.
Use the [competitive capability matrix](research/capability-matrix.md) to select high-value work.
The [manual workflow](../ENGINEERING_PLAYBOOK.md#manual-workflow) remains the default for source and tests.
Do not describe spike code as product code. [Status](status.md) owns recorded evidence and revision limits.

## Seven deciding gates

The full gates are G-ADAPTER, G-CRYPTO, G-QUERY, G-LIFECYCLE, G-PROVIDER, G-POLICY, and G-RELEASE.
All seven remain UNKNOWN. [Status criteria](status.md#missing-evidence-and-promotion-criteria) own promotion requirements.
Build slices are dependency steps, not these seven full qualification gates.
Provider/policy qualification requires selected real authorities. Independent review remains `external-review-required` and UNKNOWN.
Reuse PostgreSQL, SQLAlchemy, library crypto, providers, and the existing deployment system. Do not invent another service.

## Ordered build slices

These slices retain the original text-first baseline. Current bounded type
admission includes native text/VARCHAR and storage-only Boolean with standard
mappings. Boolean uses `cryptalis.context/v2`, `boolean-u8/v1` and lock/v4.
Its literal client defaults retain native omission/None behavior. Custom
converters and Boolean search remain unadmitted. See the
[Boolean checkpoint](status.md#boolean-storage-checkpoint-2026-10-23) and
[type contract](compatibility.md#supported-stack).
Other required types remain first-release work under the full SRS and all 34 objectives.

### 1. Manifest compiler

| Item | Requirement |
|---|---|
| Behavior | Inspect one manifest, mapping, schema, and writer inventory. Emit a deterministic lock and semantic plan without database effects |
| Dependencies | Approved stack and [scope](architecture/README.md#approved-scope). A native PostgreSQL application oracle with app-assigned keys and explicit tenancy |
| Invariants | Admit only the specified text family and bounded Boolean storage. Stable typed identities. No guessed tenancy, silent equivalence change, removed constraint, or plan-time write |
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

Preserve existing tests. Add focused lower-level checks for security invariants
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

### Optional current performance profile

`tests/profile_current_application.py` runs only when explicitly selected.
It compares native and pinned ACTIVE applications through their runtime roles.
It defaults to 10,000 rows, with 100 paired samples per workload and isolated column/index storage.
`CRYPTALIS_PERFORMANCE_ROWS` also accepts 100000 or 1000000 for separate scale observations.
Choose new absolute receipt paths. Existing receipts remain immutable.

```bash
CRYPTALIS_PERFORMANCE_RECEIPT=/tmp/cryptalis-performance-new.json \
  .venv/bin/python scripts/test_postgres.py \
  --receipt /tmp/cryptalis-performance-wrapper-new.json \
  -- -q -s tests/profile_current_application.py
```

After seeding, the profile runs named-table `VACUUM (ANALYZE)` on each owned
fixture before product planning. This uses a separate 120-second statement
limit and restores the previous setting. Product lease and lock limits stay unchanged.
PostgreSQL requires [VACUUM outside a transaction block](https://www.postgresql.org/docs/16/sql-vacuum.html).

The profile writes raw samples and target PASS/FAIL before any target assertion.
An observed target miss fails this explicit run. The seven production gates stay UNKNOWN.
The receipt states its scalar/tuple/entity, warm synchronous TEXT and public-key limits.
Process CPU and peak RSS include setup/cleanup and pytest imports.
The process retains the generated input list and creates temporary sets and
seed serialization. Its peak is not a streaming-backfill or adapter memory bound.
They do not measure database-server resources.
Historical profiler helpers supply calculations only. Do not run their direct CLI
as a substitute for the mandatory wrapper or the current lifecycle/pin path.

### Receipt outcome fields

Receipts also record `pytest_report_counts`. It separates ordinary `test_calls`,
`subtest_calls`, `setup`, `teardown`, and failed/skipped `collection` reports.
Each bucket counts final raw pytest outcomes. `selected_items` counts collected
items after selection, including items whose setup prevents a call.
Keep these buckets separate. Their sum is not a test count.

Expected failures retain raw skipped outcomes. Non-strict unexpected passes
retain raw passed outcomes. These fields do not reproduce terminal categories.
The legacy `counts` and `modules` retain their original call/error aggregation,
which includes subtest calls and omits collection/setup skips.
The counter checks run with pytest 9.1.1 and its built-in pytest/unittest subtests.
Other versions and external report plugins remain unverified.

### Pinned external application check

`tests/test_smolink_application.py` extracts Smolink revision
`498d24bae999ed53ad85e1c1f1a09ea7fa151aa4` from a local checkout with Git.
It never imports the checkout's working files or settings file.
It checks source hashes and import origins before recording adoption evidence.

Use a separate Python 3.13 interpreter with Smolink's dependencies and Cryptalis.
Install no package into the application checkout for this test.
Supply an available `redis-server` executable. The test starts a disposable server
on a private Unix socket. PostgreSQL access still uses both fresh private files
through the mandatory wrapper.

```bash
CRYPTALIS_SMOLINK_CHECKOUT=/path/to/smolink \
  /path/to/python3.13 scripts/test_postgres.py -- tests/test_smolink_application.py -q
```

An explicit opt-in fails if its interpreter, packages, source revision, or services
are unavailable. Without the opt-in, the ordinary suite skips this external test.
The [status record](status.md#pinned-smolink-adoption-2026-10-22) names the two tested
dependency cells and their limits. The workload protects only `Url.destination`.
HTTP covers URL creation and refusal cases. Repository and ORM calls cover other CRUD operations.
The host replaces the session dependency and supplies protection policy and maintenance authority.

### Automated application qualification matrix

Run the online HTTP row through `scripts/online_qualification.py --http`.
Run the other selected rows through `scripts/fresh_cluster_qualification.py`.
The fresh-cluster harness runs export and isolated restore through `scripts/test_postgres.py`.
The online harness creates three private role files on an isolated cluster and probes all three before the application test.
Each fresh-cluster export or restore phase reloads both private URL files and probes both roles.
The online HTTP phase reloads all three private URL files and probes all three roles.
If a probe fails, stop. Do not retry or substitute a database.
Use the pinned snapshots and the exact dependency cell recorded in status.
Keep each work directory new. The installed qualification runner must resolve
Cryptalis imports from the reviewed wheel instead of the source checkout.

| Row | Profile | Application journey | Evidence boundary |
|---|---|---|---|
| Original HTTP online adoption | `online_qualification.py --http` | Concurrent original signup, native HTTP during capture, fenced cutover, protected HTTP/search, latest-value reverse and package-free HTTP restart | 26 unchanged pinned files. Three roles. No backup/rotation repeat or production downtime qualification |
| Original HTTP/authentication | `--sqlmodel-http` | Native routes, Doctor, protection, search, backup, fresh adoption, root/payload/search rotation, latest-value removal, package-free HTTP restart | 26 pinned files. TestClient and loopback SMTP. Explicit single tenancy and public fixture keys |
| Original SQLModel CRUD | `--sqlmodel-public-slots` | Three protected fields, public slots, fresh adoption, direct restore-binding search rotation, native exit | Six pinned files. Positive control for the shared harness |
| Original Smolink | `--smolink` | Async URL routes/repository operations, protected backup, fresh adoption, rotations and native exit | Separate pinned revision and historical qualification. No new execution claim follows from the HTTP row |

Supply `CRYPTALIS_SQLMODEL_HTTP_SOURCE` for the HTTP row.
Supply `CRYPTALIS_SQLMODEL_APP_SOURCE` for the CRUD row.
Supply `CRYPTALIS_SMOLINK_CHECKOUT` and a local Redis executable for Smolink.

```bash
CRYPTALIS_SQLMODEL_HTTP_SOURCE=/path/to/pinned-http-snapshot \
  /path/to/python3.13 scripts/fresh_cluster_qualification.py \
  --sqlmodel-http --workdir /tmp/cryptalis-http-fresh-new-run
```

The earlier original HTTP CLI journey owns initialization and five actual
SIGKILL/resume checkpoints. The new HTTP fresh row owns genuine restore and
post-adoption authentication. Neither row proves every step or an external KMS.
Retain these separate boundaries when reporting the full developer journey.
