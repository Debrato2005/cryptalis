# Product build checklist

This file is the product engineering ledger. It tracks the 34 research objectives
against the actual product source, tests, and evidence.
[Status](status.md) owns current capability claims. [Architecture](architecture/README.md),
[security](security.md), [lifecycle](lifecycle.md), and [compatibility](compatibility.md)
own their contracts. This file does not replace those owners.

## Status vocabulary

| Term | Meaning |
|---|---|
| SPECIFIED | The final product requires the behavior; it is not implemented. |
| IMPLEMENTED | Product source exists. Verification may be incomplete. |
| VERIFIED | Executed evidence supports the named behavior at the recorded revision and cell. |
| UNKNOWN | Required evidence is absent. This is not a pass. |
| BLOCKED | An external resource, decision, or approval is required. |

First shipment is separate from final qualification. Partial progress stays visible.
No objective is complete until its acceptance evidence and applicable gate pass.

## Current boundary

- Product baseline: Git `2ff72ea`, local PostgreSQL 16.15, Python 3.12,
  SQLAlchemy 2.1.3 and 2.0.51 profiles, psycopg 3.3.6, cryptography 50.0.2.
- Implemented scope: text storage, exact equality, `IN`, tenant-scoped uniqueness,
  sync/async attachment, maintenance protection transition, in-place decrypt-back and
  additive removal for that transition format, an independent application lifecycle with
  package-free restart, a fresh-cluster protected-backup recovery harness, CF1 primitives,
  and a local development provider.
- All seven qualification gates remain UNKNOWN.
- Every protected type other than text, every advanced predicate, online migration,
  complete rotation, production KMS, and independent review remain open.

## Objective ledger

Requirement text is abbreviated. The full definitions remain in the research
`CRYPTALIS_BUILD_CHECKLIST.md` and the final blueprint; no requirement is dropped.

| ID | Requirement (abbreviated) | Product status | Implemented mechanism and evidence | Open gap / next action |
|---|---|---|---|---|
| OBJ-SEC-01 | Encrypt before PostgreSQL; prove at SQL/driver boundaries | VERIFIED, bounded | `crypto/cf1.py`, `sqlalchemy.py`; slice 2/3 receipts in `docs/_reset`; real runtime-role tests | Broader writer/auth/provider boundaries; independent review |
| OBJ-SEC-02 | Bind tenant, field, row, generation; reject malformed/swapped frames | VERIFIED, bounded | CF1 AAD, descriptor binding, sync/async tamper tests | Collision assumptions and composition review |
| OBJ-SEC-03 | Authorization, result lineage, tenant isolation, parameterization | PARTIAL | Tenant-scoped sessions, requested-point checks, typed errors | Host authorization is external; audit remaining ORM routes |
| OBJ-SEC-04 | Detect plaintext bypass through ORM, bulk, SQL, COPY, jobs, logs | PARTIAL | Guarded attachment rejects raw SQL/COPY/opaque writes and unsafe engine logging before connect/key access; writer inventory at plan | Complete route inventory; deployment enforcement is unverified |
| OBJ-SEC-05 | Isolate keys; bound nonces, leases, cache lifetime, fork safety | VERIFIED, bounded | `crypto/keys.py` strict policy, cache expiry, fork refusal | Remote cancellation, usage limits, production custody |
| OBJ-SEC-06 | Reduce equality/frequency/access leakage with documented trade-offs | SPECIFIED | Equality leakage is declared; no stronger profile admitted | Threat-model and benchmark a lower-leakage profile; six-gate admission |
| OBJ-SEC-07 | Independent red-team, crypto, adapter, provider, supply-chain review | BLOCKED | None | Assign independent reviewers; do not self-certify |
| OBJ-QUERY-01 | Exact equality, `IN`, scoped uniqueness, NULL logic, races | VERIFIED, bounded | `_sqlalchemy_search.py`, slice 4 receipt; native concurrency tests | Keep grammar reconciliation current |
| OBJ-QUERY-02 | Ordinary SQL correctness: NULL predicates, aliases, joins, projections | PARTIAL | Native sync/async controls; textual reference admission and simple negative/NULL predicates added 2026-10-19 | Continue finite native-oracle matrix; general Boolean NOT and protected joins remain unadmitted |
| OBJ-QUERY-03 | Ordering, ranges, prefix/text search, aggregates, other types | SPECIFIED | Loud refusal only | Research and admit each profile separately |
| OBJ-QUERY-04 | INSERT/UPDATE/DELETE, bulk, RETURNING, triggers, cascades, savepoints | PARTIAL | ORM flush writes, rollback, sync/async state; bulk routes reject | Qualify each broader DML effect separately |
| OBJ-QUERY-05 | Versioned compatibility corpus and read-only scanner | PARTIAL | Native-vs-attached tests and receipts | Build a real pre-adoption scanner; reconcile current revisions |
| OBJ-LIFE-01 | Deterministic plan/apply/verify with diagnostics | VERIFIED, bounded | `migration.py` plan/apply/verify; compiler inspection maps SQLAlchemy and direct psycopg errors to safe SQLSTATE; slice 5 receipts | Broader schema and failure boundaries |
| OBJ-LIFE-02 | Resumable, atomic, byte-bounded backfill with verification | VERIFIED, bounded | Journal, advisory lock, chunks, crash/resume tests | Exact memory/WAL bounds remain host inputs |
| OBJ-LIFE-03 | Near-zero-downtime migration with capture and catch-up | SPECIFIED | Maintenance pause fallback only | Design, review, and measure an online protocol |
| OBJ-LIFE-04 | Parallel/adaptive migration without lost or duplicate work | SPECIFIED | None | Depends on OBJ-LIFE-03 |
| OBJ-LIFE-05 | Decrypt-back current edits; preserve schema behavior; package-free exit | VERIFIED, bounded | `deprotection.py` implements `cryptalis.reverse/v1`: staged plaintext, verified backfill, transactional switch, recorded constraint/index/collation restoration, guarded activation, approved removal, and terminal-state assertions; seven lifecycle cases pass on both profiles; an independent three-model application completes protect/search/modify/decrypt-back/remove and a package-free restarted process performs native CRUD | Restored-cluster bring-up/adoption, pinned external application run, physical column order, comments/statistics/storage/compression, retained-native |
| OBJ-LIFE-06 | Rollback, restore, stale pin refusal, RPO/RTO, disaster drills | PARTIAL | Older-snapshot and stale-pin refusals; reverse abort, pin/state ordering, corrupt-frame and disabled-guard refusals; isolated-cluster plaintext and protected restore with frame recovery and loud authority refusal | Restored-cluster authority rebinding, fresh-cluster and provider-outage drills |
| OBJ-LIFE-07 | Three separate rotation workflows | PARTIAL | Internal rewrap candidate and bounded payload-batch preparation, verified 2026-10-19 | Active-policy publication, rotation executor, search reindex, recovery proofs |
| OBJ-LIFE-08 | Production KMS with outage/revocation/cost evidence | BLOCKED | Local development provider only | Authorized provider account and independent review |
| OBJ-LIFE-09 | Install, upgrade, decommission, clean uninstall | PARTIAL | Importable package; approved in-database removal retires reverse-owned objects after decrypt-back; a package-free restarted application process performs native CRUD | Versioned upgrade/removal, external application evidence |
| OBJ-DX-01 | Minimal model/query changes; one manifest and one attach | IMPLEMENTED | `compile_protection`, `attach`, CLI inspection | Unify status/plan/apply/remove entry points |
| OBJ-DX-02 | Read-only `cryptalis doctor` with explicit UNKNOWN results | PARTIAL | Bounded database/declaration diagnostics | Implement the full doctor and provider/role coverage |
| OBJ-DX-03 | Real FastAPI/SQLModel app plus a second independent app | PARTIAL | Synthetic Smolink demo; in-repo independent three-model application (real FK, two tenants, zero-row protected table) completes the full lifecycle and a package-free restart; no web framework or external app | Run a pinned real application; add a second app |
| OBJ-DX-04 | Normal ORM identity, loading, sessions, pooling, async | PARTIAL | Bounded sync/async adapter and search tests | Broader ORM/framework coverage |
| OBJ-DX-05 | Complete quickstart, threat model, leakage, recovery docs | PARTIAL | README, architecture, security, lifecycle, walkthroughs | Keep docs tied to admitted APIs and evidence |
| OBJ-PERF-01 | Continuous native vs protected latency/resource measurements | PARTIAL | Slice 3/4 profiles and million-row receipts | Cold/concurrent/tail/WAL/provider measurements |
| OBJ-PERF-02 | Profile-guided optimization without security loss | PARTIAL | Membership projection correction on 2026-10-09 | Continue profiling; no unverified speed claims |
| OBJ-PERF-03 | Multithreading/multiprocessing/async at 1/4/16/saturation | SPECIFIED | Single-worker maintenance path | Define and run isolation/backpressure/cancellation tests |
| OBJ-PERF-04 | Added p95 targets and growth path | PARTIAL | Earliest profiles missed targets; later searches passed local targets | Re-measure current revision; write/pause budgets undecided |
| OBJ-OPS-01 | Reproducible wheel/sdist, SBOM, provenance, reviewers | PARTIAL | `pyproject.toml`, locked dependency set | Clean build, SBOM, provenance, independent review |
| OBJ-OPS-02 | Recoverable source/evidence and traceability | PARTIAL | Git history and `docs/_reset` receipts | Durable archive and fresh restore |
| OBJ-RESEARCH-01 | Source-backed comparative research with repeatable evidence | ONGOING | Research repository provenance | Preserve failed alternatives and provenance links |
| OBJ-RESEARCH-02 | One coherent working candidate that passes all gates | PARTIAL | Implemented scope above | Continue integration; all seven gates UNKNOWN |

## Import ledger

| Date | Research reference | Mechanism | Product files | Evidence | Status |
|---|---|---|---|---|---|
| 2026-10-19 | `debgh-workspace/cryptalis-research-lab` branch `accel/integration-s20-20261014`, commit `15cf040`; `candidate/src/cryptalis/deprotection.py` (retained-native) | Reverse lifecycle evaluated; product implements an in-place `cryptalis.reverse/v1` variant for the admitted transition format, with journal/pin/approval checks, verified chunked backfill, transactional switch, and approved removal | `src/cryptalis/deprotection.py`; `tests/test_deprotection.py` | GREEN: 7 focused and 1,299 full SA2.1; 7 focused and 1,271 passed + 28 skipped full SA2.0 | VERIFIED, bounded, local cell |
| 2026-10-19 | `debgh-workspace/cryptalis-research-lab` branch `accel/integration-s20-20261014`, commit `15cf040`; `candidate/src/cryptalis/crypto/_payload_rotation.py`; test `test_payload_rotation_preparation.py` (native staging oracle omitted; product uses the in-place layout) | Inactive bounded payload-generation transform with exact source decode, target reseal, identity/header preservation, and lease recheck | `src/cryptalis/crypto/_payload_rotation.py`; `tests/test_payload_rotation_preparation.py` | GREEN: 40 focused SA2.1, 1,292 full SA2.1, 90 focused SA2.0 | VERIFIED, internal, local cell |
| 2026-10-19 | `debgh-workspace/cryptalis-research-lab` branch `accel/integration-s20-20261014`, commit `15cf040`; `candidate/src/cryptalis/manifest/compiler.py` direct-driver catch | Map direct psycopg inspection errors to `InspectionUnavailable` with safe SQLSTATE | `src/cryptalis/manifest/compiler.py` | GREEN: 61 focused each profile; 1,292 full SA2.1; 1,264 passed + 28 skipped full SA2.0 | VERIFIED, local cell |
| 2026-10-19 | `debgh-workspace/cryptalis-research-lab` branch `accel/integration-s20-20261014`, commit `15cf040`; `candidate/src/cryptalis/crypto/_rewrap.py`; test `test_rewrap_preparation.py` | Inactive rewrap candidate over every admitted root with target identity checks and no partial result | `src/cryptalis/crypto/_rewrap.py`; `tests/test_rewrap_preparation.py` | GREEN: 16 focused, 1,252 full SA2.1, 54 focused SA2.0 | VERIFIED, internal, local cell |
| 2026-10-19 | `debgh-workspace/cryptalis-research-lab` branch `accel/integration-s20-20261014`, commit `15cf040`; `candidate/src/cryptalis/_sqlalchemy_search.py` negative-predicate hunks; test `test_sqlalchemy_negative_predicates.py`; updated search grammar test | Simple `!=`, `NOT IN`, and NULL presence with native truth and outer-join tenant-guard preservation | `src/cryptalis/_sqlalchemy_search.py`; `tests/test_sqlalchemy_negative_predicates.py`; `tests/test_sqlalchemy_search.py` | RED: 57 failed, 2 passed. GREEN: 366 focused SA2.1, 1,236 full SA2.1, 202 focused SA2.0 | VERIFIED, local cell |
| 2026-10-19 | `debgh-workspace/cryptalis-research-lab` branch `accel/integration-s20-20261014`, commit `15cf040`; `candidate/src/cryptalis/sqlalchemy.py::UnsafeEngineLogging`; test `test_attachment_engine_preflight.py` | Refuse unsafe query echo or parameter hiding before connection or key access | `src/cryptalis/sqlalchemy.py`; `tests/test_attachment_engine_preflight.py` | RED: 12 unsafe-setting subtests reached `do_connect`. GREEN: 307 focused SA2.1, 1,177 full SA2.1, 143 focused SA2.0 | VERIFIED, local cell |

## Seven gates

| Gate | Status | Required evidence |
|---|---|---|
| G-ADAPTER | UNKNOWN | Complete admitted matrix; unsupported-route coverage; real app; independent review |
| G-CRYPTO | UNKNOWN | Independent composition, nonce, context, and key-lifetime review |
| G-QUERY | UNKNOWN | Semantics and leakage admission for every claimed profile |
| G-LIFECYCLE | UNKNOWN | Fresh-cluster restore, upgrade/rollback, rotation, removal |
| G-PROVIDER | UNKNOWN | Real authorized KMS custody, outage, revocation, and cost evidence |
| G-POLICY | UNKNOWN | Authenticated deployment policy, stale-worker fencing, quarantine |
| G-RELEASE | UNKNOWN | SBOM, provenance, clean build/install, independent reviews |

## Next critical path

1. Design and approve a restored protected-schema bring-up binding, because the current
   deployment target refuses a fresh cluster with `deployment_not_current`.
2. Run the same lifecycle through a pinned external application, then repeat it on a
   fresh PostgreSQL cluster.
3. Record the remaining metadata limits (physical column order, comments, statistics,
   storage, compression) and extend the fresh-cluster range (multi-table, faults).
4. Continue correctness slices that protect the compatibility promise with native
   PostgreSQL oracles; establish a second independent application baseline.
5. Keep every external review and provider item explicitly UNKNOWN.
