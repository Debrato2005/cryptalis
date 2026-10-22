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

- Payload preparation now stages bounded encrypted chunks under immutable P,
  preserves source public frames/indexes and verifies committed prefixes on resume.
  Source-only cancellation restores writers without target-provider access.
  The 26 native staging/recovery controls pass, including SIGKILL/fresh-process
  resume, actual lost COMMIT replies and rollback after native UPDATE/guard DROP.
  Full regression passes 1,745 tests and 18 subtests, with three separate-environment
  skips. Reproducible archives and all 34 installed package
  files pass release checks, including CLI startup.
  Sealed activation A, final paired cutover and payload publication remain
  SPECIFIED. See [status](status.md#payload-staging-and-cancellation-checkpoint-2026-10-23).
- Root-rewrap cutover now uses a transition/v2 successor through the existing
  executor and publication path. Native recovery controls preserve frames and
  equality-index identity, reject stale authority, and exercise two custody
  changes followed by latest-value decrypt-back/removal. Pending cancellation now
  restores source authority under the republished source ACTIVE pin, with target
  outage, terminal COMMIT loss and independent restart controls. Its expanded
  lifecycle run passes 177 cases. A final 52-case run adds shared-guard cancellation
  across multiple tables and tenants. Payload/search rotation and adopted-restore
  rewrap/cancellation remain open. See
  [cancellation](status.md#pending-rewrap-cancellation-checkpoint-2026-10-23) and
  [status](status.md#active-root-rewrap-checkpoint-2026-10-23).
  Full regression passes 1,647 tests and 18 subtests, with three separate-environment
  skips. After harness-only profile admission changes, each rewrapped text/VARCHAR
  backup passes one export and 15 restore cases on a new PostgreSQL 16 cluster.
  The installed wheel matches all 33 packaged files and starts its CLI.
- Rewrap planning checkpoint, 2026-10-23: 35 native planner cases pass within
  the 55-case planner/provider run and later full/focused suites. Five offline
  protocol groups pass. That earlier checkpoint covered inactive planning.
  The execution checkpoint above adds successor cutover and shared activation. See
  [status](status.md#inactive-rewrap-planning-checkpoint-2026-10-23).
  A later offline check installs the local wheel into a disposable environment,
  matches 33 installed files against the archive, and starts its CLI. Dependencies
  were not installed or qualified by this check; see the
  [installed-wheel receipt](_reset/rewrap-plan-installed-wheel-20261023.json).
- Development checks diagnose the default read-only Git mount and denied sockets.
  Scoped approved execution restores Git writes and both fresh PostgreSQL probes.
  Full regression passes 1,620 tests plus 18 subtests, with three separate-environment
  skips. A final diagnostic-only guard then passes 76 focused checks. The full
  suite predates that final guard. See
  [status](status.md#development-environment-recovery-2026-10-23).
- Current lifecycle evidence: local PostgreSQL 16, Python 3.12.3, SQLAlchemy 2.1.3,
  psycopg 3.3.6, cryptography 50.0.2. The full and fresh-cluster receipts below
  bind source hashes. The full SQLAlchemy 2.0.51 profile was not rerun.
  A pinned Smolink lifecycle passes separately on Python 3.13 with SQLAlchemy 2.0.51
  and 2.1.3, using alternate greenlet and driver cells; see [status](status.md#pinned-smolink-adoption-2026-10-22).
- Release artifacts: reproducible wheel and sdist, verified `RECORD`, license
  metadata, and a CycloneDX 1.5 SBOM pass on the local cell. Provenance,
  signing, publication identity, and independent rebuild remain UNKNOWN. The
  2026-10-22 correction verifies complete wheel RECORD coverage and refuses unsafe
  archive members. The installed-artifact correction compares the current wheel with
  installed files and imports verified source under an isolated bytecode cache.
  Scoped approved execution outside the sandbox restores both private-role probes
  and Git writes. An earlier full suite, before numeric API admission, passes 1,567 tests, with 3 separate-environment
  tests skipped and 18 subtests passed; [receipt](_reset/frame-policy-full-sa21-20261022.json).
  Each source type, historical text and native VARCHAR, passes one export and 15
  restore cases on a new cluster with metadata and approved status inspection;
  current [VARCHAR](_reset/fresh-cluster-restore-20261022-28.json) and
  [text](_reset/fresh-cluster-restore-20261022-27.json) receipts report matching start/end Python hashes.
- Implemented scope: native text and VARCHAR storage, exact equality, `IN`, tenant-scoped uniqueness,
  sync/async attachment, maintenance protection transition, read-only transition status, in-place decrypt-back and
  additive removal for that transition format, an independent application lifecycle and
  a pinned external Smolink URL workload with an import-free restart, a fresh-cluster protected-backup recovery harness with approved
  restore adoption, CF1 primitives, and a local development provider.
- All seven qualification gates remain UNKNOWN.
- Every protected type outside the text family, every advanced predicate, online migration,
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
| OBJ-SEC-05 | Isolate keys; bound nonces, leases, cache lifetime, fork safety | VERIFIED, bounded | `crypto/keys.py` strict policy, cache expiry, fork refusal; local provider outage/revocation/lease drills pass on both SQLAlchemy cells | Remote cancellation, usage limits, production custody |
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
| OBJ-LIFE-05 | Decrypt-back current edits; preserve schema behavior; package-free exit | VERIFIED, bounded | `deprotection.py` implements `cryptalis.reverse/v1`: staged plaintext, verified backfill, transactional switch, recorded constraint/index/collation restoration, guarded activation, approved removal, and terminal-state assertions; seven lifecycle cases pass on both profiles; an independent three-model application completes protect/search/modify/decrypt-back/remove and a package-free restarted process performs native CRUD; the same reverse completes on an adopted restored cluster with the binding; lock v2 captures and restores protected-column comments, statistics targets, storage, compression, options, column grants, constraint/index comments and extended statistics; grants are applied to the ciphertext column at protection; owned sequences remain refused; native catalogs now verify captured metadata through fresh-cluster restore and adopted removal; terminal removal refuses late metadata drift and retains the journal on failed retirement | Broader external application scope, physical column order, owned-sequence restore, retained-native |
| OBJ-LIFE-06 | Rollback, restore, stale pin refusal, RPO/RTO, disaster drills | PARTIAL | Older-snapshot and stale-pin refusals; reverse abort, pin/state ordering, corrupt-frame and disabled-guard refusals; isolated-cluster plaintext and protected restore with frame recovery and loud authority refusal; `cryptalis.restore/v1` adoption issues a binding after approval, frame authentication, schema comparison, and behavioral probes; the adopted cluster then attaches, reverses, and removes; local provider outage/revocation/lease drills keep the committed prefix and fail closed | Host-authenticated fencing/quarantine, RPO/RTO measurement |
| OBJ-LIFE-07 | Three separate rotation workflows | PARTIAL | Root-rewrap successor cutover and shared activation, byte preservation, exact lineage, pending retry/cancellation, process/COMMIT recovery and repeated-rewrap decrypt-back/removal; source-pinned payload planning, bounded durable shadows, exact prefix/terminal paired checks and source-only cancellation, native process/COMMIT recovery | Payload sealing/cutover/publication, search reindex, adopted-restore rewrap/cancellation, external provider/authority qualification |
| OBJ-LIFE-08 | Production KMS with outage/revocation/cost evidence | BLOCKED | Local development provider only | Authorized provider account and independent review |
| OBJ-LIFE-09 | Install, upgrade, decommission, clean uninstall | PARTIAL | Importable package; approved in-database removal retires reverse-owned objects after decrypt-back; a package-free restarted application process performs native CRUD | Versioned upgrade/removal and broader external application evidence |
| OBJ-DX-01 | Minimal model/query changes; one manifest and one attach | IMPLEMENTED | `compile_protection`, `attach`, CLI inspection, read-only protection and reverse `status` | Unify plan/apply/remove entry points; complete status coverage |
| OBJ-DX-02 | Read-only `cryptalis doctor` with explicit UNKNOWN results | PARTIAL | Bounded database/declaration diagnostics | Implement the full doctor and provider/role coverage |
| OBJ-DX-03 | Real FastAPI/SQLModel app plus a second independent app | PARTIAL | Pinned Smolink revision 498d24b runs its original FastAPI app, HTTP URL creation and refusal cases, real Redis, repository/ORM CRUD, protect/decrypt-back/remove, and a fresh import-denied process; 38 original Python source hashes match, with zero source/model/query edits; only Url.destination is protected; the in-repo three-model application retains its separate evidence | Broader protected fields and application suite, exact packaged Python 3.13 cell, SQLModel integration, and a second external app |
| OBJ-DX-04 | Normal ORM identity, loading, sessions, pooling, async | PARTIAL | Bounded sync/async adapter and search tests | Broader ORM/framework coverage |
| OBJ-DX-05 | Complete quickstart, threat model, leakage, recovery docs | PARTIAL | README, architecture, security, lifecycle, walkthroughs | Keep docs tied to admitted APIs and evidence |
| OBJ-PERF-01 | Continuous native vs protected latency/resource measurements | PARTIAL | Slice 3/4 profiles and million-row receipts | Cold/concurrent/tail/WAL/provider measurements |
| OBJ-PERF-02 | Profile-guided optimization without security loss | PARTIAL | Membership projection correction on 2026-10-09 | Continue profiling; no unverified speed claims |
| OBJ-PERF-03 | Multithreading/multiprocessing/async at 1/4/16/saturation | SPECIFIED | Single-worker maintenance path | Define and run isolation/backpressure/cancellation tests |
| OBJ-PERF-04 | Added p95 targets and growth path | PARTIAL | Earliest profiles missed targets; later searches passed local targets | Re-measure current revision; write/pause budgets undecided |
| OBJ-OPS-01 | Reproducible wheel/sdist, SBOM, provenance, reviewers | PARTIAL | `pyproject.toml`, `uv.lock`, `scripts/release_check.py`; [2026-10-21 receipt](_reset/release-check-20261021.json) shows identical repeat-build hashes, verified wheel `RECORD`, license metadata, CycloneDX 1.5 SBOM, and clean-venv import/CLI | Independent rebuild, signed provenance, vulnerability scan, publication identity, upgrade/uninstall matrix, independent review |
| OBJ-OPS-02 | Recoverable source/evidence and traceability | PARTIAL | Git history and `docs/_reset` receipts | Durable archive and fresh restore |
| OBJ-RESEARCH-01 | Source-backed comparative research with repeatable evidence | ONGOING | Research repository provenance; source-access and fallback rules in `AGENTS.md` | Preserve failed alternatives and provenance links |
| OBJ-RESEARCH-02 | One coherent working candidate that passes all gates | PARTIAL | Implemented scope above | Continue integration; all seven gates UNKNOWN |

## Import ledger

| Date | Research reference | Mechanism | Product files | Evidence | Status |
|---|---|---|---|---|---|
| 2026-10-23 | Payload staging and cancellation | Immutable P shadows, locked atomic progress, preserved source frames/indexes, authenticated resume and source-only abort | `rotation.apply_payload_rotation`, `status_payload_rotation`, `abort_payload_rotation`, shared maintenance mechanics | 26 native execution/recovery cases, including multi-table/tenant, actual COMMIT reply loss, SIGKILL/fresh restart and rollback after native writes; [recovery](_reset/payload-stage-recovery-20261023.json), full regression 1,745 plus 18 subtests; [full](_reset/payload-stage-full-20261023.json), 34 installed package files and CLI startup | VERIFIED for named controls; sealed A, cutover/publication and seven full gates remain SPECIFIED or UNKNOWN |
| 2026-10-23 | Payload-generation preparation | Source-pinned read-only proposal, exact retained roots/wrappers, one new independent monotonic payload root, unchanged search custody, whole-row logical budget and measured costs | `rotation.plan_payload_rotation`, `PayloadRotationPlan`, shared proposal validation and native controls | 163 focused planner/root-rewrap/crypto controls; full regression 1,719 plus 18 subtests; final matching-preparation-pin refusal; [focused](_reset/payload-plan-focused-20261023.json), [full](_reset/payload-plan-full-20261023.json), [final](_reset/payload-plan-final-admission-20261023.json) | VERIFIED for named read-only controls; staged/sealed payload execution and seven full gates remain SPECIFIED or UNKNOWN |
| 2026-10-23 | Pending root-custody cancellation | Source ACTIVE host authority, exact pending/proposal checks, atomic guard release/source restoration/ABORTED marker, target-outage recovery | `rotation.abort_rewrap`, native cancellation controls and public-fixture worker | 177 expanded lifecycle cases; final 52 cancellation/cutover cases including multi-table tenants, post-DDL rollback, terminal COMMIT loss and independent process retry; [final](_reset/rewrap-abort-final-20261023.json) | VERIFIED for named local controls; adopted-restore cancellation, full rotation and seven gates remain open or UNKNOWN |
| 2026-10-23 | Native root-custody cutover | Immutable transition/v2 successor, shared executor/guards/activation, exact predecessor admission | Migration, rotation, reverse inventory and native recovery worker | 165 focused lifecycle cases; 60 expanded recovery/planner cases including terminal COMMIT-reply loss and fresh-process activation; full regression 1,647 plus 18 subtests; rewrapped text/VARCHAR each pass one export and 15 fresh-cluster restore cases; [full](_reset/rewrap-execution-full-20261023.json), [recovery](_reset/rewrap-execution-recovery-20261023.json), [backup](_reset/fresh-cluster-restore-20261023-2.json) | VERIFIED for named local controls; complete rotation and all seven gates remain incomplete or UNKNOWN |
| 2026-10-23 | Scoped environment recovery and development diagnosis | Existing wrapper diagnoses Git/socket restrictions, private test provenance, tools, PG16 and restricted roles; supported approval supplies the required execution path | `scripts/test_postgres.py`; native diagnostic and source-evidence controls | Full suite: 1,620 tests plus 18 subtests, three skips; after final diagnostic guard: 76 focused checks; [full](_reset/environment-rewrap-full-20261023.json), [final](_reset/development-preflight-final-20261023.json) | VERIFIED in local cell; no service/credential/mount/policy changes; target authorization and all gates UNKNOWN |
| 2026-10-23 | Inactive root-rewrap admission | Read-only snapshot proposal with exact retained-root comparison, frame authentication and digest-only observations | `src/cryptalis/rotation.py`; standalone protocol and native controls | 35 native planner cases within 55 planner/provider checks; later full/focused regression above; five offline protocol groups; [native](_reset/rewrap-plan-native-green-20261023.json) | VERIFIED for named read-only observations; active rotation and all gates remain incomplete or UNKNOWN |
| 2026-10-22 | Typed numeric API admission | Share finite-number and representable-duration checks across protection, reverse and maintenance approval | Migration, reverse and native rate controls | Ten initial raw overflows; 119 focused native tests pass, including fractional rates and full transitions; reproducible artifacts and 32-file installed-wheel check pass; [focused](_reset/numeric-admission-focused-20261022.json) | VERIFIED for public numeric admission and unchanged native effects; earlier full/fresh runs are separate evidence; all gates UNKNOWN |
| 2026-10-22 | Exact restored frame policy | Admit only known PG16 forms of declared CF1 checks; bind older restatements to source fields; compare constraint identities by schema, table and name | Search storage, restore binding and fresh-cluster fixtures | Four initial false acceptances; 172 focused controls pass; text and VARCHAR each pass one export and 15 restore cases, including a same-name incoming FK; pinned Smolink and 1,567 full tests plus 18 subtests pass; [full](_reset/frame-policy-full-sa21-20261022.json), [restore](_reset/fresh-cluster-restore-20261022-27.json) | VERIFIED for named local controls and exact policy forms; general SQL equivalence is not admitted; all gates UNKNOWN |
| 2026-10-22 | Host artifact input admission | Reuse offline compiler lock and catalog structure checks; require safe estimate values and reverse snapshot maps before connection | Compiler, migration, reverse and native plan/CLI controls | 14 initial failures; 138 first focused and 64 final focused tests pass, including 24 admission controls and legacy v1/v2 artifacts; 1,567 full tests and 18 subtests pass; [full](_reset/plan-admission-full-final-sa21-20261022.json), [focused](_reset/plan-admission-final-focused-20261022.json) | VERIFIED for named structural checks and input diagnosis; no host authentication or live semantic claim; all gates UNKNOWN |
| 2026-10-22 | Host-bound staged catalog | Derive protection shadows from the source lock and reverse staging from the host-pinned protected snapshot plus native source types; retain journal continuity | Migration, reverse metadata documentation, native staged-schema controls | 24 initial false acceptances; 175 focused and 1,543 full tests plus 18 subtests pass; pinned Smolink and both fresh-cluster paths pass; [full](_reset/paused-schema-full-sa21-20261022.json) | VERIFIED for recorded catalog facts before paused progress; no freshness or value-verification claim; all gates UNKNOWN |
| 2026-10-22 | Host-bound paused writer fence | Share the host-derived guard check across protection and reverse paused operations and plaintext publication; retain journal continuity checks | Migration, reverse, native guard controls and revised crash/marker fault tests | 18 initial failures; 22 adversarial cases, two native fault controls, and 1,519 full tests plus 18 subtests pass; pinned Smolink and both fresh-cluster paths pass; [full](_reset/paused-guard-full-sa21-20261022.json) | VERIFIED for guard admission before progress; staged catalog admission is a separate later slice; all gates UNKNOWN |
| 2026-10-22 | Host-bound protected catalog | Derive the protected catalog from the source lock; inspect generated frame checks, equality indexes and pending guards; retain explicit restore restatement admission | Compiler, migration, search, reverse and restore modules; native adversarial and fresh-cluster tests | 14 initial false acceptances; 89 lifecycle, 219 expanded and 1,497 full tests plus 18 subtests pass; pinned Smolink passes; each text/VARCHAR fresh cluster passes one export and ten restore cases; [full](_reset/active-contract-full-sa21-20261022.json) | VERIFIED for recorded catalog facts and declared CF1 objects; no key/value or transitive function evidence; all gates UNKNOWN |
| 2026-10-22 | Verification source stability | Capture starting Python hashes and Git revision; compare final bytes; refuse success on changes while retaining the original pytest outcome | `scripts/test_postgres.py`, `tests/test_postgres_evidence.py` | Eight RED controls; 12 source-gate controls, ten real CLI tests, 1,459 full tests plus 18 subtests, pinned Smolink and both fresh-cluster paths pass; [focused](_reset/evidence-stability-final-focused-20261022.json) | VERIFIED for two-observation source admission; no full execution attestation; all gates UNKNOWN |
| 2026-10-22 | Reverse operational status | Read-only snapshot of decrypt-back phases, source identity, counters, native metadata and terminal removal; existing CLI dispatches by artifact format | `deprotection.py`, `migration.py`, `cli.py`; native status/CLI and fresh-cluster tests | 81 focused, 41 adversarial, seven final metadata controls, and 1,447 full tests plus 18 subtests pass; [focused](_reset/reverse-status-green-20261022.json), [adversarial](_reset/reverse-status-adversarial-20261022.json); removed counters remain unavailable | VERIFIED for named local checks; no key/value/provider verification or deployment authority; full gates UNKNOWN |
| 2026-10-22 | Pinned Smolink lifecycle and adoption corrections | Canonical catalog deparsing with restored caller settings and preserved SQLSTATE; invalidate warmed mapper flush caches at attachment | Compiler, adapter, native regressions, and pinned external app/workload tests | RED: native search-path and DML cache controls; initial full run found eight read-only route assertions. GREEN: 154 focused, 1,405 full plus 18 subtests, and the original app lifecycle on two Python 3.13 SQLAlchemy cells; [SA 2.0](_reset/smolink-final-sa20-20261022.json), [SA 2.1](_reset/smolink-final-sa21-20261022.json) | VERIFIED for storage-only Url.destination and the named alternate cells; all full gates UNKNOWN |
| 2026-10-22 | Native VARCHAR type admission | Lock v3 and pg-varchar/v1; native character limits, pending/refresh and failure-state parity; exact query binds; native type restoration; strict reader and transform admission | Compiler, adapter, search and reverse modules; native VARCHAR and fresh-cluster tests | RED: 27 initial cases; reader, rollback-state and hidden-transform controls. GREEN: 179 focused plus 18 subtests, 1,402 full plus 18 subtests, each text/VARCHAR fresh-cluster path passes one export and seven restore cases; [full](_reset/varchar-full-sa21-20261022.json), [VARCHAR restore](_reset/fresh-cluster-restore-20261022-8.json), [release](_reset/varchar-release-20261022.json) | VERIFIED, bounded local cell; external-app adoption remains open; all gates UNKNOWN |
| 2026-10-22 | Fractional measured-rate artifact correction | Share bounded JSON structure checks; admit decimals only at measured throughput paths, including embedded source plans | `src/cryptalis/manifest/parser.py`; `src/cryptalis/migration.py`; `src/cryptalis/deprotection.py`; `tests/test_transition_rates.py` | RED: 3 lifecycle failures. GREEN: 157 focused, 1,363 full tests plus 18 subtests, one export and seven restore cases, repeat release builds and 32 installed-file comparisons; [full](_reset/transition-rates-full-sa21-20261022.json), [restore](_reset/fresh-cluster-restore-20261022-6.json), [release](_reset/transition-rates-release-20261022.json) | VERIFIED, bounded local cell; all gates UNKNOWN |
| 2026-10-22 | Local operational-status slice | Read-only repeatable-read snapshot, committed progress, host pin comparison, safe CLI inputs and diagnostics | `src/cryptalis/migration.py`; `src/cryptalis/cli.py`; status and fresh-cluster tests | RED: missing API/command and malformed plan boundaries. GREEN: 1,351 full tests plus 18 subtests, one export and seven restore cases, eleven release groups and 32 installed-file comparisons; [full](_reset/status-full-sa21-20261022.json), [restore](_reset/fresh-cluster-restore-20261022-5.json), [release](_reset/status-release-20261022.json) | VERIFIED, bounded local cell; no data verification or provider admission; all gates UNKNOWN |
| 2026-10-22 | Native metadata backup/recovery and terminal removal | Lock v2 catalog comparison before journal retirement and during terminal checks; safe missing-journal inspection; native backup metadata assertions | `src/cryptalis/deprotection.py`; `tests/test_deprotection.py`; fresh-cluster qualification modules | RED: 6 drift cases, then 3 terminal retries. GREEN: 22 focused, 1,322 full plus 18 subtests, 1 export and 7 restore; [full](_reset/removal-metadata-full-sa21-20261022.json), [fresh cluster](_reset/fresh-cluster-restore-20261022-4.json), [negative control](_reset/fresh-cluster-metadata-control-20261022.json) | VERIFIED, bounded local cell; all gates UNKNOWN |
| 2026-10-22 | Installed-artifact identity audit | Compare installed bytes with the current wheel, refuse stale package files, isolate bytecode caches, and suppress raw child failure output | `scripts/release_check.py`; `scripts/test_release_check.py` | RED: 4 accepted artifact mutations, stale bytecode execution, and startup diagnostic exposure. GREEN: 11 test groups and actual offline uv install, 32 matched files, isolated CLI; [receipt](_reset/release-install-binding-20261022.json). No dependency or PostgreSQL qualification | VERIFIED, offline local cell; all gates UNKNOWN |
| 2026-10-22 | Local artifact-integrity audit | Complete wheel RECORD coverage and strict wheel/sdist member inspection | `scripts/release_check.py`; `scripts/test_release_check.py` | RED: 25 failures and 4 errors. Review RED: 7 further failures. GREEN: 10 test groups, valid controls, matching offline repeat builds, SBOM; [receipt](_reset/release-integrity-20261022.json). PostgreSQL preflight failed, exit 2; full suite unrun | VERIFIED, offline local cell; all gates UNKNOWN |
| 2026-10-21 | Local release-artifact slice | Reproducible wheel/sdist build, wheel `RECORD` verification, archive-member inspection, MIT license metadata, CycloneDX 1.5 SBOM, clean-venv import and CLI smoke | `pyproject.toml`; `scripts/release_check.py` | GREEN: two builds matched; wheel and sdist hashes recorded; clean venv imported the installed package and started the CLI; [receipt](_reset/release-check-20261021.json) | VERIFIED, local cell; G-RELEASE UNKNOWN |
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

1. Run the same lifecycle through a pinned external application, then repeat it on a
   fresh PostgreSQL cluster.
2. Close the remaining reverse-lifecycle metadata and recovery gaps (physical column
   order, retained-native, owned sequences). Lock v2 now captures and restores comments,
   statistics targets, storage, compression, options, column grants, constraint and
   index comments, and extended statistics. Owned sequences remain refused. See the [metadata research note](research/metadata-preservation-and-format-evolution.md)
   and the [lock v2 proposal](research/lock-v2-metadata-proposal.md).
3. Continue correctness slices that protect the compatibility promise with native
   PostgreSQL oracles; establish a second independent application baseline.
4. Extend the fresh-cluster range with multi-table, fault, and provider-outage drills.
5. Keep every external review and provider item explicitly UNKNOWN; review the
   [lab reconciliation](research/lab-reconciliation-2026-10-19.md) for refused-metadata
   signals, without adopting lab code.
