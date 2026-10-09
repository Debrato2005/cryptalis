# Implementation status

**IMPLEMENTED:** research prototype with a product manifest compiler, CF1 text primitives, a local development provider,
and bounded sync/async SQLAlchemy storage/search plus a PostgreSQL maintenance protection transition.
Separate runtime-role verification is complete for the local cell.
No PostgreSQL/provider/runtime cell, production key provider, independent review, or release is qualified.
VERIFIED below refers only to the named checks and their exact revisions.
All other contract and promotion requirements are SPECIFIED. All seven full gates remain UNKNOWN.

## Step A corrective checkpoint: 2026-10-09

**IMPLEMENTED:** same-schema tables share the existing operation guard function, with a separate trigger on each table.
Expand creates the function once per schema. Activation/abort inspect every fence, drop every operation trigger, then drop each function without CASCADE in the same transaction.
An existing function is never replaced or adopted; `guard_function_conflict` reports native `42723`. Names, artifacts, pins and journal state are unchanged.
Frozen field descriptors are validated once per backfill chunk and once per model verification pass. No descriptor, tenant key or row context is retained across operations.
AEAD, field/tenant/row binding, fresh nonces, key expiry/generation checks, full verification and bounded lock retries remain unchanged.

**VERIFIED:** [final checkpoint](_reset/step-a-corrective-final-030b935c0581cb72.json) at content revision `worktree-030b935c0581cb72`;
[full suite](_reset/step-a-corrective-final-verification-030b935c0581cb72.json): **1,004 passed**, including 18 same-schema E2E/attack cases.
The tests assert exact NULL/empty/Unicode values across two tables, three fields and two tenants; both write fences; five process-kill/resume phases;
idempotent pre-switch abort; atomic failure during second-table expansion/retirement; conflict preservation; fence-drift refusal; and rejection of valid wrong-field/tenant/row frames before switch.
[Corrective proofs](_reset/step-a-corrective-regressions-030b935c0581cb72.json): original engine fails the native two-table application test, fixed engine passes;
six isolated removals fail/restoration passes, and all five old single-table checkpoint phases resume through the new engine.
[Twenty prior safety removals](_reset/slice5-regressions-audit-729b0f0ba9f8fea6.json) and [five bounded-lock removals](_reset/step-a-lock-regressions-0fadd110317d7e85.json) still fail/restoration passes.
Graphify was refreshed; source confirms guard creation/retirement and descriptor call paths. All database commands used the fresh-credential wrapper.

| Instrumented one-million-row measurement | Recorded baseline | Corrected engine |
|---|---:|---:|
| Backfill / throughput | 98.126 s / 10,191 rows/s | 67.804 s / 14,748 rows/s |
| Backfill main CPU / descriptor CPU | 64.588 s / 17.739 s | 35.658 s / 0.030 s |
| Verification / descriptor CPU | 65.404 s / 16.214 s | 42.214 s / 0.000062 s |
| Writer pause / observed expansion reader wait | 169.145 s / 5.496 s | 116.291 s / 6.106 s |

The [paired 20,000-row control](_reset/step-a-corrective-summary-c64053e2b5558c3f.json) measured backfill 2.065→1.128 s and verification 1.579→1.131 s before the single new million-row run.
[New measurement](_reset/step-a-optimized-million-1000000-a94d3d18190b80fb.json) reuses the baseline data, chunks and instrumentation: 500 UPDATE batches, 5,027 inspection/marker calls and 500 pipeline sync points remain unchanged.
Backfill SQL-call wall time was 37.560 s, including 29.340 s combined server/network/scheduling time; commits took 2.887 s. Exact database execution/wait time is unavailable.
Cluster-wide backfill WAL was 1,189,163,448 bytes; equality-index growth was 88,588,288 bytes. Physical per-index writes are UNKNOWN; no database/WAL optimization is claimed.
WSL still exposed 20 CPUs, 7.47 GiB RAM and 2 GiB swap with no overrides. Starting load was 0.864/0.682/0.467, versus 0.154/0.352/0.353;
available memory was 3.94 versus 6.12 GiB. New process peak RSS was 98.31 MiB. Cache/checkpoint/load differences and instrumentation limit causal claims.
The observed writer-pause reduction is 31.2%; the paired CPU/descriptor evidence supports a real reduction in Python work. Remaining sealing/verification work and expansion locking still cost time.
The engine verified all million values; an independent decoder checked eight representative rows, and the smaller E2E cases independently decoded every field.
The small-run receipt label was overwritten by an instrumentation-loop variable; source hashes identify baseline/fixed runs. The label was corrected before the million-row run; timing/workload logic was unchanged.
No Slice 6, parallelism, dual writes, public configuration or security-contract change. All seven gates remain **UNKNOWN**; no production provider or independent review exists.

## Step A protection measurement and lock checkpoint: 2026-10-09

**VERIFIED, instrumented one-million-row PostgreSQL run at Git `0383cec`:** [measurement](_reset/step-a-protection-0383cec.json).
The user confirmed that unrelated programs were closed. WSL exposed 20 logical CPUs (20 reported cores, one thread per core), 7.47 GiB RAM and 2 GiB swap;
no `.wslconfig` overrides or narrower cgroup CPU/memory limits were found. Load averages changed from 0.154/0.352/0.353 to 1.133/0.791/0.532.

| Phase | Wall time | Main client CPU |
|---|---:|---:|
| Expand | 5.521 s | 4.711 s |
| Backfill, 500 chunks of 2,000 rows | 98.126 s; 10,191 rows/s | 64.588 s |
| One final verification and switch | 65.433 s; verification 65.404 s | 63.865 s |
| Local ACTIVE acknowledgement | 0.023 s | 0.009 s |

Writer pause was **169.145 s**, excluding seed/plan/drain and real publication delay. Expansion index creation took 0.229 s over NULL shadows.
DDL SQL calls took 0.062 s at expansion and 0.0013 s at switch; these overlap phase times.
Lock-request calls took 0.114/0.252/0.143 ms at expansion/verification/activation. No executor lock wait was sampled; exact server wait time is unavailable.
The plain reader waited 5.496 s during expansion. Client-observed ACCESS EXCLUSIVE intervals were 5.512/0.018/0.016 s at expansion/switch/activation.
Backfill/verification reads continued; their maximum observed latencies were 156/37 ms, with no sampled reader lock wait in those phases.
Backfill CPU: seal 32.371 s, repeated descriptor preparation 17.739 s, key preparation 0.025 s. Client CPU dominates this workload with public test roots.
There were 500 UPDATE batches, 5,027 inspection/marker calls, 500 pipeline sync points and 504 driver commits; exact wire round trips are unavailable.
SQL-call wall time was 40.831 s, including 8.854 s client CPU and 31.977 s non-CPU time. The latter includes server/network/scheduling, not isolated database wait.
Sampled database waits included 73 WALSync, 22 WALWrite and 79 DataFileWrite observations; variable sampling intervals do not establish wait seconds.
Backfill cluster-wide WAL advanced 1,269,621,872 bytes. Equality-index size grew 76,800,000 bytes; per-index physical writes and table-attributed WAL remain UNKNOWN.
Instrumentation adds overhead and its component timers overlap. A [failed observer run](_reset/step-a-failed-instrumentation-0383cec.json) is retained as failed evidence;
restricted-role activity fields were NULL. Corrected instrumentation passed a [1,000-row control](_reset/step-a-smoke-1000-0383cec.json) before the million-row run.

**IMPLEMENTED local fix:** the executor keeps a 5 s session lock timeout. ACCESS EXCLUSIVE acquisition now uses three 100 ms attempts, with 50 ms gaps and savepoint rollback.
Cutover explicitly upgrades before DDL; rollback releases partial upgrades but retains EXCLUSIVE verification locks. Exhaustion reports `table_lock_busy_retry`/`55P03` without switching.
These limits bound individual acquisition attempts, not time spent holding a granted lock or an entire multi-table operation.
[Regression proof](_reset/step-a-lock-regressions-e137d3240bd453e9.json): `0383cec` gives three failures/one native-control pass; fixed code gives four passes. Five safety removals fail and restoration passes.
[Full verification](_reset/step-a-lock-verification-e137d3240bd453e9.json): **986 passed** at content revision `worktree-e137d3240bd453e9`.
[Twenty prior safety removals](_reset/slice5-regressions-audit-0e01c8924bb16893.json) still fail their tests and restoration passes. All database work used the fresh-credential wrapper.
Graphify was refreshed and findings were checked in source. A [same-schema two-table control](_reset/step-a-guard-reproduction-e137d3240bd453e9.json) reproduced duplicate guard-function creation (`42723`) with atomic rollback. The corrective checkpoint above fixes it; this control remains historical evidence.
Parallel workers are **not recommended before slice 7** on this evidence. First evaluate preparing the immutable descriptor once, then repeat a controlled profile.
Disjoint workers would need atomic per-range coverage, stable context/key generations, crash reconciliation, terminal original transactions, serialized cutover, and mandatory global verification; the current single cursor does not supply that protocol.
The historical 508.7/197.0 s variation is still UNKNOWN: source, instrumentation, load, chunking and cache conditions were not controlled across those runs.
Slice 6/7, decrypt-back measurements and package-free removal remain unimplemented. No dual writes or parallelism were added. All seven gates remain **UNKNOWN**.

## Step 0 protection-pause checkpoint: 2026-10-09

**IMPLEMENTED:** uninterrupted apply verifies and switches in one transaction, with one full verification pass.
Saved VERIFIED checkpoints still require fresh verification and an unchanged frame digest before switch.
Verification uses PostgreSQL EXCLUSIVE locks: plain reads continue, while writes and locking reads wait.
DDL still acquires ACCESS EXCLUSIVE. A reader that delays DDL past the lock timeout leaves source data and the BACKFILLED marker unchanged.
`print(plan_result)` reports native row count, supplied measured rates, and the estimated uninterrupted writer pause.
Extra verification checkpoints/retries, drain, DDL, index construction, and publication delay are excluded; this is not a pause bound.
**VERIFIED, bounded PostgreSQL 16 cell:** content revision `worktree-c72bb439d7e13334`, based on Git `9f335c6`.
[Full verification](_reset/step0-verification-c72bb439d7e13334.json): **982 passed**, including seven new native lock/SQL and independent-decoder cases.
[Step 0 proofs](_reset/step0-regressions-c72bb439d7e13334.json): committed engine gives six failures and one pass; fixed copy gives seven passes.
Seven isolated Step 0 mutations and [20 existing safety removals](_reset/slice5-regressions-audit-72f0a976a1fe9d8f.json) fail their behavioral checks; restoration passes.
The authentication attack now flips a tag bit instead of assigning a byte that could already have that value.
No new million-row pause was measured. The historical 508.7 s receipt and unexplained timing variation remain historical evidence.
No protocol change, dual writes, slice 6/7, production provider or independent review is added. All seven gates remain **UNKNOWN**.

## Corrective audit checkpoint: 2026-10-09

**VERIFIED, bounded PostgreSQL 16 cell:** source/test revision `audit-a07004dfcda8cd05`, based on `fe2b061`.
This is a content-bound worktree revision, not a Git commit. [Full receipt](_reset/audit-verification-a07004dfcda8cd05.json): **975 passed**.
[Slice 3](_reset/slice3-audit-a07004dfcda8cd05.json): 64 cases; [slice 4](_reset/slice4-audit-a07004dfcda8cd05.json): 75;
[slice 5](_reset/slice5-audit-a07004dfcda8cd05.json): 53 existing plus 40 audit cases. Old receipts remain unchanged.
Earlier slice 3 and 4 row-isolation claims did **not** cover grouped or callable primary-key binds.
The fix captures grouped AND/scalar-IN identities, normalizes explicit bind values and rejects ambiguous forms before SQL.
Protected primary-key lookups in HAVING or JOIN ON also reject. Plain projections retain native primary-key grammar.
All maintenance entries require approval before connection or locks. Read-only plan/deployment/attachment checks are exempt.
Acquisition, phase and cleanup failures retain safe diagnostics, operation identity and both primary/cleanup outcomes.
The credential wrapper reloads both private files and probes both roles; three real authentication-failure controls verify suite redaction.
[Audit regressions](_reset/audit-regressions-a07004dfcda8cd05.json) compare original and fixed code in isolated copies;
[20 existing safety removals](_reset/slice5-regressions-audit-1407433d842664f6.json) fail without their mechanism and pass after restoration.
No slice 6 work, production provider or independent review is added. All seven gates remain **UNKNOWN**.

## Slice 5 checkpoint: 2026-10-09

**IMPLEMENTED:** `cryptalis.migration.plan`, `apply`, `verify`, and pre-switch `abort`.
One phase loop uses a PostgreSQL journal, cooperating session advisory lock, transactional DDL, and bounded atomic chunks.
Plans bind the native schema, compiler lock, target, runtime role, inventoried tenant key policies, writer assertions, and host cost estimates.
Expand drains table access and installs an owner-controlled statement trigger that rejects restricted-runtime writes across chunk commits and process crashes.
Resume preserves committed ciphertext. Full verification checks membership, native value/type/NULL parity, authentication, terms, generations, constraints/indexes, and trigger inventory.
At that recorded revision, switch repeated verification under exclusive table locks and retired the original SQL column without CASCADE.
Database switch remains PENDING until the host supplies the exact externally published ACTIVATING pin.
After acknowledgement, startup requires the externally current ACTIVE pin, target/schema agreement, planned runtime role, and matching tenant key policies.

**VERIFIED, local PostgreSQL 16.15:** **53 migration cases** within **917 passing full-suite cases**.
The original native application supplies plaintext/type/NULL oracles; a separate stdlib HKDF/HMAC and AEAD decoder checks migrated frames against those values.
Independent child processes are killed at durable phase boundaries and during a partly completed backfill, then resume without replacing committed frames.
A real PostgreSQL transport fault discards an already-terminal COMMIT reply. Resume inspects the committed marker and retains the first chunk's bytes.
Connection faults during expand, verify, and transactional switch preserve the original representation and prevent false completion.
Concurrent runtime writes committed before fencing are included; writes during maintenance reject with `55000`, and an attached retry works after publication.
The runtime can read progress but cannot mutate the journal, disable the fence, alter its schema, or acquire ownership.
Real corruption, missing rows, changed source/index/trigger metadata, missing markers, and wrong active generations refuse switch.
A real own-schema `pg_dump`/`psql` older-snapshot restore cannot advance under the current external ACTIVE pin.
Missing publication, stale pins, altered keys, owner attachment, and competing executors refuse.
**Twenty isolated safety removals** fail their behavioral oracles; restoring each copied source restores a passing result.

[Verification](_reset/slice5-verification.json), [regression proofs](_reset/slice5-regressions.json), and
[performance](_reset/slice5-performance.json) retain commands, hashes, scope, and costs.
The final isolated million-row run backfilled **3,942 rows/s** in 253.7 s; the measured write pause was **508.7 s**.
Expand took 5.3 s, verify 148.6 s, and repeated verification plus database switch 100.9 s.
The pause ends at local ACTIVE acknowledgement; actual host publication delay adds to it.
Runtime write attempts in all four paused phases returned `55000`; an attached post-switch edit/read succeeded.
The observed phase maximum for the customer heap and indexes was 600,793,088 bytes; cluster-wide WAL increased about 1.396 GB.
These do not prove secure erasure, attributed WAL, storage bounds, or a production pause budget.
The earlier source measured 11,559 rows/s and 197.0 s pause. The cause of the run-to-run difference remains **UNKNOWN**.
An underestimated fixed WAL multiplier was replaced with required host staging cost inputs; no multiplier is presented as a bound.
The [60-line walkthrough](walkthrough-migration.md) explains plaintext retention and deployment responsibilities.

**Limits:** protection is a maintenance operation. It does not admit online plaintext writes during backfill.
Owner/DDL writers must be excluded by the host. The tests do not qualify a deployment's worker termination, credential control, policy provenance, or restore quarantine.
A supplied pin is a host assertion, not authentication implemented by this package. A restored journal never selects current authority.
Same-context row replay, hostile result omission, nullable substitution, and writers that bypass attachment remain outside the claimed boundary.
Only inventoried tenant policies are admitted. One protection operation per schema is currently admitted; an aborted journal remains for inspection.
Decrypt-back, package-free removal, rotation, finalization, retained-backup recovery, and production provider integration are not implemented by this slice.
No source mirror survives SQL switch, but dropped-column bytes can remain in heap tuples, WAL, snapshots, and backups. No erasure claim follows.
Storage/WAL and rate estimates require host staging observations; they are not bounds. Real exhaustion and production pause budgets remain UNKNOWN/D.
No production provider or independent review exists. All seven gates remain **UNKNOWN**. No commit or push occurred.

## Slice 4 checkpoint: 2026-10-08

**IMPLEMENTED:** declared exact-text equality/IN, mapped aliases, AND/OR and native tenant-scoped uniqueness.
The attachment hashes ordinary text query values with the existing independent search-root composition.
PostgreSQL uses a B-tree over the full term inside the CF1 frame, with tenant first when declared. No extension or companion column is needed.
One bytea write updates payload and term together. Native constraints arbitrate races and preserve distinct NULLs.
Attachment validates exact index/check definitions, keys, operator classes, uniqueness and valid/ready/live state.
Catalog deparsing uses `pg_catalog` resolution to reject function shadowing. Search key changes within an attachment refuse.
Protected predicates/projections compile per operation; plain projections keep native compilation caching.

**VERIFIED, local PostgreSQL 16.15:** **75 search cases**, **four independent frozen-term vector cases**, and **864 full-suite cases**.
The application path uses the separate non-owning runtime role; owner setup grants only schema USAGE and customer CRUD in disposable schemas.
Native sync/async controls compare text membership, SQL NULL/empty-IN truth, aliases, typed/reverse/late/shared binds and two protected fields.
Concurrent same-tenant insert races produce one commit and one native `23505`; cross-tenant duplicates and distinct NULLs commit.
Uniqueness failures roll back payload/term updates; later writes and queries recover. Duplicate backfill blocks unique-index creation.
Wrong-tenant queries expose no protected value. Known small domains, absent review/leakage acceptance and malformed physical contracts reject.
Listed unsupported grammar, forged/wrapped aliases, protected JOIN/derived tables, codecs, callables and ambiguous bind names refuse before SQL.
Real elapsed key-lease expiry leaves PostgreSQL unchanged; fresh sync/async sessions recover.
Independent writers can still hide search membership or install structurally plausible invalid AEAD. Point reads reject changed frames.
Returned-row authentication supplies no freshness, presence, result completeness or adversarial global-uniqueness guarantee.

[Verification receipt](_reset/slice4-verification.json) records exact source/test hashes, test intent and isolated regression removals.
[Performance receipt](_reset/slice4-performance.json) records the million-row runtime ORM measurements and their limits.
The earlier page-query source includes a protected entity projection; its former plaintext-only label is retired.
Its historical timing and causal explanation remain historical/UNKNOWN. Current profiling separates plain projections from protected entities with plaintext filters.
Empty-schema fixture conversion is not product migration. Fresh-deployment policy binding, writer exclusion, lifecycle and key rotation remain unqualified.
No production provider or independent human review exists. All seven full gates remain **UNKNOWN**. No commit or push occurred.
See the [60-line search walkthrough](walkthrough-search.md). This run stops at slice 4.

## Slice 3 checkpoint: 2026-10-08

**IMPLEMENTED:** `cryptalis.sqlalchemy.attach` returns a tenant-scoped Session factory.
Async attachment is awaited. The target must already store protected fields as `bytea`.
The host supplies a trusted compiler lock and exact tenant keyrings. Attachment does not migrate data or authenticate deployment authority.
Only ordinary ORM flush writes and admitted SELECTs are implemented. Search rewriting belongs to slice 4.
Prepared CF1 frames replace driver binds while mapped attributes remain ordinary text or NULL.
Read projections carry payload, record identity, and declared tenant context. Authentication precedes each value's release.
Protected SELECTs disable compilation caching so operation-specific result processors cannot retain another tenant, point, or key set.
Unprotected SELECTs retain native compilation caching. Public raw-driver, COPY, opaque SQL, and unprepared-write routes reject.

**VERIFIED, earlier restricted fixture-owner run:** the adapter suite returned **41 passed in 8.01 s**; the full suite returned **777 passed in 18.41 s**.
Commands: `.venv/bin/python -m pytest -q tests/test_sqlalchemy_adapter.py --tb=short`
and `.venv/bin/python -m pytest -q --tb=short`.
The cell uses Linux/WSL, Python 3.12.3, SQLAlchemy 2.1.3, psycopg 3.3.6, cryptography 50.0.2, and PostgreSQL 16.15.
The URL stayed private. Tests created and dropped only their own schemas under the restricted fixture owner.
Native and attached controls exercise exact text/NULLs, state/history, autoflush, merge, refresh/expiry, rollback,
entities/scalars/labels, aliases, outer joins, relationships, batches, streaming, and interleaved tenants.
Async controls exercise concurrent tenant tasks and cancellation observed through PostgreSQL's `PgSleep` wait event.
Cancellation during awaited key preparation leaves the database unchanged and permits a later write.
Sync and async updates/deletes work after commit expires context attributes.
Single-tenant bigint outer joins retain native NULLs. Same-named tables in separate schemas retain distinct values.
Cancellation is propagated; rollback removes the pending row; a later tenant session recovers.
Defensive checks verify driver-bind privacy with a visible unprotected control, valid-frame wrong-tenant refusal,
wrong returned point, relocated/changed ciphertext, unsupported grammar before driver execution, mapping mutation, failed-flush cleanup, and guarded reconnects.
Ambiguous columns and alternate protected mappings reject. Attachment refuses existing checked-out connections.
Target translation, changed primary-key mappings, and catalog nullability/default mismatches reject.

**VERIFIED regression sensitivity:** the main thread used an isolated copy of the current source and tests.
Only the copy lost the protected SELECT cache-disable call. All four native sync/async entity/scalar controls passed.
All four attached cases failed with `AuthenticationFailed`. Restoring the copy gave eight passes.
The original source remained unchanged during this proof. No assertion was weakened.
The withheld output was unavailable in the main-thread context. Its findings supplied no relied-upon evidence.
[Verification receipt](_reset/slice3-verification.json) binds these observations to source/test hashes.

**VERIFIED bounded cost:** 5,000 synthetic rows, 40 paired samples, warm local keys, fully consumed results.
Point p50/p95: native 0.435/0.618 ms and attached 1.715/2.903 ms. The p95 difference was 2.285 ms.
Plaintext page p50/p95: native 1.428/1.906 ms and attached 2.238/2.810 ms. Both paths recorded 60 cache hits.
[Compatibility](compatibility.md#slice-3-local-profile-2026-10-08) owns profiling details and limits.

### Restricted runtime-role completion: 2026-10-08

**VERIFIED, local slice 3 cell:** the adapter suite returned **49 passed in 9.00 s**.
The full suite returned **785 passed in 20.27 s**, with no failures, errors, or skips.
Commands: `.venv/bin/python -m pytest tests/test_sqlalchemy_adapter.py -q --tb=line`
and `.venv/bin/python -m pytest -q --tb=line` (the full run also wrote a temporary JUnit receipt).
Each database shell command loaded both URLs fresh from the private files before a psycopg `SELECT 1` check.
The SHA-256 prefixes were `0f63934e` for the fixture owner and `4e551e31` for the runtime login.
Both roles are restricted, use the same PostgreSQL 16.15 target, and have distinct identities.
The runtime login cannot inherit or `SET ROLE` to the fixture owner.

Only owned fixture objects received grants: schema `USAGE`, customer `SELECT/INSERT/UPDATE/DELETE`, and article `SELECT`.
The article read is required by native SQLAlchemy relationship lookup during customer deletion.
The first run without it failed equally in native and attached sync/async cases; the corrected grant passed.
Effective privilege checks reject schema `CREATE`, ownership, grant options, `TRUNCATE`, `REFERENCES`, and `TRIGGER`.
Sync/async native and attached controls verify exact NULL/empty/Unicode values, CRUD, refresh, and flushed-update rollback.
An independent connection observes committed protected bytes. A bind collector sees an unprotected marker and no supplied protected insert markers.
Opaque DDL rejects through the attachment before driver execution.

Independent sync and async psycopg connections receive SQLSTATE `42501` for nine operations:
create table, add column, create index, truncate, drop table, change table owner, change schema owner, drop schema, and switch to the fixture-owner role.
Each refusal rolls back; later queries succeed; inspected ownership and schema remain unchanged.
These denials concern the owned persistent schema. The runtime login retains database `TEMP` privilege; no universal DDL-denial claim follows.

A separate runtime writer can reconnect and commit data changes without the attachment.
Fresh connections observe its changed ciphertext, replayed historical frame after a legitimate application update, NULL substitution, and deletion.
Sync/async attached reads reject changed ciphertext but accept the older authenticated value, nullable NULL, and row absence.
This proves the tested schema privilege separation and read-time tamper refusal. It does not prove writer exclusion, freshness, presence, completeness, or host authorization.
Deployment enforcement, lifecycle-metadata permissions, provider custody, and independent review remain UNKNOWN.
The [runtime verification receipt](_reset/slice3-runtime-verification.json) records hashes, cases, grants, and limits.
Product source, all existing tests, both earlier receipts, and `spikes/revamp` remain unchanged.
All fixture schemas were removed. No roles or global grants changed. Slice 4 was not started.
All seven full gates remain **UNKNOWN**. This run stops at the local slice 3 checkpoint.

### Earlier prerequisite failures (historical)

The completion above supersedes these connection and role-availability blockers. The records remain preserved.

**BLOCKED advancement:** separate non-owning runtime credentials are unavailable. `cryptalis_runtime` is absent;
the only additional membership reported is the built-in non-login role `pg_database_owner`. No roles or permissions were added.
The fixture owner cannot prove runtime privilege isolation or deployment writer exclusion.
Finish this slice with provisioned restricted runtime access, native CRUD controls, and DDL/ownership refusal evidence before slice 4.

**Latest connection recheck, 2026-10-08 19:40 UTC:** this agent process has `CRYPTALIS_TEST_DATABASE_URL` set,
but psycopg reports `FATAL: password authentication failed for user "cryptalis_migrator"`.
Neither `CRYPTALIS_TEST_RUNTIME_DATABASE_URL` nor `CRYPTALIS_RUNTIME_DATABASE_URL` is set in this process.
The runtime connection could not be attempted. No fixture, privilege, or runtime test ran during this recheck.
The earlier role-catalog observation above is historical; this attempt does not establish whether the runtime role now exists.
Resume in a process that receives both working connection variables. Do not put credentials in repository files or diagnostics.

**Connection recheck, 2026-10-08 20:04 UTC:** both `CRYPTALIS_TEST_DATABASE_URL` and
`CRYPTALIS_TEST_RUNTIME_DATABASE_URL` are present in this agent executor.
One psycopg connection attempt per role returned `SELECT 1 = 1` for the runtime connection.
The migration connection failed with `FATAL: password authentication failed for user "cryptalis_migrator"`.
The required two-connection prerequisite did not pass. No database objects changed and no runtime tests ran.
Authorized CRUD, DDL/ownership denial, and sync/async attachment under separate runtime credentials remain unverified.
This recheck supersedes the earlier missing-runtime-credentials observation; it does not establish role privileges.
Supply working migration credentials privately, then recheck both connections before fixture work.
The [connection receipt](_reset/slice3-runtime-recheck-20261008T200458Z.json) records the exact failure and preservation snapshot.

The historical million-row anomaly remains UNKNOWN. No production provider, independent review, deployment admission,
transition executor, search rewriting, rotation, or release qualification follows from this checkpoint.
All seven full gates remain **UNKNOWN**. See the [walkthrough](walkthrough-sqlalchemy.md).

## Slice 2 checkpoint: 2026-10-08

**IMPLEMENTED:** `cryptalis.crypto` seals and authenticates bounded text with trusted compiler descriptors and prepared keys.
It uses library AES-256-GCM-SIV, HKDF-SHA-256, and full HMAC-SHA-256.
Strict UTF-8 preserves exact text. SQL NULL remains SQL NULL. The encoded text limit is 16 MiB.
The product implements storage-only and packed equality frames, UUID/bigint records, and both declared tenancy codecs.
It rejects unknown flags, companion representations, malformed frames, missing generations, and invalid text.

`Keyring` pins a finite policy and exact provider identities. Frame headers cannot select provider authority.
Sync and async preparation publish keys only after all roots pass checks.
The cache has fixed expiry, with a 60-second default and 300-second maximum. Access does not extend it.
Inherited providers and keys refuse use after fork. A child can create and prepare fresh local material.
The ephemeral development provider wraps, unwraps, and rewraps roots in memory.
[Security](security.md#implemented-cf1-primitives-and-local-custody) owns these operational limits and APIs.

**VERIFIED:** the focused CF1 suite returned **30 passed**, including **eight real PostgreSQL persistence cases**.
The full suite returned **736 passed** with `.venv/bin/python -m pytest -q --tb=short`.
The environment uses PostgreSQL 16.15, Python 3.12.3, cryptography 50.0.2, SQLAlchemy 2.1.3, and psycopg 3.3.6.
Those cases compare recovered values with native text under actual compiled descriptors.
They cover both frame formats, both record codecs, and both tenant codecs, including nil UUIDs and bigint endpoints.
Eight frozen CF1 vectors use a separate RFC 8452 reference with OpenSSL AES blocks and separate HKDF/HMAC code.
Published RFC 8452, RFC 5869, and RFC 4231 vectors check that reference and the installed primitives.
The fixture reproduction command is `.venv/bin/python tests/reference_cf1_vectors.py`.

Attack and failure cases cover byte changes, relocation, wrong roots, retirement, expiry, failed/canceled preparation, and fork.
Local rewrap preserves existing frames. Failure diagnostics exclude supplied secrets and raw provider errors, including during RNG failure.
AI review found and corrected nil-UUID refusal and writable-policy retention of old cache entries.
AI review does not replace independent human security review.

**Limits at slice 2:** SQLAlchemy attachment, query rewriting, database transitions, and deployment rotations remained pending.
The slice 3 checkpoint above records the later bounded attachment evidence.
The local provider cannot recover after process loss. No production provider exists.
SQL NULL substitution and same-context replay remain accepted scope limits.
Remote cancellation, custody, independent recovery, usage bounds, collision assumptions, and independent review remain unqualified.
All seven full release gates remain **UNKNOWN**.

## Slice 1 checkpoint: 2026-10-08

**IMPLEMENTED:** `cryptalis.manifest.compiler.compile_protection` parses field intent, resolves a supplied registry,
and inspects PostgreSQL catalogs. A fresh read-only transaction holds a repeatable schema snapshot.
Unqualified mappings resolve through the original PostgreSQL search path.
The result contains canonical lock bytes, a digest, and semantic changes. Compilation creates no database effects and reads no application values.

**VERIFIED:** `.venv/bin/python -m pytest -q --tb=short` returned **706 passed**, including **58 compiler cases**.
The compiler tests use PostgreSQL **16.15**, Python **3.12.3**, SQLAlchemy **2.1.3**, and psycopg **3.3.6** under the restricted disposable role.
They compare native schema and data before and after planning. They execute proposed additive DDL only in test-owned schemas.
A real INSERT injection fails with SQLSTATE `25006`, including through an AUTOCOMMIT engine.

This compiler admits native text, application-assigned UUID or bigint keys, explicit UUID tenancy or a single-tenant declaration,
and qualified native uniqueness. Storage-only fields need no search review or search collation.
Searchable fields require `pg_catalog.C` equivalence, matching leakage acceptance, and an explicit host review of the value domain.
Small or unknown domains block search. The host declares complete writer coverage and excluded routes. These records remain host assertions.

Known unsafe schemas and inconsistent prior locks raise typed errors.
The lock includes original admitted constraints, additive DDL, immutable context descriptors, and reader requirements.
A tenant change requires resealing. A SQL rename preserves the descriptor.
Missing or changed stable identities cannot silently replace existing identities.
[Architecture](architecture/README.md#implemented-compiler-syntax) owns the exact syntax.

**Slice 1 limits:** this checkpoint did not implement attachment, encryption, a provider, transitions, or runtime query rewriting.
Other ID codecs, protected varchar/custom types, non-UUID tenant columns, protected defaults, unsupported dependencies, and schema translation reject.
A new unique request needs a qualified native source constraint first.
The additive DDL does not qualify CF1 framing or authorize a switch.
External writer exclusion and domain assertions remain unverified. All seven full gates remain **UNKNOWN**.

## Approved scope and build order

[Approved decisions](decisions.md#approved-scope-decisions-2026-10-08) resolve scope-only D items. They do not supply implementation evidence.
Python 3.12+, SQLAlchemy 2.x, psycopg 3 sync/async, PostgreSQL 16 are the selected stack.
SUPPORTED design scope: text storage, equality, IN, and tenant-scoped uniqueness.
Each protected table declares a tenant column or declares itself single-tenant. Primary keys must be application-generated.
Plan rejects serial, identity, and database-default-generated keys, unsupported types, small-domain searchable fields, missing tenancy, and unsupported writers.
All other protected types/operators are UNSUPPORTED BY DESIGN until admission. Internal research helpers remain INTERNAL ONLY.

Implement one slice per run: compiler → crypto/KeyProvider/dev provider → sync/async SQLAlchemy → equality/IN/uniqueness
→ plan/apply/verify → decrypt-back/remove → three rotation operations. Each slice needs real PostgreSQL 16 tests before the next.
Range/order/prefix/text-search work starts only after all seven slices, then [six-gate admission](compatibility.md#capability-admission) and leakage opt-in.
The [build guide](build-guide.md#ordered-build-slices) owns behavior, invariants, tests, failures, and definitions of done.

### Targets and known performance work

SPECIFIED targets: added p95 ≤ 3 ms point/equality, ≤ 8 ms IN-20, and ≤ 2× protected-column-plus-equality-index storage.
VERIFIED, earlier revision: million-row equality p95 6.517 ms versus 0.928 ms native, IN-20 16.148 ms versus 1.093 ms.
Point p95 4.150 ms versus 0.897 ms also misses its added-latency target. These are known performance work, not achieved targets.
A plaintext range/prefix/page query with no protected column cost 127.098 ms p95 versus 23.852 ms, about 5.3× native.
Its cause is UNKNOWN and must be profiled in the SQLAlchemy integration slice.
The million-row and 10,000-row receipts both predate the latest DISTINCT change. Neither establishes current-adapter service cost.
The whole-relation storage ratio does not prove the isolated column/index target.
[Compatibility](compatibility.md#performance-targets-and-recorded-costs) owns exact measurements and accounting.
Write-throughput and pause are the only undecided budget categories (D). No numeric CPU/memory or adoption budget is invented.
Non-budget security decisions and every external/review requirement remain unresolved where stated below.

## Final gap audit: 2026-10-08

All seven full gates remain **UNKNOWN**. This historical gap record retains named local observations at their recorded scope.
The [audit supplement](../spikes/revamp/results/gate-gap-audit.json) records the latest delta without replacing any previous receipt.

One concrete local correctness gap existed: `SELECT DISTINCT` could compare randomized protected payloads instead of logical values.
The isolated spike now rejects protected SELECT DISTINCT and DISTINCT ON shapes, including nested selects and ORM entities.
The [offline admission probe](../spikes/revamp/run_gate_grammar.py) passes 13 checks. It preserves the scoped COUNT DISTINCT rewrite.
Its inert connection proves expression admission only. It bypasses the planner, provider, driver and PostgreSQL.
Complete grammar, actual database results and service regression of this latest change remain unqualified.

The [primitive vector probe](../spikes/revamp/run_crypto_vectors.py) passes nine checks against three published
[RFC 8452 Appendix C.2 vectors](https://www.rfc-editor.org/rfc/rfc8452.html#appendix-C.2).
It checks AES-256-GCM-SIV encryption, decryption and changed-tag rejection with cryptography 50.0.2.
These independent expected bytes qualify only those primitive cases. They do not freeze or qualify the CF1 composition.

The original [final verification receipt](../spikes/revamp/results/gate-final-verification.json) remains unchanged.
Its implementation-match assertions describe its recorded adapter revision, not the latest DISTINCT admission change.
The seven completed service probes, 35-check child and million-row measurements remain evidence for their recorded revisions.
That audit session recorded no database URL and did not repeat service probes or substitute another database.
The latest spike adapter needs focused real-service retrofit/boundary/async regression before a current-service claim.
The CF1 format, crypto path, transition code and indexes did not change. Their prior observations retain their recorded scope.
Neither prior costs nor these new offline checks measure the latest adapter's service performance.

### Missing evidence and promotion criteria

Classifications: **L** = locally obtainable now. **E** = external infrastructure, provider or deployment.
**H** = independent human/security review. **D** = explicit product/security decision or approved budget.
A local implementation task is not an external guarantee. Unimplemented contracts remain gaps even when their development needs no cloud service.
No promotion occurs until every applicable criterion passes for an identified release artifact and compatibility cell.

| Full gate | Exact missing evidence and classification | Required evidence before PASS |
|---|---|---|
| G-ADAPTER | SPECIFIED: stack, text/ID mapping scope and admitted grammar decisions resolve scope D. L: Implement that scope and plan-time refusals. E: Non-owning runtime credentials, external writer exclusion, exact selected cell and latest DISTINCT service regression | Use separate migration/runtime principals. Positive CRUD controls with application-assigned IDs must work. Plan must reject serial, identity and database-default-generated IDs before effects. Runtime DDL, lifecycle metadata mutation, schema ownership and privilege escalation must fail. Inventory every writer credential/route. Prove excluded writers cannot reconnect or write during maintenance. Compare native/protected results, types, ORM state and async behavior for every admitted shape. Reject other shapes before SQL. Run the latest code on the exact OS/interpreter/SQLAlchemy/driver/PostgreSQL cell. The selected PostgreSQL 16 cell and each managed service need their own suite. Other majors remain UNSUPPORTED BY DESIGN until admission |
| G-CRYPTO | L: Primitive vectors now pass. D/H: Freeze admitted text/ID descriptors and nonce/aggregate usage limits. L after those decisions: Full independent CF1/KDF/HMAC/companion vectors. D/E: Fork invalidation and fresh preparation under the selected provider. H: Composition review | Publish expected intermediate and final bytes from an independent reference for every admitted codec/format. Check malformed bounds, context relocation, exact-key resolution and companion changes. Implement fork invalidation and test a child cannot use inherited material before fresh preparation. A reviewer must approve nonce/key lifetime limits, collision assumptions and cross-key behavior. Resolve material review findings. Primitive vectors and same-library roundtrips cannot satisfy this gate alone |
| G-QUERY | SPECIFIED: text/equality/IN/tenant-uniqueness scope and read/storage targets resolve scope/budget D. D: Write-throughput budget. E: Exact PostgreSQL 16/service semantics. L: Admitted integration, leakage attacks, target measurements and anomaly profiling. Advanced evidence applies only after admission | Compare all admitted predicates, NULLs, constraints, joins, projections and pagination with native PostgreSQL. Exercise restricted-role built-in DDL and selective million-row plans. Run published attacks for each admitted advanced representation with dataset and attacker assumptions. Measure per-capability table/index/temporary storage, sustained writes and GIN maintenance where applicable. Meet the approved added-p95 read and isolated column/index storage targets. Measure throughput, CPU and memory. Write-throughput remains D, without an invented threshold. Profile the unexplained plaintext-page overhead on the current revision. Plaintext age/name queries and physical arrays cannot qualify encrypted advanced fields |
| G-LIFECYCLE | E: Deployment-wide exclusion, durable independent recovery, retained readers/keys, actual disk/WAL faults and external provider transforms. D: Upgrade compatibility and pause budget. SPECIFIED: storage target resolves storage-budget D. L after implementing a versioned reader contract: Upgrade/rollback and pre-switch abort | Kill an executor and resume in an independently started process with no inherited keys or attachment. Restore a real retained backup using immutable reader/lock/wrapper artifacts and the designated provider. Compare full current membership, values, types and constraints. Upgrade mixed old/new formats under stopped writers. Inject failures before and after database/artifact switch. Transform current edits back without snapshot loss. Unsupported old types or missing keys must block rollback. Induce real bounded disk/WAL exhaustion, temp-space failure, memory/CPU pressure and timeouts on a disposable isolated target. Prove no switch, atomic failed chunks, retained completed chunks and inspected resume. Test provider rewrap/rotation and backup dependencies before retirement. Package-free removal must preserve current data and retained obligations |
| G-PROVIDER | D: Select provider, key topology and cache policy. E: Real workload identity, custody, remote cancellation, recovery and deletion. H: Identity/cache/destruction review | Exercise exact wrap/unwrap/rewrap context and wrong provider/key/workload identities. Test cold, warm, expired, disabled, outage and canceled remote calls. Discard late material and inspect ambiguous native effects before retry. Recover roots in an independent process. Observe native deletion completion, cached-use limits and every retained wrapper/backup recovery route. A deletion request or local random KEK is insufficient |
| G-POLICY | D: Select the trusted host publication/restore procedure. E: Authenticated policy startup, target binding, stale workers and quarantine | Use the real authenticated deployment artifact outside database restore. Interrupt both database/artifact switch boundaries. Keep writers stopped and deny mismatches until inspection completes publication. Reject wrong targets, old artifacts and restored old policy. Prove old workers and alternate credentials cannot resume writes. Restore in quarantine with current host authorization, then admit only a fully matched representation. The local attachment's immediate installation does not enforce this host procedure |
| G-RELEASE | SPECIFIED: approved release scope and read/storage targets resolve those D items. D: Write-throughput and pause budgets. H: Independent human reviews with resolved findings. E: Controlled release identity, build and publication. L after the runtime artifact exists: Locked hashes, SBOM and artifact inspection | Satisfy all applicable gates and the engineering release gate. Supply named review reports, material-findings resolutions and accepted residual risks. Compare the same backend in hot/cold/outage and lifecycle workloads against approved budgets. Count actual model, business-query, writer, deployment and operator changes. Inspect the exact wheel/sdist, dependencies, hashes, SBOM and provenance. Test old-reader compatibility and critical-flaw recovery. Verify controlled publication identity and security-response ownership. Existing research-package artifacts do not qualify an unbuilt runtime |

### Adversarial consistency findings

The recorded audit compared the isolated implementation, its then-current probes, gate definitions, status, security, compatibility, lifecycle and final receipts.
The latest SELECT DISTINCT rejection corrects a fail-open grammar case. Earlier references to rejected grammar cover only their listed cases.
Scoped COUNT DISTINCT evidence never established general SELECT DISTINCT or GROUP BY support.

The lifecycle checkpoint's source-constraint observation covers inspected source index definitions, validity/readiness and the fixture's scoped uniqueness.
It is not generic CHECK/FK/default/collation or dependency preservation. The executor has no format-upgrade or pre-switch abort path.
Its writer inventory is a caller assertion. Advisory and chunk/table locks cannot exclude unrelated credentials between chunks.
`retained_local_backup_reader_route` decodes an in-memory row copy with the same live provider. It proves neither backup durability nor independent recovery.
Fork-inherited restart retains authority. The package-free child proves plaintext exit, not encrypted backup recovery.
Injected division-by-zero and local-provider failures do not establish storage-exhaustion or resource-pressure behavior.

Public CLI remedies, authenticated startup/publication, production custody and artifact provenance remain intended contracts.
Local database switching remains `SWITCHED_DATABASE_POLICY_PENDING`. It is not production activation.
No new public configuration, provider identity, deployment service or security guarantee results from this audit.
This documentation-only pass authorizes no runtime changes. The unimplemented and external criteria remain explicit blockers.
The seven criterion rows remain seven UNKNOWN rows. Rows with unresolved D criteria change from seven to six because G-ADAPTER scope is resolved.
The remaining D items are non-budget security/authority decisions and the two undecided budget categories, not reopened scope decisions.

## Current integrated checkpoint: 2026-10-07

**VERIFIED, recorded 2026-10-07 spike revision:** this checkpoint supersedes older observations only for its listed cases.
The implementation remains isolated under `spikes/revamp`; the public package is unchanged.
All seven full gates remain **UNKNOWN**. No production compatibility cell is qualified.

The spike attachment protects one declared `Customer.email` field in the original three-model application.
Its original 29 assertions remain unchanged. Adoption uses one manifest and attachment, zero model/query edits,
and one opaque SQL writer changed to an equivalent typed Core update. Age/name range, prefix and ordering queries
remain ordinary plaintext queries. This is not encrypted advanced-query evidence.

| Final service command under `spikes/revamp/` | Observed checks | Scope |
|---|---:|---|
| `run_gate_retrofit.py` | 51 | Original application, historical generated int32 identities (outside approved scope), native values/state, bulk and guarded raw/COPY rejection |
| `run_gate_boundary.py` | 25 | Bound/reverse predicates, NULL/membership, aliases, scoped DISTINCT, tenant moves, concurrent sequence/uniqueness and rejected grammar |
| `run_gate_async.py` | 14 | Native AsyncSession, generated relationships/bulk, streaming, task isolation, real driver cancellation/recovery and guarded raw paths |
| `run_gate_context.py` | 48 | Host-requested point, typed context, malformed frames, inventory/schema mismatch, unsupported multi-field plans and local cache/outage/generation failures |
| `run_gate_lifecycle.py` | 23 | 1,000 rows; interrupted/resumed chunks, real lost COMMIT reply, verification mutants, rotations, current-data rollback and removal |
| `run_gate_faults.py` | 13 | Real SQL failure, injected local-provider failure, atomic marker/data rollback and expression/admission-spoof rejection |
| `run_gate_write_cost.py` | 2 | Earlier adapter revision before latest DISTINCT change; identical paired workloads and committed 400-row update readback on 10,000 rows |
| `run_gate_performance.py` | 3 | One million actual CF1 rows, exact results/NULL membership, selective equality index and paired application costs |

The million-row receipt was reused after assignment-admission fixes because the CF1 representation and index expression did not change.
The smaller cost run measures that changed adapter before the latest DISTINCT fix. Both remain earlier-revision evidence. The lifecycle fresh child also passes 35 checks:
all 29 original assertions, four blocked crypto/package imports, full current-data/type comparison and an ordinary committed edit.
Every final service suite removes only its owned schema. Sanitized receipts are linked from the [experiment guide](../spikes/revamp/README.md).
The recorded **612-passing-test** result and historical document/link/inventory checks are retained evidence, not repeated here.

| Full gate | Verdict | Exact remaining reason |
|---|---|---|
| G-ADAPTER | UNKNOWN | Non-owning runtime principal and external writer exclusion are unqualified; approved app-assigned-ID/text/tenant mappings, complete admitted grammar, plan refusals and selected cell remain pending |
| G-CRYPTO | UNKNOWN | Frozen independent admitted text/ID vectors, nonce/usage/fork bounds and independent human composition review remain pending |
| G-QUERY | UNKNOWN | Complete admitted PostgreSQL 16 semantics, leakage evidence, read/storage target measurements and anomaly profiling remain pending. Write-throughput remains D; advanced queries remain out of scope until admission |
| G-LIFECYCLE | UNKNOWN | Real deployment writer exclusion, independent fresh-process recovery/backup reader provenance, format upgrades, storage exhaustion and external provider transformations remain pending |
| G-PROVIDER | UNKNOWN | The user has selected no production provider. Memory-only local functional evidence cannot qualify custody, native deletion or remote cancellation |
| G-POLICY | UNKNOWN | The user has selected no deployment procedure. Authenticated publication/startup pin, stale workers, restore quarantine and restored-old-policy denial have no executable host evidence |
| G-RELEASE | UNKNOWN | Independent human review is unavailable (`external-review-required`); write-throughput/pause budgets and locked artifact/provenance qualification remain pending |

`cryptalis_runtime` is absent. The migration login is restricted but owns these fixtures; it cannot prove non-owning runtime enforcement.
An independent privileged driver can still bypass attachment. Unknown or unexcluded writers now block the local plan before transformation.
The database transition reports `SWITCHED_DATABASE_POLICY_PENDING`; it does not invent an authenticated external publication.
The memory-only keyring cannot recover after independent process/provider loss. Fork-inherited lab recovery does not prove that route.
The spike tests a 16 MiB UTF-8 bound, narrower than unbounded PostgreSQL varchar. It does not freeze the product text bound.
Its sequence-generated IDs conflict with the approved application-generated-key contract. Refusal of those schemas remains an implementation gap.
Unknown collation/default/constraint semantics must reject rather than silently change results.
Same-context replay, nullable-field substitution with SQL NULL and hostile omitted rows remain the explicit [security limits](security.md).

## Existing package

The current package has the product compiler, CF1 primitives, and bounded SQLAlchemy attachment above, structural record decoding/canonicalization, bounded manifest/header inspection,
local crypto/search examples, and local transition-admission research.
The slice 3/4 attachment supplies stated storage and search behavior only within the tested boundaries above.
These APIs do not qualify managed key custody, safe deployment admission, or production lifecycle.
Architecture drives replacement. Existing research formats and tests are not permanent runtime requirements.

The existing suite returned **612 passed in 7.95 s**, exit 0, after canonical documentation replacement.
No production source, test, fixture, dependency, build, container, or CI file changed in this revamp pass.
The starting dirty AGENTS/playbook edits and deleted files remain preserved.
The service continuation reran `.venv/bin/python -m pytest -q`: **612 passed in 15.59 s**, exit 0.

## New isolated evidence

**VERIFIED, historical research only:** earlier SQLite/public-hook experiments, single-user PostgreSQL physical probes,
CF1 text fixtures, restricted-service probes, synthetic frequency attacks, and current-data decrypt-back supplied narrow observations.
Their raw receipts and exact counts remain in [spikes](../spikes/revamp/README.md) and [archived provenance](research/revamp-evidence.md).
All these mechanisms are INTERNAL ONLY. Non-text algorithms, encrypted range/prefix arrays, shared joins, and generated-ID candidates do not change approved scope.
The 2026-10-07 integrated checkpoint above supersedes only the specific earlier limitations for which it records new evidence.

Historical surrogate bundle storage was about 5.5× its control. That bundle includes different representations/indexes and does not measure the selected equality column target.
Frequency attacks recovered 100% of synthetic equality/prefix classes and rows, and 27.211% of range rows under the recorded auxiliary-distribution assumptions.
These rates do not predict customer recovery. Structural/order attacks remain unexecuted and required for their applicable advanced admission.
Local rewrap/policy models do not qualify mature-provider custody, authenticated host publication, independent recovery, or deletion.
Raw-driver negative controls demonstrate that separate privileged writers can bypass attachment. Full writer exclusion remains UNKNOWN.

## Blocking evidence

Slices 1–5 have bounded product evidence for app-assigned-key planning, storage/search admission and protection transitions.
Earlier receipts omit grouped and callable primary-key binds; their row-isolation claims do not cover those forms.
The [corrective checkpoint](#corrective-audit-checkpoint-2026-10-09) records their repair. No runtime release is qualified.

Full independent recovery, deployment writer exclusion, retained-backup readers, format upgrades,
real resource-exhaustion faults, production provider custody, authenticated policy publication/restore, and independent review remain required.
[Gate criteria](#missing-evidence-and-promotion-criteria) state the deciding observations without restoring the deleted control plane.
No production provider is designated. The local provider is functional evidence only.
G-PROVIDER, G-POLICY, all review requirements, and the [release gate](../ENGINEERING_PLAYBOOK.md#release-gate) remain UNKNOWN.
