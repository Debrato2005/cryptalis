# Performance checkpoint: 2026-10-09

Evidence and proposals, not a replacement for [decisions](../decisions.md) or [lifecycle](../lifecycle.md).
The user approved one membership-scan correction before Slice 6. No online or parallel protocol is approved or implemented.
Local HEAD and GitHub `main` contain `7edd164`; the fetched migration blob matches local Git blob `5130d3c`.
That commit already fixes shared-schema guards and descriptor reuse. They were not reimplemented.
Cryptalis remains a research prototype. All seven gates remain UNKNOWN.

## Findings and measured change

The maintenance engine hashes ordered row/tenant identities in `_scope`, but its old `_stream` projection also fetched protected text.
This caused avoidable transfer, decoding and allocations during expansion's ACCESS EXCLUSIVE lock and verification's EXCLUSIVE lock.
The correction selects identities for membership only. Backfill and full source/frame authentication retain their original projections.
Cursor codecs, digest bytes, journal meaning, transaction boundaries, key checks, locks and public arguments are unchanged.

Native PostgreSQL column grants deny source reads while allowing identity reads. Committed code fails four such cases; corrected code passes.
Independent canonical hashing checks UUID/bigint boundaries, both tenancy forms, nil IDs, multiple fields/tenants and more than one scan page.
An end-to-end journal comparison and independent CF1 decoder check all 1,007 values, including NULL, empty and Unicode.
[Regression evidence](../_reset/membership-regressions-31ac368e2bbf3bd3.json) removes projection restriction, tenant binding and continued pagination in isolated copies: each fails; restoration passes.
[Twenty existing removals](../_reset/slice5-regressions-audit-d6a6b23daa40d329.json) still detect authentication, value/membership, fence, atomic commit, recovery, generation and publication failures.
[Full suite](../_reset/audit-verification-31ac368e2bbf3bd3.json): 1,009 passed in 102.12 s; revision `worktree-31ac368e2bbf3bd3`.

Five alternating scans per engine use the same connection, table and independent membership oracle:

| 5,000 rows, two protected fields, three tenants | Committed engine | Corrected engine |
|---|---:|---:|
| Median scan, 32 bytes/field | 32.54 ms | 30.33 ms |
| Median scan, 32 KiB/field | 302.48 ms | 16.92 ms |
| Wide scan, separate-process traced Python peak | 131,838,126 B | 591,129 B |
| Wide scan, separate-process peak RSS | 286.7 MiB | 98.4 MiB |

[Short paired receipt](../_reset/membership-paired-32-a81d3cf873c3edd8.json), [wide paired receipt](../_reset/membership-paired-32768-a81d3cf873c3edd8.json).
Separate-process memory controls: [before](../_reset/membership-profile-32768-a94d3d18190b80fb.json), [after](../_reset/membership-profile-32768-a81d3cf873c3edd8.json).
The wide table has 327,680,000 source bytes. Membership now transfers none of those value bytes.
RSS includes setup/native allocations; tracemalloc excludes libpq. Paired-process RSS includes both engines and cannot isolate memory gains.
Warm scans and compressible MD5-repeat data do not represent every workload. Native EXPLAIN/BUFFERS/WAL plans are retained.
Two initial profile setup attempts failed before measurement: an unsupported fixture index, then an unescaped psycopg `%` operator.
The fixture was corrected; neither failed attempt is passing evidence.

| Matched 30,000-row protection workload | Before | After |
|---|---:|---:|
| Expansion / maximum observed reader latency | 0.243 / 0.224 s | 0.138 / 0.113 s |
| Backfill / rows per second | 2.057 s / 14,584 | 1.591 s / 18,862 |
| Backfill main CPU / descriptor CPU | 1.067 / 0.000835 s | 0.963 / 0.001120 s |
| Verification / verification-and-switch | 1.360 / 1.380 s | 1.019 / 1.037 s |
| Total observed writer pause | 3.741 s | 2.813 s |
| Backfill SQL wall / commit wall | 1.154 / 0.095 s | 0.833 / 0.067 s |
| Cluster-wide backfill WAL | 23,069,960 B | 23,069,896 B |
| Peak process RSS | 98.41 MiB | 98.35 MiB |

[Before](../_reset/step-a-baseline-small-30000-a94d3d18190b80fb.json), [after](../_reset/step-a-optimized-small-30000-a81d3cf873c3edd8.json).
Backfill code is unchanged; its faster SQL/sealing shows uncontrolled cache/scheduling effects. The whole-pause difference is an observation, not a causal improvement claim.
Verification membership itself was slower in this pair (0.135→0.145 s). Short-value gains are modest and variable.
Both runs exposed 20 CPUs, 7.47 GiB RAM, 2 GiB swap, no WSL overrides or cgroup limits; starting load was 0.245/0.313/0.346 versus 0.208/0.262/0.316 and available memory about 3.28 GiB.
The programs-closed confirmation is historical; it was not independently renewed. No new million-row run was needed to prove projection/resource behavior.
Planning, drain, real publication, worker restart/admission, server wait seconds and per-index physical writes remain unmeasured here.

The [clock control](../_reset/performance-clock-control-7edd164.json) found raw/CPU elapsed about 4.8% above CLOCK_MONOTONIC in five current samples.
Linux distinguishes frequency-adjusted monotonic time from unadjusted raw time ([clock documentation](https://man7.org/linux/man-pages/man2/clock_gettime.2.html)).
The adjustment cause and historical rates are UNKNOWN. Future controlled timing must record both clocks; wall minus CPU is not isolated database wait.
This does not establish the cause of old 508.7/197.0 s variation or explain all changes in this pair.

## Ranked opportunities

The latest million-row result remains historical: 67.804 s backfill, 42.214 s verification, 116.291 s pause, 6.106 s expansion reader wait.
Its two membership passes took 10.279 s combined. Even eliminating them entirely would save only 8.8% of that pause; identity hashing remains necessary.
This patch cannot establish near-zero downtime. Native writer fencing and full verification remain mandatory.

| Priority / technique | Evidence, simplest next experiment, risk and disposition |
|---|---|
| 1: Byte-bounded value reads and parameter buffers | Backfill fetches a whole row-count chunk and builds every ciphertext parameter; verification fetches source and payload pages. The wide scan exposes actual allocation growth. Design a bounded prefix plus oversized-row path; measure full-process RSS before changing admission. Research only here |
| 2: Framing and operation-local derivation work | Current short-value CPU probe makes six `tuple_bytes` and two `_derive` calls per seal/open. Profile invariant encodings and derived search keys; require frozen wire vectors and expiry/fork/context mutants. Do not cache row keys globally |
| 3: Index build after backfill | The expression index exists during every payload UPDATE, which changes an indexed column and prevents HOT eligibility. Compare total pause/WAL/index size with post-backfill ordinary construction. Moving the verified schema/index checkpoint needs design review; no change here |
| 4: Adapter allocation/admission | Historical matched point/equality/IN satisfy local targets; full entities still cost decoding/materialization and plaintext pages reflect heap/planner costs. Profile operation-local traversal/projections before structural caching. Preserve native ORM behavior and current refusal grammar |
| 5: Batching/driver SQL | Existing executemany uses psycopg pipeline mode; another wrapper is redundant. Profile metadata calls and prepared UPDATE execution at realistic network latency. Larger batches increase memory, expiry and retry cost |
| 6: Threaded/async/process scaling | Python 3.12 GIL constrains Python work; async overlaps waits, not serial framing. No demonstrated migration worker speedup. Processes require fresh providers/connections, disjoint durable coverage and a global budget; inherited keys explicitly fail. Defer 1/2/4-worker experiments until a reviewed assignment protocol |
| Architectural: online backfill plus incremental verification | Highest availability potential, largest proof burden. Proposal below; current maintenance fallback stays available |

[Current CPU probe](../_reset/performance-crypto-cost-a81d3cf873c3edd8.json): 10,000 53-byte values sealed in 0.188 s and opened in 0.163 s; 1,000 32-KiB values took 0.096/0.082 s.
Under cProfile, derivation took 0.197/0.200 s cumulatively within 0.561/0.567 s short-value seal/open; framing overlaps those calls and must not be added to them.
For wide values, native AEAD accounted for about 0.051 s within 0.122 s profiled seal/open. These are current warm local costs, not improved cryptography or provider qualification.
Retain [the native AESGCMSIV backend](https://github.com/pyca/cryptography/blob/50.0.2/src/rust/src/backend/aead.rs); no custom cipher, nonce strategy or changed CF1 composition is warranted.
[Python threading](https://docs.python.org/3.12/library/threading.html) and [multiprocessing](https://docs.python.org/3.12/library/multiprocessing.html) explain concurrency mechanisms, not measured Cryptalis scaling.

Psycopg already pipelines executemany since 3.1 ([driver documentation](https://www.psycopg.org/psycopg3/docs/advanced/pipeline.html)).
HOT requires unchanged indexed columns and page space ([PostgreSQL 16](https://www.postgresql.org/docs/16/storage-hot.html)); deferring one index does not guarantee HOT or remove existing heap/index bloat.
Concurrent index construction requires extra scans/waits, cannot run in the expansion transaction, and can leave an invalid index enforcing uniqueness ([PostgreSQL 16](https://www.postgresql.org/docs/16/sql-createindex.html)). It is not a drop-in maintenance optimization.
Protected `_ReadText` processors retain keys, tenant and expected points. SQLAlchemy caches type processors with compiled statements ([2.1 custom types](https://docs.sqlalchemy.org/en/21/core/custom_types.html)); global `cache_ok=True` would revive the proved isolation defect.
Native plaintext caching, public pooling and async preparation already exist. Pooling reduces reconnect cost, not encryption CPU; selective plaintext projections avoid unnecessary decrypt work but must preserve application query results.
Do not introduce a plaintext/result cache, unbounded tenant preload, larger provider key age or persisted roots.
Any future cache must bind validated descriptor/lock identity or exact provider/wrapper/domain/tenant/purpose/generation, have bounded entries, and die with the operation/expiry/fork or failed preparation. Row/authorization context remains operation-local.
[CipherStash benchmark source](https://github.com/cipherstash/benches) separates query-only costs from decryption; its PostgreSQL 17/Rust/custom EQL results are not comparable qualification for this Python/PostgreSQL 16 end-to-end workload.

## Byte-budget proposal: not implemented

Measure a row reservation that includes every protected field, Python strings/rows, source libpq buffers, UTF-8 temporaries, CF1 frames, parameter tuples, pipeline buffers and temporary AEAD output.
Unicode Python storage can exceed encoded length. Row-count limits alone do not bound any of these aggregate bytes; fetching before checking a budget is too late.
Screen identity plus native `octet_length` metadata before fetching large fields; choose an ordered prefix under both row and byte budgets. Validate actual lengths after fetch.
Bound driver submission/synchronization too: an iterator of parameters alone does not bound libpq's queued buffers.
Account for the overlap of successive pages, which currently coexist while the next fetch completes. Measure RSS and traced allocations separately.
Preserve 16 MiB per-field admission. A row larger than the preferred batch budget must use a bounded field-at-a-time path in the same transaction, or require an explicit compatibility decision; it must not silently become an invalid previously valid row.
No partial field update may escape a committed complete-row/chunk marker. Do not retain plaintext/spill files or weaken final verification.
Reserve one global budget across future workers, their connections, prepared keys and in-flight native buffers; test slow providers, wide Unicode/skewed rows, cancellation and allocation failure.
Start with fixed conservative internal reservations and measured native overhead. Adaptive sizes need evidence; no new public tuning concepts are proposed now.

## Future online protocol: proposal requiring approval

Prefer a transactional dirty-identity queue plus asynchronous transform and independent incremental verification.
Install capture under a short drain/DDL lock before the base scan. PostgreSQL triggers record affected OLD/NEW identities and a fresh non-reused mutation token in the same transaction as each source change.
Capture identity/token only; do not send keys into PostgreSQL or copy plaintext into an audit log. The old column stays authoritative until cutover.
All mutations, including target/helper updates, must invalidate verification. Initial range completion and subsequent dirty work are separate durable evidence.
Backfill never trusts cursor coverage for concurrent inserts: identities inserted behind the cursor still enter the dirty queue.
Workers transform the current locked source. A separate verifier checks current membership, exact values/types/NULL, authenticated context/generations, terms and target constraints.
Data updates, dirty-token reconciliation and progress commit together. Clearing work must compare the exact token; delete/reinsert cannot reuse a numeric counter and cause an ABA skip.
Source-row and queue-lock ordering must be specified and race-tested. An absent row needs conditional token handling: there is no row lock on a nonexistent primary key.
Reject or explicitly capture both sides of identity/tenant changes. Do not order commits by sequence allocation, trigger timestamps or row IDs.

The required invariant is: every initial range is independently covered, and every subsequently committed mutation is either independently verified for its current source/target token or still has durable dirty work.
There must be no unchecked interval between capture installation, base coverage, dirty verification and the final writer fence.
Under the final fence, drain in-flight writers, reconcile all remaining dirty tokens, validate complete range coverage and valid indexes, then switch atomically.
Replacing the full stopped-table scan with this invariant is a security-contract change, not an optimization flag. A queue count or a saved VERIFIED marker cannot supply the proof.
Unknown COMMIT outcomes require inspection after the original transaction is terminal. Restore cannot make journal/coverage state current authority; compare the external pin and quarantine stale snapshots.
Database cutover and external publication remain separate. Workers stay stopped until exact publication and fresh startup admission; slow publication still defeats near-zero total unavailability.

Exact approval deltas: allow source writes during expand/backfill/verification; replace the full final scan with reviewed coverage evidence; add capture/coverage journal state and its restore/crash semantics; admit maintained trigger objects and independently verified index-building checkpoints.
Keep authenticated format, generation/key lifetime, exact query semantics, native uniqueness, alternate-writer exclusion, trusted operator/primary and external policy authority unchanged.
Plaintext remains in the live source, heap, WAL and backups throughout online expansion; this extends exposure time. Queue metadata leaks changed identities/timing and adds WAL, storage and writer latency.
Uniqueness must remain native throughout. Original plaintext constraints stay active; target unique-index readiness and matched collation must be proved before cutover. Do not admit an OR across partially covered generations.
Catch-up may never finish if mutation rate exceeds transform/verify capacity. Disk/WAL exhaustion, long transactions, deadlocks, provider outage or publication failure may force a long pause or maintenance fallback.
Neither a byte budget nor multiple workers establishes a bound on that pause.

[pg-osc source](https://github.com/shayonj/pg-osc/blob/main/lib/pg_online_schema_change/replay.rb) supplies a shadow/capture/replay lesson, but sequence-ordered event replay and its final swap do not prove this cryptographic invariant.
[pgroll source](https://github.com/xataio/pgroll/blob/main/pkg/backfill/backfill.go) uses triggers and bounded backfill with schema versions; its SQL transforms cannot seal application-owned keys and its versioning adds integration obligations.
CDC has a clean snapshot/commit-stream boundary, but needs replication privileges/configuration, duplicate-LSN reconciliation and retained WAL. Those exceed the present ordinary-owner deployment ([PostgreSQL 16 logical decoding](https://www.postgresql.org/docs/16/logicaldecoding-explanation.html)).
Transactional dual writes would require every admitted writer to change before expansion; missed/stale writers still need capture and coverage. It was not selected or implemented.

Decisive future experiment: a small adversarial PostgreSQL model before scaling; then native-matched one-million-row text/tenant workloads with NULL/empty/Unicode, wide skew and hot keys at increasing mutation rates.
Force inserts behind cursors, out-of-order commits, updates after encryption/verification, deletes/reinserts, tenant/identity moves, concurrent uniqueness and unknown COMMIT replies.
Kill every phase, alter target frames after verification, disable capture, lose an index build/provider/publication, restore an older snapshot and saturate the queue. Every removed safety mechanism must fail its independent oracle.
Record p50/p95/p99 writer/read latency, dirty backlog age/bytes, CPU/RSS, table/index/temp size, WAL/replication lag, recovery time and the entire drain-to-admission interval.
Only after correctness and bounded resources pass should disjoint 1/2/4-worker experiments compare benefit with custody/recovery complexity.
No implementation of this proposal is authorized by approval of the membership correction. Next product slice remains Slice 6.
