# Historical technical observations

These observations retain their original revision and limitations.
Use [status](../status.md) for current evidence and the [documentation map](../README.md)
for current contracts. Old pending statements do not describe the current release.

## Current local enforcement evidence: 2026-10-07

**VERIFIED, recorded spike revision:** the [integrated checkpoint](implementation-2026-10.md#current-integrated-checkpoint-2026-10-07) guards inspected SQLAlchemy executions at the DBAPI method boundary.
Its raw/COPY/protocol-handle denials occur before driver execution; an independent privileged connection remains outside that boundary.
Missing, unknown or unexcluded writer inventory blocks local transformation. The migrator-owned fixture does not qualify a non-owning runtime role.
A hostile returned row that is valid for another identity fails the captured host-requested point check before value release.
The recorded candidate also rejects changed typed field/domain/tenant/record context, descriptor/header mutations, malformed bounds and retired generations without fallback.
Same-context replay, SQL-NULL presence substitution and omitted rows remain the threat limits below.

New development roots and the local wrapping key are random and memory-only; the older experiments retain public lab roots.
Local cold/warm/expired/outage and rewrap tests are functional evidence only.

A Linux test forks while the keyring mutex is locked. The child refuses
inherited sync/async preparation without deadlock. Fresh child keys work.
The parent retains its prepared keys. The
[fork checkpoint](implementation-2026-10.md#keyring-held-mutex-fork-checkpoint-2026-10-23) bounds this evidence.

These controls do not qualify other process/runtime cells, remote-provider
cancellation, native deletion or production custody. No production provider or
deployment procedure is designated.
Independent human cryptographic/security review is unavailable: `external-review-required` remains UNKNOWN.
Frozen independent admitted text/ID vectors, exact collation evidence, and nonce/usage bounds remain required before security qualification.


## Integrated lifecycle checkpoint: 2026-10-07

The preceding 27-check lab is historical. The new [23-check receipt](../../spikes/revamp/results/gate-lifecycle.json)
uses the original three-model application's actual CF1 data and one transition executor for protect, rotate and deprotect.
Chunk members and transformed rows commit together. Resume inspects the original digest/membership and preserves committed ciphertext.
**VERIFIED, recorded spike:** streaming verification checks membership, native values/types/NULLs, and generations before the transactional switch.
It compares inspected source index names/definitions and their validity/readiness flags. Target unique-index construction exercises the fixture's scoped uniqueness.
Generic CHECK/FK/default/collation and dependency preservation remain UNKNOWN. Source-index observations do not prove them.
A competing executor is denied; an actual concurrent writer is observably blocked while the maintenance lock is held.
That observation does not prove deployment-wide writer exclusion between chunks.

The lost-reply test shuts down the receive side of the original connected socket before COMMIT completes.
It observes EOF and an initially absent marker, then independently observes the original transaction terminal and a matching committed marker.
It never consumes the COMMIT reply through libpq. Resume preserves the committed bytes.
The separate [fault receipt](../../spikes/revamp/results/gate-faults.json) proves that real SQL errors and injected local-provider failures
roll back both staged chunk data and its marker. Actual disk/WAL exhaustion remains pending.

Payload rotation, search rotation and local rewrap are separate tested actions. Current post-cutover application edits survive rollback,
reprotection and deprotect with all original columns and types compared. Eligible shadows, indexes, trigger and journal are removed.
A fresh process blocks Cryptalis/crypto readers, verifies all current data, commits an ordinary edit, then runs the untouched 29-assertion original oracle.
Only its owned synthetic rows are cleared between the current-data proof and the oracle's empty-database fixture.

The database phase remains `SWITCHED_DATABASE_POLICY_PENDING`. Authenticated host publication/startup, restored-old-policy denial,
stale-worker termination, durable independent-process readers/keys, format/codec upgrade and native provider deletion remain UNKNOWN.
The local backup decode and fork-inherited interruption test do not qualify retained-backup custody or a fresh independent provider restart.
The [million-row protection receipt](../../spikes/revamp/results/gate-performance.json) measures initial protection; it does not qualify
million-row rotation/deprotect, a production pause ceiling or a storage-exhaustion response.
These pending requirements keep the complete lifecycle gate UNKNOWN.


### Slice 3 local profile: 2026-10-08

**VERIFIED, bounded package adapter:** `.venv/bin/python tests/profile_sqlalchemy_adapter.py`.
The [hashed receipt](../_reset/slice3-performance.json) records 5,000 synthetic rows, 100-row pages, and 40 paired samples.
The local cell uses Python 3.12.3, SQLAlchemy 2.1.3, psycopg 3.3.6, cryptography 50.0.2, PostgreSQL 16.15, and warm local keys.
Both paths use identical data and application-generated UUIDs. Queries consume and compare native values and types.
Protected fixtures are seeded through ordinary attached ORM writes. Empty fixture conversion to `bytea` is test setup, not product apply.
The final main-thread run followed the full suite and cache proof, with no concurrent Cryptalis checks.
Shared-host activity remains uncontrolled. The receipt retains earlier runs and their limits.

| Current bounded workload | Native p50/p95 ms | Attached p50/p95 ms | Added p95 ms |
|---|---:|---:|---:|
| Point entity | 0.435 / 0.618 | 1.715 / 2.903 | 2.285 |
| Unprotected range/prefix/page projection | 1.428 / 1.906 | 2.238 / 2.810 | 0.904 |

The point result is within the 3 ms added-p95 target in this local run. It does not qualify the deployment target.
Earlier runs vary with shared-host activity and code changes. The receipt retains those observations without deployment qualification.
Both plaintext page paths recorded 60 compilation-cache hits and one miss.
Protected entity statements disable compilation caching to prevent retention of another operation's tenant, point, or prepared keys.
Native unprotected compilation caching remains enabled.

Ten extra cProfile page queries separate exclusive Python time into categories.
Attached admission/guard cost 0.285 ms/query, compilation/cache 0.017 ms, driver/database 1.956 ms,
and decoding/materialization 0.065 ms. Native compilation/cache cost 0.015 ms, driver/database 1.590 ms,
and decoding/materialization 0.048 ms. Dispatch, key preparation, and other ORM/engine work remain separate in the receipt.
Profiling changes timings. Cumulative calls overlap; exclusive categories do not.
Driver time combines network wait and PostgreSQL work; those parts are not independently separated.
This small plaintext profile does not explain the historical million-row anomaly. Its cause remains **UNKNOWN**.
No equality/IN, isolated storage/index, sustained-write, remote-provider, or async performance qualification was performed.
Adoption in this fixture used one manifest, one attach call, authenticated tenant scope, and application-assigned IDs.
No business-query or model declarations changed between native and attached paths.
The later runtime checkpoint verifies separate credentials and fixture grants; deployment enforcement remains unverified.

### Slice 4 local million-row profile: 2026-10-08

**VERIFIED, local warm synchronous cell only:** the [receipt](../_reset/slice4-performance.json) binds the final source hashes to 1,000,000 rows per path.
Both native and attached applications use the restricted runtime login, application UUIDs, identical 53-byte synthetic text and fully consumed results.
Owner credentials perform only fixture setup, ANALYZE, storage inspection and independent plan inspection. No extension is required.
Each workload has 10 warmups and 100 alternating paired samples. Entity samples expunge the identity map and materialize fresh objects.
Added p95 means attached p95 minus native p95; the receipt also records paired median differences and p99 estimates.

| Current workload | Native p50/p95 ms | Attached p50/p95 ms | Added p95 ms |
|---|---:|---:|---:|
| Point entity | 0.476 / 0.790 | 2.245 / 3.126 | 2.336 |
| Equality entity | 0.383 / 0.821 | 2.255 / 3.382 | 2.561 |
| IN-20 entities | 1.116 / 1.543 | 3.300 / 4.548 | 3.005 |
| Plain projection, range/prefix, broad OFFSET, 100 rows | 49.050 / 111.791 | 64.975 / 134.355 | 22.564 |
| Protected entities, plaintext range/prefix, five rows | 0.540 / 0.776 | 2.927 / 3.976 | 3.199 |

Point/equality and IN-20 meet their selected added-p95 targets in this run. No target was invented for either page workload.
The isolated protected column plus equality index is **1.4928×** the matched plaintext column plus equality index, below the 2× target.
The plaintext index is on name; the protected index is on tenant plus full term, as selected by the compiler. Whole-relation ratios are not the target denominator.
PostgreSQL plans used the generated expression index for equality and IN-20. There is no hidden filtering or result refill.
Both plain-projection paths recorded 109 cache hits and one miss; protected projections/predicates disable caching.
The receipt separates admission, compilation, key/term preparation, driver/database wait, decoding and other ORM work for all five workloads.
Server plans also record buffer reads and execution time; larger protected heaps affect ordinary plaintext page scans.
These observations do not establish the cause of the old 127/24 ms receipt. Its full-entity query and former plaintext-only label are retired as current-product evidence.
The current structural control differs in IDs, tenancy, distribution, selectivity and schema; historical causality remains UNKNOWN.

An earlier diagnostic equality run missed 3 ms at 3.565 ms added p95. Profiling removed repeated generated-node comparisons and unnecessary compilation.
The final source retained all admission checks and regression controls. Shared-host activity is uncontrolled; the earlier measurement remains in the receipt.
Seeding observed about 29,873 native and 10,648 attached rows/s. One 2,000-row chunk reached key expiry, rolled back and recovered with fresh keys.
An independent elapsed-expiry test checks no SQL/rows before recovery. Expiry limits were unchanged; a second profile retry failure would stop the run.
1,000 committed updates in ten batches observed about 7,493 native and 3,654 attached rows/s. This is an observation, not a write budget or load qualification.
Cold/remote providers, async costs, sustained-load/platform qualification and deployment admission remain unverified. All seven full gates remain UNKNOWN.

### Historical storage and transition costs

The customer relation/index total rose from 192,692,224 to 350,707,712 bytes, plus 11,100,160 bytes of operation/chunk tables.
That whole-relation total does not establish the per-column 2× target. Isolated protected-column/index evidence remains UNKNOWN.
Protection/verification took 128.821 s. Observed pause with VACUUM/ANALYZE was 130.380 s. Neither value is an approved pause budget.
Observed WAL/temp deltas and CPU/RSS are in the receipt. Unrelated activity can affect cluster/database deltas.

The [10,000-row cost receipt](../../spikes/revamp/results/gate-write-cost.json) also measures an earlier adapter revision before the latest DISTINCT change.
It records paired results and 400 committed updates. It cannot establish current-revision performance or sustained write qualification.
The receipt's historical `current_adapter` labels remain unchanged provenance.
Database-only surrogate array measurements are INTERNAL ONLY, separate from actual CF1 and whole-backend costs.
Their bundle storage ratios do not establish the admitted equality column's target.
