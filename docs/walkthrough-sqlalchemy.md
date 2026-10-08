# Slice 3: SQLAlchemy storage attachment

**IMPLEMENTED:** bounded sync/async storage attachment in `src/cryptalis/sqlalchemy.py`.
**VERIFIED:** 41 real PostgreSQL adapter cases; 777 full-suite cases on the recorded local cell.
**BLOCKED:** separate non-owning runtime credentials are unavailable. Finish slice 3 before slice 4.
All seven full gates remain **UNKNOWN**. No production provider or independent review exists.

## Purpose and mechanism

The adapter protects text before admitted ORM writes reach PostgreSQL.
Before flush, it binds each CF1 frame to the field, tenant, and application-assigned row ID.
An execution hook substitutes the frame while the ORM attribute remains ordinary text or NULL.
A read projection carries payload, record ID, and tenant. Authentication precedes value release.
Async provider preparation runs before synchronous SQLAlchemy hooks.
Protected SELECTs disable compilation caching. Unprotected SELECTs retain native cache hits.

## Use the bounded API

Use an already transformed disposable target. Product apply/remove transitions do not exist yet.
Supply a trusted compiler lock, local tenant keyrings, and an engine with parameter logging hidden.
Attach before application sessions or model use. Close existing engine connections first.
The host authenticates tenant scope and authorizes queries. The factory does not add tenant filters.
Use storage-only locks. Assign row IDs and declared tenant values before flush.
A Python ID default can remain in the mapping, but it does not replace explicit assignment.

```python
from cryptalis.sqlalchemy import attach

sessions = attach(Base.registry, engine, lock=plan.lock_bytes, keys=tenant_keyrings.__getitem__)
with sessions(tenant_id=authenticated_tenant) as session:
    session.add(Customer(id=app_assigned_uuid, tenant_id=authenticated_tenant, note="text"))
    session.commit()
# AsyncEngine: sessions = await attach(...); use async with and await native Session methods.
```

## Repeat the checks

Keep `CRYPTALIS_TEST_DATABASE_URL` private. Set it to the authorized disposable service.
The suite checks `select 1`, PostgreSQL 16, and the restricted role before fixture work.

```bash
.venv/bin/python -m pytest -q tests/test_sqlalchemy_adapter.py --tb=short
.venv/bin/python -m pytest -q tests/test_sqlalchemy_adapter.py -k interleaved --tb=short
.venv/bin/python tests/profile_sqlalchemy_adapter.py
```

## Exact behavior checked in the main thread

- Native and attached paths return exact text, NULL, empty text, and Unicode code points.
- Entities, scalar tuples, labels, aliases, outer joins, and relationships retain native results. Joined collections require native `unique()`.
- Streaming produces three two-row partitions in sync and async paths. The async path uses the real server cursor.
- Flush, history, identity maps, autoflush, refresh, expiry, merge, and rollback retain native behavior.
- An unprotected update and a delete work after commit expires the row, in sync and async paths.
- Explicit single-tenant bigint records retain alias and outer-join NULL behavior. Explicit UUID assignment works with a Python default mapping.
- Two schemas with the same table name and row ID retain separate values through insertion and update.
- Interleaved operations retain the current tenant and requested row across reused entity and scalar statements, autoflush, and rollback.
- Protected writes expose no supplied protected markers in driver binds. The collector sees the unprotected control marker.
- Wrong tenant, wrong returned point, relocated frames, and changed bytes reject before the affected value becomes available.
- Unsupported queries, ambiguous columns, alternate protected mappings, opaque SQL, raw driver routes, and COPY reject before execution.
- Target translation and changed key or nullability metadata reject. Existing native connections prevent attachment before pool replacement.
- Real database cancellation propagates after PostgreSQL reports `PgSleep`. Rollback removes the pending row. A later tenant session recovers.
- Cancellation during awaited key preparation propagates. An independent PostgreSQL read finds no inserted row. A later write succeeds.

## Cache regression sensitivity

The main thread copied the current source and tests into a temporary directory.
Only the copy lost the protected SELECT `compiled_cache=None` call. The original worktree remained unchanged.
The same unmodified interleaved tests used real PostgreSQL in both runs.

| Path and projection | Without fix | With fix |
|---|---|---|
| Native sync and async, entity and scalar | 4 passed | 4 passed |
| Attached sync and async, entity and scalar | 4 failed with `AuthenticationFailed` | 4 passed |

The restored copy matched the original source bytes. No assertion was weakened.
The withheld output was unavailable in the main-thread context. Its findings supplied no relied-upon evidence.
Direct main-thread PostgreSQL and SQLAlchemy checks supplied this record.

## Measured cost and limits

The final local profile used 5,000 rows, 100-row plaintext pages, 40 paired samples, and warm development keys.
Native page median/p95: 1.428/1.906 ms. Attached page median/p95: 2.238/2.810 ms.
The p95 difference was 0.904 ms. Both paths recorded 60 compilation-cache hits and one miss.
Point entity p95: 0.618 ms native and 2.903 ms attached. The difference was 2.285 ms.
Shared-host timings vary. This profile does not explain the historical million-row anomaly.
Async performance, sustained writes, and remote provider costs remain unmeasured.

See [status](status.md#slice-3-checkpoint-2026-10-08), [verification receipt](_reset/slice3-verification.json),
and [local profile](compatibility.md#slice-3-local-profile-2026-10-08).
The fixture owner does not prove runtime privilege isolation or separate-writer exclusion.
Search predicates and Core/bulk writes reject. Equality/IN/uniqueness belong to slice 4.
Next: provision restricted runtime access and verify CRUD plus DDL/ownership refusal before advancing.
