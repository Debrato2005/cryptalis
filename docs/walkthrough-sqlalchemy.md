# Slice 3: SQLAlchemy storage attachment

**IMPLEMENTED:** bounded sync/async storage attachment in `src/cryptalis/sqlalchemy.py`.
**VERIFIED:** 49 real PostgreSQL adapter cases; 785 full-suite cases on the recorded local cell.
Separate restricted runtime credentials verify sync/async CRUD and tested persistent DDL/ownership denials.
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

Use the authorized disposable PostgreSQL service. Keep both private URL files outside the repository.
Run this block from the project root. Reload both files and repeat the sanity checks before every database command.
The suite checks PostgreSQL 16 and role restrictions before fixture work.

```bash
set -e
export CRYPTALIS_TEST_DATABASE_URL="$(sed 's#^postgresql+psycopg://#postgresql://#' ~/.cryptalis-test-url)"
export CRYPTALIS_TEST_RUNTIME_DATABASE_URL="$(sed 's#^postgresql+psycopg://#postgresql://#' ~/.cryptalis-test-runtime-url)"
.venv/bin/python - <<'PY'
import hashlib
import os
import psycopg

names = ("CRYPTALIS_TEST_DATABASE_URL", "CRYPTALIS_TEST_RUNTIME_DATABASE_URL")
for name in names:
    value = os.environ.get(name, "")
    print(name, "set=" + str(bool(value)), "sha256_prefix=" + (hashlib.sha256(value.encode()).hexdigest()[:8] if value else "UNAVAILABLE"))
failed = False
for name in names:
    if not os.environ.get(name):
        failed = True
        continue
    try:
        with psycopg.connect(os.environ[name], connect_timeout=10) as connection:
            assert connection.execute("select 1").fetchone() == (1,)
        print(name, "SELECT_1=OK")
    except psycopg.Error as error:
        print(name, "SELECT_1=FAILED", type(error).__name__, "SQLSTATE=" + str(error.sqlstate))
        failed = True
raise SystemExit(1 if failed else 0)
PY
.venv/bin/python -m pytest -q tests/test_sqlalchemy_adapter.py --tb=line
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
The [runtime receipt](_reset/slice3-runtime-verification.json) records separate-login CRUD and PostgreSQL refusal of nine persistent DDL/ownership/role operations.
Fixture grants are schema `USAGE`, customer CRUD, and article `SELECT` for native deletion relationship lookup, without ownership or grant options.
Runtime database `TEMP` remains available. These tests do not deny every DDL statement or prove separate-writer exclusion.
Independent runtime connections can commit changed bytes, replay an older authenticated value, substitute nullable NULL, and delete rows.
Attached reads reject changed ciphertext. They accept the tested replay, NULL, and row absence; they do not establish freshness, presence, or completeness.
Search predicates and Core/bulk writes reject. Equality/IN/uniqueness belong to slice 4.
This run stops at slice 3. Deployment writer exclusion, production custody, and independent review remain UNKNOWN.
