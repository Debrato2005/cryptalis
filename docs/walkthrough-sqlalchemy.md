# SQLAlchemy storage attachment

**IMPLEMENTED:** bounded sync/async text attachment; research prototype.
All seven gates remain **UNKNOWN**. No production provider or independent review exists.
[Status](status.md) owns revision-bound tests and the corrective row-isolation evidence.

The adapter prepares row-bound CF1 frames before SQL and keeps ORM attributes as text or NULL.
Read projections carry field, tenant and row context. Authentication precedes value release.
Host-requested primary-key constraints must match returned identity. Unsupported forms fail before SQL.
Async key preparation runs before synchronous hooks. Protected SELECT caching is disabled.
Unprotected SELECTs retain native caching.

Use the [product protection transition](walkthrough-migration.md) before attachment.
Use the [decrypt-back/removal contract](lifecycle.md#deprotect-and-remove) for the current protected transition format.
Supply a trusted compiler lock, admitted tenant keyrings and an engine with parameter logging hidden.
Attach before sessions or model use. Close existing connections first.
Attach before cursor listeners. Register engine-instance observers after
attachment. They must leave driver SQL and parameters unchanged.
Class-level and connection-local cursor hooks are unadmitted because they can
precede the guard. `UnsafeDriverEvent` reports invalid order or changed driver
SQL/values. Remove the hook or move an unchanged observer to the engine after
attachment. Roll back before retry. Do not use `insert=True` to reorder it.
The host authenticates tenant scope and authorizes queries; attachment adds no tenant filter.
Assign row IDs and declared tenant values before flush. A Python default does not replace assignment.

```python
from cryptalis.sqlalchemy import attach

sessions = attach(Base.registry, engine, lock=plan.lock_bytes,
                  keys=tenant_keys.__getitem__, deployment=(plan, active_pin))
with sessions(tenant_id=authenticated_tenant) as session:
    session.add(Customer(id=app_assigned_uuid, tenant_id=authenticated_tenant, note="text"))
    session.commit()
# AsyncEngine: await attach(...); use async with and await Session methods.
```

Storage-only locks reject protected search. [Equality/IN/uniqueness](walkthrough-search.md) require declared capabilities.
Opaque SQL, COPY, protocol handles, Core writes and unsupported expressions reject.
The attached session admits ordinary mapped dictionary INSERT without RETURNING:

```python
from sqlalchemy import insert

with sessions(tenant_id=authenticated_tenant) as session:
    session.execute(insert(Customer), [
        {"id": first_uuid, "tenant_id": authenticated_tenant, "note": "first"},
        {"id": second_uuid, "tenant_id": authenticated_tenant, "note": None},
    ])
    session.commit()
```

Supply a nonempty list of ordinary dictionaries with mapped attribute names.
Assign every ID and declared tenant explicitly. A single-tenant mapping uses
its declared table UUID as the session scope. Caller dictionaries stay unchanged.
The native bulk Result returns no rows and adds no objects to the identity map.
`render_nulls=True` retains native explicit-NULL grouping.
Rollback and nested savepoint cleanup retain native behavior.

Request one direct protected mapped column when the caller needs inserted values:

```python
with sessions(tenant_id=authenticated_tenant) as session:
    result = session.execute(
        insert(Customer).returning(Customer.note, sort_by_parameter_order=True),
        [{"id": first_uuid, "tenant_id": authenticated_tenant, "note": "first"},
         {"id": second_uuid, "tenant_id": authenticated_tenant, "note": None}],
        execution_options={"render_nulls": True},
    )
    inserted_notes = result.scalars().all()
    session.commit()
```

The native Result also supports one-column Rows and retains its mapped result key.
It adds no objects to the identity map. Explicit parameter-order requests retain
native ordering. Without that request, input order has no promise.
Native processing can authenticate during `execute()`. Later iteration can read
plaintext that already passed authentication, even after its key lease expires.
Any later key use must pass its lease check. Roll back after a result failure before retry.
The INSERT can succeed before result authentication.

Tuple/entity RETURNING, labels, expressions, aliases, loader options,
caller `return_defaults()`, upserts, Core INSERT, statement-embedded values, INSERT SELECT,
SQL expressions in rows and the legacy bulk methods remain unadmitted.
A used callable, context-sensitive, SQL or server default also refuses.
An explicit value can bypass an unused default. Protected field defaults remain
unadmitted by attachment. Broader DML remains a product gap.
Direct/grouped AND lookups and scalar primary-key IN capture explicit requested IDs.
Callable defaults, tuple/transformed identities and ambiguous bind forms reject before SQL.
Primary-key lookups in HAVING or JOIN ON also reject for protected reads.
Explicit public bind overrides retain native values. Compiler-generated override names reject.

Run from the project root. The wrapper reloads both private credential files and probes both roles.
It ignores inherited URLs, prints safe failures and stops if either probe fails.

```bash
.venv/bin/python scripts/test_postgres.py -- -q tests/test_sqlalchemy_adapter.py --tb=short
```

Runtime CRUD and tested persistent DDL/ownership denials have bounded PostgreSQL 16 evidence.
Independent writers can bypass attachment. Changed ciphertext rejects; valid replay, nullable NULL
substitution and row deletion do not establish freshness, authenticated presence or completeness.
The host must exclude unsupported writers. Production custody and deployment enforcement remain UNKNOWN.
