# SQLAlchemy storage attachment

Use [shared application configuration](application.md) to reuse one manifest and
registry across planning, Doctor and attachment. The lower-level attachment
interface below remains supported.


**IMPLEMENTED:** bounded sync/async attachment for the [admitted types and operations](compatibility.md).
All seven production gates remain **UNKNOWN**; no provider deployment is production-qualified.
[Status](status.md) owns revision-bound tests and the corrective row-isolation evidence.

The adapter prepares row-bound CF1 frames before SQL and preserves admitted Python value types and NULL.
Read projections carry field, tenant and row context. Authentication precedes value release.
Host-requested primary-key constraints must match returned identity. Unsupported forms fail before SQL.
Async key preparation runs before synchronous hooks. Protected SELECT caching is disabled.
Unprotected SELECTs retain native caching.

Use the [product protection transition](walkthrough-migration.md) before attachment.
Use the [decrypt-back/removal contract](lifecycle.md#deprotect-and-remove) for the current protected transition format.
Supply a trusted compiler lock, admitted tenant keyrings and an engine with parameter logging hidden.
Attach before sessions or model use. Close existing connections first.
For worker processes, create mappings, engine, key providers and attachment in
each worker's initialization. A forked child must not reuse or close the parent's
sessions. `ForkedRuntime` requires fresh initialization, including when a key
resolver can supply fresh child keys. See [process ownership](compatibility.md#process-ownership)
for supported entrypoints and the memory/driver limits.
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

SQLModel 0.0.48 uses its optional attachment with native `exec` results:

```python
from cryptalis.sqlmodel import attach
from sqlmodel import select

sessions = await attach(Base.registry, async_engine, lock=plan.lock_bytes,
                        keys=tenant_keys.__getitem__, deployment=(plan, active_pin))
async with sessions(tenant_id=authenticated_tenant) as session:
    customer = (await session.exec(
        select(Customer).where(Customer.id == app_assigned_uuid)
    )).one()
    customer.note = "updated"
    await session.commit()
```

Call async `exec` with `await`; consume its buffered native result normally.
Use ordinary async SQLAlchemy methods for streaming and transaction operations.
The same query, tenant and writer restrictions apply. For a synchronous engine,
omit `await` and use the synchronous session context. The [SQLModel contract](compatibility.md#optional-sqlmodel-bridge)
states dependency and mapping admission.

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

To return inserted values, add direct columns, named columns or the mapped entity:

```python
result = session.execute(
    insert(Customer).returning(Customer.note.label("display_note"),
                               sort_by_parameter_order=True),
    params=[{"id": first_uuid, "tenant_id": authenticated_tenant, "note": "first"}],
)
assert result.scalar_one() == "first"
session.commit()
```

The optional ordering flag uses native input ordering across pages. Each protected
result must authenticate and match its exact prepared input. SQLModel `exec` uses
the same `params=` keyword; async execution and commit use `await`.

For one record with returned values, pass a single assignment dictionary:

```python
from sqlalchemy import update

result = session.execute(
    update(Customer)
    .where(Customer.id == app_assigned_uuid,
           Customer.tenant_id == authenticated_tenant)
    .returning(Customer.id, Customer.note),
    {"note": "updated"},
    execution_options={"synchronize_session": False},
)
returned = result.one_or_none()
session.commit()
```

The dictionary uses physical column keys, as native single-statement UPDATE
does. Returned column names normally follow mapped attributes; use
`Customer.note.label("display_note")` for an explicit result name. Use `await`
for async execution and commit; SQLModel `exec` takes the dictionary as `params=...`.
For a declared single-tenant table, omit the tenant predicate and use its table
UUID as the session scope. Existing loaded objects remain stale under
`synchronize_session=False`; refresh them when needed. Missing records return no
row. Native assignment errors can still occur for a missing record during SQL
evaluation; roll back the failed transaction or savepoint before retrying.

You can instead put ordinary scalar assignments on the statement and omit
the external dictionary:

```python
result = session.execute(
    update(Customer)
    .where(Customer.id == app_assigned_uuid,
           Customer.tenant_id == authenticated_tenant)
    .values(note="updated")
    .returning(Customer.id, Customer.note),
    execution_options={"synchronize_session": False},
)
returned = result.one_or_none()
session.commit()
```

Keywords use mapped attribute names; `.values({Customer.note: "updated"})`
also works. Python `None` retains native NULL behavior. Cryptalis captures and
rechecks the assignments around key preparation, encrypts protected values,
and executes an owned statement copy. The original statement remains reusable.
Do not combine this form with external parameters or explicit SQL expressions,
`bindparam`, callable values, or ordered assignments.

Omit `.returning(...)` when only the affected-row count is needed. The same
single-record update then returns native `result.rowcount` (zero or one), with
`result.returns_rows` false. Reading rows from that result raises SQLAlchemy's
normal `ResourceClosedError`. Identity-map and transaction behavior remain the
same; even assigning the existing value counts a matched record.

Use direct or explicitly named returned columns, or the mapped entity. Computed
expressions, table aliases, identity/tenant changes, and multirow
executemany RETURNING are outside this route. It uses the existing encryption
and declared search representation; it adds no search capability or production
qualification. See [status](status.md) for exact verification.

For mapped dictionary UPDATE on an explicitly single-tenant table, use its
declared table UUID as session scope and let SQLAlchemy select each typed
primary key:

```python
from sqlalchemy import update

with sessions(tenant_id=declared_table_uuid) as session:
    session.execute(update(Customer),
                    [{"id": first_uuid, "note": "updated"}],
                    execution_options={"synchronize_session": False})
    session.commit()
```

Supply no WHERE clause for this fixed-scope route. A missing primary key retains
native `StaleDataError`; roll back before retry. Tenant-column tables use the
separate explicit tenant-equality form in the [UPDATE contract](compatibility.md#full-capability-matrix).
Async sessions use the same statements with awaited execution and commit.
Loaded objects retain native stale state until refresh or expiration. Use
rollback or the enclosing savepoint to recover from errors. UPDATE expressions,
Core statements and RETURNING remain unadmitted. The
[online scalar checkpoint](history/implementation-2026-10.md#single-tenant-mapped-update-2026-10-29)
adds current-value removal evidence across the admitted storage types.

Delete one record from the same explicitly single-tenant table with its exact
typed primary key:

```python
from sqlalchemy import delete

with sessions(tenant_id=declared_table_uuid) as session:
    result = session.execute(delete(Customer).where(Customer.id == first_uuid),
                             execution_options={"synchronize_session": False})
    session.commit()
```

Without RETURNING, native `result.rowcount` is zero or one. To receive the deleted
values, add `.returning(Customer.id, Customer.note.label("display_note"))` and consume the ordinary
Result with `.one_or_none()`, `.all()` or `.scalars()`. Returning the mapped entity
is also supported. For a tenant-column table, include exact tenant equality
alongside the record equality. Async execution uses `await`; SQLModel async
`exec` uses the same statement.

Loaded objects retain native stale identity state with
`synchronize_session=False`. Protected returned values authenticate before
release; an error can occur after DELETE executed, so roll back before retrying
or committing. Do not supply external parameter dictionaries, additional
predicates, labelled/aliased/expression outputs or automatic/fetch synchronization.

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

Direct tuple/entity RETURNING is also admitted under the [current result contract](compatibility.md#full-capability-matrix).
Labels, expressions, aliases, loader options,
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
