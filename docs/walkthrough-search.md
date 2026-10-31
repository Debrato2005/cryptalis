# Slice 4: equality, IN and tenant-scoped uniqueness

**IMPLEMENTED:** bounded sync/async equality search for exact text and finite NUMERIC on PostgreSQL 16.
This is a research prototype. All seven gates remain **UNKNOWN**. No provider deployment is production-qualified; independent human review remains unavailable. See [status](status.md).

Declare `queries: ["equality"]`, or `["equality", "unique"]`, in the manifest.
Supply the matching `accept_leakage` entries and a host `SearchReview` for each field.
Known small domains and absent reviews reject. This is host admission, not automatic classification.
Use application-assigned IDs and an authenticated tenant UUID. Exact UTF-8 text uses the admitted deterministic native C or implicit database-default collation; no normalization occurs.

Finite NUMERIC uses the same queries with exact `Decimal` or Python int values.
Equality ignores scale, so `Decimal('1.2')` matches stored `Decimal('1.20')`.
Assignment to `Numeric(8, 2)` rounds `1.235` to `1.24`; a query pivot of `1.235`
remains unrounded and does not match `1.24`. See the exact
[numeric bind contract](compatibility.md#numeric-equality-search).

```python
from sqlalchemy import bindparam, select
from cryptalis.sqlalchemy import attach

sessions = attach(Base.registry, engine, lock=plan.lock_bytes, keys=tenant_keys.__getitem__)
with sessions(tenant_id=authenticated_tenant) as session:
    statement = select(Customer).where(Customer.email == bindparam("email"))
    customer = session.scalar(statement, {"email": supplied_email})
    matches = session.scalars(select(Customer).where(Customer.email.in_(supplied_emails))).all()
# AsyncEngine: await attach; use async with and await Session methods.
```

The target must already contain CF1 bytea columns, exact generated expression indexes and validated framing checks.
The walkthrough fixtures create these objects with the owner login; the application uses only runtime CRUD grants.
Use the [product protection transition](walkthrough-migration.md) for existing data. Do not apply fixture DDL to real data.
The B-tree indexes the full 32-byte keyed term inside each frame, with tenant first when declared.
Payload and term change in one ORM write. Native unique indexes arbitrate concurrent writes; duplicates raise `IntegrityError`.
NULL stays NULL. NULLs remain distinct for uniqueness. Empty IN matches no rows; NULL in IN keeps native three-valued truth.
AND/OR/NOT, mapped aliases, ordinary text binds and explicit late values are admitted.
Negative equality, NOT IN and NULL-presence predicates retain the bounded
grammar in [compatibility](compatibility.md#full-capability-matrix).
[Order search](compatibility.md#order-search) adds ranges, sorting and direct MIN/MAX on integer, date and naive/aware timestamp
fields that opt in. Protected joins, derived tables, patterns, general protected
grouping/DISTINCT and aggregates outside the admitted count and order-extrema grammar reject.
Custom codecs, callables, generated parameter-name overrides and conflicting named defaults without explicit values also reject.
Protected compilation is per operation; plain queries retain SQLAlchemy caching.

For an order-enabled field, direct extrema keep native empty-input behavior:

```python
low, high = session.execute(
    select(func.min(Invoice.amount), func.max(Invoice.amount))
    .where(Invoice.tenant_id == tenant)
).one()
```

These values authenticate through the ordinary reader. One provable tenant is
required; group/window/FILTER forms and explicit result-type conversions refuse.

Compose supported predicates normally:

```python
from sqlalchemy import and_, not_

statement = select(Customer).where(not_(and_(
    Customer.email.in_(excluded_emails),
    Customer.email.is_not(None),
)))
with sessions(tenant_id=authenticated_tenant) as session:
    matches = session.scalars(statement).all()
```

PostgreSQL's NULL rules still apply. Cryptalis keeps generated tenant guards
outside negation; wrapping an unsupported protected operation in NOT still fails.

## Count reports

Use the same attached session to count protected values. A direct non-NULL count
needs no equality representation. A distinct count requires declared equality
and one provable tenant scope per group:

```python
from sqlalchemy import func

statement = select(
    func.count(Customer.email).label("present"),
    func.count(Customer.email.distinct()).label("different"),
).where(Customer.tenant_id == authenticated_tenant)
with sessions(tenant_id=authenticated_tenant) as session:
    totals = session.execute(statement).one()
    present, different = totals.present, totals.different
```

An explicitly single-tenant table needs no tenant-column filter. A tenant-column
table can instead group by its exact tenant column for separate tenant totals.
Global cross-tenant distinct counts refuse. Native count FILTER predicates and
non-distinct windows may use public fields. Counts trust the database's integer
result and do not authenticate each contributing frame. The
[illustrated guide](professor-guide.md#count-reports-over-encrypted-values)
explains that boundary and measured costs.

Run from the project root. The wrapper loads both private files fresh and probes both roles.
Inherited URLs are ignored. A failed probe stops the run with sanitized diagnostics.

```bash
.venv/bin/python scripts/test_postgres.py -- -q tests/test_sqlalchemy_search.py --tb=short
```
Returned frames authenticate. Separate writers can hide matches, replay frames, substitute NULL or delete rows.
The host must pin the correct keys and exclude bypass writers. Grants do not prove freshness or complete results.
