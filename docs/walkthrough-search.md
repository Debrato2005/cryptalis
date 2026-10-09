# Slice 4: equality, IN and tenant-scoped uniqueness

**IMPLEMENTED:** bounded sync/async search attachment for exact text on PostgreSQL 16.
This is a research prototype. All seven gates remain **UNKNOWN**. No production provider or independent review exists. See [status](status.md).

Declare `queries: ["equality"]`, or `["equality", "unique"]`, in the manifest.
Supply the matching `accept_leakage` entries and a host `SearchReview` for each field.
Known small domains and absent reviews reject. This is host admission, not automatic classification.
Use application-assigned IDs and an authenticated tenant UUID. Exact UTF-8 text uses the selected native C collation; no normalization occurs.

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
Product migration, verification and deployment admission belong to slice 5. Do not apply fixture DDL to real data.
The B-tree indexes the full 32-byte keyed term inside each frame, with tenant first when declared.
Payload and term change in one ORM write. Native unique indexes arbitrate concurrent writes; duplicates raise `IntegrityError`.
NULL stays NULL. NULLs remain distinct for uniqueness. Empty IN matches no rows; NULL in IN keeps native three-valued truth.
AND/OR, mapped aliases, ordinary text binds and explicit late values are admitted.
Protected joins, derived tables, inequality, NOT IN, patterns, ordering, grouping, DISTINCT and aggregates reject.
Custom codecs, callables, generated parameter-name overrides and conflicting named defaults without explicit values also reject.
Protected compilation is per operation; plain queries retain SQLAlchemy caching.

Reload both private files before each database command. Stop if either sanity check fails.

```bash
set -e
export CRYPTALIS_TEST_DATABASE_URL="$(sed 's#^postgresql+psycopg://#postgresql://#' ~/.cryptalis-test-url)"
export CRYPTALIS_TEST_RUNTIME_DATABASE_URL="$(sed 's#^postgresql+psycopg://#postgresql://#' ~/.cryptalis-test-runtime-url)"
.venv/bin/python - <<'PY'
import hashlib, os, psycopg
names = ("CRYPTALIS_TEST_DATABASE_URL", "CRYPTALIS_TEST_RUNTIME_DATABASE_URL")
for name in names:
    value = os.environ.get(name, "")
    print(name, "set=" + str(bool(value)), "sha256=" + hashlib.sha256(value.encode()).hexdigest()[:8])
failed = any(not os.environ.get(name) for name in names)
for name in names:
    if not os.environ.get(name): continue
    try:
        with psycopg.connect(os.environ[name], connect_timeout=10) as connection:
            assert connection.execute("select 1").fetchone() == (1,)
        print(name, "SELECT_1=OK")
    except psycopg.Error as error:
        print(name, type(error).__name__, "SQLSTATE=" + str(error.sqlstate)); failed = True
raise SystemExit(1 if failed else 0)
PY
.venv/bin/python -m pytest tests/test_sqlalchemy_search.py -q --tb=short
```
Returned frames authenticate. Separate writers can hide matches, replay frames, substitute NULL or delete rows.
The host must pin the correct keys and exclude bypass writers. Grants do not prove freshness or complete results.
