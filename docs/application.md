# Shared application configuration

`ApplicationConfig` keeps one explicit manifest, ORM registry, writer inventory,
search review set and optional SELECT sample set. Reuse it for initialization,
Doctor, protection planning and runtime attachment. It contains no engine,
credentials, keyring, deployment pin or maintenance approval.

Use [compatibility](compatibility.md) to choose protected fields and supported
operations. This API does not expand that matrix or qualify a production deployment.

## Configure once

```python
from pathlib import Path
from sqlalchemy import bindparam, select
from cryptalis.application import ApplicationConfig

protection = ApplicationConfig(
    manifest=Path("cryptalis.json").read_bytes(),
    mapping=Base.registry,
    writers=verified_writer_inventory,
    search_reviews=approved_search_reviews,
    queries=(select(Customer).where(Customer.email == bindparam("email")),),
)
```

The writer inventory and search reviews are explicit host evidence, as described
in the [manifest reference](manifest.md). The library cannot infer that unknown
credentials or writer routes are excluded. Construction parses and canonicalizes
bounded manifest bytes without database or provider access. The configuration is
frozen and suppresses its value representation; the ORM registry still belongs
to the application and remains subject to normal mapping checks.

The optional `queries` tuple contains at most 128 SELECT samples. Inspection
uses runtime admission without executing the samples or reporting their values.
It does not establish complete query coverage, runtime parameter validity or
application authorization.

## Diagnose and plan

For direct Python use:

```python
report = protection.diagnose(owner_engine)
plan = protection.plan(
    owner_engine,
    keys=tenant_keys,
    runtime_role=runtime_role,
    target_id=approved_target_id,
    backfill_rows_per_second=measured_backfill_rate,
    verify_rows_per_second=measured_verify_rate,
    temporary_bytes_per_row=measured_temporary_cost,
    wal_bytes_per_row=measured_wal_cost,
)
```

Diagnosis is key-free and read-only. A successful schema/sample check leaves
unobserved boundaries UNKNOWN. Planning uses the same manifest and samples;
a known incompatible or unavailable sample inspection blocks planning before
key-policy resolution. It does not create a journal or alter application data.
The measured costs remain host estimates, not automatic resource guarantees.

For the CLI, return contexts made from the same object:

```python
def inspection_context():
    return protection.initialization_context(new_owner_engine())

def planning_context():
    return protection.planning_context(new_owner_engine(), **planning_authority)
```

`planning_authority` contains the explicit keyword inputs shown in the Python
planning example. It must come from trusted host configuration. Each factory
transfers a fresh owned engine to the CLI, which disposes it on success or failure.
Direct Python calls borrow their engine; its lifetime remains with the caller.

```console
cryptalis doctor --initialization-context myapp.security:inspection_context --json
cryptalis init --host-context myapp.security:inspection_context --out intent.json --json
cryptalis plan intent.json --host-context myapp.security:planning_context --out plan.json --json
```

The configuration-created planning context binds the CLI manifest to the same
canonical declaration. Changed domain/field/tenant/search intent refuses before
connection or key resolution. Existing manually constructed `PlanningContext`
objects remain compatible; their optional `declaration=None` does not add this
intent binding. Query inspection is also available directly through
`migration.plan(..., queries=(...))`.

## Attach the application

After the [protection transition and host publication](walkthrough-migration.md)
complete, attach with the current trusted plan and ACTIVE pin:

```python
sessions = protection.attach(
    runtime_engine,
    keys=tenant_keys,
    deployment=(plan, active_pin),
)
with sessions(tenant_id=authenticated_tenant) as session:
    customer = session.get(Customer, application_record_id)
```

The plan supplies its own compiled lock. The configuration's canonical manifest
and writer/search evidence must match the plan's recorded facts before any
connection or key access. Incomplete or changed inventory/reviews refuse. Existing adapter
checks still validate mapping, logging, target, current pin, schema and keys.
This method performs no migration or policy publication. Missing deployment or
mismatched intent raises typed `ConfigurationInvalid`; no fallback attachment occurs.

For an AsyncEngine, await `protection.attach(...)` and use the returned async
session factory. Select `adapter="sqlmodel"` for SQLModel's native `Session.exec`
behavior. Unsupported adapter names refuse. An adopted target can supply the
existing `(plan, active_pin, restore_binding)` tuple; the normal restore authority
checks remain mandatory.

This shared configuration reduces repeated setup. Tenant authentication, provider
credentials, deployment publication, writer exclusion, plaintext-removal consent
and retained-backup ownership remain explicit host responsibilities. Other lifecycle
commands retain their [approved context inputs](host-contexts.md).
