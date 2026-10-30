# Shared application configuration

`ApplicationConfig` keeps one explicit manifest, ORM registry, writer inventory,
search review set and optional SELECT sample set. Reuse it for initialization,
Doctor, protection planning/application, runtime attachment, three rotations and verified removal.
It contains no engine,
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

## Apply, inspect and resume

Use the same configuration and the host's current plan/pin:

```python
progress = protection.apply(
    owner_engine,
    deployment=(plan, prepared_pin),
    keys=tenant_keys,
    approval=maintenance_approval,
)
observed = protection.status(owner_engine, deployment=(plan, prepared_pin))
```

`apply` uses the existing protection executor and defaults to `PENDING`, with
writers still stopped. Repeating it with the same operation and current host pin
resumes committed progress. `chunk_size` retains the existing bounds. After the
host publishes its matching `ACTIVATING` pin, an explicit `until="ACTIVE"` call
finishes activation. The configuration never creates or publishes a pin.
Online capture, rotations and tenant provisioning retain their dedicated
[lifecycle procedures](lifecycle.md); this method does not choose an executor for them.

`status` reads protection or decrypt-back progress without keys or writes. It
checks recorded metadata, not current cryptographic values or provider readiness;
its verification field remains `NOT_PERFORMED`. Status cannot authorize publication.
For an adopted source, status accepts `(plan, active_pin, restore_binding)`.
Protection apply accepts only `(plan, pin)`; it cannot resume the original
migration on a restored target by silently ignoring the restore binding.

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

## Rotate keys and change custody

Use the same configuration with explicit source and target key-policy resolvers.
Cryptalis preserves the three different [rotation contracts](lifecycle.md#changes-and-rotation):

| Operation | Shared configuration | Effect |
|---|---|---|
| Root rewrap | `plan_rewrap`, `rewrap`, `abort_rewrap` | Verify the same roots under changed wrapping custody; preserve payload and search bytes |
| Payload generation | `plan_rotation(purpose="payload")` | Stage new authenticated payloads while retaining search terms |
| Search generation | `plan_rotation(purpose="search")` | Stage new search terms and resealed payloads; preserve native uniqueness |

Rewrap uses an exact successor artifact:

```python
proposal = protection.plan_rewrap(
    owner_engine, deployment=(active_plan, active_pin), keys=source_keys,
    target_keys=target_keys, verify_rows_per_second=measured_verify_rate,
)
successor = proposal.activation_plan
# Retain proposal/successor outside PostgreSQL; obtain this exact PREPARED pin.
protection.rewrap(
    owner_engine, proposal=proposal, deployment=(successor, successor_prepared_pin),
    keys=source_keys, target_keys=target_keys, approval=maintenance_approval,
)
```

For a generation change, `plan_rotation` takes the four measured rates/costs from
`plan`, explicit `purpose`, source `deployment`, `keys` and `target_keys`.
Optional `max_batch_rows` and `max_batch_bytes` bound logical staging work.
Use `(proposal, preparation_pin)` to prepare/resume, inspect or seal it:

```python
progress = protection.prepare_rotation(
    owner_engine, deployment=(proposal, preparation_pin), keys=source_keys,
    target_keys=target_keys, approval=maintenance_approval,
)
successor = protection.seal_rotation(
    owner_engine, deployment=(proposal, preparation_pin), keys=source_keys,
    target_keys=target_keys, approval=maintenance_approval,
    copy_rows_per_second=measured_copy_rate, copy_wal_bytes_per_row=measured_copy_wal,
)
# Retain the exact sealed artifact before obtaining its PREPARED pin.
protection.switch_rotation(
    owner_engine, proposal=proposal, deployment=(successor, successor_prepared_pin),
    keys=source_keys, target_keys=target_keys, approval=maintenance_approval,
)
```

`prepare_rotation` defaults to `BACKFILLED`; `max_chunks` allows a bounded partial
run and `status` reports its durable progress without claiming fresh verification.
Committed chunks resume without resealing. Sealing returns verified observations,
not publication authority. Rewrap and generation switch both leave `PENDING` with
writers stopped. After external publication, use `apply` with the successor's
`ACTIVATING` pin and `until="ACTIVE"`, then attach through the current host pin.

To cancel eligible staging, use `abort_rotation` with `proposal`, the original
source `deployment`, source `keys` and maintenance `approval`. Pending rewrap uses
`abort_rewrap` with the same source inputs. Both require the host to republish its
source ACTIVE authority first; neither needs target keys. A completed generation
switch cannot use staging cancellation. The underlying executor rejects stale
pins, mismatched successors, missing approval and unsafe state.

Planning accepts `(source_plan, source_pin, restore_binding)` on a restored
target; the existing restore proof and lineage remain mandatory. No method
retires old wrappers, destroys provider keys or removes retained-backup readers.
Provider calls may have native audit/cost effects. Failed AppRole authentication
remains uncertain even while creating an inactive rewrap candidate.

## Decrypt current values and remove protection

```python
reverse = protection.plan_deprotection(
    owner_engine,
    deployment=(plan, active_pin),
    keys=tenant_keys,
    plaintext_runtime_role=approved_plaintext_role,
    backfill_rows_per_second=measured_backfill_rate,
    verify_rows_per_second=measured_verify_rate,
    temporary_bytes_per_row=measured_temporary_cost,
    wal_bytes_per_row=measured_wal_cost,
)
progress = protection.decrypt_back(
    owner_engine,
    deployment=(reverse, reverse_prepared_pin),
    keys=tenant_keys,
    approval=maintenance_approval,
    consent=plaintext_approval,
)
```

Reverse planning is read-only and grants no plaintext consent. For an adopted
source, pass its third `restore_binding` value during planning; the reverse
artifact retains that binding. `decrypt_back` restores authenticated **current**
values, including edits since protection, and defaults to `PLAINTEXT_PENDING`.
It can resume the same operation. Plaintext staging/WAL/backup exposure requires
the explicit `PlaintextApproval`. The host must publish the matching
`PLAINTEXT_ACTIVATING` pin before `until="PLAINTEXT_ACTIVE"` can finish activation.

After verifying the ordinary application and retained recovery obligations:

```python
removed = protection.remove(
    owner_engine,
    deployment=(reverse, removing_pin),
    approval=maintenance_approval,
    consent=plaintext_approval,
    removal=removal_approval,
)
```

`remove` requires the existing `RemovalApproval`, plaintext-active database state
and `REMOVING` host pin. It retires eligible database objects and verifies native
metadata. It does not uninstall the package, destroy keys or delete backups.
Package removal follows the [complete removal procedure](lifecycle.md#deprotect-and-remove).
`status(owner_engine, deployment=(reverse, removed_pin))` can inspect the terminal
state; unavailable retired progress counters remain `None`.

All these methods compare the configuration's canonical manifest and writer/search
evidence to the trusted plan before database or key access. Reverse operations
compare against the original protected source. A wrong plan type or configuration
drift raises `ConfigurationInvalid`; pin, approval, schema, key and integrity
failures retain the underlying typed lifecycle errors. No method invents authority
or creates a second transition state machine.

This shared configuration reduces repeated setup. Tenant authentication, provider
credentials, deployment publication, writer exclusion, plaintext-removal consent
and retained-backup ownership remain explicit host responsibilities. CLI lifecycle
commands retain their [approved context inputs](host-contexts.md). Direct lifecycle
methods use a synchronous owner engine, including for applications whose runtime
attachment is asynchronous; engine ownership stays with the caller.
