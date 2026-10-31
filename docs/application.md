# Application API

Start with `Project`. Use `ApplicationConfig` only when your host needs its own
publication system or per-step control.

## Project: the small API

`Project` needs a manifest, your ORM registry, a key provider and a private state
directory. It generates wrapped roots, retains plans, publishes pins and resumes
after a crash. It adds no cryptography, SQL or transition logic: every call drives
the executors described below.

```python
from cryptalis import Project

project = Project("cryptalis.json", Base.registry,
                  provider=my_key_provider, state_dir="/etc/myapp/cryptalis")
```

| Call | What it does |
|---|---|
| `doctor(engine)` | Read-only check. Before protection, pass the owner engine: schema and query samples, no keys. Afterwards, pass the runtime engine: attachment metadata and cold provider access |
| `protect(owner, runtime_role=, writers_stopped=, search_reviewed=)` | Encrypt existing rows with writers stopped |
| `protect_online(owner, runtime_role=, source_role=, writers_excluded=, accept_plaintext_capture=True)` | Encrypt existing rows while the native application keeps writing, until the final fence |
| `attach(engine)` | Return the session factory. Await it for an `AsyncEngine`. Use `adapter="sqlmodel"` for SQLModel |
| `status(owner)` | Recorded progress, or `None` before protection starts |
| `rotate(owner, "payload" \| "search", writers_stopped=)` | New payload key, or new search key and terms |
| `rotate(owner, "wrapping", provider=new, writers_stopped=)` | Move the same roots to another provider; stored bytes do not change |
| `modify(owner, writers_stopped=, search_reviewed=)` | Apply a changed manifest's search settings |
| `add_tenant(owner, tenant_id, writers_stopped=)` | Add one empty tenant with its own keys. Restart workers afterwards |
| `recover(owner, host=, quarantine=, source_fenced=True)` | Adopt a database restored from backup |
| `decrypt(owner, plaintext_role=, writers_stopped=, accept_plaintext=True, retained_backups=)` | Restore current values to plaintext columns |
| `remove(owner, writers_stopped=, application_verified=, old_workers_stopped=True)` | Drop generated objects after `decrypt`. Uninstall the package last |
| `abort(owner, writers_stopped=)` | Cancel an unfinished operation. A completed switch refuses; resume it instead |

Repeat a lifecycle call that failed to resume it. Repeating a finished call reports the
result, except `rotate`, which starts a new rotation. An unfinished operation blocks
`attach` and other lifecycle calls until you finish or abort it, with a
`ProjectError` that says what to do. `owner` is a synchronous engine with the schema
owner's credentials; `runtime_role` is your application's separate role.

**Decisions stay visible.** String arguments such as `writers_stopped` and
`search_reviewed` are your statements. Cryptalis cannot verify them. They are required
and recorded in the plan. `search_reviewed` is needed only when the manifest declares
search on a field.

**State directory.** It is the deployment authority, so keep it outside database
backups: a restored old database then cannot authorize itself. It holds wrapped roots,
plans and phases, never plaintext keys or values. It must be owner-writable only;
`ProjectError` refuses anything else. Every worker must read the same state, for
example from your deployment artifact or a shared volume, and must restart after a
lifecycle change. Run one lifecycle operation at a time. Losing the state directory
loses access to the wrapped roots, so back it up.

**Estimates.** Pause estimates use conservative defaults of 1,000 rows per second.
`protect` refuses if the estimate exceeds `max_pause_seconds` (default one hour). Pass
measured values through `Project(..., estimates={...})`. They are estimates, not
guarantees.

**Limits.** `writers_stopped` covers one attached application. For several writer
routes, pass `Project(..., writers=WriterInventory(...))`. `add_tenant` pauses writers
and verifies every frame, so it suits occasional onboarding rather than signup traffic.
`recover` needs a real restored copy and the state directory copy from the time of that
backup, because state records only the latest plan. The
[fresh-cluster harness](qualification.md) runs it on a genuinely restored cluster with
`--project`. `modify` is not available on a restored target until another lifecycle
change has run there. Compatibility limits and all seven production gates apply unchanged.

## Shared application configuration

`ApplicationConfig` keeps one explicit manifest, ORM registry, writer inventory,
search review set and optional SELECT sample set. Reuse it for initialization,
Doctor, protection planning/application, online capture, tenant onboarding,
runtime attachment, active-field modification, three rotations and verified removal.
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
Online capture, rotations and tenant preparation use the explicit methods below;
`apply(..., until="ACTIVE")` activates their sealed or published successors under
the matching host pin. It never chooses a preparation executor implicitly.

`status` reads protection or decrypt-back progress without keys or writes. It
checks recorded metadata, not current cryptographic values or provider readiness;
its verification field remains `NOT_PERFORMED`. Status cannot authorize publication.
For an adopted source, status accepts `(plan, active_pin, restore_binding)`.
Protection apply accepts only `(plan, pin)`; it cannot resume the original
migration on a restored target by silently ignoring the restore binding.

## Protect while native writers continue

`plan_online` uses the same declaration, mapping, writer/search evidence and query
samples as ordinary planning. Supply the ordinary four measured cost/rate inputs,
`keys`, `runtime_role`, `target_id`, and the separate native `source_role`.
`native_tenants=None` selects the existing fixed-scope contract. An explicit tuple
of approved UUIDs selects bounded tenant-scoped capture, including empty approved
scopes. The host supplies custody for every approved scope; future unknown tenants
are refused. This API defaults `max_rows`/`max_bytes` to 1,000 rows and 64 MiB;
the executor's existing ceilings remain 5,000 rows and 1 GiB.

```python
capture = protection.plan_online(
    owner_engine, source_role=native_writer_role,
    native_tenants=approved_native_tenants, **planning_authority,
)
progress = protection.capture_online(
    owner_engine, deployment=(capture, capture_pin), keys=tenant_keys,
    approval=online_approval, max_chunks=10,
)
```

Here `planning_authority` contains the explicit inputs listed above, and
`online_approval` is the existing `OnlineApproval`: owner/DDL writer exclusion,
plaintext-capture consent and an approved pause bound. Native values remain
authoritative while capture runs. Repeating `capture_online` resumes committed
chunks. `status` accepts `(capture, pin)` and remains key-free.

Before cutover, use `capture_online(..., fence=True)` to install the durable
native-writer fence, then finish bounded catch-up with further calls. An empty
backlog alone does not authorize switching. `seal_online` verifies current values
and returns an immutable successor for the host to retain. `switch_online` takes
the same capture deployment and the exact `successor`; it verifies again and
transfers access, leaving protection PENDING. Publish the matching successor pin,
then use `apply(..., until="ACTIVE")` and attach a fresh runtime engine.

All execution calls retain `keys` and `approval`; `abort_online` needs only the
capture deployment and approval. It preserves native edits and removes eligible
capture/shadow state before cutover. It cannot undo an active protected deployment.
`workers` and `target_chunk_seconds` forward the existing optional bounded worker
controls; thread-safe host custody is required for multiple workers. These methods
do not supply production fencing or a verified downtime bound. The
[online lifecycle contract](lifecycle.md) remains authoritative.

## Add an approved empty tenant

Use `plan_tenant` against the ACTIVE source deployment with the approved typed
`tenant_id`, its `key_policy` Keyring, existing `keys` and a measured
`verify_rows_per_second`. A restored source may include its explicit third tuple
element, the restore binding. This is maintenance onboarding of an empty scope,
not automatic authorization of a signup request or tenant moves during capture.

```python
proposal = protection.plan_tenant(
    owner_engine, deployment=(source, active_pin), keys=tenant_keys,
    tenant_id=approved_tenant_id, key_policy=approved_tenant_keyring,
    verify_rows_per_second=measured_verify_rate,
)
successor = proposal.activation_plan  # Retain before publication or effects.
progress = protection.provision_tenant(
    owner_engine, proposal=proposal, deployment=(successor, prepared_pin),
    keys=tenant_keys, approval=maintenance_approval,
)
```

The exact successor must match the proposal. Preparation fences writers and
preserves ciphertext while leaving publication PENDING. `status` observes that
successor; `apply(..., until="ACTIVE")` uses its matching ACTIVATING pin. Retire
the old attached engine/factory and restart with a fresh registry and engine bound
to the new policy; new attachments refuse a stale deployment pin. Existing workers retain their
original authority until the host drains/stops them; automatic cross-process
fencing is not supplied. No attachment is silently upgraded.
After removal, restart with ordinary native mappings as well; an attached registry
is not converted back into a plaintext application mapping in place.

Before activation, `abort_tenant` accepts the proposal, republished source ACTIVE
deployment, source `keys` and maintenance approval. It does not require the
unpublished tenant's custody. Existing nonempty scopes, wrong contexts/pins,
stale data, changed intent and missing authority refuse. The
[tenant maintenance contract](lifecycle.md#add-an-empty-tenant-policy-under-maintenance)
defines the full verification and retained-custody limits.

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

## Modify active fields

To enable or disable equality/IN search on already protected TEXT/VARCHAR or finite NUMERIC fields,
create a new configuration with the updated manifest. Enabling requires the
search review and leakage acceptance. Disabling sets `queries: []` and
`accept_leakage: []` and removes that field’s search review; uniqueness changes
are refused. Remove disabled predicates from the application’s query samples.
Existing key policies and retained-backup obligations remain unchanged.
The [modification contract](lifecycle.md#enable-exact-search-on-active-encrypted-text)
defines the bounded change and retained host responsibilities. Keep the optional
`queries` tuple: planning checks those SELECT structures against the proposed
target lock before database access or key resolution. Samples are never executed,
and their literals do not enter the retained proposal. Unsupported structures or
unavailable inspection refuse planning; admitted structure is not complete route
coverage or proof of runtime parameter validity.

```python
proposal = changed.plan_modification(
    owner_engine, deployment=current_deployment, keys=tenant_keys,
    backfill_rows_per_second=measured_backfill_rate,
    verify_rows_per_second=measured_verify_rate,
    temporary_bytes_per_row=measured_temporary_cost,
    wal_bytes_per_row=measured_wal_cost,
)
# Retain proposal and obtain its exact PREPARED host pin.
changed.prepare_modification(
    owner_engine, deployment=proposal_deployment,
    keys=tenant_keys, approval=maintenance,
)
successor = changed.seal_modification(
    owner_engine, deployment=proposal_deployment,
    keys=tenant_keys, approval=maintenance,
    copy_rows_per_second=measured_copy_rate,
    copy_wal_bytes_per_row=measured_copy_wal,
)
# Retain successor before cutover; obtain its exact PREPARED host pin.
changed.switch_modification(
    owner_engine, proposal=proposal, deployment=successor_deployment,
    keys=tenant_keys, approval=maintenance,
)
```

Inspect preparation with `changed.status`; repeat `prepare_modification` to resume.
After cutover, publish the successor through the existing ACTIVATING → ACTIVE
sequence and attach with `changed`. A database phase does not publish host
authority. To cancel preparation before cutover, call `changed.abort_modification`
with the proposal, source keys, maintenance approval and explicitly republished
source ACTIVE deployment. Normal current-value removal remains available after
activation. This route does not implement arbitrary schema or package upgrades.

Saved modification proposals can be inspected with the same read-only
[`cryptalis status` command](walkthrough-migration.md#inspect-rotation-preparation).
Recorded progress is not fresh verification or publication authority.

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
