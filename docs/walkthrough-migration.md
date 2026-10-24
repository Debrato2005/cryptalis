# Protect an existing text column

**IMPLEMENTED research prototype.** No production provider or independent review exists.
All seven gates remain UNKNOWN. Use the authorized disposable PostgreSQL 16 cell.

1. Keep the native text mapping as `Text`, `String(n)`, or `VARCHAR(n)`. Assign primary keys in the application.
2. Declare tenancy, protected fields, query leakage, writers, and searchable value domains.
3. Use owner maintenance and restricted runtime roles. Approve measured costs and pause.

Use distinct owner and runtime roles. Initial planning, ACTIVE and restored
connection checks, and the shared maintenance executor reject unsafe effective privileges.
The runtime cannot create objects in the database or declared schemas, assume
the owner, or hold administrative role attributes. It cannot hold TRIGGER or
TRUNCATE privileges on protected tables. Tables and journal retain the planned
owner. Runtime CRUD on protected data remains admitted through the attachment.
The journal permits runtime SELECT only. Table-level mutation grants and
column-level INSERT, UPDATE, or REFERENCES grants cause `unsafe_runtime_role`.
Protected-column grant drift during restore causes `source_metadata_changed`.
Correct the role or grant configuration before retry.

```python
from cryptalis.migration import plan, apply, MaintenanceApproval
from cryptalis.sqlalchemy import attach
from cryptalis.doctor import preflight

report = preflight(manifest_bytes, Base.registry, owner_engine,
    writers=writer_inventory, search_reviews=domain_reviews)
print(report)
if report["checks"]["manifest_schema"] != "PASS":
    raise SystemExit("Resolve the Doctor issues before planning protection.")

p = plan(manifest_bytes, Base.registry, owner_engine,
    writers=writer_inventory, search_reviews=domain_reviews,
    keys=tenant_keyrings, runtime_role=runtime_role, target_id=deployment_target_id,
    backfill_rows_per_second=measured_backfill_rate,
    verify_rows_per_second=measured_verify_rate,
    temporary_bytes_per_row=measured_storage_cost, wal_bytes_per_row=measured_wal_cost)
print(p)  # Estimated pause from native row count and the supplied measured rates.
approval = MaintenanceApproval(writer_exclusion_evidence, approved_pause_seconds)
options = dict(keys=tenant_keyrings, pin=prepared_pin, approval=approval)
apply(p, owner_engine, **options)  # Switch database; return PENDING.
```

The Python pre-adoption Doctor reuses the compiler's read-only catalog inspection.
It reads no application values and resolves no keys. Known declaration or schema
incompatibilities return FAIL with issue codes, locations and remedies.
Unavailable inspection returns UNKNOWN. Schema compatibility can pass while the
overall report and uninspected provider, query and operational checks remain UNKNOWN.
The report supplies no deployment authority. The [pre-adoption CLI](#diagnose-before-adoption)
uses this same compiler. ACTIVE diagnosis retains its separate deployment scope.

`plan` changes no schema or data. It rejects incompatible keys, types, tenancy, and search domains.
Save `p.artifact` and the authenticated current pin outside restore; bind target, operation, digest, and phase. The host supplies pin provenance.
Stop and drain known workers. Exclude all alternate writers with owner or DDL credentials.
The journal is progress evidence. Never reconstruct current authority from a restored journal.

Expand installs bytea shadows, indexes, and durable per-table maintenance triggers. Tables in one schema share the operation guard function.
Runtime writes during maintenance fail with SQLSTATE `55000`; callers must roll back and retry later. Concurrent plaintext commits are refused.
Backfill commits each bounded chunk with its marker. Resume with the same artifact and current pin.
Committed chunks retain their ciphertext. Failed chunks leave neither rows nor markers partially changed.
Verification decrypts every value and checks source equality, types, NULLs, membership, generations, and schema.
Default apply verifies and switches in one transaction. A saved VERIFIED checkpoint is checked again on resume.
Explicit `verify` adds a pass. The pause estimate excludes extra passes, drain, DDL, index build, and publication delay.

Plain reads continue during verification; writes and locking reads wait. DDL can pause reads after its lock is granted.
Strong locks retry three 100 ms attempts with 50 ms gaps; exhaustion reports `table_lock_busy_retry`. Other lock waits retain the 5 s default.
The default switch drops the original column and renames the ciphertext shadow.
The [explicit public-slot layout](#select-public-slot-preservation) converts the original
attribute instead. Neither layout keeps a live plaintext rollback mirror.
**Plaintext-at-rest remains possible:** dropped-column bytes can remain in heap tuples, WAL, snapshots, and backups.
`DROP COLUMN` is not erasure ([PostgreSQL 16](https://www.postgresql.org/docs/16/sql-altertable.html)). Retain recovery dependencies until explicit finalization.
The separate decrypt-back path restores current values. See [lifecycle](lifecycle.md#deprotect-and-remove).

Publish the exact artifact through the trusted host deployment tool while writers stay stopped.
Supply its `ACTIVATING` pin to `apply(..., until="ACTIVE")` to acknowledge publication and remove the fence.
Record the `ACTIVE` pin outside snapshots and restart fresh workers:

```python
sessions = attach(Base.registry, runtime_engine, lock=p.lock_bytes,
    keys=tenant_keyrings, deployment=(p, active_pin))
```

Startup rejects stale pins, schema mismatches, owner credentials, and unplanned tenant key policies.
`apply`, `verify` and `abort` require maintenance approval before connection or locks.
Read-only `plan`, `status`, `diagnose_deployment`, `check_deployment`, and
supplied-connection `check_attachment` are exempt.
Before switch, `abort` restores native writes and retains the journal; it cannot undo cutover.
Run tests through `scripts/test_postgres.py`; it reloads both private files and probes both roles.
Protection admits one initial operation per schema. Root rewrap adds an exact
successor chain. General journal reuse remains unfinished.
[Evidence](status.md) records tests, costs, and limits.

## Use the optional SQLModel bridge

Use the `sqlmodel` extra from a locally built wheel in an isolated application environment.
Use the same SQLAlchemy registry for planning and attachment.
The host still supplies the trusted lock, active deployment pin, key policy and authenticated tenant UUID.

```python
from cryptalis.sqlmodel import attach as attach_sqlmodel
from sqlmodel import select

sessions = attach_sqlmodel(mapping, runtime_engine, lock=p.lock_bytes,
    keys=tenant_keyrings, deployment=(p, active_pin))
with sessions(tenant_id=tenant_uuid) as session:
    user = session.exec(select(User).where(User.id == record_id)).one()
```

The optional bridge supports SQLModel 0.0.48 with synchronous PostgreSQL only.
It preserves native SQLModel validation, client defaults, NULL, refresh and
`Session.exec` result shapes in the tested cell. Missing dependencies, other
versions and async engines refuse before connection or key work.
The [pinned template checkpoint](status.md#optional-sqlmodel-template-checkpoint-2026-10-23)
covers unchanged CRUD modules for one storage-only field.
HTTP routes, authentication, full startup and deployment remain outside that checkpoint.

## Diagnose before adoption

**IMPLEMENTED, bounded:** supply the protection declaration, private inspection
connection file and an explicit trusted host factory:

```console
cryptalis doctor --pre-adoption cryptalis.json --host-context myapp.cryptalis_config:context --database-url-file /private/owner-connection.txt --json
```

The host module must already be importable in the application's environment.
Its synchronous zero-argument factory returns exactly
`(Base.registry, writer_inventory, domain_reviews)`, where `writer_inventory`
is a `WriterInventory` and `domain_reviews` is a tuple of `SearchReview` records.
Use the same explicit declarations as planning. Supply no engine or keys through
this tuple. The CLI owns its inspection connection and cleanup.
Keep the mapped application classes alive, as ordinary module-level models.
A registry uses weak references and cannot retain function-local model classes alone.

Importing the module and calling its factory executes trusted application Python.
The command does not sandbox that code or inspect its effects. It discards Python
stdout/stderr during loading; native descriptor writes remain a host responsibility.
The report states `host_configuration_effects: UNKNOWN` and scopes `effects: NONE`
to `compiler_inspection`. Do not load an untrusted module.

The compiler inspects a read-only repeatable-read snapshot without application
values or keys. Exit 0 means the manifest/schema check passed. Overall status and
unobserved provider, route and operational checks remain UNKNOWN. Schema refusal
exits 3 with issue codes, locations and remedies. Unavailable inspection, loader,
cleanup or output exits 4 with safe diagnostics. Invalid inputs exit 2.
Mixed pre-adoption and ACTIVE inputs refuse before host loading or connection.

## Diagnose an active deployment

**IMPLEMENTED, bounded:** Doctor checks one existing active runtime deployment.
It accepts an immutable `MigrationPlan`, its exact ACTIVE pin, and a private
connection file for the declared runtime role. Reverse plans and rotation
preparation P artifacts are outside this command's scope.

```bash
cryptalis doctor plan.json --pin current-pin.json --database-url-file /private/runtime-connection.txt --json
```

For an adopted target, add `--restore-binding binding.json`. The binding must
match the source plan. Doctor admits the plan, ACTIVE pin, and optional binding
before connection. It then uses the existing attachment admission checks in
one read-only, repeatable-read transaction. These checks compare the actual
runtime identity, target, lineage, effective privileges, and protected schema.
Use runtime credentials; maintenance credentials do not satisfy this check.
The [input limits below](#inspect-committed-progress) also apply to Doctor.

Success reports `scope: active_runtime_deployment`, overall `status: UNKNOWN`,
and `checks.runtime_deployment: PASS`. These six checks remain UNKNOWN:
`provider_keys`, `frame_authentication`, `query_routes`, `writer_exclusion`,
`host_authority`, and `recovery_capacity`.
The report also gives `effects: NONE`, `verification: NOT_PERFORMED`, and
`authority: HOST_SUPPLIED_PIN`. Doctor uses no keys, authenticates no frames,
and does not repeat a rotation's frozen cutover proof. Later valid ACTIVE
edits remain admitted. The supplied pin does not authenticate its own publication.

Exit 0 means the scoped runtime check passed. It does not promote UNKNOWN
checks to PASS. Invalid or denied input returns 2. An observed deployment
mismatch returns 3. An unavailable connection, cleanup, or output returns 4.
Failures use the standard stderr error envelope. `error.checks` reports a
runtime deployment FAIL for an observed mismatch, or UNKNOWN when inspection
could not finish. Diagnostics omit credentials and raw driver error text.

Inspection failures include the selected plan's public `operation_id` in JSON
and text output. Known role and pin failures also include `remedy`. Use the
planned runtime role for `attachment_requires_planned_runtime_role`. For
`unsafe_runtime_role`, remove the reported unsafe authority while retaining
required application CRUD. For `external_policy_mismatch`, get the current pin
from the trusted host authority. Do not edit artifacts to bypass that refusal.
Other inspection codes retain the generic reason. Cleanup failures also include
the operation UUID. These diagnostics do not prove that a remedy succeeded.

The Python API returns `None` on success and raises `TransitionFailure` on refusal:

```python
from cryptalis.migration import diagnose_deployment

diagnose_deployment(p, runtime_engine, pin=active_pin)
# For an adopted target: diagnose_deployment(p, runtime_engine, pin=active_pin, restore=binding)
```

Current effective grants can change after this observation. Doctor does not
freeze administrative changes, exclude independent writers, or qualify a
production deployment. [Status](status.md) owns executable evidence and limits.

## Inspect committed progress

Save the exact plan artifact and current pin through the trusted host process.
Keep the authenticated current pin outside database snapshots.
The pin JSON has exactly four members: `target_id`, `operation_id`, `plan_digest`,
and `phase`. The two IDs are nonzero UUID strings. The digest identifies the exact
plan bytes. The phase describes current external deployment policy.
Copying fields from a journal does not authenticate that policy.

Use a private regular file for the connection string. The command reads that file
and does not select credentials from inherited Cryptalis test variables.
Plan and restore-binding files each have a 16 MiB limit.
Pin and connection files each have a 64 KiB limit.

The output reports `scope: protection_transition`, committed counts, both phases,
and `runtime_metadata_matches`. It always reports `verification: NOT_PERFORMED`,
`authority: HOST_SUPPLIED_PIN`, and `effects: NONE`.
Exit 0 means ACTIVE metadata matches the supplied ACTIVE pin.
Exit 2 means invalid or denied input. Exit 3 means incomplete or uncertain state.
Exit 4 means an operational, cleanup, or output failure.
The command never advances a transition or publishes policy.
ACTIVE and PENDING inspection repeat the shared effective runtime privilege
checks. Status can use an inspection connection; Doctor additionally requires
the actual declared runtime identity. Both remain metadata observations.

For an approved restored target, add `--restore-binding binding.json`.
The binding supplies target and restored-state evidence. The source plan and
current external pin still supply their original identities.
The command does not replace recovery approval or fresh data verification.

```bash
cryptalis status plan.json --pin current-pin.json --database-url-file /private/connection.txt --json
```

```python
from cryptalis.migration import status

observed = status(p, owner_engine, pin=active_pin)
assert observed.verification == "NOT_PERFORMED"
```

### Inspect rotation preparation

**IMPLEMENTED, bounded:** the same command accepts preparation proposal P in
either exact format: `cryptalis.payload-rotation/v1` or
`cryptalis.search-rotation/v1`. It calls the existing
`rotation.status_payload_rotation` or `rotation.status_search_rotation` API.

```bash
cryptalis status payload-preparation.json --pin preparation-pin.json --database-url-file /private/connection.txt --json
cryptalis status search-preparation.json --pin preparation-pin.json --database-url-file /private/connection.txt --json
```

Supply the pin for that exact P: its operation ID and digest identify P, and
its target ID identifies the source target. The admitted external phases are
PREPARED, EXPANDED, and BACKFILLED. This preparation pin does not authorize
application publication. Recorded phases are PREPARED, EXPANDED, BACKFILLED,
or ABORTED. No P row exists yet in PREPARED. Cutover to the sealed successor
supersedes P; inspect the successor artifact after cutover.

Output uses `scope: payload_rotation_preparation` or
`scope: search_rotation_preparation`, with P's `operation_id` and its
`source_operation_id`. Every admitted recorded phase returns exit 3,
`runtime_metadata_matches: false`, and `verification: NOT_PERFORMED`.
`effects: NONE` and `authority: HOST_SUPPLIED_PIN` remain explicit.
BACKFILLED reports recorded progress, not fresh frame authentication or
deployment admission. ABORTED reports the retained committed counters.

Inspection uses one read-only, repeatable-read transaction. It checks the
source runtime's effective privileges in every recorded phase. It uses no
keys and acquires no maintenance table or advisory locks. It does not stage,
seal, switch, publish, or cancel an operation.

A wrong P identity or unsupported external phase fails before connection
with `payload_operation_pin_mismatch` or `search_operation_pin_mismatch`
and exit 2. An EXPANDED or BACKFILLED pin with no P journal row fails with
`missing_payload_operation` or `missing_search_operation` and exit 3.
The command refuses `--restore-binding` for P before reading the binding or
connecting. A lineage-bearing payload proposal already embeds its source; it does
not accept a separate restore binding. Search rotation with lineage requires the
[published-source route](#rotate-search-keys-after-adopted-lineage). Doctor also
refuses preparation artifacts. The common input limits and safe operational
failure handling apply. [Status](status.md) owns evidence and remaining gaps.

### Inspect decrypt-back and removal

Use the exact reverse plan and current reverse pin with the same command:

```bash
cryptalis status reverse-plan.json --pin reverse-pin.json --database-url-file /private/connection.txt --json
```

The Python API is `cryptalis.deprotection.status(reverse_plan, engine, pin=reverse_pin)`.
Output uses `scope: reverse_transition` and adds `source_operation_id`.
Exit 0 means native metadata matches the supplied `PLAINTEXT_ACTIVE` or `REMOVED` pin.
It does not establish fresh value verification, key availability, or deployment admission.

The reverse artifact already records its approved restore binding, when applicable.
An optional `--restore-binding` must match that recorded binding exactly.
After journal retirement, `committed_rows` and `committed_chunks` are null in JSON
and UNKNOWN in text. The native schema and captured metadata must still match.
An absent journal under an earlier pin fails explicitly.
The command requires no keys or plaintext/removal approval because it makes no transition.

Reverse planning requires a distinct plaintext runtime role with the same safe
effective privileges as the protected runtime. It checks both roles before key
work. Keep the protected role safe through PLAINTEXT_PENDING. After the host
publishes plaintext and supplies PLAINTEXT_ACTIVATING, keep the declared
plaintext role safe through journal retirement. Reverse execution and keyless
status select the role from that host pin. A journal phase cannot change it.

Repair `unsafe_runtime_role` failures in the protected role. Repair
`unsafe_plaintext_runtime_role` failures in the selected plaintext role.
These failures deny staging or resume without advancing plaintext progress.
An admitted ABORTED retry remains idempotent and needs no keys.

With the authenticated REMOVED pin and an actually absent journal, terminal
remove, status, and removal inspection check native metadata and object absence.
They do not require either former runtime privilege boundary. Later ordinary
native edits remain intact. If the journal still exists, REMOVED does not bypass
plaintext-role safety or establish completed removal. Status continues to
report `NOT_PERFORMED`, rather than fresh value verification.

## Change root-wrapping custody

This bounded API changes wrapping custody while retaining the same payload and
search roots. Payload-key rotation and search reindex remain separate work.
The host prepares an inactive target key policy and retains both complete policies
for recovery. A local fixture provider supplies test evidence only.

Use the current ACTIVE source plan, its authenticated pin, and both key factories.
Measure verification throughput before setting the pause approval.

```python
from dataclasses import replace
from cryptalis import migration
from cryptalis.rotation import plan_rewrap, apply_rewrap

proposal = plan_rewrap(source_plan, owner_engine, source_pin=source_pin,
    keys=source_keys, target_keys=target_keys,
    verify_rows_per_second=measured_verify_rate)
successor = proposal.activation_plan
prepared = migration.DeploymentPin(successor.target_id, successor.operation_id,
    successor.digest, "PREPARED")
approval = migration.MaintenanceApproval(writer_exclusion_evidence,
    approved_pause_seconds)

apply_rewrap(proposal, owner_engine, keys=source_keys,
    target_keys=target_keys, pin=prepared, approval=approval)
```

Save the proposal and successor artifact through the trusted host process.
Deploy the reader for transition/v2 ordinary successors or transition/v5 adopted successors before publication.
Stop and drain all writers before execution.
The transaction rechecks both policies and every frame, installs writer guards,
records the successor as PENDING, and marks the source SUPERSEDED.
It preserves payload bytes, search bytes, and existing indexes.

Publish the exact successor artifact and target wrapped policies outside PostgreSQL.
Keep writers stopped until activation succeeds.
Then acknowledge that publication through the shared executor:

```python
migration.apply(successor, owner_engine, keys=target_keys,
    pin=replace(prepared, phase="ACTIVATING"), approval=approval, until="ACTIVE")
active_pin = replace(prepared, phase="ACTIVE")
# Attach fresh application workers with target_keys and (successor, active_pin).
```

After an uncertain commit, inspect the saved successor with `migration.status`.
Resume `apply_rewrap` with the same proposal and a matching PREPARED or PENDING pin.
Resume publication acknowledgement with the matching ACTIVATING pin.
Keep the host pin consistent with the actual publication phase.
To cancel a PENDING rewrap, keep writers stopped and republish the exact source
ACTIVE pin through the trusted host process. A saved stale pin alone supplies
no current authority. Then use the original proposal and source keys:

```python
from cryptalis.rotation import abort_rewrap

aborted = abort_rewrap(proposal, owner_engine, keys=source_keys,
    pin=republished_source_active_pin, approval=approval)
assert aborted.phase == "ABORTED"
```

Cancellation needs no target-provider call. It authenticates source policy and
current data before atomically restoring the source journal and removing guards.
The successor remains ABORTED and cannot activate. Inspect the source plan with
`migration.status` and its current ACTIVE pin. A terminal cancellation retry
inspects source authority without restoring old data or repeating a stale scan.
An ACTIVE successor requires a new rewrap, rather than cancellation.
Retain predecessor artifacts and both custody policies for retained backups.
Successful cutover does not authorize key deletion or establish stronger revocation.

For the first root rewrap after adoption, pass the exact `restore=binding` to
`plan_rewrap` above. The saved rewrap/v2 proposal retains that binding.
Publish its transition/v5 successor with its own current pin and target policies.
Attach fresh workers with `(successor, active_pin)`. The old source binding cannot
replace successor authority.

For a later rewrap from a published v5 or v6 source, omit `restore` or pass `restore=None`.
The source artifact carries the inherited lineage. Keep the same publication steps.
A PENDING retry uses the saved successor, not the superseded source's former ACTIVE digest.

To cancel, republish the original source ACTIVE pin and use the original proposal.
That proposal retains the original restore binding. Supply source keys only.
Cancellation restores the exact original adopted source journal and removes
successor guards atomically. It needs no target provider. Terminal retries
preserve later edits and cannot revive a superseded source.

The [17 fresh-target source controls](_reset/fresh-cluster-restore-20261024-4.json)
pass. Source VARCHAR and installed-wheel TEXT profiles also pass 17 each.
Status records the full primary and installed application regression boundaries.
The [lifecycle](lifecycle.md#adopted-target-root-rewrap-2026-10-24) and
[format decision](decisions.md#adopted-target-root-rewrap-2026-10-24) own the
full contract. [Status](status.md#adopted-target-root-rewrap-2026-10-24)
owns exact evidence and limits.

The existing fresh-cluster harness has separate root-rewrap profiles:

```bash
.venv/bin/python scripts/fresh_cluster_qualification.py --rewrap
.venv/bin/python scripts/fresh_cluster_qualification.py --rewrap --varchar
.venv/bin/python scripts/fresh_cluster_qualification.py --adopted-rewrap
.venv/bin/python scripts/fresh_cluster_qualification.py --adopted-rewrap --varchar
```

These use approved disposable PostgreSQL 16 targets through `scripts/test_postgres.py`.
They do not qualify a production provider or host publication service.

## Plan payload-key rotation

Prepare the inactive target policy through the trusted host process. Retain every
exact source wrapper and add one independent payload root above all retained
payload generations. Keep search custody unchanged. Retain backup dependencies.

```python
from cryptalis.rotation import plan_payload_rotation

proposal = plan_payload_rotation(source_plan, owner_engine,
    source_pin=current_source_active_pin, keys=source_keys, target_keys=target_keys,
    backfill_rows_per_second=measured_backfill_rate,
    verify_rows_per_second=measured_verify_rate,
    temporary_bytes_per_row=measured_temporary_cost,
    wal_bytes_per_row=measured_wal_cost,
    max_batch_rows=1000, max_batch_bytes=64 * 1024 * 1024)
print(proposal)
costs = proposal.document["estimates"]  # Review temporary storage, WAL and provider estimates.
```

This call authenticates a read-only snapshot. Current source writers remain
admitted. The artifact pins source frames and membership, public root contexts,
operation identities, logical limits and cost estimates. It contains no roots,
wrapped bytes or plaintext digest. Provider preparation can incur external costs.
The estimate includes backfill and three verification passes. Lock drain, DDL,
index build, publication and capacity guarantees remain outside the estimate.

The logical byte budget includes source/target frames, decoded UTF-8 and native
identities across all fields. It excludes Python, driver, database and provider
overhead. A single oversized row fails before frame retrieval.

## Stage or cancel payload-key rotation

Save the exact proposal P through the trusted host process.
Stop known writers and exclude owner or DDL writers before expansion.
Keep source and target policies available for resumable preparation.
Use P's operation ID and digest for its preparation pin.
This pin does not select an application deployment.

```python
from cryptalis import migration
from cryptalis.rotation import (
    apply_payload_rotation, status_payload_rotation, abort_payload_rotation,
)

preparation_pin = migration.DeploymentPin(
    source_plan.target_id, proposal.operation_id, proposal.digest, "PREPARED")
approval = migration.MaintenanceApproval(
    writer_exclusion_evidence, approved_pause_seconds)

progress = apply_payload_rotation(proposal, owner_engine,
    keys=source_keys, target_keys=target_keys, pin=preparation_pin,
    approval=approval, max_chunks=1)
observed = status_payload_rotation(proposal, owner_engine, pin=preparation_pin)
assert observed.verification == "NOT_PERFORMED"
```

The executor keeps public source frames and their original journal unchanged.
It adds separate ciphertext shadows, guards, and a journal row for P.
It holds write-excluding locks across size probes, frame reads, updates, and each
cursor commit. Each completed chunk retains its ciphertext on resume.
The source schema now contains staging objects. Ordinary attachment therefore
cannot admit it as an unchanged ACTIVE schema. Keep writers stopped.

Resume with the same proposal, policies, and current preparation pin.
Without `max_chunks`, the default call continues to BACKFILLED.
A bounded call can report EXPANDED after its last data chunk.
Another call performs the terminal check. BACKFILLED requires full source and
target authentication, exact generations, equal values and NULLs, unchanged
search headers, and source observations that match P. BACKFILLED retries repeat
this check. Status reports recorded progress without data verification.

To cancel, keep writers stopped and republish the source ACTIVE pin through the
trusted host process. Then use source keys only:

```python
aborted = abort_payload_rotation(proposal, owner_engine, keys=source_keys,
    source_pin=republished_source_active_pin, approval=approval)
assert aborted.phase == "ABORTED"
```

Cancellation authenticates the source and checks exact shadows and guards.
It removes only those objects and commits P's ABORTED marker atomically.
The target provider can remain unavailable. Terminal cancellation retries
preserve later source edits. A later operation that supersedes the source
prevents an old cancellation from reviving it.

After an uncertain commit, inspect the original operation through
`status_payload_rotation`. Resume only after the original transaction is terminal.
Keep the saved proposal and policies. An absent marker alone does not establish
rollback. The [adopted-lineage route](#rotate-payload-keys-after-adopted-lineage)
uses a published successor. The [direct-binding route](#plan-generation-rotation-from-a-restore-binding)
uses the original source and explicit binding.

The byte budget is a logical bound across complete rows and fields, not a
process resident-memory limit. P cannot enter `migration.apply` or authorize
publication.

## Seal and publish payload-key rotation

Complete preparation before sealing. Use the current preparation pin and both
saved policies. Supply measured native copy throughput and WAL bytes per row:

```python
from dataclasses import replace
from cryptalis.rotation import seal_payload_rotation, switch_payload_rotation

backfilled = apply_payload_rotation(proposal, owner_engine,
    keys=source_keys, target_keys=target_keys, pin=preparation_pin, approval=approval)
assert backfilled.phase == "BACKFILLED"
activation = seal_payload_rotation(proposal, owner_engine,
    keys=source_keys, target_keys=target_keys, pin=preparation_pin, approval=approval,
    copy_rows_per_second=measured_copy_rate,
    copy_wal_bytes_per_row=measured_copy_wal_cost)
print(activation)
```

Sealing holds maintenance locks, authenticates P's source, and compares all staged
target values, generations, NULLs, and search headers. It makes no database
changes. Provider preparation can incur audit/cost effects. Repeated sealing
with identical staged bytes and costs produces identical A. A binds P and
actual target ciphertext observations. P reserves A's operation ID without
embedding its digest. Without restore lineage, deploy a transition/v3-capable
reader before publication. The [adopted-lineage route](#rotate-payload-keys-after-adopted-lineage)
requires v6-capable readers.

Persist exact P and A outside the database through the trusted host process.
Review A's costs and approve the terminal write pause separately. Keep writers
stopped. The following pin records the reviewed A identity. Pin provenance and
current publication authority still come from the trusted host process.

```python
activation_pin = migration.DeploymentPin(
    activation.target_id, activation.operation_id, activation.digest, "PREPARED")
activation_approval = migration.MaintenanceApproval(
    writer_exclusion_evidence, approved_activation_pause_seconds)
pending = switch_payload_rotation(proposal, activation, owner_engine,
    keys=source_keys, target_keys=target_keys, pin=activation_pin,
    approval=activation_approval)
assert pending.phase == "PENDING"
```

The switch repeats paired verification against P and A. A server-side UPDATE
copies the exact target ciphertext into existing public columns. It preserves
column identities, constraints, expression indexes, grants, and metadata.
It removes P's shadows and exchanges P's guards for A's guards. Source
SUPERSEDED to P, P SUPERSEDED to A, and A PENDING commit together. A fresh
bounded target pass checks copied frames against A before commit. No search
reindex occurs. P preparation and cancellation now refuse SUPERSEDED.

A estimates one atomic copy plus five authentication passes. These comprise
one source pass, both sides of the paired source/target comparison, one
post-copy target pass, and one publication target pass. Prior staging and
sealing, lock drain, DDL, provider overhead, and capacity guarantees remain
outside the estimate. The final full-table write uses one transaction.
Preparation chunk limits do not bound that write, its WAL, or process memory.

The owner can inspect recorded copy measurements from the exact A journal row:

```python
from sqlalchemy import text

quote = owner_engine.dialect.identifier_preparer.quote_identifier
journal = f"{quote(activation.document['journal_schema'])}.{quote('_cryptalis_journal')}"
statement = text(f"SELECT state -> 'cutover_measurements' FROM {journal} "
                 "WHERE operation_id = :operation_id AND plan_digest = :plan_digest")
with owner_engine.connect() as connection:
    measurements = connection.execute(statement, {
        "operation_id": activation.operation_id,
        "plan_digest": activation.digest,
    }).scalar_one()
print(measurements)
```

`copy_wall_ns` measures native wall time around the copy loop.
`copy_wal_bytes_cluster_delta` records the cluster-wide WAL change around that
loop. Other cluster transactions can contribute WAL. This window excludes
later DDL, verification, commit, and publication. These observations establish
no total pause, isolated WAL cost, capacity bound, or external authority.
`migration.status(activation, ..., pin=current_activation_pin)` reports
`NOT_PERFORMED`. It supplies no fresh cryptographic proof.

Publish exact A and its target policies through the trusted host process.
Use the independently current ACTIVATING pin to acknowledge publication.
Restart application workers with fresh runtime engines and mapping state before
attaching A:

```python
migration.apply(activation, owner_engine, keys=target_keys,
    pin=replace(activation_pin, phase="ACTIVATING"),
    approval=activation_approval, until="ACTIVE")
active_pin = replace(activation_pin, phase="ACTIVE")
sessions = attach(Base.registry, runtime_engine, lock=activation.lock_bytes,
    keys=target_keys, deployment=(activation, active_pin))
```

Generic `migration.apply` accepts A only for ACTIVE publication with an
ACTIVATING or ACTIVE pin. It never expands a missing payload successor.
ACTIVATING checks target frames against A even if the journal already claims
ACTIVE. A genuine ACTIVE pin permits later application edits. Decrypt-back
and removal preserve those latest values.

After an uncertain switch, wait until the original transaction is terminal.
Inspect the exact saved P, A, and current host pin. A PENDING retry of
`switch_payload_rotation` authenticates target frames and reciprocal ancestry
against A. It does not compare the replaced source frames or call the separate
source resolver. Target custody still requires all retained roots. Missing A
with partially superseded ancestors is inconsistent. It cannot authorize
reconstruction of a commit or cancellation through P.

All seven full gates remain UNKNOWN. See [status](status.md) for current evidence.

## Rotate payload keys after adopted lineage

Use the current ACTIVE v5 rewrap or v6 payload successor as `source_plan` in the
payload workflow above. Supply that successor's own current pin and retained
policies. Do not supply the earlier restore binding as current authority.
Direct payload planning with `restore=binding` follows the
[separate v2 route](#plan-generation-rotation-from-a-restore-binding).

The saved preparation remains `cryptalis.payload-rotation/v1` and embeds the
complete source. Sealing produces transition/v6 with every v3 payload proof
member, unchanged flat restore lineage and inherited ancestors followed by source
and preparation. Deploy readers that admit both the embedded source and v6 before
publication. Keep the same staging, source-only cancellation, switch and separate
publication steps. Publish v6 with its own pin. Cancellation before switch needs
no target provider; terminal retries preserve later edits and cannot revive a
superseded source.

The harness has a separate adopted-payload profile:

```bash
.venv/bin/python scripts/fresh_cluster_qualification.py --adopted-payload
.venv/bin/python scripts/fresh_cluster_qualification.py --adopted-payload --varchar
```

It uses approved disposable PostgreSQL 16 targets through `scripts/test_postgres.py`.
The [TEXT run](_reset/fresh-cluster-restore-20261024-11.json) passes 12 controls,
including current-value publication, cancellation, refusal and recovery paths.
The separate original Smolink [source](_reset/fresh-cluster-export-20261024-13.json)
and [fresh-target](_reset/fresh-cluster-restore-20261024-12.json) stages pass through
adopted rewrap, payload generation 2 to 3, ASGI/JWT/Redis work, latest-value removal
and an import-denied restart. The [source VARCHAR profile](_reset/fresh-cluster-restore-20261024-13.json)
and [installed TEXT wheel](_reset/fresh-cluster-restore-20261024-14.json) also pass 12 each.
The installed Smolink [source](_reset/fresh-cluster-export-20261024-17.json)
and [fresh-target](_reset/fresh-cluster-restore-20261024-16.json) stages repeat
the original application journey. [Status](status.md#payload-rotation-after-adopted-lineage-2026-10-24)
records the full regression and exact artifact boundaries. Later search rotation
uses the [lineage-bearing route](#rotate-search-keys-after-adopted-lineage). External custody, authenticated host publication and all seven gates
remain unqualified or UNKNOWN. The [lifecycle](lifecycle.md#payload-rotation-after-adopted-lineage-2026-10-24)
and [format decision](decisions.md#adopted-target-payload-rotation-2026-10-24) own the contract.

## Recover a payload-rotation backup

Retain exact A, its current ACTIVE pin, the target policy with its retained
roots, and the required readers outside the database backup. Restore into
quarantine and fence the source through the trusted host process. Use existing
`restore.plan` with explicit `RestoreApproval`, then attach with `(A, pin, binding)`.
No new restore-binding format is required.

```python
from cryptalis.restore import RestoreApproval, plan as plan_restore

restore_approval = RestoreApproval(
    restore_host, restore_intent, quarantine_evidence, source_fenced=True)
binding = plan_restore(activation, restored_owner_engine,
    pin=current_activation_active_pin, keys=target_keys, approval=restore_approval)
sessions = attach(Base.registry, restored_runtime_engine,
    lock=activation.lock_bytes, keys=target_keys,
    deployment=(activation, current_activation_active_pin, binding))
```

Adoption checks source identity, ACTIVE progress, reciprocal ancestors,
effective runtime privileges, and protected-column grants before probes or
provider work. Missing source/P rows, forged links, and inconsistent A proof
fields fail admission. A valid backup can include ordinary edits after A's
publication. Adoption authenticates its current selected-generation frames.
It does not require the backup to equal A's original sealing hashes. A valid
older-generation frame and the original source policy remain refused.

The native fresh-cluster harness has a separate payload profile:

```bash
.venv/bin/python scripts/fresh_cluster_qualification.py --payload-rotation
.venv/bin/python scripts/fresh_cluster_qualification.py --payload-rotation --varchar
```

Select one fixture profile. The options are mutually exclusive. `--varchar` selects native VARCHAR(64). The harness
uses the approved disposable PostgreSQL 16 targets and `scripts/test_postgres.py`.
The payload fixture exports a backup after publication and a later protected
edit. It checks retained-policy recovery, independent generation-2 decoding,
valid generation-1 substitution refusal, adopted edits, decrypt-back/removal,
and native metadata restoration. See [status](status.md) for current receipts.

These controls do not qualify external custody, authenticated publication, or
source fencing. Rotation after adoption requires the separate
[lineage-bearing route](#rotate-payload-keys-after-adopted-lineage).
All seven full gates remain UNKNOWN.

## Search-key rotation contract

**IMPLEMENTED, bounded native verification:** the following APIs implement search
rotation through shared staging, cutover, and publication. [Status](status.md)
owns current receipts and their exact verification boundaries. Planning inputs
and maintenance controls parallel [payload rotation](#plan-payload-key-rotation).

Retain exact source wrappers and material, then add one independent search root
above all retained search generations. Keep the selected payload root unchanged.
Keep policies with no selected search generation unchanged. Searchable frames receive new terms
and fresh nonces. Storage-only frames retain their exact bytes.

| API | Required artifact and result |
|---|---|
| `plan_search_rotation` | Current source ACTIVE pin and both policies. Returns inactive SearchRotationPlan P, format `cryptalis.search-rotation/v1` |
| `apply_search_rotation` | P's operation pin and maintenance approval. Commits bounded encrypted chunks, then full paired verification for BACKFILLED |
| `status_search_rotation` | P and its pin. Reports recorded progress with `NOT_PERFORMED` and no fresh cryptographic proof |
| `abort_search_rotation` | Republished source ACTIVE pin and source keys. Cancels P before switch without target-provider access |
| `seal_search_rotation` | BACKFILLED P, both policies, P's pin, approval, and measured copy costs. Returns deterministic activation A from actual staged bytes |
| `switch_search_rotation` | Exact saved P and A, both policies, A's PREPARED/PENDING pin, and approval. Commits the database switch to PENDING |

A is a `cryptalis.transition/v4` MigrationPlan with `kind: search_rotation`.
Its proof fields are `search_rotation_plan_digest`,
`search_rotation_observations`, and `search_batch_limits`. Persist exact P and A
through the trusted host process before switch. P never authorizes publication.

Keep writers stopped through sealing, final paired proof, atomic native UPDATE,
and publication. The UPDATE maintains the existing expression and unique
indexes as it copies target ciphertext into the existing public columns.
Source-to-P-to-A supersession and guard exchange share the transaction.
A fresh target pass must match A before commit. PENDING retry authenticates
current target bytes against A, because source bytes no longer exist.

Supply measured `copy_rows_per_second` and `copy_wal_bytes_per_row` that include
all native index maintenance. The final full-table write and index updates use
one transaction. Preparation chunk limits do not bound that write. Storage
capacity, WAL, process memory, and pause ceilings remain unqualified.

Publish exact A and target policies, then acknowledge with
`migration.apply(A, ..., until="ACTIVE")` under the current ACTIVATING pin.
An ACTIVE pin also supports terminal inspection. ACTIVATING must authenticate
A's target proof even if the journal claims ACTIVE. A genuine ACTIVE deployment
permits later edits and latest-value decrypt-back/removal. Only one selected
search generation serves queries. Retained readers do not admit mixed-generation
OR queries.

### Recover a search-rotation backup

Use the existing restore approval and `RestoreBinding` path with the exact
search v4 A, its current ACTIVE pin, and retained target policy. The native
profile exports a backup after publication and a later edit to row 999.
That edit differs from A's sealed observations. Adoption authenticates current
generation-2 frames. The independent decoder checks the new search root and
HMAC while the payload root stays unchanged. A valid generation-1 frame and
the original source policy fail admission.

```bash
.venv/bin/python scripts/fresh_cluster_qualification.py --search-rotation
.venv/bin/python scripts/fresh_cluster_qualification.py --search-rotation --varchar
```

Choose one fixture profile. The options are mutually exclusive. `--varchar` selects native
VARCHAR(64). Both stages use the mandatory PostgreSQL credential wrapper.
The text profile completes adoption, current reads/search, later edits,
decrypt-back/removal, and native metadata checks. [Status](status.md) records
which profiles completed and preserves the exact receipts.

This evidence does not qualify external custody, authenticated publication, or
source fencing. Later search rotation uses the
[published lineage-bearing route](#rotate-search-keys-after-adopted-lineage).
The separate [payload route](#rotate-payload-keys-after-adopted-lineage) requires
a published lineage-bearing successor.
All seven full gates remain UNKNOWN.

## Rotate search keys after adopted lineage

Use the current ACTIVE v5/v6/v7 successor and its own pin in the search workflow
above. Preparation stays `cryptalis.search-rotation/v1`. Sealing adds the unchanged
flat restore lineage to all v4 proof members and emits `cryptalis.transition/v7`.
Keep the same source-only cancellation, atomic switch and separate publication
steps. Deploy compatible readers before publication. A historical binding cannot
replace the successor pin. Direct restore-binding generation planning follows its
[separate v2 route](#plan-generation-rotation-from-a-restore-binding).

```bash
.venv/bin/python scripts/fresh_cluster_qualification.py --adopted-search
.venv/bin/python scripts/fresh_cluster_qualification.py --adopted-search --varchar
```

These profiles use approved disposable PostgreSQL 16 targets through
`scripts/test_postgres.py`. All 11 native mixed-field controls pass.
Source VARCHAR, affected-suite and ordinary installed application checks also pass.
The installed TEXT wheel also passes all 11. [Status](status.md#search-rotation-after-adopted-lineage-2026-10-24)
records receipts and limits. The [lifecycle](lifecycle.md#search-rotation-after-adopted-lineage-2026-10-24)
and [format decision](decisions.md#adopted-target-search-rotation-2026-10-24) own
the contract. This adds no crypto, index, journal or authority format and grants
no key-retirement permission. All seven production gates remain UNKNOWN.

The separate original SQLModel searchable-application profile uses its pinned
schema, genuine backup adoption and root v5 before search v7:

```bash
.venv/bin/python scripts/fresh_cluster_qualification.py --sqlmodel-searchable
```

The original email CRUD/search controls, later edits and latest-value
removal/import-denied restart pass in source and installed-wheel runs.
User.full_name storage bytes and native index identities stay exact through
search rotation. Fixture-only single-tenant email admission remains required.
This profile does not add HTTP/JWT/SMTP, browser or deployment qualification.
See the [application checkpoint](status.md#original-searchable-sqlmodel-adoption-2026-10-24)
for exact receipts and the unchanged product boundary.

## Plan generation rotation from a restore binding

Add `restore=binding` to either existing generation-planner call. Keep the
original source, its ACTIVE pin and retained policies. The binding supplies
the evaluated target and recorded adoption, without rewriting source identity.
Persist the complete v2 proposal. Preparation status uses that embedded binding
and still refuses a separate CLI `--restore-binding` option.

Use the same staging, source-only cancellation, sealing, switch and separate
publication steps. Activation remains v6/v7 with inherited lineage plus the
explicit binding. Deploy v2 proposal readers before use. Existing activation
readers accept unchanged v6/v7 formats. All 19 source controls pass, including
CLI status and process/COMMIT recovery. Source VARCHAR, affected-suite and ordinary
installed application checks also pass. All 19 installed direct controls and
the original six-file SQLModel direct source/installed journey pass. Its legacy
installed path also passes. The
[lifecycle](lifecycle.md#generation-planning-from-a-restore-binding-2026-10-24),
[format decision](decisions.md#direct-restore-binding-generation-planning-2026-10-24)
and [status](status.md#direct-restore-binding-generation-planning-2026-10-24)
define the contract and evidence limits. All seven production gates remain UNKNOWN.

The local `--direct-generation` harness profile requires
`CRYPTALIS_PREVIOUS_READER_PYTHON` to name a trusted interpreter with the previous
2df0715a9d4e wheel installed. This supplies actual old-reader proposal refusal and
activation acceptance controls. The `--sqlmodel-direct-search` profile reuses the
pinned application snapshot required by `--sqlmodel-searchable`. It requires no
previous-reader interpreter and adds no HTTP/JWT/SMTP qualification.

## Preserve an admitted owned sequence

Deploy readers for lock/v5 and restore/v2 before sequence-bearing protection.
Keep record IDs application-generated. Keep protected server defaults absent.
Planning captures each admitted sequence's identity, configuration, owner and ACL.
The switch preserves that object through native ownership DDL. Do not reset its
counter to the captured start value. Native rollback gaps remain valid.

Keep the complete restore/v2 binding after fresh-cluster adoption. The restored
sequence has a new OID, which the binding maps from the source-effective identity.
Use that binding for attachment, direct generation planning or reverse planning.
Later inherited lineage retains its mapping. A changed OID, ownership, ACL or
configuration requires resolution before retry. Removal retains exact admitted
user sequences, including declared `_cryptalis_*` names. Other leftover objects refuse.

The revised query passes 201 source and 269 installed affected/application controls.
Source and installed fresh-target profiles each pass four. Both original six-file
SQLModel adoption paths pass with the installed wheel. The full source regression
also passes. The
[lifecycle contract](lifecycle.md#owned-sequence-preservation-and-restored-identity-2026-10-24),
[format decision](decisions.md#owned-sequence-metadata-and-restored-identity-2026-10-24)
and [status](status.md#owned-sequence-preservation-and-restore-2026-10-24) define the current scope.

## Select public-slot preservation

Pass `layout="preserve-public-slots/v1"` to `compile_protection()` or `migration.plan()`.
Deploy lock/v6 and restore/v3 readers first. Keep the complete restore/v3 binding
after adoption. Attachment, reverse and rotation derive the layout from the lock.
Do not treat a previous lock as an opt-in. Keep source artifacts and host pins unchanged.

Budget the heap rewrite, index work and native lock drain separately. Host
row-rate and WAL estimates exclude these costs. Retain the existing maintenance
approval and writer exclusion. Repair slot or catalog drift before retry.
Source TEXT/VARCHAR and installed sequence-bearing fresh-target controls pass.
The installed three-field SQLModel lifecycle and legacy compatibility profiles
also pass. The full source regression passes. The original three-field application
still needs fresh-v6/direct-binding qualification. Earlier formats retain DROP/RENAME behavior.
See the [lifecycle contract](lifecycle.md#public-column-slot-layout-2026-10-24)
and [recorded evidence](status.md#public-column-slot-preservation-2026-10-24).

## Measured throughput

Use positive finite integer or floating-point observations for measured rows per second.
The saved plan retains the supplied rates, including a rate below one row per second.
Pause estimates round the calculated time to whole seconds.
Protection, reverse, and generation-rotation plans accept their measured rate
fields after artifact reload. Payload and search activation also accept measured
`copy_rows_per_second`. Other numeric fields retain their integer-only format.
These estimates are planning observations, not pause limits or deployment qualification.

## Native VARCHAR mappings

Keep a native VARCHAR field mapped as `String(n)` or `VARCHAR(n)`.
Match the database character limit exactly. Use `String()` for unbounded VARCHAR.
Use standard `Text` for native PostgreSQL text. Custom type decorators, domains,
fixed-width `char`/`bpchar`, and dialect variants remain unadmitted.
Searchable fields require the admitted deterministic native C or implicit
database-default equivalence and explicit leakage acceptance. Source indexes
must use the same qualified collation. See [text admission](compatibility.md#query-semantics).
Storage-only VARCHAR fields can retain their native default collation.
The existing 16 MiB text-codec limit still applies.

VARCHAR assignment counts characters, rather than UTF-8 bytes.
When only excess ASCII spaces exceed the limit, the stored value loses those spaces.
A query value keeps its exact characters. Length validation never truncates query terms.
`VarcharLengthExceeded` carries SQLSTATE `22001` and requires session rollback.
It occurs before protected SQL sends any parameter to PostgreSQL.

Plans with VARCHAR require the v3 lock reader and `pg-varchar/v1`.
Historical text-only plans retain their existing readers and CF1 framing.
Decrypt-back restores the original native type and character limit.
Existing active text deployments do not receive an automatic type upgrade.

Sources: [PostgreSQL 16 character types](https://www.postgresql.org/docs/16/datatype-character.html)
and [SQLAlchemy 2.1 exception extensions](https://docs.sqlalchemy.org/en/21/core/exceptions.html#sqlalchemy.exc.DontWrapMixin).
