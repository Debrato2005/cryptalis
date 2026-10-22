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
Switch drops the original column and renames the ciphertext shadow. There is no live plaintext rollback mirror.
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
Read-only `plan`, `status`, `check_deployment`, and supplied-connection `check_attachment` are exempt.
Before switch, `abort` restores native writes and retains the journal; it cannot undo cutover.
Run tests through `scripts/test_postgres.py`; it reloads both private files and probes both roles.
Protection admits one initial operation per schema. Root rewrap adds an exact
successor chain. General journal reuse remains unfinished.
[Evidence](status.md) records tests, costs, and limits.

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
Deploy the transition/v2 reader before publication.
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
Rewrap and cancellation on an adopted restored target remain unsupported.
Retain predecessor artifacts and both custody policies for retained backups.
Successful cutover does not authorize key deletion or establish stronger revocation.

The existing fresh-cluster harness has separate root-rewrap profiles:

```bash
.venv/bin/python scripts/fresh_cluster_qualification.py --rewrap
.venv/bin/python scripts/fresh_cluster_qualification.py --rewrap --varchar
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
rollback. Adopted restored targets remain unsupported.

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
embedding its digest. Deploy a transition/v3-capable reader before publication.

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

Preparation, sealing, and cutover on adopted restored targets remain unsupported.
All seven full gates remain UNKNOWN. See [status](status.md) for current evidence.

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

Select either `--payload-rotation` or `--rewrap`. The options are mutually
exclusive fixture profiles. `--varchar` selects native VARCHAR(64). The harness
uses the approved disposable PostgreSQL 16 targets and `scripts/test_postgres.py`.
The payload fixture exports a backup after publication and a later protected
edit. It checks retained-policy recovery, independent generation-2 decoding,
valid generation-1 substitution refusal, adopted edits, decrypt-back/removal,
and native metadata restoration. See [status](status.md) for current receipts.

These controls do not qualify external custody, authenticated publication, or
source fencing. Rotating payload keys on an adopted restored target remains
unsupported. Search rotation remains unimplemented. All seven full gates
remain UNKNOWN.

## Measured throughput

Use positive finite integer or floating-point observations for measured rows per second.
The saved plan retains the supplied rates, including a rate below one row per second.
Pause estimates round the calculated time to whole seconds.
Protection, reverse, and payload-activation plan readers accept their measured
rate fields after artifact reload. Payload activation also accepts measured
`copy_rows_per_second`. Other numeric fields retain their integer-only format.
These estimates are planning observations, not pause limits or deployment qualification.

## Native VARCHAR mappings

Keep a native VARCHAR field mapped as `String(n)` or `VARCHAR(n)`.
Match the database character limit exactly. Use `String()` for unbounded VARCHAR.
Use standard `Text` for native PostgreSQL text. Custom type decorators, domains,
fixed-width `char`/`bpchar`, and dialect variants remain unadmitted.
Searchable fields still require exact C equivalence and explicit leakage acceptance.
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
