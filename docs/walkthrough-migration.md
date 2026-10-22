# Protect an existing text column

**IMPLEMENTED research prototype.** No production provider or independent review exists.
All seven gates remain UNKNOWN. Use the authorized disposable PostgreSQL 16 cell.

1. Keep the native text mapping as `Text`, `String(n)`, or `VARCHAR(n)`. Assign primary keys in the application.
2. Declare tenancy, protected fields, query leakage, writers, and searchable value domains.
3. Use owner maintenance and restricted runtime roles. Approve measured costs and pause.

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
Pre-publication rewrap abort and rewrap on an adopted restored target remain unsupported.
Keep writers stopped and inspect or resume the pending operation.
Retain predecessor artifacts and both custody policies for retained backups.
Successful cutover does not authorize key deletion or establish stronger revocation.

The existing fresh-cluster harness has separate root-rewrap profiles:

```bash
.venv/bin/python scripts/fresh_cluster_qualification.py --rewrap
.venv/bin/python scripts/fresh_cluster_qualification.py --rewrap --varchar
```

These use approved disposable PostgreSQL 16 targets through `scripts/test_postgres.py`.
They do not qualify a production provider or host publication service.

## Measured throughput

Use positive finite integer or floating-point observations for measured rows per second.
The saved plan retains the supplied rates, including a rate below one row per second.
Pause estimates round the calculated time to whole seconds.
Protection and reverse plan readers accept these rate fields after artifact reload.
Other numeric fields retain their integer-only format.
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
