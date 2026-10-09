# One transition engine

**SPECIFIED:** lifecycle contract. **IMPLEMENTED:** bounded product protection transition with plan/apply/verify and pre-switch abort.
Decrypt-back, removal and rotation remain unimplemented product slices. [Status](status.md) states the evidence limits.
The protection engine verifies and switches in one transaction; saved verification checkpoints require a fresh pass on resume.
Plain reads continue during verification. Writes and locking reads wait; schema DDL can pause all access.
VERIFIED paragraphs below describe recorded receipts, not current product qualification. All other requirements remain SPECIFIED.
Every protection change uses expand → backfill → verify → switch → contract.
Rollback, deprotect, search changes, and key transformations reuse this path.

**VERIFIED, recorded earlier lab:** the service lab passes 27 listed checks over 1,000 synthetic rows. It observes a blocked concurrent writer,
a process exit after a committed chunk, inspected idempotent resume, full verification mutants, CF1 companion transport,
payload/search rotation, and current-data decrypt-back. An isolated ordinary application then reads and updates the recovered data with Cryptalis/lab-reader imports blocked.
This is not the original application's complete retrofit/removal test. Post-commit process exit is not a transport-level lost COMMIT-reply test.
Live provider custody, authenticated deployment publication, retained-backup readers and full writer ownership remain unqualified.

## Integrated lifecycle checkpoint: 2026-10-07

The preceding 27-check lab is historical. The new [23-check receipt](../spikes/revamp/results/gate-lifecycle.json)
uses the original three-model application's actual CF1 data and one transition executor for protect, rotate and deprotect.
Chunk members and transformed rows commit together. Resume inspects the original digest/membership and preserves committed ciphertext.
**VERIFIED, recorded spike:** streaming verification checks membership, native values/types/NULLs, and generations before the transactional switch.
It compares inspected source index names/definitions and their validity/readiness flags. Target unique-index construction exercises the fixture's scoped uniqueness.
Generic CHECK/FK/default/collation and dependency preservation remain UNKNOWN. Source-index observations do not prove them.
A competing executor is denied; an actual concurrent writer is observably blocked while the maintenance lock is held.
That observation does not prove deployment-wide writer exclusion between chunks.

The lost-reply test shuts down the receive side of the original connected socket before COMMIT completes.
It observes EOF and an initially absent marker, then independently observes the original transaction terminal and a matching committed marker.
It never consumes the COMMIT reply through libpq. Resume preserves the committed bytes.
The separate [fault receipt](../spikes/revamp/results/gate-faults.json) proves that real SQL errors and injected local-provider failures
roll back both staged chunk data and its marker. Actual disk/WAL exhaustion remains pending.

Payload rotation, search rotation and local rewrap are separate tested actions. Current post-cutover application edits survive rollback,
reprotection and deprotect with all original columns and types compared. Eligible shadows, indexes, trigger and journal are removed.
A fresh process blocks Cryptalis/crypto readers, verifies all current data, commits an ordinary edit, then runs the untouched 29-assertion original oracle.
Only its owned synthetic rows are cleared between the current-data proof and the oracle's empty-database fixture.

The database phase remains `SWITCHED_DATABASE_POLICY_PENDING`. Authenticated host publication/startup, restored-old-policy denial,
stale-worker termination, durable independent-process readers/keys, format/codec upgrade and native provider deletion remain UNKNOWN.
The local backup decode and fork-inherited interruption test do not qualify retained-backup custody or a fresh independent provider restart.
The [million-row protection receipt](../spikes/revamp/results/gate-performance.json) measures initial protection; it does not qualify
million-row rotation/deprotect, a production pause ceiling or a storage-exhaustion response.
These pending requirements keep the complete lifecycle gate UNKNOWN.

## Maintenance and ownership

Use a bounded maintenance write pause for affected tables.
The deployment operator stops known workers/jobs and excludes unsupported writers before transformation.
The runtime principal cannot change schema, operation metadata, or lifecycle privileges.
Unknown writer coverage blocks apply. An empty connection snapshot alone does not prove that excluded writers cannot reconnect.

One PostgreSQL journal stores the immutable operation ID/plan digest, target binding, source/desired lock, phase, and chunk outcomes.
Chunk data and its completion marker commit in one transaction.
A session advisory lock serializes cooperating executors. It is not external writer exclusion or fencing of provider calls.
Hold table locks where required. Reinspect durable operation state after a crash or lost connection.
A second executor must acquire the lock and reconcile the original operation before it resumes work.

No operation leases, distributed worker registrations, receipt dispatcher, or per-request mutation ledger are required.
The deployment stop, database transaction, and provider native outcome define the SPECIFIED boundary.
Unresolved in-flight work remains pending. A timeout does not establish worker termination or external effect completion.

## Plan and phases

The plan binds its exact target, original/desired lock digests, schema facts, data scopes, writer inventory, readers/keys, approvals, and estimates.
`plan` creates no data or schema effects. It shows changed query semantics, leakage, and plaintext exposure before approval.
A changed manifest is a request, not authorization to weaken the active representation.

| Phase | Required evidence |
|---|---|
| Expand | Inspected additive shadows/indexes and durable operation identity. Old representation remains authoritative |
| Backfill | Bounded chunks authenticate source where protected and write complete target payload/companions plus marker atomically |
| Verify | Full required row membership, decoded value/type/NULL equivalence, companion recomputation, and valid constraints/indexes under writer exclusion |
| Switch | Verification still matches the stopped source. Database schema/state and the independently controlled deployment pin select the same representation |
| Contract | Package/reader/key/backup dependencies permit exact approved retirement. Actual effects and retained obligations remain observable |

Schema/data switch can be transactional within PostgreSQL.
Updating an external deployment artifact is a separate effect, not a cross-service atomic commit.
Writers remain stopped between those effects. Startup denies either mismatch until inspection finishes the switch.
Use the existing deployment tool to publish the exact planned policy artifact.
Do not write a new distributed CAS or automatic policy service merely to hide maintenance downtime.

Default chunk size is a measured tuning parameter, not a security guarantee.
The executor resumes committed chunks without regenerating their ciphertext.
Counters/cursors alone do not prove membership coverage. Full terminal verification is mandatory.
Verification mutants must include wrong payload, missing row, stale companion, duplicate normalization, and invalid index.
Disk/WAL/provider exhaustion stops progress and retains completed chunks. It never produces a partial-success switch.

For a lost COMMIT response, do not automatically retry business writes or assert rollback.
For transition chunks, inspect the original operation/chunk marker on the trusted current primary after the original transaction is terminal.
A matching marker and transformed rows establish the committed chunk within PostgreSQL's durability assumptions.
An absent marker while the original transaction can still commit is UNKNOWN.
Privileged corruption, failover data loss, or wrong-target inspection also prevents a confident classification.
No global exactly-once guarantee follows from a marker.

## Rollback

The default is decrypt-back or transform-back from **current** active data.
It is the same verified engine used for deprotect. A static pre-switch snapshot is not a lossless rollback after post-switch writes.

Before switch, `apply --abort OPERATION` can remove operation-owned shadows and retain the unchanged source.
After switch, rollback pauses writers, reads current values, transforms the previous representation, verifies, and performs a new switch.
It requires compatible readers/keys and a lossless prior type/constraint contract.
If current values cannot fit that contract, report the exact conflict class and keep the active representation.
Do not discard new values or restore an old data snapshot silently.

Rollback/removal remains available through decrypt-back until explicit user finalization retires its required recovery dependencies.
Finalization uses the existing lifecycle and adds no command or mode.
The selected default retains no live plaintext rollback mirror and no timer that forces finalization.
Plaintext needed for rollback appears only in the explicitly approved reverse transition.
Rollback can be slower. Status shows estimated pause and actual progress.
A required old key/reader cannot be retired while it remains the only approved reverse or backup recovery route.

The earlier local experiment changed a value after cutover, then recovered that current value through decrypt-back.
The integrated checkpoint records the original application's narrow rollback/removal evidence. Neither qualifies the full lifecycle gate.

## Changes and rotation

| Change | Engine action |
|---|---|
| Protect or stop protection | Transform payload, create/drop declared search representations, verify, switch, contract |
| Add/remove a query capability | Derive/retire companions and indexes. Reseal payload when authenticated search metadata changes. Verify source/target and queries |
| Normalizer/search-domain change | Full reindex and duplicate/constraint review. New identity, no in-place reinterpretation |
| Payload key generation | Re-encrypt payloads and authenticated companion metadata. Search roots can remain stable |
| Search key generation | Rebuild terms/arrays and indexes. Reseal authenticated payload headers with fresh nonces. Keep writers stopped |
| Provider/KEK change | Rewrap exact roots and verify unwrap/context under the new provider. Payload/search bytes stay unchanged |
| Format/codec upgrade | Deploy required readers first, transform, verify, then switch writers. Retire old readers only after dependency review |

Keep exactly one active application writer representation during maintenance cutover.
No partial-generation OR query or cross-generation uniqueness gap is silently admitted.
Native KMS KEK material rotation is different from root rewrap, payload rotation, or search reindex.
Rewrap alone does not cure a leaked payload/search root.
No normal rotation automatically deletes historical keys or makes copied old ciphertext safe after compromise.

## Restore and authority loss

These are deployment requirements. Only a local policy model ran; no authenticated restore test passed.
A restore starts in quarantine with production writers stopped.
The operator inspects trusted schema, target identity, current deployment policy, key wrappers, formats, and backup lineage.
A restored operation journal is progress evidence, not current authority.
Old consistent metadata cannot select an older active policy or revive externally revoked access.

Compare the database representation to the current policy artifact outside the restore.
If it is older, plan a verified transformation to current policy before admission.
If required readers/keys no longer exist, identify irrecoverable scopes and refuse silent incomplete recovery.
If current policy provenance is unavailable, keep service stopped. A restored database pin cannot replace it.

The host's existing current authorization must enforce subject denial independently when that denial must survive restore.
Putting the only deny record inside PostgreSQL cannot supply that property.
Deployment policy can reject retired generations. It does not prove every row is fresh within an admitted generation.
No policy counter detects arbitrary same-context row replay or an invisible old application/RAM clone by itself.
Workers must restart under current policy and target credentials after restore.
Managed-provider target identity and failover behavior remain external compatibility tests.

KMS/provider loss and policy loss differ. Intact keys with unprovable current policy deny service.
Permanent loss of every recovery key/wrapper can make ciphertext permanently unreadable.
The operator retains a tested recovery inventory and reader artifact. There is no Cryptalis key-hostage service.

## Revocation and destruction

Subject revocation means host-authorized managed denial and row cleanup, not cryptographic erasure.
Default tenant roots remain able to decrypt a subject's old encrypted backup when the required authority survives.
Shared search roots can retain subject linkage. Deleting a current row or wrapper does not destroy backed-up copies.

Domain/tenant key destruction is a separate provider-admin operation after inventory and explicit approval.
Tenant-level destruction requires a provider KEK dedicated to that tenant, or another independently proved root-destruction route.
Deleting a tenant wrapper cannot erase its backed-up copies under a surviving shared KEK.
Report requested deletion, provider pending state, observed native deletion, remaining cached/copied keys, and physical backup expiry separately.
Do not call recoverable values shredded, erased forever, or cryptographically destroyed.
A provider deletion request is not proof of completed deletion or loss of every descendant key.
No per-subject KMS key, puncturable encryption, tombstone service, or instantaneous revocation protocol is selected by default.

## Deprotect and remove

Approve plaintext exposure before the first plaintext staging write.
The approval names scope, target, resulting WAL/backups, and retained recovery ownership.
Authenticate current ciphertext, reconstruct original ordinary SQL types, recompute/verify exact values, and switch while writers remain stopped.

Removal completes only after:

1. The ordinary-schema application passes real read/write/query tests without Cryptalis attachment or import.
2. Search companions/indexes, ciphertext columns, and eligible internal metadata are retired after dependency review.
3. Every retained encrypted backup has a tested reader/key route or an explicit approved loss disposition.
4. Old workers/jobs no longer require Cryptalis readers or write protected representations.
5. Package removal occurs last. Status names ongoing external key/backup obligations.

Rollback during deprotect/removal uses the same transform-back path. It is not a second mirror protocol.
The earlier package-free SQL read does not satisfy application removal. The integrated checkpoint records a narrow original-application child test.
Durable retained-backup recovery and the full removal gate remain UNKNOWN.
Dropping columns does not erase dead tuples, WAL, backups, or host exports.
PostgreSQL can also retain dropped-column bytes in existing heap tuples: `DROP COLUMN` hides the column from SQL,
but does not immediately remove its stored data ([PostgreSQL 16 ALTER TABLE](https://www.postgresql.org/docs/16/sql-altertable.html)).
Protection switch retires the original SQL column after verification. It does not establish plaintext erasure.
Historical plaintext and encrypted-reader obligations remain explicit after application exit.

## Recovery behavior

`status` reports the original operation, last durable phase, attempted effect, pending work, and remedy.
`apply --resume` reinspects that operation and actual state before another effect.
An expired initial plan cannot authorize changed effects. It can identify an already approved operation for current reinspection.
Unknown provider effect requires native inspection before retry. Advisory locks do not fence an already dispatched KMS request.
No separate reconcile, break-glass, receipt repair, or restore-admission language is required for the normal product.
If an essential outcome cannot be established, remain PENDING/UNKNOWN and state the specific required observation.

## Supported deployment candidate

The selected candidate uses one application deployment, one current PostgreSQL primary, and an existing trusted release operator.
The operator controls worker termination, database credentials, deployment artifacts, and restore quarantine.
No profile qualifies yet. Multi-deployment writer coordination is unavailable until that exact host procedure passes its tests.

1. Stop affected writers and wait for their transactions to finish. Confirm that alternate credentials cannot restart a writer.
2. Run the database transition and full verification under the maintenance principal. Record the exact pending policy artifact digest.
3. Switch the database representation. Leave writers stopped. `status` names the operator and the required artifact publication.
4. Publish the exact artifact through the trusted deployment tool. Restart workers with fresh target credentials and empty key caches.
5. Admit traffic only after startup compares the current artifact, target, schema, and active representation.

Interruptions between steps 3 and 4 retain `writers: STOPPED` and a named pending effect.
Neither the restored journal nor a stale worker can approve publication. Missing provenance keeps service stopped.
This procedure needs real tests for both switch boundaries, stale policy, old workers, and unavailable host denial authority.

`plan` must estimate temporary storage, WAL, provider calls, verification duration, and total writer pause.
Pause budgets remain undecided (D). The operator must approve the concrete measured/estimated pause before an actual transition.
No production pause ceiling is approved.
The admitted text/equality plan enforces encoded-text and bind limits before SQL.
Range tree depth/cover and prefix term bounds are INTERNAL ONLY until capability admission.
Resource bounds prevent uncontrolled expansion. They do not establish an approved write-throughput budget.
Advanced capability/normalizer/search-domain changes are UNSUPPORTED BY DESIGN until [admission](compatibility.md#capability-admission).
The selected lifecycle scope uses text, application-generated primary keys, and explicit tenancy.
