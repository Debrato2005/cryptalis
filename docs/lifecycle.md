# Data and key lifecycle

Status: DESIGNED. One INTERNAL ONLY engine owns every lifecycle operation.
No transition executor, live provider or restore admission exists in the [current code](status.md).
The [architecture](architecture/README.md#public-surface) owns command names. The [security owner](security.md) owns key authority and claims.

## Maintenance transitions

The supported strategy is a bounded maintenance write pause across one protection domain. One domain owns one lifecycle operation. Online backfill, mixed-generation dual writers and writable CDC are UNSUPPORTED BY DESIGN.
Read availability can continue only when every admitted reader uses the unchanged source representation and holds a compatible fence.
No read availability is promised during DDL, verification or switch. Plans show downtime rather than hide it.

A plan binds operation ID, kind, source/current-head digest and revision, desired compiled-lock digest, target incarnation,
schema/Alembic heads, exact binary/format/provider identities, selected scopes, prerequisites, estimates, expiry, approvals and recovery obligations.
Its schema is 2. A domain-labeled SHA-256 over canonical complete bytes is pinned in external pending-operation state.
Plans expire after 15 minutes before initial execution. A started durable operation resumes by current operation ID and reinspection, not a renewed stale plan.
Approvals name action, plan digest, target, scope, operator identity, validity window and irreversible consequence.
An operator cannot replay approval onto a different target, operation, cleanup action or weakened policy.

| Internal phase | Required effect and completion evidence |
|---|---|
| PLAN | Read current external authority, mappings, exact infrastructure target, schema, writers, keys and recovery inventory. Produce no data/DDL effects |
| PREPARE | Claim exclusive external operation ownership and DB overlap lock. Deny new writes, restrict runtime writer role, drain transactions/pools/jobs. Reinspect current facts. Create additive isolated shadows and a recovery checkpoint |
| TRANSFORM | One scoped executor processes bounded idempotent chunks. Authenticate/decode source when protected, derive target/terms, commit coherent target plus operation/source revision marker atomically |
| VERIFY | Full terminal row/value/type/NULL/term equivalence and source membership coverage under current writer exclusion. Inspect catalog/index/provider state and controls. No count-only, shape-only or sampling substitute |
| SWITCH | Reinspect target, scope, writer exclusion and verification generation. Conditional external head change selects one writer representation. Reconcile lost response by operation ID, not blind retry |
| OBSERVE | Start only admitted compatible writers/readers. Report health, exact reversible representation, mirror exposure and deadline. Failed controls or stale mirror suspend readiness |
| FINALIZE | Reinspect inventory and require approval for each irreversible action. Retire only eligible columns/terms/readers/keys, journal actual effects and retained copy obligations |

Before any nontransactional DDL/provider effect, persist exact intent, action, target and idempotency identity durably.
Then record observed outcome or ambiguity. Never send a destructive request before its independent intent receipt exists.
Every chunk transaction checks current operation ownership and fence generation and commits its marker with the transformed data.
Each phase records last completed step and every attempted external/DDL/data effect.
Execution states are RUNNING, REPAIR_REQUIRED, FAILED, PENDING, INCONCLUSIVE and COMPLETE.
SWITCH does not mean FINALIZE completed. Status distinguishes active protection, retained rollback exposure, and finalized current storage.
No generic workflow framework or separate key/restore activation engine is required.

## Writer exclusion and crash safety

Enumerate effective DB roles/memberships, owners, grants, sessions, pools, jobs, binaries, separate drivers, migrations, replicas and external workers.
`application_name`, shared DB credentials and process heartbeats are hints, not authenticated writer identity.
Disable new affected authority admissions, revoke relevant runtime writes, drain admitted transactions and acquire the exclusive domain DB fence.
Unknown external writers block transformation unless privileges demonstrably exclude them.
An empty connection snapshot alone never proves future write exclusion.
The application principal has no owner/superuser/BYPASSRLS/schema-creation powers and cannot undo maintenance restrictions.
Separate migration roles hold exactly reviewed effects. Ordinary web grants cannot migrate.

The supported DB profile requires `max_prepared_transactions=0`, no prepared transactions, no protected CDC/publications/subscriptions or downstream writers,
trusted schema/search_path, reviewed RLS and a complete executable-object inventory.
Functions, triggers, rules, casts, operators, extensions, defaults, generated columns, views and policies can change restore or DML behavior.
Unexpected objects or missing inspection privileges block dependent readiness.
Lock/statement timeouts, catalog definitions, invalid indexes, disk/temp/WAL limits and cancellation recipes belong in each physical plan.

Default chunks contain at most 500 rows or 8 MiB encoded data, whichever comes first. Lower limits are allowed.
The source snapshot and explicit durable row revision define membership. PostgreSQL `xmin` is not a permanent logical revision.
Target bytes and completion marker commit together. A later checkpoint can replay that commit without regenerating already completed ciphertext.
A cursor, `SKIP LOCKED`, count or skipped range is not terminal coverage evidence.
Deletion, insertion behind the cursor, scope transfer, constraint drift or unexpected writer invalidates verification.
One operation owns overlapping assets. A second executor cannot independently publish or transform them.
Lock loss, authority unavailability or expiry stops new effects. No stale worker can use its old permit to commit under a changed DB fence.

The terminal verifier scans every required current row after transformation in a stable snapshot with writers still excluded.
It authenticates source/target where encrypted, compares exact payload value/type/representation, validates NULL state and recomputes all required terms.
It records complete membership and revision coverage plus exact valid constraints/indexes.
Independent samples supplement the full scan. They never certify unscanned rows.
Controls deliberately introduce wrong values, stale terms, missing rows and wrong target identity to prove the verifier can fail.
No row plaintext or token appears in the receipt. Recheck durable operation ownership/fence inside each data-and-marker transaction.

Record durable intent before nontransactional DDL/provider effects. DDL outside transaction boundaries is journaled separately. Concurrent index construction is not required by this maintenance design.
If an existing or manually reviewed concurrent step leaves an invalid index, inspect definition/owner/validity/readiness before repair.
`IF NOT EXISTS`, a name or Alembic stamping is not proof of completed schema/data work.
Alembic uses public operation/render/autogenerate interfaces to propose reviewed DDL. It does not backfill or activate policy implicitly.
Repeated autogenerate on the reconciled schema emits no Cryptalis diff. A downgrade refuses after irreversible state instead of fabricating recovery.

DB and DynamoDB have no cross-service atomic commit.
Before switch, shadows remain non-authoritative and writer admission stays blocked. After switch, the external head dominates a stale local checkpoint.
Every lost acknowledgement remains PENDING until actual catalog/row/provider/authority state resolves it.
Process crash before/after each durable boundary, two executors, cancellation and resource exhaustion are mandatory acceptance scenarios.
The [authority protocol](security.md#admission-and-fencing) owns token/worker/effect ordering. This engine cannot bypass it.

### Ordinary commit evidence

Every protected mutation gets a random operation UUID and immutable request digest before DML, registered externally with
worker incarnation, exact target/fence and original backend fingerprint. Digest covers the canonical operation shape, scoped
identities, expected revisions and a keyed commitment to value bytes, not public low-entropy plaintext hashes.
Choose the lexicographically smallest (root-handle UUID bytes, generation) among the mutation's admitted payload roots as its
immutable commitment anchor. Deletes include the deleted rows' roots. An empty protected mutation requires no mutation record.
Derive `Kop = HKDF-SHA256(anchor_root, salt=payload-extract salt for that root,
info=E("cryptalis/mutation-commitment/1", operation_UUID), length=32)` using the security owner's fixed tag/tuple encoding.
The request digest is full HMAC-SHA-256(Kop, E("cryptalis/mutation-request/1", canonical_request_bytes)).
The last component is tag 5 opaque bytes. The request uses the manifest's canonical JSON rules and exactly these members:
`version`=1, `domain_id`, `target_incarnation`, `fence_token`, `anchor_handle`, `anchor_generation`, `operation_id`,
and `mutations` sorted by model UUID, typed record identity and action. Each mutation contains `model_id`, `record`,
`tenant_id`, `subject_id` (UUID or null), `action` (insert/update/delete), `expected_revision` (uint decimal string or null),
`ordinary_changes` (defined below), and `fields` sorted by field UUID. A field has `field_id`, `descriptor_digest` (lowercase hex), `codec_id`, and
`value` (null or canonical padded Base64 of the encoded scalar bytes). Record identity is exactly
`{"kind":"uuid","value":"canonical UUID"}` or `{"kind":"u64","value":"minimal unsigned decimal"}`.
Integers for tokens/generations follow the bounded manifest counters. Reject duplicate mutation/field identities.
The frozen request also covers every explicitly changed ordinary mapped attribute in an `ordinary_changes` array, with
its lock-pinned original type ID and exact admitted scalar bytes encoded the same way. Unknown/custom processors reject.
The whole canonical request is bounded to 16 MiB and depth 32 before its keyed digest is computed.
Host-side implicit effects outside this closed write inventory are ineligible. The root/generation stays a read dependency
through reconciliation and the retry-retention barrier. Do not log canonical requests or the anchor root/key.
Independent canonical-byte/commitment vectors and full changed-attribute/default inventory remain G-TRANSITION/G-ORM evidence.
All effects (including DELETE and rollback-mirror updates) commit with one logged outcome row in the same PostgreSQL transaction.
The outcome stores domain/target/operation, request digest, worker/token, protocol/generation and committed effect summary;
no plaintext, search terms or raw SQL. UNIQUE(domain, operation) prevents a repeated operation from executing twice.
A different digest under the same ID is `OperationIdentityConflict`. An already committed matching operation returns its
recorded outcome after current authorization, not a fresh mutation. Statement retries after a rolled-back transaction reuse that ID.

If COMMIT was sent and acknowledgement is lost, do not mark rollback, resend effects, clear ownership or delete the outcome.
Reconcile the original external record and backend on the exact current writer target. First establish that original backend
is terminal: completed, rolled back or verified terminated with no prepared transaction. Then read the durable marker using
a fresh current-primary transaction (not a stale replica/snapshot or restored checkpoint). Matching marker means COMMITTED,
including when later work deleted the data row. Absent marker means NOT_COMMITTED only after terminality and trusted target
lineage/durability are proven. Otherwise outcome remains UNKNOWN. Failover data-loss ambiguity cannot manufacture rollback.
No automatic commit retry occurs from marker absence while the original backend might still commit.

External receipts record the observed DB outcome afterwards. They are not atomically committed with PostgreSQL.
Registered operations remain until classification/conditional acknowledgement. Marker GC requires all operation owners terminal,
external acknowledgements durable, no supported delayed retry/recovery dependency and approved retention closure.
There is no fixed TTL or row-delete cascade. Capacity exhaustion in the outcome ledger denies new mutations safely.
Authority loss cannot reconstruct permission from DB markers alone. H2 does not create a cross-service transaction.

### Capacity preflight and exhaustion

Before shadows, provider effects or switch, inventory exact live rows/bytes, old and target per-root usage reservations,
unspent/retry-burned quotas, accepted growth during the bounded rollback window and both current/mirror encryption costs.
For each generation require live transformation calls/bytes + reserved crash/retry allowance + observed-window write allowance
<= remaining 2**24/2**40 ceilings. An oversized live set is rejected before effects. Split-scope redesign needs a reviewed contract.
Old-generation mirror writes consume old quotas even after switch. Do not allocate every old byte/call to migration.
If mirror headroom cannot cover the approved write rate/window, deny writer reopening until an approved verified finalization
or generation plan fits. Declining rollback must be explicit before the first irreversible switch, never automatic exhaustion cleanup.

The physical plan estimates old/target/shadow/mirror columns, both term indexes and constraint rebuilds, outcome records,
WAL/archive/backup growth, temporary space and table/index bloat. Reserve at least estimated peak plus 25% safety headroom;
measure estimates with representative data. Unknown available disk/temp/WAL or provider capacity blocks preflight.
KMS, DynamoDB transaction/item/throughput, SDK concurrency/deadlines, S3 request/retention and account/Region quotas are inspected
inputs, not universal constants. Preflight uses operator-supplied inspected facts. No guessed quota is admitted.
Rate-limit chunks within those budgets. No global guarantee of uninterrupted service follows from the estimate.

| Failure | Required outcome/remedy | Invariant |
|---|---|---|
| Live set exceeds fresh generation cap | `CapacityInsufficient` before effects. Reviewed scope/generation redesign | No usage reset/silent oversize |
| Quota reservations burned by crashes/retries | Recompute before next chunk. Pause if remaining cap insufficient | Restored DB cannot refund usage |
| Disk/WAL/provider throttle mid-transition | Roll back uncommitted chunk; PENDING with committed markers/fences. Inspect and resume | No partial switch or plaintext fallback |
| Mirror quota/write or deadline fails | Deny the entire ordinary write. Reconcile/finalize with bound approval | Advertised rollback remains current |
| Unknown quota/owner/backend after loss | UNKNOWN. Reconcile without new effect | Missing capacity/outcome is not safe |

### Recovery catalogue

All commands below are DESIGNED. They first authenticate the operator, inspect current authority/target/token and the original
immutable operation proposal stored with its digest. A supplied expired plan cannot renew it: resumption revalidates current
permissions, exact effects and absolute rollback deadline. Changed effects need a new reviewed plan after safe closure.
Outputs are bounded IDs/states/remedies only. They never emit plaintext, terms, bind values or raw exceptions.
Resume of previously approved deprotection can persist the approved plaintext representation. It does not print its values.
Break-glass cannot waive a tombstone, invent current journal completeness or claim destruction after a permission failure.

| Stuck state | Operator command | Idempotent rule / safe result |
|---|---|---|
| Lost ordinary COMMIT reply / unknown backend | `cryptalis reconcile OPERATION` | Terminal-backend and exact-marker procedure above; UNKNOWN remains pending |
| Prepared or partially transformed operation, known owner terminal | `cryptalis apply --resume OPERATION` | Original proposal/action IDs. Inspect markers before each chunk. No old-plan reactivation |
| Reversible pre-switch shadow, abort requested | `cryptalis abort OPERATION` | Drain/inspect, remove only operation-owned reversible shadows, acknowledge closure. Permanent denials/intents stay |
| Switched/mirrored operation | `cryptalis rollback OPERATION` or `cryptalis finalize OPERATION` | Verify current mirror/dependencies or approve exact cleanup. Abort returns `IrreversibleState` |
| Invalid index / DDL response lost | `cryptalis reconcile OPERATION`, then `apply --resume OPERATION` | Inspect exact definition/ownership/validity. No name-only success |
| Provider action in flight / lease expired | `cryptalis reconcile OPERATION` | No transfer/re-dispatch until old dispatcher terminal and native state resolved |
| Capacity/authority/receipt outage | `cryptalis status`, then `reconcile OPERATION` and `apply --resume OPERATION` | Restore inspected dependency/capacity first. Retain fencing and known effects |
| Subject denial pending worker drain | `cryptalis reconcile OPERATION` | Terminate/drain authenticated incarnations. Never expire denial |
| New restored target / stale checkpoint | `cryptalis restore check TARGET`, then `restore admit PLAN` | Quarantine, current target-bound full verification. Resume on wrong target denies |
| Authority identity/state loss | `cryptalis recover authority --domain ID --evidence PATH` | Separate break-glass role, complete current archive/native proof. Unprovable old domain remains denied |

Unknown states return typed `ReconciliationRequired` plus operation ID, never an undocumented manual permission bypass.
Repeated reconcile cannot apply a data mutation. Repeated resume/abort recognizes durable completed steps and changes no extra effects.
G-TRANSITION/G-RESTORE exercise every catalogue row, repeated calls, wrong target/digest/role and output canaries.

## Protect and reconfigure

Protection creates ciphertext/term shadows and leaves the source unchanged during transformation.
Full verification must finish before active mapping switches. New rows must never be inserted in plaintext to obtain an identity for subsequent encryption.
Existing record IDs must satisfy the [identity contract](architecture/README.md#manifest) or adoption rejects with a concrete remedy.
A rename preserves stable logical IDs. A new representation, changed scope or type uses authenticated source-to-target transformation.
Removing a declaration is a downgrade request, not permission to drop protection.
Changing a normalizer, adding/removing search or changing uniqueness uses deliberate REINDEX/RECONFIGURE.
Equivalent values that merge under the new normalizer block switch until the host resolves conflicts without discarded data.
No planner silently removes search because a sample observed no queries.

## Rollback and finalization

Before switch, rollback abandons shadows after writer exclusion and restores unchanged source admission.
After switch, rollback requires a current verified source representation, exact admitted reader and intact key dependencies.
If writers resume, they update the active target and rollback mirror atomically in one row transaction.
Any mirror error aborts the whole write. A static pre-switch snapshot is not application rollback after later writes.
Observation-window writes must satisfy both representations and retained constraints. Incompatible values fail atomically with a finalization remedy.
No lossy conversion or silently removed old UNIQUE constraint preserves a rollback claim.
Reversal fences writers, verifies every current mirrored value and performs a new monotonic authority transition.
It does not reduce the external authority revision or revive a tombstone.

For protection, that mirror is plaintext. Status says `PROTECTED_WITH_PLAINTEXT_ROLLBACK`, not finalized database confidentiality.
The plan records the deliberate exposure, who can read the mirror, destinations and affected WAL/backups/replicas.
The default rollback window is 24 hours from first switch. The absolute maximum is first switch plus 7 days.
At deadline, further mirrored writes stop until the operator finalizes or rolls back. No automatic destructive cleanup occurs.
Extensions require new explicit exposure approval and current inventory within that absolute maximum.
New approvals or operation IDs cannot reset the original exposure deadline. Expiry denies the complete mirrored transaction.
Elapsed time does not erase existing plaintext or authorize contraction.
Normal users see one pending action and deadline through status, not internal phase vocabulary.

Finalization stops and drains mirror writers, verifies the current active representation, checks package/read/key/copy dependencies, and requests exact cleanup approval.
The first irreversible cleanup boundary is explicitly recorded per action: source removal, reader retirement, recovery-key deletion or custody destruction.
Deleting a plaintext mirror loses cheap old-application rollback. Afterwards rollback requires a new verified deprotect/transform,
or an explicitly retained independently recoverable backup with reconciliation of post-backup writes.
Restoring a pre-cutover backup alone is not lossless rollback. `rollback` returns `IrreversibleState` when the promised route is gone.
No automatic column drop, key deletion or Alembic downgrade follows a declaration change or observation period.

## Rotation and upgrades

| Operation | Actual layer and required transformation |
|---|---|
| KMS automatic material rotation | KMS retains old decrypt material. Payload roots, terms and row ciphertext remain unchanged |
| `--layer wrapper` | Rewrap independent roots under a new admitted KEK. Verify every wrapper/context. Payload/terms need no rewrite |
| `--layer payload` | Prepare independent target payload roots for the executor, re-encrypt and verify under maintenance fence, then select new application writes at SWITCH |
| `--layer search` | Create independent search roots/term slots, full maintenance reindex, valid new UNIQUE enforcement, then switch |

Reader-first order is mandatory: deploy readers for old and new admitted formats/generations and verify all worker compatibility.
Prepare the target generation for maintenance transforms, stop application write admission, transform and fully verify existing data,
then select the new application writer generation at SWITCH. Retire eligible old dependencies only after observation/finalization.
There is exactly one active write protocol and one selected write generation per scope. Adjacent package binaries can coexist only if both implement that protocol and all required readers.
Old jobs, containers and delayed workers cannot write an obsolete generation after the fence changes.
Unknown formats, descriptors or incompatible binaries fail startup or operation admission.

The maintenance design needs no online dual-index OR protocol. Writes stay stopped while uniqueness moves to the new generation.
At no admitted writer boundary is uniqueness unenforced. Separate independent UNIQUE indexes are not treated as cross-generation enforcement.
Reindex can temporarily retain old terms for rollback. Same-row old/new links increase leakage during that explicit window.
KEY_REWRAP preserves secret bytes. KEY_REENCRYPT changes payload protection. REINDEX changes search independently.
No ordinary rotation automatically destroys old keys or erases copied old ciphertext.

Retiring a generation requires current row coverage, compatible binary inventory, old backup/reader dependencies and explicit finalization.
Semantic normalizer changes use new IDs. Internal format/schema version changes retain exact old readers while required data remains.
Renaming a format ID or algorithm in place is forbidden. Unknown critical fields cannot be ignored for compatibility.
Compromise response separately names leaked payload/search roots, KEK/workload credentials, primitive or format defects and already copied data.
Contain admissions first. Plan the needed new custody/material/format and verified transformations. Rewrap alone does not cure an exposed payload root.

## Restore and authority loss

Bind the production target to account, Region, immutable RDS `DbiResourceId`, database identity and externally approved incarnation.
ARN/endpoint/name alone can be reused and are insufficient. Obtain resource identity from authenticated AWS control-plane inspection.
Use TLS hostname validation and the admitted destination/role. A database row UUID or OID cannot attest infrastructure identity.
Failover within the same admitted RDS resource follows its checked cell. Restore/clone and blue-green replacement require a new target admission.
Development PostgreSQL without this identity resolver is INTERNAL ONLY and supplies no production restore guarantee.

A restored target starts isolated with no production writer admission. Restore metadata, schema and checkpoints are untrusted.
`pg_restore` can execute source-superuser-controlled code. Inspect a quarantined environment and rebuild trusted schema before admitting data.
Do not assume data-only selection makes hostile schema safe.
Read current external head, denial/tombstones, accepted formats and completed destructive operations independently of restored DB state.
Current revoked subjects/scopes cannot be released. Inventory and remove/quarantine their restored rows/terms under current denial,
without overriding that denial to decrypt them. Record excluded irrecoverable values explicitly.
Verify every required admissible row and reconcile schema/key/reader dependencies before conditional target admission.
Old DB counters, restored provider credentials or old VM caches never restore authority.

Production disaster recovery stays within the same protection domain only after current ledger proof and exact target admission.
There is no automatic cross-region authority failover. A staging clone uses a different domain, keys and workload credentials.
Production data transfer to staging requires an explicit authorized re-encryption transition. Raw ciphertext copying does not inherit authorization.
Restored VMs restart the runtime, discard caches/permits/clients and re-admit. Invisible VM-memory rollback remains unsupported.

Recovery inventory retains DB backup lineage, exact formats, wrapped roots, provider resources, nonsecret policy bytes, readers and external destructive-intent receipts.
It contains no raw root escrow. Standard AWS-generated KEKs cannot be exported for a Cryptalis escrow file.
The product chooses provider durability rather than customer raw-key escrow. Imported/escrowed/custom-store custody is excluded.
If a KEK is permanently deleted or irrecoverably lost, every dependent wrapped payload/search root and ciphertext can become permanently unreadable.
Loss of a subject wrapper without a retained copy can also lose its values. Loss of a search root can be repaired only if payloads remain decryptable for reindex.
Authority loss with intact keys denies service. Current latest state must remain independently provable.
The [external authority contract](security.md#external-authority) defines receipt custody, intent ordering and crash reconciliation.
Permanent authority identity/state loss without current complete proof permanently denies the old domain, without TTL.
An old authority backup or immutable prefix cannot authorize reactivation.
No break-glass instruction silently clears a tombstone or trusts an incomplete recovery graph.
This can make existing ciphertext operationally unrecoverable even while KMS material survives.
It is a deliberate fail-closed boundary, not a claim that provider durability solves authority loss.

## Revocation and destruction

`revoke --subject` means managed access denial, not per-subject cryptographic destruction.
It records irreversible current subject-incarnation tombstone, denies new reads/writes, fences/drains registered operations,
and removes current protected rows/terms through an authorized scoped plan where host relational dependencies permit.
If dependencies prevent removal, retain quarantined denied rows and report PENDING cleanup. Reads of a denied candidate fail the whole buffer.
Recreation needs a new subject incarnation. It cannot reuse the tombstoned identity.
Restoring a stale backup does not clear that managed denial.

Payload roots are independent, but their old wrappers can survive in backups under the surviving domain KEK.
Those wrappers remain cryptographically recoverable with sufficient external authority. Shared tenant-field equality keys also retain linkage to old subject terms.
Deleting current wrappers/rows or denying access never proves unrecoverability.
Per-subject cryptographic erasure, per-subject search keys that break cross-subject equality, and custom puncturable encryption are UNSUPPORTED BY DESIGN.

`destroy --domain` can destroy the dedicated KMS custody scope only after separately approved irreversible inventory.
Report three independent axes: managed access (admitted/revoked/drain-pending/no-new-use), provider custody (requested/pending/native-deleted),
and recovery (recoverable/unknown/bounded-destruction-verified). They can coexist. Denial or pending deletion does not imply destruction.
Provider observations also retain their native state, time, exact resource, Region, origin and evidence source.
AWS deletion waits 7–30 days, is cancelable during the pending interval, and can complete up to 24 hours after the scheduled date.
Request success is not destruction. Cached/copied descendant keys are unaffected by the provider call.

Bounded destruction requires managed drain, known key-copy/custody inventory, no prohibited escrow/import/replica paths,
observed completed deletion of every current AND historical domain KEK that wraps any surviving root, and independent recovery trials over each route.
Rewrap can leave historical wrappers recoverable through an old KEK. Destroying only the current KEK is insufficient.
Recovery trials need positive controls proving they reached the intended material/reader route.
Permission/transport failures, malformed backups and unavailable readers are INCONCLUSIVE, never destruction evidence.
Unknown copies or workers make the stronger conclusion INCONCLUSIVE. No local row deletion prints `ERASED`.
The evidence states its effort/custody/copy boundary under NIST SP 800-88 Rev. 2 concepts. It makes no certification or universal sanitization claim.
Host exports, already disclosed values, logs, prior plaintext and unmanaged copies remain excluded.

## Deprotect and remove

Deprotect requires scoped downgrade approval before the first plaintext staging write, including shadow columns, temporary tables and files.
Approval describes resulting WAL/backups/replicas and application publication. A switch-only approval is too late.
The same valid approval can cover staging and switch if both actions are explicit.
Expired, wrong-target, missing or ambiguous approval denies further plaintext writes. A crash records existing partial exposure rather than erase its history.

The engine fences writers, authenticates every required admissible source value, backfills isolated ordinary-type columns, and verifies exact value/type/NULL coverage.
A deprotect observation window uses attached mirror-capable writers while encrypted rollback remains promised.
Removal keeps production writes fenced through package-free tests on an isolated ordinary-schema copy.
It explicitly finalizes the encrypted rollback route before resuming ordinary package-free production writers.
Application deprotection alone does not remove historical encrypted recovery obligations.

Removal is one aggregate plan with this order:

1. Inventory every protected field, schema object, binary/job, key, backup, export and required reader.
2. Deprotect and fully verify all required admissible values under the approved publication scope.
3. Switch the host mapping, retain the production writer fence, and run real package-free read/write/query tests on an isolated ordinary-schema copy.
4. Retain a tested standalone recovery reader, exact formats and keys for encrypted backups, or explicitly approve loss of those recovery routes.
5. Retire search terms/indexes, protected columns, admitted old readers and eligible key dependencies through exact finalization actions.
6. Remove Cryptalis database metadata only after operation/recovery receipts move to their independent retention owner.
7. Remove attachment/configuration and uninstall the package last. Report retained external recovery obligations separately.

The standalone recovery reader enforces the same pinned current external authority, tombstones, exact backup formats/scopes and target admission.
Unavailable/unprovable current authority denies recovery. Retain its authority configuration, dependency pins, instructions and tested format coverage independently.
Application exit does not delete external tombstones or recovery authority. Test revoked-subject recovery from a stale encrypted backup.
After explicit encrypted-rollback finalization and package-free gate, resume production ordinary writers.

Package-free application operation is a proof gate. A package import smoke test alone is insufficient.
An unknown encrypted archive, old job or required key blocks eligible retirement. The plan can leave external backup obligations with the operator,
but it cannot strand those backups or call them removed without an explicit disposition.
The reader is an independently pinned recovery artifact, never a secret lock-in service.

## Residual plaintext and reports

Current-row protection does not erase old plaintext from dead tuples, TOAST, WAL/PITR, replicas, snapshots, backups, exports or downstream systems.
Vacuum and column deletion are not universal media sanitization. Migration and deprotection can create additional plaintext copies.
Reports distinguish current representation, rollback mirror, known historical copy with retention/owner, and UNKNOWN external inventory.
Copy expiry is an observed custody fact, not an invented guarantee.
Finalized current storage can coexist with historical plaintext exposure. Status must show both.

An operation receipt records schema version, operation/plan/target IDs, source/target digests, scope, phases/effects, coverage,
observation times, collector/control health, operator attestations, native provider observations, exclusions and recovery obligations.
No raw values, keys, terms or ciphertext bodies are included. Exact finalized bytes are hashed and retained independently.
Required checks are selected before evaluation. A failed check cannot be removed from scope to turn the result green.
Documentation, first-party tests, operator attestation, independently observed facts and independent review remain distinct evidence bases.
A receipt proves only its declared provenance and scope. It does not make a collector honest or establish complete erasure.
Receipt schema 2 requires every listed member, including explicit empty exclusions, and rejects unknown security fields or incompatible versions.
Parse with the bounded JSON profile, hash exact complete bytes, and render from the same immutable validated object.
UTC times record clock source and uncertainty. Deadlines use local monotonic elapsed time after trusted UTC admission.
Uncertain/invalid time or clock discontinuity denies expiry-dependent actions. Independent clocks are not interchangeable.
