# One transition engine

**SPECIFIED:** lifecycle contract. **IMPLEMENTED:** bounded product protection transition with plan/apply/verify and pre-switch abort,
plus an in-place decrypt-back and additive-removal path.
Root rewrap, payload-key rotation, and search-key rotation have bounded cutover and shared publication paths.
Generation preparation stages and verifies encrypted chunks, inspects progress, and supports cancellation before switch.
P1 single-tenant online protection has source and installed evidence in the [status record](status.md#bounded-online-initial-protection-2026-10-24). The tenant-scoped P2 extension has local source and installed evidence in the [status record](status.md#tenant-scoped-online-lifecycle-2026-10-24).
The protection engine verifies and switches in one transaction; saved verification checkpoints require a fresh pass on resume.
Plain reads continue during verification. Writes and locking reads wait; schema DDL can pause all access.
VERIFIED paragraphs below describe recorded receipts, not current product qualification. All other requirements remain SPECIFIED.
Every protection change uses expand → backfill → verify → switch → contract.
Rollback, deprotect, search changes, and key transformations reuse this path.

## Bounded online initial protection

The [authenticated tenant HTTP journey](status.md#verified-continuation-checkpoint-2026-10-28)
extends local P2 evidence to an unchanged original application's approved owner
cohort. Source and actual-wheel runs stop the source cluster before initializing
a distinct restore target, require explicit adoption, exercise all rotations,
reverse the latest values and restart original HTTP with Cryptalis imports
refused. Each restarted child reads the specific latest Items under original
owner authentication. Dynamic tenant-policy provisioning is not implemented.
These are local, public-fixture-custody observations, not production recovery or
external fencing qualification.

`cryptalis.online` captures native writes while it prepares an initial text protection plan. P1 requires each protected table to declare itself single-tenant. P2 accepts tenant-column tables with a host-approved tenant set. Tables without a tenant column retain their fixed table UUID scope. P1 behavior and format v1 remain unchanged. Every protected field must use `TEXT` or `VARCHAR`. The online path does not change the existing maintenance path.

Select P2 by supplying `native_tenants` as a tuple of at most 1,024 unique UUID objects. The artifact stores the approved UUID strings in sorted order. The nil UUID is valid. An omitted tuple selects P1. P2's policy map contains exactly one policy for each approved tenant, including empty scopes, plus one fixed table UUID policy for each single-tenant table. UUIDs outside the approved native and fixed scope union fail before the host key resolver. A native row whose UUID matches a fixed scope can resolve that already approved policy before its native-scope refusal. It still cannot pass planning or locked admission. Lock tables and recheck all existing tenant values before journal creation or other DDL.

Planning records a strict access contract for three distinct direct-login roles: the table owner, the source runtime role, and the target runtime role. The source role has direct table-level CRUD while native columns are active. The target role has direct table-level CRUD while encrypted columns are active. The owner retains table CRUD, `TRUNCATE`, `REFERENCES`, and `TRIGGER`. Column ACLs must be empty. The host must exclude application writers with owner or DDL credentials for the operation.

The capture trigger leaves native values authoritative until the representation switch. Each non-owner insert or update clears all shadow payloads and sets a nullable dirty marker. `NULL` means dirty. For P2, the trigger rejects an unapproved non-NULL tenant with SQLSTATE `55000`. A NULL tenant still fails the native NOT NULL constraint with SQLSTATE `23502`. Tenant or record moves clear every shadow so the next chunk reseals under the row's actual tenant and record identity. Bounded apply calls capture dirty rows by primary key, up to the plan's row and byte limits. The default is 1,000 rows and 1 GiB per call limit; plan limits cannot exceed 5,000 rows or 1 GiB. `max_chunks` bounds each call. Progress counts row versions, not unique rows. Repeated writes can keep a row dirty, so capture does not promise convergence while writes continue.

The host approves the final write pause before it requests the fence. The fence drains in-flight native writers, then prevents writes while bounded catch-up and terminal verification run. `max_chunks` defaults to 1 and accepts 0 through 100,000 per call. After catch-up, `seal` returns the immutable successor artifact. Save it durably outside PostgreSQL before `switch`. A successful switch marks the capture plan P superseded and creates successor A as PENDING. Keep both artifacts. Publish A through the existing host authority, then call `migration.apply(A, ..., until="ACTIVE")` with its independently published `ACTIVATING` pin. The host must keep writers stopped until activation completes.

Before switch, `abort` removes only this operation's capture objects and shadows. It preserves committed native edits, both before and after the fence. After switch, use the existing current-data reverse transition to return to plaintext. Its access contract records the original source runtime role. Keep P and A for all rotation and restored-target operations; successors retain the exact access contract. Finish with the existing package-free native exit.

The terminal proof scans current data in O(N) and verifies all rows. Tenant-scoped unique indexes include the tenant key before the protected equality term. The activation artifact remains `cryptalis.transition/v8`, and its access-contract successor chain remains unchanged. Empty tenant policies stay in the artifact through restore and all rotations. Index DDL and public-slot conversion can also take time under locks. Chunk limits do not bound this work, lock drain, or host publication delay. Plan and approve measured pause costs. This API gives no global near-zero-downtime guarantee. No live KMS or production pause qualification follows. All seven production gates remain UNKNOWN.

Boolean storage uses this same lifecycle with typed value authentication.
The [Boolean checkpoint](status.md#boolean-storage-checkpoint-2026-10-23) records mixed
text/search/Boolean rotations and fresh-cluster backup recovery after payload rotation.
Decrypt-back restores native Boolean columns and the latest values.
These local checks leave production custody, publication authority and all seven gates UNKNOWN.

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

Initial planning, ACTIVE connection checks, restored connection checks,
ACTIVE/PENDING status, payload/search preparation status, Doctor, and the
shared maintenance executor check
effective runtime privileges. Runtime role
attributes and owner membership must exclude administrative authority. Effective
CREATE on the database or declared schemas is refused. Protected tables and
the journal must retain the planned owner. Runtime TRIGGER/TRUNCATE privileges
on protected tables are refused. The journal permits runtime SELECT only.
Runtime table-level mutation privileges and column-level INSERT, UPDATE, or
REFERENCES privileges on the journal cause refusal. Ordinary protected-data
CRUD remains admitted through the declared writer boundary.
`unsafe_runtime_role` reports privilege failures. Owner drift reports
`maintenance_requires_table_owner`. These checks do not replace writer exclusion.

Preparation status checks runtime safety even before P has a journal row and
after cancellation. Its keyless snapshot reports recorded progress, with no
publication authority or fresh value verification. The same `cryptalis status`
command accepts payload and search P artifacts. See
[preparation inspection](walkthrough-migration.md#inspect-rotation-preparation)
for pins, output, refusal codes, and exit behavior.

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
Protection, decrypt-back and restored-frame scans use the [bounded row lease retry](security.md#implemented-cf1-primitives-and-local-custody)
before SQL or progress effects. Other lifecycle routes retain separate expiry limits.
Payload/search staging and paired-frame verification also share one retry
budget per row across pure crypto steps. They check both pinned policies and
the retained-root relationship before fresh admission. Source-only and
activation-target observations and outer return checks still stop on expiry.
The [rotation lease checkpoint](status.md#rotation-row-lease-recovery-checkpoint-2026-10-23) owns the executed boundary.
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

### Add an empty tenant policy under maintenance

`cryptalis.tenancy.plan` accepts an ACTIVE source and actual source pin, an exact
new UUID and host-held Keyring, declared source keys and a verification rate.
The source must carry a scoped-table access contract. Existing/fixed scopes,
wrong policy contexts, occupied membership and unsupported authority refuse.
Existing policies, lock, schema and frames remain unchanged.

Retain the immutable proposal and successor outside PostgreSQL. Apply under
the existing stop/drain/exclusion approval; it repeats source authentication and
emptiness checks under locks before committing source SUPERSEDED/new PENDING.
Normal/adopted successors use v15/v16. Publish the actual successor externally,
then use its ACTIVATING pin with `migration.apply` to reach ACTIVE. A pending
retry inspects the same operation. Cancellation requires the republished source
ACTIVE authority and retains an ABORTED successor. Keep the full lineage for
rotation, restore and current-data removal.

The [verified boundary](status.md#maintenance-tenant-policy-provisioning-2026-10-28)
covers this Python API with O(N) verification and a global writer pause. It is
not scalable online tenant signup or a new policy service. Host authentication,
external custody/publication and production fencing remain separate obligations.

| Change | Engine action |
|---|---|
| Protect or stop protection | Transform payload, create/drop declared search representations, verify, switch, contract |
| Add/remove a query capability | Derive/retire companions and indexes. Reseal payload when authenticated search metadata changes. Verify source/target and queries |
| Normalizer/search-domain change | Full reindex and duplicate/constraint review. New identity, no in-place reinterpretation |
| Payload key generation | Re-encrypt payloads and authenticated companion metadata. Search roots can remain stable |
| Search key generation | Recompute declared search terms and reseal searchable CF1 frames with fresh nonces. Maintain native indexes during atomic UPDATE. Keep writers stopped |
| Provider/KEK change | Rewrap exact roots and verify unwrap/context under the new provider. Payload/search bytes stay unchanged |
| Format/codec upgrade | Deploy required readers first, transform, verify, then switch writers. Retire old readers only after dependency review |

**IMPLEMENTED, read-only preparation:** `rotation.plan_payload_rotation` emits an
inactive `PayloadRotationPlan` (P) for a current ACTIVE protection plan. It authenticates
source frames in a repeatable-read snapshot and requires exact retained source
wrappers/roots, one new independent monotonic payload root, and unchanged search
custody. Historical readers and tenants with no remaining rows remain required.
The proposal records source observations, schema/policy digests, reserved operation
identities, logical batch limits and host-measured cost estimates. It stores no
root, wrapper bytes or plaintext digest. It changes neither data nor authority.

The length scan bounds the aggregate logical source/target/decoded-text budget
across each complete row before frame retrieval. This is not a Python RSS,
database memory, driver buffering, provider or capacity bound.

**IMPLEMENTED, staged preparation:** `rotation.apply_payload_rotation` uses P's
own operation pin, maintenance approval, journal row, guards, and ciphertext
shadows. P supplies no application deployment authority. During preparation,
the original public frames and source journal stay unchanged. The executor checks exact source
authority, retained custody, and schema before expansion. Each chunk holds
write-excluding table locks across length probes, frame reads, shadow updates,
and the cursor commit. Shadow updates and progress commit together.

Resume authenticates the committed prefix and reuses its ciphertext bytes.
Before BACKFILLED, the executor compares every source and target value, exact
generations, NULLs, search headers, and source observations from P. An invocation
that finds BACKFILLED repeats full authentication. Journal counters cannot replace
that check. A `max_chunks` limit can leave EXPANDED after the last data chunk.
Resume the same operation to complete terminal verification.

`rotation.status_payload_rotation` reports recorded progress without keys or
effects. Its verification is `NOT_PERFORMED`. Staging changes the schema, so
ordinary attachment cannot treat the source as an unchanged ACTIVE deployment.
Writers must remain stopped. `rotation.abort_payload_rotation` requires the
republished source ACTIVE pin and source custody. It checks unchanged source
data, exact shadows, and guards before atomic cleanup and an ABORTED marker.
Target custody is unnecessary. A terminal retry preserves later source edits
and cannot revive a source that a later operation superseded.

**IMPLEMENTED, sealed activation:** `rotation.seal_payload_rotation` requires
BACKFILLED and measured `copy_rows_per_second` and `copy_wal_bytes_per_row`.
Under maintenance locks, it authenticates source frames against P and compares
exact source/target generations, values, NULLs, and unchanged search headers.
It returns activation artifact A from the actual staged ciphertext observations.
It changes no database data, schema, or journal. Provider preparation can incur
audit/cost effects. The same staged bytes and costs produce identical A.

Without restore lineage, A is a `cryptalis.transition/v3` MigrationPlan with `kind: payload_rotation`.
It binds P's digest, target frame/membership observations, batch limits, and
exact source-to-P ancestry. P reserves A's operation ID without embedding A's
digest. This avoids a circular artifact identity. Persist exact P and A outside
the database before switch. P never supplies publication authority.

**IMPLEMENTED, atomic cutover:** `rotation.switch_payload_rotation` requires
A's PREPARED or PENDING pin and maintenance approval. It repeats source proof
against P and paired verification against A before replacing public ciphertext.
A server-side UPDATE copies verified shadows into the existing public columns.
Public column identities, constraints, expression indexes, grants, and metadata
remain intact. Search roots and authenticated search headers do not change.
This operation requires no search reindex.

The transaction removes P's shadows, exchanges its guards for A's guards,
and records source SUPERSEDED to P, P SUPERSEDED to A, and A PENDING.
A fresh bounded target pass checks copied frames against A before commit.
Preparation resume and cancellation refuse the switched P.

After an uncertain switch, inspect the original transaction and exact artifacts.
A PENDING retry authenticates current target frames and reciprocal ancestry
against A. Original source frames no longer exist for comparison. It does not
call the separate source resolver. Target custody still requires retained roots.
Missing A with partially superseded ancestors is inconsistent and cannot
justify reconstruction of a commit.

Publish exact A and its target policies through the trusted host process.
Shared `migration.apply(A, ..., until="ACTIVE")` admits only ACTIVATING or ACTIVE
pins and never expands a missing payload successor. ACTIVATING authenticates
current target frames against A, even when the journal already claims ACTIVE.
A genuine ACTIVE pin permits later ordinary edits. Decrypt-back and removal
use those latest values, rather than the original source snapshot.

A estimates the atomic copy plus five authentication passes: one source pass,
a paired source/target pass, one post-copy target pass, and one publication
pass. The paired pass counts twice. Prior preparation and sealing, lock drain,
DDL, provider overhead, and capacity guarantees remain outside that estimate.
The terminal full-table write uses one transaction. Preparation chunk limits
do not bound that write or its WAL.

A's journal records `cutover_measurements.copy_wall_ns` and
`copy_wal_bytes_cluster_delta` around the native copy loop. These observations
exclude later DDL, verification, commit, and publication. The WAL delta can
include other cluster transactions. These values supply neither total pause,
isolated WAL, a capacity bound, nor host authority. Keyless status still reports
`NOT_PERFORMED` and supplies no fresh cryptographic proof.

The [two-artifact decision](decisions.md#payload-rotation-preparation-and-activation-2026-10-23)
defines the preparation and activation boundary. The
[adopted-lineage extension](#payload-rotation-after-adopted-lineage-2026-10-24)
defines the v5/v6 route below. Direct payload planning from an explicit restore
binding follows the [separate v2 route](#generation-planning-from-a-restore-binding-2026-10-24).
All seven full gates remain UNKNOWN.

### Payload rotation after adopted lineage: 2026-10-24

**IMPLEMENTED, bounded verification:** start from the current ACTIVE v5 or v6
successor, its own pin and retained source policies. Do not pass the old restore
binding as current authority. The existing payload preparation proposal embeds
that complete source and keeps its v1 format.

Use the existing preparation, cancellation, sealing, switch and publication
steps. Before switch, cancellation needs source custody and the source ACTIVE
pin; target custody can remain unavailable. Exact source admission, guards and
shadow checks still apply. Terminal cancellation preserves later source edits
and cannot revive a superseded source.

Seal lineage-bearing activation as transition/v6 with all v3 payload proof
members and the unchanged nonempty flat restore lineage. Keep inherited
predecessors, then append source and preparation. Reuse exact frame-probe,
ancestor-order, target-chain and owner checks before effects. A PENDING retry
authenticates the current successor and reciprocal ancestry; publish it under
its own pin before ordinary writers resume.

Later payload rotation can retain the same lineage. Ordinary rewrap of v6
produces rewrap/v2 and a v5 successor. Fractional copy rates must survive both
direct and embedded-source artifact round-trips. No-lineage payload activation
remains v3. [Search rotation with lineage](#search-rotation-after-adopted-lineage-2026-10-24)
uses its separate successor format. Direct restore-binding generation planning follows its
[separate route](#generation-planning-from-a-restore-binding-2026-10-24). This adds no key-retirement permission,
host authority service or cryptographic format. All seven production gates remain UNKNOWN.
See the [format decision](decisions.md#adopted-target-payload-rotation-2026-10-24).
Native TEXT/VARCHAR and installed TEXT controls, plus the unchanged installed
Smolink journey, verify this boundary. [Status](status.md#payload-rotation-after-adopted-lineage-2026-10-24)
owns the exact receipts, full regression and remaining limits.

### Search-key rotation

**IMPLEMENTED, bounded native verification:** search rotation uses the same two-artifact
preparation, sealing, cutover, and publication protocol as payload rotation.
`rotation.plan_search_rotation` returns P as `cryptalis.search-rotation/v1`.
P supplies no application deployment authority. Without restore lineage, activation artifact A is a
`cryptalis.transition/v4` MigrationPlan with `kind: search_rotation`. Its exact
proof fields are `search_rotation_plan_digest`, `search_rotation_observations`,
and `search_batch_limits`.

For each policy with a selected search generation, retain every exact source
wrapper and root material. Add one independent search root above all retained
search generations. Keep the selected payload root and generation unchanged.
A tenant policy with no selected search generation stays unchanged. Searchable frames receive
new terms and fresh nonces under the unchanged selected payload root.
Storage-only frames retain their exact bytes, including when their tenant also
has searchable fields. One selected search generation serves application queries.
Retained search readers do not authorize mixed-generation OR queries.

`apply_search_rotation` stages bounded chunks under P's exact guards and schema.
Rows and progress commit together. Resume reuses authenticated staged bytes.
BACKFILLED retries repeat paired source/target proof. `status_search_rotation`
reports `NOT_PERFORMED`. `abort_search_rotation` requires the republished source
ACTIVE pin and source custody, removes only P's staging, and preserves later
source edits on terminal retries. It needs no target provider.

`seal_search_rotation` authenticates the source against P and binds A to the
actual new target frame hashes. Persist P and A before destructive switch.
`switch_search_rotation` repeats paired proof, copies shadows into existing public
columns, and maintains native expression and unique indexes through UPDATE.
Source SUPERSEDED to P, P SUPERSEDED to A, guard exchange, and A PENDING
commit atomically with a fresh target check. Original columns and metadata remain
intact. PENDING recovery checks A's target proof because original frames are gone.
A switched P cannot resume preparation or cancel the cutover.

Shared `migration.apply` accepts A only for ACTIVE publication with an
ACTIVATING or ACTIVE pin. ACTIVATING repeats A's target proof even if the
journal claims ACTIVE. A genuine ACTIVE pin permits later application edits
and latest-value decrypt-back/removal. The existing restore-binding format remains
the selected recovery contract. Search rotation with adopted lineage follows
the [search extension](#search-rotation-after-adopted-lineage-2026-10-24).
The [payload extension](#payload-rotation-after-adopted-lineage-2026-10-24)
defines the separate lineage-bearing payload route.

Measured `copy_rows_per_second` and `copy_wal_bytes_per_row` must include native
maintenance of every affected expression and unique index. The terminal copy
and index updates share one full-table transaction, beyond bounded preparation
chunks. Logical batch limits establish no process-memory, storage-capacity, WAL,
or pause bound. The same five authentication passes accompany the terminal copy.

Native controls cover current-value search and uniqueness, retained readers,
paired proof, cancellation, lost COMMIT replies, and SIGKILL with fresh-process
recovery. The text backup profile also completes adoption and latest-value
removal. [Status](status.md) owns current receipts and verification boundaries.
All seven full gates remain UNKNOWN.

### Search rotation after adopted lineage: 2026-10-24

**IMPLEMENTED, bounded source and installed verification:** use the current ACTIVE v5/v6/v7 source, its
own pin and retained policies. Preparation keeps `cryptalis.search-rotation/v1`.
Seal a `cryptalis.transition/v7` search_rotation successor with every v4 proof
member, unchanged flat restore lineage and inherited predecessors followed by
source and preparation.

Use the existing staging, resume, cancellation, cutover and publication steps.
Before switch, cancellation requires source custody, its current ACTIVE pin and
maintenance approval. Target custody can remain unavailable. Terminal retries
preserve later edits and cannot revive a superseded source. PENDING recovery
authenticates the successor and reciprocal ancestry. Publish under its own pin.

Retain exact frame/probe, owner and target-chain admission. Keep one selected
search namespace and native index/uniqueness semantics. Later rewrap returns to
v5. Later payload rotation produces v6. Both retain lineage and embedded
fractional-rate identities. Direct restore-binding planning follows the
[separate v2 route](#generation-planning-from-a-restore-binding-2026-10-24).

Compatible readers must precede publication. Crypto, journal and authority
contracts stay unchanged. No key-retirement permission follows.
All seven production gates remain UNKNOWN. See the
[format decision](decisions.md#adopted-target-search-rotation-2026-10-24).
Source TEXT/VARCHAR and installed TEXT controls verify this boundary.
[Status](status.md#search-rotation-after-adopted-lineage-2026-10-24) records exact
receipts and the separate ordinary application regressions.

### Generation planning from a restore binding: 2026-10-24

**IMPLEMENTED, bounded source and installed verification:** supply the existing binding through `restore`
when planning payload or search rotation directly on an adopted target. Retain
the original source and ACTIVE pin. A nonnull binding produces purpose/v2 with
the full embedded binding. With no explicit binding, purpose/v1 remains byte-compatible.

Validate identity, original custody, frame probes, owner, journal-state digest
and the combined lineage before provider work. Use the evaluated actual target
for maintenance and read-only status. Staging preserves the original source
journal. Source-only cancellation keeps the original binding usable and later
edits intact. Status uses the embedded binding, without separate binding authority.

Seal v6/v7 with all existing proofs, inherited lineage plus the explicit binding,
and the same flat source/preparation/activation ancestry. PENDING retry checks the
current target, without rechecking a superseded source or calling its resolver.
Publish under the successor's own pin. Deploy v2 proposal readers before use.
Compatible existing readers can read unchanged v6/v7 activation formats.
No crypto, provider, authority or key-retirement permission changes. All seven
production gates remain UNKNOWN. See the
[format decision](decisions.md#direct-restore-binding-generation-planning-2026-10-24).
[Status](status.md#direct-restore-binding-generation-planning-2026-10-24) records
19 controls each for source TEXT/VARCHAR and installed TEXT, refusal/recovery scope,
and the unchanged SQLModel direct source/installed and legacy installed journeys.

Keep exactly one active application writer representation during maintenance cutover.
No partial-generation OR query or cross-generation uniqueness gap is silently admitted.
Native KMS KEK material rotation is different from root rewrap, payload rotation, or search reindex.
Rewrap alone does not cure a leaked payload/search root.
No normal rotation automatically deletes historical keys or makes copied old ciphertext safe after compromise.

**IMPLEMENTED, verified in the named local cell:** `cryptalis.rotation.plan_rewrap`
proposes an inactive root rewrap from an ACTIVE protection plan. It leaves the
database and deployment pin unchanged. It compares exact retained source and
target roots and authenticates current frames in a read-only repeatable-read
snapshot. Its protocol records digests and public contexts, not secret roots or
wrapped bytes. The host retains both complete policies outside the database.
These observations are not maintenance approval or current publication authority.

**IMPLEMENTED, bounded native evidence:** `apply_rewrap` rechecks the immutable
proposal under the existing maintenance executor and table locks. It authenticates
all current frames under both custody sets and preserves every frame byte.
The same transaction installs the existing writer guard, records the successor
as PENDING and marks its exact predecessor SUPERSEDED. A changed source requires
a new plan. A committed retry inspects and retains the original successor.

The host publishes `proposal.activation_plan` separately. Use the existing
`migration.apply` with its ACTIVATING pin to verify target frames against host
observations and remove the guard. A journal ACTIVE claim cannot replace that
verification. Normal ACTIVE operation permits later application edits.
Old deployment pins fail. Exact predecessor links remain necessary for runtime,
restore and reverse/removal admission. Repeated rewraps use a flat trusted chain.

The transition/v2 reader requirement and retained artifacts are defined in
[decisions](decisions.md#root-rewrap-successor-artifacts-2026-10-23).
The native controls include repeated custody changes, latest-value decrypt-back,
removal, a lost terminal COMMIT reply and independent process restart from disk.
Rewrapped text and VARCHAR backups also complete fresh-cluster recovery, approved
adoption, latest-value decrypt-back/removal and native metadata checks.
Adoption refuses the original custody policy even though the root material matches.
The process and provider fixtures use public synthetic roots. They establish
no external custody or authenticated deployment authority.
`abort_rewrap` cancels a PENDING successor only after the host republishes the
exact source ACTIVE pin. It rechecks original source state, source keys,
membership, frames, schema and guards under maintenance locks. Source ACTIVE,
guard removal and the terminal ABORTED successor marker commit together.
Target custody can remain unavailable. An uncertain retry inspects that marker
and current source authority without replaying snapshot data. After ordinary
source edits, repeat cancellation leaves those edits intact. A later operation
that supersedes the source prevents an old cancellation from reviving it.
Inspect current progress with the original source plan and current source pin.
An ACTIVE successor requires a new rewrap rather than cancellation.
The [adopted-target extension](#adopted-target-root-rewrap-2026-10-24) defines
the separate rewrap and cancellation path for an adopted copy.
After activation, a new rewrap can change custody again without rewriting data.
The full lifecycle gate remains UNKNOWN.
See [status](status.md#active-root-rewrap-checkpoint-2026-10-23).

### Adopted-target root rewrap: 2026-10-24

Supply `restore=binding` to `plan_rewrap` for the first rewrap on an adopted
copy. Preserve that exact binding in rewrap/v2. A source with inherited restore
lineage can use `restore=None`. The v5 successor records the effective target,
complete flat adoption lineage and ordinary ordered predecessors. Shared
schema checks retain each admitted restored CHECK through later operations
and backups. Newer recorded definitions take precedence for the same field.

Before first execution, validate the original source, binding and current
adopted journal state. Check every custody entry against the original source
policy map before effects. Inherited bindings remain historical records after
custody changes. Once the successor is PENDING, retry against that successor.
The superseded source cannot pass its former ACTIVE-state check.
Publish the successor with its own current pin. Its inherited binding records
history and cannot substitute for successor publication authority.

Cancel only under the republished original source ACTIVE pin and its original
binding. Restore its exact original journal state and remove successor guards
atomically. A terminal retry preserves later application edits and cannot
revive a source that another operation superseded. Cancellation cannot republish
the old binding as successor authority. An ACTIVE successor needs a new rewrap.
The [payload extension](#payload-rotation-after-adopted-lineage-2026-10-24)
defines rotation from an ACTIVE lineage-bearing successor. The
[search extension](#search-rotation-after-adopted-lineage-2026-10-24) supplies its separate route. The host retains
custody policies, fenced-source evidence and restore approval.

**VERIFIED, bounded native profile:** one
[source export](_reset/fresh-cluster-export-20261024-5.json) and
[17 fresh-target controls](_reset/fresh-cluster-restore-20261024-4.json) pass.
The [earlier expanded failures](_reset/fresh-cluster-restore-20261024-3.json)
remain recorded. Full-suite and installed-application results retain their
separate verification boundaries. See the
[adopted-target format decision](decisions.md#adopted-target-root-rewrap-2026-10-24).

## Restore and authority loss

The host supplies current-policy provenance, source fencing, and quarantine.
Local backup/adoption tests below do not authenticate those external controls.
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

### In-place reverse format: 2026-10-19

**IMPLEMENTED:** `cryptalis.deprotection` adds `cryptalis.reverse/v1` for an admitted
`cryptalis.transition/v1` source. The reverse row shares the source journal and advisory
lock; the source row remains `ACTIVE` and is never mutated. Reverse phases are
`PREPARED`, `EXPANDED`, `BACKFILLED`, `VERIFIED`, `PLAINTEXT_PENDING`, and
`PLAINTEXT_ACTIVE`. External pins are `PLAINTEXT_ACTIVATING`, `REMOVING`, and `REMOVED`;
a pin may not claim a later plaintext phase than the journal has reached, and the journal
may not report plaintext active while the external pin still declares ciphertext.
Expand adds native-typed plaintext staging columns and fences inventoried schemas.
Backfill decrypts current frames and verifies membership, authentication, and exact values.
The default layout drops the ciphertext column without `CASCADE`, renames staging into the original
column name, restores recorded constraints and indexes, and records the resulting schema.
Pre-switch abort removes only reverse-owned staging and guards. Removal requires a
`RemovalApproval`, matching external pins, an empty metadata diff, no remaining
unadmitted `_cryptalis` relations or functions in inventoried schemas, and the recorded retirable
aborted rows. A repeated terminal request asserts the recorded state and does not invent a
new success.
Journal retirement and later removal checks also compare the native catalog with
lock v2 `source_metadata`. Drift raises `metadata_not_restored:source_metadata`;
a failed retirement rolls back the journal drop. A terminal retry inspects journal
existence before it checks the package-free state.

The original reverse checkpoint used a transition/v1 source. Current reverse
admission also accepts root-rewrap v2 and payload-rotation v3 successors with
their exact validated ancestor chains.

**VERIFIED, local PostgreSQL 16.15 cell:** seven lifecycle cases pass on SQLAlchemy 2.1.3
and 2.0.51. Full suites report **1,299 passed** on 2.1.3 and **1,271 passed, 28 skipped**
on 2.0.51 ([2.1.3 receipt](_reset/reverse-full-sa21-20261019.json),
[2.0.51 receipt](_reset/reverse-full-sa20-20261019.json)).
The cases cover edited and deleted rows, a row added while protected, wrong custody,
corrupt frames, disabled guards, lost replies, abort, metadata restoration, and unsafe
plan/removal refusals. Counts are not gate evidence.

**Limits:** the default DROP/RENAME layout cannot restore physical column order (`attnum`). Lock v2
captures and restores protected-column comments, statistics targets, storage,
compression, options, column grants, constraint and index comments, and extended
statistics. At that checkpoint, protection refused expression extended statistics and
sequences owned by a protected column. The [sequence extension](#owned-sequence-preservation-and-restored-identity-2026-10-24)
adds the bounded preservation contract. At that checkpoint, fresh-cluster
restore, a real package-free application run, retained-backup reader proof, and the
retained-native alternative remained UNKNOWN.
Layout comparison and the decision not to promote retained-native are recorded in
[the 2026-10-19 evaluation](_reset/layout-evaluation-20261019.md).

### Owned-sequence preservation and restored identity: 2026-10-24

**IMPLEMENTED, bounded source and installed verification:** lock/v5
captures ordinary persistent sequences automatically owned by protected columns.
Each sequence must share the table's schema and owner. The inventory records
qualified name, OID, native type, configuration, comment, effective ACL, grantor,
grant option and automatic dependency. Identity, internal, extension and other
unsupported dependencies refuse. Existing generated-key and protected-default
rules remain unchanged. Without the public-slot opt-in, locks without owned sequences retain their earlier formats.

Forward and reverse switches check the inventory, detach ownership, replace the
column and attach the same sequence to its replacement. The existing transaction
contains all steps. After native ALTER locking, another check requires the same
OID, owner, configuration, comment and ACL before column replacement. ACTIVE,
paused reverse, restore and removal checks require the admitted inventory.
Older locks refuse a newly owned sequence. Terminal removal exempts only exact
admitted sequence identities from its Cryptalis object scan, including declared
`_cryptalis_*` names. Other leftover objects still refuse.

Cryptalis does not capture mutable counters as drift facts, call sequence
functions, recreate sequences or replay their state. Native increments, rollback
gaps and unused cache reservations remain PostgreSQL behavior. Sequence locking
does not authenticate the host's writer-exclusion assertion or fence all consumers.

Sequence-bearing adoption emits restore/v2. Its complete ordered map binds each
model, schema, name and column to its source-effective OID and actual target OID.
Exact logical facts precede the mapping. Later checks require the mapped target
identity. Flat lineage composes mappings through later adoption and direct
generation planning without rewriting source artifacts or journal authority.
Without the public-slot layout, sources without owned sequences retain restore/v1.
Deploy v5/v2 readers first.
CF1, provider authority and retained-key duties remain unchanged. See the
[format decision](decisions.md#owned-sequence-metadata-and-restored-identity-2026-10-24)
and [current evidence](status.md#owned-sequence-preservation-and-restore-2026-10-24).
The four source and installed fresh-target controls pass mapped identities through inherited
root/payload lineage, direct generation planning, a second adoption and native
exit. Actual older readers refuse both new formats before database access.
The revised compiler query passes 201 source and 269 installed affected/application
controls. Both installed original SQLModel adoption paths also pass. The full
source regression passes 2,478 tests and 116 subtests. The later
[public-slot extension](#public-column-slot-layout-2026-10-24) has a separate
verification boundary. Retained-native preservation remains open.

### Public column slot layout: 2026-10-24

**IMPLEMENTED, bounded source and installed verification:** select `layout="preserve-public-slots/v1"`
through the public compiler or protection planner. Lock/v6 carries that immutable
policy and the v5 metadata shape, including empty owned-sequence inventories.
Attachment, reverse and rotation derive their strategy from the validated lock.
None and earlier formats retain existing selection and DROP/RENAME behavior.

Within the existing maintenance transaction, ALTER COLUMN TYPE USING copies
verified staged values into original public attributes. Forward rebuilds public
CF1 CHECKs and equality indexes before dropping shadows. Reverse removes generated
dependencies, converts those same attributes to native types and restores captured
constraints, indexes, statistics and column metadata. Sequences retain the same
object and ownership attribute without detach/reattach. Native counter gaps remain
valid. No durable half-converted state is admitted.

ACTIVE metadata preserves captured comments, statistics targets, options and ACLs.
Storage/compression become EXTENDED/default for bytea. Reverse restores captured native
policies. Late expression statistics remain unsupported and refuse before providers
or effects. Host pins and mapped slot checks bound paused and terminal observations.
A matching mutable journal cannot authorize changed public slots.

Restore/v3 adds a complete ordered `columns` map to existing binding members.
Each entry has `model`, `column`, `source_attnum` and `target_attnum`. Both slots
are exact native integers greater than zero and below 32768. Sources must
match the current inherited mapping. Targets must be unique per model and
preserve visible name order. The `sequences` member is mandatory, including an
empty list. Flat lineage composes both maps. Original source identity and
journal authority remain unchanged. Restore/v1/v2 cannot authorize this layout.

The operation rewrites heap and index storage under native maintenance locks.
Host row-rate, WAL and staging estimates exclude these DDL costs. This contract
changes no CF1 format, key custody, generated-ID admission or retained-backup duty.
Current source TEXT fresh-target profiles pass six each, with and without an
owned sequence. See [status](status.md#public-column-slot-preservation-2026-10-24)
for the focused and VARCHAR scope. The actual installed wheel passes 294
affected/application controls, six sequence-bearing fresh-target cases and the
original three-field SQLModel lifecycle. Installed VARCHAR and legacy compatibility
profiles also pass. The full source regression passes 2,503 tests and 116 subtests.
The original three-field application still needs fresh-v6/direct-binding qualification.
The [format decision](decisions.md#original-slot-layout-and-restore-authority-2026-10-24)
owns version admission. All seven gates remain UNKNOWN.

### Late expression-statistics admission: 2026-10-24

Expression-only statistics can omit ordinary column-key entries. Admission must
check non-null `stxexprs` directly rather than infer absence from column keys.
Legacy layouts share this rule with public-slot layout v6. The guard extension
covers source, unrecorded-metadata and protected-contract checks.
Two native legacy failures establish the pre-fix gap. The first expanded
candidate passes 42 and fails one. An EXPANDED reverse retry reaches the forbidden resolver.
A separate first reverse-expansion control also fails. Revised guards pass 44
focused source controls, including both paths before providers or DDL and exact
repair through native exit. Affected-source and revised installed controls pass,
including the original three-field fresh-v6 journey and legacy sequence/adoption.
Formats and cryptographic contracts remain unchanged.
See the [decision](decisions.md#expression-statistics-admission-across-layouts-2026-10-24)
and [current evidence](status.md#legacy-expression-statistics-admission-2026-10-24).

### Reverse privilege admission: 2026-10-23

**IMPLEMENTED, bounded:** reverse planning checks source and plaintext runtime
safety before key work. Reverse apply, abort, removal, and status share
phase-aware admission. The current external host pin selects the required role:

| Host pin | Required runtime safety while the journal exists |
|---|---|
| PREPARED, EXPANDED, BACKFILLED, VERIFIED, PLAINTEXT_PENDING | Protected source runtime |
| PLAINTEXT_ACTIVATING, PLAINTEXT_ACTIVE, REMOVING, REMOVED | Declared plaintext runtime |

The host's PLAINTEXT_ACTIVATING pin asserts publication of the plaintext policy.
The former protected role no longer supplies runtime admission at that boundary.
A forged journal phase
cannot select the plaintext role while the host still supplies a pre-publication
pin. Source privilege failures raise `unsafe_runtime_role`. Plaintext privilege
failures raise `unsafe_plaintext_runtime_role`. The shared checks cover effective
privileges and planned ownership, rather than only role attributes at plan time.

An admitted ABORTED retry remains idempotent and checks source runtime safety.
It needs no keys and replays no data. A REMOVED request first checks actual
journal existence. Only an absent journal permits both role checks to be skipped.
Terminal removal, status, and removal inspection then check native schema,
captured metadata, and absence of Cryptalis objects. They preserve ordinary
edits after removal and do not reimpose retired runtime privilege boundaries.
A missing journal under an earlier pin remains a failure.

[Status](status.md) owns current receipts and test totals. These bounded checks
supply no authenticated host-policy provenance or complete writer exclusion.
All seven full gates remain UNKNOWN.

### Restored protected-backup adoption: 2026-10-19

**VERIFIED, isolated PostgreSQL 16.15 cluster:** a protected `pg_dump` of one schema
restores into a fresh cluster with the same role names and the recorded privileges.
The runtime role observes `bytea` only. The retained key policy and descriptor recover
every exact value through the product decoder and an independent decoder oracle.
A restored journal remains progress evidence, never restore authority by itself.

`cryptalis.restore/v1` (`src/cryptalis/restore.py`) adds the approved bring-up contract.
Sequence-bearing sources use the [restore/v2 extension](#owned-sequence-preservation-and-restored-identity-2026-10-24).
A host `RestoreApproval` asserts the restore intent, the quarantine, and a fenced source
(`source_fenced`). Adoption runs as the owner without durable database changes.
It authenticates every retained frame with the retained keys, verifies the target
facts and environment, compares the
restored schema to the source lock, and issues a `RestoreBinding`. The binding records the
source plan identity and original target facts, the restored target facts and environment,
the restored source journal state digest, the retained custody set, and each restated
compiler frame `CHECK`.

Restored-frame authentication retries one unfinished row after actual lease expiry,
with an exact retained-policy check and fresh key preparation. A second expiry,
provider fault or changed policy stops adoption with `KeyUnavailable`. Schema
inspection precedes authentication. Effectful savepoint probes follow it.
The [restore lease checkpoint](status.md#restored-frame-lease-recovery-checkpoint-2026-10-23) records native and fresh-cluster controls.

A logical dump and restore can restate a frame `CHECK` with different boolean grouping.
Adoption accepts only the known PostgreSQL 16 nested and flattened forms of the declared
frame `CHECK`. Length bounds, header bytes, generation checks, and identifier quoting must
match. Every other schema fact must remain structurally equal. Savepoint probes also
check rejection of a truncated frame, a changed magic byte, a zero payload generation,
and a zero search generation on a query field. The probes write and roll back
inside savepoints and accept only SQLSTATE 23514. A restated frame without a retained row,
a failed probe, or any other definition change is refused with
`restored_constraint_probe_failed` or `restored_definition_restatement_unsupported`.
Later checks compare the live structure and the restored journal state against the binding,
so a stale, cloned, tampered, or drifted copy is refused with a typed failure.

Attachment accepts `(plan, pin, binding)`. The binding changes the evaluated target only:
the source plan, pin, and journal are unchanged, and a binding never authorizes a different
source. Reverse `plan(..., restore=binding)` records the binding in the reverse artifact and
re-checks the binding identity against the source pin. Protected deployment admission and
reverse execution also check each recorded restatement against the source field and known
forms. An older binding cannot authorize weaker bounds because its finite probes passed.

**Evidence:** the qualification module refuses missing or unfenced approval, the current
source, tampered bindings, and corrupt frames; it then refuses post-adoption structural
schema drift, definition-only frame drift, and journal-state drift on the restored copy;
it restores the adopted facts and completes the adopted lifecycle: attach,
ORM read, exact search, modify, add, delete, reverse to plaintext under the binding,
removal, schema-fact equality, native `psycopg` readback, and journal absence. Receipts:
[export](_reset/fresh-cluster-export-20261019-3.json),
[adoption](_reset/fresh-cluster-restore-20261019-3.json). The full suites report
**1,302 passed, 2 skipped** on SQLAlchemy 2.1.3
([receipt](_reset/restore-full-sa21-20261019.json)) and **1,274 passed, 30 skipped** on
2.0.51 ([receipt](_reset/restore-full-sa20-20261019.json)).

**Limits:** the host asserts source fencing and quarantine; this package does not
authenticate either and has no cryptographic evidence of source isolation. Adoption
refuses a restated constraint without a retained frame row,
and it admits two exact forms rather than general SQL equivalence. The probes cover only
the named malformed frames. Physical column order remains open. Owned-sequence
capture was unadmitted at that checkpoint. Its [extension](#owned-sequence-preservation-and-restored-identity-2026-10-24)
has a separate verification boundary.

### Payload-rotation backup adoption: 2026-10-23

**IMPLEMENTED, bounded native profile:** a protected backup can use the ACTIVE
payload successor A and contain a later application edit. Adoption reuses
`cryptalis.restore/v1` and the existing `RestoreBinding`. It authenticates
current frames under A's exact target policy and selected generation. It does
not freeze ordinary ACTIVE backups to A's original sealed frame observations.
A valid source-generation frame fails even when retained roots can decrypt it.
The original source policy also fails target-policy admission.

Before any malformed-frame probe or provider call, adoption checks the source
identity, ACTIVE progress, exact reciprocal source-to-P-to-A chain, runtime
privileges, and protected-column grants. A's proof digest and recorded counters
must match its immutable contract. Missing ancestors, forged successor links,
wrong proof digests, unsafe privileges, and journal-column write grants cause
refusal. Column-grant drift raises `source_metadata_changed`. Current restored
connections repeat privilege and metadata checks after adoption.

The fixture verifies generation-2 decoding through both the product reader and
an independent decoder. It also exercises current-value reads/search, edits,
decrypt-back, and journal retirement. The profile preserves the source metadata
checks. Its evidence does not authorize root deletion or retained-backup loss.
The walkthrough lists the profile commands. [Status](status.md) owns current
receipts and test totals.

Backup adoption after payload rotation differs from rotation on an adopted
target. The [adopted-lineage extension](#payload-rotation-after-adopted-lineage-2026-10-24)
uses a published v5/v6 successor. Direct payload planning from a restore
binding follows the [separate v2 route](#generation-planning-from-a-restore-binding-2026-10-24).
[Search rotation with lineage](#search-rotation-after-adopted-lineage-2026-10-24)
uses a published successor. Host publication provenance,
source fencing, and provider custody remain external qualification boundaries.
All seven full gates remain UNKNOWN.

### Search-rotation backup adoption: 2026-10-23

**IMPLEMENTED, bounded native verification:** the text profile exports an ACTIVE
search v4 successor and a later protected edit to row 999. That edit differs
from A's sealed frames. Adoption uses the existing `cryptalis.restore/v1`
`RestoreBinding` and authenticates current selected-generation frames. It does
not freeze the backup to A's original sealing hashes.

The independent decoder derives the generation-2 search root, HKDF keys, and
HMAC terms from public fixture definitions. The selected payload root remains
unchanged. The product reader and independent decoder recover the same current
values. A valid original search-generation-1 frame fails adoption, although its
root remains retained. The original source policy also fails target admission.

Authority controls reject missing source/P ancestors, forged links, proof-digest
changes, and malformed counters before probes or key preparation. The adopted
application reads, searches, edits, decrypts current values, and removes eligible
journal/storage objects. Native metadata checks preserve the source contract.
The harness also accepts `--varchar`. [Status](status.md) owns each profile's
receipts and qualification boundary. This evidence does not qualify production
custody, host publication, or source fencing. Later generation rotation requires
a [published lineage-bearing successor](#search-rotation-after-adopted-lineage-2026-10-24),
or the [direct-binding route](#generation-planning-from-a-restore-binding-2026-10-24).
All seven full gates remain UNKNOWN.

### Independent application exit: 2026-10-19

**VERIFIED, local PostgreSQL 16.15 cell:** an ordinary three-model application with a real
foreign key, two tenants, and a zero-row protected table completes protect, exact search,
modify, decrypt-back, and approved removal under attachment. A fresh process with
Cryptalis imports blocked then edits, inserts, deletes, and reads through the
application's own code and matches the expected native values. The post-removal schema
facts equal the recorded source facts for every protected table. The application module
imports no Cryptalis component; only the host bootstrap does.

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
