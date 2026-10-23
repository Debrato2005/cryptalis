# Simplification decisions

**SPECIFIED:** this ledger records the approved scope and selected architecture.
It does not preserve old IDs as implementation obligations. Historical dispositions remain in [archived revamp evidence](research/revamp-evidence.md).
[Status](status.md) owns IMPLEMENTED/VERIFIED claims. All seven full gates remain UNKNOWN.

## Approved scope decisions: 2026-10-08

These decisions are final. Scope-only D blockers are resolved. No decision supplies executable qualification.

| Decision | Approved contract | Resolution/evidence limit |
|---|---|---|
| 1. Stack | Python 3.12+, SQLAlchemy 2.x, psycopg 3 sync/async, PostgreSQL 16 | Scope D resolved. Exact cell tests remain required |
| 2. First protected type | Text first. The 2026-10-22 VARCHAR admission extends the text family. Other types remain UNSUPPORTED BY DESIGN until admission | Type-scope D resolved. Text/ID descriptors and collation evidence remain required |
| 3. Capabilities | SUPPORTED: storage-only, equality, IN, tenant-scoped uniqueness | Capability/grammar scope D resolved. Every other operation rejects until admission |
| 4. Tenancy | Each protected table declares a tenant column or declares itself single-tenant | Tenant-scope D resolved. Missing tenancy blocks plan |
| 5. Primary keys | Require application-generated UUID, Snowflake-style, or other app-assigned ID. Reject serial/identity/database-default keys at plan time with a plain explanation | Identity-scope D resolved. Historical sequence-preallocating spikes do not implement this contract |
| 6. Targets | Added p95 ≤ 3 ms point/equality, ≤ 8 ms IN-20. Protected column with equality index ≤ 2× storage | Read/storage-budget D resolved as targets, not achievements. Write-throughput and pause budgets remain D |
| 7. Authorities/review | No designated production key provider and no independent review. Local provider is functional evidence only | G-PROVIDER, G-POLICY, and review requirements remain UNKNOWN. No production publication/restore procedure is selected |
| 8. Build order | Compiler → crypto/KeyProvider/dev provider → sync/async SQLAlchemy → equality/IN/uniqueness → plan/apply/verify → decrypt-back/remove → three rotation operations | One slice per run. Each requires real PostgreSQL tests before the next. Advanced work requires all seven slices, then six-gate admission and leakage opt-in |
| 9. Lock v2 metadata | Add `cryptalis.lock/v2` `source_metadata`; dual v1/v2 reader; new plans emit v2; in-place restore first, fresh cluster separate | Approved 2026-10-21. Column attributes, grants, comments, and extended statistics are captured and restored. Owned sequences stay refused |

**VERIFIED, earlier revision only:** the million-row receipt records equality p95 about 6.5 ms versus 0.93 ms native and IN-20 about 16.1 ms versus 1.1 ms.
Both miss the approved added-latency targets. Point reads also miss. These are known performance work, not current-revision qualification.
A range/prefix/page query with plaintext filters cost about 5× native: p95 about 127 ms versus 24 ms.
Slice 4 source inspection corrects its earlier label: it projects the full Customer, including protected email.
Its cause is UNKNOWN and must be profiled in the integration slice.
[Compatibility](compatibility.md#performance-targets-and-recorded-costs) owns exact values, target accounting, storage denominator, and revision mismatch.

## Selected choices

All choices below are SPECIFIED. Research mechanisms remain INTERNAL ONLY until admission.

| Problem | Choice and reason | Rejected alternative | Failure/limit and deciding evidence |
|---|---|---|---|
| Small integration | One attachment through public SQLAlchemy hooks with native mapper/history/Result | Wire proxy, manual crypto calls, bootstrap remap, custom publication frames | Exact types/state, guarded writers, async behavior, app-assigned IDs and complete admitted grammar need G-ADAPTER evidence |
| Query scope | Text storage, equality/IN, tenant-scoped uniqueness. Other operations are UNSUPPORTED BY DESIGN | Universal encrypted SQL or declaring research arrays supported | Exact semantics, leakage opt-in and measured targets. G-QUERY |
| SQL storage | Built-in bytea packed term/expression index or admitted constraint-driven separate term | Mandatory custom type/extension | Complete compiler DDL and isolated column/index cost remain unproved. G-QUERY |
| Payload primitive | Library AES-256-GCM-SIV with fresh random nonce and small HKDF/HMAC composition | Deterministic payload, new primitive, distributed nonce counter by default | CF1 vectors, usage bounds, portability and cross-key review. G-CRYPTO |
| Key custody | Independent payload/search roots per tenant generation, mature external wrapping provider, bounded process cache | Per-field remote call or persisted raw-key cache | No production provider designated. Each provider qualifies separately. G-PROVIDER |
| Current authority | Deployment-controlled policy/target/wrapper identities outside database restore. Host current authorization remains separate | Database self-admission or a mandatory authority service | Publication/restore procedure and writer exclusion remain unqualified. G-POLICY |
| Lifecycle | One PG journal, cooperating advisory lock, writer pause, full verify, separate artifact publication | General workflow engine or distributed dispatcher | Lost replies, independent recovery, retained backups and exclusion need full G-LIFECYCLE evidence |
| Rollback | Transform current data through the removal engine until explicit finalization | Timed live plaintext mirror or stale snapshot restore | Compatible readers/keys and full current-data proof. G-LIFECYCLE |
| Diagnostics | Reuse init/plan/apply/status/startup checks, including bounded Doctor admission | Separate diagnostic platform or SQL parser | No missing observation becomes PASS. Broader Doctor checks remain UNKNOWN |
| Erasure | Host managed denial and separately observed provider/tenant destruction | Instant arbitrary-process revocation or default per-subject key topology | Backups, surviving wrappers and cached keys can recover values |
| Supply chain | Mature lock/SBOM/build/provenance/Trusted Publishing tools | Custom signer/scanner platform | Independent artifact and release review. G-RELEASE |

## Deleted mechanisms

The former DynamoDB authority, S3 receipts, distributed fencing, registered-worker protocol, per-request mutation ledger,
receipt dispatcher, shared crypto quotas, custom mapper/publication frames, timed plaintext mirror, doctor, shred/tombstone,
and break-glass/restore-admit command families are removed from the selected contract.
These are historical dispositions, not dependencies or public capabilities.
The later [bounded Doctor decision](#bounded-doctor-diagnosis-2026-10-23)
supersedes the removed Doctor command scope. The former diagnostic subsystem
and its absolute guarantees remain removed.
Their absolute guarantees are also removed: immediate arbitrary-worker denial, atomic multi-service lifecycle,
whole-result publication, subject cryptographic erasure, and hostile-database completeness/freshness.
A removed mechanism cannot retain its old guarantee through wording alone.

## Bounded rotation row recovery: 2026-10-23

Admit one exact-expiry retry across a row's pure payload/search crypto steps.
Check both pinned policies and retained roots before fresh admission. Keep
the three-frame logical budget and withhold effects until successful work.
Preserve terminal expiry in source-only observations and outer return checks.
Do not change generation policy, public APIs, activation artifacts or publication.

## Exact native identity codecs: 2026-10-23

Reject dialect-specific variants on record and tenant identity mappings during
planning. A matching top-level type cannot authorize SQL-side context changes.
This narrows admission to the existing native codec contract. It adds no codec.

## Safe inspection remedies: 2026-10-23

Reuse the current CLI failure envelope for the public plan operation UUID and
fixed remedies for known runtime-role and external-pin refusals. Preserve codes,
exit classes and unknown observations. Keep all authority changes manual through
the existing trusted host process. No diagnostic service or automatic repair is added.

## Restored-frame expiry recovery: 2026-10-23

Extend the existing local row retry to restored-frame authentication. Keep
exact retained-policy admission, the one-retry limit and custody failure codes.
Run effectful CHECK probes only after every retained frame authenticates.
Do not change restore approval, target identity, binding format or host authority.
The [lifecycle owner](lifecycle.md#restored-protected-backup-adoption-2026-10-19) defines adoption.

## Optional external SDK bridge: 2026-10-23

Add an optional AWS KMS implementation of the existing provider protocol.
The caller supplies a configured SDK client, a provider UUID and one full key
ARN. Pin both requests and responses to that identity and SYMMETRIC_DEFAULT.
Use fixed versioned public context for exact domain/tenant/root/generation binding.
Do not discover credentials, select aliases, administer keys or add a mandatory
SDK dependency. Keep CF1 and key policies unchanged.
The [security owner](security.md#optional-aws-kms-sdk-adapter) defines the boundary.
SDK tests do not designate or qualify a production provider. All seven gates remain UNKNOWN.

## Mapped protected scalar RETURNING: 2026-10-23

Extend mapped dictionary INSERT with exactly one direct protected mapped column
in `returning()`. Preserve native one-column Row/scalar results, parameter-order
requests, grouping, paging and transaction behavior. Tuple/entity results,
labels, expressions, aliased columns and loader options need separate admission.
Caller `return_defaults()` remains refused. Admit only the native derived
primary-key/defaults forms associated with the validated scalar request.
Resolve owned column lineage because ordinary ORM annotations can retain native types.

Capture each native group's immutable record-to-prepared-frame expectations
during compilation. Allow distinct prepared frames for duplicate input IDs so
an earlier result does not replace a later native uniqueness failure.
Require the returned tenant, real record identity and exact prepared frame or
NULL before plaintext release. Keep SELECT outer-join NULL extension separate.
Processors retain prepared keys and immutable expectations, without the operation
or session. Lease checks occur at actual cryptographic use.

Reuse the installed dialect's native insertmanyvalues generator. Validate its
processed input against the admitted batch before paging. Compare each page's
input rows with the original frozen slice before accepting its SQL/parameters.
This prevents an earlier callback from changing a future page unnoticed.
Consume one exact page permit on its cursor/context at final driver dispatch.
Keep the shared first-capture and completed-dispatch checks.

Do not parse generated parameter suffixes, compile replacement SQL, assemble a
replacement Result or change CF1. The private dialect hook needs native evidence
in each selected compatibility cell. [Status](status.md) owns that evidence.

Native supplemental RETURNING can decrypt during `execute()`.
Later iteration can therefore read plaintext that already passed authentication.
Expired keys must fail before a later cryptographic use, without provider refresh.
Result failure can follow successful uncommitted SQL. Require rollback before retry.
This adds no hostile-database completeness, ordering or general freshness guarantee.

## Shared driver event boundary: 2026-10-23

Extend final driver admission to ordinary flush and protected read paths.
Capture SQLAlchemy's native processed statement/parameters before cursor
listeners, then compare at the guarded dialect dispatch. Snapshot each native
insertmanyvalues page. Reuse its compilation, ordering, RETURNING and transaction
mechanics instead of implementing another SQL compiler or batch association.
Freeze SQL, binary buffers, containers and ordinary typed primitive/identity
values. Keep unknown unprotected adapters by identity, without claiming to
freeze their internal state.
For psycopg Binary objects, require exact native buffer types and read the
buffer directly. Custom `__bytes__` behavior cannot stand in for bytes that the
driver actually sends.

SQLAlchemy's inspected Connection event implementation does not forward
`insert=True` as a prepend instruction. Check actual effective callback order
at capture and dispatch. Require the capture first and exactly once. Refuse
preexisting engine listeners before connection and effective Connection
listeners before catalog validation. Only later engine-instance observers are
admitted. Any captured SQL/value mutation, unsafe order or missing capture raises the typed
`UnsafeDriverEvent`. No event callback receives a driver permit.
After-cursor admission also requires a completion marker set only after the
guarded raw execute succeeds. This prevents a preexisting or newly installed
dialect callback from returning `True` and silently skipping an INSERT.
Reset both markers for every native page. This retains harmless dialect
observers without a separate dialect-listener policy.

This strengthens the existing boundary without changing CF1, provider trust,
search leakage, transaction objects or public DML scope. Separate clients,
host authorization, custom adapter internals and external qualification keep
their existing limits. [Status](status.md) owns executable evidence.

## Mapped dictionary INSERT: 2026-10-23

Admit ordinary `Session.execute(insert(Model), list[dict])` through the existing
sync/async attachment. Reuse CF1 frames, native ORM dispatch and PostgreSQL
constraints. Copy each row and bind every supplied protected value to its own
field, typed identity, tenant and operation. Match final driver values against
the admitted batch after cursor events. No new cryptographic format, provider
authority, query representation or transaction state machine is introduced.

The later [scalar RETURNING decision](#mapped-protected-scalar-returning-2026-10-23)
supersedes the original blanket RETURNING refusal.
Keep other RETURNING shapes, embedded values, SQL row expressions, Core INSERT, upserts,
INSERT SELECT, legacy bulk methods and used context-sensitive defaults outside
this admission. Explicit values can bypass unused defaults.

VARCHAR validation precedes encryption. For a known invalid row, execute only
its valid prefix first so an earlier native constraint error wins. Invoke the
invalid row through the same native ORM path so autoflush retains precedence.
After its owned bind failure, PostgreSQL 16's three-argument VARCHAR assignment
function receives public constants and raises SQLSTATE 22001. This preserves
native aborted-transaction/savepoint behavior without sending protected text.
Any unavailable or unexpected carrier outcome raises a separate typed failure.
The [PostgreSQL 16 implementation](https://raw.githubusercontent.com/postgres/postgres/REL_16_15/src/backend/utils/adt/varchar.c)
defines this assignment coercion. The native oracle exercises its transaction
behavior. A supplied invalid text value never becomes an error SQL parameter.

Admit exact stock savepoint-control clauses separately, with empty parameters,
native SQL compilation and unchanged configuration. Do not wrap or replace
native transactions. These controls confer no data permit. Other write routes
and the seven production gates retain their separate evidence requirements.

## Bounded Doctor diagnosis: 2026-10-23

The current product mandate requires a useful `cryptalis doctor`. Add a thin
read-only interface over existing runtime deployment admission. It introduces
no new authority, diagnostic framework, SQL parser, or application scan.
`migration.diagnose_deployment` accepts an immutable migration plan, exact
ACTIVE pin, actual runtime connection, and optional matching restore binding.
It admits host artifacts before connection and checks one repeatable-read,
read-only snapshot through `check_attachment`. ACTIVE/PENDING status also
repeats the shared effective privilege checks.

A passed runtime check leaves the overall Doctor result UNKNOWN. Provider
keys, frame authentication, query routes, writer exclusion, host authority,
and recovery capacity remain unobserved. Exit 0 means only scoped admission
passed. Later ACTIVE edits remain valid; Doctor does not repeat frozen
activation frame proofs. The host still authenticates deployment publication.
[The walkthrough](walkthrough-migration.md#diagnose-an-active-deployment)
owns command inputs and results. [Status](status.md) owns executable evidence.
All seven full gates remain UNKNOWN.

## Rotation preparation diagnostics: 2026-10-23

Reuse the existing payload/search P status APIs in `cryptalis status` through
exact artifact-format dispatch. Keep P separate from publication artifact A.
Recorded progress remains keyless, read-only, and `NOT_PERFORMED`; it never
returns application deployment admission. Repeat shared runtime privilege
checks in every recorded phase. Refuse P restore bindings before reading
them or connecting. This adds no artifact format or lifecycle state machine.

Admit the source plan and pin before search-planner field inspection.
Missing preparation and activation failures use the actual payload/search
purpose. [The walkthrough](walkthrough-migration.md#inspect-rotation-preparation)
owns diagnostic codes and command behavior. [Status](status.md) owns evidence.
All seven full gates remain UNKNOWN.

## Complexity budget

| Retained mechanism | Essential reason | Mature dependency | User exposure | Deciding test / removal |
|---|---|---|---|---|
| Compiler/lock | Preserve schema/query meaning and detect changed intent | SQLAlchemy inspection, JSON | Manifest and concrete plan | Native application/schema diff. Retire eligible lock after package-free exit |
| Row context/projection | Reject relocation without business crypto calls | Public SQLAlchemy hooks, PG binary functions | One attachment | Entity/scalar/type/state oracle. Ordinary mapping after decrypt-back |
| Payload/equality core | Encrypt before DB and execute declared predicates | cryptography, HMAC/HKDF, native indexes | Profile and leakage opt-in | Vectors, attacks, exact indexed queries. Decrypt-back and index removal |
| Wrapped roots/cache | External custody without per-field RPC | Mature provider, process memory | Provider configuration | Cold/outage/recovery/deletion observations. Retain backup route until approved retirement |
| Deployment pin | Prevent restored DB from selecting stale authority | Existing deployment/auth system | Deployment prerequisite | Interrupted publication/restore/stale-worker tests. Explicit retained obligations |
| Journal/locks | Resumable atomic chunks, single cooperating executor | PG transactions/advisory locks | Apply/status/resume/abort | Faults and verification mutants. Remove eligible journal last |

These dependencies can reduce code. They do not establish low operational cost.
Plan reports writer pause, temporary disk/WAL, provider costs, and ownership. Only write-throughput and pause budgets remain budget D items.
Other security decisions, usage limits, provider topology/cache policy, upgrade compatibility, and host publication procedure remain unresolved where status records them.
Assumptions from this pass are in [reset notes](_reset/notes.md), not another contract owner.

## Independent expert review

**SPECIFIED requirements, UNKNOWN evidence:** an independent cryptographer reviews implemented CF1 vectors, text/ID codecs,
AAD, exact-key resolution, full-HMAC assumptions, leakage, and usage bounds.
A security reviewer reviews provider identity/cache, writer bypass, deployment provenance, restore/revocation, logs/caches/exports, supply chain, and retained-copy limits.
A database/SQLAlchemy reviewer reviews admitted grammar, constraints, async state, interruption, verification, and package-free exit.
Any advanced admission adds review of its exact representation and leakage attacks.
AI council criticism and vendor documents do not replace these reviews. No independent review is available.

## Native VARCHAR text admission: 2026-10-22

**IMPLEMENTED, bounded:** admit PostgreSQL `text` and native
`varchar`, with or without a character limit, as the text family.
Keep custom types, domains, `char`/`bpchar`, and non-text values unadmitted.
This extends the approved text scope without a new cryptographic construction,
search representation, leakage profile, or source of deployment authority.

Emit `cryptalis.lock/v3` when a protected field uses native `varchar`.
Require `pg-varchar/v1` in that lock's reader list. Preserve v1/v2 reading and
v2 emission for text-only declarations. The complete source schema already
records each native typmod. Keep the field-source member shape unchanged.
A v3 reader must check the native type, typmod, and mapped length together.
Restore the same native type and typmod during decrypt-back.

Apply native VARCHAR assignment rules before payload encryption.
Preserve character counts, accepted excess ASCII spaces, and exact stored values.
Preserve pending ORM attributes until native refresh or expiration changes them.
Do not apply assignment coercion to equality query values.
An overlength non-space value raises a safe typed error before protected SQL.
The error carries SQLSTATE `22001`. Callers must roll back before retry.
Read-time validation must refuse an authenticated value beyond its native limit.

Keep CF1, `utf8-exact/v1`, and `identity/v1` unchanged.
The codec encrypts the exact value after native assignment coercion.
The existing 16 MiB codec limit still applies. Search still requires qualified
exact C equivalence and explicit leakage acceptance.

The native oracle must cover Unicode character counts, trailing spaces, overlength
errors, unchanged pending state, refresh, equality/IN, scoped uniqueness, async
writes, decrypt-back, native metadata, and package-free restart.
Do not claim external-application adoption from these type tests alone.

Source: [PostgreSQL 16 character types](https://www.postgresql.org/docs/16/datatype-character.html).

## Root-rewrap successor artifacts: 2026-10-23

**IMPLEMENTED, bounded:** root custody changes use `cryptalis.transition/v2`
with `kind: rewrap`. Existing v1 protection plans remain readable. The successor
keeps the same compiled lock and CF1 context, but receives a new immutable
operation ID and digest. Its host artifact records the rewrap proposal digest,
expected frame/membership observations and a flat ordered predecessor list.
CF1, key generations, search representations and leakage remain unchanged.

Use the existing maintenance executor, advisory lock, table locks and writer
guard implementation. Full source/target authentication, a successor PENDING
row and predecessor SUPERSEDED marker commit together. The old row retains its
original operation ID and plan digest. It names its exact successor.
The host publishes the successor independently. Existing activation verifies
target data against host observations before removing the guard. An ACTIVATING
retry also checks those observations when a journal already claims ACTIVE.
An ACTIVE pin permits later ordinary edits and metadata inspection.

Runtime and reverse/removal admission validate each predecessor's exact digest,
SUPERSEDED phase and reciprocal successor link. An arbitrary SUPERSEDED row is
not admitted. Known ancestors remain in the journal until approved removal.
Do not recursively embed complete predecessor plans or rewrite their identities.

Deploy a transition/v2-capable host reader before successor publication.
Older transition readers fail format admission. Ciphertext readers and retained
old wrappers remain separate recovery dependencies. No wrapper/key deletion,
automatic backup retirement, new authority service or stronger revocation
guarantee follows from this format. Production providers, authenticated host
publication and independent review remain UNKNOWN.

## Pending root-rewrap cancellation: 2026-10-23

**IMPLEMENTED, bounded native verification:** cancellation uses the original
proposal and the exact source ACTIVE pin, republished by the trusted host while
writers remain stopped. A successor pin cannot authorize source writers.
The target provider can remain unavailable because cancellation changes no roots
or frames. The source policy and retained readers must still authenticate data.

Use the shared executor and maintenance approval. Under table locks, require the
exact PENDING successor, source SUPERSEDED link, original source state digest,
schema, guard, and proposal frame/membership observations. Restore the original
source ACTIVE state and remove only successor guards in one transaction.
Retain the successor as ABORTED with exact proposal and source linkage.
An already-ACTIVE successor requires a new rewrap, rather than cancellation.
An adopted restored target remains outside this cancellation contract.
Admit the caller's source ACTIVE pin separately. The deterministic successor
selects the shared executor identity and current verification cost. Its internal
PREPARED pin supplies no host publication authority. Historical protection work
does not repeat and supplies no cancellation pause estimate.

A retry after an uncertain commit inspects the terminal marker and current
source authority. It cannot reapply snapshot data or resurrect a source that
a later operation superseded. Ordinary source edits after cancellation remain
valid. Keep retained policies and backup dependencies until explicit retirement.

## Payload-rotation preparation and activation: 2026-10-23

**SPECIFIED:** use two immutable host artifacts. A preparation proposal P pins
the current source plan, ACTIVE pin, source frame/membership observations, exact
retained policies, batch limits and measured costs. P reserves a distinct
successor operation ID. It supplies no application deployment authority.

The target retains every exact source wrapper and reader root. It adds exactly
one independent payload root with a generation above all retained payload
generations. The selected search generation and wrapper remain unchanged.
Rewrap and search rotation remain separate workflows. No normal rotation deletes
retained roots or backup dependencies.

The staged executor will commit fresh target ciphertext and chunk progress
together in operation-owned shadows. Original public frames remain intact.
Before destructive switch, sealing must authenticate both exact active
generations, compare exact decoded values/NULLs and unchanged search headers,
and compare original frames/membership against P. Sealing returns an immutable
activation plan A with observed target frame digests. Repeated sealing of the
same committed bytes must produce identical A, without new nonces or timestamps.
The host must persist A before switch and publication.

The final switch must repeat paired verification under maintenance locks.
Source SUPERSEDED to P, P SUPERSEDED to A, and A PENDING commit together.
A's flat predecessor list includes both source and preparation identities.
Its target digests supply publication verification, including an ACTIVATING
retry when the database journal already claims ACTIVE. Journal hashes cannot
replace host-pinned observations. A genuine ACTIVE pin permits later edits.

Preparation planning and staged execution remain separate evidence boundaries.
Row limits alone do not bound logical memory. Scan length metadata before frame
retrieval and bound the aggregate source/target/decoded-text budget across all
fields and tenants. Python, driver, database and provider overhead remain outside
this logical bound. Estimates require host measurements and qualify no capacity.

Payload preparation uses EXPANDED and BACKFILLED progress under P's unchanged
identity. Each chunk holds write-excluding locks across length probes, frame
reads, shadow writes and the journal commit. No chunk overwrites an already
populated unprocessed shadow. Resume authenticates the committed prefix and
preserves its ciphertext and nonces. BACKFILLED requires a complete paired
source/target pass on every successful return, including a terminal retry.
An unkeyed status call reports recorded progress and NOT_PERFORMED verification.

Derive each shadow from the original field's reserved payload name plus
`_rotation`. It is nullable bytea without defaults, constraints or indexes during
preparation. Existing shadow names cause refusal. Validate the exact guard and
shadow definitions, remove only those facts from catalog observations, and bind
the remaining source facts to P's host-pinned schema digest. Source journal
identity and original state remain unchanged until the final switch.
Ordinary source attachment refuses the changed staging schema. Keep workers
stopped until cancellation or completed publication.

Pre-switch cancellation needs the republished source ACTIVE pin and source keys.
It authenticates the source against P, removes only P's shadows and guards, and
records P ABORTED atomically. Target custody can remain unavailable. Repeated
cancellation inspects the terminal marker and current source authority without
replaying old data. A later source supersession prevents an old cancellation
from reviving it. Restored-target preparation remains outside this contract.

The initial final-switch implementation must preserve the existing public
columns, their constraints, native expression indexes, grants and metadata.
Use a server-side ciphertext UPDATE from the verified shadows under final
maintenance locks, then remove the shadows and exchange P's guards for A's
guards in the same transaction. Verify the copied target observations against
A before commit. This choice requires another complete-table write in the
terminal transaction. Measure and report its WAL and pause cost. Bounded
preparation chunks do not make that terminal write a bounded committed chunk.
A future column swap needs separate metadata-preservation evidence.

If A already records PENDING, retry must authenticate the current target and
exact reciprocal lineage against A. Original source frames no longer supply a
retry comparison. Missing A with partially superseded source or P is an
inconsistent state, not permission to reconstruct a commit. Preparation resume
and cancellation must reject the switched P.

Activation uses `cryptalis.transition/v3` with `kind: payload_rotation`.
Its exact fields include `payload_rotation_plan_digest`,
`payload_rotation_observations`, `payload_batch_limits`, and the flat predecessor
list. Scopes match the observed model identities and row counts. Construct
scope order from the source lock, independent of JSON object key order.
Sealing verifies and serializes these observations. It does not create a
cryptographic signature or replace trusted host persistence and current authority.

A requires measured native copy throughput and copy WAL bytes per row. Its
terminal estimate counts one source pass, both sides of paired verification,
one post-copy target pass, one publication pass, and the atomic copy. Preparation,
sealing, DDL, lock drain, provider overhead and capacity guarantees stay outside
that estimate. The journal records copy wall nanoseconds and the cluster-wide
WAL delta around the native UPDATE loop. Those diagnostic observations cannot
supply host authority or isolated operation cost.

Before payload publication, validate the exact predecessor chain, journal
progress shape, table owner, public metadata and complete journal inventory.
ACTIVATING repeats bounded target authentication against A, including a journal
claim of ACTIVE. A genuine ACTIVE pin permits later edits. The sealed target
snapshot does not become an immutable-data requirement for ordinary operation
or subsequent current-value decrypt-back/removal.

## Restored payload generations and privilege admission: 2026-10-23

**IMPLEMENTED, bounded:** adopt a backup of published payload activation A through
the existing restore binding. Require A's exact source/preparation ancestry,
strict progress shape, current schema and selected generation before admission.
Authenticate the backup's current rows under its retained policy. Do not compare
ordinary postpublication edits against A's historical cutover frame digest.
The host must authorize restore, quarantine and writer exclusion separately.

Check effective runtime privileges and protected-column metadata before effectful
schema probes or provider access. Reject journal writes through table or column
grants. Reject database/schema CREATE and protected-table TRIGGER/TRUNCATE.
Apply the shared role check during initial planning, active admission, adopted
binding admission and shared maintenance execution. Later grant changes require
a new admission check. These observations do not enforce every external writer
boundary or replace host credential control.

Keep the restore binding format unchanged. Retain old keys for approved recovery
obligations, but refuse an old-generation frame under the selected new policy.
Fresh-cluster backup recovery does not admit rotation on an adopted target.
Search reindex, qualified production providers and all seven full gates remain
open or UNKNOWN. See the [recorded evidence](status.md#payload-backup-recovery-and-runtime-admission-checkpoint-2026-10-23).

## Reverse publication selects the runtime boundary: 2026-10-23

**IMPLEMENTED, bounded:** repeat the shared effective-privilege check during
reverse execution and status. Select the role from the trusted host pin.
Prepublication pins through PLAINTEXT_PENDING require the source runtime.
PLAINTEXT_ACTIVATING, PLAINTEXT_ACTIVE and REMOVING require the declared plaintext
runtime. Database progress cannot change that selection. Plaintext planning
checks the selected role before provider access.

Preserve package-free terminal retries. When REMOVED matches an actually absent
journal, inspect the native schema without either former runtime role check.
An existing journal cannot use that exception. Preserve native metadata and later application edits after retirement. Privilege observations do not authenticate the
host, freeze later administrative grants or prove credential deletion. See
[status](status.md#reverse-runtime-admission-checkpoint-2026-10-23).

## Search-generation preparation and sealed activation: 2026-10-23

**IMPLEMENTED, bounded native verification:** use the existing writer-paused preparation and publication
protocol for search-key rotation. Keep payload selection and every retained
wrapper/root unchanged. Each selected search policy adds exactly one independent
root above all retained search generations. A search-less policy remains exact.
Storage-only frames remain byte-identical. Searchable frames require a fresh
OS nonce and authenticated resealing because CF1 binds the search header.
The cryptographic construction and CF1 format remain unchanged.

Preparation P uses `cryptalis.search-rotation/v1`. Sealing emits immutable
activation A as `cryptalis.transition/v4`, with `kind: search_rotation`.
A binds `search_rotation_plan_digest`, `search_rotation_observations` and
`search_batch_limits`. Deploy a v4-capable host reader before publication.
Retain v1 protection, v2 rewrap and v3 payload artifact readers.

Share the concrete encrypted-shadow, cursor, guard, copy and publication
mechanics across the two generation workflows. Keep their policy and header
checks explicit. Paired verification requires exact text, NULL, type, identity
and selected generations. It recomputes target search terms under the new root.
Source-to-P-to-A lineage and public-frame replacement commit atomically.
Post-copy and ACTIVATING retries require A's actual target frame hashes.
A genuine ACTIVE pin permits later ordinary edits.

Keep one active query namespace. Admit retained search readers only under an
exact bound deployment policy. Never query multiple generations with OR.
Native public UPDATE maintains expression and unique indexes inside the
terminal transaction. Native conflicts roll back the entire switch.
Host copy-rate and WAL estimates must include this index work.

Restore uses the existing approved binding and selected-generation checks.
Rotation on adopted targets remains outside this contract. Rotation deletes no
retained keys and supplies no unlinkability or cryptographic-erasure claim.
Production custody, authority and independent review remain unqualified.
