# Security and leakage

**SPECIFIED:** security contract, not an audit. [Status](status.md) owns executable evidence.
IMPLEMENTED has the exact boundary in status. The package includes a bounded storage attachment; full runtime qualification remains UNKNOWN.
VERIFIED means only the named recorded checks. All unlabelled requirements below are SPECIFIED.
The selected scope is text storage, equality/IN, and tenant-scoped uniqueness with application-assigned keys.
Advanced search representations and shared joins are INTERNAL ONLY and remain UNSUPPORTED BY DESIGN as public capabilities until admission.
The trusted application transforms protected plaintext before PostgreSQL receives it through an admitted path.
Payload confidentiality depends on uncompromised application and key authority, qualified cryptography, and the declared leakage boundary.

## Current local enforcement evidence: 2026-10-07

**VERIFIED, recorded spike revision:** the [integrated checkpoint](status.md#current-integrated-checkpoint-2026-10-07) guards inspected SQLAlchemy executions at the DBAPI method boundary.
Its raw/COPY/protocol-handle denials occur before driver execution; an independent privileged connection remains outside that boundary.
Missing, unknown or unexcluded writer inventory blocks local transformation. The migrator-owned fixture does not qualify a non-owning runtime role.
A hostile returned row that is valid for another identity fails the captured host-requested point check before value release.
The recorded candidate also rejects changed typed field/domain/tenant/record context, descriptor/header mutations, malformed bounds and retired generations without fallback.
Same-context replay, SQL-NULL presence substitution and omitted rows remain the threat limits below.

New development roots and the local wrapping key are random and memory-only; the older experiments retain public lab roots.
Local cold/warm/expired/outage and rewrap tests are functional evidence only.

A Linux test forks while the keyring mutex is locked. The child refuses
inherited sync/async preparation without deadlock. Fresh child keys work.
The parent retains its prepared keys. The
[fork checkpoint](status.md#keyring-held-mutex-fork-checkpoint-2026-10-23) bounds this evidence.

These controls do not qualify other process/runtime cells, remote-provider
cancellation, native deletion or production custody. No production provider or
deployment procedure is designated.
Independent human cryptographic/security review is unavailable: `external-review-required` remains UNKNOWN.
Frozen independent admitted text/ID vectors, exact collation evidence, and nonce/usage bounds remain required before security qualification.

## Slice 3 storage enforcement: 2026-10-08

**IMPLEMENTED, bounded prototype:** admitted ORM writes prepare row-bound CF1 frames before SQL.
Public execution hooks substitute those frames without changing mapped plaintext attributes.
Generated read projections carry the expected record and declared tenant context with the payload.
The processor verifies host tenant and requested point, then authenticates and decodes each value.
Keys are prepared outside synchronous async hooks. Protected SELECT compilation caching is disabled.
Unprotected SELECTs retain native caching. The host must authenticate the lock and tenant scope.
Guards reject unsupported grammar, opaque SQL, COPY, protocol handles, and unprepared writes on the attached engine.
These guards do not constrain independent connections or a compromised application.

The bounded mapped dictionary INSERT route binds each prepared frame to its
admitted operation, field, typed row identity and tenant. It checks actual
driver parameters after SQLAlchemy cursor events, including exact payload
bytes, identity and tenant, against the admitted batch. Late parameter or SQL
replacement refuses before driver dispatch. This boundary does not make
arbitrary host plugins trustworthy or qualify other write routes.
For one protected scalar RETURNING, the processor also requires a real input
identity and exact prepared ciphertext or NULL for that native group.
SELECT's outer-join NULL-identity rule does not apply to inserted rows.
A valid fresh frame for the same context still refuses if this operation did
not prepare it. This stronger write-result check does not establish general
read freshness or completeness.

Native supplemental RETURNING can authenticate
during `execute()`, so later iteration can read already authenticated plaintext.
An expired lease refuses at actual key use without a provider refresh.
Roll back after a result failure. SQL can succeed before result authentication.

The scoped mapped bulk UPDATE route keeps an ordered immutable input ledger.
Owned physical column lineage binds the explicit tenant and generated record
predicates. Each native group must consume the corresponding inputs before
execution. Exact prepared frames, typed scope/record binds and final driver
snapshots then protect dispatch. Read-only properties and SQL-producing bind
types refuse before SQL and key preparation in both sync and async execution.
The adapter captures the request before key preparation and checks it again
afterward. Public Python bind processors remain native.

For finite VARCHAR targets, each affected native group uses a private
parameterized CASE with public constants. Omitted columns retain their existing
frames. The carrier contains no protected plaintext. The adapter captures the
generated statement, SQL, bind names and constants before execution.
Compiled and final driver checks require those exact values with the existing
row, tenant and frame proofs. The tested healthy route never stores the public
overflow marker. These checks do not make arbitrary host plugins trustworthy.

Attachment requires exact native identity types and flags without dialect
variants or SQL-producing type hooks. Configuration admission repeats before
host key resolution and driver dispatch. This applies to existing flush and
INSERT routes as well as the bounded UPDATE route.

SELECT admission checks typed AST nodes before generated-node exceptions and
repeats admission on the compiled statement. It refuses SQL-producing type
hooks, variants, dynamic implementations, user-defined type spelling and
literal-execution binds. Compiler dispatch must retain exact native function
identity on an actual correctly bound method. Decorator and container inner
types receive the same checks. Only the exact owned physical payload type may
use its internal output hook, with every other type check still active.
These controls preserve tested Python bind/result codecs and native Boolean/Enum
behavior. They do not establish a universal public write-type policy or a
hostile-Python sandbox.

The optional type exception checks exact SQLModel 0.0.48 AutoString before
native String admission. It captures native hook identities and refuses changed
hooks, subclasses, variants or implementations. Existing SELECT lineage,
authenticated output, guarded writes and driver checks remain active.
It adds no reader, ciphertext format, key provider trust or tenant authority.
The ordinary Python and independent-connection trust boundaries remain unchanged.
The [SQLModel compatibility contract](compatibility.md#optional-sqlmodel-bridge)
defines its finite mapping and synchronous attachment scope.

SELECT admission expands entity and table projections before it checks types
and expressions. The same node snapshot includes each selected column and its
descendants. Existing lineage and protected-expression rules apply to that
snapshot. A public output hook cannot select stored CF1 bytes through a hidden
expanded column. Protected outputs retain the existing authenticated processor.
Public computed expressions retain native behavior within the admitted grammar.

For UUID primary-key SELECT lookup, the adapter derives an expected UUID from
admitted PostgreSQL text without replacing the caller's bind or identity-map
key. The exception requires exact native Uuid flags and bound processor methods.
Invalid native inputs retain their database errors and transaction failure.
Their private marker cannot authorize any frame or outer-join NULL release.
Existing tenant, row and authenticated-decryption checks remain active.

The scoped mapped DELETE route freezes the original typed tenant and record
before provider callbacks. Native AST identity, compiled binds and actual driver
arguments must retain that authority. Ordinary ORM flush DELETE also requires
native compiler nodes. Unsupported custom nodes refuse before execution.
DELETE returns no protected value and makes no stored-frame authentication claim.
Native rollback, savepoint, foreign-key and identity-map behavior remain required.

Unprotected mapped DELETE admits one physical nonprotected table from the same
registry. Exact native equality/AND nodes bind fixed typed literals. The adapter
captures table/mapper identities and ordered predicates before provider callbacks.
It repeats metadata and predicate admission afterward and at driver dispatch.
Compiled SQL and actual bind values must match the captured request. Native
ORM synchronization remains bounded to default/auto/evaluate/False. This
permission does not admit Core DELETE, fetch synchronization, RETURNING or
custom AST paths. It grants no authority over a protected table and does not
replace the existing tenant-scoped protected DELETE checks.

The native bulk page hook validates processed input against the admitted batch.
Each page must retain its original frozen input slice before the hook freezes
the native generated SQL/parameters. Earlier callbacks cannot change a later
page's binary data and get a new permit for that change.
The permit belongs to one cursor/context and one dispatch, then clears.
No SQL parser, replacement compiler, result assembly or cryptographic format is added.

Typed native savepoint controls carry no data permit. Their final SQL must
match native compilation, with empty parameters and unchanged configuration.

The shared native driver boundary now snapshots each statement before cursor
callbacks and checks it after those callbacks. It freezes actual SQL text,
binary bytes, native containers and ordinary typed primitive/identity binds.
It consumes one capture per dispatch, including each native RETURNING page.
An after-cursor check also requires completion by the guarded raw dispatch
before SQLAlchemy constructs results or reports unit-of-work success. A dialect
callback cannot return `True` to skip the guard and silently drop an INSERT.
SQL and named-key comparison cannot invoke a supplied string subclass's
equality override. Bulk INSERT also retains its independent sealed-batch checks.
For psycopg Binary objects, accept only exact `bytes`, `bytearray` or
`memoryview` buffers and read the buffer directly. A custom `__bytes__` method
cannot report different bytes from the buffer that psycopg sends.

The capture must be first and unique in effective Connection event order.
Preexisting engine listeners refuse before connection. Effective Connection
listeners refuse before catalog validation. Later class/connection callbacks
also refuse before data dispatch. Engine-instance observers can register after
attachment and retain native results when they leave SQL and values unchanged.
No cursor callback receives a driver permit. A missing or changed capture
raises `UnsafeDriverEvent`, without fallback.

This check covers the cursor-event boundary. It does not authenticate arbitrary
host code, mutable internals of unprotected custom driver adapters, independent
clients or application authorization. Earlier expression/event admission,
cryptographic frame checks and deployment writer policy remain separate.
Deliberate removal of Cryptalis callbacks is trusted-host guard tampering.

**VERIFIED, local restricted fixture owner:** native PostgreSQL comparisons verify ordinary values and ORM behavior.
Sync and async interleaved two-tenant tests fail without the cache fix and pass after its restoration in an isolated copy.
Four native controls pass in both runs. The proof leaves the original worktree unchanged.
Valid ciphertext is rejected under the wrong tenant; wrong returned points, relocated frames, and changed bytes reject before value release.
A driver-bind collector observes an unprotected marker and detects no supplied protected markers during tested writes.
Unsupported query controls verify rejection before driver execution, including ambiguous columns and alternate protected mappings.
Changed storage/context mappings, translated targets, and catalog mismatches reject.
Attachment refuses checked-out native connections before pool replacement. Same-named tables in separate schemas retain distinct row preparation.
Real async database cancellation propagates and permits explicit rollback and later-session recovery.
Cancellation during awaited key preparation leaves PostgreSQL unchanged and permits a later write.
[Status](status.md#slice-3-checkpoint-2026-10-08) and its hashed receipt define the exact evidence boundary.
**VERIFIED, separate restricted runtime login:** sync/async attachment CRUD matches native SQLAlchemy in owned PostgreSQL 16.15 schemas.
Runtime grants are schema `USAGE`, customer CRUD, and article `SELECT` for native relationship lookup during deletion.
The role has no ownership, fixture-owner inheritance, grant options, or schema `CREATE`.
Independent sync/async driver calls receive SQLSTATE `42501` for the nine tested persistent DDL, ownership, truncate, and role-switch operations.
Database `TEMP` remains available. These tests do not establish database-wide least privilege or denial of every DDL statement.

The same runtime credentials can reconnect through an independent driver and commit data changes.
Changed ciphertext fails on an attached read. Replaying an older valid frame after a committed application update restores the older value.
Replacing a nullable payload with SQL NULL is accepted; deleting a row produces ordinary row absence.
Thus schema privilege separation does not enforce attachment use, writer exclusion, freshness, presence, or result completeness.
The host must exclude unsupported routes and authorize tenant access. No database grant added here supplies those controls.
The [runtime receipt](_reset/slice3-runtime-verification.json) records the exact evidence and limits.
The local provider is ephemeral. Writer exclusion, provider custody, deployment policy admission, lifecycle-metadata permissions,
and independent review remain UNKNOWN. All seven full gates remain UNKNOWN.
Same-context replay, SQL NULL substitution, hostile omitted rows, and host authorization limits remain unchanged.

## Slice 4 search enforcement: 2026-10-08

Earlier slice 3/4 row-isolation tests omit grouped and callable primary-key binds.
The [corrective checkpoint](status.md#corrective-audit-checkpoint-2026-10-09) records their repair and the revised evidence boundary.

**IMPLEMENTED, bounded prototype:** exact-text equality/IN uses full HMAC terms from the independently keyed CF1 header.
Simple negative equality and `NOT IN` reuse the same terms; NULL presence uses a SQL NULL check and needs no equality representation.
Each comparison includes declared tenant scope. Native B-tree expression indexes enforce declared uniqueness during races.
Payload and term are one bytea value. Public framing checks refuse malformed shape; they cannot prove AEAD authenticity.
Attachment checks exact index/check definitions under `pg_catalog` search-path resolution, including validity, keys and operator classes.
Aliases retain physical-column lineage. Forged mappings, protected derived tables, joins and unadmitted grammar refuse before the driver.
Exact text search admits inspected deterministic `pg_catalog.C`/provider `c`
or implicit `pg_catalog.default`/provider `d`. Source and index collations must
match their qualified identities. Byte-exact equality does not normalize case,
Unicode or trailing spaces, and admits no ordering or pattern behavior.
User-defined shadow names and nondeterministic collations still refuse.
The existing exact AutoString recognizer also checks original SQLModel search
binds; custom hooks, variants and unqualified types remain outside admission.

Search binds use ordinary text codecs and explicit values. Custom codecs, callables, ambiguous unsupplied named defaults and generated parameter-name overrides refuse.
These codec checks cover every placeholder sharing a search name, including plain fields. Protected ON conditions cannot reuse WHERE permits.
Independent frozen vectors verify query terms; native PostgreSQL comparisons verify truth, result membership and uniqueness outcomes.
Search wrappers and generation are pinned per tenant for the attachment lifetime. A replacement refuses before query or write.
This pin does not authenticate a fresh deployment or infer the correct root from existing data. The host must supply that authority.
Cross-process policy publication, stale-deployment exclusion, full data verification and search-key transitions remain unqualified.

Independent runtime writers can change a public term and hide a matching row without changing its payload length or framing.
An attached point read rejects the changed frame. An equality query need not return it, so no completeness check occurs.
Plausible framing with invalid AEAD can pass PostgreSQL's CHECK and later fail an attached read.
Replay, NULL substitution, deletion and hostile global uniqueness remain outside the returned-row authentication guarantee.
Small-domain and leakage reviews remain trusted host assertions. They do not stop authorized chosen-input enumeration.
The [slice 4 receipt](_reset/slice4-verification.json) records tests, isolated regression removals and local claim boundaries.
All seven gates remain UNKNOWN. No production provider or independent review exists.

## Trust boundaries

| Boundary | Assumption and control |
|---|---|
| Host to adapter | The host authenticates users, authorizes access, and supplies the correct tenant scope |
| Adapter to PostgreSQL | Only ciphertext and declared keyed representations cross admitted writes. Runtime roles cannot replace schema or lifecycle policy |
| PostgreSQL to adapter | Bounded framing, expected context, exact admitted key, AEAD, codec, and companion verification precede value release |
| Adapter to key provider | Workload identity, pinned provider/key identity, exact wrapping context, bounded retries, and memory-only cached material |
| Database restore to deployment | The restored database cannot replace the current externally pinned policy or authorize itself |
| Operator to transition | Inspected target, semantic diff, writer stop, plaintext exposure approval, full verification, and explicit destructive disposition |

The attacker can know source, manifest, algorithms, schema, normalization, ciphertext format, dumps, indexes, and backups.
Confidentiality does not depend on hiding these facts.
The attacker lacks secret roots, provider decrypt authority, host plaintext, and authorized query-oracle access unless a scenario states otherwise.
Chosen inserts, repeated queries, and auxiliary distributions remain important leakage attacks even without key compromise.

## Threat limits

| Threat | Boundary |
|---|---|
| Stolen finalized dump or read-only DBA | Randomized payloads hide value bytes without keys. Search, length, presence, row linkage, and historical plaintext remain exposed |
| Returned bit tamper or cross-field/tenant/record relocation | Context-bound AEAD rejects before that value becomes available |
| Same-context historical replay | Not prevented. AEAD supplies authenticity, not current-row freshness |
| Hostile omitted rows or corrupted unreturned search terms | Not prevented by returned-row authentication. No completeness or adversarial global-uniqueness claim |
| Nullable field replaced with SQL NULL | Presence is not authenticated in the selected default. Required presence needs a separately qualified authenticated-null profile |
| Application compromise/RCE, broken authorization, host plaintext logs/caches/exports | Outside confidentiality boundary. The process legitimately holds plaintext and cached material |
| Key/provider/workload credential compromise | Can recover permitted roots. Least privilege reduces scope but cannot save those values |
| Raw/alternate writers | The intended guarded paths must reject. Complete prototype coverage is unproved. Unknown separate writers block adoption. Schema checks cannot cryptographically certify arbitrary bytes |
| Old deployment or database restore | The intended current deployment pin must block recognized stale generations. Only a policy model ran. Operator quarantine and worker termination remain required |
| Invisible RAM clone or immediate arbitrary-process revocation | Outside the claim. Cache expiry does not recall plaintext or copied keys |
| Plaintext in pre-protection WAL/backups/logs | Remains exposed until its actual custody/retention disposition |

The new design deliberately removes the former distributed instantaneous-denial protocol.
It promises controlled deployment changes and explicit maintenance, not cryptographic recall of previously released data.
No subject-erasure guarantee follows from row deletion, policy denial, or deleting a current wrapped root.

## Key hierarchy and providers

Use two independent random 32-byte roots per tenant/domain key generation:

```text
external provider KEK
  ├── wrapped payload root
  │     └── HKDF payload key for each stable field/record context
  └── wrapped search root
        └── HKDF key for each declared capability/search domain
```

The independent search root permits payload rotation without reindex and explicit search rotation when required.
Shared equality joins are INTERNAL ONLY research. They need a common search-domain identity and identical codec/normalizer before admission.
Other fields and tenants derive different keys. There is no universal global token key.

The internal provider contract is `wrap(root, context)`, `unwrap(wrapper, context)`, and `rewrap(wrapper, new_provider, context)`.
The wrapper records pinned provider identity and nonsecret scope, purpose, root identity, and generation.
The deployment policy selects the exact wrapper. Envelope headers cannot choose provider URLs, credentials, or arbitrary keys.
AWS KMS, Vault Transit, and GCP KMS have relevant envelope/rewrap APIs, but each adapter needs its own custody and failure evidence.
Only a local stand-in ran in the new experiments. None is production-qualified.

Production KEKs normally remain outside PostgreSQL. Generated public wrapper/policy artifacts remain under deployment integrity controls.
A development file/environment key is allowed only in an explicit local profile with reduced guarantees.
It cannot be selected by a production manifest downgrade.
No secret root appears in the public manifest, diagnostic output, database functions, or query terms.

Preload the finite admitted generations for the operation's tenant, not every tenant at application startup.
Cache unwrapped roots only in process memory, with a maximum age and no refresh-on-access.
Invalidate inherited caches/clients after fork. No Redis or persisted raw-key cache is required.
A cold or expired key fails when the provider is unavailable. A warm admitted key can operate until its configured expiry.
Provider disable/deletion does not instantly invalidate existing cached keys.
The operator must stop/drain or restart affected workers before declaring no further managed use.
Async preparation awaits remote work outside synchronous SQLAlchemy hooks.
Cancellation discards late material and reports actual transaction ambiguity rather than assuming rollback.

The policy bundle is the minimum non-restored metadata: active lock/target pin, admitted generations, and wrapped-root identities.
Its integrity comes from the existing trusted deployment system. It is not a signed hash-chain freshness invention.
Current subject denial remains in the host's existing authoritative authorization system when required across database restore.
A deployment with no independent current authorization cannot claim restore-resistant subject revocation.

Operational status treats journal counters as recorded progress, not current value verification.
Reverse plaintext inspection also compares native metadata with the host-supplied original lock.
A changed journal snapshot cannot redefine that native contract.
Protected ACTIVE and PENDING inspection derives its catalog contract from the
host-supplied source lock and declared CF1 transformation. Matching edits to
the live catalog and journal do not authorize extra columns, changed native
definitions, weaker frame checks or indexes, or a rewritten pending writer fence.
Paused protection and reverse operations also derive the writer fence from the
host plan before committing progress. Replacing the function body or enabling
definer security cannot become authorized through a matching journal snapshot.
This check precedes backfill, verification, switching, abort and plaintext publication.
Paused schema inspection also compares protection shadows with the source lock,
and reverse staging with the host-pinned protected snapshot and native source types.
Matching catalog and journal edits cannot authorize a different staged schema.
Host artifact construction also checks compiler lock structure, required estimates,
and reverse catalog snapshot structure before connection. This prevents empty
model inventories from making metadata inspection vacuous. Structural validity
does not authenticate a host artifact or replace live catalog and policy checks.
Direct Python rate and maintenance inputs also use safe numeric admission.
Duration estimates must fit the canonical integer range. Numeric overflow returns
a typed failure without a substitute estimate or partial transition effects.
Restore adoption applies the same contract before accepting its explicit CHECK
restatements. Only known PostgreSQL 16 forms of the declared frame check can pass.
Malformed-frame probes supplement exact text admission. They do not establish SQL
equivalence. Protected deployment admission and reverse execution check recorded
restatements against the source fields and policy, including bindings embedded in reverse
plans. This binds recorded catalog facts, not the bodies of external
functions, domain definitions, collation implementations, or index storage options.
Status needs no keys and does not establish key custody or deployment-wide writer exclusion.
After journal retirement, progress counters are unavailable rather than zero.

Migration guard observations use canonical catalog rendering under
`pg_catalog`, then restore the caller's search path. Equivalent observations
across worker sessions no longer depend on visible application schemas.
Actual trigger, function, owner and configuration changes still refuse.
Older paused journals can retain noncanonical observations and still refuse.
This change does not rewrite journal evidence or authorize recovery of those records.

**IMPLEMENTED, shared privilege admission:** initial protection planning checks
runtime safety before key work. ACTIVE connection checks, restored deployment
checks, ACTIVE/PENDING status, payload/search preparation status, Doctor, and
the shared maintenance executor repeat the same effective-privilege checks.
The runtime must differ from the owner and cannot hold superuser, role-creation,
database-creation, RLS-bypass, replication, or owner-membership authority.
Effective CREATE on the current database or any declared schema is refused.
Protected tables must retain their planned owner. Runtime TRIGGER and TRUNCATE
privileges on those tables are refused.

The journal must retain the planned owner. Runtime table-level INSERT, UPDATE,
DELETE, TRUNCATE, REFERENCES, and TRIGGER privileges are refused. Column-level
INSERT, UPDATE, and REFERENCES privileges are also refused. Native privilege
functions include inherited and PUBLIC grants. Ordinary protected-data CRUD
remains admitted through the declared writer boundary. The runtime journal
access is SELECT only. Unsafe privileges raise `unsafe_runtime_role`. Owner
drift raises `maintenance_requires_table_owner`. These checks do not establish
coverage of unknown writers or authenticate deployment policy.

Payload/search preparation status repeats these checks in every recorded
phase, including PREPARED before its journal row exists and ABORTED after
cancellation. It admits the exact P identity before connection and reports
`runtime_metadata_matches: false` with `verification: NOT_PERFORMED`.
Recorded BACKFILLED progress does not authenticate current frames or admit
an application deployment. It needs no keys or maintenance locks and makes
no writes. The CLI refuses a P restore-binding option before reading that binding
or connecting. A lineage-bearing payload proposal already embeds its source.
Search rotation with lineage requires a
[published successor](lifecycle.md#search-rotation-after-adopted-lineage-2026-10-24).
[The walkthrough](walkthrough-migration.md#inspect-rotation-preparation)
owns the full operator contract.

**IMPLEMENTED, bounded pre-adoption Doctor:** `cryptalis.doctor.preflight`
reuses the existing read-only compiler catalog inspection. It accepts no keys
and reads no application values. Known declaration/schema refusals return
actionable issues. Inspection failure remains UNKNOWN with safe diagnostics.
Schema compatibility alone can pass. Provider access, query routes, writer
exclusion, runtime deployment, host authority and recovery capacity stay UNKNOWN.
The report returns no deployment artifact or apply authority.
The pre-adoption CLI accepts an explicit trusted host factory for the registry,
writer inventory and search reviews. It owns the private connection and uses
this same compiler. Host import/factory effects remain UNKNOWN; only compiler
inspection is read-only. The CLI suppresses Python stream output while loading
host configuration, but does not sandbox host Python or native descriptor writes.
Known loader, schema, inspection and cleanup failures retain safe typed diagnostics.

**IMPLEMENTED, bounded ACTIVE Doctor:** `migration.diagnose_deployment` and
`cryptalis doctor` inspect an existing ACTIVE deployment without keys.
The immutable migration plan, exact ACTIVE pin, and optional matching restore
binding pass admission before connection. A read-only, repeatable-read snapshot
then uses the shared attachment check for the actual declared runtime role,
target, lineage, effective privileges, and schema. Doctor authenticates no
frames and does not compare current ACTIVE data with frozen activation frames.
Later valid edits remain admitted.

Only `runtime_deployment` can report PASS in this scope. Provider keys, frame
authentication, query routes, writer exclusion, host authority, and recovery
capacity remain UNKNOWN. The aggregate result remains UNKNOWN, with
`verification: NOT_PERFORMED`, `effects: NONE`, and
`authority: HOST_SUPPLIED_PIN`. An observed mismatch reports runtime FAIL;
unavailable inspection reports UNKNOWN. Current grants can change later.
This observation neither authenticates host publication nor establishes
production readiness. See [Doctor diagnosis](walkthrough-migration.md#diagnose-an-active-deployment).

**IMPLEMENTED, bounded reverse admission:** reverse planning checks the source
and declared plaintext runtime roles before key work. Reverse execution and
read-only status repeat the effective-privilege checks for the role selected
by the current host pin. Pre-publication pins require the source runtime.
PLAINTEXT_ACTIVATING, PLAINTEXT_ACTIVE, REMOVING, and REMOVED select the declared
plaintext runtime while the journal exists. A mutable journal phase never
selects a different role or authorizes weaker admission.

Unsafe source privileges raise `unsafe_runtime_role`. Unsafe selected plaintext
privileges raise `unsafe_plaintext_runtime_role`. The same owner, administrative,
CREATE, table, and journal mutation restrictions apply to either selected role.
Only a REMOVED request with an actually absent journal skips both role checks.
It still requires the package-free native schema and captured metadata checks.
Terminal retries preserve later native edits and do not restore retired runtime
privilege boundaries. Keyless status still reports `NOT_PERFORMED`.

These checks observe current effective grants. They do not freeze later
administrative changes or authenticate host publication. The native retirement
control changes schema privileges and preserves later native edits after
journal retirement. It does not execute DROP ROLE. Actual role retirement
remains an external qualification requirement.

Restore adoption checks exact source identity, ACTIVE progress, reciprocal
ancestry, effective runtime privileges, and protected-column grants before
malformed-frame probes or provider work. For a payload or search successor, A's proof
digest and recorded progress must also match its immutable contract. Missing
or forged source/P ancestors cannot authorize adoption. Protected-column grant
drift raises `source_metadata_changed`, even if catalog and journal edits agree.
Later restored connection checks repeat privilege and metadata admission.

An ACTIVE payload or search backup can contain legitimate edits after publication.
Adoption authenticates current frames under A's exact selected policy and
generation. It does not compare those frames with A's original sealing hashes.
A valid older-generation frame still fails, although its root remains retained.
The original source policy cannot replace A's target policy. Existing
`cryptalis.restore/v1` bindings support this path without owned sequences or the public-slot layout.
Sequence-bearing sources use the restore/v2 identity mapping described below.
Payload rotation after a published lineage-bearing successor follows the
[adopted-lineage contract](lifecycle.md#payload-rotation-after-adopted-lineage-2026-10-24).
Search rotation with lineage follows its [successor contract](lifecycle.md#search-rotation-after-adopted-lineage-2026-10-24).
Direct restore-binding generation planning follows its
[separate contract](lifecycle.md#generation-planning-from-a-restore-binding-2026-10-24).
All seven full gates remain UNKNOWN.

## Operational CLI trust boundary

**IMPLEMENTED, bounded source and installed verification:** the plan/apply workflow accepts
an explicit trusted host factory. It executes Python code without a sandbox.
Host imports, factory calls and native effects remain UNKNOWN. Planning authority
is `HOST_SUPPLIED_CONTEXT`, distinct from a published pin. Apply requires the actual
host pin and maintenance approval. The CLI does not authenticate, infer or
publish that authority.

Require a fresh CLI-owned PostgreSQL/psycopg engine with safe logging. After context
handoff, dispose it on success and failure. Reject an operation mismatch before host loading.
Key resolvers must be synchronous, including callable objects. Recognized async
callables must fail context admission before command-managed database access.
The first expanded candidate fails this requirement. Revised validation passes
all 22 focused source controls. Existing affected CLI/Doctor/status routes pass.
The actual installed wheel passes the combined 211 controls and original application.
These checks do not qualify production host authentication or provider custody.
Keep keys, credentials and host exception text outside result envelopes.
The `effects` field reports known command-managed progress. `host_configuration_effects`
remains UNKNOWN. Output or cleanup errors can follow artifact publication or
committed transition progress. Preserve the original artifact and `known_result`.
Inspect the operation and current host pin before retry. An error does not prove rollback.
Doctor retains its strict key-free tuple and inspection scope. These contexts
do not waive core planner, tenant, runtime-role or lifecycle admission. See the
[specified workflow](walkthrough-migration.md#plan-and-apply-protection-through-the-cli)
and [status](status.md#operational-cli-protection-workflow-2026-10-24).

### Reverse CLI authority

**IMPLEMENTED, bounded source and installed verification:** the host supplies `PlaintextApproval` after it
reviews the saved reverse digest. Removal also requires `RemovalApproval` and the
exact REMOVING or REMOVED pin. A command, factory name or missing journal supplies
no consent or authority. Retained-backup obligations remain host assertions.
Planning embeds only the explicit `RestoreBinding` or None. Execution accepts no
replacement binding. Reject wrong artifact kinds, phases, operation selectors and
conflicting flags before host loading. An unreturned execution result requires
INSPECT_JOURNAL. Preserve known progress after output or cleanup failure.
No plaintext, credentials, raw host exceptions or context representations enter
reports. Host-code effects remain UNKNOWN. Doctor's key-free tuple stays unchanged. See the
[verified checkpoint](status.md#operational-cli-reverse-and-removal-2026-10-24).
Source and installed genuine fresh-target verification pass.

### Root-rewrap CLI artifact and authority boundary

**IMPLEMENTED, bounded source and installed verification:** persist deterministic A before effectful host
loading or API execution. Its existence supplies no authority or database progress.
Normal output collisions refuse. Explicit resume checks the operation UUID, bounded
artifact parse, exact expected bytes and a private regular file. Symlinks refuse.
A missing output permits exclusive publication. Re-sync verified A and its parent
before retry. Do not overwrite a mismatched artifact.

Report file facts separately from database `known_result`. If an effectful API
returns no progress, require INSPECT_JOURNAL even when A is durable. Preserve P/A
after success or cancellation. Source ACTIVE cancellation authority and successor
publication authority remain separate. The CLI creates no provider, keys, host pin,
consent or fencing. Host-code effects and retained-backup obligations retain their
existing limits. Payload/search CLI admission remains future work. See the
[verified checkpoint](status.md#operational-cli-root-rewrap-2026-10-24).
Source and installed genuine adopted-target verification pass.

### Payload CLI artifact retention

**IMPLEMENTED, bounded source and installed verification:** P reserves only A's UUID. Seal must authenticate
staged ciphertext before it creates A. Losing seal output permits authenticated
resealing only while BACKFILLED shadows remain. Seal supplies no database Progress.
Retain exact private durable P+A before switch. Verify bounded canonical A through
a stable regular non-symlink mode0600 descriptor. Re-sync that descriptor and its
parent before host loading or switch. Never overwrite an existing A.

Keep artifact results separate from database known results. An unreturned switch
requires INSPECT_JOURNAL. After switch, use A-status. P is superseded and its shadows
are gone. Losing every external A copy loses the proof current APIs require.
Do not reconstruct A from database assertions or treat key-free status as fresh
verification. Existing source-only cancellation, target-only activation, host authority,
provider and Doctor boundaries remain unchanged. Host-code effects remain UNKNOWN. See the
[verified checkpoint](status.md#operational-cli-payload-rotation-2026-10-24).
Source and installed genuine adopted-target verification pass.

### Search CLI admission

**IMPLEMENTED, bounded source and installed verification:** authenticate all fields and preserve selected payload
generation and retained wrappers. Reseal only searchable CF1 with new nonces and
search terms. Preserve storage-only CF1 bytes exactly. Use search-specific artifact
kinds, digests and explicit P/A authority. Keep existing protection/reverse/payload
refusal exits unchanged. New contexts require direct dispatch evidence.

Reuse the payload artifact-retention boundary, including authenticated reseal before
switch and externally retained A after switch. Key-free status reports NOT_PERFORMED,
not fresh value verification. Source-only cancellation, target-only publication,
unknown host-code effects and Doctor's tuple remain unchanged. See the
[payload retention contract](#payload-cli-artifact-retention) and
[verified checkpoint](status.md#operational-cli-search-rotation-2026-10-24).
Source and installed genuine adopted-target verification pass.

### Initialization CLI trust boundary

**IMPLEMENTED, bounded source and installed verification:** declaration bytes are explicit public host input.
Enforce their type, size and strict parse before canonicalization. Use the existing
read-only compiler through Doctor preflight. Do not infer tenancy, runtime roles,
keys, providers, pins or deployment authority. No application values or keys enter inspection.

Publish only after manifest_schema PASS. Preserve all unobserved UNKNOWN results
and the aggregate UNKNOWN status. Qualify effects NONE as compiler inspection only.
Host import/factory effects remain UNKNOWN. On output, fsync or cleanup failure,
preserve known inspection and artifact facts without inventing a database result,
operation UUID or transition phase. Existing private publication and safe diagnostics apply. See the
[verified checkpoint](status.md#operational-cli-initialization-2026-10-24).
Source and installed initialization verification pass.

### HTTP operational journey limits

**VERIFIED, bounded local source and installed profiles:** the joined profile keeps original authentication, authorization,
JWT and password behavior. Only declared User.email, full_name and is_active fields
are protected. Email equality/uniqueness uses the existing opaque UUID128 fixture in
one explicit table tenant. Password hashes and Item remain native. SMTP capture uses real loopback
TCP only. Receipts contain no JWTs, passwords, reset tokens, response bodies or private URLs.
The import-denied original HTTP child verifies latest native data and does not test SMTP.

This local ASGI/TestClient qualification supplies no browser, deployment, external-mail,
live-custody or production evidence. Status of external retained obligations needs explicit
host inventory/provenance. Wrappers or an empty journal cannot prove no obligations. See the
[qualification checkpoint](status.md#original-http-operational-cli-journey-2026-10-24).

### Synchronous KMS method boundary

**IMPLEMENTED, bounded protocol verification:** recognized async encrypt/decrypt
methods fail client construction with InvalidContext before invocation. Synchronous
SDK behavior, key ARN, context and response checks remain unchanged. No live AWS
qualification follows. See the
[checkpoint](status.md#synchronous-kms-sdk-admission-2026-10-24).

## Owned-sequence admission

**IMPLEMENTED, bounded source and installed verification:** lock/v5 admits only inspected ordinary persistent sequences
with automatic ownership of protected columns and the same table owner/schema.
Admission checks visible catalog dependencies across the database. Unsupported
dependencies refuse. Catalog checks do not enumerate arbitrary dynamic SQL or
authenticate exclusion of external consumers. The host retains that responsibility.

The switch preserves the same sequence object and its effective grants, including
grantor and grant option. Runtime gets no new DDL or ownership privilege.
Post-lock checks precede destructive column replacement. Reverse proposal and
paused checks also refuse inventory drift before providers or new effects.
Only exact admitted `_cryptalis_*` sequence identities escape terminal garbage
classification. Counter tamper resistance is not established. Native counter
increments and rollback gaps remain valid behavior.

Restore/v2 maps source-effective sequence OIDs to new restored OIDs after exact
logical catalog comparison. Later checks use those exact identities through flat
lineage. The binding changes no source identity, host publication authority or
key custody. Old locks still refuse late sequences. This admission does not allow
server-generated record IDs or protected server defaults. Production gates remain UNKNOWN.
See the [lifecycle contract](lifecycle.md#owned-sequence-preservation-and-restored-identity-2026-10-24)
and [current evidence](status.md#owned-sequence-preservation-and-restore-2026-10-24).

## Expression-statistics admission

The unsupported-dependency rule covers expression statistics on modeled tables
for every layout. The shared guard reads `pg_statistic_ext.stxexprs` through
catalog EXISTS. It evaluates no statistics expression. The intended failure is
`unsupported_dependency` before provider resolution or lifecycle effects.
Product code implements the legacy extension. Its first expanded reverse-resume
control reaches the forbidden resolver. A separate first reverse-expansion control
also fails. Revised guards pass 44 focused source controls, including both reverse
paths, unchanged-state refusal and exact repair. Affected-source and revised
installed controls pass, including repair through native exit and both fresh-cluster
profiles. The current status owns the exact scope.
This changes no artifact version, key policy, privilege grant or host authority.
See the [decision](decisions.md#expression-statistics-admission-across-layouts-2026-10-24)
and [current evidence](status.md#legacy-expression-statistics-admission-2026-10-24).

## Public-slot authority

**IMPLEMENTED, bounded source and installed verification:** lock/v6 selects original public attribute
preservation explicitly. The exact `preserve-public-slots/v1` token cannot come from
mutable journal state or an older comparison lock. Runtime gains no DDL privilege.
Public frame CHECKs and equality indexes must refer to converted public columns.
Unsupported expression statistics refuse before provider resolution or lifecycle effects.
Host fencing remains an assertion.

Restore/v3 grants only exact mapped slot authority for the source it names.
The complete ordered map includes every public column. It preserves visible
name order, rejects duplicate, Boolean and out-of-range slots, and composes through
flat lineage. Sequence maps remain mandatory and exact. V1/v2 bindings cannot
waive v6 slot checks. Legacy metadata comparison remains unchanged. CF1, tenant,
key-policy and publication authority do not change. See the
[lifecycle contract](lifecycle.md#public-column-slot-layout-2026-10-24) and
[verification boundary](status.md#public-column-slot-preservation-2026-10-24).

## Cryptographic format

The selected candidate profile uses library AES-256-GCM-SIV, HKDF-SHA-256, and full HMAC-SHA-256 terms.
VERIFIED, recorded primitive probe: cryptography 50.0.2 supplies native AES-GCM-SIV support.
It reduces accidental nonce-reuse harm but does not permit fixed runtime nonces or remove usage-bound review.
AES-GCM requires stronger nonce uniqueness discipline. ChaCha20-Poly1305 also requires nonce discipline.
Extended-nonce libraries can be alternatives after portability and review. No silent algorithm fallback is allowed.
Primary algorithm and library evidence is in [prior art](prior-art.md).

**IMPLEMENTED Boolean storage extension:** the storage-only value
codec uses `cryptalis.context/v2` and `value_codec: boolean-u8/v1`. Its canonical
bytes are 00 for false and 01 for true. Authentication precedes the strict
one-byte decoder. The descriptor digest supplies type binding in the existing
AAD. Text context/v1 bytes and derivation remain unchanged. SQL NULL remains
visible SQL NULL. No Boolean equality term is admitted: the two-value domain
retains its enumeration risk. Lock/v4 requires the Boolean reader and rejects
older readers before use. Non-NULL Boolean frames have exactly 43 bytes.
The [Boolean checkpoint](status.md#boolean-storage-checkpoint-2026-10-23) states
the independent vectors, native controls and lifecycle evidence.
These checks do not supply independent human cryptographic review or production qualification.

CF1 payload framing:

| Byte field | Exact encoding |
|---|---|
| Magic | Four bytes `43 46 31 00` |
| Suite | One byte, value 1 for the selected AEAD/KDF profile |
| Flags | One byte. Bit 0 means packed equality term. Bit 1 adds a companion commitment. Bits 2–7 reject |
| Payload generation | Four-byte unsigned big-endian integer, nonzero |
| Search generation | Four-byte unsigned big-endian integer. Zero without search |
| Packed equality term | Exactly 32 bytes when flag 0 is set. Otherwise absent |
| Companion commitment | Exactly 32 bytes when flag 1 is set. Otherwise absent |
| Nonce | Exactly 12 bytes from the operating-system cryptographic RNG |
| Sealed payload | Encoded bytes plus the full 16-byte AEAD tag. Remaining frame bytes |

Reject unknown suite/flags/generations, short/trailing malformed data, and values beyond the qualified field bound.
NULL is SQL NULL, not a zero-byte encrypted value. Empty text remains an authenticated non-null payload.
Storage-only overhead is 42 bytes. Packed equality overhead is 74 bytes, before SQL tuple/index costs.
A companion commitment adds 32 bytes. Derived arrays add their own SQL storage.
The product implements storage-only and packed equality frames. It rejects the companion flag and all advanced representations.
Independent product vectors cover both formats and both admitted record and tenant codecs. Companion vectors remain unqualified.
The first adapter spike uses a different small lab frame. Its success does not verify CF1.
The offline CF1 text fixture passes 30 framing/context/rotation mutation checks. Same-library roundtrips do not qualify independent AEAD vectors or the generic composition.

Define `T(parts)` as a four-byte unsigned big-endian component count, followed by four-byte byte lengths and exact component bytes.
Generation arguments use four-byte unsigned big-endian integers. Domain, tenant, field, root, and search-domain identities use immutable 16-byte IDs.
Codec and normalizer IDs are frozen UTF-8 names. The descriptor digest uses SHA-256.
For the search root, `search_salt` uses the same salt formula with its own root ID and generation.
Strings use strict UTF-8 and stable IDs use 16 bytes. A bigint record ID uses `T("int64", signed_eight_byte_big_endian_value)`.
Other integer/record codecs require their own immutable typed identities.
No `repr`, delimiter concatenation, implicit Unicode normalization, or mutable SQL name enters cryptographic encoding.

```text
salt = SHA256(T("CF1/root", domain_id, tenant_id, root_id, generation))
payload_key = HKDF-SHA256(payload_root, salt,
    info=T("CF1/payload-key", field_id, typed_record_id), length=32)
aad = T("CF1/payload", domain_id, tenant_id, field_id,
        typed_record_id, immutable_codec_descriptor_digest, complete_header)
search_key = HKDF-SHA256(search_root, search_salt,
    info=T("CF1/search-key", search_domain_id, codec_id, normalizer_id, capability), length=32)
term = HMAC-SHA256(search_key, T(capability, canonical_value_or_node))
```

The descriptor pins type, codec, null policy, representation identity, and context encoding.
It excludes mutable table/column names and unrelated manifest edits.
Define the companion commitment as SHA-256 of `T("CF1/companions", entries...)`.
Each entry is `T(capability_id, representation_id, T(sorted_unique_full_terms))`.
Sort entries by capability ID as bytes. Reject duplicates and terms that are not 32 bytes.
The complete header ends after the optional commitment. AAD includes every header byte, including generations and packed term.
The payload processor receives projected companion arrays and verifies their commitment before release.
Adding/removing a capability or rotating search terms therefore requires a fresh nonce and payload reseal, even when its payload key stays unchanged.
The offline text fixture tests the commitment and reseal behavior with public roots.
The service lifecycle lab now reads actual projected arrays and rejects changed/missing/malformed companions before full verification can succeed.
Independent vectors and a complete advanced-field ORM projection remain unqualified.
Expected context comes from the host/mapping and generated row projection, not ciphertext-supplied authority.
Per-record key derivation limits repeated use of one payload key. It does not establish a reviewed aggregate lifetime bound by itself.
No quantified security bound or approved key-retirement threshold exists yet.
Independent review must settle those bounds before real-data admission. The former distributed quota service is not retained by assumption.

### Optional AWS KMS SDK adapter

**IMPLEMENTED, SDK boundary only:** `cryptalis.crypto.aws_kms.AwsKmsKeyProvider`
implements the existing provider protocol without a mandatory SDK dependency.
Construct it with `AwsKmsKeyProvider(client, provider_id=provider_uuid, key_arn=full_key_arn)`.

The optional AWS KMS adapter accepts a caller-supplied synchronous SDK client,
a provider UUID and one full key ARN. It sends the exact ARN and
SYMMETRIC_DEFAULT on Encrypt and Decrypt. Aliases and bare key IDs refuse.
Every response must match that ARN and algorithm. Plaintext roots must contain
exactly 32 bytes. Provider ciphertext remains bounded opaque bytes.

Its versioned encryption context binds provider, domain, tenant, purpose,
root identity and generation. These are public metadata and can appear in
CloudTrail. The host supplies credentials, endpoint, timeout and bounded SDK
retry settings. The adapter performs no credential discovery or key administration.
Async unwrap uses a worker thread. Cancellation prevents late keyring publication
but cannot cancel an already dispatched SDK call. Inherited providers refuse
after fork. Python bytes provide no verified zeroization guarantee.

Protocol controls and existing CF1/keyring behavior pass through the mandatory
wrapper. The caller-supplied client remains a trusted host boundary.
These checks do not qualify live AWS custody, IAM, workload identity,
endpoint, provider deletion or production operation. All seven gates remain UNKNOWN.

The exact public encryption-context keys are `cryptalis:format`,
`cryptalis:provider`, `cryptalis:domain`, `cryptalis:tenant`, `cryptalis:purpose`,
`cryptalis:root` and `cryptalis:generation`. The format value is
`CF1/aws-kms-wrap/v1`. Identities use canonical UUID text and generation uses
unsigned decimal text. Wrappers remain provider-opaque bytes. CF1 frames and
key-policy admission do not change.
The [AWS encryption-context reference](https://docs.aws.amazon.com/kms/latest/developerguide/encrypt_context.html)
explains service matching and logging. No caller-supplied context names are accepted.

### Implemented CF1 primitives and local custody

`cryptalis.crypto` exports `FieldDescriptor`, `seal_text`, `open_text`, `KeyProvider`,
`DevelopmentKeyProvider`, `create_root`, `KeyContext`, `KeyPolicy`, and `Keyring`.
`FieldDescriptor.from_compiled(document, digest)` consumes one trusted compiler descriptor.
A matching digest checks structure. It does not authenticate the deployment policy.
Seal and open take the descriptor, expected tenant and record, and prepared keys.
They encode exact UTF-8 text without NUL and refuse encoded values above **16 MiB**.
Empty text uses an authenticated frame. SQL NULL remains SQL NULL.
Protection planning rejects dialect-specific type variants on record and tenant
identity columns. A SQL-side identity transformation cannot preserve the declared
row context codec merely because the top-level mapped type remains UUID or bigint.
Nil UUIDs are valid native tenant and record values. Single-tenant context equals the stable table UUID.

Each keyring pins one immutable policy for one domain and tenant.
The policy admits at most **32 wrapped roots** and selects active write generations.
Frame generations select only already prepared keys. They cannot select provider authority or cause network calls.
`prepare()` and `prepare_async()` return keys for an operation.
The cache defaults to **60 seconds** and permits a maximum of **300 seconds**.
Access does not extend expiry. Each crypto operation checks expiry before it returns a value.
These operational limits are prototype safeguards. They are not reviewed cryptographic usage limits.

Protection, decrypt-back and restored-frame scans can discard one unfinished
row after actual key lease expiry. They then check the exact host policy, prepare fresh keys, and
retry local row crypto once. SQL, durable progress, and verification digests
change only after the complete row succeeds. A provider failure, changed
policy, or second expiry stops the operation. This retry does not extend a
lease or refresh keys inside frame processing. Restored-frame scans retain
`KeyUnavailable` for custody failures and finish before effectful CHECK probes.
ORM operations retain their separate expiry rules. Payload/search staging and
paired-frame verification separately share one retry budget across a row's
pure crypto steps. Fresh admission checks both exact pinned policies and the
retained-root relationship before replacing prepared material. This preserves
the three-frame logical budget by releasing source frames before target decoding.
Source-only and activation-target observations, plus outer executor/return lease
checks, still stop on expiry. No generic provider or policy fault retries.

`create_root(provider, context)` uses independent operating-system randomness.
Wrapped roots carry exact provider identity, domain, tenant, purpose, root identity, and generation.
Provider payloads are opaque bytes with a **64 KiB** limit.
The development wrapper binds this metadata with AES-256-GCM-SIV and a fresh 12-byte nonce.
Its sealed bytes contain the nonce and a 32-byte root with a full 16-byte tag.
It retains the local key-encryption key only in memory. Process loss prevents recovery.
Local `rewrap` preserves the root and creates a wrapper under the replacement provider.
This does not implement a deployment rotation workflow.
**IMPLEMENTED, internal candidate only:** `prepare_rewrap(source, target)` resolves every
admitted root under the source lease, wraps each root under the target provider identity,
unwraps and compares it, and returns an inactive policy with the same contexts and
generations. It does not publish, persist, or change the source policy. Invalid target
identity, provider faults, wrong roots/contexts/providers, identity drift, and source
expiry return `KeyUnavailable` without a partial candidate. Interruption propagates.
The bounded `rotation.plan_rewrap` and `rotation.apply_rewrap` APIs add a
maintenance workflow around independently prepared source and target policies.
They authenticate exact roots and current frames before a byte-preserving
successor cutover. The host retains both policies and publishes the successor
outside PostgreSQL. Shared activation authenticates target frames against the
host artifact before removing writer guards. A journal claim supplies no current
deployment authority. This establishes no production custody, stronger revocation,
key deletion, or automatic retained-backup retirement.
Pending cancellation requires the republished source ACTIVE pin and authenticates
source policy, retained roots, frames, schema and lineage before guard removal.
The target provider need not remain available. A terminal retry inspects current
source authority and cannot revive a source superseded by a later operation.
See [lifecycle](lifecycle.md#changes-and-rotation) and [status](status.md#active-root-rewrap-checkpoint-2026-10-23).

Adopted-target root rewrap retains the explicit original binding in rewrap/v2
and flat inherited restore lineage in transition/v5. Binding identity, original
source custody and recognized frame CHECK/probe admission precede provider work.
Historical bindings retain schema evidence, not successor publication authority.
The successor requires its own current host pin. Cancellation restores the exact
adopted source state under its republished source pin and original binding.
It needs no target provider and cannot replay old data on a terminal retry.
The [17-control source profile](_reset/fresh-cluster-restore-20261024-4.json)
supplies no new cryptographic or host authority. See the
[lifecycle contract](lifecycle.md#adopted-target-root-rewrap-2026-10-24),
[format decision](decisions.md#adopted-target-root-rewrap-2026-10-24) and
[current evidence](status.md#adopted-target-root-rewrap-2026-10-24).

Payload rotation after adopted lineage starts from the current ACTIVE v5/v6
successor and its own host pin. The unchanged `cryptalis.payload-rotation/v1` proposal embeds
that source. Its `cryptalis.transition/v6` activation retains flat restore lineage and every v3 payload
proof. Existing frame/probe, owner, target-chain and reciprocal-ancestor checks
remain required. Historical bindings supply no current publication authority.
Before switch, cancellation still requires source custody, the current source
ACTIVE pin and maintenance approval. It needs no target provider. Terminal
cancellation preserves later source edits and cannot revive a superseded source.

The [12 native fresh-target controls](_reset/fresh-cluster-restore-20261024-11.json)
pass, as do the source VARCHAR and installed TEXT profiles. The final installed
Smolink journey and full regression retain their exact
[status boundaries](status.md#payload-rotation-after-adopted-lineage-2026-10-24).
Search rotation with lineage follows its [successor contract](lifecycle.md#search-rotation-after-adopted-lineage-2026-10-24).
Direct restore-binding generation planning follows its
[separate contract](lifecycle.md#generation-planning-from-a-restore-binding-2026-10-24). Deploy readers that admit the embedded
source and v6 before publication. CF1, host approval/fencing, retained-reader
obligations and key-retirement permissions do not change. All seven production
gates remain UNKNOWN. See the [format decision](decisions.md#adopted-target-payload-rotation-2026-10-24).

Adopted search rotation uses the current lineage-bearing source and its own pin.
Search-rotation/v1 retains the embedded source; v7 retains every v4 search proof
and the admitted restore lineage. All 11 native mixed-field controls pass, including refusal and recovery paths.
Source TEXT/VARCHAR, installed TEXT, affected and ordinary installed application
checks pass within their recorded boundaries. See the
[current boundary](status.md#search-rotation-after-adopted-lineage-2026-10-24).
The crypto, index representation, journal and host-authority contracts do not change.

Direct generation planning can embed the existing restore binding in an exact
purpose/v2 proposal. Pure identity, original custody, frame/probe, owner and
lineage checks precede provider work. The evaluated target does not replace the
original source identity or host pin. Existing cancellation and publication
authority rules remain required. The [current checkpoint](status.md#direct-restore-binding-generation-planning-2026-10-24)
records 19 native controls, including changed CHECK and disabled-guard refusal
before providers. Source VARCHAR, affected-suite and ordinary installed application
checks also pass. All 19 installed direct controls and the original six-file
SQLModel direct search journey pass within their recorded boundaries.
This adds no cryptographic, production email-domain or key-retirement permission.

**IMPLEMENTED, internal batch only:** `prepare_payload_rotation_batch(rows, field, tenant,
source=..., target=...)` decodes each current frame under the exact source payload
generation, reseals the same exact text under the target generation, preserves record
identity and the source search-header bytes, and returns a complete immutable tuple or
raises. It admits one field and tenant, distinct source/target payload roots, an
unchanged search generation, bounded rows/bytes, and unique records. It performs no SQL,
provider, policy, or schema change. A caller must integrate any result into a separately
approved journaled lifecycle before a database switch.

**IMPLEMENTED, read-only planning:** `rotation.plan_payload_rotation` produces
preparation proposal P and checks complete source custody, including retained
roots and deleted tenants. Its target
retains every exact source wrapper and adds one new independent payload root.
The selected generation exceeds all retained payload generations. Search custody
does not change. The snapshot authenticates current source frames under both
reader sets and records frame/membership digests, public contexts and estimates.
It stores no plaintext digest, wrapper bytes or root material. Provider preparation
can have provider-side audit/cost effects. A successful plan performs no staging
or publication. Lease expiry remains `KeyUnavailable`.

**IMPLEMENTED, encrypted staging:** `rotation.apply_payload_rotation` uses the
existing CF1 batch transform under maintenance guards and table locks. The
source frames and original journal remain unchanged during preparation. P owns
separate shadows and progress. The executor checks the schema against P and exact guard facts.
It checks cursor membership, shadow lengths, NULL presence, and the empty suffix
before fetching a committed prefix. It authenticates exact source and target
generations, values, and search headers. Retained roots cannot make an unchanged
source frame pass as a rotated target.

BACKFILLED retries repeat full authentication against P's source observations.
Keyless status reports `NOT_PERFORMED`, not cryptographic verification. Chunk
ciphertext and its cursor commit atomically. The executor preserves completed
ciphertext on resume. Row and aggregate byte limits bound logical inputs across
fields. They do not bound process resident memory, driver buffering, database
memory, or provider overhead.

Cancellation requires the host to republish the exact source ACTIVE pin.
Source-only authentication precedes removal of exact shadows and guards.
Cleanup and the ABORTED marker share one transaction. The target provider need
not remain available. A terminal retry preserves later source edits without
restoring snapshots.

**IMPLEMENTED, sealed target proof:** sealing authenticates the unchanged
source against P and the actual staged target before it emits immutable A.
A binds P's digest and exact ancestry, target ciphertext observations, and
batch limits. P reserves A's ID without its digest. Neither a staging cursor
nor mutable journal hashes can replace those host-pinned observations.
Sealing requires BACKFILLED, maintenance approval, and measured copy costs.
It holds maintenance locks but makes no database data, schema, or journal change.
Provider audit/cost effects remain possible. Sealing creates no cryptographic
signature and cannot replace trusted host persistence or current authority.
Persist A before destructive switch.

Cutover repeats source/target proof under locks and copies ciphertext into the
existing public columns. It preserves their identities, constraints, expression
indexes, grants, and metadata. Source-to-P-to-A supersession, guard exchange,
and a post-copy target check share one transaction. Search headers and roots
remain unchanged. No search reindex occurs. The final full-table write is not
a bounded preparation chunk. A's estimate counts that copy and five
authentication passes, including both sides of the paired comparison.

PENDING recovery checks exact target observations and reciprocal ancestry
against saved A. Original source bytes no longer support retry comparison.
Preparation and cancellation refuse a superseded P. Shared activation requires
an independently current ACTIVATING or ACTIVE pin. An ACTIVATING retry checks
A's target proof even when the journal claims ACTIVE. A genuine ACTIVE pin
permits subsequent edits and latest-value decrypt-back/removal.

Recorded copy wall time and cluster-wide WAL deltas are diagnostic observations.
They exclude later DDL, verification, commit, and publication. Other cluster
writes can contribute WAL. These metrics establish no capacity bound, isolated
WAL cost, deployment authority, or fresh cryptographic proof. Payload rotation
after adopted lineage requires a published v5/v6 source; direct payload planning
from an explicit restore binding follows the
[separate v2 contract](lifecycle.md#generation-planning-from-a-restore-binding-2026-10-24). All seven full gates remain UNKNOWN.

**IMPLEMENTED, bounded native verification:** search rotation retains every exact
source wrapper and root material. It adds one independent search root above all
retained search generations. The selected payload generation and root stay unchanged.
Policies with no selected search generation stay unchanged. Searchable CF1 frames receive fresh
nonces, new authenticated search metadata, and terms under the target generation.
Storage-only frames retain their exact bytes. This introduces no new CF1 format.

One exact host-pinned policy selects the active search wrapper. Retained roots
serve readers without adding an application query namespace. Mixed-generation
OR queries and cross-generation uniqueness gaps remain unadmitted. This boundary
must survive later payload and rewrap successors. Search rotation does not erase
old search leakage or authorize retirement of retained roots.

The search P/A protocol binds source observations to P and actual randomized
target frames to A. It uses `cryptalis.search-rotation/v1` preparation and a
`cryptalis.transition/v4` activation with `kind: search_rotation`. Paired proof,
server-side copy, native expression/unique-index maintenance, reciprocal ancestry,
and guard exchange precede publication. Journal hashes cannot replace A's target
proof. An ACTIVATING retry must check that proof even if the journal claims
ACTIVE. A genuine ACTIVE pin permits later edits.

Copy measurements must include all native index maintenance. The atomic terminal
write is not a bounded preparation chunk. Storage capacity and writer-pause
bounds remain unqualified. The existing restore-binding format supports the
bounded search-backup profile. An independent generation-2 search/HMAC decoder
and the product reader recover current values after publication edits. A valid
old-generation frame and the original source policy fail adoption. Later adopted
edits survive decrypt-back and removal. Later search rotation follows the
[adopted-lineage contract](lifecycle.md#search-rotation-after-adopted-lineage-2026-10-24). The separate [payload route](lifecycle.md#payload-rotation-after-adopted-lineage-2026-10-24)
requires a published lineage-bearing successor. External custody, current host authority, and source fencing
remain unqualified. [Status](status.md) owns executable evidence.
All seven full gates remain UNKNOWN.

Sync and async preparation publish keys only after every required root passes checks.
Cancellation rejects late provider material, including when a provider suppresses cancellation.
Inherited providers, keyrings, and prepared keys refuse use after fork.
The child must construct a fresh provider and prepare fresh roots.
Python immutable bytes do not give a verified zeroization guarantee.
Failures have safe codes, operation IDs, stages, retry indicators, effect states, and remedies.
Raw provider and cryptographic exception text does not enter those diagnostics.
The [slice 2 checkpoint](status.md#slice-2-checkpoint-2026-10-08) records the exact evidence boundary.

Full-width terms avoid intentional false positives. Exact query claims remain conditional on HMAC collision resistance and intact indexed representations.
Recomputing a term from returned plaintext does not detect a collision with a different value. AEAD cannot repair that semantic error.
No collision detector exists in the small prototype. Do not promise unconditional collision-free queries.
A UNIQUE token conflict fails the write, but does not by itself classify equal values versus a collision.
Human review must accept the computational assumption or require explicit original-predicate validation before capability admission.
Such validation must fail on a mismatch. Hidden filtering and incomplete pagination are forbidden.
A token match never authorizes data access. A UNIQUE conflict leaks membership and requires host authorization and rate limits.
No key-commitment guarantee is claimed. Exact-key resolution and cross-key attacks need human review.

## Capability leakage

Storage/equality/IN/tenant-uniqueness leakage below is the accepted SPECIFIED boundary.
Advanced representations add no accepted public capability or leakage opt-in until [six-gate admission](compatibility.md#capability-admission).

| Representation | What PostgreSQL can learn |
|---|---|
| Storage only | Row linkage, ciphertext length, presence/NULL, write timing, access, and result volumes |
| Equality and IN | Also equal-value classes, frequencies, repeated queries, and queried membership sets within the tenant/domain |
| Tenant-scoped uniqueness | Also existence/membership from uniqueness conflicts within that tenant |
| Shared equality join, INTERNAL ONLY | Also linkage between the explicitly shared fields/tables |
| Tree range, INTERNAL ONLY | Also node membership, frequency, ancestor/intersection relationships, query covers, and structure/access/volume patterns. Known bounds or queries can label ranges |
| Native-order OPE candidate, INTERNAL ONLY | Also complete relative order and equality. Auxiliary distributions and sorting can recover values. Construction-specific leakage needs review |
| Prefix, INTERNAL ONLY | Also shared prefix membership, length through term count, prefix relationships, query repetition, and chosen-input labels |
| Text token candidate, INTERNAL ONLY | Also word/token relationships and frequency. Positions/ranking require further representations and leakage |

A static keyed tree is not MongoDB's full structured-encryption protocol or a forward/backward-private SSE scheme.
It has no ORAM/PIR or opaque-field claim. No home-grown primitive is introduced, but the composition still requires expert review.
The measured frequency attack on 100,000 synthetic skewed names recovered 100% of classes and rows using an independent auxiliary sample.
This is a realistic-shaped synthetic control, not a customer recovery-rate estimate.
The same frequency technique recovered 100% of rows/classes from complete prefix-array signatures.
It recovered 27.211% of rows and 33.333% of classes from range-array signatures over synthetic clipped ages.
The attacker sees arrays and independently sampled auxiliary frequencies, not the secret key.
Range-structure and prefix-specific published attacks remain unexecuted. None of these rates predicts a customer distribution.
`plan` must show that absence and block advanced-capability apply until the required attack evidence exists.
An acknowledgment alone cannot convert missing security evidence to PASS.
G-PROVIDER, G-POLICY, and independent review requirements remain UNKNOWN. No local provider/policy check qualifies production custody or publication.

## Public failure contract

Failures expose an operation ID, stage, safe code, retry class, durable progress, and a concrete remedy.
They do not expose plaintext, key bytes, ciphertext bodies, terms, SQL binds, or raw provider exception text.
Engine defaults use `echo=False` and `hide_parameters=True`. Attachment refuses an engine with query echo enabled or parameter hiding disabled before any connection or key access. Host logging remains a separate trusted responsibility.

| Condition | Required result |
|---|---|
| Missing or expired key | `KeyUnavailable`, no plaintext fallback |
| Provider outage, revoked identity or malformed material | `KeyUnavailable` (or `TransitionFailure` carrying that code), no partial commit; retry after provider recovery |
| Unsupported query/mapping/writer | `UnsupportedProtectedOperation`, reject the affected path before admitted plaintext SQL |
| Wrong context or invalid tag | `AuthenticationFailed`, no unauthenticated value |
| Payload/companion mismatch | `RepresentationMismatch`, fail the operation rather than filter candidates |
| Stale deployment/manifest | `PolicyMismatch`, no automatic activation from database state |
| Failed/incomplete verification | `TransitionIncomplete`, no switch |
| Lost COMMIT/provider reply | Explicit UNKNOWN/PENDING. Inspect the original action before retry |
| Missing required observation | UNKNOWN, never PASS |

CLI exit 0 means complete requested scoped success. Invalid/denied input returns 2, incomplete state or an observed mismatch returns 3, and operational/output failure returns 4.
Doctor can exit 0 while its six unobserved checks and aggregate result remain
UNKNOWN. Its failure envelope includes `error.checks`; unavailable inspection
keeps the runtime check UNKNOWN. Inspection and cleanup failures include the
selected plan's public operation UUID. Known runtime-role and external-pin
refusals include fixed safe remedies. Other inspection codes keep the generic
reason. No remedy automatically changes grants, artifacts or host authority.
Successful plan output is a proposal, not applied protection.
Report existing effects if cleanup or output also fails. Nothing security-critical may fail silently.

## Human review

Review the implemented codec/frame/KDF/AAD/search composition, usage bounds, provider identity, raw-writer boundary, and restore/erasure claims.
Also review ORM semantics, migration interruption, and package-free removal.
AI council review is first-party criticism. It does not replace an independent cryptographer or production evidence.
The [release gate](../ENGINEERING_PLAYBOOK.md#release-gate) remains mandatory.
