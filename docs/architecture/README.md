# Cryptalis architecture

**SPECIFIED:** selected architecture. [Status](../status.md) owns implementation and verification claims.
No runtime compatibility cell is qualified. A document is not executable evidence.
The manifest declares field intent. Cryptalis compiles that intent into payload, search, mapping, and transition plans.

## Documentation ownership

| Owner | Contract |
|---|---|
| [README](../../README.md) | Adoption and prerequisites |
| This document | Selected scope, components, data paths, manifest, integration, and CLI |
| [Security](../security.md) | Trust, crypto, keys, leakage, failures |
| [Lifecycle](../lifecycle.md) | Migration, rollback, rotation, restore, and removal |
| [Compatibility](../compatibility.md) | Query grammar, DDL, performance targets, and admission |
| [Status](../status.md) | Actual executable capabilities, gate criteria, and evidence |
| [Build guide](../build-guide.md) | Implementation order and deciding tests |
| [Decisions](../decisions.md) | Approved choices and unresolved decisions |
| [Prior art](../prior-art.md) | Primary-source comparison |
| [Engineering playbook](../../ENGINEERING_PLAYBOOK.md) | Manual implementation, tests, and release |
| [Revamp research](../research/revamp-evidence.md) | Archived experiment provenance and replaced constraints |

Research files are historical evidence, not alternate specifications. Git preserves replaced contracts.
No old internal API or experimental format constrains authorized implementation.

## Approved scope

All contracts in the following sections are **SPECIFIED** unless a paragraph labels recorded evidence.
SUPPORTED selects current admitted design scope, not production qualification.
The first public release targets the full SRS and all 34 objectives under the
[comprehensive release direction](../decisions.md#comprehensive-first-public-release-2026-10-23).
The table below records current admission, not permanent product exclusions.

| Contract | Approved choice |
|---|---|
| Stack | Python 3.12+, SQLAlchemy 2.x, psycopg 3 sync and async, PostgreSQL 16 |
| Protected type | Native text/VARCHAR and storage-only Boolean, finite Date and signed integers with standard mappings. Other protected types remain CURRENTLY UNADMITTED |
| Capabilities | SUPPORTED: storage-only, equality/IN with simple negative forms, tenant-scoped uniqueness and bounded count reports under the [compatibility contract](../compatibility.md) |
| Tenancy | Every protected table declares a tenant column or declares itself single-tenant. The compiler never guesses tenant ownership |
| Primary keys | Application-generated UUID, Snowflake-style, or another app-assigned ID. Reject serial, identity, and database-default-generated keys at plan time |

Comparisons/ranges, ordering, prefix/substring/fuzzy search, protected aggregates
other than admitted counts, JSON and other encrypted types remain **CURRENTLY UNADMITTED**.
They remain engineering objectives. Safe refusal does not complete them.
The [seven baseline slices](../build-guide.md#ordered-build-slices) retain their dependency requirements.
The [six-gate admission rule](../compatibility.md#capability-admission) and leakage opt-in control each addition.
Use the [competitive capability matrix](../research/capability-matrix.md) to select secure practical profiles.
Research arrays, order encodings, internal transport, and diagnostic helpers are **INTERNAL ONLY**. They do not admit a public capability.

Internal storage-only candidates now include signed int2/int4/int8 and exact
DATE. DATE uses the same compiler, CF1/context, adapter and lifecycle components,
with strict lock/v8 and `pg-date-days-be/v1`; literal defaults also require
`pg-date-default/v1`. These candidates do not admit numeric/date search or
qualify a production cell. See the [DATE boundary](../compatibility.md#internal-date-storage-candidate).

## Compatibility promise

Cryptalis never silently changes what the backend returns.
Every supported operation matches the unprotected database's results, native types, NULL behavior, and ORM state.
Every unsupported operation raises `UnsupportedEncryptedQuery` or an equivalent typed error before execution.
Different, partial, unauthenticated, or plaintext-fallback results are forbidden.
The [query grammar](../compatibility.md#query-semantics) bounds this promise. The [security owner](../security.md) states its cryptographic assumptions and adversarial limits.

## Components

| Responsibility | Work |
|---|---|
| Compiler | Validate manifest/mapping/schema. Generate stable identities, representations, DDL, query rules, and semantic diff |
| SQLAlchemy adapter | Prepare row context, encrypt writes, rewrite admitted expressions, authenticate reads, reject unsupported paths |
| Crypto/provider boundary | Encode typed values, use library AEAD/HKDF/HMAC, resolve exact admitted keys, wrap/unwrap roots |
| Transition executor | Maintenance transitions plus explicit bounded initial native-write capture, final catch-up fence, verification, switch and reversible role transfer |

CLI commands compose these four responsibilities. Startup, plan, apply, and status reuse the same checks.
PostgreSQL supplies constraints, transactional DDL, atomic chunks, indexes, and ordinary transaction outcomes.
Deployment supplies current policy, credentials, writer exclusion, and restore quarantine. The provider supplies external root custody.

### Operational protection CLI

**IMPLEMENTED, bounded source and installed verification:** the initial workflow composes
existing Python operations. Public frozen `PlanningContext` and `ApplyContext` values
supply explicit host inputs. `--host-context MODULE:FACTORY` selects a trusted
synchronous zero-argument factory. There is no automatic context discovery or authority inference.

`PlanningContext` requires `engine`, `mapping`, `writers`, `search_reviews`, `keys`,
`runtime_role`, `target_id`, `backfill_rows_per_second`, `verify_rows_per_second`,
`temporary_bytes_per_row` and `wal_bytes_per_row`. `ApplyContext` requires `engine`,
`keys`, `pin` and `approval`. The factory supplies a fresh engine owned by
one CLI invocation. Accept only PostgreSQL/psycopg with `echo` False or None
and `hide_parameters` True. Dispose the engine on success and failure.
Host-code effects remain UNKNOWN.
Key resolvers must be synchronous, including callable objects. Recognized async
callables must fail context admission before command-managed database access.

Plan writes the existing immutable protection `MigrationPlan` artifact with exclusive
private output and atomic durable publication. Protection execution accepts protection plans only.
Resume and abort bind the requested operation before host loading. The default
target is PENDING. ACTIVE requires the supplied ACTIVATING host pin and maintenance
approval. The CLI cannot authenticate or infer host authority. Doctor's key-free
configuration tuple remains separate. Other lifecycle commands remain required future
work. No format, cryptographic or core protocol changes. See the
[status checkpoint](../status.md#operational-cli-protection-workflow-2026-10-24).
These dependencies do not supply host business authorization. No additional authority, workflow, or diagnostic service is required.

### Reverse and removal CLI

**IMPLEMENTED, bounded source and installed verification:** `plan --reverse SOURCE --out REVERSE` calls
existing reverse planning and persists its canonical artifact. The positional
manifest and `--reverse` are mutually exclusive. `apply REVERSE` and `rollback REVERSE`
share the existing reverse executor. `rollback` accepts only reverse artifacts.

| Trusted context | Required inputs |
|---|---|
| `ReversePlanningContext` | `engine`, `keys`, `source_pin`, `plaintext_runtime_role`, four measured costs/rates and explicit `restore` or None |
| `ReverseApplyContext` | `engine`, `keys`, `pin`, `approval`, `consent` |
| `RemovalContext` | `engine`, `pin`, `approval`, `consent`, `removal` |

The four measurements retain `backfill_rows_per_second`, `verify_rows_per_second`,
`temporary_bytes_per_row` and `wal_bytes_per_row`. The source pin names the ACTIVE
source. Execution and removal pins name the exact reverse operation and digest.
`consent` is `PlaintextApproval`. `removal` is `RemovalApproval`. An optional
`RestoreBinding` is explicit during planning and has no execution override.

Both execution spellings default to PLAINTEXT_PENDING. The host supplies the
PLAINTEXT_ACTIVATING pin before explicit PLAINTEXT_ACTIVE completion. UUID checks
precede host loading. Abort uses no keys and removes only pre-switch staging.
Removal requires PLAINTEXT_ACTIVE database state and the REMOVING host pin.
A terminal retry requires REMOVED authority and the same approvals. Removal
neither uninstalls the package nor deletes provider material. Existing engine,
publication, privacy and Doctor boundaries remain unchanged. See the
[verified checkpoint](../status.md#operational-cli-reverse-and-removal-2026-10-24).
Source and installed genuine fresh-target verification pass.

### Tenant-policy maintenance CLI

**IMPLEMENTED, bounded source and installed verification:** `tenants provision
plan|apply|activate|abort` reuses the maintenance tenant API and shared policy
transition runner. The trusted host supplies the approved typed UUID/Keyring;
there is no CLI-selected tenant/key authority. `TenantPlanningContext` carries
`engine`, `source_keys`, `source_pin`, `tenant_id`, `key_policy`,
`verify_rows_per_second` and `restore`. Distinct apply/activation contexts carry
`engine`, `keys`, `pin` and `approval`; abort carries `engine`, `source_keys`,
`source_pin` and `approval`. The existing engine and synchronous-resolver rules
apply. Apply retains the exact private successor durably before host loading or
database effects. Actual host publication and source-only cancel authority stay
external. See the [procedure](../lifecycle.md#add-an-empty-tenant-policy-under-maintenance)
and [evidence](../status.md#tenant-policy-maintenance-cli-2026-10-28).

### Root-rewrap CLI

**IMPLEMENTED, bounded source and installed verification:** `keys rotate rewrap plan SOURCE --out P`
saves the existing proposal. `apply P --out A` saves exact `P.activation_plan`
before host loading and calls existing rewrap execution. It requires both source
and target key resolvers, including PENDING retry. `activate A` calls the shared
publication executor with target keys alone. `abort P` uses source keys and the
separately supplied source ACTIVE pin. Abort creates no target context.

| Trusted context | Required inputs |
|---|---|
| `RewrapPlanningContext` | `engine`, `source_keys`, `target_keys`, `source_pin`, `verify_rows_per_second`, `restore` |
| `RewrapApplyContext` | `engine`, `source_keys`, `target_keys`, `pin`, `approval` |
| `RewrapActivationContext` | `engine`, `target_keys`, `pin`, `approval` |
| `RewrapAbortContext` | `engine`, `source_keys`, `source_pin`, `approval` |

Restore is an explicit binding or None. P retains its binding and lineage.
Apply requires successor PREPARED/PENDING authority bound to A. Activation requires
ACTIVATING/ACTIVE authority. Cancellation requires republished source ACTIVE authority
with writers stopped. An ACTIVE successor cannot be cancelled. Terminal ABORTED
retry preserves later source edits and refuses later supersession. Existing safe
engine, synchronous resolver, privacy and Doctor boundaries remain unchanged. See the
[verified checkpoint](../status.md#operational-cli-root-rewrap-2026-10-24).
Source and installed genuine adopted-target verification pass.

### Payload-rotation CLI

**IMPLEMENTED, bounded source and installed verification:** `keys rotate payload` composes seven actions:
`plan SOURCE --out P`, `apply P`, `status ARTIFACT`, `seal P --out A`,
`switch P --activation A`, `activate A` and `abort P`.
All use an explicit trusted synchronous factory and the existing owned-engine contract.

| Trusted context | Required inputs |
|---|---|
| `PayloadPlanningContext` | `engine`, `source_keys`, `target_keys`, `source_pin`, four preparation measurements, `restore` |
| `PayloadApplyContext` | `engine`, `source_keys`, `target_keys`, `pin`, `approval` |
| `PayloadStatusContext` | `engine`, `pin` |
| `PayloadSealingContext` | `engine`, `source_keys`, `target_keys`, `pin`, `approval`, `copy_rows_per_second`, `copy_wal_bytes_per_row` |
| `PayloadSwitchContext` | `engine`, `source_keys`, `target_keys`, `pin`, `approval` |
| `PayloadActivationContext` | `engine`, `target_keys`, `pin`, `approval` |
| `PayloadAbortContext` | `engine`, `source_keys`, `source_pin`, `approval` |

Preparation measurements retain `backfill_rows_per_second`, `verify_rows_per_second`,
`temporary_bytes_per_row` and `wal_bytes_per_row`. Restore is explicit None or an
existing binding. It enters only planning and stays embedded in P. Target keyrings
already contain the independent payload root. The CLI creates no root or provider.
P staging pins and A switch/publication pins bind distinct operation IDs and digests.

Apply stops at EXPANDED or BACKFILLED. Seal authenticates BACKFILLED shadows without
a new journal phase. Switch consumes externally retained exact P+A. First switch
uses both custody resolvers. A PENDING switch retry accepts both arguments but
uses target custody only after reciprocal proof. Activation is target-only. Abort
is source-only and refuses after switch. Key-free status dispatches P/A to existing
status APIs and reports NOT_PERFORMED verification. Copy, DDL, commit and publication
costs remain outside preparation chunk bounds. See the
[verified checkpoint](../status.md#operational-cli-payload-rotation-2026-10-24).
Source and installed genuine adopted-target verification pass.

### Search-rotation CLI

**IMPLEMENTED, bounded source and installed verification:** prefix the same seven payload actions with
`keys rotate search`. Use exact `SearchPlanningContext`, `SearchApplyContext`,
`SearchStatusContext`, `SearchSealingContext`, `SearchSwitchContext`,
`SearchActivationContext` and `SearchAbortContext` types. Each requires the same
fields as its corresponding Payload context. Planning requires explicit restore
and four measurements. Sealing requires both copy measurements. Status is key-free,
activation has only target keys, and abort has only source keys/source ACTIVE pin.

P uses search-rotation/v1 or v2. A has kind `search_rotation`, transition/v4 or v7.
Validate `search_rotation_plan_digest`, reserved A UUID and artifact kind before host
loading. Keep P/A pins distinct. First switch uses both custody resolvers. Its
PENDING retry accepts both arguments but invokes only target custody after reciprocal
proof. Publication is target-only. Cancellation is source-only and refuses after switch.
Shared payload seal, durability and external artifact-retention rules apply unchanged.
Search rotation changes searchable CF1 nonces/terms while retaining exact payload
custody and storage-only CF1 bytes. No new core or cryptographic construction follows. The
[payload context table](#payload-rotation-cli) supplies the shared field contract.
See the [verified checkpoint](../status.md#operational-cli-search-rotation-2026-10-24).
Source and installed genuine adopted-target verification pass.

### Initialization CLI

**IMPLEMENTED, bounded source and installed verification:** `init --host-context MODULE:FACTORY --out DECLARATION`
accepts an exact frozen, repr-disabled `InitializationContext` with required
`engine`, `mapping`, `declaration: bytes`, `writers` and `search_reviews` fields.
Use the existing fresh owned PostgreSQL/psycopg engine with safe logging and disposal.
Reject an existing output or symlink before host loading.

Apply the existing byte bound and strict parser before canonicalization. Reuse
`doctor.preflight` with no keys or application-row inspection. Publish canonical bytes
only after manifest_schema PASS. Use exclusive private publication with file/parent
fsync. Report SHA-256 of the exact saved canonical bytes.

Successful scope is `initialization`, with status UNKNOWN and the unchanged embedded
`doctor/v1` report with scope `pre_adoption`. Six unobserved checks and aggregate status remain UNKNOWN.
The artifact result has no transition phase or operation UUID. Compiler inspection
effects are NONE, while host-code effects remain UNKNOWN. No planning, key or
deployment authority follows. Doctor's strict key-free tuple remains unchanged. See the
[verified checkpoint](../status.md#operational-cli-initialization-2026-10-24).
Source and installed initialization verification pass.

### Public key-policy status metadata

**IMPLEMENTED, bounded source and installed verification:** optional `status --key-policy-context
MODULE:FACTORY` accepts exact KeyPolicyStatusContext(operation_id, plan_digest,
policies). Admit protection/activation or reverse artifacts. Refuse preparation P
before host loading. Require exact native policy values, matching domain and the
complete pinned tenant-policy digest set. Bound metadata to 64 policies, 32
wrappers per policy and 16 MiB aggregate sealed bytes. Existing policy canonical
bytes and wrapper order remain unchanged.

Report public identities, selected generations and wrapper SHA-256 values. Emit
no wrapper bytes or keys. DIGEST_MATCH proves local agreement only. Host authority,
provider availability, material correctness, completeness and recovery remain
unqualified. Doctor, retained contexts and no-option status preserve their contracts.
See the [checkpoint](../status.md#pinned-public-key-policy-status-2026-10-24).

### Retained-backup status metadata

**IMPLEMENTED, bounded source and installed verification:** optional `status --host-context MODULE:FACTORY`
accepts exact frozen `RetainedObligationsContext(operation_id, plan_digest, records)` and
`RetainedBackupObligation(backup_id, source_plan, dump_sha256, reader_sha256, drill_sha256)`.
Admit exact source/predecessor lineage and restore bindings before database access.
Limit records to 64 and aggregate source bytes to 16 MiB. Reader/drill references
can be None. Contexts have no keys. Doctor and omitted-context status remain unchanged. See the
[source checkpoint](../status.md#declared-retained-backup-status-references-2026-10-24).
The [integrated checkpoint](../status.md#integrated-defensive-hardening-2026-10-24)
includes genuine fresh-cluster metadata controls. Declared references do not prove
file availability or recovery.

### Original HTTP operational qualification

**VERIFIED, bounded source and installed qualification:** join existing CLI workflows to the original
26-file HTTP/JWT/local-SMTP workload. Preserve all pinned source bytes. Use only the
existing `get_db` override and reload its full dependency/router graph after successors.
Run retained-user HTTP/password/inactive/Item-cascade controls after publication. Finish requests,
background mail and fixture SMTP work before maintenance. Reuse the existing five
process-recovery checkpoints. Product and helper bytes remain unchanged in this test-only join. See the
[qualification checkpoint](../status.md#original-http-operational-cli-journey-2026-10-24).

## Exact data paths

```text
Write: ordinary attributes → app-assigned row identity + tenant context
       → typed value validation/encoding → local admitted keys
       → randomized authenticated payload + declared equality term
       → atomic INSERT/UPDATE without protected plaintext binds
       → normal PostgreSQL transaction outcome

Read: entity/scalar SELECT → payload + expected row/tenant context
      → exact-generation local key → bounded framing/authentication
      → typed decode + required term recomputation → ordinary Python value

Search: admitted SQLAlchemy expression → typed deferred binds
        → tenant/domain-bound equality terms → native indexed predicate
        → ordinary authenticated read
```

Database functions never receive keys or decrypt values. Projection functions transport public expected context only.
Missing keys, unknown operators, context mismatch, and invalid authentication raise typed errors.
Implicit candidate filtering, refill, full-table decryption, and plaintext query fallback are forbidden.
Authentication precedes release of each value. Already returned authenticated values remain application-owned if another row fails.
No whole-result publication, hostile-database completeness, or freshness guarantee follows from payload authentication.

## SQLAlchemy integration

Attach once, before model instances, sessions, or compiled statements exist. Replace the existing session factory once.
The attached factory accepts authenticated tenant scope and prepares keys once per operation.
Preserve native mappers, identity maps, history, Result, refresh, expiry, merge, autoflush, and exact application value types.
Use public custom-type, comparator, projection, inspection, Session-event, and expression/compiler hooks.

A scalar type processor lacks sufficient row context and cannot fetch remote keys safely inside synchronous async-result hooks.
Prepare row-bound frames before flush. Substitute prepared values through public execution hooks while attributes retain ordinary Python values.
The application supplies a stable identity before encryption. Never insert protected plaintext to obtain an ID or preallocate a server-generated key.
A late unprepared protected value must fail before SQL. Failed flush/rollback clears preparation.
No row-to-parameter association may depend on an unqualified batch-order assumption.

The bounded dictionary INSERT route uses `Session.execute(insert(Model), rows)`
through the attached sync or async session. Every row supplies its typed stable
identity and declared tenant. Prepare a separate authenticated frame for each
supplied protected value, including repeated dictionary references. Copy caller
dictionaries and retain native ORM grouping, NULL omission, autoflush and errors.
At final driver dispatch, match the actual SQL, identity, tenant and ciphertext
against the admitted batch. Compiled parameters alone do not establish what the
driver receives.

RETURNING admits direct mapped-column tuples/scalars, public-only columns and
the inserted mapped entity. Native results keep grouping, page handling and
optional parameter ordering. Entity loading retains the native identity map,
expiration and refresh behavior. Each protected output must match its own tenant,
real input identity and exact
prepared frame or NULL. Immutable expectations come from that native group.
They survive operation cleanup without retaining the operation or session.

Mapped dictionary UPDATE reuses the prepared-input ledger. Tenant-column tables
require one explicit tenant equality. Explicitly single-tenant tables instead
use bare `update(Model)` with session scope equal to the declared table UUID.
Native primary-key predicates and row-count failures remain in force; no
synthetic predicate disables missing-record detection. Both routes require
typed record IDs and `synchronize_session=False`, with no RETURNING.

The dialect's native page generator supplies SQL and processed parameters.
Validate full processed input first, then each page's rows against the original
frozen slice. An exact one-shot page snapshot precedes cursor callbacks and
final dispatch. Reuse native result processing and sentinel ordering.
The private page hook needs evidence for each selected SQLAlchemy cell.
Labels, expressions, aliases, loader options, caller return_defaults, embedded
statement values, Core INSERT, upsert and INSERT SELECT remain unadmitted.

Stock SQLAlchemy SAVEPOINT, ROLLBACK TO and RELEASE clauses need no data permit.
Accept only their exact native compilation with empty parameters and unchanged
attachment configuration. This adds no raw SQL or protected-write authority.
Keep native transaction objects and cleanup behavior.

The driver guard captures native SQL and processed parameters at the first
cursor event, then consumes that capture at driver dispatch. Freeze binary
buffers, ordinary containers and typed primitive/identity values. This includes
each native insertmanyvalues page, without reimplementing its SQL or row order.
Require one capture callback, first in the effective Connection dispatch.
Require one matching raw-dispatch completion before native post-execution and
ORM success. A dialect callback that skips the guard must fail explicitly.
Refuse preexisting engine cursor listeners before connection and effective
Connection listeners before attachment validation. Register engine-instance
observers after attachment. Class/connection cursor listeners and changes to
captured SQL or values remain unadmitted. No callback receives a driver permit.
Unknown unprotected native adapters retain their original object identity.
Their mutable internal state is not part of this snapshot guarantee.

Async preparation awaits provider work outside synchronous events. Type/result processors use local admitted material only.
Sync sessions use synchronous provider APIs. Ordinary SQLAlchemy restrictions on async implicit I/O still apply.
Detached authenticated values remain ordinary application values, without a revocable plaintext wrapper.

Entity/scalar projections carry expected typed row identity and tenant context with the payload.
Requested point identity and host tenant scope must agree with returned context. Ciphertext headers cannot select provider authority.
Aliases, outer-join NULL sides, relationships through unprotected keys, column tuples, cache behavior, and parameter shapes need differential tests.
A changed tenant requires authorization, new context, and resealing. Stable record identity remains immutable while protected.
The compiler freezes exact context encodings for each admitted app-assigned ID mapping before vectors and integration tests.

Comparators rewrite only the admitted grammar. Public expression traversal rejects unadmitted operators, nested clauses, functions, and protected DISTINCT.
Textual `ORDER BY`, `GROUP BY`, `DISTINCT ON`, window, and ordered-aggregate names resolve against native name spaces before the driver; a protected candidate refuses.
Do not substitute string matching against arbitrary SQL for expression admission.
Bulk writes need complete row identity, tenant context, and companions. Opaque SQL/COPY and raw protocol paths must reject within guarded attachment routes.
Separate drivers remain writer-inventory gaps. Unsupported or unknown writers block protection unless the deployment excludes them.
Shape constraints cannot prove encryption to a database without keys. Full verification detects observed authentication failures, not every privileged bypass.

### Implemented storage attachment

**IMPLEMENTED, bounded prototype:** `cryptalis.sqlalchemy.attach(registry, engine, lock=lock_bytes, keys=keyrings)`.
`keyrings` is a `Keyring` or a callable that resolves one from the authenticated tenant UUID.
Attachment returns a factory called as `sessions(tenant_id=tenant_uuid)`. Await attachment for an AsyncEngine.
The compiler lock must be trusted by the host. Physical protected columns must already be `bytea`.
This call does not perform a schema/data transition. Attach before application sessions or model use.
The optional `cryptalis.sqlmodel.attach` uses the same arguments for synchronous
and asynchronous PostgreSQL sessions on SQLModel 0.0.48. Await attachment for an
AsyncEngine. It reuses native `Session.exec` result shaping; async `exec` first
passes the shared async admission and key preparation boundary. It
normalizes only the checked exact AutoString mapping to native String.
The [compatibility contract](../compatibility.md#optional-sqlmodel-bridge)
defines its refusals. The [checkpoint](../status.md#optional-sqlmodel-template-checkpoint-2026-10-23)
owns its bounded runtime and application evidence.

The engine must use PostgreSQL/psycopg, `echo=False`, and `hide_parameters=True`. Attachment refuses unsafe logging settings before it opens a connection or resolves a key, and it requires no checked-out connections at activation.
Ordinary ORM flush writes, mapped dictionary INSERT with native scalar/tuple/entity
RETURNING, direct
projections and declared equality/IN are implemented. Simple negative equality,
`NOT IN`, and NULL presence are admitted with native truth. Core writes, other
bulk routes and unadmitted grammar reject.
Mapped text attributes remain ordinary `str` or NULL. Generated projections carry row and tenant context for authentication.
Protected projections and predicates disable compilation caching because their processors retain prepared material and operation context.
Unprotected projections retain native caching. Guards reject public raw-driver, opaque SQL, COPY, and unprepared-write routes.
**VERIFIED:** native/attached comparisons and cache regression sensitivity have the exact boundary in the
[slice 3 checkpoint](../status.md#slice-3-checkpoint-2026-10-08).
Separate non-owning runtime CRUD and tested persistent DDL/ownership denials have local PostgreSQL evidence.
These grants do not enforce attachment use by separate writers. Deployment enforcement remains unverified; all seven full gates remain UNKNOWN.

**IMPLEMENTED, slice 4:** equality uses the CF1 frame's full HMAC-SHA-256 term through a built-in expression index.
Attachment validates the exact tenant key, bytea operator class, index validity/uniqueness and public framing CHECK.
Query binds become terms per operation; tenant predicates scope each declared comparison. NULL/empty-IN retain native truth.
The native unique index arbitrates races. Payload and term occupy one frame, so a write cannot update them separately.
Host search-domain review and leakage acceptance remain required. Search roots/generations cannot change within an attachment.
Fresh attachments still depend on the correct trusted host policy. Deployment binding and reindex transitions remain slice 5/7 work.
The [slice 4 checkpoint](../status.md#slice-4-checkpoint-2026-10-08) defines executable evidence and limitations.

**IMPLEMENTED, spike only:** the [2026-10-07 checkpoint](../status.md#current-integrated-checkpoint-2026-10-07) uses public hooks on one text field.
It preallocates server-generated int32 sequence IDs. That historical behavior conflicts with the approved app-assigned-key contract and supplies no product admission.
The latest DISTINCT denial has offline evidence only. Neither the historical service receipts nor performance measurements qualify that revision.

## Manifest

The public manifest uses bounded JSON. Its field-intent declaration is independent of existing structural research-header schemas.

| Member or fact | Rule |
|---|---|
| `schema` | `cryptalis.protection/v1` for implemented field intent |
| `profile` | Selected library crypto profile. No arbitrary algorithms or executable normalizers |
| `models`, `fields` | Names resolve within the supplied registry. No imports from strings. Unlisted fields retain native behavior |
| `protect` | True requests protection. Removal requests a verified transition, never automatic plaintext writes |
| `queries` | Empty means storage-only. `equality` includes `IN`. `unique` implies tenant-scoped equality |
| `accept_leakage` | Required matching acceptance for every search capability. Missing acceptance blocks plan |
| `tenancy` | Exactly `{"column": "attribute_name"}` or `{"single_tenant": true}` per protected table |
| Mapping facts | Text codec, deterministic exact collation, nullability, application-assigned PK, tenant scope, constraint scope, and writer inventory |

Range bounds, prefix limits, shared-join domains and arbitrary normalizers remain unadmitted.
Boolean, signed integer, finite Date and UUID storage use pinned value codecs.
Their search operators remain unadmitted.
The compiler rejects unsupported types, server-generated keys, small-domain searchable fields, missing tenant scope, and unsupported writers at plan time.
Searchable small domains remain unsafe because enumeration can label their equality classes. No invented cardinality threshold supplies evidence.
The planner does not infer every application query. Attached staging tests expose query-level incompatibilities.

The generated public lock records stable domain/field/representation identities, original schema, codecs, DDL, and reader dependencies.
Renames preserve stable identities. Removal and re-addition creates new identities unless an authorized mapping proves continuity.
Unrelated manifest edits do not alter payload AAD. The compiler must not silently remove a constraint or change equivalence.

A deployment-controlled artifact outside database restore pins active lock, target, admitted formats/generations, and wrapped-root identities.
Existing deployment integrity controls authenticate it. Manifest and policy contain no secret key bytes.
A database checkpoint cannot activate a manifest. Startup rejects disagreement among policy, lock, target, and representation.
G-POLICY remains UNKNOWN. No trusted publication/restore procedure is selected.

### Implemented compiler syntax

**IMPLEMENTED:** `cryptalis.manifest.compiler.compile_protection` uses the declaration below.
[Status](../status.md#slice-1-checkpoint-2026-10-08) owns its tested cell and limits.
The compiler accepts bounded UTF-8 JSON with no duplicate or unknown members.
Domain, table, and field IDs are distinct, nonzero canonical UUIDs. Names resolve only in the supplied registry.
The compiler never imports a module from a name.

```json
{
  "schema": "cryptalis.protection/v1",
  "profile": "cf1",
  "domain_id": "10000000-0000-0000-0000-000000000001",
  "models": [{
    "model": "Customer",
    "table_id": "20000000-0000-0000-0000-000000000001",
    "tenancy": {"column": "tenant_id"},
    "fields": [{
      "name": "email",
      "field_id": "30000000-0000-0000-0000-000000000001",
      "protect": true,
      "queries": ["unique"],
      "accept_leakage": ["equality", "unique"]
    }]
  }]
}
```

Queries permit `equality` and `unique`. An empty list means storage-only. Equality also declares `IN`.
Unique implies equality and requires both leakage acknowledgments. `protect` must be true.
Removal uses a semantic diff and a later verified transition.

Without owned sequences, text-only plans emit `cryptalis.lock/v2`. Plans with native VARCHAR emit `cryptalis.lock/v3`
and require `pg-varchar/v1`. A plan with Boolean storage emits `cryptalis.lock/v4`
and requires `boolean-u8/v1`. Mixed fields retain each required reader.
Plans with admitted owned sequences emit `cryptalis.lock/v5`. Other plans retain
their existing format selection and bytes. The explicit public-slot layout emits
`cryptalis.lock/v6`. The internal integer candidate emits `cryptalis.lock/v7`
and requires its exact pg-int2/int4/int8-be/v1 codec readers. Current readers
accept v1 through v7; old readers refuse v7 before effects.
Older operational readers refuse the embedded v5 lock before effects.
The [VARCHAR decision](../decisions.md#native-varchar-text-admission-2026-10-22) defines assignment and reader boundaries.
Its exact top-level members are
`schema`, `profile`, `domain_id`, `database`, `declaration`, `models`, `writer_inventory`, `search_reviews`, `ddl`, and `required_readers`.
V6 adds `layout: "preserve-public-slots/v1"`. V7 always includes layout as
NULL or that selector and always includes source_metadata.owned_sequences.
For earlier formats, public `layout=None` keeps
the earlier selector. A previous lock does not select a layout implicitly.
The declaration is canonical. Models contain `model`, `table_id`, `schema`, `table`, `record`, `tenancy`, `fields`, `source_schema`, and `source_metadata`.
Fields contain `name`, `column`, `field_id`, `queries`, `representation`, `payload_column`, `unique_indexes`, `original`, `source`, `descriptor`, and `descriptor_digest`.
Boolean fields also contain `application_default`: absent-default NULL or a literal Boolean.
The internal integer candidate includes that member only for a literal client
default. Its value is a canonical signed decimal string; pg-integer-default/v1
is then required. Default-free v7 fields retain their existing bytes and readers.
The [installed checkpoint](../status.md#integer-literal-default-installed-checkpoint-2026-10-24)
owns the exact default and native ORM-state checks.
The compiler and attachment compare this fact with the current native mapping.
Server, callable and on-update protected defaults remain refused.

The source schema stores inspected relation, column, constraint, index, and dependency facts.
`source_metadata` stores protected-column attributes (comment, statistics target,
storage, compression, options, ACL entries), constraint and index comments, and extended
statistics rebuilt from captured fields. The protection switch applies captured column
grants to the ciphertext column; reverse restores them. Statistics targets use strings because the
manifest integer grammar is non-negative and bounded.
V5 and v6 add `owned_sequences` to every model's source metadata, including empty inventories.
It records stable identity, owner, native configuration, effective ACL and dependency facts.
Atomic ownership transfer preserves the same sequence object through either column switch.
Restore/v2 binds new restored OIDs after exact logical comparison. No cryptographic
value format changes. The [lifecycle contract](../lifecycle.md#owned-sequence-preservation-and-restored-identity-2026-10-24)
and [status](../status.md#owned-sequence-preservation-and-restore-2026-10-24) define the verification boundary.
The revised query passes source and installed controls. Both fresh-target profiles
pass complete OID mapping, direct generation and repeated adoption. The full
source regression also passes at that checkpoint. The public-slot extension below
has a separate verification boundary. Retained-native preservation remains open.

The opt-in v6 layout converts original public attributes with ALTER TYPE USING
verified staged values. Public CF1 CHECKs and equality indexes precede shadow
removal. Reverse converts the same attributes and restores captured native metadata.
Sequences remain owned by the same attributes. Heap and index storage rewrites
remain outside host-supplied row-rate/WAL estimates. Restore/v3 binds complete ordered
source/target slots for every public column, plus a mandatory sequence map.
Flat lineage composes these maps without changing legacy comparison or source authority.
See the [lifecycle contract](../lifecycle.md#public-column-slot-layout-2026-10-24)
and [bounded verification](../status.md#public-column-slot-preservation-2026-10-24).
Catalog type modifiers use strings because PostgreSQL uses negative sentinels.
Unrelated SQL definitions use SHA-256 fingerprints of their canonical JSON string values.
Original admitted unique constraints and indexes retain their exact definitions for later restoration.
The lock contains no database connection string or row values. Boolean client defaults are policy facts.
`ddl.expand` contains additive proposals. `ddl.requires_before_switch` names prerequisites that remain unimplemented.
Reader requirements describe the intended readers. They do not claim those readers exist.

The record codec is `uuid16/v1` or `int64-be/v1`. UUID context uses 16 exact bytes.
Bigint context uses `T` with the `int64` tag and eight signed big-endian bytes, as [security](../security.md#cryptographic-format) specifies.
Single-tenant context uses the stable table UUID. The text codec is `utf8-exact/v1`.
The normalizer is `identity/v1`. The null policy is `sql-null/v1`. Composed and decomposed text remain distinct.

Descriptor digests exclude SQL names. They bind the domain, table, field, record codec, tenant codec, text codec, normalizer, null policy, and representation.
The representation is `cf1-storage/v1` or `cf1-packed-equality/v1`. The descriptor schema is `cryptalis.context/v1`.
Boolean storage uses `cryptalis.context/v2` with `value_codec: boolean-u8/v1`
instead of `text_codec`. False encodes as byte 00. True encodes as byte 01.
The descriptor digest binds the value type in the shared authenticated path.
SQL NULL stays SQL NULL. Boolean equality terms remain unadmitted.
Signed integer storage also uses context/v2. Its pinned codecs encode int2/int4/int8
as 2/4/8 signed big-endian bytes. Finite Date stores a four-byte unsigned Gregorian
ordinal under `date-ordinal-u32/v1` and lock/v8. UUID values store sixteen
network-order bytes under `uuid-bytes16/v1` and lock/v9. Nil UUID values are valid;
the public record and tenant UUID codecs keep their separate context role.
All other CF1 authenticated context and nonce rules remain unchanged. The
[local scalar checkpoints](../status.md#native-uuid-value-storage-2026-10-28)
retain their source, artifact and cost boundaries.
For equality, the stable field UUID identifies the search domain. Crypto implementation and independent vectors belong to slice 2.

`WriterInventory` requires `complete=True` and a nonempty inventory for each protected table.
Writer records name a table UUID, a distinct writer name, a route, an exclusion flag, and a nonsecret evidence reference.
Only `sqlalchemy` routes can remain admitted. `raw_sql`, `copy`, and `external` routes require exclusion. Unknown routes always reject.
`SearchReview` names a searchable field UUID, a small-domain classification, and a nonsecret evidence reference.
These declarations do not prove enforcement.

`PlanningRejected` gives typed issues, remedies, an operation ID, stage, retry classification, and effects `NONE`.
`InspectionUnavailable` gives a safe SQLSTATE and a remedy. Raw driver text and SQL binds do not enter these error messages.
A previous lock must match its declaration, native facts, context descriptors, originals, DDL, and reader requirements before diff.
A lock hash detects change. It does not authenticate deployment authority.

## Physical storage

Storage-only text receives randomized `bytea` payloads. Equality adds one full HMAC-SHA-256 term.
The slice 4 product packs the term in the payload with an expression index.
Separate/generated terms are compiler output for admitted tenant-scoped constraints, not another integration mode.
No custom extension, type, or operator class is required.
Payload and companion commit in the same transaction. Search roots remain independent of payload roots.
Payload rotation need not reindex. Search-key changes require complete reindex and authenticated-header resealing with fresh nonces.
An internal candidate-preparation API resolves, rewraps, and verifies every admitted root without publishing a policy.
The bounded root-rewrap executor records an immutable transition/v2 successor through
the shared maintenance and activation machinery. Adopted targets use transition/v5
with flat restore lineage. Host publication remains separate.
A separate internal batch API reseals current frames between payload generations and preserves search headers.
Read-only payload planning produces preparation proposal P. It pins exact retained custody, source observations,
aggregate logical batch limits and measured costs. It reserves distinct preparation
and successor identities. Payload preparation also has bounded apply, status,
and abort APIs. The shared maintenance executor stages ciphertext and commits
chunk progress under P's separate operation identity. During preparation, source
frames and journal remain unchanged. Resume authenticates committed ciphertext.
BACKFILLED retries repeat full source and target authentication. Keyless status
reports `NOT_PERFORMED`. Cancellation uses the republished source ACTIVE pin
and needs no target custody. The logical byte budget spans all fields in each
batch and is not a process memory bound.

`seal_payload_rotation` authenticates BACKFILLED shadows and returns deterministic
activation artifact A from their actual ciphertext observations. A is a
`cryptalis.transition/v3` MigrationPlan with `kind: payload_rotation`; inherited
restore lineage uses transition/v6. It binds
P's digest, source-to-P ancestry, target observations, logical limits, and
measured terminal copy costs. P reserves A's ID but does not embed A's digest.
Sealing holds maintenance locks and changes no database data, schema, or journal.
Provider audit/cost effects remain possible. Persist A outside the database
before cutover.

`switch_payload_rotation` repeats paired proof and updates the existing public
columns from their shadows. Column identities, indexes, constraints, grants,
and metadata remain intact. Source-to-P-to-A supersession and guard exchange
commit with a fresh target check. This terminal full-table write uses one
transaction, beyond the bounded preparation chunks. A estimates its copy plus
five authentication passes. Recorded copy time and cluster-wide WAL deltas are
diagnostic observations, not isolated costs, capacity bounds, or host authority.

A PENDING retry authenticates only current target frames against A because
original source frames no longer exist. P resume and cancellation refuse
SUPERSEDED. Shared `migration.apply` requires ACTIVATING or ACTIVE authority
for A. ACTIVATING repeats target proof even if the journal claims ACTIVE.
A genuine ACTIVE pin permits later edits and latest-value removal. Keyless
status remains `NOT_PERFORMED`. Search rotation uses the same staging and
publication engines, with separate policy and frame checks. Its preparation
artifact uses `cryptalis.search-rotation/v1`; activation uses
`cryptalis.transition/v4`; inherited restore lineage uses transition/v7.
It retains source roots, selects one new search generation, preserves payload
selection, and replaces terms under fresh
authenticated nonces. Native UPDATE maintains equality/unique indexes atomically.
Storage-only frames remain exact. Generation rotation on an adopted target can
start from its published lineage-bearing successor and its own ACTIVE pin.
Alternatively, both planners accept the original source ACTIVE pin and an explicit
restore binding. This direct route embeds the binding in the purpose-specific
preparation/v2 artifact. It retains the original source artifact and emits
transition/v6 or v7 with the actual target and ordered restore lineage.
With no explicit binding, preparation/v1 remains byte-compatible.
The [current status](../status.md#direct-restore-binding-generation-planning-2026-10-24)
records the exact verification boundary. All seven full gates remain UNKNOWN.
See [lifecycle](../lifecycle.md#changes-and-rotation) for recovery and publication boundaries.
[Security](../security.md#cryptographic-format) owns framing, commitments, keys, and failure rules.
Generic CHECK/FK/default/collation preservation across other schema transforms
remains UNKNOWN. [Lifecycle](../lifecycle.md) states the verifier's actual checks.

## Public surface

The table defines the **SPECIFIED** final command surface.
A bounded `status` command reports protection, payload/search preparation, and
reverse progress and metadata. Preparation status uses the existing typed P
status APIs and never supplies application publication authority.
A bounded `doctor` checks either a pre-adoption manifest/schema or an existing
ACTIVE deployment. Pre-adoption mode uses the same compiler and an explicit
trusted host factory; host-code effects remain UNKNOWN. ACTIVE mode uses the
declared runtime connection and repeats shared attachment admission in a
read-only snapshot. Unobserved boundaries and aggregate results remain UNKNOWN.
Doctor can also inspect supplied SELECT structures through the same runtime
admission rules. Python callers pass queries=select_samples. CLI hosts can add
select_samples as a fourth context member. Use a tuple of at most 128 samples.
No attachment, query execution, mapping-type replacement or key resolution occurs.
Successful samples report STRUCTURE_ADMITTED. Complete route coverage and aggregate
health stay UNKNOWN. Known unsupported samples produce a FAIL with safe indexes
and remedies. This check supplies no deployment or migration authority. See the
[installed checkpoint](../status.md#installed-application-query-diagnostics-2026-10-24).

The initial `plan` and protection `apply` commands have the bounded
[operational contract](#operational-protection-cli). The
[reverse/removal extension](#reverse-and-removal-cli) and
[root-rewrap CLI](#root-rewrap-cli) have bounded source, installed and genuine
fresh-target evidence. The [payload CLI](#payload-rotation-cli) has bounded source
and installed verification. Its source and installed genuine adopted-target checks pass.
The [initialization CLI](#initialization-cli) has bounded source and installed verification.
Its source and installed verification pass.
The [search CLI](#search-rotation-cli) has bounded
source and installed verification. Its source and installed genuine adopted-target checks pass.
Full status coverage of keys and retained obligations
remains SPECIFIED. The migration walkthrough defines the implemented subset.
See [committed progress](../walkthrough-migration.md#inspect-committed-progress).

| Command | Purpose |
|---|---|
| `cryptalis init` | Create declaration and inspect configuration |
| `cryptalis plan` | Report incompatibilities, semantic diff, DDL, leakage, writers, estimates, and approvals. Refuse any incompatibility |
| `cryptalis apply PLAN` | Run or resume the verified transition |
| `cryptalis status` | Show representation, progress, failures, keys, and retained obligations |
| `cryptalis doctor` | Inspect pre-adoption schema or ACTIVE runtime admission; report unobserved boundaries as UNKNOWN |
| `cryptalis rollback` | Transform current data to the previous compatible representation |
| `cryptalis keys rotate` | Select rewrap, payload rotation, or search reindex through the same executor |
| `cryptalis remove` | Decrypt-back, verify, test package-free operation, retire eligible generated objects |

`apply --resume OPERATION` reinspects the original durable plan. `apply --abort OPERATION` removes only owned shadows before switch.
After switch, rollback transforms current values. Status reports ambiguous effects and the concrete observation needed before retry.
No new command or mode is required for staging adoption or finalization.
Recovery stays available through decrypt-back until explicit finalization retires necessary readers/keys under the existing lifecycle.

## Minimum host contract

Supply the selected stack, text mappings, app-assigned stable PKs, explicit tenancy, and one inspected attached session factory.
Inventory handlers, jobs, scripts, Core/bulk statements, and separate drivers. Replace opaque protected raw writers with typed statements.
Supply external provider configuration, deployment policy, maintenance exclusion, and retained recovery ownership.
No production provider is designated. The local provider is functional evidence only.

Use the [recommended adoption path](../../README.md#intended-adoption): manifest, plan, attached staging application suite, qualified production apply, decrypt-back exit.
It does not guarantee zero changes. Every required workflow must pass its native-result oracle or block protection of the affected field.
Count actual application and deployment edits. An example attach call is not a measured retrofit.
