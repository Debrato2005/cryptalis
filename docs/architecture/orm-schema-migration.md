# ORM, Query, Schema and Migration Contracts

Status: Canonical design contract. Pre-implementation. No supported runtime profile

Evidence reviewed: 2026-09-30

This document owns detailed SQLAlchemy mapping and query contracts, physical schema, Alembic and
existing-data migration. Cross-system authority, stable identity, manifest serialization, crypto,
lifecycle and evidence policy remain in the [architecture owner](README.md) and [manifest/context
API contract](manifest-context-api.md). The [platform evidence
ledger](../research/orm-platform-evidence.md) owns dated upstream observations. Proposed interfaces
and thresholds below are requirements for future manually typed implementation, not implemented
behavior.

## Boundaries and artifacts

The adapter consumes a verified manifest, immutable authorized operation context, installed mapping
profile and current schema/migration checkpoint. It produces physical writes, validated query plans,
logical decoded values and redacted evidence. It never attests authority from request values or
connection state. Stable logical asset and record IDs bind crypto.

The adapter does not independently add physical table or column renames, or the current whole-manifest digest, to additional authenticated data (AAD). A record-binding change needs an explicit authorized re-encryption migration.
Ordinary manifest changes preserve the original recorded binding.

Each artifact carries its own format version, originating manifest digest and producer version.
Families are `MappingPlan/v1`, `QueryIR/v1`, `QueryPlan/v1`, `PhysicalSchemaPlan/v1`,
`SchemaSnapshot/v1`, `MigrationPlan/v1`, `MigrationCheckpoint/v1` and `CompatibilityCell/v1`.
Unknown major formats or required fields fail closed. Extension handling follows the shared
contract.

New semantic meaning requires a version change even if shape remains identical. Plans are
deterministic for declared inputs and hash-addressed. Persistent hashes exclude runtime secret
values.

| Proposed boundary | Inputs | Outputs and conditions |
|---|---|---|
| `compile_mapping` | Manifest, inspected mapper metadata, compatibility cell | MappingPlan and rejected constructs. No I/O |
| `adapt_query` | SQLAlchemy expression/parameters, MappingPlan, operation context, migration epoch | QueryIR and QueryPlan with typed binds. No provider calls under warm profile |
| `prepare_flush` | Session new/dirty/deleted rows, MappingPlan, operation context, warmed handles | Complete physical row updates and state invalidation actions. No commit |
| `decode_field` | Envelope, original binding, codec ID/version, access authorization | Declared Python value or controlled value. No unauthenticated output |
| Public `compile_schema(manifest, metadata, snapshot, catalogue)` | Exact shared API inputs. Compiler/version drawn from verified catalogue | SchemaPlan/findings. PhysicalSchemaPlan/v1 is its versioned DTO alias. No DDL/key access |
| Public `plan_migration(source, target, snapshots, writers)` | Exact shared API inputs. Budgets/recovery policy bound by source/target manifests and inspected inventory | MigrationPlan and blocking findings. No DDL/data motion |
| Internal `compile_physical_diff` | Source/target compiled plans, catalog snapshot, compiler version | Ordered physical operations with preconditions, locks and fingerprints. Called by public compiler/planner |
| Internal `assemble_migration_plan` | Reviewed schema diff, reader/writer inventory, declared budgets/recovery limits | Versioned MigrationPlan. Cannot replace public input validation |
| `step_migration` | Plan ID, phase revision, migration grant, lease/fence, evidence | CAS checkpoint transition plus DDL/chunk journal. Never implicit contract |

These names describe boundaries, not shipped APIs. Shared errors/configuration must be registered
through the [manifest/context contract](manifest-context-api.md), rather than a second hierarchy.

## Mapping and instance state

A MappingPlan records stable model and field IDs, mapper identity, Python and SQL types, and codec
and normalization versions. It also records the logical descriptor and comparator, hidden
ciphertext, index and version attributes, null and constraint policy, and immutable binding source.
It records admitted operations and loaders. The logical plaintext attribute cannot remain
independently mapped to a persistent plaintext column after protection is active.

Migration source columns exist only in the named compatibility window.

The first candidate uses an immutable scalar `str` or `bytes`, one ordinary declarative mapper and a
client-established immutable record ID. It admits instance insert, update and delete, full-entity
select, explicit refresh, and declared equality, IN and null predicates. Every component is a
separate fixture cell. Implicit async lazy/deferred loading, inheritance, dataclasses, composites,
synonyms, hybrids, server-generated binding IDs and mutable containers do not follow from this
candidate.

Logical and physical state remain distinct. The setter validates type and size. It uses public
mapped instrumentation to record a logical mutation. Ciphertext never replaces the public value.

The prototype must prove that public APIs mark descriptor changes dirty without mapping a plaintext
storage column. Requiring `AttributeImpl`, `ClassManager` or comparable private machinery triggers
review. An explicit repository or controlled value is the comparison. A descriptor alone is not ORM
history support.

`before_flush` validates authority, identity, codec, fence, warmed handle and terms for all affected
protected rows before it prepares protected DML. It derives all physical values from one logical
revision and stages them together. Delete requires ownership authorization and fixtures for
companions and cascades. Database deletion alone implies no key destruction. A missing binding ID
fails before row SQL.

Inserting plaintext and then encrypting after getting a server ID is forbidden.

Physical and logical revisions agree. Repeated flush without logical change does not regenerate
ciphertext/indexes. A retry after rollback may regenerate randomized ciphertext, but cannot reuse
stale tokens or call staged output committed. A failing flush requires normal Session rollback and
cannot partially commit a protected row.

Logical cache identity includes instance identity, physical revision, original binding and access
epoch. The following invalidation semantics are mandatory candidates, tested under G-ORM-1. A clear
removes adapter references and blocks logical access. It makes no Python-memory zeroization claim.

| Boundary | Required cache/state transition |
|---|---|
| Initial load | Start with no logical cache. Publish decoded state only after authentication, binding and query verification. Index a fresh cache by physical revision and access epoch |
| Refresh of selected fields | Clear selected logical values and staged terms before replacing physical state. Discard their unflushed assignments consistently with the declared SQLAlchemy refresh semantics. Decode anew under current authority |
| Expire of selected fields / expire_all | Clear selected/all logical values and staged terms, and discard the corresponding unflushed logical assignments. Mark unresolved. Access uses admitted explicit reload or rejects, never returns the old cache |
| Transaction rollback, including failed flush | Discard every staged ciphertext/term/logical mutation and clear affected decoded caches. Restore persistent state from last committed storage through authorized refresh, rather than keeping attempted values. Transient/deleted state follows tested Session rollback classification |
| Delete | Clear the instance's decoded cache, staged terms and leased handles at deletion marking. Subsequent protected attribute access rejects. Rollback requires authorized reload before logical access resumes |
| Detach/expunge/session close | Clear all adapter decoded caches, terms and handles for detached instances. Ordinary protected access rejects. Separate explicit reveal requires a fresh authorized context. Reattach/merge remains unsupported |
| Authority expiry/deny, physical revision change or binding change | Clear all affected decoded/staged values and terms and invalidate handles. No flush or logical release under the old epoch/binding. New session/operation authority and explicit authorized state reload are required |

The initial transparent publication boundary is the handoff of the complete authenticated decoded
entity or buffer by Session execute, load or refresh. Later Python property evaluations do not
define that boundary. All decoded transparent fields in that handed-off object count as released
plaintext, even if the caller reads an attribute later. Resolve the registered publication operation
only after that handoff or proven abort.

Suspension between validation and return remains pending drain. Later access to already released
fields applies the local state, grant and epoch invalidation rules above as accident and consistency
guards. This cannot establish recall or prevention of host-owned plaintext reuse. It makes no hidden
registration or provider RPC.

Fresh load, refresh, deferred decode or controlled reveal is a new managed operation. It requires
explicit preparation and admission. Unresolved fields cannot get plaintext from a cold descriptor.
Deferred access remains rejected unless its separate awaited profile passes. G-ORM-1/5 include
entity handoff suspension, cache hits after expiry or deny, refresh, and reuse of previously
released values.

These fixtures distinguish managed release from host reuse.

Previously returned Python plaintext cannot be recalled. These adapter invalidations must happen at
actual public event or instrumentation boundaries. A table does not prove that SQLAlchemy exposes
all needed hooks. A failed public-instrumentation prototype selects the explicit repository
alternative.

Detached reads require a separately authorized explicit reveal context. Ordinary descriptor access
fails. Detach/reattach, merge, pickle and foreign physical attribute assignment remain rejected
until import provenance is specified. `merge(load=False)` is not presumed safe. In-place mutation
requires its own mutable or copy-on-write adapter, or rejection.

Client defaults validate before encryption. Protected server defaults, generated columns and payload
triggers reject.

SQLAlchemy documents that `before_flush` may change session state, while `do_orm_execute` governs
ORM execution rather than unit-of-work SQL. These require distinct fixtures. [Session
events](https://docs.sqlalchemy.org/en/20/orm/session_events.html)

## Query IR and execution planning

QueryIR conservatively interprets SQLAlchemy expression trees, not arbitrary SQL strings. It records
statement class, mapper and alias occurrences, scoped stable field IDs, and operator, boolean and
subquery nodes. It also records result shape, loader strategy, parameter references and types,
capability, domain and version requirements, and tenant-scope proof or unknown. It records source
span if known and origin (`runtime_exact`, `static_candidate`, `unknown`).

Values remain in ephemeral process slots. Static discovery cannot execute this IR or attest
discovery of every application branch.

Node families are `FieldRef`, `PlainFieldRef`, `ParamRef`, `Eq`, `In`, `IsNull`, `IsNotNull`, `And`,
`Or`, `Not`, `AliasScope`, `SelectScope`, `Unsupported`. Unsupported nodes retain operator category
and unresolved dependencies. A public visitor plus explicit node adapters traverses the expression.
Unknown nodes that might contain a protected reference fail validation. Legacy Query, functions,
casts, textual columns, literals, nested SELECT/CTE, union/correlated predicates, custom compilers
and user operators each need their own cell.

Traversal alone is not semantic coverage. [Traversal
API](https://docs.sqlalchemy.org/en/20/core/visitors.html)

QueryPlan includes a logical shape hash, physical expression, domain and version set, scoped
authority binding, and ephemeral typed binds. It also includes decoding and decrypted
predicate-verification plans, cardinality limits, manifest, schema and migration fence,
classification and evidence ID. Comparators initially emit logical protected operands, not tokens
captured at import or construction. Generate terms after execution authority validation.

Construction without a session is allowed. Execution without authorized context is not.

| Logical expression | Candidate physical plan | Required semantics |
|---|---|---|
| `field == value` | Equality columns compared to locally generated versioned terms | Exact type/normalization/domain plus decrypted normalized predicate verification. Null follows explicit null rule |
| `field.in_(values)` | Expanding typed list for each admitted term generation | Maximum 1,000 logical entries and 2,000 term binds for at most two generations. No unbounded generator. Empty list false |
| `field.is_(None)` / `field == None` | Declared null representation predicate | Explicit SQL three-valued semantics |
| `field.is_not(None)` | Declared non-null presence predicate | Separate capability and null-policy fixture |
| Ordinary `AND` / `OR` | Preserve grouping/precedence | Whole statement validates. Tenant condition in one OR branch proves no global scope |
| `!=`, `NOT IN`, general `NOT`, LIKE, sort, extrema, encrypted joins/grouping, JSON/path | Reject initially | Capability-specific research and result/null semantics required |

IN containing None preserves SQL null behavior: null members do not become IS NULL or select null
rows. Only non-null entries generate terms. Empty cases, all-null cases and negation have
truth-table fixtures. Do not silently substitute Python membership semantics.

Duplicate physical terms may be coalesced only after validation of the logical-entry cap.
Dual-generation expansion cannot widen the logical cap. Database parameter ceilings may require a
lower declared per-profile cap.

Equality terms are unauthenticated candidate selectors. Before publishing any result, authenticate
every bounded candidate. Decode every bounded candidate. Recompute every required current term under
its declared domain and normalization.

Evaluate the admitted original logical predicate with its SQL three-valued and Boolean semantics.
Preserve original payload text. Compare normalized copies only. A tampered or stale stored term
raises Query.IndexInconsistent and fails the whole buffered result. An unexplained wrong-predicate
candidate also fails.

Do not publish earlier rows and then discover inconsistency. Branches whose verification needs
unavailable protected values or unsupported expression semantics reject at planning. Plain columns
retain ordinary database trust assumptions. This mechanism does not authenticate arbitrary plaintext
predicates or query completeness.

The initial profile retains the caller's SQL LIMIT/OFFSET and admitted ordering exactly. It does not
silently drop wrong-predicate candidates, refill a LIMIT, overfetch, rerun without limits, or
convert the query to a scan. A malicious database can remove terms or rows, or corrupt skipped
candidates. Thus, a successful bounded result does not prove completeness. An optional
overfetch/postfilter planner would be a distinct explicit capability.

It would need deterministic order, declared candidate and byte budgets, exhaustion errors, and
differential LIMIT/OFFSET/IN fixtures. It is not initially admitted. The explicit query wrapper may
prepare additional bounded quota and key batches between hidden-row fetch and local validation. The
same grant and operation deadlines and whole-result buffer apply.

The query wrapper budgets query terms plus recomputation for every fetched candidate. Quotas are not inferred from
the IN count alone. Exhaustion either raises Key.QuotaExhausted or uses that explicitly awaited
preparation phase before decoding the next batch. A scalar processor never replenishes remotely and
no earlier logical row is published while preparation/verification remains incomplete. QueryPlan
must bind a publication buffer of at most 10,000 candidates and 16 MiB aggregate fetched ciphertext
and companions.

QueryPlan must declare a separate decoded-memory budget. Applications may lower these caps. Overflow fails
without partial plaintext. Decoded objects stay internal until the complete bounded result verifies.

Only then can the adapter attach them to caller-visible logical state. G-ORM-2 includes swapped
terms on authentic ciphertext, stale generations, IN containing NULL, Boolean branches, and
tampering that occupies the first LIMIT slots.

Protected SELECT injects or validates authorized tenant criteria for every protected mapper, alias
and scope through a tested loader-criteria profile. Caller WHERE values are not authority. Ambiguous
aliases, joins, OR/subquery scope or uncovered protected targets fail. The adapter checks returned
rows against the selected tenant and binding before decryption.

This includes identity-map hits that emit no SQL. Point loads additionally require the shared
[requested resource binding](manifest-context-api.md#requested-resource-binding): compare
independently authorized expected record UUID, tenant/table and relational locator against the
authenticated row before release. A substituted authentic ciphertext plus all subject/key/record
metadata at the same requested PK must fail. A missing independent point-load binding rejects.
Mutable database ownership metadata cannot manufacture one. General authorized tenant-wide queries
guarantee row self-consistency and predicates.

They do not guarantee locator integrity or completeness against a hostile database. Identity-map
retrieval follows exactly the same release checks.

`do_orm_execute` validates complete statements and parameters before execution. Scalar projections
such as `select(User.email)`, RETURNING, rows lacking tenant, subject or binding companions, and
expression RHS reject initially. Full entities supply context. Hidden physical attributes require an
explicit diagnostic/migration operation.

The adapter validates execute-time substitutions like literals. It rejects raw token or ciphertext
objects as ordinary logical values that bypass transformation.

Compiled caching stores shape only. Compiler objects cannot retain context, handles, plaintext or
terms. Rebuild runtime plans and binds under current authority and fence. Cross-tenant statement
reuse has the same allowed shape and different domain-bound terms.

Literal-bind debug output is unavailable for protected values. Disabling caching is acceptable until
safe keys are demonstrated. [Custom types](https://docs.sqlalchemy.org/en/20/core/custom_types.html)

Coexistence queries OR across explicitly admitted generations. Different normalization and domains
are not interchangeable. Migration declares row and query semantics. Broadening readable versions
without checkpoint changes fails.

Dual-search OR does not prove uniqueness.

## Interception and coverage registry

CompatibilityCell records exact interpreter/build, OS, SQLAlchemy, applicable Alembic,
driver/implementation/libpq, PostgreSQL, mapping, operation, loader, sync/async profile,
manifest/compiler/envelope/codec versions, classification, fixture IDs and artifact hashes.
Candidate is not support. Transparent/reject claims require executable evidence. Absent cells are
unsupported.

Static findings never upgrade a cell.

| Path | Initial disposition | Boundary and residual limit |
|---|---|---|
| Instance flush/load and comparators | Transparent candidate | Admit after state/query/row fixtures |
| Async lazy/deferred/expired access | Reject candidate until awaited fixture passes | No implicit provider/driver I/O outside chosen boundary |
| Autoflush/commit/nested transaction | Separate transparent candidates | `begin_nested` may flush before savepoint. Reject at actual boundary |
| ORM bulk DML, legacy bulk, upsert, executemany | Reject candidates | Session wrapper and execution guards. Flush hook alone insufficient |
| Core/text through protected Session | Reject candidates | Strict profile rejects every text/unknown statement, not table-name guesses |
| Core/text through dedicated strict protected Engine | Reject candidate | Adapter-issued operation capability. Caller flags cannot authorize bypass |
| Core Connection on non-strict shared Engine | Detect unless tested guard reliably rejects | No logical row authority recovered from strings |
| Raw DBAPI cursor from registered Engine | Detect | Engine events do not promise direct-cursor interception |
| Separate engine/driver/COPY/ETL/trigger/external writer | Unobservable by adapter | External database/operator controls. No transformation claim |
| Alembic/backfill worker | Separate migration candidate | Scoped migration authority and durable protocol |

A strict engine denies unknown statement origin and is dedicated to protected traffic. Unrestricted
unprotected SQL uses a separate declared engine. Process-local capabilities mark adapter-generated
physical statements. This prevents accidental bypass in a trusted process, not arbitrary code
execution.

Guards cannot universally parse text or prevent separate writers. Rejection metrics require
emitted-SQL and stored-row assertions to count as prevention evidence. [Core
events](https://docs.sqlalchemy.org/en/20/core/events.html)

## Sync and async provider-access comparison

All three candidates use identical manifest, crypto, codec, authorization and provider fault traces.
Measure their ergonomic differences rather than hide them in setup.

| Candidate | I/O boundary | Failure behavior |
|---|---|---|
| Explicit warm/prefetch | Await setup. Descriptor/flush work locally | Cold write fails before protected DML. Authorized bounded hidden-ciphertext reads may precede subject warming. No implicit scalar network I/O |
| Greenlet bridge | Yield async provider awaitable inside compatible greenlet | Outside greenlet fails. No synchronous SDK fallback in async path. Internal dependency isolated |
| Deferred/batch reveal | Load opaque unresolved value. Explicitly await reveal/finalize | Unresolved coercion/serialization fails. No partial plaintext publication on batch failure |

SQLAlchemy's documented run_sync adapts database I/O, while ordinary synchronous I/O in its callable
can block the loop. The official pydantic-encryption source is a more specific counterexample. Async
provider functions yield through `sqlalchemy.util.await_` or `await_only`. MissingGreenlet selects a
synchronous fallback.

Descriptors batch pending siblings and scalar hooks use the bridge. This was source-inspected at
commit `1f251f66368ce7053e6db2d3b0f3620c9c75ae1e`, not executed in this review. [SQLAlchemy
asyncio](https://docs.sqlalchemy.org/en/20/orm/extensions/asyncio.html), [pinned
bridge](https://github.com/julien777z/pydantic-encryption/blob/1f251f66368ce7053e6db2d3b0f3620c9c75ae1e/pydantic_encryption/integrations/sqlalchemy/async_bridge.py)

An unknown-subject read first validates the grant, tenant and search-key lease, QueryPlan and
bounded hidden row shape. Then it reads ciphertext and required companions only. It may explicitly
await bounded subject-key warming. Before publishing logical values, it revalidates resource binding
and epoch, authenticates, decodes and verifies predicates.

Hidden rows are internal unresolved data, not plaintext/entity results. Cancellation, cold/provider
failure, buffer overflow or changed grant publishes nothing and closes the read/handle lifetime. For
writes, every subject key and term key must be authorized and warm before any protected INSERT,
UPDATE or DELETE. Provider waits cannot occur mid-DML. G-ORM-1/2/5 separately gate the two-phase
read.

It does not make arbitrary lazy loading safe.

Internal helpers are evidence, not automatically acceptable dependencies. A production candidate
needing undocumented internals must document maintenance ownership, pin the helper contract and
obtain architecture review or expose a deferred public boundary. Use one AsyncSession per task.
Concurrent tasks must never share session mutations or grants. Task context copying follows the
shared authority contract. [Python task API](https://docs.python.org/3/library/asyncio-task.html)

Inject cancellation before and after setup, provider awaits, term preparation, flush, commit, load
and reveal. Cancelled operations cannot extend authority, return unverified values, commit half a
representation or silently reuse polluted sessions/connections. Reconcile ambiguous commit with a
fresh authorized read and operation ID. Timeout does not prove rollback.

Deferred batch publication is all-or-fail within one allowed authority scope. Error slots omit
values. Outage never selects plaintext. Warm-cache availability follows lifecycle policy by
reference, not a new TTL here.

## Types, normalization and nulls

Payload encoding and search normalization are separate. Payload bytes preserve declared logical
round trips. Normalization derives index inputs without replacing returned values. Each codec names
accepted exact types, canonical bytes, size caps, decode rejection, equality and version vectors.

Bool is not int by inheritance. Implicit str(value), pickle and repr serialization are forbidden.

| Type | Required contract before admission |
|---|---|
| str | UTF-8 strict. Unpaired surrogates reject. Code-point/byte limits. Original text retained |
| bytes | Exact preservation. Bytes-like coercions explicit. No base64/UTF-8 guessing |
| Integer/Boolean/Enum/UUID | Distinct tags. Integer bounds. Stable enum labels/version. UUID bytes |
| Decimal | Precision/scale, rounding/rejection, equality of 1.0/1.00. No float conversion |
| Date/time/datetime | Naive/aware, timezone/fold/precision, instant versus wall-time equality |
| Float | Future gated codec, excluded from the initial str/bytes transparent profile. Finite values, signed zero, NaN/infinity, canonical bytes and equality require explicit codec review/vectors |
| JSON/list/map/array | Schema/type preservation, keys/numbers/null, size/depth caps, immutable/tracked updates. Research initially |

First scalar prototypes limit the complete F1 encoded plaintext to 1 MiB (1,048,576 bytes). The
five-byte scalar state/length frame leaves at most 1,048,571 UTF-8 content bytes or raw bytes. Other
codecs must subtract their own complete framing overhead. This is not a 1 MiB user-content
allowance.

The text encoder adds no BOM. An actual leading U+FEFF is valid string content. The encoder
preserves and counts it rather than rejecting it as an encoding marker. Envelope/AAD limits belong
to crypto.

Queries allow at most 1,000 logical IN entries. Applications may lower all bounds. Larger profiles
require measurement. JSON SQL NULL, JSON null and missing paths are distinct. Normalization names
ordered transforms (e.g. NFC then casefold), Unicode database version and vectors.

Turkish I, sharp S, combining marks, whitespace and non-BMP cases are mandatory. Interpreter/Unicode
upgrades cannot silently reindex data. [Unicode
API](https://docs.python.org/3/library/unicodedata.html)

The first nullable profile uses SQL NULL for None, all scalar companions NULL and no term. Non-null
values require valid ciphertext and enabled terms. Missing or stale companions are invalid, not
null. Nullness leaks, and nullable SQL absence is not authenticated against an attacker changing a
row to NULL.

Integrity of null presence requires encrypted-null envelopes or authenticated row-presence and
separate fixtures. No integrity claim follows from SQL nullability. Required fields use ciphertext
NOT NULL and checked companion consistency.

The default unique policy is NULLS DISTINCT: multiple nulls per tenant and domain. Empty text and
bytes are values. NULLS NOT DISTINCT requires explicit capability, tested composite index and
non-null scope columns. Encrypted-null has separate terms/predicates. Shape CHECKs use explicit null
branches and IS TRUE where needed. [PostgreSQL
constraints](https://www.postgresql.org/docs/18/ddl-constraints.html)

## Physical schema compiler

Input catalog inventory covers identity, columns/types/nulls, indexes/validity/predicates,
constraints/validation, defaults/generated expressions/triggers, FKs, partitions and dependencies.
Output has names/types, before/after fingerprints, operation dependencies/transactions, storage/WAL
estimates, lock classes/time budgets, rollback limits and unresolved findings. Estimates name
assumptions. Unsupported catalog, partition and inheritance shapes block automatic planning.

Initial scalar companions use same-row BYTEA. Metadata follows the frozen envelope's embedded or
separate representation. Schema cannot invent an envelope. Naming version 1 uses the field's
lowercase UUID without hyphens (`f`, 32 hex characters) and an explicit nonzero unsigned-32-bit slot
ordinal (`s`, eight lowercase hex characters): ciphertext `cp_{f}_ct_s{s}`, equality
`cp_{f}_eq_s{s}`, payload shape constraint `cpc_{f}_ct_s{s}`, term shape constraint
`cpc_{f}_eq_s{s}` and equality index `cpi_{f}_e_s{s}` or unique index `cpi_{f}_u_s{s}`.

These ASCII names fit PostgreSQL's 63-byte default identifier limit. Cross-companion coherence
constraints use `cpc_{f}_co_s{payload_slot}_s{term_slot}` for each admitted payload/term-slot pair,
binding the immutable predicate version and null/presence relationship in the plan. Shape checks
never reuse that role. Every role/slot binds exactly one contract fingerprint, and a predicate
version change uses a new declared slot/transition.

Slot 1 is the initial field/representation. An incompatible physical representation uses the next
ordinal declared in target manifest physical_mapping, never a runtime random suffix. The immutable
parent manifest/catalogue binds each slot to its full payload or term tuple, including format/policy
or domain/normalizer/representation and allowed generation mapping. Payload and term slot spaces are
separate.

Retired ordinals never recycle. The compiler validates the declared slot transition against manifest
history and the live snapshot. Tenant key generations map into declared term slots. The compiler
does not automatically allocate a new column for every tenant.

Explicit stable-ID columns for record/scope metadata use `cp_{model_uuid_hex}_rid`, `_tid` and
`_sid`. Existing relational locator columns retain their reviewed names. Check every emitted name
against the entire schema. Reject any name bound to a different identity or tuple.

Never truncate or rename implicitly. Stable IDs distinguish a rename from deletion and creation.
Similar names are not identity evidence. Companion token tables remain a separate experiment with
FK/cascade, atomicity and lifecycle fixtures.

The required dependency order is:

1. Frozen envelope and index bytes, and parser failures
2. Physical codec and null model
3. Immutable version-specific shape predicate
4. Coexistence predicate
5. Downgrade and revalidation fixtures

Shape checks reject malformed envelopes and missing terms without keys. They authenticate neither
ciphertext nor tenant or writer. Never silently redefine frozen predicate functions. Create a new
version. Validate existing rows. Then retire old predicates through migration.

Plaintext CHECKs, functional indexes, defaults/generated expressions, FK targets and payload
triggers need reviewed protected equivalents or compilation rejects. Manifest or schema drift fails
startup. Startup emits no DDL, backfill or destruction. Relational IDs/FKs follow the shared
architecture.

Uniqueness uses a database composite unique index over non-null tenant/domain and equality term, not
application preflight. Conflict errors map constraint ID to field ID without values. Initial terms
are full construction-defined terms. Truncation needs a collision protocol.

Unexplained collisions pause for authorized comparison, never delete a row or assert equality from
tokens alone.

Separate old/new unique indexes do not enforce continuous uniqueness if writers emit disjoint
versions. Initial safe rotation follows this order:

1. Fence all writers to the dual-term protocol.
2. Retain the old authoritative unique index while backfilling all new terms.
3. After full term verification, validate/build the new unique index.
4. Before selecting V as authoritative, exclude every U-only route.

U+V writers may continue. Admit V-only writers only after proving V coverage, uniqueness and the
cutover fence. Keep U enforcement while any U-dependent route remains. Retire U only after
observation and explicit contract.

This matches the [crypto uniqueness protocol](crypto-search-lifecycle.md). Never start V backfill
while admitted writers can change only U. New normalization may merge old distinct values: detect
every conflict before admitting new semantics. If both generations cannot be produced and proven,
select an explicit bounded write pause or reject online rotation.

Never permit an unenforced uniqueness window.

## Alembic integration

The structured Plugin API starts at 1.18.0. That release did not introduce the older operation
plugins. Use public Operations/MigrateOperation, registrations/implementations/renderers, plugin
comparators and EnvironmentContext configuration. Registration and reflection do no provider or
crypto I/O. [Alembic plugins](https://alembic.sqlalchemy.org/en/latest/api/plugins.html),
[operations](https://alembic.sqlalchemy.org/en/latest/api/operations.html)

Compare stable-ID/schema-contract versions before rendering proposed expand/add-generation/validate/
checkpoint/contract operations. Each operation includes pre/postconditions, stable ID, reversibility
and deterministic renderer. Second autogenerate on applied schema emits zero Cryptalis changes. A
missing plugin, unknown operation version or incompatible Alembic heads block planning. A reviewed
merge is required. Mutate no unrelated schema objects.

Autogenerate is candidate DDL, not backfill/cutover proof. Current optional named CHECK detection
compares names and misses changed expressions. Cryptalis compares predicate contract versions and
catalog mismatches itself. Renames use explicit identity mapping.

Offline mode renders requirements and DDL but cannot attest catalog/data/provider state or advance
checkpoints. [Alembic autogenerate](https://alembic.sqlalchemy.org/en/latest/autogenerate.html)

Revisions embed no plaintext, keys, terms, credentials, network crypto loops or automatic
destructive downgrade. Durable data workers are separate. Downgrade checks reversible conditions and
raises an irreversible-state failure after destructive boundaries, requiring recorded recovery.
Alembic head stamping alone never proves Cryptalis backfill/verification/contract completion.

Concurrent index DDL is a journaled autocommit step with no adjacent uncommitted data changes. After
success or interruption, inspect definition, ownership and catalog indisvalid and indisready. Name
or IF NOT EXISTS is not completion proof. An invalid index pauses the transition.

Repair requires an explicit drop and recreate under the matching plan, or a tested rebuild. Failed
concurrent unique indexes may still enforce uniqueness. Concurrent build cannot run inside a
transaction block. [CREATE INDEX](https://www.postgresql.org/docs/18/sql-createindex.html)

## Migration state machine and concurrency

The canonical phase order is:

```text
INSPECT -> PLAN -> EXPAND -> COMPATIBILITY_WINDOW -> BACKFILL
        -> VERIFY -> CUTOVER -> OBSERVE -> CONTRACT
```

PAUSED, REPAIR_REQUIRED and FAILED are orthogonal statuses. Each records the last completed phase,
attempted step and resume preconditions. They cannot erase destructive journal entries. Coexistence
starts before BACKFILL.

The historical dossier's backfill-before-coexistence diagram is not the online contract.

| Phase | Entry/action | Completion evidence / rollback bound |
|---|---|---|
| INSPECT | Scoped read-only catalog/row/writer inventory | Source fingerprint, type/null/constraint/conflict findings, Alembic heads. Unresolved writers block online path |
| PLAN | Bind formats, authority, versions, budgets, recovery | Reviewed plan hash. Separate irreversible points. No automatic execution |
| EXPAND | Add nullable shadows/phase metadata and reviewed predicates | Catalog matches plan. Old writers valid while shadow target is non-authoritative |
| COMPATIBILITY_WINDOW | Deploy dual readers/writers and fence incompatible writers | Enforced writer epoch/leases. Plaintext authoritative. Legacy fallback counted |
| BACKFILL | Claim chunks. Encrypt current source. CAS coherent output | Durable row revisions and chunk journal. Stale backfill cannot overwrite newer writes |
| VERIFY | Full streaming authentication, source comparison and term recomputation for every current row, plus a separate stratified sample | Current scan complete. Zero conflicts. Healthy controls. Inconclusive blocks cutover |
| CUTOVER | Fence incompatible readers/writers. Select protected-only protocol | No plaintext fallback. Replicas/deployments at admitted epoch. Final consistency proof |
| OBSERVE | Operate protected-authoritative with no legacy fallback or legacy-authoritative writes. Optional declared atomic rollback mirror | Zero legacy-authoritative reads/writes and unresolved repairs with complete healthy telemetry. Mirror activity explicitly counted |
| CONTRACT | Separately approve each destructive operation | Journaled removal/checkpoint and recovery limits. No automatic rollback claim |

Before the writer fence, shadows may be stale and are never read authority. Old single writers run
only during additive expansion. Backfill begins only after every admitted write atomically updates
plaintext, ciphertext, required terms and a monotonically incremented durable row revision. External
writers unable to implement this protocol lose write access for the window or require offline
migration.

Heartbeat advertisement alone is not a fence. Enforce admission through registered roles and
adapters, bounded leases and the transaction-lock protocol below. A standalone epoch check just
before COMMIT races a deny/cutover and does not establish serialization.

While plaintext is authoritative, dual writers derive both shapes from one logical input. Readers
use source authority. They use protected values only with source-revision consistency validation
under the admitted protocol. Missing/stale target schedules CAS repair and cannot override newer
source.

At cutover ciphertext becomes authoritative. A retained rollback mirror must be atomically
maintained by new writers during the named remaining coexistence window. It remains plaintext
leakage. Stopping mirror writes makes old-application rollback unavailable at that point. OBSERVE
does not imply rollback works. Observation begins only after CUTOVER's fence is acknowledged by
every registered route and the full verifier/replicas have reached the admitted epoch. A permitted
mirror write is an atomic projection from the protected-authoritative input, not legacy application
authority or plaintext fallback.

Its count must be visible separately. The eligibility requirement is zero legacy-authoritative
activity, not zero mirror projections. Mirror scope/retention must be in the plan. Dropping mirror
freshness is a separately recorded loss of rollback ability.

Stale mirror data cannot be called a recovery path.

MigrationCheckpoint includes these fields:

- Plan and migration ID, phase, status and revision
- Source and target manifest, codec, format, normalization, index and key generations
- Stable binding, schema fingerprint and Alembic head set
- Compatible reader and writer versions, writer epoch and chunk journal
- Owner, expiry and fencing sequence
- Counts (claimed, converted, already_current, CAS_conflict, deleted, invalid, remaining)
- DDL journal, replica watermark, evidence and irreversible-operation IDs

Do not include hashes of values. Low-entropy hashes leak. Artifact digests/counts follow shared
policy. Exports pseudonymize row IDs.

Operational cursors remain in authorized internal storage.

### Reference transaction fence

This proposed PostgreSQL protocol composes with the [acknowledged lifecycle
drain](crypto-search-lifecycle.md), not an assertion of implemented enforcement. A tenant fence row
exists before any admitted protected write. Scope fence rows cover subject, index-domain and
migration epochs. Each protected transaction acquires PostgreSQL FOR SHARE row locks on the tenant
row and all affected scope rows, in canonical (tenant UUID bytes, scope-kind enum, scope UUID bytes)
order, before protected DML. The enum order is tenant, subject, index-domain, migration.

Every route uses that order. Newly allocated subjects first lock the preexisting tenant row. The
adapter installs their new fence rows while holding it. Thus, inserts cannot evade a tenant deny by
inventing a scope.

Missing fence rows fail closed. Never lazily trust an unfenced existing row. Locks last through
COMMIT or ROLLBACK. After locking, the transaction validates current replicated epoch and deny
state.

Before DML, it rechecks its grant and operation permit. Provider warming precedes these transaction
locks.

External authority durably denies new affected operation admission first. The lifecycle controller
then acquires conflicting FOR UPDATE locks on the applicable database fence rows, waiting for all
previously admitted protected transactions to end, and updates epoch/deny state in that transaction.
New transactions that obtain locks later see the new state and reject. Transactions already holding
shared locks may finish during drain, but necessarily precede the acknowledged database-fence
commit. A controller timeout, deadlock victim or ambiguous controller commit produces no
drain-complete receipt.

Before retry, reconcile the durable operation ID and state. Advisory process checks alone cannot
replace this lock conflict. Savepoints do not end the outer fence lifetime. Guards must cover all
actual flush, nested transaction and commit paths.

Multi-scope writes use the same global order and bounded lock wait. Migration writer cutover and
worker-lease replacement use this same serialization, not a heartbeat flag.

The trusted adapter, roles and registered writer inventory must enforce participation. Arbitrary
external SQL clients are outside the adapter guarantee and block an online completion claim unless
separately fenced. Database fence rows are replicas of external authority, not authority against a
malicious database or restored snapshot. Startup/resume obtains the current external epoch before
admission and reconciles stale local fence state. A managed completion receipt additionally requires
external operation/output permits drained and physical sink acknowledgments as specified by crypto.
Lease expiry blocks new authorized operations.

It does not prove that a suspended worker emitted no previously authorized plaintext. Missing drain
acknowledgments leave the operation incomplete.

Lease and phase revision use CAS. Stale workers cannot commit after losing a fence. Chunk
transactions read source plus durable application row revision, compute locally and update only
while row revision, source format and worker fence match. PostgreSQL xmin is not the durable
revision contract.

Target and row completion marker commit together. The chunk checkpoint advances after committed
rows. Replay is safe between row commit and checkpoint. Cursor alone is not coverage: inserts behind
it, skipped locks, retries/deletes/moved ranges require a final sweep using per-row target revision
markers. SKIP LOCKED may assist claims but never marks skipped rows complete.

Default job chunks are at most 500 rows or 8 MiB source bytes per transaction, whichever is first.
Operators may tighten limits. An oversized row blocks. Preparation prefetches warm material per
bounded batch.

Provider calls are not per field. Concurrent identity/codec/normalization/domain change requires a
new plan and pause. Compatible key generation transitions need explicit admission and
reverification. Workers never read mutable global settings mid-chunk.

Resume re-inspects catalog, phase revision, fences and DDL journal. Restored old checkpoints cannot
authorize progress: compare external migration/deployment authority and lifecycle tombstones before
row/key access. Key destruction and recovery expiry reference lifecycle operations. CONTRACT does
not complete them. Last-plaintext deletion, compatibility removal, old schema drop, readable-version
retirement and last recovery expiry remain separately signed irreversible points.

Approval binds exact operation/plan digest and precondition evidence.

Verification streams every current non-null row through local envelope authentication, codec decode
and recomputation of all required active index terms. It checks the durable source and target
revision. It compares source and target logical values while plaintext remains authoritative. This
is a full semantic consistency pass, separate from the independent second-pass stratified sample. A
count-only or shape-only scan cannot certify index contents.

Concurrent writes remain admitted only under the dual-write fence. The verifier rescans changed rows
before cutover, or a bounded write fence finalizes the pass. No raw terms or value hashes leave the
verifier.

## Errors and observability

Use the [canonical error registry](manifest-context-api.md#errors-and-observability).

| Error | Condition |
|---|---|
| Key.ColdMaterial | Unwarmed writes or decodes |
| Codec.InvalidType/InvalidValue/Oversize | Scalar validation failure |
| Query.IndexInconsistent | Failed recomputation or predicate verification |
| Schema.UniquenessConflict | Expected logical duplicate |
| Schema.UniquenessCollision | Unexplained token conflict |
| Execution.CommitAmbiguous | Unknown commit outcome |

These names are shared aliases, not a competing hierarchy. Register remaining domain failures
through that registry:

- Unsupported mapping, query or path
- Missing or expired context, cold material, and invalid type or size
- Unknown codec, envelope or index, drift, and binding mismatch
- Stale writer or fence, uniqueness conflict or collision, and invalid concurrent index
- Ambiguous commit, migration conflict, inconclusive verification and irreversible transition

Safe records contain code, stable field, operation or plan ID, phase, retryability and evidence ID.
Omit values, ciphertext, terms, credentials and parameter-bearing underlying exception text. Never
retry with a broader scope or downgrade. Bounded retries reauthorize and revalidate current state.

Telemetry records these dimensions:

| Area | Dimensions |
|---|---|
| Query | Operation, operator, classification, rejection reason, shape hash, generation count, tokenization and total time |
| Flush | Rows prepared or failed, cache state, revision and statement count |
| Async | Declared await boundaries, calls, coalescing, cleanup and loop lag |
| Migration | Phase revision, remaining, repair and CAS counts, chunk throughput and latency, locks, WAL, replica lag, index validity and telemetry health |

Exclude raw binds, literals, value hashes and sensitive high-cardinality IDs from logs and metric
labels. Synthetic controls may enter quarantined assurance artifacts only under that owner's policy.

## Research gates

Results are pending. These are initial falsifiable lab budgets, not product SLAs. A changed budget
requires a new experiment revision and rationale. Preserve P0-P10 meanings in the [hardening
dossier](../adversarial-architecture-hardening.md). G-ORM gates are detailed executable owners, not
renamed P risks. Runs bind versions, seed, offered/completed load, schema/manifest/plan hashes,
controls and raw artifacts.

Use the [playbook testing policy](../../ENGINEERING_PLAYBOOK.md#test-layers) to select test boundaries.
Prefer real session/crypto/PostgreSQL workflows. Focused compatibility and recovery checks retain the exact gates below.
Failure narrows the affected profile. Missing collectors or unexecuted fault branches yield
inconclusive.

### Open decisions: question, defaults and admission evidence

Each row below is an open empirical question, not an undocumented design choice. Its same-ID row in
the protocol table immediately below supplies the **Experiment** and exact **Pass condition**.
**Fail condition** means any listed correctness or security counterexample, threshold violation or
missing required artifact or control. Missing evidence is INCONCLUSIVE. It blocks admission just as
a failure does, while preserving that distinction.

Alternative selection requires its own recorded run. It cannot bypass that row's oracle or silently
weaken the intended property.

| Gate / Question | Why it matters | Current default | Alternatives | Evidence needed | Blocked claim / safe work before proof |
|---|---|---|---|---|---|
| G-ORM-1: Can public instrumentation keep logical/physical history and authority coherent through every state transition? | Dirty-state or identity-map errors can publish stale/cross-resource plaintext or store plaintext | Immutable str/bytes descriptor plus hidden same-row attributes, explicit cache transitions, one task/tenant/session | Explicit repository/controlled value. Private instrumentation only after maintenance review | Exact compatibility cell, seeded transition traces, Session histories, SQL/row assertions, binding-substitution controls and failure artifacts | Transparent state/loader support blocked. Mapping DTOs and synthetic state prototype safe |
| G-ORM-2: Does expression planning and every admitted execution guard preserve logical predicates and reject bypass? | Missing scope or wrong-predicate candidates defeat tenant/query boundaries | Conservatively admitted EQ/IN/null/full-entity trees. Buffered authentication/term/predicate checks. Unchanged LIMIT semantics | Explicit repository statements. A separately declared bounded postfilter planner. Dedicated strict engine | Generated tree corpus, logical result-ID oracle, emitted SQL/binds under quarantined controls, authentic-row/term tampering, bypass classifications | Query/execution-plane prevention blocked. IR/compiler and fixture design safe |
| G-ORM-3: Are typed bytes, normalization, nulls and limits stable across processes/versions? | Coercion or Unicode/null drift changes round trips, search equivalence and uniqueness | Exact str/bytes codecs, separate normalization, SQL NULL with explicit unauthenticated-presence limit, encoded-value cap | Encrypted-null/authenticated presence. Separately registered richer immutable codecs or mutable adapters | Cross-process golden bytes, malformed/boundary vectors, Unicode version/corpus, null truth tables, declared codec entry/version | Type/null-integrity profiles blocked. Codec experiments and registry design safe |
| G-ORM-4: Which async provider boundary meets correctness, latency and ergonomic requirements? | A hidden synchronous SDK wait may stall unrelated tasks | Explicit warm/prefetch with bounded hidden-row two-phase reads. No scalar implicit network I/O | Compatible greenlet bridge. Deferred/batch reveal. All compared under matching semantics | Exact provider fault traces, latency histograms/loop-lag recordings, offered/completed load, task/config versions and independent repetitions | Async performance/profile selection blocked. All three synthetic prototypes safe |
| G-ORM-5: Does cancellation/coalescing preserve operation/session lifetime without hidden fallback? | Cancellation can leak grants, connections or half-published plaintext and make unknown commits look rolled back | Bounded single-flight misses, explicit await boundaries, all-or-fail publication and observed cleanup | Deferred finalize. Independent bounded fetches with a separately measured no-coalescing profile | Per-boundary cancellation traces, fetch-count/coalescing controls, handle/connection counts and durable ambiguous-commit dispositions | Cancellation-safe async/coalescing claim blocked. Fault harness and DTO design safe |
| G-ORM-6: Can public schema/Alembic integration deterministically represent and revalidate protected invariants? | Name-only changes or mutable CHECK functions miss drift and stale rows | Same-row scalar companions, stable IDs, immutable version-specific predicates, structured public plugin | Companion tables. Reviewed manual schema plan/inspect-only tooling. Older operation APIs as a separate lane | Before/after catalog snapshots, deterministic plans/renderers, second-autogenerate diffs, invalid-presence/predicate fixtures and startup SQL capture | Automatic compiler/plugin/drift-prevention support blocked. Offline plan renderer and catalog inspection safe |
| G-ORM-7: Does fenced dual-write/CAS migration survive concurrent writes, crash and restore? | Backfill can overwrite newer values or falsely certify a destructive transition | Compatibility fence before backfill. Durable row revision, lock-serialized commits, external authority and journals | Explicit bounded write pause/offline migration. Alternative journal protocol only after equivalent oracle evidence | Seeded source/target oracle, writer histories, row/CAS journals, fault boundary traces, fence acknowledgments and restore denial controls | Online migration and serialized-completion claims blocked. Plan/checkpoint models and isolated synthetic workers safe |
| G-ORM-8: Does verification cover all current crypto/source/index invariants without overstating sampling? | Shape/count-only checks miss authentic wrong values and corrupted terms | Full streaming authentication/source comparison/term recomputation plus independent stratified sample | Full verification during a bounded write pause. Declared snapshot plus complete change-journal replay | Full coverage/revision/term records, sample seed/strata, independent controls, exact conflicts and uncovered branches | Cutover consistency/completeness claim blocked. Verifier streaming/stratification prototypes safe |
| G-ORM-9: Can the declared migration profile meet lock, transaction, WAL, replica and storage budgets? | Safe algorithms can still be operationally unusable | Named initial budget table and bounded chunks. Exceeding budget pauses the plan | Smaller chunks, scheduled DDL/write windows, or a separately revised measured budget/profile | Baseline and protected workload traces, lock/transaction histograms, WAL/storage accounting and replica epoch/lag evidence | Low-disruption/storage-cost claim blocked. Estimation and instrumented synthetic workload safe |
| G-ORM-10: Does post-cutover observation prove contract eligibility with no hidden legacy authority? | Missing telemetry can make absent events look like drained writers | Acknowledged cutover then healthy 24-hour observation. Optional atomic rollback mirror counted separately. Explicit irreversible approvals | Longer observation. No rollback mirror. Deferred/offline contract after separately proven drain | Complete route/lease inventory, telemetry health/controls, replica/fence state, mirror classification, irreversible approval/journal artifacts | Destructive contract eligibility and rollback availability blocked. Non-destructive observation/receipt prototype safe |

| Gate | Protocol and threshold | Consequence |
|---|---|---|
| G-ORM-1 state (P0/P1/P4) | >=10,000 randomized transitions per sync/async cell plus every deterministic state/loader case. Zero incorrect round trips, stale histories/terms, cross-tenant identity-map output, requested-PK plus full-metadata substitution release or plaintext SQL/rows | Remove failing transparent cell. Redesign |
| G-ORM-2 query/bypass (P2) | >=1,000 trees per admitted operator/null policy, >=100 unsupported forms and every execution-plane row. Authentic-row/term swaps and LIMIT/OFFSET/IN/OR/null fixtures. Zero incorrect result IDs versus logical oracle, zero partial publication on index inconsistency. Zero T/R plaintext. Rejected constructs fail before their SQL | Reject uncovered forms. D/U remain gaps |
| G-ORM-3 codecs (P1/P5) | >=1,000 vectors per codec plus boundary corpus, >=10,000 Unicode vectors, complete null truth tables. Byte-identical cross-process encoding. Zero coercion surprises. Unicode drift detected | Narrow codec/profile or migrate explicitly |
| G-ORM-4 async (P3) | All three designs at 0/10/100/500 ms provider delay, warm/cold/outage/throttle, 1/32/128 tasks. Five independent 60-second runs after warmup. Added p99 loop lag <=10 ms at 32 tasks versus identical baseline. 256-byte hot-path p99 overhead <=5 ms and end-to-end <=25% at baseline p95 >=20 ms | Fail correctness/lag means not selected. Relative budget inapplicable below specified baseline |
| G-ORM-5 async faults (P3/P7) | 100 cancels per await boundary. 100 simultaneous misses per authority/cache key. Zero sync fallback, partial output, grant/connection leaks or unexpected commits. <=1 overlapping provider fetch per cache key with coalescing. Cleanup <=2 seconds under responsive lab provider | Redesign boundary/coalescing or deferred profile |
| G-ORM-6 compiler (P2/P6/P10) | >=100 diffs including rename/collision/drift/predicate/head/unknown cases. Deterministic render. Zero second-autogenerate changes. All shape/presence negative fixtures fail. Zero startup DDL | Inspect-only if conditions cannot be proven |
| G-ORM-7 migration (P5/P6) | 1,000,000 seeded rows, two workers, 32 writers for 30 minutes. Death before/after each checkpoint/journal/DDL/fence-lock boundary repeated 20 times. Simultaneous revoke/COMMIT, new subject insertion, stale leases, behind-cursor inserts, invalid unique index, skew and restore. Zero lost newer values, unique duplicates, skipped final rows or false completion | Online migration blocked. Offline/inspect remain possible |
| G-ORM-8 verifier (P6/P8) | Full row/count/presence/index-version coverage and full streaming authentication/source comparison/term recomputation. Independent second pass on >=10,000 distinct sampled rows or all if smaller, stratified tenant/format/null/generation. Zero mismatches/conflicts. Exposure controls healthy. Seed/uncovered strata reported | Any incomplete full invariant/stratum blocks cutover. Sampling is bounded confidence only |
| G-ORM-9 budgets (P6) | Lock acquire <=1 second. Chunk/DDL hold p99 <=100 ms except named DDL window. Chunk transaction <=2 seconds. Cutover replica lag <=1 second and applied epoch proven. WAL <=2x baseline writer workload. Scalar-equality database expansion <=3x source | Exceeding pauses plan for revised measured budgets |
| G-ORM-10 contract (P6/P7) | >=24 continuous hours after acknowledged cutover. Every writer/reader lease covered. Zero legacy-authoritative reads/writes and unresolved repairs, invalid indexes and unresolved chunks. Declared atomic rollback-mirror writes counted separately. Replicas current. Grant/fence controls passed. Approval per irreversible point | Missing telemetry resets eligibility interval. No absence-only contraction |

Correctness and security thresholds permit zero failures. Performance and storage budgets are not
cryptographic or leakage acceptance. Full streaming cryptographic, source and term verification is
mandatory. The second stratified sample adds bounded confidence.

It never replaces full verification. ORM's 25%/10 ms end-to-end budget concerns the specified
32-task application baseline. Crypto's 20%/5 ms microbenchmark has its own workload. A compatibility
profile claiming both must pass each applicable workload separately. Passing one does not relax the
other. Storage accounts shadow plaintext, both terms, TOAST/index/WAL and recovery sources
separately.

## Compatibility candidates and unresolved decisions

Proposed first lane as observed 2026-09-30: CPython 3.13.15 ordinary GIL build, SQLAlchemy 2.0.54,
Alembic 1.20.0, Psycopg 3.3.6, PostgreSQL 18.6. It preserves the existing 2.0 experiment while
updating patches. SQLAlchemy 2.1.1 is released: immediate comparison lane, not beta-only future. The
2026-10-01 recheck selects CPython 3.14.8 for comparison (3.14.7 is the earlier observation).
PostgreSQL 17.11/16.15, asyncpg and pure/C/binary driver implementations expand one variable at a
time.

Freeze OS, libpq, greenlet and crypto builds before execution. No lane is supported before
CompatibilityCell evidence. [Version
ledger](../research/orm-platform-evidence.md#version-observations)

Before runtime admission, prove these properties:

1. Public instrumentation (G-ORM-1)
2. Physical representation after envelope freeze (G-ORM-3/6)
3. Admitted codec and null integrity (G-ORM-3)
4. Strict-engine capabilities and cross-scope traversal (G-ORM-2)
5. Specified uniqueness and fence transitions (G-ORM-7/8/10)
6. Selected async helper contract (G-ORM-4/5)

Their candidate behavior is specified here. Prototype results remain unknown. Manual experimental
implementation may begin without claiming support. Broader encryption alternatives in the ledger
and [prior-art owner](../prior-art.md) are comparison evidence, not integrations or absence claims.
