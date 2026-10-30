# Query compatibility

[Documentation map](README.md) · [Current evidence](status.md)

- [Support vocabulary](#support-vocabulary)
- [Supported stack](#supported-stack)
- [Compatibility promise](#compatibility-promise)
- [Full capability matrix](#full-capability-matrix)
- [Native function admission](#native-function-admission)
- [Query semantics](#query-semantics)
- [Signed integer storage](#signed-integer-storage)
- [Internal DATE storage candidate](#internal-date-storage-candidate)
- [Optional SQLModel bridge](#optional-sqlmodel-bridge)
- [Portable DDL](#portable-ddl)
- [Capability admission](#capability-admission)
- [Performance targets and recorded costs](#performance-targets-and-recorded-costs)
- [Database evidence](#database-evidence)
- [Native identifier deparser admission](#native-identifier-deparser-admission)
- [Persisted Date reader compatibility](#persisted-date-reader-compatibility)


**SPECIFIED:** selected scope and query contract. **No production cell is qualified.**
SUPPORTED selects design scope. IMPLEMENTED means code exists, with its boundary stated.
VERIFIED means named evidence exercises the stated property on its recorded revision and cell. It does not imply release qualification.
[Status](status.md) owns current evidence. [Security](security.md) owns collision, omission, replay, NULL-presence, and host-compromise limits.

## Support vocabulary

Every capability has one current admission label: **SUPPORTED**, **CURRENTLY UNADMITTED**,
**UNSUPPORTED BY DESIGN**, or **INTERNAL ONLY**. SUPPORTED selects admitted design scope,
not production qualification. CURRENTLY UNADMITTED marks unfinished capabilities
that the runtime must refuse. UNSUPPORTED BY DESIGN retains explicit safety
and selected-runtime exclusions. INTERNAL ONLY covers research mechanisms that cannot establish support.
Only the full SRS and 34 objectives define first-release requirements.
An unadmitted label alone does not expand that set.
The [comprehensive release direction](decisions.md#comprehensive-first-public-release-2026-10-23)
retains the full SRS and all 34 objectives. Safe refusal does not complete a capability.
The [competitive capability matrix](research/capability-matrix.md) tracks future parity and E2E acceptance.
All normative sections here are SPECIFIED. Recorded-cost sections are VERIFIED only at their stated historical measurement scope.

## Supported stack

Python 3.12+, SQLAlchemy 2.x, psycopg 3 sync and async, PostgreSQL 16.
The text family includes native PostgreSQL text and VARCHAR, with matching standard mappings.
Native Boolean storage has a separate pinned codec and standard Boolean mapping.
Native signed int2/int4/int8 storage uses exact SmallInteger/Integer/BigInteger
mappings, typed fixed-width values and admitted literal client defaults.
Native DATE storage admits exact standard Date mappings and Python date values
in years 1 through 9999. Date search, defaults, string/timestamp coercions and
custom mappings refuse; NULL presence and direct COUNT retain their grammar.
Literal Boolean client defaults retain native INSERT omission/None behavior.
UPDATE with None retains native nullability errors and rollback. Custom converters refuse admission.
An explicit [SQLModel bridge](#optional-sqlmodel-bridge) admits one exact pinned
AutoString mapping through its checked native String implementation.
Other required protected types remain CURRENTLY UNADMITTED. PostgreSQL 16 is the selected first-release environment.
An admission label does not add PostgreSQL majors, every locale or custom host hooks to the SRS.
The compiler inspects exact text equivalence, nullability, stable application-generated IDs, tenant declarations, and constraint scopes.
Every protected table declares its tenant column or declares itself single-tenant.
Serial, identity, and database-default-generated primary keys fail at plan time with a plain explanation.
App-assigned UUID, Snowflake-style, and other ID mappings need frozen typed context encodings and differential evidence.
No sequence-USAGE or preallocation exception admits a server-generated key.

## Compatibility promise

Cryptalis never silently changes what the backend returns.
For every supported operation, results match the unprotected database, including native values, types, NULLs, and ORM behavior.
Every unsupported operation raises `UnsupportedEncryptedQuery` or an equivalent typed error before execution.
Different, partial, unauthenticated, or plaintext-fallback data is forbidden.
Full-term query exactness assumes HMAC collision resistance and intact search representations.
Payload authentication does not prove hostile-database completeness, freshness, or adversarial global uniqueness.

Unsupported operations on protected fields fail. Users must inspect this list before protecting a field:
comparisons/ranges, ORDER BY, LIKE/prefix/contains, regex, SUM/AVG/MIN/MAX, general DISTINCT, protected-field joins, and other unadmitted protected types.
The recommended adoption path is manifest → plan → staging apply plus the attached application suite → qualified production apply → decrypt-back exit.
Plan refuses server-generated keys, unsupported types, small-domain searchable fields, missing tenancy, and unsupported writers.
Attach rejects unsupported queries. Application tests on staging expose query-level incompatibilities before production.
This path does not guarantee zero changes and adds no command or mode.
Adoption costs a manifest, one attach call, typed replacements for opaque protected writers, and application-generated primary keys.
Rollback/removal transforms current data through decrypt-back until explicit finalization retires its recovery dependencies.

## Process ownership

An attachment belongs to the process that created it. After POSIX `fork`, its
session factory, supported sync/async query and transaction entrypoints, cached
`Session.get`, and guarded driver operations raise `ForkedRuntime`. This check
precedes key resolution. The attached engine's `connect` and `raw_connection`
entrypoints refuse before native pool locks. Captured guarded driver methods
check ownership when called, including commit, rollback and close.

Initialize fresh mappings, engine, providers/keyrings, attachment and sessions
inside each child. Fresh keys alone do not authorize an inherited engine or
session. Close parent-owned sessions in the parent. Native
`engine.dispose(close=False)` can detach an inherited pool without closing its
connections, but it does not transfer Cryptalis attachment ownership. Use a
fresh runtime; do not retry an inherited call. Ordinary cleanup in the owning
process does not require provider access.

These checks do not revoke copied Python objects, already buffered results,
plaintext, keys or private native handles. They do not qualify arbitrary engine
wrappers, process start methods, fork during native driver execution, or general
multiprocess throughput. The host must keep live connections and sessions out of
cross-process application work. [Status](status.md) owns the bounded native
parent/child transaction evidence and remaining qualification work.

## Full capability matrix

| Operation | Classification | Contract or reason for rejection |
|---|---|---|
| Text storage/read/write, entity/scalar projection, SQL NULL | SUPPORTED | Randomized authenticated payload. Preserve exact str, empty text, NULL, native ORM state, and expected row/tenant context |
| COUNT of a directly protected column | SUPPORTED | Bounded local implementation of native non-NULL counts, optional output labels, aliases, public grouping and public FILTER predicates. Non-distinct windows admit public partitions/order and native bounds. Custom dispatch and protected argument/filter/partition/order expressions refuse |
| Boolean storage/read/write, entity/table/scalar projection, SQL NULL | SUPPORTED | Typed authenticated one-byte values, native Boolean input processing and literal client defaults. No Boolean equality term. [Bounded evidence](history/implementation-2026-10.md#boolean-storage-checkpoint-2026-10-23) |
| Date storage/read/write and SQL NULL | SUPPORTED | Exact Python date values in years 1 through 9999; pinned four-byte Date codec and lock/v8. Storage-only, native sync/async values and latest-value removal. Non-finite/BC/out-of-range source dates refuse before migration effects |
| UUID value storage/read/write and SQL NULL | SUPPORTED | Exact standard native UUID mappings and Python UUID inputs, including nil; sixteen authenticated network-order bytes and lock/v9. Storage-only; defaults, coercions and custom mappings refuse. Public record/tenant UUIDs keep their separate context contract |
| Signed integer storage/read/write and SQL NULL | SUPPORTED | Exact int2/int4/int8 mappings and width-bound Python ints, literal client defaults, native failure/transaction behavior and typed fixed-width CF1. Storage-only; the fixed authentication overhead is published in the local cost profile |
| Mapped dictionary INSERT without RETURNING | SUPPORTED | Attached sync/async `Session.execute(insert(Model), list[dict])`, explicit typed IDs and tenant scope, copied attribute dictionaries, native NULL/grouping, autoflush, uniqueness and transaction behavior. Other bulk routes remain unadmitted |
| Mapped dictionary INSERT with RETURNING | SUPPORTED | Native direct-column tuples/scalars and inserted mapped entities, including public-only columns. Preserve result keys/types, grouping, paging and optional input ordering. Entity results retain identity-map loading and refresh. Authenticate each protected output against its own exact prepared input. Label/expression/alias, loader-option and caller return_defaults forms remain unadmitted |
| Scoped mapped dictionary UPDATE | SUPPORTED | Attached sync/async admitted storage types, typed IDs, nonempty list of dictionaries and synchronize_session=False. Tenant-column tables require explicit tenant equality. Declared single-tenant tables use the fixed table UUID and no caller WHERE. Preserve native omission/NULL, grouping, repeated IDs, row-count checks and transactions. Core and RETURNING routes remain unadmitted |
| Single-record mapped UPDATE with RETURNING | SUPPORTED | Attached sync/async `Session.execute`, exact record and tenant equality (or declared fixed scope), one nonempty external assignment dictionary using native physical column keys, and `synchronize_session=False`. Direct returned columns/scalars/tuples and mapped entities retain native labels, types, identity behavior and transactions. Authenticate protected outputs; changed protected values must match the exact newly prepared frame. Embedded `.values()`, Core, expressions/labels/aliases, identity/tenant assignment, automatic/fetch synchronization and executemany RETURNING remain unadmitted |
| Scoped mapped single-record DELETE | SUPPORTED | Attached sync/async execute, exact typed record equality and either tenant equality or explicit fixed table-UUID scope. No external parameters; require synchronize_session=False. Without RETURNING, preserve native row counts. Direct-column scalar/tuple and mapped-entity RETURNING preserves native keys, types, identity state and transactions; protected values authenticate against the requested row, field and tenant. Unsupported custom AST classes refuse before execution |
| Unprotected-table mapped DELETE | SUPPORTED | One physical table mapped in the attached registry, with no protected fields. Native equality/AND predicates with fixed typed literals only. Default/auto/evaluate/False synchronization. No Core, RETURNING, fetch synchronization or custom AST |
| Equality `==` and `IN` | SUPPORTED | Declared full tenant/domain-bound HMAC term. Preserve typed binds and native NULL/empty-list truth tables |
| Simple negative equality `!=`, `NOT IN`, and NULL presence | SUPPORTED | Reuse the authenticated term for values and a SQL NULL check for storage-only fields. Preserve native three-valued truth, NULL elements, empty lists, and outer-join NULL extension. General Boolean NOT remains unadmitted |
| Tenant-scoped uniqueness | SUPPORTED | Full term plus tenant scope in a race-safe native unique index. Explicit single-tenant declaration supplies its one scope |
| Comparisons `<`, `<=`, `>`, `>=`, BETWEEN/ranges | CURRENTLY UNADMITTED | No admitted range representation |
| ORDER BY and sorted pagination on protected values | CURRENTLY UNADMITTED | No admitted order representation. Ciphertext ordering is forbidden |
| LIKE, ILIKE, prefix/startswith, contains, suffix | CURRENTLY UNADMITTED | No admitted pattern/text grammar or representation |
| Regex, fuzzy/similarity, full text | CURRENTLY UNADMITTED | No admitted exact query or text-search contract |
| SUM, AVG, MIN, MAX, arithmetic | CURRENTLY UNADMITTED | Selected payload/equality format does not implement these operations |
| COUNT DISTINCT on an equality field | SUPPORTED | Bounded local implementation counts existing full-width equality terms within one tenant per group. Require explicit single tenancy, direct tenant equality in WHERE, or GROUP BY the exact tenant column. SQL NULL is excluded; native expression/label result keys are retained. Storage-only fields and global multi-tenant distinct counts refuse |
| DISTINCT of one direct protected equality field | SUPPORTED | Existing full-width terms within one provable tenant scope; authenticate the representative payload. Labels, aliases and SQL NULL retain native value-set semantics. No output-order promise |
| DISTINCT with each protected source's public primary key selected | SUPPORTED | Native entity/table/direct-tuple behavior, public ordering/pagination, labels and duplicate join rows. Also admits storage-only fields. Each record ID must match the protected column's exact source alias |
| General DISTINCT, DISTINCT ON, protected GROUP BY | CURRENTLY UNADMITTED | Multiple outputs, caller DISTINCT ON, protected grouping, ordering and pagination require separate admission. Randomized-payload comparison changes logical semantics |
| Joins/FKs on protected fields | CURRENTLY UNADMITTED | No admitted shared search-domain or protected-FK contract |
| Field-to-field equality, general Boolean NOT, other unadmitted functions/operators | CURRENTLY UNADMITTED | Approved scope does not independently admit these shapes |
| Other protected types, JSON predicates, unqualified custom protected types | CURRENTLY UNADMITTED | Text and storage-only Boolean, Date and signed integers have bounded admission. The exact pinned SQLModel AutoString exception retains native String admission |
| Opaque raw SQL/COPY protected writes and unknown external writers | UNSUPPORTED BY DESIGN | Reject guarded routes. Plan blocks protection unless the deployment excludes separate routes |
| Research range/prefix arrays, order candidates, scoped aggregate helpers, internal binary projections | INTERNAL ONLY | Experiments and adapter machinery, not public query capabilities |

For mapped bulk UPDATE, use `update(Model).where(Model.tenant_id == tenant)`
with `execution_options={"synchronize_session": False}` and typed IDs in each
input dictionary. The single predicate must be direct typed tenant equality.
For an explicitly single-tenant table, use bare `update(Model)` with the same
list of typed-ID dictionaries and session scope equal to its declared table
UUID. Caller WHERE clauses refuse for that route. Native missing-record
row-count failures remain `StaleDataError`; roll back the transaction or savepoint
before retry.
See also the [online scalar UPDATE evidence](history/implementation-2026-10.md#single-tenant-mapped-update-2026-10-29).
The adapter rejects extra predicates, embedded values, version counters,
dynamic defaults, read-only mapped properties, SQL-producing type hooks and
type variants. Ordinary Python public-field bind processors remain native.
The ordered input ledger checks each emitted group and complete consumption.
The [bulk UPDATE checkpoint](history/implementation-2026-10.md#scoped-mapped-bulk-update-checkpoint-2026-10-23) owns the earlier TEXT evidence.
The [VARCHAR checkpoint](history/implementation-2026-10.md#native-varchar-mapped-update-checkpoint-2026-10-23)
adds finite VARCHAR targets and records native plan behavior.

Admitted plaintext fields retain native query semantics, including ranges, order,
aggregates, and joins through unprotected keys. Public-column DISTINCT and
DISTINCT ON remain admitted when WHERE uses a supported protected search.
They deduplicate public results only. Protected outputs and distinct keys retain
their refusal. SELECT type admission refuses
SQL-producing custom type hooks, dialect variants, custom SQL type rendering,
user-defined SQL type spelling and literal-execution binds. Ordinary Python
bind/result processors remain admitted under the finite native type contract.
Native dispatch identity and exact owned payload-type identity constrain the
internal output hook. Nested decorator, ARRAY and tuple types receive the same
checks. These SELECT checks do not extend admission for public write-type hooks.

UUID primary-key SELECT lookup accepts the native PostgreSQL ASCII text forms
under the exact `Uuid(as_uuid=True, native_uuid=True)` contract. This includes
uppercase, optional braces and optional hyphens after each four hexadecimal
digits. Normalization derives expected authenticated context only. SQL binds
and ORM identity-map keys retain native behavior. Malformed text and integer
inputs retain PostgreSQL 22P02/42846 errors and require rollback after failure.
An invalid expected-point marker authorizes neither a frame nor an outer-join
NULL result. This lookup admission does not admit string identities for writes.

Entity and table projections expand into the same admitted node snapshot.
Each selected column and its descendants receive the existing type, lineage
and protected-expression checks. Protected outputs retain authenticated decryption.
The [expanded SELECT checkpoint](history/implementation-2026-10.md#expanded-select-projection-checkpoint-2026-10-23)
owns current projection evidence. The earlier
[SELECT type checkpoint](history/implementation-2026-10.md#finite-select-type-admission-checkpoint-2026-10-23)
owns its recorded native refusal and compatibility evidence.
Tenant-scoped uniqueness uses PostgreSQL's original qualified NULL behavior. Unqualified partial/compound or NULLS NOT DISTINCT variants must reject at plan time.

For scoped mapped DELETE, use `delete(Model)` with exact typed tenant and record
equalities and `execution_options={"synchronize_session": False}`. Explicit
single-tenant tables instead require only exact record equality, with session
scope equal to their declared table UUID. The route admits one
application-assigned UUID or int64 record.
Without RETURNING it returns native row counts. RETURNING accepts direct columns
or the mapped entity, including public-only outputs, through the ordinary Result.
Protected outputs require a real row identity and authenticate with SELECT's
freshness/completeness limits; they are not newly prepared frames. Result failure
can follow SQL execution and requires rollback. Core DELETE, external parameter
dictionaries, labelled/expression/alias outputs, loader options, automatic/fetch
synchronization, inheritance, version counters and other predicate shapes refuse.
Ordinary ORM flush DELETE retains its existing native lifecycle contract.
Both routes require native compiler nodes. Custom AST classes refuse before SQL.
The [DELETE checkpoint](history/implementation-2026-10.md#mapped-delete-admission-checkpoint-2026-10-23)
owns the exact native controls and remaining limits.

A separate mapped DELETE route admits only unprotected tables in the same
attached registry and metadata. Use direct column equality to fixed UUID, int,
str or bytes values with matching admitted native types. AND can combine these
predicates. Default, auto, evaluate and False synchronization retain native ORM
behavior. Core DELETE, external parameter dictionaries, RETURNING, fetch,
inheritance, version counters and other grammar refuse. The route captures
physical table/mapper identities and ordered predicates before key resolution.
It repeats admission afterward and checks native compiled SQL and exact driver
binds. The protected scoped DELETE contract stays separate. These routes do
not admit general public DML.

Protection planning and attachment require native row-context codecs without
dialect-specific type variants. Attachment repeats configuration admission before
host key resolution and SQL, including changes to identity flags or type hooks. The real native SQL transformation controls and 105-case planning
regression are recorded in the [identity planning checkpoint](history/implementation-2026-10.md#identity-variant-planning-checkpoint-2026-10-23).

## Native function admission

Attached SELECTs accept the finite native function classes and names listed in
[`_sqlalchemy_functions.py`](../src/cryptalis/_sqlalchemy_functions.py).
Ordinary calls resolve explicitly in `pg_catalog`; supported special SQL
expressions retain native syntax. Unknown or database-defined functions, other
namespaces and custom dispatch refuse before keys and execution, including on
unprotected arguments. Functions on protected fields still require their own
capability admission. Existing aggregate/window/public-expression controls do
not admit protected aggregates or general encrypted advanced queries.

## Query semantics

Compare every admitted shape with the same native PostgreSQL application.
Test typed/reversed/late binds, AND/OR compositions of admitted predicates, aliases, projections, pagination, and outer joins through unprotected keys.
Preserve SQL UNKNOWN. Preserve NULL elements, empty `IN` lists, and `NOT IN` three-valued truth. Simple negative forms may add the authenticated tenant scope through an OR with an absent outer-join record key. General Boolean NOT that could invert that scope is rejected. Reject an unadmitted nested operator before SQL.
NULL payloads remain SQL NULL. Empty strings encrypt normally. Reject PostgreSQL-forbidden NUL text before SQL.
Strict UTF-8 never changes composed/decomposed text or silently casefolds it.

Text equality requires inspected deterministic exact equivalence. Current admission
accepts exact `pg_catalog.C` with provider `c` and mapped `C`, or exact
`pg_catalog.default` with provider `d` and an implicit mapped collation.
Both must be deterministic. Each source index must use the same qualified
collation as its column. This admits byte-exact equality and uniqueness only;
it supplies no locale-sensitive ordering, normalization or pattern semantics.
User-defined names and nondeterministic collations remain unadmitted.
Existing readers reject new default-collation search locks before use.
The [searchable application checkpoint](history/implementation-2026-10.md#searchable-sqlmodel-application-checkpoint-2026-10-23)
records the bounded native and unchanged-application evidence.
Nondeterministic collations, citext, bpchar padding, locale-sensitive operators, custom types and changed normalizers remain outside the current text profile.
Each required profile needs exact equivalence and separate admission. This does not require every locale or arbitrary host hook.
The compiler rejects a constraint or mapping it cannot preserve exactly. Generic CHECK/FK/default/collation preservation is UNKNOWN.
[Lifecycle](history/technical-observations-2026-10.md#integrated-lifecycle-checkpoint-2026-10-07) bounds the current verifier's source-index and scoped-uniqueness evidence.
A searchable small domain fails planning because enumeration can label equality classes. No arbitrary size threshold substitutes for leakage evidence.

The attached driver boundary requires its capture callback first and unique.
Register unchanged engine-instance cursor observers after attachment.
Preexisting, class-level and connection-local cursor hooks refuse. Changes to
captured SQL, binary bytes or typed primitive/identity binds also refuse before
the driver. Native ORM RETURNING pages for unprotected server defaults retain
their native results. The bounded protected scalar route also validates native
page inputs and freezes each exact generated page before cursor callbacks.
It preserves native ordering without an input-order promise unless requested.
Its result proof does not establish hostile-database result completeness or ordering.

Native VARCHAR preserves its character limit and assignment semantics through protection and decrypt-back.
Typed length failures require rollback, as the native ORM flush does.
For the bounded dictionary INSERT route, a length failure preserves native
Session activity and PostgreSQL's aborted transaction or savepoint state.
An earlier row constraint failure retains precedence. No protected plaintext
reaches PostgreSQL to produce the length error.
For dictionary UPDATE, native plan selection can change when PostgreSQL rejects
an overlength assignment. Custom plans reject the tested matching and unmatched
assignments. Generic plans reject matching assignments but allow unmatched
updates with zero effects. The adapter uses a parameterized CASE with public
constants to preserve this behavior. Known carrier length errors retain the
typed `VarcharLengthExceeded` failure and SQLSTATE `22001`.
The tested transaction abort and savepoint recovery remain native.
Protected plaintext does not reach PostgreSQL for this check.
Other custom type decorators and dialect variants remain unadmitted for protected mappings and query binds.
See [native VARCHAR mappings](walkthrough-migration.md#native-varchar-mappings).

## Signed integer storage

Native signed int2/int4/int8 mappings have bounded storage-only source and installed checks.
They require exact SmallInteger/Integer/BigInteger types and Python int or SQL NULL.
Bool, custom hooks, domains, width mismatches and coercions refuse. Protected
integer predicates, ordering, arithmetic, aggregates other than admitted direct
COUNT, and joins remain unadmitted.
Exact integer scalar client defaults have bounded construction evidence.
Server, callable, SQL, on-update and generated defaults still refuse. Existing NULL-presence predicates retain their bounded grammar.

Native prepared-plan selection controls when an overflow fails. Public bound
coercion constants preserve custom/generic timing, stale-row behavior and earlier
INSERT constraints without private numeric binds. Range failures retain typed
IntegerRangeExceeded and SQLSTATE 22003. Local storage admission retains the
published fixed-overhead cost; production qualification remains UNKNOWN. See
the [installed checkpoint](history/implementation-2026-10.md#integer-installed-lifecycle-checkpoint-2026-10-24).
The newer [default/state checkpoint](history/implementation-2026-10.md#integer-literal-default-installed-checkpoint-2026-10-24)
adds native default semantics and fixes attribute expiration after valid flushes.

## Internal DATE storage candidate

Exact native SQLAlchemy `Date`/PostgreSQL `DATE` mappings now have bounded
storage-only construction and lifecycle evidence. Values are exact Python
`datetime.date` or SQL NULL, from 0001-01-01 through 9999-12-31. Datetime objects,
subclasses, implicit conversions, custom hooks, variants, server/callable/SQL
defaults and on-update generation remain unadmitted. Literal date client defaults
retain native omission/None, ORM/dictionary/async state and transaction behavior
within the tested grammar. Public lock defaults use canonical `YYYY-MM-DD`.

DATE-bearing plans use strict lock/v8, `pg-date-days-be/v1` and, only for literal
defaults, `pg-date-default/v1`. Old v1-v7 behavior remains separate. The codec is
four signed big-endian days from 2000-01-01, bound through existing context/v2.
Non-NULL frames occupy 46 bytes and contain no search term. A count-only native
source-domain check refuses infinity and dates outside Python's domain during
operational planning and again under table locks before transition effects.
The schema-only compiler does not read application values.

Both physical layouts, rotations alongside independently searchable text,
genuine fresh restore, latest-value reverse/removal and a process that refuses
Cryptalis imports have local evidence. Protected DATE search, comparisons,
ordering, arithmetic, aggregates and joins remain unadmitted; existing NULL
presence grammar is retained. Bounded online capture also covers Date alongside
Boolean, signed integers and UUID; the [native scalar journey](../tests/test_online_scalars.py)
checks current values, interruption/resume, abort and native exit.
Broader external DATE applications, deployment cost qualification and all six
technical admission gates remain required. No full type or production
qualification follows from this internal candidate.

## Optional SQLModel bridge

An explicit `cryptalis.sqlmodel.attach` bridge targets synchronous and
asynchronous PostgreSQL sessions on SQLModel 0.0.48. It uses the same manifest,
authenticated tenant
scope, key policy and deployment pin. The returned session inherits native
`Session.exec` and keeps native scalar, tuple and entity results.
For an AsyncEngine, await attachment and use the returned async session factory.
Async `exec` uses native SQLModel result shaping after guarded statement
admission and awaited key preparation. Existing SELECT and mapped DML grammar
applies. Missing dependencies and unsupported versions refuse before connection
or key work. The ordinary SQLAlchemy attachment keeps its existing interface.

Only the exact pinned AutoString type can normalize to its checked native String
implementation. Its type, version, native method identities, flags, length,
collation and dialect implementation must match the finite contract.
Subclasses, changed SQL hooks, variants and changed implementations refuse.
The native String and existing expression checks still apply after normalization.
This exception admits no other custom protected type or query grammar.
The [SQLModel checkpoint](history/implementation-2026-10.md#optional-sqlmodel-template-checkpoint-2026-10-23)
owns exact runtime and pinned application evidence.

## Portable DDL

Required extensions: none. The selected equality representation uses built-in `bytea`, B-tree `bytea_ops`, and immutable expression indexes.
The compiler emits the tenant scope, qualified NULL contract, and declared constraint structure.

```sql
-- SPECIFIED packed CF1 equality, with an explicit tenant scope.
CREATE UNIQUE INDEX protected_email_unique
  ON protected_customer USING btree
  (tenant_id, (substring(email_payload FROM 15 FOR 32)) bytea_ops);
```

The final index needs framing checks for suite, flags, admitted generations, minimum lengths, and term presence.
A declared single-tenant table needs no synthetic public tenant column.
Generated/separate equality terms are compiler choices for admitted constraints. They do not admit protected joins or FKs.
Shape checks reject malformed bytes, but cannot certify encryption without keys.
[Database prerequisites](local-development.md#prerequisites) state migration/runtime role boundaries.
Exact generated CHECK/default/collation DDL preservation and deployment writer exclusion remain UNKNOWN.
The [slice 3 runtime checkpoint](history/implementation-2026-10.md#restricted-runtime-role-completion-2026-10-08) verifies local non-owning CRUD and tested persistent DDL/ownership denials.

## Capability admission

The seven baseline build slices must pass their real PostgreSQL tests before dependent product admission.
Independent research and internal implementations do not establish admitted support.
Every added type, operator, mapping, or platform must then pass all six technical gates:
G-ADAPTER, G-CRYPTO, G-QUERY, G-LIFECYCLE, G-PROVIDER, and G-POLICY.
[Status](status.md#missing-evidence-and-promotion-criteria) owns each gate's unchanged evidence requirements.
Admission also requires explicit per-capability leakage opt-in, exact grammar, bounded representations, published attack evidence, and approved measured costs.
G-RELEASE remains an additional release requirement. No local experiment or acknowledgment bypasses these gates.
The six-gate grouping and conservative unadmitted grammar assumptions are recorded in [reset notes](_reset/notes.md).

## Performance targets and recorded costs

The [current `09c635a` observation](status.md#current-performance-boundary) fails
all six scalar/tuple and full-entity read-latency targets in the warm 10k profile.
Indexed-column storage meets 2× at 1.52483×. Diagnostic traversal measurements and
a discarded candidate are retained; they do not qualify performance or explain
all historical anomalies. Earlier observations below retain their exact bounds.

The [earlier warm 10k observation](history/implementation-2026-10.md#sdk-protocol-and-early-tenant-admission-checkpoint-2026-10-28)
over `d7f2dba` reports added p95 of 1.8042 ms point, 3.5577 ms equality and
3.7962 ms IN-20. Equality misses 3 ms; isolated indexed-column storage measures
1.4976×. This is one local synchronous warm-provider cell with 40 samples per
workload. It does not supersede older cells, prove a deterministic regression,
or qualify production performance. A slower admission-cache experiment was
reverted; all three security admission checks remain.

The [integer observation](history/implementation-2026-10.md#integer-storage-cost-observation-2026-10-24)
records three storage-only 10k fixtures. All six scalar/entity point observations
meet 3 ms locally. Column bytes measure 22.5×/11.75×/6.375× native for int2/int4/int8.
No equality index is admitted, so this does not evaluate the 2× indexed-column
target. Public-ID batches do not qualify encrypted-value IN. The later
[local admission decision](history/decisions-2026-10.md#local-integer-storage-admission-2026-10-28)
accepts these storage-only costs for the assignment. Production performance
remains UNKNOWN.

The latest SQLModel integration profile has an initial six-target latency failure
and a passing unchanged-source follow-up. The cause remains UNKNOWN. The
[current checkpoint](history/implementation-2026-10.md#optional-sqlmodel-template-checkpoint-2026-10-23)
retains both observations and the prior-revision comparison. Production performance
qualification remains UNKNOWN.

**VERIFIED, earlier 10k observation at `3a21096`:** after shared identity and
SELECT type admission, all six added-p95 targets pass. Scalar/tuple point,
equality and IN-20 measure 1.5218, 2.2998 and 3.7486 ms. Entity values measure
1.4839, 2.0060 and 2.9876 ms. Isolated storage measures 1.52483× native.
The 100-pair warm synchronous TEXT profile keeps 150 Python hashes stable.
The [post-admission checkpoint](history/implementation-2026-10.md#post-admission-10k-profile-checkpoint-2026-10-23) owns exact scope, process observations and receipts.
Older scale observations below retain their original revision boundaries.


**SPECIFIED targets; local observations do not qualify a deployment:**

| Workload | Approved target |
|---|---|
| Point and equality reads | Added p95 ≤ 3 ms against the matched unprotected backend |
| IN with 20 values | Added p95 ≤ 8 ms |
| Protected column with equality index | Storage ≤ 2× the matched plaintext column plus its equality index |
| Write throughput | Undecided (D). No approved number |
| Maintenance pause | Undecided (D). No approved number |

**VERIFIED, current bounded projection cell:** the
[pinned 10,000-row checkpoint](history/implementation-2026-10.md#current-pinned-performance-checkpoint-2026-10-23)
measures warm synchronous TEXT with unique 53-byte names and public local keys.
Added p95 is 1.6294 ms for a point scalar, 2.0107 ms for equality tuples and
2.5330 ms for IN-20 tuples. Isolated column/index storage is 1.5248× native.
These meet the local targets in that cell. They do not qualify entity paths,
million-row scale, remote providers or deployment performance.
The subsequent full-entity extension measures 1.2622/2.6119/2.8613 ms added p95
for point/equality/IN-20 on the same 10,000-row distribution.
Those entity paths also meet the local targets. Their separate raw samples
and exact source boundaries appear in the same checkpoint.
The later 100,000-row run also meets all six local read targets.
Entity added p95 is 1.2667/1.7083/2.5670 ms for point/equality/IN-20,
with isolated storage at 1.5296× native. Its process resource observations
exclude database-server CPU and memory.

The subsequent prepared million-row profile completes the product transition
and meets all six local targets. Entity added p95 is 2.4646/2.1569/2.5735 ms
for point/equality/IN-20, with isolated storage at 1.4372× native.
Its stable 137-file receipts include bounded row lease recovery and explicit
fixture maintenance before planning. The [current checkpoint](history/implementation-2026-10.md#current-pinned-performance-checkpoint-2026-10-23)
owns raw evidence and process resource limits. Remote/concurrent/platform
qualification and the historical page-query cause remain UNKNOWN.

**VERIFIED, recorded earlier revision only:** [million-row CF1 receipt](../spikes/revamp/results/gate-performance.json), warm PostgreSQL 16.15 and memory-only local keys.
These observations predate the latest DISTINCT change and do not measure the current adapter.

| Workload | Native p95 ms | Protected p95 ms | Added p95 ms | Target result |
|---|---:|---:|---:|---|
| Point entity, 100 samples | 0.897 | 4.150 | 3.253 | Misses 3 ms |
| Equality entity, 100 samples | 0.928 | 6.517 | 5.589 | Misses 3 ms |
| IN-20 entities, 100 samples | 1.093 | 16.148 | 15.055 | Misses 8 ms |
| Plaintext-filter range/prefix/page, 20 samples | 23.852 | 127.098 | 103.246 | About 5.3× native. Full entity includes protected email |

The page-query anomaly has an unknown cause. Slice 4 source inspection corrects the former plaintext-only label:
[`browse_customers`](../spikes/revamp/plain_app.py) calls `active_customers`, which selects the complete Customer including email.
The historical receipt is retired as current-product cost evidence. The measurements and unexplained historical cause remain preserved.
Separate expression admission, statement compilation/cache behavior, driver/database time, row decoding, and materialization in the matched workload.
No encrypted range/prefix/order capability follows from these plaintext queries.

## Database evidence

**VERIFIED, bounded product cell:** PostgreSQL 16 storage/search/transition suites include protected DISTINCT refusal.
[Status](status.md) owns current revision-bound evidence. Earlier single-user/service research remains [archived provenance](research/revamp-evidence.md).
No production cell is qualified. Provider deployment and authenticated publication remain unqualified; independent human review is unavailable.

| Cell | Classification and qualification |
|---|---|
| Selected Python/SQLAlchemy/psycopg/PostgreSQL 16 sync and async | SUPPORTED design scope. Exact runtime/driver/OS cell remains UNKNOWN |
| SQLite labs, single-user physical probes, old generated-ID adapter | INTERNAL ONLY evidence. Cannot qualify the selected contract |
| PostgreSQL majors other than 16 | Outside the selected release runtime. Separate admission required |
| PostgreSQL 16 managed services | SUPPORTED design scope. RDS/Aurora, Cloud SQL, Azure, Supabase, and Neon cells remain UNKNOWN |

The selected equality index requires no extension. No provider extension allowance supplies missing qualification.

## Native identifier deparser admission

**IMPLEMENTED, bounded verification:** PostgreSQL 16 type/function keyword
identifiers can require quotes in catalog deparsing even when SQLAlchemy emits
them without quotes. Frame admission accepts only the same declared column's
known native quoted/unquoted nested forms. It checks the exact single-column
constraint dependency and full frame policy. A dump-restored flattened form
still requires its exact inspected restatement; equivalent arbitrary SQL is
not admitted. Search indexes retain exact structural admission and use native
`pg_catalog.quote_ident` for the expected expression spelling. See the
[identifier checkpoint](history/implementation-2026-10.md#postgresql-identifier-admission-correction-2026-10-28)
for the exact tested cells and remaining qualification limits.

The same installed identifier-fix wheel also passes genuine int4 `integer`
keyword fresh recovery in both layouts. The existing integer harness verifies
exact restatement admission, latest edits, native types and package-free removal.
This does not extend that fresh-recovery claim to keyword text or other names.
See the [fresh checkpoint](history/implementation-2026-10.md#keyword-identifier-fresh-recovery-2026-10-28).

## Persisted Date reader compatibility

New protection plans use `pg-date-days-be/v1`. The reader also accepts the exact
historical `date-ordinal-u32/v1` descriptor, digest and required-reader identity
in an otherwise valid Date-bearing lock. The codec is never inferred from v8.
Both encodings authenticate before returning an exact Python Date. PG-epoch
literal defaults and their reader tag remain separate from the default-free
ordinal profile. Changing codecs is a representation change in the semantic
diff; automatic conversion of an ACTIVE deployment remains unimplemented.
An actual retained ordinal backup passes new source and installed-reader
recovery through latest-data removal. See the
[combined checkpoint](history/implementation-2026-10.md#consolidated-implementation-checkpoint-2026-10-29).
