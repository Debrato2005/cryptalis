# Query compatibility

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

## Full capability matrix

| Operation | Classification | Contract or reason for rejection |
|---|---|---|
| Text storage/read/write, entity/scalar projection, SQL NULL | SUPPORTED | Randomized authenticated payload. Preserve exact str, empty text, NULL, native ORM state, and expected row/tenant context |
| COUNT of a directly protected column | SUPPORTED | Bounded local implementation of native non-NULL counts, optional output labels, aliases, public grouping and public FILTER predicates. Non-distinct windows admit public partitions/order and native bounds. Custom dispatch and protected argument/filter/partition/order expressions refuse |
| Boolean storage/read/write, entity/table/scalar projection, SQL NULL | SUPPORTED | Typed authenticated one-byte values, native Boolean input processing and literal client defaults. No Boolean equality term. [Bounded evidence](status.md#boolean-storage-checkpoint-2026-10-23) |
| Date storage/read/write and SQL NULL | SUPPORTED | Exact Python date values in years 1 through 9999; typed four-byte ordinal and lock/v8. Storage-only, native sync/async values and latest-value removal. Non-finite/BC/out-of-range source dates refuse before migration effects |
| UUID value storage/read/write and SQL NULL | SUPPORTED | Exact standard native UUID mappings and Python UUID inputs, including nil; sixteen authenticated network-order bytes and lock/v9. Storage-only; defaults, coercions and custom mappings refuse. Public record/tenant UUIDs keep their separate context contract |
| Signed integer storage/read/write and SQL NULL | SUPPORTED | Exact int2/int4/int8 mappings and width-bound Python ints, literal client defaults, native failure/transaction behavior and typed fixed-width CF1. Storage-only; the fixed authentication overhead is published in the local cost profile |
| Mapped dictionary INSERT without RETURNING | SUPPORTED | Attached sync/async `Session.execute(insert(Model), list[dict])`, explicit typed IDs and tenant scope, copied attribute dictionaries, native NULL/grouping, autoflush, uniqueness and transaction behavior. Other bulk routes remain unadmitted |
| Mapped dictionary INSERT with one protected scalar RETURNING | SUPPORTED | Exactly one direct protected mapped column. Preserve native Row/scalar keys/types, grouping, paging, parameter-order requests and empty identity map. Authenticate against exact prepared input. Tuple/entity, label/expression/alias, loader-option and caller return_defaults forms remain unadmitted |
| Scoped mapped dictionary UPDATE | SUPPORTED | Attached sync/async TEXT, VARCHAR and Boolean targets, explicit tenant-column equality, typed IDs, nonempty list of dictionaries and synchronize_session=False. Preserve native omission/NULL, grouping, repeated IDs, zero matches and transactions. Single-tenant, Core and RETURNING routes remain unadmitted |
| Scoped mapped single-record DELETE | SUPPORTED | Attached sync/async execute, exact typed tenant and application-record equalities, no external parameters or RETURNING, and synchronize_session=False. Preserve native row counts and transactions. Unsupported custom AST classes refuse before execution |
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
The adapter rejects extra predicates, embedded values, version counters,
dynamic defaults, read-only mapped properties, SQL-producing type hooks and
type variants. Ordinary Python public-field bind processors remain native.
The ordered input ledger checks each emitted group and complete consumption.
The [bulk UPDATE checkpoint](status.md#scoped-mapped-bulk-update-checkpoint-2026-10-23) owns the earlier TEXT evidence.
The [VARCHAR checkpoint](status.md#native-varchar-mapped-update-checkpoint-2026-10-23)
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
The [expanded SELECT checkpoint](status.md#expanded-select-projection-checkpoint-2026-10-23)
owns current projection evidence. The earlier
[SELECT type checkpoint](status.md#finite-select-type-admission-checkpoint-2026-10-23)
owns its recorded native refusal and compatibility evidence.
Tenant-scoped uniqueness uses PostgreSQL's original qualified NULL behavior. Unqualified partial/compound or NULLS NOT DISTINCT variants must reject at plan time.

For scoped mapped DELETE, use `delete(Model)` with exact typed tenant and record
equalities and `execution_options={"synchronize_session": False}`. The route
admits one application-assigned UUID or int64 record on a tenant-column table.
It returns native row counts. Core DELETE, external parameter dictionaries,
RETURNING, inheritance, version counters and other predicate shapes refuse.
Ordinary ORM flush DELETE retains its existing native lifecycle contract.
Both routes require native compiler nodes. Custom AST classes refuse before SQL.
The [DELETE checkpoint](status.md#mapped-delete-admission-checkpoint-2026-10-23)
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
regression are recorded in the [identity planning checkpoint](status.md#identity-variant-planning-checkpoint-2026-10-23).

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
The [searchable application checkpoint](status.md#searchable-sqlmodel-application-checkpoint-2026-10-23)
records the bounded native and unchanged-application evidence.
Nondeterministic collations, citext, bpchar padding, locale-sensitive operators, custom types and changed normalizers remain outside the current text profile.
Each required profile needs exact equivalence and separate admission. This does not require every locale or arbitrary host hook.
The compiler rejects a constraint or mapping it cannot preserve exactly. Generic CHECK/FK/default/collation preservation is UNKNOWN.
[Lifecycle](lifecycle.md#integrated-lifecycle-checkpoint-2026-10-07) bounds the current verifier's source-index and scoped-uniqueness evidence.
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
the [installed checkpoint](status.md#integer-installed-lifecycle-checkpoint-2026-10-24).
The newer [default/state checkpoint](status.md#integer-literal-default-installed-checkpoint-2026-10-24)
adds native default semantics and fixes attribute expiration after valid flushes.

## Optional SQLModel bridge

An explicit `cryptalis.sqlmodel.attach` bridge admits synchronous PostgreSQL
sessions on SQLModel 0.0.48. It uses the same manifest, authenticated tenant
scope, key policy and deployment pin. The returned session inherits native
`Session.exec` and keeps native scalar, tuple and entity results.
Missing dependencies, unsupported versions and async engines refuse before
connection or key work. The ordinary SQLAlchemy attachment keeps its existing interface.

Only the exact pinned AutoString type can normalize to its checked native String
implementation. Its type, version, native method identities, flags, length,
collation and dialect implementation must match the finite contract.
Subclasses, changed SQL hooks, variants and changed implementations refuse.
The native String and existing expression checks still apply after normalization.
This exception admits no other custom protected type or query grammar.
The [SQLModel checkpoint](status.md#optional-sqlmodel-template-checkpoint-2026-10-23)
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
[Database prerequisites](../README.md#database-prerequisites) state migration/runtime role boundaries.
Exact generated CHECK/default/collation DDL preservation and deployment writer exclusion remain UNKNOWN.
The [slice 3 runtime checkpoint](status.md#restricted-runtime-role-completion-2026-10-08) verifies local non-owning CRUD and tested persistent DDL/ownership denials.

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

The [integer observation](status.md#integer-storage-cost-observation-2026-10-24)
records three storage-only 10k fixtures. All six scalar/entity point observations
meet 3 ms locally. Column bytes measure 22.5×/11.75×/6.375× native for int2/int4/int8.
No equality index is admitted, so this does not evaluate the 2× indexed-column
target. Public-ID batches do not qualify encrypted-value IN. The later
[local admission decision](decisions.md#local-integer-storage-admission-2026-10-28)
accepts these storage-only costs for the assignment. Production performance
remains UNKNOWN.

The latest SQLModel integration profile has an initial six-target latency failure
and a passing unchanged-source follow-up. The cause remains UNKNOWN. The
[current checkpoint](status.md#optional-sqlmodel-template-checkpoint-2026-10-23)
retains both observations and the prior-revision comparison. Production performance
qualification remains UNKNOWN.

**VERIFIED, earlier 10k observation at `3a21096`:** after shared identity and
SELECT type admission, all six added-p95 targets pass. Scalar/tuple point,
equality and IN-20 measure 1.5218, 2.2998 and 3.7486 ms. Entity values measure
1.4839, 2.0060 and 2.9876 ms. Isolated storage measures 1.52483× native.
The 100-pair warm synchronous TEXT profile keeps 150 Python hashes stable.
The [post-admission checkpoint](status.md#post-admission-10k-profile-checkpoint-2026-10-23) owns exact scope, process observations and receipts.
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
[pinned 10,000-row checkpoint](status.md#current-pinned-performance-checkpoint-2026-10-23)
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
fixture maintenance before planning. The [current checkpoint](status.md#current-pinned-performance-checkpoint-2026-10-23)
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

### Slice 3 local profile: 2026-10-08

**VERIFIED, bounded package adapter:** `.venv/bin/python tests/profile_sqlalchemy_adapter.py`.
The [hashed receipt](_reset/slice3-performance.json) records 5,000 synthetic rows, 100-row pages, and 40 paired samples.
The local cell uses Python 3.12.3, SQLAlchemy 2.1.3, psycopg 3.3.6, cryptography 50.0.2, PostgreSQL 16.15, and warm local keys.
Both paths use identical data and application-generated UUIDs. Queries consume and compare native values and types.
Protected fixtures are seeded through ordinary attached ORM writes. Empty fixture conversion to `bytea` is test setup, not product apply.
The final main-thread run followed the full suite and cache proof, with no concurrent Cryptalis checks.
Shared-host activity remains uncontrolled. The receipt retains earlier runs and their limits.

| Current bounded workload | Native p50/p95 ms | Attached p50/p95 ms | Added p95 ms |
|---|---:|---:|---:|
| Point entity | 0.435 / 0.618 | 1.715 / 2.903 | 2.285 |
| Unprotected range/prefix/page projection | 1.428 / 1.906 | 2.238 / 2.810 | 0.904 |

The point result is within the 3 ms added-p95 target in this local run. It does not qualify the deployment target.
Earlier runs vary with shared-host activity and code changes. The receipt retains those observations without deployment qualification.
Both plaintext page paths recorded 60 compilation-cache hits and one miss.
Protected entity statements disable compilation caching to prevent retention of another operation's tenant, point, or prepared keys.
Native unprotected compilation caching remains enabled.

Ten extra cProfile page queries separate exclusive Python time into categories.
Attached admission/guard cost 0.285 ms/query, compilation/cache 0.017 ms, driver/database 1.956 ms,
and decoding/materialization 0.065 ms. Native compilation/cache cost 0.015 ms, driver/database 1.590 ms,
and decoding/materialization 0.048 ms. Dispatch, key preparation, and other ORM/engine work remain separate in the receipt.
Profiling changes timings. Cumulative calls overlap; exclusive categories do not.
Driver time combines network wait and PostgreSQL work; those parts are not independently separated.
This small plaintext profile does not explain the historical million-row anomaly. Its cause remains **UNKNOWN**.
No equality/IN, isolated storage/index, sustained-write, remote-provider, or async performance qualification was performed.
Adoption in this fixture used one manifest, one attach call, authenticated tenant scope, and application-assigned IDs.
No business-query or model declarations changed between native and attached paths.
The later runtime checkpoint verifies separate credentials and fixture grants; deployment enforcement remains unverified.

### Slice 4 local million-row profile: 2026-10-08

**VERIFIED, local warm synchronous cell only:** the [receipt](_reset/slice4-performance.json) binds the final source hashes to 1,000,000 rows per path.
Both native and attached applications use the restricted runtime login, application UUIDs, identical 53-byte synthetic text and fully consumed results.
Owner credentials perform only fixture setup, ANALYZE, storage inspection and independent plan inspection. No extension is required.
Each workload has 10 warmups and 100 alternating paired samples. Entity samples expunge the identity map and materialize fresh objects.
Added p95 means attached p95 minus native p95; the receipt also records paired median differences and p99 estimates.

| Current workload | Native p50/p95 ms | Attached p50/p95 ms | Added p95 ms |
|---|---:|---:|---:|
| Point entity | 0.476 / 0.790 | 2.245 / 3.126 | 2.336 |
| Equality entity | 0.383 / 0.821 | 2.255 / 3.382 | 2.561 |
| IN-20 entities | 1.116 / 1.543 | 3.300 / 4.548 | 3.005 |
| Plain projection, range/prefix, broad OFFSET, 100 rows | 49.050 / 111.791 | 64.975 / 134.355 | 22.564 |
| Protected entities, plaintext range/prefix, five rows | 0.540 / 0.776 | 2.927 / 3.976 | 3.199 |

Point/equality and IN-20 meet their selected added-p95 targets in this run. No target was invented for either page workload.
The isolated protected column plus equality index is **1.4928×** the matched plaintext column plus equality index, below the 2× target.
The plaintext index is on name; the protected index is on tenant plus full term, as selected by the compiler. Whole-relation ratios are not the target denominator.
PostgreSQL plans used the generated expression index for equality and IN-20. There is no hidden filtering or result refill.
Both plain-projection paths recorded 109 cache hits and one miss; protected projections/predicates disable caching.
The receipt separates admission, compilation, key/term preparation, driver/database wait, decoding and other ORM work for all five workloads.
Server plans also record buffer reads and execution time; larger protected heaps affect ordinary plaintext page scans.
These observations do not establish the cause of the old 127/24 ms receipt. Its full-entity query and former plaintext-only label are retired as current-product evidence.
The current structural control differs in IDs, tenancy, distribution, selectivity and schema; historical causality remains UNKNOWN.

An earlier diagnostic equality run missed 3 ms at 3.565 ms added p95. Profiling removed repeated generated-node comparisons and unnecessary compilation.
The final source retained all admission checks and regression controls. Shared-host activity is uncontrolled; the earlier measurement remains in the receipt.
Seeding observed about 29,873 native and 10,648 attached rows/s. One 2,000-row chunk reached key expiry, rolled back and recovered with fresh keys.
An independent elapsed-expiry test checks no SQL/rows before recovery. Expiry limits were unchanged; a second profile retry failure would stop the run.
1,000 committed updates in ten batches observed about 7,493 native and 3,654 attached rows/s. This is an observation, not a write budget or load qualification.
Cold/remote providers, async costs, sustained-load/platform qualification and deployment admission remain unverified. All seven full gates remain UNKNOWN.

### Historical storage and transition costs

The customer relation/index total rose from 192,692,224 to 350,707,712 bytes, plus 11,100,160 bytes of operation/chunk tables.
That whole-relation total does not establish the per-column 2× target. Isolated protected-column/index evidence remains UNKNOWN.
Protection/verification took 128.821 s. Observed pause with VACUUM/ANALYZE was 130.380 s. Neither value is an approved pause budget.
Observed WAL/temp deltas and CPU/RSS are in the receipt. Unrelated activity can affect cluster/database deltas.

The [10,000-row cost receipt](../spikes/revamp/results/gate-write-cost.json) also measures an earlier adapter revision before the latest DISTINCT change.
It records paired results and 400 committed updates. It cannot establish current-revision performance or sustained write qualification.
The receipt's historical `current_adapter` labels remain unchanged provenance.
Database-only surrogate array measurements are INTERNAL ONLY, separate from actual CF1 and whole-backend costs.
Their bundle storage ratios do not establish the admitted equality column's target.

## Database evidence

**VERIFIED, bounded product cell:** PostgreSQL 16 storage/search/transition suites include protected DISTINCT refusal.
[Status](status.md) owns current revision-bound evidence. Earlier single-user/service research remains [archived provenance](research/revamp-evidence.md).
No production cell is qualified. No production provider, authenticated deployment procedure, or independent review is available.

| Cell | Classification and qualification |
|---|---|
| Selected Python/SQLAlchemy/psycopg/PostgreSQL 16 sync and async | SUPPORTED design scope. Exact runtime/driver/OS cell remains UNKNOWN |
| SQLite labs, single-user physical probes, old generated-ID adapter | INTERNAL ONLY evidence. Cannot qualify the selected contract |
| PostgreSQL majors other than 16 | Outside the selected release runtime. Separate admission required |
| PostgreSQL 16 managed services | SUPPORTED design scope. RDS/Aurora, Cloud SQL, Azure, Supabase, and Neon cells remain UNKNOWN |

The selected equality index requires no extension. No provider extension allowance supplies missing qualification.
