# Query compatibility

**SPECIFIED:** selected scope and query contract. **No production cell is qualified.**
SUPPORTED selects design scope. IMPLEMENTED means code exists, with its boundary stated.
VERIFIED means named evidence exercises the stated property on its recorded revision and cell. It does not imply release qualification.
[Status](status.md) owns current evidence. [Security](security.md) owns collision, omission, replay, NULL-presence, and host-compromise limits.

## Support vocabulary

Every capability is exactly one of **SUPPORTED**, **UNSUPPORTED BY DESIGN**, or **INTERNAL ONLY**.
An unsupported capability remains rejected until admission changes its classification.
A research mechanism or receipt is INTERNAL ONLY and cannot establish public support.
All normative sections here are SPECIFIED. Recorded-cost sections are VERIFIED only at their stated historical measurement scope.

## Supported stack

Python 3.12+, SQLAlchemy 2.x, psycopg 3 sync and async, PostgreSQL 16.
Every protected value is text. Other protected types and PostgreSQL majors are UNSUPPORTED BY DESIGN until admission.
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
comparisons/ranges, ORDER BY, LIKE/prefix/contains, regex, SUM/AVG/MIN/MAX, general DISTINCT, protected-field joins, and non-text types.
The recommended adoption path is manifest → plan → staging apply plus the attached application suite → qualified production apply → decrypt-back exit.
Plan refuses server-generated keys, unsupported types, small-domain searchable fields, missing tenancy, and unsupported writers.
Attach rejects unsupported queries. Application tests on staging expose query-level incompatibilities before production.
This path does not guarantee zero changes and adds no command or mode.
Adoption costs a manifest, one attach call, typed replacements for opaque protected writers, and application-generated primary keys.
Rollback/removal transforms current data through decrypt-back until explicit finalization retires its recovery dependencies.

## Full capability matrix

| Protected-field operation | Classification | Contract or reason for rejection |
|---|---|---|
| Text storage/read/write, entity/scalar projection, SQL NULL | SUPPORTED | Randomized authenticated payload. Preserve exact str, empty text, NULL, native ORM state, and expected row/tenant context |
| Equality `==` and `IN` | SUPPORTED | Declared full tenant/domain-bound HMAC term. Preserve typed binds and native NULL/empty-list truth tables |
| Tenant-scoped uniqueness | SUPPORTED | Full term plus tenant scope in a race-safe native unique index. Explicit single-tenant declaration supplies its one scope |
| Comparisons `<`, `<=`, `>`, `>=`, BETWEEN/ranges | UNSUPPORTED BY DESIGN | No admitted range representation |
| ORDER BY and sorted pagination on protected values | UNSUPPORTED BY DESIGN | No admitted order representation. Ciphertext ordering is forbidden |
| LIKE, ILIKE, prefix/startswith, contains, suffix | UNSUPPORTED BY DESIGN | No admitted pattern/text grammar or representation |
| Regex, fuzzy/similarity, full text | UNSUPPORTED BY DESIGN | No admitted exact query or text-search contract |
| SUM, AVG, MIN, MAX, arithmetic | UNSUPPORTED BY DESIGN | Selected payload/equality format does not implement these operations |
| General DISTINCT, DISTINCT ON, GROUP BY, COUNT DISTINCT | UNSUPPORTED BY DESIGN | Randomized-payload comparison changes logical semantics. A spike's scoped aggregate rewrite does not admit this family |
| Joins/FKs on protected fields | UNSUPPORTED BY DESIGN | No admitted shared search-domain or protected-FK contract |
| `!=`, NOT IN, field-to-field equality, other unadmitted functions/operators | UNSUPPORTED BY DESIGN | Approved scope does not independently admit these shapes |
| Non-text protected values, JSON predicates, custom protected types | UNSUPPORTED BY DESIGN | Text is the only admitted protected type |
| Opaque raw SQL/COPY protected writes and unknown external writers | UNSUPPORTED BY DESIGN | Reject guarded routes. Plan blocks protection unless the deployment excludes separate routes |
| Research range/prefix arrays, order candidates, scoped aggregate helpers, internal binary projections | INTERNAL ONLY | Experiments and adapter machinery, not public query capabilities |

Plaintext fields retain native query semantics, including ranges, order, aggregates, and joins through unprotected keys.
Tenant-scoped uniqueness uses PostgreSQL's original qualified NULL behavior. Unqualified partial/compound or NULLS NOT DISTINCT variants must reject at plan time.

## Query semantics

Compare every admitted shape with the same native PostgreSQL application.
Test typed/reversed/late binds, AND/OR compositions of admitted predicates, aliases, projections, pagination, and outer joins through unprotected keys.
Preserve SQL UNKNOWN. Preserve NULL elements and empty `IN` lists. Reject an unadmitted nested operator before SQL.
NULL payloads remain SQL NULL. Empty strings encrypt normally. Reject PostgreSQL-forbidden NUL text before SQL.
Strict UTF-8 never changes composed/decomposed text or silently casefolds it.

Text equality requires inspected deterministic exact equivalence, such as a qualified `C` collation.
Nondeterministic collations, citext, bpchar padding, locale-sensitive operators, custom types, and changed normalizers are UNSUPPORTED BY DESIGN until admission.
The compiler rejects a constraint or mapping it cannot preserve exactly. Generic CHECK/FK/default/collation preservation is UNKNOWN.
[Lifecycle](lifecycle.md#integrated-lifecycle-checkpoint-2026-10-07) bounds the current verifier's source-index and scoped-uniqueness evidence.
A searchable small domain fails planning because enumeration can label equality classes. No arbitrary size threshold substitutes for leakage evidence.

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
Exact generated CHECK/default/collation DDL preservation and non-owning runtime enforcement remain UNKNOWN.

## Capability admission

Only after all seven build slices pass their real PostgreSQL tests can range, order, prefix, or text-search work start.
Every added type, operator, mapping, or platform must then pass all six technical gates:
G-ADAPTER, G-CRYPTO, G-QUERY, G-LIFECYCLE, G-PROVIDER, and G-POLICY.
[Status](status.md#missing-evidence-and-promotion-criteria) owns each gate's unchanged evidence requirements.
Admission also requires explicit per-capability leakage opt-in, exact grammar, bounded representations, published attack evidence, and approved measured costs.
G-RELEASE remains an additional release requirement. No local experiment or acknowledgment bypasses these gates.
The six-gate grouping and conservative unadmitted grammar assumptions are recorded in [reset notes](_reset/notes.md).

## Performance targets and recorded costs

**SPECIFIED targets, not achieved:**

| Workload | Approved target |
|---|---|
| Point and equality reads | Added p95 ≤ 3 ms against the matched unprotected backend |
| IN with 20 values | Added p95 ≤ 8 ms |
| Protected column with equality index | Storage ≤ 2× the matched plaintext column plus its equality index |
| Write throughput | Undecided (D). No approved number |
| Maintenance pause | Undecided (D). No approved number |

**VERIFIED, recorded earlier revision only:** [million-row CF1 receipt](../spikes/revamp/results/gate-performance.json), warm PostgreSQL 16.15 and memory-only local keys.
These observations predate the latest DISTINCT change and do not measure the current adapter.

| Workload | Native p95 ms | Protected p95 ms | Added p95 ms | Target result |
|---|---:|---:|---:|---|
| Point entity, 100 samples | 0.897 | 4.150 | 3.253 | Misses 3 ms |
| Equality entity, 100 samples | 0.928 | 6.517 | 5.589 | Misses 3 ms |
| IN-20 entities, 100 samples | 1.093 | 16.148 | 15.055 | Misses 8 ms |
| Plaintext range/prefix/page, 20 samples | 23.852 | 127.098 | 103.246 | About 5.3× native. No protected field in this query |

The plaintext page-query anomaly has an unknown cause. Profile it in the SQLAlchemy integration slice before attributing its cost.
Separate expression admission, statement compilation/cache behavior, driver/database time, row decoding, and materialization in the matched workload.
No encrypted range/prefix/order capability follows from these plaintext queries.

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

**VERIFIED, recorded research cells only:** single-user PostgreSQL 16.2 physical experiments and PostgreSQL 16.15 service probes supplied narrow local evidence.
[Status](status.md) and [archived experiment provenance](research/revamp-evidence.md) retain their exact counts and limits.
The latest DISTINCT rejection has offline admission evidence only and needs real PostgreSQL regression.
No production cell is qualified. No production provider, authenticated deployment procedure, or independent review is available.

| Cell | Classification and qualification |
|---|---|
| Selected Python/SQLAlchemy/psycopg/PostgreSQL 16 sync and async | SUPPORTED design scope. Exact runtime/driver/OS cell remains UNKNOWN |
| SQLite labs, single-user physical probes, old generated-ID adapter | INTERNAL ONLY evidence. Cannot qualify the selected contract |
| PostgreSQL majors other than 16 | UNSUPPORTED BY DESIGN until admission |
| PostgreSQL 16 managed services | SUPPORTED design scope. RDS/Aurora, Cloud SQL, Azure, Supabase, and Neon cells remain UNKNOWN |

The selected equality index requires no extension. No provider extension allowance supplies missing qualification.
