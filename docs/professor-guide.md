# Explaining Cryptalis

Cryptalis protects selected database columns inside a Python application. The
application still works with ordinary values. PostgreSQL stores authenticated
ciphertext and, for explicitly searchable fields, a keyed equality term.

This guide explains the college project. It does not change the production
requirements in [status](status.md) or mark an unfinished objective complete.
Live provider qualification and independent security reviews are outside the
assignment demonstration.

## The problem

A database dump normally reveals values such as names and email addresses.
Encrypting those values hides their contents, but ordinary database equality
and unique indexes then stop working. Cryptalis keeps a bounded set of those
operations available while moving encryption keys outside the database.

## Where protection happens

```mermaid
flowchart LR
    Manifest["Manifest: fields, tenancy, allowed searches"] --> Compiler
    Schema["Native schema and ORM mappings"] --> Compiler
    Compiler["Read-only compiler"] --> Plan["Immutable protection plan"]
    Plan --> Adapter["SQLAlchemy / SQLModel attachment"]
    App["Application: ordinary Python values"] <-->|"CRUD and admitted queries"| Adapter
    Provider["Key provider outside PostgreSQL"] -->|"Prepared keys"| Adapter
    Adapter <-->|"Ciphertext and declared equality terms"| DB[("PostgreSQL 16")]
```

The manifest selects protection; it does not contain secret keys. The compiler
checks the schema and rejects incompatible plans. The attachment handles admitted
application operations. The transition engine changes the stored representation.
The host application still authenticates users and authorizes tenant access.

## Why equality still works

```mermaid
flowchart TD
    Value["Plaintext value"] --> Encrypt["Randomized authenticated encryption"]
    Value --> Term["Keyed equality term, when declared"]
    Context["Tenant + field + row + generation"] --> Encrypt
    Scope["Tenant + field + search generation"] --> Term
    Encrypt --> Frame["CF1 stored frame"]
    Term --> Frame
    Query["Equality / IN search value"] --> QueryTerm["Same scoped keyed-term construction"]
    QueryTerm --> Index["Native PostgreSQL B-tree lookup"]
    Frame --> Index
    Index --> Verify["Authenticate returned frames before releasing values"]
    Verify --> Result["Ordinary Python result"]
```

Randomized encryption produces different payloads for repeated values. The
equality term lets PostgreSQL find matching rows without receiving the search
plaintext. That term reveals equal-value groups, frequencies and query patterns.
The manifest requires explicit acceptance of this leakage. This is searchable
encryption with a stated trade-off, not a claim that database activity is hidden.

## What the implementation demonstrates

| Area | Recorded local behavior | Important boundary |
|---|---|---|
| Values | TEXT/VARCHAR and storage-only Boolean; internal signed-integer candidate | Integer full admission and additional types remain pending |
| Search | Exact equality, IN, admitted NULL/negative forms and tenant-scoped uniqueness | Protected ranges, ordering, text patterns and general aggregates refuse |
| Reports | Non-NULL counts, one-tenant distinct counts, public count filters/windows and public DISTINCT with encrypted filters | General protected grouping, joins and other aggregate families remain pending |
| Application integration | Sync/async SQLAlchemy and a synchronous SQLModel bridge | Selected operations and mappings, not arbitrary SQL |
| Migration | Atomic resumable chunks, verification and publication-gated cutover | Initial online text capture still needs a final write pause |
| Recovery | Protected backups, fresh-cluster adoption and stale-authority refusal | Local fixtures do not establish production disaster-recovery targets |
| Key changes | Root rewrap, payload rotation and search rotation | A local provider and SDK controls do not establish live cloud custody |
| Exit | Latest-value decrypt-back, metadata restoration and package-free restart | Retained backups can still need old keys and readers |
| Delivery | CLI, Doctor, repeat builds and dependency inventory | No production-qualified release |

These statements summarize [implementation status](status.md), not new test runs.
The [34-objective ledger](BUILD_CHECKLIST.md#objective-ledger) retains the full
requirements and each remaining gap.

## Work still open

The repository's baseline is broader than this demonstration. These are actual
implementation gaps, even with production qualification excluded:

| Area | Remaining work |
|---|---|
| Protected queries | Ranges, ordering, exact text patterns, general grouping/joins and SUM/AVG/MIN/MAX |
| Types | Additional scalar and structured JSON contracts; full admission of the internal integer candidate |
| Integration | Broader bulk/RETURNING routes, upserts, trigger/cascade cases and automatic query/writer inventory |
| Migration | Parallel/adaptive execution and broader online type coverage |
| Measurements | Cold and saturated workloads, larger concurrent profiles, resource limits and pause/recovery budgets |

These features need their own stored representations, query contracts or
integration work. The counts added here reuse existing storage. Live provider
qualification, production deployment assurance and independent security review
remain outside the college demonstration.

## Count reports over encrypted values

`COUNT(column)` counts non-NULL stored values without decrypting every row.
For equality-enabled fields, `COUNT(DISTINCT column)` counts the existing equality
terms within one tenant. Randomized
ciphertexts are not used as distinct-value keys.

For the values `Ada`, `Ada`, NULL and an empty string, the row count is four,
the non-NULL count is three and the distinct non-NULL count is two.

```mermaid
flowchart LR
    Frames[("Stored CF1 frames")] --> Present["COUNT: non-NULL values"]
    Frames --> Terms["Existing equality terms"]
    Terms --> Distinct["COUNT DISTINCT: logical value classes"]
    Present --> Result["Ordinary integer results"]
    Distinct --> Result
```

The normal SQLAlchemy API and result keys remain available:

```python
present = func.count(Customer.name)
distinct_names = func.count(Customer.name.distinct()).label("distinct_names")
row = session.execute(select(present, distinct_names)).one()
non_null_total = row._mapping[present]
different_values = row.distinct_names
```

Public fields can also control the report without decrypting the protected column:

```python
eligible = func.count(Customer.name).filter(Customer.age >= 18)
running = func.count(Customer.name).over(order_by=Customer.id, rows=(None, 0))
```

The first expression counts non-NULL names for adults. The second reports a
running non-NULL count in public ID order. Protected filters and sort keys still
need their own query admission.

Use the attached session and declared single tenancy from the walkthrough.
For a tenant-column table, add a direct `Customer.tenant_id == tenant_id` filter,
or group by `Customer.tenant_id` to report each tenant separately. A global
distinct count across tenants refuses because their terms are intentionally
different even when their plaintext values match.
Counts trust the database's aggregate result; they do not authenticate every
frame or prove that the database returned complete results. Other aggregate
families and general protected grouping remain unfinished objectives.

### Measured count cost

![Native and protected non-NULL and distinct-count p95 latency for 1,000 and 10,000 rows.](images/count-latency.svg)

| Rows | Operation | Native p95, ms | Protected p95, ms |
|---:|---|---:|---:|
| 1,000 | Non-NULL count | 0.32 | 1.05 |
| 1,000 | Distinct count | 0.43 | 1.72 |
| 10,000 | Non-NULL count | 0.73 | 1.47 |
| 10,000 | Distinct count | 2.47 | 4.02 |

These [local paired samples](_reset/count-performance-20261028.json) compare
the same synchronous queries and data distribution on native text and attached
CF1 fixtures. Each path has five warmups and 31 alternating samples. Both return
909 or 9,090 non-NULL values and 257 distinct values. The query returns one
integer rather than transferring all names to Python for counting.

The [wrapper receipt](_reset/count-performance-wrapper-20261028.json) records
stable source hashes and three authenticated PostgreSQL role probes. This is a
loopback PostgreSQL 16.15 fixture measurement, not migration timing, a target-branch
speedup or a production performance guarantee. The original target branch
refused these protected counts.

## A reversible lifecycle

```mermaid
flowchart LR
    Native["Native values"] --> Plan["Plan and inspect"]
    Plan --> Backfill["Expand and resumably backfill"]
    Backfill --> Verify["Verify complete current data"]
    Verify --> Pending["Database switched; publication pending"]
    Pending --> Active["Host publishes ACTIVE authority"]
    Active --> Rotate["Rewrap / payload rotation / search rotation"]
    Rotate --> Active
    Active --> Reverse["Decrypt current values and verify"]
    Reverse --> Remove["Publish native access and remove generated objects"]
    Remove --> Exit["Original app runs without Cryptalis"]
```

The distinction between switching the database and publishing application
authority is deliberate. An interrupted switch must not silently authorize
mismatched workers. Reverse migration uses current committed values, so edits
made after protection survive removal.

## Performance evidence

The repository records matched native and protected read profiles at 10,000,
100,000 and 1,000,000 rows. Each workload uses ten warmup pairs and 100 measured
pairs with alternating execution order. The recorded local warm TEXT workloads
meet their read-latency and isolated column-plus-equality-index storage targets.

![Native and protected p95 latency for point, equality and IN-20 reads at three recorded row counts.](images/read-latency.svg)

The bars show complete native and protected p95, not just encryption CPU time.
These are separate historical profiles at different source revisions, not a
controlled scaling experiment or a before/after benchmark of this PR.

![Protected column and equality-index storage relative to native storage; the local target is at most twice native.](images/indexed-storage.svg)

| Recorded fixture | Source revision | Raw evidence |
|---|---|---|
| 10,000 rows | `4f11600` | [Latency samples and storage](_reset/performance-current-20261023.json) |
| 100,000 rows | `c7cc47d` | [Latency samples and storage](_reset/performance-100k-20261023.json) |
| 1,000,000 rows | `3bd4467` | [Latency samples and storage](_reset/performance-million-prepared-20261023.json) |

Regenerate both figures with `uv run scripts/render_performance.py`. Its plotting
dependency is isolated from the application environment and runtime package.

P95 is the value at or below which 95% of the measured requests fall. Added p95
means protected p95 minus native p95. It is not the p95 of pairwise differences.
Storage counts the protected column and its equality index; it is not total
database storage. A large percentage increase on a small native latency can
still be a small increase in milliseconds.

The receipts use local public fixture keys and revision-specific implementations.
They do not measure cloud key-provider latency or prove performance on every
workload. Earlier slower measurements and unresolved anomalies remain in
[compatibility](compatibility.md#performance-targets-and-recorded-costs).

## Query-inspection optimization

SQLAlchemy represents a query as a tree of expressions. Cryptalis inspects that
tree to find references to protected columns. The implementation now builds one
set of protected-column ancestors per inspection, then uses set intersections.
It avoids repeating a comparison against every protected field for every query
column. The set is rebuilt on each call; it is not a persistent query cache.

![Target-branch and candidate inspection times for wide public projections and early protected matches, showing both the speedup and its trade-off.](images/lineage-inspection.svg)

This [paired microbenchmark](_reset/admission-lineage-20261028.json) extracts the
original method from target commit `5d6ff65` and runs it alongside candidate
`c9a1049` in the same process. Each case has 100 warmups and 31 alternating
batches of 200 calls. Both methods must agree with the expected lineage results.

| Query shape with 32 protected fields | Target median, microseconds | Candidate median, microseconds |
|---|---:|---:|
| One public column | 7.60 | 3.65 |
| 32 public projection labels | 282.53 | 56.45 |
| First protected field matches | 4.20 | 6.84 |
| Last protected field matches | 11.02 | 6.88 |
| Public labels and a protected field | 36.87 | 32.86 |

The wide public projection improves substantially, while an early match can cost
more because the new method builds the complete lineage set first. One
millisecond is 1,000 microseconds. These are inspection costs, not whole-query
latency or encryption throughput. The receipt also includes the one-field and
eight-field cases, raw samples, interpreter versions and exact source hashes.

## Suggested demonstration

1. Explain the database-dump problem and the application/database trust boundary.
2. Show a declaration from the [SQLAlchemy walkthrough](walkthrough-sqlalchemy.md).
3. Explain the equality term and its leakage before showing a search.
4. Follow protection, a current-data edit, key rotation and decrypt-back.
5. Show the [recorded online application journey](status.md#original-online-http-fresh-recovery-2026-10-24).
6. Finish with the measured costs and the objective ledger's unfinished work.

Keep the distinction between a design, implemented code and recorded verification
visible. A refused unsupported query is a useful correctness demonstration, but
it does not mean that query capability has been implemented.

Use the [local run guide](local-development.md) to reproduce the checks and
regenerate the figures without configuring a cloud account.
