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
| Application integration | Sync/async SQLAlchemy and a synchronous SQLModel bridge | Selected operations and mappings, not arbitrary SQL |
| Migration | Atomic resumable chunks, verification and publication-gated cutover | Initial online text capture still needs a final write pause |
| Recovery | Protected backups, fresh-cluster adoption and stale-authority refusal | Local fixtures do not establish production disaster-recovery targets |
| Key changes | Root rewrap, payload rotation and search rotation | A local provider and SDK controls do not establish live cloud custody |
| Exit | Latest-value decrypt-back, metadata restoration and package-free restart | Retained backups can still need old keys and readers |
| Delivery | CLI, Doctor, repeat builds and dependency inventory | No production-qualified release |

These statements summarize [implementation status](status.md), not new test runs.
The [34-objective ledger](BUILD_CHECKLIST.md#objective-ledger) retains the full
requirements and each remaining gap.

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
