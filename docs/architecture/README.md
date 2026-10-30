# Cryptalis architecture

The manifest declares intent; Cryptalis compiles it into storage, query and
lifecycle behavior. **Complex internals, simple external interface.** Simplicity
must not weaken security, native semantics or failure visibility.

[Status](../status.md) owns implementation evidence. [Compatibility](../compatibility.md)
owns the exact admitted stack, types and operations. No production cell is qualified.

## Documentation ownership

The [documentation map](../README.md#document-owners) is the single ownership index.
Declaration/lock syntax lives in [manifest](../manifest.md), trusted CLI inputs in
[host contexts](../host-contexts.md), and procedures in the
[operator walkthrough](../walkthrough-migration.md).

## Approved scope

The first production release requires the full SRS and all 34 objectives.
The baseline is authenticated storage, equality/IN/tenant-scoped uniqueness and
SQLAlchemy integration. Further capabilities remain obligations subject to
[admission](../compatibility.md#capability-admission), not silent scope reductions.

Protected tables declare a tenant column or explicit single tenancy. Records
have stable application-assigned identities before encryption. Separate runtime
and migration principals preserve privilege boundaries. Unknown writers and
unsupported expressions fail before effects.

## Components

| Responsibility | Source / contract |
|---|---|
| Manifest compiler | `manifest/`: declaration, mapping/schema inspection, stable descriptors, lock, DDL and semantic diff; [reference](../manifest.md) |
| ORM adapter | `sqlalchemy.py`, `_sqlalchemy_*.py`, `sqlmodel.py`: prepared row context, guarded writes, admitted query mapping and authenticated results; [compatibility](../compatibility.md) |
| Crypto and providers | `crypto/`: typed CF1, HKDF/HMAC, exact admitted roots, provider wrap/unwrap and bounded process caches; [security](../security.md) |
| Transition engine | `migration.py`, `rotation.py`, `deprotection.py`, `_online.py`: plan, chunk, verify, switch, publication admission and current-data exit; [lifecycle](../lifecycle.md) |
| Public orchestration | `cli.py`, `_cli_operations.py`, `cli_host.py`, `doctor.py`: reuse the same underlying checks with explicit host inputs |

PostgreSQL supplies transactions, native constraints, indexes and cooperating
locks. Providers supply root custody. The host supplies tenant authentication,
current policy/pins, credentials, writer exclusion, publication and restore quarantine.
No database journal, hash or diagnostic report can replace host authority.

## Exact data paths

```text
Write: ordinary attributes + stable row/tenant identity
       → typed encoding + prepared admitted keys
       → randomized authenticated payload + declared equality term
       → guarded atomic SQL write → normal transaction outcome

Read: admitted projection + expected row/tenant/field context
      → exact-generation local key → bounded frame authentication
      → typed decode + required term verification → ordinary Python value

Search: admitted ORM expression + typed binds
        → tenant/domain-bound HMAC terms → native indexed predicate
        → authenticated ordinary read
```

Payload and search roots are independent. Crypto completes outside PostgreSQL;
SQL functions transport context, never keys or decrypted values. Missing keys,
invalid context and unsupported grammar produce typed failures. There is no
plaintext fallback, hidden candidate filtering or full-table decryption fallback.
Each value authenticates before release. This does not establish hostile-database
freshness/completeness or whole-result publication atomicity.

## SQLAlchemy integration

Attach before model instances, sessions or compiled statements are used. Replace
one session factory; preserve native mapping, identity/history, Result and
transaction behavior for admitted operations. The host authenticates tenant
scope and authorizes the query; attachment does not invent a tenant filter.

A scalar type processor cannot establish row identity or perform remote key I/O
inside synchronous result hooks. The adapter prepares exact row-bound frames
before writes and asynchronous provider work before synchronous hooks. It checks
final SQL/driver values against the admitted operation, rejects late unprepared
values and clears preparation on rollback. It never guesses batch ordering.

[Application examples](../walkthrough-sqlalchemy.md) own the attach/CRUD usage.
[Compatibility](../compatibility.md) owns native semantics, loading and query/DML
admission. [Security](../security.md#slice-3-storage-enforcement-2026-10-08) owns
engine, event, bind, provenance and output integrity rules.

## Manifest

Use bounded JSON `cryptalis.protection/v1`. Names resolve only inside the
supplied registry; no name triggers an import. The [manifest reference](../manifest.md)
owns exact syntax, tenancy, search reviews, stable identities and lock readers.
Connection strings, plaintext keys and workload tokens do not belong in a manifest.

## Physical storage

Storage-only fields use authenticated `bytea`. Equality adds a full keyed term,
packed with the payload and indexed through native PostgreSQL expressions;
admitted uniqueness can require a separate/generated term. These are compiler
choices, not alternative user integration modes. No custom extension or operator
class is required. See [security](../security.md#cryptographic-format) for CF1 and
[lifecycle](../lifecycle.md) for schema conversion, rotation and verified removal.

## Public surface

The current CLI is authoritative through `cryptalis --help`. Use the
[operator walkthrough](../walkthrough-migration.md) for init, planning, apply,
resume/abort, rotation, diagnosis, status and removal. The
[host context reference](../host-contexts.md) defines explicit factory inputs.
A future command spelling is not a currently implemented command.

Doctor separates schema/supplied-query inspection, ACTIVE runtime admission and
explicit cold-provider preparation. Each scope reports unobserved properties as
UNKNOWN and supplies no deployment authority. Lifecycle status is observation,
not value verification or permission to publish.

## Minimum host contract

Supply admitted mappings, stable application IDs, authenticated tenant scope,
provider/policy resolution, protected logging, deployment pins and inventoried
writer routes. Supply explicit maintenance exclusion and retained-backup ownership
for lifecycle changes. Validate actual application behavior in an attached staging
journey before applying protection to required workflows.

Cryptalis manages cryptographic and database mechanics inside these boundaries.
Host credentials, deployment authorization and tenant authentication remain host
responsibilities. Their production qualification is tracked in the
[objective ledger](../BUILD_CHECKLIST.md), not implied by an example attach call.
