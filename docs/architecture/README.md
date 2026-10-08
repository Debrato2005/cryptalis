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
SUPPORTED selects design scope, not current product support.

| Contract | Approved choice |
|---|---|
| Stack | Python 3.12+, SQLAlchemy 2.x, psycopg 3 sync and async, PostgreSQL 16 |
| Protected type | Text only. Every other protected type is UNSUPPORTED BY DESIGN until admission |
| Capabilities | SUPPORTED: storage-only, equality, `IN`, tenant-scoped uniqueness |
| Tenancy | Every protected table declares a tenant column or declares itself single-tenant. The compiler never guesses tenant ownership |
| Primary keys | Application-generated UUID, Snowflake-style, or another app-assigned ID. Reject serial, identity, and database-default-generated keys at plan time |

Comparisons/ranges, ordering, LIKE/prefix/contains, regex, protected aggregates, general DISTINCT, and joins on protected fields are **UNSUPPORTED BY DESIGN**.
Range, order, prefix, and text-search work starts only after all [seven build slices](../build-guide.md#ordered-build-slices) pass real PostgreSQL tests.
The [six-gate admission rule](../compatibility.md#capability-admission) and leakage opt-in then control each addition.
Research arrays, order encodings, internal transport, and diagnostic helpers are **INTERNAL ONLY**. They do not admit a public capability.

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
| Crypto/provider boundary | Encode text, use library AEAD/HKDF/HMAC, resolve exact admitted keys, wrap/unwrap roots |
| Transition executor | Expand, backfill, verify, switch, contract under a maintenance write pause |

CLI commands compose these four responsibilities. Startup, plan, apply, and status reuse the same checks.
PostgreSQL supplies constraints, transactional DDL, atomic chunks, indexes, and ordinary transaction outcomes.
Deployment supplies current policy, credentials, writer exclusion, and restore quarantine. The provider supplies external root custody.
These dependencies do not supply host business authorization. No additional authority, workflow, or diagnostic service is required.

## Exact data paths

```text
Write: ordinary attributes → app-assigned row identity + tenant context
       → text validation/encoding → local admitted keys
       → randomized authenticated payload + declared equality term
       → atomic INSERT/UPDATE without protected plaintext binds
       → normal PostgreSQL transaction outcome

Read: entity/scalar SELECT → payload + expected row/tenant context
      → exact-generation local key → bounded framing/authentication
      → text decode + required term recomputation → ordinary Python value

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

Async preparation awaits provider work outside synchronous events. Type/result processors use local admitted material only.
Sync sessions use synchronous provider APIs. Ordinary SQLAlchemy restrictions on async implicit I/O still apply.
Detached authenticated values remain ordinary application values, without a revocable plaintext wrapper.

Entity/scalar projections carry expected typed row identity and tenant context with the payload.
Requested point identity and host tenant scope must agree with returned context. Ciphertext headers cannot select provider authority.
Aliases, outer-join NULL sides, relationships through unprotected keys, column tuples, cache behavior, and parameter shapes need differential tests.
A changed tenant requires authorization, new context, and resealing. Stable record identity remains immutable while protected.
The compiler freezes exact context encodings for each admitted app-assigned ID mapping before vectors and integration tests.

Comparators rewrite only the admitted grammar. Public expression traversal rejects unadmitted operators, nested clauses, functions, and protected DISTINCT.
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
The engine must use PostgreSQL/psycopg, `echo=False`, and `hide_parameters=True`, with no checked-out connections at activation.
Ordinary ORM flush writes and admitted SELECT projections are implemented. Core/bulk writes and protected search predicates reject in this slice.
Mapped text attributes remain ordinary `str` or NULL. Generated projections carry row and tenant context for authentication.
Protected projections disable compilation caching because their processors retain prepared material and operation context.
Unprotected projections retain native caching. Guards reject public raw-driver, opaque SQL, COPY, and unprepared-write routes.
**VERIFIED:** native/attached comparisons and cache regression sensitivity have the exact boundary in the
[slice 3 checkpoint](../status.md#slice-3-checkpoint-2026-10-08).
Separate non-owning runtime credentials and deployment enforcement remain unverified. Slice 4 cannot start yet.

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

Range bounds, prefix limits, shared-join domains, arbitrary normalizers, and non-text codecs are not admitted manifest capabilities.
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

The lock schema is `cryptalis.lock/v1`. Its exact top-level members are
`schema`, `profile`, `domain_id`, `database`, `declaration`, `models`, `writer_inventory`, `search_reviews`, `ddl`, and `required_readers`.
The declaration is canonical. Models contain `model`, `table_id`, `schema`, `table`, `record`, `tenancy`, `fields`, and `source_schema`.
Fields contain `name`, `column`, `field_id`, `queries`, `representation`, `payload_column`, `unique_indexes`, `original`, `source`, `descriptor`, and `descriptor_digest`.

The source schema stores inspected relation, column, constraint, index, and dependency facts.
Catalog type modifiers use strings because PostgreSQL uses negative sentinels.
Unrelated SQL definitions use SHA-256 fingerprints of their canonical JSON string values.
Original admitted unique constraints and indexes retain their exact definitions for later restoration.
The lock contains no database connection string or application values.
`ddl.expand` contains additive proposals. `ddl.requires_before_switch` names prerequisites that remain unimplemented.
Reader requirements describe the intended readers. They do not claim those readers exist.

The record codec is `uuid16/v1` or `int64-be/v1`. UUID context uses 16 exact bytes.
Bigint context uses `T` with the `int64` tag and eight signed big-endian bytes, as [security](../security.md#cryptographic-format) specifies.
Single-tenant context uses the stable table UUID. The text codec is `utf8-exact/v1`.
The normalizer is `identity/v1`. The null policy is `sql-null/v1`. Composed and decomposed text remain distinct.

Descriptor digests exclude SQL names. They bind the domain, table, field, record codec, tenant codec, text codec, normalizer, null policy, and representation.
The representation is `cf1-storage/v1` or `cf1-packed-equality/v1`. The descriptor schema is `cryptalis.context/v1`.
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
The default candidate packs the term in the payload with an expression index.
Separate/generated terms are compiler output for admitted tenant-scoped constraints, not another integration mode.
No custom extension, type, or operator class is required.
Payload and companion commit in the same transaction. Search roots remain independent of payload roots.
Payload rotation need not reindex. Search-key changes require complete reindex and authenticated-header resealing with fresh nonces.
[Security](../security.md#cryptographic-format) owns framing, commitments, keys, and failure rules.
Generic CHECK/FK/default/collation preservation remains UNKNOWN. [Lifecycle](../lifecycle.md) states the verifier's actual checks.

## Public surface

All commands below are **SPECIFIED**, not implemented package commands.

| Command | Purpose |
|---|---|
| `cryptalis init` | Create declaration and inspect configuration |
| `cryptalis plan` | Report incompatibilities, semantic diff, DDL, leakage, writers, estimates, and approvals. Refuse any incompatibility |
| `cryptalis apply PLAN` | Run or resume the verified transition |
| `cryptalis status` | Show representation, progress, failures, keys, and retained obligations |
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
