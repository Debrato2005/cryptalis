# Cryptalis

**IMPLEMENTED: research prototype with a manifest compiler, CF1 primitives, a local development provider, and bounded SQLAlchemy storage, equality/IN and tenant-scoped uniqueness.**
The sync/async attachment has scoped PostgreSQL tests under separate restricted runtime credentials.
Tested runtime DDL and ownership changes are refused. Separate writers can still change data; deployment writer exclusion remains unverified.
All seven full gates remain **UNKNOWN**. Read [status](docs/status.md) for evidence and revision limits.
No runtime compatibility cell, production key provider, or independent review is qualified.
The [slice 3 walkthrough](docs/walkthrough-sqlalchemy.md) gives the implemented API and its limits.
The [search walkthrough](docs/walkthrough-search.md) covers slice 4 and its native-index mechanism.

**SPECIFIED:** Cryptalis adds application-side protection to a Python 3.12+, SQLAlchemy 2.x, psycopg 3, PostgreSQL 16 backend.
One manifest selects protected text fields. One attachment handles admitted writes, reads, and expressions.
One transition executor handles protection, verification, decrypt-back, removal, and three separate rotation operations.
SUPPORTED below selects design scope. It does not mean implemented, verified, or released support.

## Compatibility promise

**SPECIFIED:** Cryptalis never silently changes what your backend returns.
For every supported operation, results match the unprotected database, including native values, types, NULL behavior, and ORM state.
Every unsupported operation raises a typed error, such as `UnsupportedEncryptedQuery` or its equivalent.
It must not return different results, partial results, or plaintext-fallback data.
[Security](docs/security.md) states the full-HMAC collision assumption and hostile-database limits of this promise.

**SUPPORTED:** text storage/read/write, equality, `IN`, and tenant-scoped uniqueness.
Every protected table declares a tenant column or declares itself single-tenant.
Primary keys must be application-generated, such as UUID, Snowflake-style, or another app-assigned ID.
`plan` rejects serial, identity, and database-default-generated keys with a plain explanation.

**UNSUPPORTED BY DESIGN:** comparisons and ranges, `ORDER BY`, `LIKE`/prefix/contains, regex,
`SUM`/`AVG`/`MIN`/`MAX`, general `DISTINCT`, joins on protected fields, and every non-text protected type.
Other unadmitted operators also fail. Do not protect a field whose required queries use these operations.
Queries on unprotected fields retain their native semantics.
Range, order, prefix, and text-search work starts only after all seven build slices pass their PostgreSQL tests.
Admission then requires all [six technical gates](docs/compatibility.md#capability-admission) and explicit leakage opt-in.

## Intended adoption

**SPECIFIED:** use this recommended path. It is not a guarantee of zero application changes.

1. Write the manifest with text fields, capabilities, tenant declarations, and leakage acceptance.
2. Run `plan`. It reports schema incompatibilities and refuses to proceed on any of them.
3. Apply to a staging database copy. Run the application's own test suite with Cryptalis attached.
4. Resolve or exclude incompatible workflows before applying to production under the qualified deployment procedure.
5. Use rollback or removal through verified decrypt-back until you explicitly finalize and retire the required recovery dependencies.

Schema incompatibilities include server-generated keys, unsupported types, small-domain searchable fields, missing tenant scope, and unsupported writers.
Attachment rejects unsupported queries. The staging suite therefore exposes query incompatibilities before production.
Planning cannot infer every query the application will execute.
The production step remains blocked by the [release gate](ENGINEERING_PLAYBOOK.md#release-gate).
Finalization is an explicit retirement decision through the existing lifecycle, not a new command or timer.

The real adoption cost is a manifest, one attach call, typed statements replacing opaque raw-SQL protected writers, and application-generated primary keys.
The host supplies its authenticated tenant scope, writer inventory, external provider configuration, and current deployment policy.
Cryptalis does not replace authentication or authorization.

```python
# SPECIFIED API example. It is not importable from the current package.
sessions = attach(Base.registry, engine, manifest="cryptalis.json", keys=provider)
with sessions() as session:
    session.add(User(id=app_assigned_id, email="alice@example.com"))
    found = session.scalar(select(User).where(User.email == "alice@example.com"))
```

## Query intent

**SPECIFIED:** an empty query list means storage-only. Equality permits `IN`. Uniqueness implies equality within the declared tenant scope.
No field receives an undeclared search representation. The compiler must reject a search capability without its leakage acknowledgment.
The [implemented compiler syntax](docs/architecture/README.md#implemented-compiler-syntax) defines field intent.
Existing structural inspectors do not validate this declaration.

**IMPLEMENTED:** inspect intent and a native schema through the compiler API:

```python
from cryptalis.manifest.compiler import compile_protection

plan = compile_protection(
    manifest_bytes, Base.registry, engine,
    writers=writer_inventory, search_reviews=domain_reviews,
)
```

The result contains canonical lock bytes, a digest, and semantic changes. Compilation creates no database effects.
The host supplies complete writer coverage and value-domain reviews. These records remain host assertions.
[Status](docs/status.md#slice-1-checkpoint-2026-10-08) gives the tested compiler cell and its limits.

## Protection and cost

**SPECIFIED:** admitted protected writes transform plaintext before PostgreSQL receives it.
PostgreSQL receives randomized authenticated payloads and only declared keyed equality representations.
The public source, manifest, schema, and backups contain no secret key material.

Accepted leakage is capability-specific:

- Storage-only: row linkage, ciphertext length, presence/NULL, write timing, access patterns, and result volumes.
- Equality and `IN`: also equal-value classes, frequencies, repeated queries, and queried membership sets.
- Tenant-scoped uniqueness: also membership revealed by uniqueness conflicts within that tenant.

Auxiliary knowledge and chosen inputs can reveal values from searchable fields. These fields are not opaque.
**UNSUPPORTED BY DESIGN:** protection against application compromise, key compromise, broken authorization, and plaintext the host logs, caches, or exports.
Same-context replay, malicious result omission, nullable-field substitution with SQL NULL, and privileged schema modification also remain outside the claim.
Plaintext migrations and removal can leave historical WAL, backup, and snapshot exposure.
[Security](docs/security.md) owns accepted leakage and these limits.

**SPECIFIED targets:** added p95 at most 3 ms for point/equality reads, at most 8 ms for `IN` with 20 values.
Storage targets at most 2× for a protected column with an equality index.
Local measurements and remaining limits belong to [compatibility](docs/compatibility.md#slice-4-local-million-row-profile-2026-10-08).
Recorded latency misses these targets. The [performance owner](docs/compatibility.md#performance-targets-and-recorded-costs) gives measurements and the unexplained plaintext-page slowdown.
Write-throughput and pause budgets remain undecided (D).

No production provider is designated. The local provider supplies functional evidence only.
Production requires external root custody and a current deployment policy outside database restore.
The operator stops and drains known writers for maintenance. Immediate arbitrary-process revocation is outside the claim.

## Database prerequisites

**SPECIFIED:** PostgreSQL 16 is the selected major. Other majors are **UNSUPPORTED BY DESIGN** until admission.
Managed services on PostgreSQL 16 remain unqualified until their exact service cell passes the required suite.
Research observations on 16.2 single-user and 16.15 service-mode PostgreSQL do not qualify a deployment.

The selected storage/equality representations use built-in `bytea`, B-tree `bytea_ops`, and expression indexes. Required extensions: none.
The migration role needs ownership of affected tables, CREATE on the application schema, and ordinary DDL/index privileges.
An administrator provisions roles and grants once. The migration role needs no superuser, CREATEROLE, replication, or untrusted languages.
The runtime role needs admitted table privileges. It must not own tables or schema.
Server-generated keys are rejected. Sequence preallocation is not part of the selected contract.
Protected COPY, opaque raw SQL writes, and unknown external writers block adoption unless those routes are excluded.
Maintenance needs operator-controlled writer exclusion and evidence that existing transactions finished.

## Current commands

**IMPLEMENTED:** research utilities only.

```bash
.venv/bin/python -m cryptalis manifest inspect examples/manifests/genesis.json --json
.venv/bin/python examples/demo_smolink_crypto.py --json
```

These commands inspect structural records or synthetic data. They do not attach database protection.
The specified `init`, `plan`, `apply`, `status`, `rollback`, `keys rotate`, and `remove` commands are not package capabilities.
[Spikes](spikes/revamp/README.md) contain isolated functional experiments with explicit limits.

## Read next

1. [Architecture](docs/architecture/README.md): selected scope, components, manifest, and attachment.
2. [Security](docs/security.md), then [lifecycle](docs/lifecycle.md): leakage, keys, transitions, and exit.
3. [Compatibility](docs/compatibility.md), then [status](docs/status.md): grammar, targets, and evidence.
4. [Decisions](docs/decisions.md), then [build guide](docs/build-guide.md): approved choices and seven ordered slices.
5. [Engineering playbook](ENGINEERING_PLAYBOOK.md): manual implementation, tests, and release.

[Prior art](docs/prior-art.md) contains dated primary-source comparisons.
