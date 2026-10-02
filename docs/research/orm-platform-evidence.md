# ORM and Platform Evidence Ledger

Status: Dated primary-source research. No Cryptalis implementation or benchmark evidence

Access/review date: 2026-09-30. Selected release/CLI observations rechecked 2026-10-01

Owner: upstream observations about SQLAlchemy, Alembic, PostgreSQL and Python, and broader ORM
encryption comparison inputs. Detailed Cryptalis requirements are in [ORM/schema/migration
contracts](../architecture/orm-schema-migration.md). Cross-system decisions are in the [architecture
owner](../architecture/README.md). Positioning belongs to [prior art](../prior-art.md).

Research observations do not expand a compatibility claim.

## Evidence levels and method

`documented` means an official API, manual or maintainer publication states behavior.
`source-inspected` means the review read relevant source at the recorded ref. `reproduced` requires
commands, exact environment, raw results and assertions. `benchmarked` also requires controlled
measurements. Neither reproduced nor benchmarked applies to any runtime claim in this ledger. Source
tests read without execution describe source-inspected test intent. Mutable documentation and branch
URLs are dated inputs.

Before claiming compatibility, freeze artifacts, checksums and source refs in the future experiment.

The review read the current architecture, full hardening dossier, build guide, prior-art ledger and
claims audit. It browsed official documents. It read selected pydantic-encryption files through its
maintainer's GitHub tree and raw endpoints. No package installation, external test execution,
migration, provider operation or source, configuration or test edit occurred.

The ledger records URL retrieval failures. It does not interpret them as missing features.

## Version observations

These are upstream observations at the access date. They are not dependency installation evidence or
support.

| Component | Official observation | Proposed use / source |
|---|---|---|
| Python | Sep 30 observation: 3.14.7 and 3.13.15 listed. Oct 1 recheck: 3.14.8 released Sep 30 is listed, 3.13.15 remains, 3.15 still pre-release with planned Oct 1 final | 3.13.15 ordinary GIL reference. 3.14.8 comparison selected after Oct 1 recheck. 3.14.7 historical observation. [Python releases](https://www.python.org/downloads/) |
| SQLAlchemy | 2.1.1 current, released 2026-09-25. 2.0.54 maintenance, 2026-09-15 | First existing-design 2.0.54 lane. Immediate 2.1.1 comparison. [Official releases](https://www.sqlalchemy.org/download.html) |
| Alembic | 1.20.0 released 2026-09-11. 1.20.1 changelog has no release date | 1.20.0 candidate. Undated entry not a release pin. [Changelog](https://alembic.sqlalchemy.org/en/latest/changelog.html) |
| PostgreSQL | Versioning page lists 18.6, 17.11 and 16.15 as current supported minors | 18.6 reference. 17.11/16.15 later comparison. [Versioning policy](https://www.postgresql.org/support/versioning/) |
| Psycopg | Release notes mark 3.3.6 current. Site header is 3.3.7.dev1 | 3.3.6 candidate. Header is not released pin. [Release notes](https://www.psycopg.org/psycopg3/docs/news.html) |
| pydantic-encryption | PyPI lists 0.13.1, 2026-08-25, Python >=3.11,<3.15 | Counterexample/comparison only. [PyPI release](https://pypi.org/project/pydantic-encryption/0.13.1/) |

Before execution, record the Python build and Unicode database, OS, driver pure/C/binary
implementation, libpq, greenlet, OpenSSL and crypto library. Also record the database image digest,
settings and all transitive dependencies. Version range notation is not a collection of passing
compatibility cells. The previous 2.1-beta and Alembic <1.20 proposal is historical.

It cannot be called the current upstream state.

## Framework API findings

| ID | Exact bounded observation | Level and primary source | Contract consequence |
|---|---|---|---|
| ORM-E1 | before_flush may inspect and change session state. do_orm_execute covers ORM Session execution and loaders. Flush persistence has separate events | documented. [session events](https://docs.sqlalchemy.org/en/20/orm/session_events.html), [ORM events](https://docs.sqlalchemy.org/en/20/orm/events.html) | Distinct mapping/flush/query guards and fixtures. No universal write interception claim |
| ORM-E2 | Scalar TypeDecorator hooks are value/dialect oriented. Caching has explicit contract | documented. [custom types](https://docs.sqlalchemy.org/en/20/core/custom_types.html) | No inference of complete row authority. Cache shape cannot contain grants/terms |
| ORM-E3 | Descriptors, hybrids and synonyms supply attribute mechanisms. Visitors traverse expressions | documented. [mapped attributes](https://docs.sqlalchemy.org/en/20/orm/mapped_attributes.html), [visitors](https://docs.sqlalchemy.org/en/20/core/visitors.html) | Feasible building blocks, not proof of history/rollback/rewrite completeness |
| ORM-E4 | run_sync invokes a callable in adapted greenlet context. Ordinary synchronous I/O can block | documented. [asyncio](https://docs.sqlalchemy.org/en/20/orm/extensions/asyncio.html) | Compare provider await bridge separately. Do not call arbitrary SDK nonblocking |
| ORM-E5 | Core execution events operate at registered SQLAlchemy connection boundaries | documented. [Core events](https://docs.sqlalchemy.org/en/20/core/events.html) | Direct cursors/separate drivers need explicit detect/unobservable classification |
| PY-E1 | asyncio tasks normally copy current context. Cancellation propagates through awaits | documented. [task API](https://docs.python.org/3/library/asyncio-task.html) | Clear/derive authority on spawn. Cancellation/cleanup corpus |
| PY-E2 | unicodedata exposes normalization and Unicode database version | documented. [Unicode API](https://docs.python.org/3/library/unicodedata.html) | Pin Unicode version and golden transform vectors |
| ALE-E1 | Structured Plugin system added 1.18.0. Register operations, comparators and implementations. Legacy comparator registrations predate it | documented. [plugins](https://alembic.sqlalchemy.org/en/latest/api/plugins.html), [operations](https://alembic.sqlalchemy.org/en/latest/api/operations.html) | Plugin floor applies to chosen structured API, not all custom operation mechanisms |
| ALE-E2 | Autogenerate produces reviewed candidates. Renames need manual correction. Optional named CHECK detector is name-only and does not notice changed expressions | documented. [autogenerate](https://alembic.sqlalchemy.org/en/latest/autogenerate.html) | Cryptalis must compare its own predicate contract IDs. Stamp/head is not data proof |
| PG-E1 | CHECK accepts true or null. Changing predicate functions does not recheck old rows. Default unique NULLs are distinct, optional NOT DISTINCT exists | documented. [constraints](https://www.postgresql.org/docs/18/ddl-constraints.html) | Explicit null branches/NOT NULL, versioned predicates/revalidation, declared unique-null semantics |
| PG-E2 | Concurrent index build is outside transaction blocks. Failure may leave invalid index. Failed unique index can still enforce uniqueness | documented. [CREATE INDEX](https://www.postgresql.org/docs/18/sql-createindex.html) | Journal autocommit boundaries, inspect validity/definition and repair explicitly |
| PG-E3 | pgcrypto runs in server and requires trust in administrators/server | documented. [pgcrypto](https://www.postgresql.org/docs/18/pgcrypto.html) | Different trust boundary. Not Cryptalis primary architecture |

The review checked these observations for feasibility, not universal compatibility. Future evidence
must show actual SQL parameters and rows, state histories, query oracle results, catalog transitions
and failure traces on every claimed cell.

## pydantic-encryption greenlet counterexample

Source ref: `1f251f66368ce7053e6db2d3b0f3620c9c75ae1e`.

| Inspected file | Source observation | Level |
|---|---|---|
| [async_bridge.py](https://github.com/julien777z/pydantic-encryption/blob/1f251f66368ce7053e6db2d3b0f3620c9c75ae1e/pydantic_encryption/integrations/sqlalchemy/async_bridge.py) | Imports await_ with await_only fallback. Constructs coroutine. Yields it. MissingGreenlet closes coroutine then calls synchronous function | source-inspected |
| [encryption.py](https://github.com/julien777z/pydantic-encryption/blob/1f251f66368ce7053e6db2d3b0f3620c9c75ae1e/pydantic_encryption/integrations/sqlalchemy/encryption.py) | Bind and result paths call bridge-backed encrypt and decrypt. Deferred result yields opaque EncryptedValue | source-inspected |
| [descriptor.py](https://github.com/julien777z/pydantic-encryption/blob/1f251f66368ce7053e6db2d3b0f3620c9c75ae1e/pydantic_encryption/integrations/sqlalchemy/descriptor.py) | Uses session siblings for batch decrypt on first unresolved attribute read. Detached path uses one row | source-inspected |
| [test_async_sqlalchemy.py](https://github.com/julien777z/pydantic-encryption/blob/1f251f66368ce7053e6db2d3b0f3620c9c75ae1e/tests/integration/test_async_sqlalchemy.py) | Tests intend to verify explicit finalization drains pending decrypt and releases transaction, then cached attribute access | source-inspected test intent, not locally passed |
| [pyproject.toml](https://github.com/julien777z/pydantic-encryption/blob/1f251f66368ce7053e6db2d3b0f3620c9c75ae1e/pyproject.toml) | Python >=3.11,<3.15. Optional SQLAlchemy >=2.0.51 and greenlet >=3. File version says 0.13.0 | source-inspected metadata |

PyPI 0.13.1 identifies this publishing commit, but its source metadata says 0.13.0. Preserve both
observations. Do not assert exact source and release equivalence until independent inspection of the
wheel and sdist. PyPI lists sdist SHA-256
`fd93c3dc56087a7330bfffe1f6de9e297ee5d95025ad4cf4ec22ca1ebdac07d1` and wheel SHA-256
`8e7ef75023cf4ea98b6834e461f29cb8a78fddc2aefc3317d96398be3161c8c6`. [Publisher
metadata](https://pypi.org/project/pydantic-encryption/0.13.1/)

The conclusion is bounded. Synchronous-looking hooks can yield async provider calls in a compatible
context. Source inspection does not prove performance, cancellation, detached-access safety or
Cryptalis authority semantics. Synchronous fallback outside the bridge can block an event loop.

Cryptalis must compare warm-up, greenlet and deferred candidates. Internal helper use and the rule
against synchronous fallback in async paths are explicit decision gates. They do not claim that
bridging cannot work.

## Broader alternatives and comparison scope

| Alternative | Primary evidence reviewed | Relevant comparison and limit |
|---|---|---|
| SQLAlchemy-Utils StringEncryptedType | [maintainer source, mutable master inspected 2026-09-30](https://github.com/kvesteri/sqlalchemy-utils/blob/master/sqlalchemy_utils/types/encrypted/encrypted_type.py); source-inspected | Existing scalar encryption/decoding and callable key pattern. Compare type fidelity/state/nulls. No inferred manifest, authenticated row authority, migration or lifecycle guarantee. Freeze a commit before benchmark. This is not latest-release claim |
| Django Cryptography | [project field docs](https://django-cryptography.readthedocs.io/en/latest/fields.html), documented; header 1.1.dev20200210060112 | Encrypted field wrapper, expiry and restricted lookups are comparative DX/type/lifecycle inputs. Old docs header does not establish current maintenance or security |
| Rails Active Record Encryption | [official guide](https://guides.rubyonrails.org/active_record_encryption.html), documented, mutable current guide | Transparent model access, deterministic query mode, previous schemes/unprotected migration support and parameter filtering. Different language/ORM and deterministic-payload tradeoff |
| CipherSweet | [maintainer repository](https://github.com/paragonie/ciphersweet), documented README inspected | Separate field encryption/blind-index transformations. PHP ecosystem. Compare domain/normalization/leakage discipline, not direct SQLAlchemy support |
| MongoDB Queryable Encryption | [official supported operations](https://www.mongodb.com/docs/manual/core/queryable-encryption/reference/supported-operations/), documented | Driver/type/operator-specific rejection. Automatic encryption edition boundary. No automatic mapping of Mongo operators to PostgreSQL/ORM support |
| CipherStash | [official cryptography](https://cipherstash.com/docs/security/cryptography), documented; selected [CLI reference](https://cipherstash.com/docs/reference/cli) retrieved by coordinating reviewer Oct 1 | Query representations/leakage are construction references. CLI reference generated from stash v1.0.0 documents plan/impl/status and encrypt plan/status/backfill/drop. db migrate explicitly not implemented. No CLI/runtime execution evidence |
| PostgreSQL pgcrypto | [official server extension docs](https://www.postgresql.org/docs/18/pgcrypto.html), documented | Useful server-crypto educational comparison, but administrator/server trust differs |

CLI retrieval provenance: the Sep 30 plan URL request failed. On Oct 1 the coordinating reviewer
retrieved the official 137-line CLI page through the web tool (reported crawl age one month). It
identified stash v1.0.0, a reviewable .cipherstash/plan.md draft, local-agent impl, implementation
status, encryption drift and phase inspection, and resumable backfill. db migrate was explicitly
absent. This reviewer's separate Oct 1 request returned a cached 381-line page redirected to
/docs/sdk/reference/cli (reported crawl age 1.3 years) without those commands.

Preserve the different retrievals. Declare neither retrieval a reproduction. The selected
observation relies on the coordinating reviewer's actual newer official-page retrieval and remains
documented-only. Before experimental comparison, freeze it against a CLI artifact.

The source or page generation version does not establish the current installed or globally latest
CLI version.

This is a broader comparison sample, not an exhaustive list of Python and ORM packages. No absent
search result proves feature nonexistence. Package existence is not market-size evidence. Security
and migration claims must be reproduced with exact semantics before any assertion of better, faster
or safer behavior.

## Pre-consolidation findings and current disposition

These findings describe the draft inspected during the 2026-09-30 research pass, not fresh
contradictions asserted against the current consolidated owners. The review read dispositions on
2026-10-01. They are documentation reconciliation, not experimental proof.

| Historical finding | Current disposition / authoritative owner |
|---|---|
| Old build-guide section 5.1 treated scalar-hook remote I/O as impossible while permitting a later bridge comparison | Rewritten [build guide](../cryptalis-build-guide.md) and [async comparison](../architecture/orm-schema-migration.md#sync-and-async-provider-access-comparison) make warm, greenlet and deferred designs empirical alternatives. No impossibility claim |
| Dossier section 9 placed backfill before coexistence | Dossier is explicitly superseded dated history. [canonical state machine](../architecture/orm-schema-migration.md#migration-state-machine-and-concurrency) admits enforced dual writers before backfill |
| Historical lane called SQLAlchemy 2.1 beta and excluded Alembic 1.20 | Historical snapshot retained as such. Dated [version observations](#version-observations) own the candidate versions, none supported |
| Earlier audit wording could imply all Alembic operation plugins began at 1.18 | [Alembic owner](../architecture/orm-schema-migration.md#alembic-integration) distinguishes the structured Plugin API from older operation/comparator APIs |
| SQL NULL could be mistaken for authenticated null presence | [Null owner](../architecture/orm-schema-migration.md#types-normalization-and-nulls) explicitly exposes nullness and unauthenticated absence. Encrypted-null/authenticated-presence remain separate gates |
| Whole-current manifest or mutable physical names in AAD would strand ordinary evolution | Shared manifest/context owner defines immutable creation-format identity. ORM consumes original binding rather than adding current whole-manifest/physical-name AAD |

The resumed ORM reconciliation also specifies buffered decrypted predicate and term validation
without silent LIMIT repair. It specifies full streaming verification plus a separate sample,
explicit rollback-mirror classification, public and internal API separation, and two-phase hidden
reads. It specifies exact scalar encoded caps, shared errors, independent requested-resource
binding, and the proposed serialized database fence. All runtime correctness, compatibility, denial,
drain and performance claims remain unexecuted.

## Reproduction queue

1. Freeze wheel and source identity and exact environments.
2. Execute G-ORM-1 through G-ORM-10 with the raw artifact requirements in the
   [contract](../architecture/orm-schema-migration.md#research-gates).
3. Pin the competitor artifact.
4. Compare only matching authority, crypto, query, provider and access semantics.
5. Disclose architectural mismatches.

SQLAlchemy-Utils, Django, Rails and CipherSweet are targeted behavioral comparisons. They are not
interchangeable security or performance baselines. Recheck release observations before any
compatibility release or public comparison.
