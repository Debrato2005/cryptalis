# Integration and encrypted-search research

> Historical research archive. The [revamp record](revamp-evidence.md) supersedes its architecture choices and scope.
> This file records past evidence, not the current specification or runtime qualification.

Access date: 2026-10-06. Status: external evidence and design comparison. No runtime support, benchmark, or independent audit claim.

This file supplies evidence for the canonical reset. It does not own a second architecture.
Upstream documentation describes upstream behavior. The recommendations below are Cryptalis design judgments and need executable gates.

## Repository evidence examined

The existing ORM contract separated Session flush, Session execution, Core connections, driver calls, and external writers.
It also required authenticated row context, bounded publication, predicate checks, and explicit async preparation.
Those constraints remain useful. The old no-search starting profile and unresolved integration alternatives do not define the final product.
The existing platform ledger used SQLAlchemy 2.1.1. The current documentation reports 2.1.3.

## Integration choice and weights

The primary model is attachment to a registered SQLAlchemy Session factory and mapper registry.
Attachment creates protected Session and AsyncSession classes internally. It installs public descriptors, comparators, statement guards, and physical mappings before application queries start.
Normal assignments and admitted SQLAlchemy expressions keep their usual spelling. A trusted application callback supplies tenant identity at Session creation.
The callback must derive identity from authenticated application state. Request parameters and database rows do not establish authority.

Weights total 100: bypass resistance 30, query transparency 30, parser attack surface 20, async support 10, uninstallability 10.
Scores range from 1 to 5. A higher score means a better fit for this product.
These scores are design judgments, not measured security or performance results.

| Model | Bypass | Transparency | Parser surface | Async | Uninstall | Weighted score |
|---|---:|---:|---:|---:|---:|---:|
| Attached SQLAlchemy with physical guards | 4 | 5 | 5 | 4 | 4 | 90/100 |
| PostgreSQL protocol proxy with physical guards | 4 | 4 | 1 | 4 | 3 | 66/100 |
| Explicit repository with physical guards | 3 | 1 | 5 | 5 | 4 | 62/100 |

The attachment wins because supported business code stays ordinary, while the planner reads typed expressions rather than arbitrary SQL text.
The bypass score includes database constraints, restricted credentials, and doctor checks. ORM events alone do not earn that score.

A proxy adds SQL grammar, prepared-statement state, result typing, COPY, pipelining, pool identity, network deployment, and another plaintext process.
It still needs physical guards for unmapped paths. It does not remove the encrypted-query capability matrix.
An explicit repository makes async preparation easier, but requires widespread application changes and still permits separate drivers with shared credentials.
Cryptalis does not expose a second general repository integration. Its maintenance runner reuses the same compiled policy and crypto core internally.

The public-instrumentation prototype is a production blocker. A failed prototype does not silently change the integration model.
It requires a documented redesign and an updated decision ledger before support.

### Precise interception limits

`before_flush` handles unit-of-work state. `do_orm_execute` handles Session statement execution and loaders.
An engine event does not cover another engine or a direct driver cursor.
A scalar TypeDecorator receives a field value, not authenticated record identity and complete row context.
Its existence does not prove safe transparent encryption for this design.

Sync events cannot await arbitrary provider calls. AsyncSession wrappers prepare authority and key batches at awaited execute, flush, and commit boundaries.
Provider SDK calls run in an awaited async adapter or bounded executor. Local synchronous hooks consume prepared material only.
`run_sync` adapts SQLAlchemy database I/O. It does not make arbitrary synchronous KMS calls nonblocking.
Cold material inside a descriptor or unexpected synchronous hook causes a typed failure before SQL or plaintext release.

Full entities supply companions directly. `select(User.email)` requires projection expansion with hidden authenticated context.
The adapter must remove companions from the returned logical Result and preserve scalar, row, label, order, and cardinality semantics.
A scalar processor cannot do this alone. This ordinary query form is a chosen support target blocked on the projection gate.
Unsupported expression projections, aggregates, DISTINCT, streaming, implicit async lazy access, inheritance, and custom operators reject before SQL.
Eager relationship loading needs separate fixture cells. A successful full-entity test does not establish any loader cell.

Logical values cannot remain mapped to live plaintext columns after finalization.
The protected mapper uses hidden ciphertext and token columns. Logical attributes keep public history through supported instrumentation.
Refresh, expire, rollback, close, detach, and identity-map hits need behavioral tests.
Returned Python plaintext cannot be recalled. Clear adapter caches without a Python zeroization claim.

A record identifier must exist before field encryption. Client UUIDs satisfy this condition.
A supported sequence profile can reserve its normal database identifier before INSERT, with ordinary sequence gaps.
Other server-generated identities reject when the adapter cannot safely reserve them. An INSERT with plaintext followed by encryption is forbidden.

### Database guards and their limits

Use a non-owner runtime role. Separate the migration role, restrict schema creation, and examine inherited privileges and executable objects.
Compiled protected storage has bytea envelopes, bounded framing checks, required format metadata, and companion-consistency constraints.
Remove the persistent logical plaintext column at finalization. Do not retain a plaintext compatibility view.
These guards reject ordinary plaintext mistakes through SQL, COPY, bulk operations, and uninstrumented workers.

PostgreSQL INSERT permission also permits COPY FROM. There is no independent COPY denial privilege for the same writable columns.
COPY FROM invokes check constraints and triggers. The schema guard must therefore cover it.
Framing is not AEAD verification. A writer can place plaintext inside forged framing or insert an invalid authenticated envelope.
A complete doctor authentication scan detects that stored corruption. Unknown writers and unexamined executable objects remain UNKNOWN and block admission.
An owner or superuser can remove guards. Database constraints do not protect against that administrator.

The resulting claim is bounded: every declared writer path is protected, rejected, or examined and reported by doctor.
No ORM mechanism proves universal interception. An incomplete scan never produces a complete PASS.
Doctor cannot detect a plaintext value that an attacker wrote, copied, and erased before observation.
It does not establish confidentiality for an unknown or malicious writer.

## Equality, IN, and uniqueness choice

Use randomized payload encryption plus a separate full 256-bit HMAC-SHA-256 equality term.
Derive a distinct search key for each protection domain, tenant, logical field, normalization version, and search generation.
Use an unambiguous length-prefixed encoding with a fixed purpose label and declared codec identity.
The crypto owner must freeze the exact key derivation and encoding. This lane does not propose a second primitive suite.

Do not truncate equality terms in the selected profile. HMAC is not mathematically injective, but full-width output avoids intentional false positives.
The approximate birthday bound for distinct inputs is n(n-1)/2^257 under a pseudorandom-function assumption.
This bound is not a proof about the full implementation or its key handling.
Forced collision fixtures must still fail explicitly. They must never return a wrong logical match.

Truncated beacons can reduce some distribution leakage, but require candidate filtering, paging changes, and careful dataset analysis.
A separate full-width uniqueness term would restore frequency leakage anyway.
Partitioned beacons add query fan-out and do not preserve ordinary SQL pagination without a different planner.
The selected construction keeps one exact-match representation and explains its stronger leakage plainly.

| Operation | Design choice | Result semantics |
|---|---|---|
| Equality | Versioned full-width term, then authenticate and recompute fetched rows | Normalized equality under the declared profile |
| IN | Terms for non-null typed entries, bounded list and generation expansion | Empty list is false. NULL entries do not become IS NULL |
| NULL | Authenticated null marker plus declared public presence companion | Preserve SQL three-valued logic. Presence leaks |
| Uniqueness | PostgreSQL unique index on tenant and term, with declared NULL policy | Database enforces concurrent uniqueness on normalized values |
| LIMIT/OFFSET | Keep caller's SQL bounds and admitted unprotected ordering | No postfilter refill, hidden scan, or changed page size |
| Index mismatch | Fail the complete bounded result before publication | No earlier plaintext rows escape |

Each fetched candidate must authenticate its payload and original binding.
Recompute its equality terms and null companion under the declared versions.
Compare the original logical predicate before publishing the result buffer.
Malformed, stale, substituted, or inconsistent companions fail the whole operation. They do not become skipped rows.
A hostile database can omit rows, alter plaintext ordering, or hide a corrupt row outside the selected page.
Cryptalis does not authenticate query completeness, arbitrary plaintext predicates, or the full database snapshot.

Uniqueness checks in application code do not prevent concurrent duplicates. The database unique index remains necessary.
A rare full-width collision reports an explicit conflict after authenticated comparison. It can deny availability, not produce silent equality.
During search rotation, every admitted writer supplies both generations while the old complete unique index remains authoritative.
Backfill and full verification complete before a target unique index becomes authoritative.
A mixed partial index is never sufficient proof of uniqueness. Retirement waits for reader, writer, and recovery obligations.

Normalization must name its exact algorithm and data version. It applies to a search copy, while encrypted payload retains original text.
No implicit database collation, arbitrary normalizer callback, or unspecified email lowercasing is allowed.
Changing normalization requires a reindex transition, duplicate review, and index verification before activation.
Preserve the explicit distinction between exact bytes, Unicode normalization, case folding, and application-defined identifier semantics.

### Leakage and shredding decision

Full-width terms expose equality classes and frequency within the same tenant, field, normalization, and generation.
An observer of queries learns repeated searches, matching record identifiers, result size, access patterns, and timing.
A chosen-input observer can map guesses to terms or observe matching records. A keyed hash does not stop that oracle.
Public source and configuration do not reveal the search key. An offline unkeyed dictionary attack is not the correct model.
Auxiliary distributions, correlations, known values, and chosen inputs can nevertheless identify searchable plaintext.

Search defaults to absent. Enabling it requires a field-specific acceptance of equality-frequency leakage in the reviewed manifest.
Booleans, small enums, medical outcomes, small numerical domains, and similarly guessable categories are unsupported for the equality profile.
The system cannot determine a real dataset's entropy from its type or a developer label.
Doctor must report incomplete leakage review as UNKNOWN. A high-cardinality label is not evidence of confidentiality.

Use tenant-shared field search keys to preserve cross-subject equality and uniqueness.
Do not derive terms from subject payload keys. That would break a single ordinary equality lookup across subjects.
Destroying one subject's payload authority does not remove old terms from backups or erase equality links.
Live subject terms must be removed during the shred transition. Old snapshots can retain links while shared search authority remains.
Thus, subject shredding means payload-key denial and bounded destruction, not anonymity or erasure of index knowledge.

## Competitor and substitute comparison

These comparisons use the dated sources below. No vendor behavior was reproduced in this pass.

| Alternative | Useful evidence | Cost or boundary for Cryptalis |
|---|---|---|
| CipherStash Proxy and Stack SDK | Client encryption, PostgreSQL terms, ORM wrappers, migration and proxy surfaces | Closest product substitute. Proxy parsing and its unmapped pass-through need explicit review |
| Acra | SQL proxy, API service, key storage, searchable encryption, rollback tooling | Broader deployed service suite. Current fetched docs are a 2024 build, so current release claims are rejected |
| MongoDB Queryable Encryption | Automatic driver query analysis and explicit operator support | Different database. Snapshot guarantees exclude persistent attackers with query information. Unique plaintext constraints are not guaranteed |
| AWS Database Encryption SDK | HMAC beacons, false-positive filtering, partition fan-out, hierarchical KMS cache | Mature DynamoDB approach. Beacon configuration and retrofit restrictions do not transfer to PostgreSQL |
| CipherSweet | Randomized field payloads, separate keyed indexes, AAD and rotation interfaces | Useful construction discipline. Requires adapters and application-owned lifecycle. No direct Python ORM support established |
| Rails Active Record Encryption | Ordinary attributes and deterministic equality queries, migration schemes, uniqueness guidance | Strong UX prior art. Deterministic payloads and plaintext migration compatibility differ from this choice |
| Lockbox plus Blind Index | Ordinary Rails attributes, separate search columns, backfill and rotation | Strong retrofit prior art. Shared-key leakage and host history/logging remain explicit concerns |
| SQLAlchemy-Utils | Scalar encrypted types and custom-type integration | Minimal encryption helper. No row-context, manifest, restore, or complete key lifecycle support established |
| Tink | Vetted primitive and keyset APIs, KMS envelope options | Crypto building block, not an ORM/lifecycle product. KMS envelope-per-value differs from cached encrypted-keyset use |
| Evervault | SDK/HTTP Relay, enclave key authority, hosted offboarding export | Different process and provider boundary. No PostgreSQL expression rewriting or index semantics established |
| pgcrypto | Built-in database cryptographic functions | PostgreSQL receives plaintext and requires administrator trust. It fails this product's pre-database boundary |
| Disk encryption or TDE | Media, database-file, log, and backup protection | Useful additional control. Authorized database queries see plaintext |
| Manual envelope encryption | Mature AEAD and external KMS can protect field payloads | Application owns search, context, migrations, rollback, recovery, and removal. Cryptalis must justify this automation cost |

No comparison establishes market size or superiority. The strongest product reason is one reviewed declaration plus a coherent retrofit and removal lifecycle.
If ordinary ORM behavior or safe lifecycle requires pervasive manual application changes, that reason fails its own acceptance test.

## Opened source ledger

All rows use access date 2026-10-06. Dates marked unavailable were not shown by the fetched source.
Vendor documentation is evidence of its published contract, not a reproduced benchmark or audit.

| ID | Actual page used | Publication or release observation | What this established |
|---|---|---|---|
| IS-01 | [SQLAlchemy documentation index](https://docs.sqlalchemy.org/en/21/) | 2.1.3, 2026-10-02 | Current release differs from the old repository ledger |
| IS-02 | [Session events](https://docs.sqlalchemy.org/en/21/orm/session_events.html) | 2.1.3 series | Session execution and flush are separate interception boundaries |
| IS-03 | [Custom types](https://docs.sqlalchemy.org/en/21/core/custom_types.html) | 2.1.3 series | Bind/result processors and comparators exist but do not supply complete row authority |
| IS-04 | [SQLAlchemy asyncio](https://docs.sqlalchemy.org/en/21/orm/extensions/asyncio.html) | 2.1.3 series | Sync event targets and run_sync do not make arbitrary provider I/O asynchronous |
| IS-05 | [PostgreSQL documentation index](https://www.postgresql.org/docs/current/) | 18.6 shown. Patch date unavailable | Current stable documentation resolves to PostgreSQL 18 |
| IS-06 | [PostgreSQL privileges](https://www.postgresql.org/docs/current/ddl-priv.html) | PostgreSQL 18 | INSERT includes COPY FROM. Owners retain authority to alter objects |
| IS-07 | [PostgreSQL COPY](https://www.postgresql.org/docs/current/sql-copy.html) | PostgreSQL 18 | COPY FROM invokes check constraints and triggers |
| IS-08 | [PostgreSQL constraints](https://www.postgresql.org/docs/current/ddl-constraints.html) | PostgreSQL 18 | Unique indexes enforce concurrent uniqueness and support explicit NULL treatment |
| IS-09 | [pgcrypto security limitations](https://www.postgresql.org/docs/current/pgcrypto.html#PGCRYPTO-SECURITY-LIMITATIONS) | PostgreSQL 18 | Database-side crypto requires database and system administrator trust |
| IS-10 | [Python downloads](https://www.python.org/downloads/) | 3.14.8 and 3.13.16, 2026-09-30 | Current interpreter patch observations |
| IS-11 | [Psycopg release notes](https://www.psycopg.org/psycopg3/docs/news.html) | Current 3.3.6. 3.3.7 unreleased | Development documentation banner is not a stable release pin |
| IS-12 | [Psycopg 3.3.6 release](https://github.com/psycopg/psycopg/releases/tag/3.3.6) | Tag displays September 18. Year omitted in rendering | Released tag and async cancellation/performance notes exist |
| IS-13 | [CipherStash docs index](https://cipherstash.com/docs) | Updated 2026-07-30 | Entry point used to navigate current integration, security, and reference pages |
| IS-14 | [CipherStash EQL](https://cipherstash.com/docs/reference/eql) | EQL 3.0.4. Updated 2026-08-31 | Client encryption and PostgreSQL domain/operator architecture, including removal limits |
| IS-15 | [CipherStash Proxy](https://cipherstash.com/docs/reference/proxy) | Updated 2026-07-30 | Protocol proxy is a separate deployment and plaintext boundary |
| IS-16 | [CipherStash Proxy message flow](https://cipherstash.com/docs/reference/proxy/message-flow) | Updated 2026-07-09 | Casts, unresolved scopes, and some COPY forms can pass without encryption |
| IS-17 | [CipherStash Stack SDK](https://cipherstash.com/docs/reference/stack) | Updated 2026-07-30 | TypeScript encryption SDK and separate framework wrappers |
| IS-18 | [CipherStash cryptography](https://cipherstash.com/docs/security/cryptography) | Updated 2026-09-27 | Current published primitives include AES-256-GCM-SIV and equality HMAC-SHA-256 |
| IS-19 | [CipherStash searchable encryption](https://cipherstash.com/docs/concepts/searchable-encryption) | Updated 2026-08-31 | Randomized payload and per-capability search representations have explicit leakage costs |
| IS-20 | [CipherStash Proxy changelog](https://github.com/cipherstash/proxy/blob/main/CHANGELOG.md) | 3.0.0, 2026-08-05. 2.2.4, 2026-06-18 | Maintainer records show past query semantics, upsert encryption, scope, and token-renewal failures |
| IS-21 | [MongoDB Queryable Encryption index](https://www.mongodb.com/docs/manual/core/queryable-encryption/) | Current manual identifies 9.0. Page date unavailable | Automatic/explicit integration and current operator families |
| IS-22 | [MongoDB limitations](https://www.mongodb.com/docs/manual/core/queryable-encryption/reference/limitations/) | Current manual. Page date unavailable | Snapshot versus persistent-query attacker limit, migration restrictions, and uniqueness limits |
| IS-23 | [MongoDB supported operations](https://www.mongodb.com/docs/manual/core/queryable-encryption/reference/supported-operations/) | Current manual. Page date unavailable | Encryption support remains operator-specific |
| IS-24 | [MongoDB compatibility](https://www.mongodb.com/docs/manual/core/queryable-encryption/reference/compatibility/) | Dynamic selectors did not expose a complete matrix | Exact edition/driver support remains unverified. No stale Community/Enterprise claim used |
| IS-25 | [AWS Database Encryption SDK overview](https://docs.aws.amazon.com/database-encryption-sdk/latest/devguide/what-is-database-encryption-sdk.html) | Page date unavailable | Hierarchical branch-key caching avoids a KMS call per record |
| IS-26 | [AWS searchable encryption](https://docs.aws.amazon.com/database-encryption-sdk/latest/devguide/searchable-encryption.html) | Page date unavailable | Truncation, partitioning, skew, correlation, and retrofit costs need dataset analysis |
| IS-27 | [AWS beacon length and partitions](https://docs.aws.amazon.com/database-encryption-sdk/latest/devguide/choosing-beacon-length.html) | Page date unavailable | Collision and fan-out configuration is a security/performance choice |
| IS-28 | [CipherSweet index](https://ciphersweet.paragonie.com/) | Page date unavailable | Library threat boundary, separated keys, and limited operators |
| IS-29 | [CipherSweet security](https://ciphersweet.paragonie.com/security) | Page date unavailable | Chosen inputs, ciphertext relocation, AAD, and index leakage need distinct analysis |
| IS-30 | [SQLAlchemy-Utils index](https://sqlalchemy-utils.readthedocs.io/en/latest/) | 0.42.0 docs. Release date unavailable | Encrypted scalar types exist. Complete lifecycle coverage is not established |
| IS-31 | [Evervault docs index](https://docs.evervault.com/) | Page date unavailable | Entry point used to navigate encryption, Relay, and removal |
| IS-32 | [Evervault encryption](https://docs.evervault.com/developers/evervault-encryption) | Page date unavailable | E3 enclave authority and SDK cryptographic boundary |
| IS-33 | [Evervault Relay](https://docs.evervault.com/relay) | Page date unavailable | HTTP payload selector proxy differs from a PostgreSQL ORM adapter |
| IS-34 | [Evervault removal](https://docs.evervault.com/more/migrating-off-evervault) | Page date unavailable | Hosted CSV decryption/export is its documented offboarding mechanism |
| IS-35 | [SQL Server security index](https://learn.microsoft.com/en-us/sql/relational-databases/security/security-center-for-sql-server-database-engine-and-azure-sql-database?view=sql-server-ver17) | Page date unavailable | Navigation separates file encryption from source encryption |
| IS-36 | [SQL Server TDE](https://learn.microsoft.com/en-us/sql/relational-databases/security/encryption/transparent-data-encryption?view=sql-server-ver17) | Updated 2026-07-20 | File/page encryption and retained restore-key obligations differ from application encryption |
| IS-37 | [Acra index](https://docs.cossacklabs.com/acra/) | Build 2024-09-06 | Fetched release information is stale and cannot establish a current release |
| IS-38 | [AcraServer](https://docs.cossacklabs.com/acra/acra-in-depth/architecture/acraserver/) | Build 2024-09-06 | Historical published SQL proxy mechanism parses traffic and uses external key storage |
| IS-39 | [Tink index](https://developers.google.com/tink) | Updated 2024-11-14 | Entry point used to navigate current primitive and key-management pages |
| IS-40 | [Tink primitive choice](https://developers.google.com/tink/choose-primitive) | Updated 2026-09-17 | KMS envelope AEAD and KMS-encrypted keysets have different RPC costs |
| IS-41 | [Tink cloud KMS](https://developers.google.com/tink/client-side-encryption) | Current page. Date not recorded | KMS envelope encrypts a fresh DEK and invokes KMS per operation |
| IS-42 | [Tink key management](https://developers.google.com/tink/key-management-overview) | Updated 2026-08-11 | External KEK, encrypted keysets, rotation, and language-specific provider limits |
| IS-43 | [Rails Guides index](https://guides.rubyonrails.org/) | v8.1.4. 8.1 release family October 2025 | Navigation identifies the current guide family |
| IS-44 | [Rails Active Record Encryption](https://guides.rubyonrails.org/active_record_encryption.html) | v8.1.4 guide. Page date unavailable | Transparent attributes, deterministic query/uniqueness tradeoff, and previous-scheme migration |
| IS-45 | [Lockbox maintainer README](https://github.com/ankane/lockbox) | Mutable main. Release date unavailable | Attribute encryption, plaintext-column migration, previous keys, AAD, and history exclusions |
| IS-46 | [Blind Index maintainer README](https://github.com/ankane/blind_index) | Mutable main. Release date unavailable | Equality and chosen-input leakage, unique indexes, rotation columns, and name-based key compatibility |
| IS-47 | [RDS PostgreSQL release calendar](https://docs.aws.amazon.com/AmazonRDS/latest/PostgreSQLReleaseNotes/postgresql-release-calendar.html) | RDS 18.6 and 17.11 released 2026-08-25 | Both currently listed through September 2027 standard support |
| IS-48 | [RDS DBInstance API](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DBInstance.html) | Page date unavailable | DbiResourceId is Region-unique and immutable. ARN and endpoint are separate properties |
| IS-49 | [RDS blue/green identity considerations](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/blue-green-deployments-considerations.html) | Page date unavailable | A recreated instance can reuse a name and ARN with a different resource ID |

The proposed experiment cell is CPython 3.14.8, SQLAlchemy 2.1.3, Psycopg 3.3.6, and Amazon RDS PostgreSQL 18.6.
Sync and async use the same Psycopg family. These are research pins, not a supported runtime matrix.
Binary versions, libpq build, operating system, and provider adapter still need recording in executable evidence.
RDS lists 18.6 and 17.11 as available from 2026-08-25. Region-specific creation availability still needs an API check. [IS-47]

The selected production target identity is an external registry binding of AWS account, Region, and `DbiResourceId`.
Include ARN, endpoint, and logical database as checked metadata. ARN or endpoint alone does not prove instance continuity.
AWS documents a recreated instance with the same name and ARN but a different `DbiResourceId`. [IS-48/49]
A blue/green cutover or restored instance requires explicit target admission and a new registry binding.
Do not accept an unchanged DNS name as proof that the admitted target survived.
This registry design is a Cryptalis inference from documented resource identity, not an AWS security guarantee.
The SQL connection also needs an authenticated transport and trusted endpoint resolution.
A local standalone database remains an internal development target, with no equivalent managed identity claim.

## Community pain signals

These pages supplied questions and failure examples. They do not establish present defects or Cryptalis performance.

| Page opened | Date observation | Signal and authoritative check |
|---|---|---|
| [SQLAlchemy discussion 11714](https://github.com/sqlalchemy/sqlalchemy/discussions/11714) | Answer 2024-08-09 | Developers confuse statement DML with flush events. IS-02 confirms separate boundaries |
| [SQLAlchemy-Utils issue 532](https://github.com/kvesteri/sqlalchemy-utils/issues/532) | Opened 2021-06-10 | Historical type-fidelity complaint. Current defect status was not reproduced |
| [CipherStash HN discussion](https://news.ycombinator.com/item?id=48920328) | Relative dates only in fetched page | Readers struggled to find threat and leakage limits. IS-18/19 establish current published design |
| [MongoDB QE HN discussion](https://news.ycombinator.com/item?id=31653710) | 2022-06-07 | Readers raised application compromise, sparse technical detail, and KMS cost questions. IS-22/25 bound relevant facts |
| [MongoDB CSFLE performance report](https://www.reddit.com/r/mongodb/comments/1vzf5qu/api_performance_with_csfle/) | Relative date only. Search and page dates differed | An unverified latency complaint motivates matched baselines. It establishes no numerical budget |

Current sources must replace historical behavior claims when they disagree.
CipherStash's changelog records resolved defects. It does not show that a current release still contains those defects.

## Required evidence before production support

The selected attachment requires public-API state-history, expire, rollback, identity-map, projection-shape, and eager-loader tests.
Query tests need differential SQL truth tables, forced collisions, NULL, normalized duplicates, concurrent uniqueness, and exact pagination.
A hostile database fixture must swap authentic payloads and tokens, omit rows, change requested identifiers, and corrupt the first limited candidate.
Bypass fixtures must include direct driver calls, Core DML, upserts, COPY, ETL, migration scripts, triggers, and alternate worker credentials.
Async fixtures must cover cold keys, delay, throttling, cancellation, concurrent misses, autoflush, restart, fork, and cleanup.
Removal must prove ordinary plaintext mappings and queries after deprotection, while retained backups still have an explicit decoder/key recovery path.
Search construction, key derivation, context encoding, and leakage policy require independent cryptographer review.

No Cryptalis implementation, benchmark, or independent cryptographic audit occurred in this research lane.

## Supplemental competitor check

Access date: 2026-10-06. These are external mechanisms, not additional Cryptalis contracts.
The Acra documentation index names 0.90.0, while the maintainer release list marks 0.96.0, dated September 9, 2024, as latest visible [IS-50].
That mismatch invalidates a current edition/operator matrix inferred from the old index.
The release notes also record parser, NULL, prepared-statement, configuration and Unicode fixes.
These are maintainer-recorded changes, not reproduced vulnerabilities or proof of complete coverage.

Historical Acra search documentation prefixes an HMAC-SHA-256 index to its encryption container [IS-56].
It rewrites predicates to extract that prefix and transforms prepared binds.
Shared ClientID keys permit documented joins, with the corresponding cross-table linkability.
The page describes prefix hashes and edition-specific operators, but its limitation list conflicts with newer release changes.
Treat the current edition/operator/rotation combination as unverified.
The operational model includes a KMS-backed master key, encrypted client storage/search keys and a separate keystore [IS-57].
The published rollback tool decrypts selected rows to SQL output or optional inserts [IS-66].
That is an exit mechanism, not proof of a current mirror or complete crash-safe reversal.
Identifier configuration can affect whether a query receives protection [IS-67].
This reinforces exact-name/schema checks and explicit rejection. It does not establish universal proxy enforcement.

CipherSweet separates field and index keys and documents name-based key derivation [IS-62].
Its blind-index specification exposes slow/fast modes and configurable truncation [IS-63].
The planner balances population, input domain and existing index widths against false positives and inference [IS-60].
Its recommendation is model-dependent, not a confidentiality certification.
Rotation APIs prepare ciphertext and indexes using old/new keys, backends and AAD [IS-61].
Cryptalis chooses stable IDs, full-width terms, forbidden low-cardinality search and full maintenance verification instead.
That choice accepts equality leakage. It does not inherit the privacy effect of deliberately truncated indexes.

All supplemental source rows use access date 2026-10-06.

| ID | Actual page used | Date observation | What this established |
|---|---|---|---|
| IS-50 | [Acra maintainer releases](https://github.com/cossacklabs/acra/releases) | Latest visible 0.96.0, September 9, 2024 | Index/release disagreement and historical parser/configuration changes |
| IS-51 | [Acra security controls](https://docs.cossacklabs.com/acra/security-controls/) | Build September 6, 2024 | Navigation to search and key management |
| IS-52 | [Acra maintenance index](https://docs.cossacklabs.com/acra/configuring-maintaining/) | Same historical build | Navigation to configuration and migrations |
| IS-53 | [Acra depth index](https://docs.cossacklabs.com/acra/acra-in-depth/) | Same historical build | Architecture, crypto and data-flow navigation |
| IS-54 | [CipherSweet PHP index](https://ciphersweet.paragonie.com/php) | Publication date unavailable | Navigation to planning/rotation, limited operators and truncated-index tradeoffs |
| IS-55 | [CipherSweet internals index](https://ciphersweet.paragonie.com/internals) | Publication date unavailable | Navigation to hierarchy and index specification |
| IS-56 | [Acra searchable encryption](https://docs.cossacklabs.com/acra/security-controls/searchable-encryption/) | Build September 6, 2024 | HMAC prefix, SQL/bind rewrite, ClientID join linkage and stale limitation list |
| IS-57 | [Acra key management](https://docs.cossacklabs.com/acra/security-controls/key-management/) | Same historical build | Master key, client DEKs/storage keys, separate search keys and keystore operations |
| IS-58 | [Acra migration guides](https://docs.cossacklabs.com/acra/configuring-maintaining/migrations/) | Same historical build | Published upgrades need version-specific migration review |
| IS-59 | [Acra controls configuration](https://docs.cossacklabs.com/acra/configuring-maintaining/controls-configuration-on-acraserver/) | Same historical build | Per-column configuration, environment/Vault/KMS choices and operational flags |
| IS-60 | [CipherSweet index planning](https://ciphersweet.paragonie.com/php/blind-index-planning) | Publication date unavailable | Index size recommendations depend on population/domain/other indexes |
| IS-61 | [CipherSweet rotation](https://ciphersweet.paragonie.com/php/key-rotation) | Publication date unavailable | Old/new field/row/multi-row preparation returns ciphertext and indexes with optional changed AAD |
| IS-62 | [CipherSweet key hierarchy](https://ciphersweet.paragonie.com/internals/key-hierarchy) | Publication date unavailable | Field/index domain separation and packed-name derivation |
| IS-63 | [CipherSweet blind-index specification](https://ciphersweet.paragonie.com/internals/blind-index) | Publication date unavailable | Slow/fast backends and explicit bit truncation are distinct configurations |
| IS-64 | [Acra general configuration](https://docs.cossacklabs.com/acra/configuring-maintaining/general-configuration/) | Build September 6, 2024 | Utility and service inventory, including rollback and rotation |
| IS-65 | [AcraServer flags](https://docs.cossacklabs.com/acra/configuring-maintaining/general-configuration/acra-server/) | Same historical build | Configuration/TLS/key-storage flags expose operational complexity |
| IS-66 | [Acra rollback](https://docs.cossacklabs.com/acra/configuring-maintaining/general-configuration/acra-rollback/) | Same historical build | Decrypt selected data to output or explicit inserts. Keys and SQL selections remain prerequisites |
| IS-67 | [Acra encryptor configuration](https://docs.cossacklabs.com/acra/configuring-maintaining/general-configuration/acra-server/encryptor-config/) | Same historical build | Column order and identifier matching affect interception. Unmatched configured names can omit protection |
