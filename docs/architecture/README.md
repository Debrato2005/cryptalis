# Cryptalis Architecture Blueprint

Status: Accepted research direction; pre-implementation

Last reviewed: 2026-08-22

This document is the sole owner of Cryptalis technical architecture. It replaces the superseded
gateway-first ADR set. Decisions remain provisional until the named prototype and verification gates
pass.

## 1. Final thesis and learning boundary

Cryptalis is a **SQLAlchemy-native protection compiler**, not a new cipher and not a transparent SQL
proxy. It turns a logical protection declaration into five synchronized plans:

1. an in-process crypto plan;
2. a physical PostgreSQL schema plan;
3. a SQLAlchemy query-rewrite plan;
4. a key-lifecycle and shredding plan; and
5. an evidence plan for compatibility, leakage, migration, and attack impact.

The architecture is optimized for deep learning through a coherent security system, not for avoiding
features that competitors already implement. CipherStash, MongoDB Queryable Encryption, Rails,
`pydantic-encryption`, Acra, Semgrep, CodeQL, ZAP and Burp are reference systems to study, compare,
integrate and sometimes independently reproduce. Competitor overlap is not a stop condition.

Production-facing protection still uses reviewed primitives and evidence-bound claims. Educational
implementations of known constructions and security engines are allowed when attributed, isolated,
tested against references and clearly labeled. The governing criteria and complete system
are in the [learning-first research philosophy](../learning-first-research-philosophy.md).

## 2. Trust and threat model

The application process is trusted to handle plaintext. PostgreSQL, its operators, database
credentials, dumps, and backups are outside the plaintext boundary. KMS/Vault root custody is
separate from PostgreSQL.

Protected threats are database extraction, backup leakage, direct database access, and accidental
plaintext persistence through supported paths. Out of scope are arbitrary code execution in the
trusted process, a fully compromised application host, XSS, authentication bypass, SQL injection
prevention, and plaintext copied after decryption.

Model A does increase accidental log and serialization exposure compared with opaque values. That
trade-off is accepted for transparent fields, mitigated by log filters and safe diagnostics, and
avoidable per field through controlled access. Documentation must never collapse “database attack
succeeded” into “plaintext exposed.”

## 3. Access models

### Transparent access: primary

The mapped logical attribute behaves as its declared Python type. Writes are encrypted before SQL;
loads are decrypted locally on access. Pydantic and application serializers therefore see plaintext
when they access the field. No claim is made that transparent access prevents application logging.

### Controlled access: optional

Controlled fields remain opaque and require purpose/identity-bound reveal. This mode is justified
for secrets such as national identifiers, recovery material, or medical notes. It advances as a
parallel profile because it doubles serialization, typing, validation, testing, and user-education
paths and must not silently share transparent-field assumptions.

A controlled field is an active parallel workstream. It provides additional security only if decryption depends on authority the
compromised workload cannot freely assert—for example, a verified end-user identity or separately
scoped short-lived grant. A local wrapper using the same broad workload credential is merely an
accidental-disclosure guard.

## 4. Protection Manifest intermediate representation

`cryptalis.protect()` compiles into a canonical, versioned, hash-addressed manifest. The manifest is
the source of truth; model decorators, migration scripts, runtime adapters, and CLI tools consume it
instead of independently inferring policy.

Each protected field records:

- model, table, logical attribute, Python type, and original database type;
- physical ciphertext, metadata, and search-index representation;
- tenant, subject, immutable record identity, and key/index domains;
- access mode and enabled query capabilities;
- normalization, null, uniqueness, and constraint semantics;
- algorithm suite and envelope/index versions;
- migration state, previous readable versions, and cutover requirements;
- declared leakage profile and shredding behavior; and
- supported ORM/Core operations and required failure behavior.

Manifest compilation rejects ambiguous ownership, mutable subject identity, incompatible constraints,
unknown capabilities, unsafe defaults, and undeclared cross-tenant search. A manifest diff is a
security-relevant schema change and must be reviewed like code.

## 5. SQLAlchemy data-plane architecture

A scalar `TypeDecorator` alone is insufficient because bind/result processors receive a value and
dialect, not tenant, subject, record identity, or authenticated workflow context. Remote provider
calls inside those synchronous processors can also block an async event loop.

The proposed adapter therefore combines:

- hidden mapped physical attributes for ciphertext and search representations;
- a public descriptor exposing the logical Python value;
- mapper configuration that installs capability-aware comparators;
- `before_flush` processing that sees complete row context and writes physical attributes;
- `do_orm_execute` guards for ORM statements and bulk operations;
- Core/engine guards for declared strict environments; and
- a protected-session context that establishes a validated tenant and prewarms required branch-key
  material before normal synchronous SQLAlchemy internals run.

Plaintext logical state and ciphertext physical state remain separate; the adapter must not replace
the public value with ciphertext during flush. Prototype gates cover dirty tracking, rollback,
expiration, refresh, merge, detach, relationship loading, autoflush, server defaults, Pydantic
serialization, and identity-map reuse.

`AsyncSession` is a proxy over synchronous SQLAlchemy internals. Transparent attribute access cannot
perform awaitable KMS I/O. Consequently, remote key acquisition occurs only in an explicit async
session/context setup or batch prefetch operation. Once active, field crypto and search-token
generation are local. A cold or missing context fails; it never blocks secretly or stores plaintext.

## 6. Query rewriting and compatibility

SQLAlchemy comparators own logical operator mapping:

```text
User.email == value  -> users.email_eq == equality_token(value)
User.email.in_(xs)   -> users.email_eq IN equality_tokens(xs)
```

The right-hand plaintext becomes a typed bind value whose token is generated locally under the
active tenant/index context. `do_orm_execute` validates the complete expression tree, tenant scope,
bulk semantics, and manifest version before execution. Statement rewriting is a guard and planner,
not a universal SQL parser.

Unsupported operations raise `UnsupportedEncryptedQuery` before SQL emission. Raw text, direct
asyncpg, external ETL, and uninstrumented connections cannot be universally intercepted. Production
protection therefore also uses database domains or constraints that reject malformed ciphertext
envelopes and missing required index terms. Those checks prevent obvious plaintext persistence; they
do not prove that arbitrary ciphertext was produced by Cryptalis.

The compatibility contract is versioned by Python, SQLAlchemy, driver, PostgreSQL, operation, loader
strategy, and sync/async path. Anything absent is unsupported, not “probably works.”

## 7. Search architecture and leakage

Every field stores randomized authenticated ciphertext. Search is a separate, capability-specific
representation with domain-separated keys. Search is never silently inferred or enabled.

| Capability | Construction direction | Query semantics | Leakage and lifecycle cost | Decision |
|---|---|---|---|---|
| Equality | Keyed blind index over canonical normalized value | `==`, `!=`, `IN`, `NOT IN` | Repetition, frequency, query/access patterns; low-entropy guessing if key leaks | Active production-candidate workstream |
| Scoped uniqueness | Unique composite index over tenant/domain plus equality token | normalized uniqueness | Same as equality; rotation needs dual tokens | Active production-candidate workstream |
| Equijoin/grouping | Shared explicit join-domain token | equality across declared fields | Cross-column correlation; shared key complicates shredding | Active research workstream |
| Range/order | Published ORE/OPE or another analyzed scheme in an isolated research track; reviewed path for production | comparisons, sort, extrema | Order and query-pattern leakage; difficult updates/rotation | Active research workstream |
| Prefix/text/fuzzy | Token/trigram/Bloom-filter experiments in companion rows | declared text operations | Token/pattern leakage, false positives, large indexes | Active experimental workstream |
| JSON/path | Per-path capability-token experiments in companion rows | declared paths/operators | Structure/path/query leakage and complex drift | Active experimental workstream |

CipherStash currently documents AES-256-GCM-SIV payloads, HMAC equality terms, OPE/ORE range terms,
encrypted Bloom-filter text terms, and structured query support. Cryptalis may independently study
and reproduce known constructions, but never from marketing descriptions alone. Research work
requires primary papers/specifications, an explicit threat/leakage model, adversarial vectors,
migration/lifecycle design, attribution, and comparison with established implementations. A
production profile additionally requires a reviewed library/provider or external cryptographic
review and an evidence-backed reason to accept the risk.

### Equality details

Normalization is declared and versioned: for example Unicode form, case folding, whitespace rules,
and type encoding. Tokens are domain-separated by tenant, table/logical domain, field or explicit
join domain, normalization version, and index version. Null remains a distinct declared state.

An equality index is not encryption and must never contain an unkeyed hash. Short or low-entropy
values remain risky because frequency and online query observation can reveal candidates. Index-key
rotation uses a bounded dual-token transition; queries include active and previous versions only
during a declared migration window.

### Search versus shredding

Cross-subject search and strict subject erasure are in tension:

- A tenant-scoped index enables one token to find many subjects, but destroying one subject key does
  not destroy the shared search key. Current index rows must be deleted and old backups may retain
  correlation tokens.
- A subject-scoped index is destroyed with the subject key, but cannot support a normal tenant-wide
  equality lookup without generating a token for every subject.

The manifest therefore requires one of two profiles. `searchable` permits tenant/domain-scoped
indexes and gives a bounded ciphertext-shredding claim; `strict_shred` permits only subject-scoped
indexes or no search. Cryptalis must never claim that deleting a subject encryption key erases
shared index leakage.

## 8. Minimum-leakage planning

`cryptalis plan` combines four evidence sources:

1. explicit declarations and constraints;
2. SQLAlchemy expression-tree inspection during tests;
3. conservative static AST discovery of obvious ORM expressions; and
4. opt-in runtime statement tracing using synthetic or redacted values.

It reports observed operators, source locations, confidence, missing capabilities, unnecessary
capabilities, leakage changes, and migration consequences. Static analysis cannot resolve dynamic
query builders, monkey-patching, raw SQL, generated code, or unexecuted branches. Runtime tracing
cannot prove unobserved production behavior. Therefore `plan` recommends; it never silently expands
the manifest or claims completeness.

`cryptalis doctor` validates manifest/model/schema/Alembic consistency, unsupported operations,
raw/bulk escape paths, unsafe constraints, plaintext-compatible columns, provider/cache settings,
and previous migration evidence. `cryptalis schema explain Model.field` shows logical-to-physical
mapping, keys, capabilities, leakage, constraints, versions, and shredding profile.

## 9. Physical PostgreSQL schema

Scalar protected fields use explicit same-table companion columns because they preserve transaction
atomicity and conventional indexes:

```text
email_ct        BYTEA or versioned domain, NOT NULL as declared
email_meta      compact version/key metadata when not embedded in the envelope
email_eq_v1     BYTEA, indexed only when equality is enabled
```

Variable-cardinality text and JSON tokens, if ever accepted, use companion tables keyed by immutable
record identity. Physical names are deterministic but collision-checked. Relational identifiers,
tenant IDs, and foreign keys remain unencrypted by default; protecting them destroys ordinary join
and integrity semantics and must require a separate design review.

Runtime startup may validate schema but never add/drop columns or backfill data. Automatic mutation
would make deployment order, rollback, locks, and data-loss behavior unacceptable.

## 10. Schema compiler and Alembic

The compiler emits a reviewable schema diff and custom Alembic operations for protected columns,
indexes, constraints, manifest checkpoints, and migration phases. Alembic supports custom comparison
functions, renderers, and operation plugins, so integration is feasible; autogeneration still cannot
prove that a data backfill or cutover is safe.

`alembic revision --autogenerate` may render Cryptalis operations when its plugin is enabled.
`cryptalis migrate plan` additionally explains data motion, leakage, locks, expected storage,
rollback limits, and required verification. Generated revisions are never auto-applied.

Constraint rules:

- `NOT NULL` maps to ciphertext presence and logical-null encoding rules.
- `UNIQUE` requires an equality capability and a tenant/domain-scoped composite unique index.
- plaintext `CHECK`, functional indexes, defaults, and generated columns are rejected unless a
  reviewed protected equivalent exists.
- foreign keys remain on unprotected identifiers; encrypted payload fields are not FK targets.
- changing normalization, index domain, algorithm, or key version creates a migration, not an
  in-place metadata edit.

## 11. Existing-database migration

Migration is an explicit state machine:

```text
inspect -> expand -> chunked backfill -> round-trip/index verify
        -> dual-read/controlled dual-write -> cutover -> observe -> contract
```

Jobs are resumable, idempotent, bounded, and keyed by immutable primary key ranges or a durable
cursor. Checkpoints contain counts, hashes, versions, and errors—not plaintext. Backfill crypto is
local and batched; provider calls unwrap branch material, not each field.

Plaintext coexistence is allowed only in a named migration window. Reads of legacy plaintext are
explicitly enabled, telemetry-counted, and fail after cutover. Rollback before contract may restore
the old application path; rollback after plaintext deletion cannot promise recovery without a
separately approved snapshot. The migration verifier samples decrypted round trips, checks full-row
counts and index consistency, scans for known synthetic plaintext, and blocks contraction on
inconclusive evidence.

## 12. Key hierarchy and providers

```text
provider root KEK
  -> tenant branch-key generations
      -> wrapped subject-key generations
          -> domain-separated field/search keys or per-value derived keys
```

KMS/Vault owns root wrapping authority, not field-by-field encryption. The provider interface is
narrow: wrap/unwrap tenant branch material, identify provider/key versions, and report lifecycle
state. Local crypto derives or wraps subject and value material with established constructions and
authenticated context. Tenant, subject, model, field, record, algorithm, and version identifiers are
canonical AAD where applicable.

V1 implements one deterministic local-development provider and one production adapter. Provider
independence is an interface and vector suite, not a claim that AWS KMS, Google Cloud KMS, and Vault
have identical deletion, audit, availability, or rotation semantics.

Per-subject keys are practical only as wrapped application records; creating a cloud KMS key per
subject is too expensive and operationally heavy. Subject key generations support new-write
rotation while previous generations remain decrypt-only until migration or retirement.

## 13. Caching and availability

Local branch/subject material is required for acceptable throughput and async-safe transparency.
Every cache entry is bounded by tenant, key ID, generation, operation, manifest version, TTL, and
capacity. Cache hits avoid provider I/O; misses occur in explicit warm/prefetch APIs. No plaintext or
keys enter shared Redis/memcached caches.

Caching weakens immediate revocation and shredding. The control plane publishes monotonically
increasing revocation epochs; workers stop new operations, evict matching entries, and acknowledge.
Completion waits for all registered live instances or for their lease plus maximum TTL to expire.
Offline or partitioned workers make immediate global destruction impossible.

On provider outage, an already authorized cache entry may continue only under a documented bounded
offline policy. Cold operations fail closed. The system reports degraded key authority; it does not
silently persist plaintext or extend TTL.

## 14. Rotation, revocation, and shredding

Rotation creates a new generation for writes while retaining old generations for reads and
controlled re-encryption. Revocation fences new encrypt/decrypt operations immediately within the
cache-acknowledgement model but retains recoverable key records. Shredding is destructive and
idempotent:

1. validate scope and authorization;
2. fence the subject and increment its revocation epoch;
3. stop writes and search-index creation;
4. invalidate and collect cache acknowledgements;
5. delete every wrapped subject-key generation and temporary migration copy;
6. delete subject-owned search-index rows and document shared-index residue;
7. write a durable tombstone outside restorable application snapshots;
8. verify restore behavior and remaining provider state; and
9. issue a signed receipt only after the declared completion condition.

The truthful guarantee is:

> After registered instances acknowledge the fence or lose their lease and cache TTL, all
> Cryptalis-managed wrapped subject-key generations covered by the receipt are destroyed and the
> durable tombstone prevents their restoration through supported workflows. Covered ciphertext is
> computationally inaccessible under the stated provider, cache, backup, export, and host
> assumptions.

This does not prove memory zeroization, deletion of plaintext logs/exports, removal from unmanaged
backups, destruction of shared search leakage, legal erasure, or honesty of a compromised control
plane.

## 15. Receipts and audit

Receipts contain tenant/subject pseudonymous identifiers, manifest and key generations, requested
and completed times, instance leases/acknowledgements, deleted key-record identifiers, search-index
treatment, provider status, tombstone/checkpoint identifiers, assumptions, unresolved exceptions,
and a signature. They prove that the recorded workflow and checks occurred under the signer’s trust
model—not that every copy of plaintext or key material ceased to exist.

Lifecycle, migration, manifest, provider, verification, and controlled-reveal events use canonical
redacted records in a hash chain with signed checkpoints exported to an independent append-only
witness. Transparent reads are not synchronously audited by default: doing so would add a hidden
availability dependency and still would not prove how plaintext was used. Optional access telemetry
is best-effort and explicitly weaker.

Audit, logs, metrics, traces, receipts, exceptions, and CLI output never contain plaintext, raw
tokens, key bytes, or ciphertext bodies. Framework log filters are generated from the manifest, but
Python cannot provide general taint tracking after a transparent field becomes a normal `str`.

## 16. Verification and academic module

The full adversarial decision is in
[Security Assurance Suite research](../security-assurance-suite-research.md). The accepted product
boundary is narrow: the selling point is a manifest-backed protection graph, deterministic
protection scenarios, exposure correlation, and evidence semantics. Mature
SAST/DAST/pentesting/network tools remain replaceable collectors and comparison systems. The
learning architecture may also implement AST/CFG/data-flow/taint, crawler/mutator/oracle, template
and flow-analysis subsystems internally. Those engines are valuable research even when generic;
causal protected-asset evidence remains the differentiated product claim.

The mandatory IS-Lab module is **Web Application Pentesting**. A quarantined local harness combines
OWASP ZAP automation with deterministic Cryptalis scenarios. It compares pinned baseline and
protected deployments and reports independently:

```text
execution, applicability, exploit result, database access,
protected-column extraction, plaintext exposure, and control outcome
```

The core catalogue covers SQL injection extraction, stolen DB credentials, raw/bulk bypasses,
cross-tenant/subject access, migration windows, provider outage, ciphertext relocation, cache
revocation, shredding/restoration, audit mutation, and seeded plaintext in logs/artifacts. Generic
scanner findings remain visible but are not converted into Cryptalis claims.

PCAP/TShark/Zeek correlation is an active networking workstream. It may corroborate other evidence,
but with TLS a passive capture cannot
inspect application or database plaintext without controlled session-key logging or a capture point
inside the encrypted boundary. Direct PostgreSQL rows, emitted SQL parameters in a synthetic test
driver, and application artifacts are stronger evidence. Nmap may validate deployment exposure but
is too shallow to validate field protection.

`cryptalis verify` checks manifest/schema agreement, envelope structure, known-canary absence,
index consistency, key generations, migration completion, tombstones, fail-loud behavior, and
evidence completeness. Missing collectors or controls produce `inconclusive`, never pass. A pass
also requires positive and negative collector controls plus a narrow semantic control mutant; a
detector that cannot identify deliberately seeded exposure or weakened protection cannot support an
assurance claim.

## 17. Performance and storage evidence

No performance number is accepted without a pinned benchmark. Compare baseline SQLAlchemy,
Cryptalis, and `pydantic-encryption`; compare CipherStash only where equivalent deployment and
licensing allow reproduction. Record inserts/reads/queries per second, p50/p95/p99, CPU, memory,
PostgreSQL size, index growth, cache hit rate, provider calls, cold-start cost, and migration
throughput.

Scenarios separate steady cache hits, cold tenant/subject paths, single-row, batch, sync, async,
rotation dual-index windows, and provider outage. Local AEAD/HMAC should be cheap relative to network
KMS, but this is a hypothesis. Short fields can have high percentage overhead because nonce/tag,
version/AAD metadata, alignment, and one or more fixed-size indexes dominate payload size. Text and
JSON indexes can exceed ciphertext size many times and require a feature-specific budget before
acceptance.

## 18. Flat capability program

All capability workstreams are active from the start:

1. Manifest, randomized AEAD, search representations, transparent and controlled SQLAlchemy access,
   and explainability.
2. Existing-data migration, constraint compilation, drift detection, and compatibility Doctor.
3. Subject lifecycle, distributed cache fencing, shredding receipts, and restore tests.
4. Minimum-leakage static/runtime planning, the protection graph, and the verification corpus.
5. Doctor syntax/semantic IR, symbols, CFG, local and interprocedural data flow, taint and rules.
6. Pentest endpoint/state graphs, crawling, authentication, mutators, payloads, oracles and replay,
   continuously compared with ZAP, Burp, sqlmap and Nuclei.
7. Writer provenance, distributed fault injection, PCAP/flow correlation and DevSecOps evidence.
8. Equijoin/grouping, range/order, text/fuzzy and structured/JSON search as construction-specific
   research and production-candidate profiles.

Workstreams may proceed concurrently in research and documentation. A workstream crosses into a
production profile only after its own published-construction study, leakage and lifecycle review,
vectors, adversarial tests, benchmarks, compatibility evidence, and required independent review.

This is one product with progressive manifest capabilities, not multiple unrelated services.

## 19. Solo flat-program execution

Cryptalis is built by one person across the complete set of active workstreams. The initial
dependency spine is:

1. manifest and envelope foundations;
2. one transparent sync/async SQLAlchemy path;
3. equality/`IN`/scoped uniqueness;
4. schema/Alembic and one resumable migration;
5. tenant/subject lifecycle and cache fencing;
6. bounded Doctor/Verify and ZAP-backed evidence; and
7. compatibility, fuzzing, benchmarks and review.

This spine does not prohibit Doctor, Pentest, advanced-search, networking, or lifecycle experiments
before the core is complete. It identifies dependencies for production claims, not permission to
learn or build. The builder may advance multiple workstreams, but each source change is still typed
and verified one file at a time. AI assistance may update documentation and provide one file at a
time in conversation; the solo builder manually types all source, tests, migrations, configuration
and CI code. The complete working agreement and workstream maps are in the
[solo build guide](../cryptalis-build-guide.md).

## 20. Fatal risks and stop conditions

1. Transparent async access may require unacceptable session ceremony or hidden blocking.
2. SQLAlchemy bypass detection may be too incomplete to support the persistence claim.
3. Automatic schema/migration planning may become a fragile framework rather than a library.
4. Tenant-wide search indexes weaken subject-shredding claims.
5. Cached keys prevent immediate revocation/destruction.
6. Normal Python plaintext inevitably reaches some application logs and serializers.
7. Equality indexes leak frequency and are weak for low-entropy domains.
8. Advanced search requires expertise and reviewed implementations the solo builder may not have.
9. Provider semantics differ enough to make portable lifecycle guarantees misleading.
10. A solo builder may spread across ORM, crypto operations, migrations, SAST/DAST and evidence
    without completing a robust vertical slice.

Stop, redesign, or reclassify the affected capability if its high-risk prototypes cannot demonstrate
row-context correctness, async-safe local hot paths, loud rejection of known bypasses,
deterministic migration recovery, or bounded multi-instance cache fencing. A failed gate constrains
that capability's production claim; it does not automatically narrow unrelated research workstreams.

## 21. Reasons not to build

- Basic field encryption is already solved well enough for many applications.
- CipherStash offers substantially broader encrypted queries and a maintained key service.
- MongoDB Queryable Encryption offers deeper cryptographic integration if changing databases is
  acceptable.
- Rails users already have mature transparent encryption; Python demand is not yet validated.
- Search leakage and lifecycle complexity may exceed the risk reduction for many teams.
- A proxy or managed product may be operationally easier than ORM-wide enforcement.

These are reasons not to build Cryptalis solely as a commercial replacement. They do not invalidate
it as a falsifiable learning-first systems/security project. Before any product claim, it still needs
working adoption interviews, compatibility evidence, adversarial review, and benchmarks—not
ambition alone.

## 22. Evidence sources

Primary references current at the review date:

- [SQLAlchemy custom types](https://docs.sqlalchemy.org/en/20/core/custom_types.html),
  [comparators](https://docs.sqlalchemy.org/en/20/orm/internals.html), and
  [session execution hooks](https://docs.sqlalchemy.org/en/20/orm/session_events.html)
- [Alembic autogeneration](https://alembic.sqlalchemy.org/en/latest/api/autogenerate.html) and
  [plugin API](https://alembic.sqlalchemy.org/en/latest/api/plugins.html)
- [CipherStash cryptography](https://cipherstash.com/docs/security/cryptography),
  [Proxy flow](https://cipherstash.com/docs/stack/cipherstash/proxy/message-flow), and
  [identity-aware encryption](https://cipherstash.com/docs/stack/encryption/identity)
- [MongoDB Queryable Encryption supported operations](https://www.mongodb.com/docs/v8.0/core/queryable-encryption/reference/supported-operations/)
- [CipherSweet](https://github.com/paragonie/ciphersweet)
- [Rails Active Record Encryption](https://guides.rubyonrails.org/active_record_encryption.html)
- [`pydantic-encryption`](https://pypi.org/project/pydantic-encryption/)
- [AWS hierarchical keyring](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/use-hierarchical-keyring.html),
  [Google Cloud envelope encryption](https://docs.cloud.google.com/kms/docs/envelope-encryption), and
  [Vault Transit](https://developer.hashicorp.com/vault/docs/secrets/transit)
- [PostgreSQL `pgcrypto` limitations](https://www.postgresql.org/docs/current/pgcrypto.html)
- [OWASP ZAP Automation Framework](https://www.zaproxy.org/docs/desktop/addons/automation-framework/)
- [NIST SP 800-88 Rev. 2](https://csrc.nist.gov/pubs/sp/800/88/r2/final)
