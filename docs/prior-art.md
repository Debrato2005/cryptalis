# Prior Art, Learning, and Claim Discipline

Status: Working research summary; re-verify before public claims

Last reviewed: 2026-08-22

This document owns competitive positioning and reference-system discipline. Documented capability
is not independently reproduced capability, and vendor performance statements are not Cryptalis
evidence. Competitor overlap is not a reason to reject a learning-rich feature; it is a reason to
attribute prior art, study the threat model, compare behavior and avoid unsupported novelty claims.

## Verdict

Cryptalis cannot realistically become “better than every competitor.” The competitors optimize
different trust boundaries, databases, languages, and operational models. Market claims stay
specific and testable, while the complete research architecture remains active:

> Become the strongest open Python/SQLAlchemy workflow for compiling explicit protection and minimum
> leakage into ORM behavior, reviewable schema/migrations, subject-key lifecycle, compatibility
> diagnostics, and attack-impact evidence.

Cryptalis should not claim better or novel cryptography merely because it independently implements
prior art. It may reproduce valuable CipherStash, MongoDB, CipherSweet, Acra, SAST and DAST concepts
for learning, provided the work is attributed, independently designed, isolated when experimental,
tested against known vectors and compared with established implementations. See the
[learning-first philosophy](learning-first-research-philosophy.md).

## Competitive matrix

| System | Objectively stronger at | Limitation relevant to Cryptalis | Cryptalis response |
|---|---|---|---|
| CipherStash | Broad Postgres search, published leakage choices, wire proxy, SDK, per-value keys, identity-bound derivation, bulk operations, and current plan/implementation/status workflows | TypeScript/product ecosystem and managed control-plane assumptions; not documented as a SQLAlchemy source/attack/exposure correlator | Benchmark and study deeply; independently implement valuable concepts where learning/correctness gates justify it |
| `pydantic-encryption` | Existing Python package with SQLAlchemy, blind indexes, AWS KMS, async/deferred batch decrypt | Does not establish the full manifest/schema compiler, distributed shredding, drift/compatibility planning, or attack-evidence thesis | Benchmark, reuse, contribute, or independently implement; existing coverage does not invalidate the learning project |
| MongoDB Queryable Encryption | Cryptographic research, automatic driver integration, randomized searchable encryption, equality/range support, fail-loud operator catalogue | MongoDB-specific; limited operations; migration and uniqueness constraints remain material | Reproduce its compatibility discipline and study driver/query architecture without copying protocols blindly |
| CipherSweet | Mature open blind-index discipline, key/domain separation, framework adapters, conservative threat-model guidance | Primarily PHP; no SQLAlchemy/Alembic lifecycle compiler | Copy leakage discipline and transformation/index separation; do not claim blind indexes as novel |
| Rails Active Record Encryption | Mature transparent DX, deterministic equality, log-parameter filtering, coexistence with old schemes | Deterministic ciphertext leaks equality; Rails-specific; lifecycle/shredding is not its central abstraction | Match framework ergonomics and migration clarity; prefer randomized ciphertext plus separate blind indexes |
| Django encrypted-field packages | Familiar declarative field APIs across a large Python ecosystem | Fragmented packages, varying maintenance/security, often limited querying/key lifecycle | Validate demand, but remain SQLAlchemy-first until the core contract is proven |
| AWS Encryption SDK/KMS | Reviewed envelope encryption, hierarchical keyring, branch-key caching, IAM/audit, managed root custody | Provider-specific store/cache semantics; not an ORM, migration, or subject-lifecycle product | Use as production provider/reference; keep provider calls off field hot paths |
| Google Cloud KMS | Managed KEKs, versioning, envelope guidance, scheduled destruction | Provider-specific delayed destruction and IAM semantics | Provider adapter reports actual state; never normalize delayed deletion into immediate proof |
| Vault Transit | Self-hostable crypto service, derivation, datakeys, ACLs, rotation/deletion | Per-operation service calls can dominate; key deletion requires configuration; operational burden | Support narrow wrap/unwrap adapter; local data-plane crypto remains default |
| PostgreSQL `pgcrypto` | Simple SQL-level crypto and established deployment | Database/server sees keys/plaintext and DBAs are trusted; weak fit for DB-compromise threat | Explicitly reject as primary boundary |
| Acra | Encryption/search, SQL firewall, anomaly reactions, honeytokens, SIEM events, signed audit logs, and key inventory | Proxy/operational model; not documented as SQLAlchemy/Alembic protection-graph and attack-exposure analysis | Study and selectively reproduce SQL-policy, honeytoken, reaction and audit concepts; retain framework-semantic correlation |
| Thales/Fortanix/Imperva | Estate-wide discovery, classification, posture, activity monitoring, centralized key inventory, and compliance operations | Enterprise breadth rather than developer-local SQLAlchemy causality | Integrate/export first; build only bounded subsystems with clear learning and test value |

## CipherStash deep comparison

CipherStash is the primary benchmark. Its current documentation describes:

- application-process encryption with AES-256-GCM-SIV payload protection;
- HMAC-SHA-256 equality terms;
- CLLW order-preserving or block-ORE range/order terms;
- encrypted Bloom-filter/trigram text representations;
- query/configuration support for structured values;
- a PostgreSQL wire-protocol Proxy that transparently rewrites parameters and decrypts results;
- an SDK with single, model, and bulk operations;
- ZeroKMS split authority/client material, keysets, cache-aware initialization, and identity-aware
  lock contexts; and
- explicit metrics and failure modes for proxy parsing, key initialization, and cache churn.

Its current CLI also documents `init`, `plan`, `impl`, database validation/status, and per-column
encryption phase/progress. Consequently, “plan and track an encryption migration” is no longer a
credible Cryptalis differentiator by itself. The remaining test is whether Cryptalis can connect
SQLAlchemy source semantics and Alembic state to exercised bypasses and observed exposure. Sources:
[CLI](https://cipherstash.com/docs/stack/cipherstash/cli),
[plan](https://cipherstash.com/docs/stack/cipherstash/cli/plan),
[implementation](https://cipherstash.com/docs/stack/cipherstash/cli/impl), and
[status](https://cipherstash.com/docs/stack/cipherstash/cli/status).

These are not superficial features. Equality terms disclose repetition/frequency and query access.
Order-preserving/order-revealing representations disclose ordering and can enable inference attacks.
Text/token structures disclose token or pattern relationships and consume substantial storage.
Identity-aware decryption can provide a boundary that a broad workload credential alone does not.

CipherStash is stronger than Cryptalis on advanced query capability, deployed cryptographic key
derivation, and operational maturity. Cryptalis could be preferable only where teams require
SQLAlchemy-specific mapping/query/schema understanding, an open provider abstraction, existing-data
migration intelligence, per-subject lifecycle semantics, or a reproducible local evidence harness.
Those are hypotheses until implemented and benchmarked.

Sources:
[cryptography](https://cipherstash.com/docs/security/cryptography),
[searchable encryption](https://cipherstash.com/docs/concepts/searchable-encryption),
[Proxy message flow](https://cipherstash.com/docs/stack/cipherstash/proxy/message-flow),
[identity-aware encryption](https://cipherstash.com/docs/stack/encryption/identity), and
[troubleshooting/metrics](https://cipherstash.com/docs/stack/cipherstash/proxy/troubleshooting).

## Security-assurance competitors

Acra is a direct challenge to broad Cryptalis assurance positioning. Its documented security
controls already combine data protection with a SQL firewall, anomaly responses, honeytokens,
security/SIEM events, cryptographically signed audit logs, and key inventory. Cryptalis should not
claim that data-protection products stop at encryption status. Its narrower opportunity is to
correlate declared SQLAlchemy fields, physical schema, Alembic history, write paths, key/cache state,
controlled attacks, and exposure artifacts. Sources: [Acra security controls](https://docs.cossacklabs.com/acra/security-controls/),
[SQL firewall](https://docs.cossacklabs.com/acra/security-controls/sql-firewall/), and
[security logging/events](https://docs.cossacklabs.com/acra/security-controls/security-logging-and-events/).

Enterprise platforms also defeat any estate-wide posture claim. Thales CipherTrust documents data
discovery/classification, activity monitoring, risk analysis, protection, and centralized key
management; Fortanix emphasizes cryptographic posture/key discovery; Imperva provides broad
discovery and unified data-security visibility. Cryptalis should consume or export their evidence
where useful. It may build bounded posture, policy or monitoring experiments when the learning value
is concrete, but should not drift into an untestable enterprise-platform clone. Sources:
[CipherTrust Data Security Platform](https://cpl.thalesgroup.com/encryption/data-security-platform),
[Fortanix platform](https://www.fortanix.com/platform), and
[Imperva unified visibility](https://www.imperva.com/products/data-security/unified-visibility/).

The complete tooling and integration decision is in the
[security assurance research](security-assurance-suite-research.md).

## `pydantic-encryption` test

As of the review date, `pydantic-encryption` documents field encryption, hashing, blind indexes,
SQLAlchemy integration, Python 3.11–3.14 support, AWS KMS, and a `DeferredDecryptMixin` that batch
decrypts sibling instances on first attribute access. It explicitly addresses the fact that
synchronous SQLAlchemy type hooks and remote KMS can block async workloads.

Therefore this is not a valid Cryptalis pitch:

> “Transparent encrypted SQLAlchemy fields with AWS KMS and equality lookup.”

A developer may obtain most of that with the existing package and project-specific migrations. The
remaining justification must be concrete: canonical manifest/IR, generated physical schema,
constraint migration, query compatibility/fail-loud guards, multi-instance subject-key fencing,
restore-resistant tombstones, leakage planning, drift checks, and exposure verification. If the
integrated system currently demonstrates only the smaller pitch, that evidence may still be a valid
checkpoint, but it is not a credible product-differentiation claim. The broader protection,
analysis, pentesting, lifecycle, networking and searchable-encryption workstreams remain active.
Contributing findings upstream remains a responsible option.
Source: [`pydantic-encryption` on PyPI](https://pypi.org/project/pydantic-encryption/).

## MongoDB lessons

MongoDB Queryable Encryption is a stronger cryptographic reference than a typical ORM library. Its
current production capability supports equality and range; prefix/suffix/substring remain preview in
MongoDB 8.2. Automatic drivers reject unsupported commands, operators, stages, types, and expression
forms. Encrypted-field comparisons, uniqueness, arrays, cross-collection operations, and migration
have explicit limitations.

Cryptalis should copy the fail-loud catalogue and versioned compatibility mindset. It should not
promise that SQLAlchemy offers the same control as a database-specific driver/server protocol. Range
and string search require external expert review; MongoDB’s investment is evidence that these are
research projects, not backlog checkboxes. Sources:
[fundamentals](https://www.mongodb.com/docs/manual/core/queryable-encryption/fundamentals/) and
[supported operations](https://www.mongodb.com/docs/v8.0/core/queryable-encryption/reference/supported-operations/).

## CipherSweet and framework lessons

CipherSweet separates randomized field encryption from domain-separated blind indexes and warns
users to define the threat model before enabling searchable encryption. Its transformation and
compound-index model is useful prior art for equality planning. Cryptalis should copy the discipline,
not its PHP API or implementation. Source: [CipherSweet](https://github.com/paragonie/ciphersweet).

Rails Active Record Encryption demonstrates that Model A can preserve ordinary application code,
filter encrypted parameters from logs, migrate mixed plaintext/ciphertext periods, and support
previous schemes. Its deterministic equality mode produces repeatable ciphertext and trades
confidentiality for convenience. Cryptalis should prefer separate equality terms so payload
ciphertext remains randomized, while copying Rails’ explicit migration and logging ergonomics.
Source: [Rails Active Record Encryption](https://guides.rubyonrails.org/active_record_encryption.html).

Django’s fragmented encrypted-field ecosystem is market evidence that Python developers want
declarative protection, but it is not proof they will adopt the lifecycle and migration complexity
Cryptalis proposes. Django comparison and adapter research is active in parallel; supported
production integration still requires a proven framework-specific contract.

## KMS, Vault, and database crypto

AWS’s hierarchical keyring demonstrates the relevant scaling pattern: cache branch material and use
unique per-message data keys rather than call KMS for every field. Its documentation also makes the
cache security/availability trade-off explicit. Google Cloud recommends locally generated DEKs
wrapped by centrally managed KEKs. Vault Transit supports derivation and datakey operations, but a
network service remains an availability and latency boundary.

Cryptalis is not a replacement for these systems. It uses them for root custody and adds application
semantics they do not know. Provider adapters must preserve differences in deletion delay, restore,
export, audit, authentication, outage, and version behavior.

PostgreSQL `pgcrypto` is inappropriate as the primary design because operations run in the database
server and its documentation requires trusting the database administrator. That contradicts the
database-compromise threat model. Sources:
[AWS hierarchical keyring](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/use-hierarchical-keyring.html),
[Google envelope encryption](https://docs.cloud.google.com/kms/docs/envelope-encryption),
[Vault Transit](https://developer.hashicorp.com/vault/docs/secrets/transit), and
[`pgcrypto`](https://www.postgresql.org/docs/current/pgcrypto.html).

## What to copy conceptually

- CipherStash: explicit leakage capabilities, bulk local crypto, operational metrics, identity-aware
  key release, schema rejection of malformed protected payloads.
- MongoDB: formal supported-operation lists and immediate errors for unsupported query shapes.
- CipherSweet: independent index keys, versioned transforms, and conservative blind-index claims.
- Rails: normal model ergonomics, parameter filtering, previous-scheme migration windows.
- AWS/GCP: envelope hierarchy, branch/DEK separation, bounded cache reuse, provider-managed roots.
- Vault: self-hostable custody option and narrow cryptographic service APIs.

## What not to copy blindly

- CipherStash’s entire query surface without construction-by-construction study, tests and
  maintenance ownership.
- Deterministic payload encryption merely to get equality queries.
- Per-field remote KMS/Transit calls.
- A SQL proxy parser as an accidental second product architecture; an isolated comparison experiment
  is acceptable.
- Runtime schema mutation disguised as convenience.
- Silent pass-through for unsupported ORM/Core paths.
- Search indexes whose leakage and shredding treatment are undocumented.
- Gateway-signed “proof” presented as independent evidence.

## Claims not available

- “Better than CipherStash/MongoDB” without a capability-specific reproduced benchmark.
- “More secure,” “production-ready,” “zero leakage,” “automatic protection of all SQL,” or “complete
  crypto-shredding.”
- “Prevents SQL injection” or “prevents a data breach.”
- “Legally equivalent to erasure” or guaranteed regulatory compliance.
- “First,” “only,” or “novel cryptography.”
- Performance, storage, adoption, or compatibility claims without pinned evidence.

Acceptable destruction wording is defined in the
[architecture blueprint](architecture/README.md#14-rotation-revocation-and-shredding). NIST SP
800-88 recognizes cryptographic erase as a media-sanitization technique, but that does not prove
deletion from application memory, logs, exports, unmanaged backups, or shared search indexes.

## Product and adoption risks

1. Demand for a full lifecycle/compiler platform is unvalidated despite evidence for field
   encryption generally.
2. Existing packages may be “good enough.”
3. The API can become framework magic that teams distrust.
4. Migrations may be the most valuable feature and the largest source of data-loss risk.
5. Search leakage explanations may discourage the same users the feature attracts.
6. Self-hosted lifecycle coordination adds operational burden.
7. A managed competitor can iterate faster on cryptographic primitives and compliance evidence.
8. Version support across SQLAlchemy, drivers, Alembic, and PostgreSQL is expensive.
9. Controlled and transparent access modes can confuse users.
10. Academic breadth can produce a demo with no maintainable core.

Before product positioning, interview maintainers of real FastAPI/SQLAlchemy systems, study relevant
issue trackers, and validate willingness to adopt generated schema and protected-session context.
Sparse community discussion is not evidence of a market.

## Evidence rules

- Prefer official documentation, papers, standards, source repositories, and reproducible code.
- Record product/version/edition, URL, access date, and exact capability.
- Separate documented, source-inspected, reproduced, benchmarked, and independently reviewed claims.
- Treat vendor latency statements as hypotheses.
- Treat absence of search results as absence of evidence, never non-existence.
- Re-run this review before a paper, release, demo, résumé claim, or public comparison.
