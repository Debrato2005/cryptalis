# Prior art, attribution, and product thesis

Reviewed 2026-09-30.
The sources below supply documented or source-inspected evidence only.
They do not supply independently reproduced, benchmarked, or reviewed Cryptalis evidence.
The [ORM ledger](research/orm-platform-evidence.md),
[crypto/provider ledger](research/crypto-provider-evidence.md), and
[assurance-tool ledger](research/assurance-tool-evidence.md) own exact versions, editions, access dates, and source details.
This document owns comparisons and positioning. It does not own runtime contracts or implementation status.

## Defensible thesis

Field encryption, blind indexes, migration planning, and scanner aggregation already exist.
Cryptalis cannot claim novel primitives or universal superiority.
It cannot claim to be the first or only ORM-native encryption system, or the only system that integrates protection and assurance.
Its strongest proposed distinction connects an explicit SQLAlchemy Protection Manifest to schema and Alembic history, query and leakage policy, and authenticated subject lifecycle.
It also connects writer and route paths to exercised attack and exposure evidence, with unknowns preserved.
That remains a hypothesis until the graph, oracle, and usefulness gates beat mature tools plus manual inspection.

Product differentiation, research contribution, and learning value are separate.
A reproduced known construction can teach deeply without novel or commercially preferable behavior.
Related-work search is bounded discovery. It cannot prove that an equivalent system does not exist.
Before a paper or stronger public claim, refresh the search.
Get independent review of related work and cryptographic use.

## Current comparisons

The access date for these rows is 2026-09-30, except for the CipherStash CLI recheck on 2026-10-01.
The ledgers hold product releases, editions, and exact sources.
A rolling web page does not establish an installed binary version.
'Not documented here' does not mean 'cannot do'.
These are dated comparisons of documented capabilities, not current reproduced capability claims.

The tables use object-relational mapping (ORM), application programming interface (API), and software development kit (SDK) terminology.
A command-line interface (CLI) exposes commands. A key management service (KMS) manages custody.

| Reference | Stronger documented area | Relevant limitation / lesson / Cryptalis response | Primary source |
|---|---|---|---|
| CipherStash | Advanced PostgreSQL search, proxy/SDK, and identity-aware service. CLI v1.0.0 documented reviewable plans and encryption backfill, status, and drop operations | SDK and provider derivation and caching differ from the local branch-key model. Query planning and migration alone do not differentiate Cryptalis. Study leakage and operational semantics. Compare only equivalent deployments | [Cryptography](https://cipherstash.com/docs/security/cryptography), [CLI v1.0.0](https://cipherstash.com/docs/reference/cli) |
| MongoDB Queryable Encryption | Driver/server-coordinated encrypted query catalogue | Exact version, operator, and threat restrictions differ from ORM blind indexes. Redirects do not establish general availability (GA) for string preview. Copy explicit rejection and catalogue discipline, not security guarantees | [Supported operations](https://www.mongodb.com/docs/manual/core/queryable-encryption/reference/supported-operations/), [limitations](https://www.mongodb.com/docs/manual/core/queryable-encryption/reference/limitations/) |
| CipherSweet | Mature separate field and index constructions, with domain discipline | The PHP, API, and normalization model differs. It implies no SQLAlchemy recovery evidence. Use it as a construction oracle. Benchmark keyed equality alternatives | [Official repository](https://github.com/paragonie/ciphersweet) |
| Rails Active Record Encryption | Transparent attributes, deterministic query option, migration and previous schemes, and logging ergonomics | Application plaintext remains accessible. Deterministic payload leaks repetition. Preserve ordinary ergonomics with randomized payload and separate declared terms | [Rails guide](https://guides.rubyonrails.org/active_record_encryption.html) |
| pydantic-encryption | Python encrypted fields, blind indexes, SQLAlchemy/KMS, deferred and batch access, and a greenlet path | The actual await bridge has contextual and synchronous-fallback hazards. Do not assume equivalent lifecycle bound to rows. Compare the real implementation and artifact/source provenance | [PyPI](https://pypi.org/project/pydantic-encryption/), [source ledger](research/orm-platform-evidence.md) |
| SQLAlchemy-Utils | Maintained API for custom encrypted SQLAlchemy types | The type abstraction does not itself attest row authorization. EncryptedType is deprecated in favor of StringEncryptedType. Compare state and type fidelity with the exact engine configuration | [0.42.0 docs](https://sqlalchemy-utils.readthedocs.io/en/latest/data_types.html) |
| Acra | Protection plus SQL policy, honeytokens, security events, audit, and key controls | Proxy semantics and scope differ. Encryption plus assurance is not unique. Study the controls. Retain correlation specific to fields, paths, and lifecycle as a testable hypothesis | [Security controls](https://docs.cossacklabs.com/acra/security-controls/) |
| AWS/GCP KMS, Vault Transit | Custody, identity and access management (IAM), auditing, and root lifecycle | Rotation, deletion, import, export, and restore differ. Adapters preserve actual observations. Wrapped backup plus a parent key defeats offline subject erasure | [Crypto ledger](research/crypto-provider-evidence.md) |
| ZAP/Burp/CodeQL/Semgrep/Nuclei/sqlmap | Mature generic dynamic/static analysis and comparison engines | Alert absence does not prove field protection. Editions, licensing, and safety differ. Integrate broad detection. Benchmark internal learning engines | [Tool ledger](research/assurance-tool-evidence.md) |
| Trivy/Grype/Gitleaks/Nmap/TShark/Zeek | Supply-chain, secret, service, packet, and flow evidence | Imported observations retain their own semantics. Transport layer security (TLS) payload remains opaque without authorized lab secrets. Do not rebuild generic feeds or decoders | [Tool ledger](research/assurance-tool-evidence.md) |
| Thales/Fortanix/Imperva | Broad documented discovery, classification, key visibility, and data-security visibility | Estate posture targets a different problem from local ORM causal evidence. Import and export relevant facts instead of claiming broader coverage | [Thales](https://cpl.thalesgroup.com/encryption/data-security-platform), [Fortanix](https://www.fortanix.com/platform), [Imperva](https://www.imperva.com/products/data-security/unified-visibility/) |

The CLI recheck resolved the old URL through an official redirect.
That page explicitly states that `db migrate` is not yet implemented.
A documented command reference does not supply local execution evidence.

CipherStash and MongoDB remain stronger references for advanced search in this dated comparison.
Do not copy algorithms from marketing summaries.
The crypto ledger holds exact primary constructions and leakage assumptions.
Provider caches and statements about immediate revocation describe vendor-documented scope. They are not our benchmark.
No fair competitor latency result exists in Cryptalis.

Publication requires matching attacker, operator, dataset, platform, provider, and availability semantics, or an explicitly qualitative comparison.

### 2026-10-05 workflow and composition lessons

Access date: 2026-10-05. These primary pages are documented-only, not installed/reproduced comparisons.
Rolling product docs do not select a Cryptalis dependency version.
The [canonical blueprint](architecture/README.md#load-bearing-decisions) owns the resulting design decisions.
No reference product proves Cryptalis behavior.

| Reference / source scope | Adopt, narrow, or reject | Evidence and limit |
|---|---|---|
| SQLAlchemy 2.0.54 / Alembic 1.20.0 documentation | Adopt public Session/flush boundaries and reviewed candidate DDL. Narrow to one synchronous cell. Reject universal raw/Core interception and private-hook dependence | [Session events](https://docs.sqlalchemy.org/en/20/orm/session_events.html), [autogenerate](https://alembic.sqlalchemy.org/en/latest/autogenerate.html). Public hooks still need Q3 fixtures |
| Tink / AWS Encryption SDK, rolling guides | Study established composition, visible authenticated context, exact dispatch and commitment policy. Reject a home-designed primitive or format approval from a parser | [Tink AEAD](https://developers.google.com/tink/aead), [AWS SDK concepts](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html). Sole suite Q2 remains open |
| AWS KMS / GCP / Vault, current service/API docs | Adopt native-state reporting and custody separation. Narrow first support to one provider/configuration. Reject rotation/delete/rewrap equivalence and alias-as-identity | [Crypto evidence update](research/crypto-provider-evidence.md#2026-10-05-composition-and-lifecycle-source-update). First provider Q4 remains open |
| Rails, rolling guide | Adopt simple field ergonomics and diagnostic attention. Keep randomized payloads and separately gated search. Reject deterministic payload as a universal query solution | [Active Record Encryption](https://guides.rubyonrails.org/active_record_encryption.html). Different language and migration/authority model |
| CipherStash, migration/deployment guides updated 2026-07-30 | Adopt explicit writer inventory, resumability, credential identity, coverage and destructive rollback limits. Narrow initial Cryptalis to offline maintenance and full terminal verification. Defer online dual writers | [Data migration](https://cipherstash.com/docs/guides/migration), [deployment](https://cipherstash.com/docs/guides/deployment). The handoff blog path failed retrieval. These official guides resolved. No vendor migration ran |
| MongoDB Queryable Encryption, rolling manual | Adopt exact operator/type/version refusal and explicit attacker limitations. Reject transferring a queryable-encryption security claim to deterministic blind indexes | [Limitations](https://www.mongodb.com/docs/manual/core/queryable-encryption/reference/limitations/). Snapshot/transcript scope requires exact construction evidence |
| Prisma, rolling Data Guide | Adopt dependency-aware additive preparation and explicit cleanup. Narrow first strategy to quiesced writers instead of automatic zero downtime | [Expand/contract](https://www.prisma.io/dataguide/types/relational/expand-and-contract-pattern). This is workflow guidance, not a Cryptalis verifier |
| Terraform, current CLI docs | Adopt a reviewable saved plan and explicit target/precondition checks. Reject sensitive saved-plan contents and treating editable artifacts as authority | [Plan](https://developer.hashicorp.com/terraform/cli/commands/plan). Cryptalis deliberately excludes data-derived material from plans |
| Kubernetes, rolling concepts | Adopt desired/observed reconciliation and pending cleanup obligations. Hide the engine behind a small library workflow. Reject a broad public controller/finalizer vocabulary | [Controllers](https://kubernetes.io/docs/concepts/architecture/controller/), [finalizers](https://kubernetes.io/docs/concepts/overview/working-with-objects/finalizers/). Neither selects Q1's authority backend |

Practitioner posts, issues, forums, and incidents remain discovery-only unless separately attributed and corroborated by primary evidence.
No new practitioner assertion in this pass closes a research question.
The first product value is a narrow no-search offline protection workflow. Graph/attack correlation remains a later usefulness hypothesis.

## New and broader discovery

Bounded searches examined Python/SQLAlchemy field protection, ORM search, database proxies, migration, key deletion, security correlation, and encrypted-search research.
Discoveries weaken generic product claims.
They do not show that Cryptalis's complete proposed integration already exists.
The current evidence comes from repository and page inspection. The review did not execute the listed projects.

| Reference/version or snapshot | Exact finding / limitation | Lesson and response | Evidence source/date/basis |
|---|---|---|---|
| Fieldseal, main working draft | Portable cell envelope, suite/key-provider/blind-index specification, and shared vectors. Explicitly pre-alpha and unreviewed. Its README reports two Python/TypeScript cores. Adapters and backfill remain placeholders | Envelope and ORM portability are not novel. Consider independently reviewed vectors as differential inputs. Never inherit provisional crypto approval. Retain stable mandatory context binding and a real greenlet comparison | [Repository](https://github.com/fieldseal-dev/fieldseal-spec), [research memo](https://github.com/fieldseal-dev/fieldseal-spec/blob/main/docs/00-research-memo.md), accessed 2026-09-30, documented-only |
| ankane blind_index, main README | Rails keyed index separation, explicit backfill and key rotation, and unsupported text predicates | Search migration and normalization ergonomics have prior art. Compare cost and low-entropy leakage. Do not copy identities bound to names | [Repository](https://github.com/ankane/blind_index), 2026-09-30, documented-only |
| Arca, repository main | Python structured-encryption research library and referenced research | Useful candidate for an attributed educational construction or oracle. It does not establish reviewed production integration | [Repository](https://github.com/cloudsecuritygroup/arca), 2026-09-30, documented-only |
| django-hashed-encrypted-fields, main | Django companion searchable hash fields and configurable encryption provider | Declaration/index pairing has prior art. Exact keyed-hash and security configuration require source and vector review before oracle use | [Repository](https://github.com/kolanos/django-hashed-encrypted-fields), 2026-09-30, documented-only |
| Miguel Grinberg sqlalchemy-encryption tutorial repo, main | Code that accompanies an encrypted-column tutorial. It does not claim to be an integrated lifecycle product | Compare narrow type and state ergonomics. A tutorial does not establish maintenance or support | [Repository](https://github.com/miguelgrinberg/sqlalchemy-encryption), 2026-09-30, documented-only |
| OpenBao Transit, rolling stable docs | Alternative service-based transit API | Additional candidate for a custody seam. Do not assume semantic equivalence with Vault. Release and deletion tests must reflect the provider | [Stable Transit docs](https://openbao.org/docs/secrets/transit/), 2026-09-30, documented-only |
| OpenFGA Python SDK, repository main | External adapter for fine-grained authorization | It can supply host policy decisions. It cannot establish subject ownership automatically or prevent stale grants automatically | [Official SDK](https://github.com/openfga/python-sdk), 2026-09-30, documented-only |

No source absence supports a 'first' claim.
Fieldseal's source also contains its own technical assumptions.
Its provisional specification is a useful challenge. It does not have authority over Cryptalis.
The current architecture still requires mandatory stable row, tenant, and subject binding and evaluates actual asynchronous alternatives.

Fieldseal's key-commitment concerns become a cryptographic review question.
They do not justify inventing a primitive.

## Adoption and maintenance evidence

Demand for the combined compiler, lifecycle, and assurance system is unvalidated.
Package existence, stars, search volume, and encryption tutorials are demand proxies, not a market estimate.
Five maintainer interviews are a learning checkpoint. They do not supply statistical population evidence.

Ask for concrete incidents and rejected tradeoffs in each of these areas:

- Sensitive fields and excluded adversaries
- Current encryption and migration failures
- Required equality, unique, range, text, join, and administrative queries
- Raw, Core, ETL, and support writers
- Tenant and subject authority, with job contexts
- KMS, outage, rotation, and backups
- Willingness to accept companion schema, explicit query failures, trusted Session identity, and a maintenance window
- Deletion scope and shared index residue
- Whether graph and exposure evidence changes a review decision
- Reasons for immediate rejection

Record role, scale, current solution, incident basis, prototype willingness, and maintenance burden.
The [G-API](architecture/manifest-context-api.md#version-compatibility-and-research-gates) gate owns thresholds for API task studies.

Alternatives can remain preferable. A small encrypted type may suffice.
Managed search can reduce the local cryptographic and operational burden.
Migration and schema changes carry data-loss risk. Infrastructure for subject-level control is expensive.
First-party evidence might not satisfy independent assessors.

Maintaining compatibility with ORM, driver, provider, and scanner versions requires substantial work.

Learning value can justify construction. Product claims require demonstrated comparative utility.

## Attribution and claim discipline

Record the exact product, version, edition, URL, access date, capability, and evidence basis.
Primary papers, standards, official APIs, and source outrank marketing and secondary discussion.
Source inspection does not equal reproduction. Vendor vectors and benchmarks are vendor evidence.
Preserve original tool semantics.

Without scoped evidence, do not claim zero leakage, complete shredding/SAST/DAST, production readiness, or breach prevention.
That restriction also applies to universal SQL injection protection, legal erasure/compliance, novel cryptography, and superiority.
That evidence must support independent review.
NIST media-sanitization guidance does not certify legal application deletion.
The [lifecycle owner](architecture/crypto-search-lifecycle.md) specifies what receipts actually mean.

The [philosophy](learning-first-research-philosophy.md) owns research scope and evaluation.
The [blueprint owners](architecture/README.md) own technical behavior.
The [checklist](backend-build-checklist.md) owns maturity.
Refresh external claims before a release, paper, demo, or comparison.
No current published Cryptalis performance, support, or cryptographic-review evidence exists.
