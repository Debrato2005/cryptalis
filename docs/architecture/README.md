# Cryptalis architecture blueprint

Status: accepted architecture specification with empirical gates.
Reviewed: 2026-09-30. Integration corrections: 2026-10-01. Field-format boundary review: 2026-10-05. Authoritative handoff reconciliation: 2026-10-05. The
[checklist](../backend-build-checklist.md) is the authority for current capability state.

## Product and first target

Cryptalis is a planned data-protection and security-assurance system for Python and SQLAlchemy.
Declarations express desired policy. An immutable Protection Manifest records it. Authenticated external active state controls runtime admission. Application engineers would retrofit
selected sensitive fields. Operators would manage keys and migrations. Reviewers would interpret
protection evidence within its stated scope.

The first application profile is a tenant-aware Python service. It uses one registered
synchronous SQLAlchemy Session/Engine cell, PostgreSQL, immutable record UUIDs, and explicit
authenticated grants. FastAPI is an optional host adapter. Cryptalis does not supply an identity
authority through FastAPI. The [shared glossary](manifest-context-api.md#terms-and-maturity)
defines terms and abbreviations.

The design trusts the application process, which handles plaintext. Payload protection must
happen before database persistence. Supported paths must keep unwrapped keys out of PostgreSQL
and its dumps and backups. PostgreSQL credentials and operator access must not expose those
keys.

Malware or authorized code in the trusted process can still access plaintext and keys.
Most runtime capabilities remain proposed. A complete architecture is separate from implementation evidence.

## Documentation ownership

Each detail owner below is authoritative for its contract family. This blueprint defines shared
boundaries, dependency edges, and invariant IDs. Other documents link to the contracts instead
of repeating them.

If an invariant conflicts with a detailed contract, stop the affected claim. Reconcile the
owners. Record the change. No document silently overrides another.

| Document | Audience / owns | Does not own |
|---|---|---|
| [README](../../README.md) | New users: promise, boundary, entry points | Version support/capability state/details |
| This blueprint | Integrator: product/threat model, cross-system invariants, owner map, decision rationale | Duplicate subsystem algorithms |
| [Manifest/context/API](manifest-context-api.md) | Implementer: manifest schema, provenance, maturity/glossary, modules, API/CLI/errors/config/versions | Crypto/ORM/assurance algorithm copies |
| [Crypto/search/lifecycle](crypto-search-lifecycle.md) | Security/runtime engineer: envelope, domains/leakage, providers, cache/fence/restore/receipts | Host business authorization |
| [ORM/schema/migration](orm-schema-migration.md) | ORM/database engineer: query/type/path/async/compiler/Alembic/recovery/compatibility | Provider destruction semantics |
| [Assurance/evidence](assurance-evidence.md) | AppSec/analyzer engineer: Doctor/graph/writers/Verify/Pentest/network/results/bundles/lab/benchmarks | Core field policy mutation |
| [Research philosophy](../learning-first-research-philosophy.md) | Builder: learning/evaluation/build vs integrate and broader research gates | Live technical or capability-state copies |
| [Build guide](../cryptalis-build-guide.md) | Builder: dependency-aware first files/concepts/outcomes | Competing interface definitions |
| [Checklist](../backend-build-checklist.md) | Maintainer: evidence state/dependency/exit links | Architecture rationale |
| [Prior art](../prior-art.md) | Researcher/reviewer: attribution, competitor/product thesis | Cryptalis runtime specification |
| [Assurance research](../security-assurance-suite-research.md) | Researcher: analyzer/scenario learning depth and comparisons | Second normative assurance owner |
| [Engineering playbook](../../ENGINEERING_PLAYBOOK.md) | Contributor: explicit failure and behavior-first testing policies, manual implementation, review, and release process | New architectural guarantees |
| [Claims audit](../documentation-claims-audit.md) | Reviewer: dated findings/closure/validation provenance | Architecture/status authority |
| [Historical pause handoff](../SESSION_HANDOFF.md) | Maintainer: interrupted-session chronology, superseded by audit | Live goal state or remaining design decisions |
| [Hardening dossier](../adversarial-architecture-hardening.md) | Researcher: historical hostile analysis and alternatives | Current versions or contracts |
| [ORM source ledger](../research/orm-platform-evidence.md), [crypto ledger](../research/crypto-provider-evidence.md), [tool ledger](../research/assurance-tool-evidence.md) | Reviewer: current primary evidence/version/edition/access date | Reproduced Cryptalis measurements |

## Load-bearing decisions

DECIDED specifies policy. DEFAULT requires named validation. OPEN identifies a choice that
requires an experiment. None implies working software. This decision record replaces duplicate
architecture decision record (ADR) specifications.

| ID / status | Decision, credible alternatives, consequence | Owner / falsifier |
|---|---|---|
| D01 DECIDED | Protect at the application/ORM boundary. Database encryption would trust the DB. A proxy would lose ORM semantics. Raw writers remain coverage gaps | Threat model and ORM. P2 coverage |
| D02 DECIDED, refined 2026-10-05 | Separate DeclaredPolicy, generated PolicyLock, external ActiveState, and TransitionRecord. Immutable history records policy. A declaration never activates it. The optional graph contains observations | [Shared authority](manifest-context-api.md#desired-policy-and-active-authority). G-ACTIVE/G-MANIFEST |
| D03 DEFAULT, refined 2026-10-05 | Prepare keys internally at explicit Session boundaries, then encrypt locally. Normal callers supply trusted identity once. Async, bridge, and deferred comparisons remain later gates | ORM P3 and shared API. Q3 remains open |
| D04 DECIDED | Use randomized payloads with separate declared search representations. Reject deterministic payloads as the default because they couple encryption to repetition leakage | Crypto. P5 and search gates |
| D05 DEFAULT | Use provider KEK -> tenant branch -> wrapped subject generation. Stronger erasure requires per-subject provider destruction or a reviewed puncturable scheme | Crypto. P7 and provider gates |
| D06 DECIDED, refined 2026-10-05 | One internal transition engine, offline maintenance strategy first. Reviewed Alembic DDL, full verification, CAS activation, separate irreversible approval. Online protocols remain future strategies | [Transition owner](orm-schema-migration.md#migration-state-machine-and-concurrency). G-OFFLINE/P6 |
| D07 DECIDED | Reject unknown query semantics, context, or formats explicitly. Never fall back to plaintext or an implicit client scan | ORM and manifest. P0/P1/P2 |
| D08 DECIDED | Treat controlled evidence as first-party. An external signed witness establishes integrity and provenance, not measurement truth or independent proof | Assurance. P8 controls and value |
| D09 DECIDED | Isolate attributed known constructions in research packages. Primitive library selection requires vectors and review | Crypto and modules. P10/G-BOUNDARY |
| D10 DECIDED | Require authenticated grants from principals to tenants and subjects, plus immutable row identity. Raw IDs and ambient context cannot establish authority | Manifest G-CONTEXT/P0 |
| D11 DECIDED | Use explicit state, narrow contracts, deterministic behavior, and observable failures. Silent recovery or undefined best effort can hide invalid state. Apply the playbook policy across subsystem boundaries | [Failure policy](../../ENGINEERING_PLAYBOOK.md#fail-loudly-and-explicitly) and [error contract](manifest-context-api.md#errors-and-observability). Failure-path evidence |
| D12 DECIDED | Generate stable logical IDs, never-reused protected representation IDs, and an environment protection domain. Renames preserve identity. Re-adoption creates a new representation | Manifest identity, crypto bindings. Q2/Q7 remain open |
| D13 DECIDED | Quarantine every restore. Current external policy and denial dominate restored data and checkpoints. Deprotect and decommission use the same engine and report retained copies | Crypto restore, ORM exit. Q1/Q5 remain open |
| D14 DECIDED | One active writer version, no search, no CDC or prepared transactions in the initial target. Fleet, online, search, and broad assurance require separate evidence | ORM profile and compatibility. No runtime cell supported |

For a decision change, record the predecessor ID and the primary-source or experimental basis.
Name the affected owners, consequences for manifests, formats and compatibility, and blocked
claims. Keep this information in the audit or change record.

Historical ADRs removed in cc54ee8 remain in Git history. They do not restore authority to the
former gateway-first design.

## Trust and threat model

Protected assets include logical values, subject and tenant keys, authenticated identities,
searchable metadata, policy and schema transitions, and evidence. The model trusts host
authentication adapters, the registered cryptographic library, current workload and provider
credentials, and the managed control plane.

Database contents, backups, and query inputs are untrusted. Control-plane compromise defeats the
core model. Offline keys exported by trusted workloads and malicious code inside the trusted
boundary also defeat it.

| Threat / attacker capability | Intended control and assumption | Residual exposure / verification |
|---|---|---|
| Stolen dump/backup | Randomized AEAD, root keys separate from DB | Length/IDs/index terms; extraction/canary fixture |
| Stolen DB credentials/direct SQL/overprivileged DBA | Same boundary; DB does not know unwrapped keys | Availability, deletion/replay/malformed rows, metadata; tamper/relocation tests |
| Historical valid ciphertext rollback | AEAD proves authenticity, not freshness | Freshness outside bound unless external row-version authority; rollback scenario reports this limit |
| Accidental supported-path persistence | Authenticated context, row-aware adapter and atomic companion writes | Plaintext in trusted app remains; inspect SQL/rows/mutants |
| Unregistered/Core/bulk/raw/COPY/ETL writer | Reject registered known paths, roles/framing defense, writer ledger | Unobservable separate writers; no universal prevention; P2 T/R/D/U matrix |
| Migration mistake/stale plan | Target-bound plan, offline quiescence, row revisions, complete verification, external CAS | Downtime and copy residue. Wrong-target, crash, and two-executor fixtures |
| Cross-tenant/subject substitution | Host-authenticated grants + stable tuple in AAD and tenant filters | Host policy bugs remain risk; P0 colliding IDs/task/pool/jobs |
| Untrusted manifest/descriptor substitution | Bounded structural parsing, ancestry-chain checks, and separate digest domains. Catalogue admission and authenticated authority required | Current helpers establish byte consistency, not policy authenticity, current-head authority, or catalogue approval. G-MANIFEST/P0/P10 remain pending |
| Malformed or forged envelope from a database attacker | Bounded framing before key lookup. Authorized registry selection and AEAD required afterward | The private F1/W1 parsers reject malformed structure but accept well-shaped forged bytes. G-CRYPTO/G-CROSSKEY/G-AAD remain pending |
| Cache stale worker/partition | Epoch/lease authorization plus serialized DB fence and acknowledged output drain | Expiry denies new authorization; physical completion requires drain evidence and can remain pending; bytes may remain in suspended RAM; P7 chaos |
| Restore/resurrection/hostile schema | Quarantine, trusted executable-object inventory, current external ActiveState and denial | Surviving keys permit offline recovery. Hostile-schema and PITR admission fixtures |
| Search metadata/frequency/auxiliary/chosen query observer | Capability-specific accepted leakage, explicit domains | Equality/order/token/access patterns; attacks/cost gate per capability |
| Key/provider outage | Cold deny; bounded authorized cache only | Availability and declared offline lease; outage/expiry tests |
| Artifact/log/report leak | Synthetic fixtures, redacted observations, safe errors | Transparent Python values can be logged by host code; collector controls/Doctor |
| Fully compromised application/host or malicious authorized code | Beyond core protection | Can read plaintext/keys, bypass grants; independent controlled release is separate profile |
| Business auth flaws, XSS, SQL injection itself | Host AppSec responsibility; Pentest can exercise impact | Vulnerability remains even if DB ciphertext holds; results separated |
| Deliberate post-decrypt export/unmanaged copies | Beyond technical deletion scope | Export/log/backups excluded explicitly; no universal erasure/compliance claim |

A supported-path claim names its exact prevention and compatibility scope. Detected-only and
unobservable paths remain coverage gaps, even when a clean run does not exercise them. Database
framing constraints do not authenticate writer authority or ciphertext. Passive Transport Layer
Security (TLS) capture does not prove absence of plaintext inside applications. The assurance
contract defines detailed attack models and collectors.

## Data flow and plane boundaries

```mermaid
flowchart TD
  Decl[DeclaredPolicy] --> Lock[Generated PolicyLock + immutable history]
  Lock --> Plan[Target-bound transition plan]
  Authority[External authenticated ActiveState + denial] --> Plan
  Plan --> Engine[One internal offline transition engine]
  Engine --> DB[PostgreSQL data + schema]
  Engine --> CAS[Verified CAS switch]
  CAS --> Authority
  Authority --> Runtime[Admitted Session + local crypto]
  Runtime --> DB
  Provider[Exact provider identity + bounded material] --> Runtime
  Engine --> Finalizer[Separate irreversible approval + residual obligations]
  Lock --> Check[Read-only check / optional analysis]
  DB --> Facts[Scoped observations]
  Authority --> Facts
  Provider --> Facts
  Check --> Evidence[Bounded evidence / optional graph and lab]
  Facts --> Evidence
```

The [shared owner](manifest-context-api.md#desired-policy-and-active-authority) defines the four artifacts and their schemas.
The [transition owner](orm-schema-migration.md#migration-state-machine-and-concurrency) defines execution and finalization.
Neither compilation, schema stamping, a saved plan, nor evidence activates policy.
Runtime admission uses current external authority and an exact compatibility cell.

The proposed write path validates trusted Session identity and active compatibility before encoding and local encryption.
It prepares required material internally, then persists one coherent physical representation.
Search is absent from the initial path. Later admitted terms share its transaction boundary.

The read path bounds parsing, checks current authority and resource identity, authenticates the complete binding, then decodes and releases values.
No unauthenticated bytes become Python values. Internal key preparation has a visible Session I/O boundary.
Later search verifies candidates independently from completeness. Missing hits need separate evidence.

Restored database state starts untrusted. Current authority, denial, retirement, and operation generations survive outside its restore domain.
The [crypto owner](crypto-search-lifecycle.md#recovery-manifest-and-restore-admission) defines recovery inputs and admission obligations.
Deprotection publishes plaintext only with explicit approval. Complete exit retains truthful backup, key, and reader obligations.

Analysis reads facts and emits proposals. Evidence cannot change policy, approve finalization, or admit a restored workload.
[Module contracts](manifest-context-api.md#packages-and-dependency-direction) define import direction.

## Integration dependency DAG

```mermaid
flowchart TD
  Contract[Desired / active / transition contracts C33] --> Identity[Domain + representation + suite freeze C34]
  Identity --> Path[Minimal explicit runtime / pinned Session C35]
  Path --> DB[PostgreSQL preflight + reviewed DDL C36]
  DB --> Offline[Offline protect / reconfigure / deprotect C37]
  Offline --> Recovery[One provider + keys + restore C38]
  Recovery --> Exit[Upgrade + decommission C39]
  Exit --> Release[Safe telemetry + release provenance C40]
  Release --> Advanced[Separate search / async / fleet / online / assurance gates]
```

The [checklist](../backend-build-checklist.md#ordered-foundation-slices) owns the dependency and evidence rows.
The [build guide](../cryptalis-build-guide.md#dependency-spine) expands learning order.
Q1–Q5 below block every dependent runtime behavior until research closes and review accepts the answers.
Current structural parsers do not freeze a production suite or descriptor.
Independent research can proceed. Failed dependencies cannot support integrated claims.
Graph, DAST, distributed writer leases, and online journals are not first-transition prerequisites.

## 23. Canonical security invariants

The stable IDs below identify normative design requirements. These properties are not yet
proven. Evidence must bind source, manifest, schema, deployment, and tool versions to an exact
interval and scope. Each owner describes the mechanism. Future scenarios reference the invariant
ID instead of maintaining a duplicate catalogue.

| ID / invariant | Mechanism / owner | Test/adversary/evidence | Failure state |
|---|---|---|---|
| I01 Supported writes never intentionally persist plaintext | Row-aware transform + atomic physical state / ORM | Positive round trip; plaintext-write mutant; SQL+row collector | Abort transaction; capability claim blocked |
| I02 Unknown semantics never silently broaden/fallback | Typed query IR/path catalogue / ORM | Every operator/bypass family; emitted SQL confirms no execution for reject paths | UnsupportedEncryptedQuery or visible coverage gap |
| I03 Payload authenticates domain/tenant/subject/record/model/table/field/representation/format/purpose/generation | Strict AAD/AEAD / crypto | Bit tamper, relocation, identity moves, unknown format vectors | Authentication/format error, no value |
| I04 Representations exist only for declared capability | Manifest compiler/domain policy / crypto+ORM | Undeclared query/index mutant; schema/term inventory | Compile/query rejection or drift failure |
| I05 Key purposes/domains are separated | Versioned derivation labels / crypto | Cross-purpose/tenant/domain vectors and collisions | Key/domain mismatch; no release |
| I06 Remote I/O is visible in selected profile | Internal preparation at visible Session boundaries; bridged/deferred gates / ORM | Event-loop lag/cancellation/N+1/provider traces | Cold/error typed, no hidden fallback |
| I07 Identity has authenticated provenance | Immutable grant + tenant/ownership scope / manifest | Colliding IDs, jobs/tasks/pools/identity-map substitutions | Pre-key/pre-SQL Context error |
| I08 No new operation authority after declared fence; physical completion requires drain | Epoch/lease authorization, serialized commit fence and acknowledged sink drain / lifecycle | Partition/suspend/resume/cache/grant expiry; timestamped operation evidence | Denied/pending, never false completion |
| I09 Supported restores cannot revive old authority | Quarantine + current external active/denial/retirement state / lifecycle | DB/control snapshot rollback and stale queue; fresh/stale decrypt | RestoreDenied/INCONCLUSIVE; offline recovery caveat |
| I10 Migration never completes with inconsistent unverified state | CAS/checkpoints/complete coverage/fenced cutover / ORM | Crash every phase, mixed writers, invalid index, unique conflicts | Paused/repair; contraction denied |
| I11 Missing/failed collectors never create absence PASS | Health/watermarks/positive-negative-mutant controls / assurance | Drop/redact/timeout collector and seed exposure | INCONCLUSIVE for affected claim |
| I12 Evidence does not become sensitive-value repository | Synthetic oracle + redacted digest-based exports / assurance | Seed value/key/token/credential leak in bundle mutant; retention/access checks | Bundle quarantine; release blocked |
| I13 Desired intent never activates runtime authority | Generated lock/history, authenticated external head, verified transition and CAS / manifest+ORM | Desired-before-schema, stale history, wrong binary, unavailable authority | Deny admission or pause transition |
| I14 One operation controls overlapping transition scope | Target-bound immutable plan, reinspection, overlap lock, durable idempotency / manifest+ORM | Wrong target, plan tamper/expiry, two executors, restored checkpoint | Plan invalid or repair required |
| I15 Initial activation requires stable offline full verification | Writer quiescence, row revisions, terminal coverage, reconciled DDL / ORM | Hidden writer, prepared transaction, CDC, interrupted chunks, invalid index | Switch and finalization denied |
| I16 Each irreversible boundary requires exact separate approval | Action/target/plan/expiry binding and residual obligations / manifest+ORM+crypto | Plaintext publication, replayed approval, format/key retirement, abandoned cleanup | Boundary blocked. No automatic deprotect/drop/destruction |
| I17 Identity never silently reuses an incarnation or crosses a domain | Generated representation IDs and domain-bound crypto / manifest+crypto | Remove/re-add, staging clone, alias retarget, cross-domain vectors | No key load or logical release |

## P0 documentation review register

The ordered 2026-10-05 handoff patches are reconciled into the owners below.
Every row remains **RECONCILED / REVIEW PENDING**. This register supplies no implementation or independent review evidence.
Research questions remain separate from documentation review.

| Blocker | Canonical review scope | Disposition |
|---|---|---|
| Desired versus active authority | [Authority and activation](manifest-context-api.md#desired-policy-and-active-authority) | Review pending. Q1 remains open |
| Cryptographic identity | [Descriptor](manifest-context-api.md#immutable-field-format-descriptor) and [bindings](crypto-search-lifecycle.md#required-domain-and-representation-bindings) | Review pending. Q2 remains open |
| Transition contract | [Plan schemas](manifest-context-api.md#plan-record-approval-and-receipt-schema) and [offline execution](orm-schema-migration.md#migration-state-machine-and-concurrency) | Review pending. Q1/Q5 remain open |
| Public/runtime boundary | [Normal API](manifest-context-api.md#public-python-surface) and [coverage](orm-schema-migration.md#interception-and-coverage-registry) | Review pending. Q3 remains open |
| Initial PostgreSQL profile | [Profile and preflight](orm-schema-migration.md#initial-postgresql-profile-and-live-preflight) | Review pending. Q5 remains open |
| Restore and destructive truth | [Recovery/admission](crypto-search-lifecycle.md#recovery-manifest-and-restore-admission) and [key effects](crypto-search-lifecycle.md#key-operation-contract) | Review pending. Q1/Q4/Q5 remain open |
| Compatibility and exit | [Upgrade admission](orm-schema-migration.md#one-writer-upgrade-admission) and [exit/finalization](orm-schema-migration.md#deprotect-decommission-and-finalization) | Review pending. Applicable Q1–Q5 dependencies remain blocked |

Review closure records the exact document snapshot, reviewer, findings, resolution, and accepted disposition.
The [checklist](../backend-build-checklist.md#evidence-admission) owns evidence admission.
Closing a documentation row does not answer a research question or admit a runtime cell.
No exception, operator approval, or passing optional tool bypasses required Q1–Q5 research closure or P0 documentation review.

## Unresolved research questions

This register owns the ten unresolved questions from the 2026-10-05 authoritative handoff.
All remain **OPEN**. A settled invariant does not select its implementation.
No dependent runtime crypto, ORM, migration, KMS, restore, or decommission behavior proceeds while Q1–Q5 remain unresolved.
P0 documentation reconciliation also needs review before dependent runtime work. This pass does not supply that review.

| Question | Unresolved selection | Closure owner and evidence |
|---|---|---|
| Q1 | Concrete external authority for authenticated monotonic ActiveState/CAS and disaster recovery | [Shared authority gate](manifest-context-api.md#version-compatibility-and-research-gates): backend, trust roots, rollback/loss/CAS/idempotency/recovery trials. Local development is not production authority |
| Q2 | Sole established AEAD/key-management composition and whether exact-key dispatch needs an additional committing construction | [Crypto gates](crypto-search-lifecycle.md#research-gates): exact composition, revised binding bytes, multi-key vectors, independent review |
| Q3 | Public SQLAlchemy-only path versus explicit repository wrapper across state/loader/async/bypass cells | [ORM gates](orm-schema-migration.md#research-gates): pinned public-hook prototype and rejected-path SQL evidence. Initial sync narrowing does not answer the full question |
| Q4 | First live KMS/provider and regional/recovery configuration | [Provider gate](crypto-search-lifecycle.md#research-gates): exact service/SDK/region/material origin and native-state/fault/restore evidence |
| Q5 | Safe stable PostgreSQL target identity across managed restore, clone, and failover | [Target gate](orm-schema-migration.md#research-gates): replacement-at-same-endpoint, restore, clone, failover identity fixtures. Hostname/OID alone cannot close it |
| Q6 | Sufficient evidence that every writer is quiesced when external systems exist | ORM offline gate: privilege exclusion, session/pool/job inventory and scoped operator attestations. Unknown writers block completion |
| Q7 | Whether production DR shares protection domain/authority and exact staging-clone procedure | Crypto restore gate: explicit recovery-realm design, clone/DR vectors and credential separation. No automatic inheritance |
| Q8 | Rollback retention defaults during deprotection and upgrade | ORM compatibility and crypto recovery gates: explicit retained material, exposure, expiry and tested recovery. No invented default duration |
| Q9 | Product goal of strong per-subject deletion versus managed denial with recoverability | Crypto lifecycle gate: declared recovery graph and independent trials. Initial claim can remain managed denial only |
| Q10 | Safe aggregate equality-risk signals without value-frequency leakage | Assurance and crypto equality gates: bounded signals, redaction and inference trials. Search stays disabled |

Q1–Q5 require researched answers and reviewed closure before a supported production cell.
Q6–Q10 can initially remain open through explicit narrowing of support and claims.
Closure records need a primary-source basis, pinned artifacts, reproduction commands/results, limitations, reviewer identity, and accepted disposition.
Documentation checks never close these questions.

## Fatal risks and resolution gates

The historic P0-P10 IDs retain meaning but detailed current gates live at canonical owners:
[context/manifest/API](manifest-context-api.md#version-compatibility-and-research-gates),
[ORM/async/query/schema/migration](orm-schema-migration.md#research-gates),
[crypto/search/lifecycle](crypto-search-lifecycle.md#research-gates), and
[assurance/evidence](assurance-evidence.md#research-gates). The IDs retain these meanings:

| Risk | Meaning |
|---|---|
| P0 | Identity provenance |
| P1 | ORM state |
| P2 | Bypass coverage |
| P3 | Actual async alternatives |
| P4 | Authorized identity migration |
| P5 | Race-safe equality and uniqueness |
| P6 | Migration recovery |
| P7 | Lifecycle and restore |
| P8 | Oracle and Protection Graph value |
| P9 | Doctor usefulness |
| P10 | Suite freeze |

Each gate names alternatives, fixtures and evidence, pass/fail thresholds, blocked claims, and
safe independent work.

Stop the affected claim if any of these conditions occurs:

- Unauthorized context selection, ambiguous identity, or silently changed query semantics
- Claimed support that requires private framework APIs
- An unfenced old writer or stranded migration of additional authenticated data (AAD)
- Non-atomic uniqueness, unbounded cache use, or restored access that should remain denied
- A fabricated absence result, uncontained active traffic, or sensitive evidence bundle
- An advanced construction without a credible oracle and review

Redesign the affected profile or demote its maturity. Failures in Doctor noise, maintenance,
usability, or Protection Graph value narrow the affected product claim. They do not prohibit an
isolated learning experiment. Recoverable key paths block strong-erasure claims.

## Claim and compatibility discipline

No package or profile is supported today. [ORM contracts](orm-schema-migration.md) list
candidate runtime versions and public extension APIs. Linked ledgers contain dated source
observations. A reference version is a test input, not a guarantee.

Claims require separately reviewable definitions and evidence. This applies to coverage of all
SQLAlchemy operations, security scores, zero leakage, complete erasure, complete static or
dynamic application security testing (SAST/DAST), breach prevention, compliance, and first,
only, or novel claims.

Assumptions about dominant performance costs are hypotheses for the [benchmark
protocol](assurance-evidence.md). Competitor comparisons require equivalent workloads,
deployments, and threats. The proposed research contribution is correlation with explicit
unknowns. It is not a novelty assertion.
