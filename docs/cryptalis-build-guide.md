# Cryptalis: Complete System and Solo Build Guide

Status: Pre-implementation guide; documentation only

Last reviewed: 2026-08-22

Audience: the solo builder of Cryptalis and future contributors who need to understand why each
piece exists before writing it.

This guide answers two questions:

1. What is the complete Cryptalis system?
2. How can one person advance its complete set of workstreams without losing rigor?

Technical decisions remain owned by the [architecture blueprint](architecture/README.md).
Implementation status remains owned by the [backend checklist](backend-build-checklist.md). The
[learning-first philosophy](learning-first-research-philosophy.md) owns complete research scope.
This guide owns the readable, dependency-ordered construction narrative.

## 1. The one-paragraph explanation

Cryptalis is a Python/SQLAlchemy-native data-protection and security-assurance system. An application
declares which model fields are sensitive, how they may be queried, which tenant and data subject
own them, and how their keys should live or be destroyed. Cryptalis compiles that declaration into
local authenticated encryption, capability-specific search indexes, physical PostgreSQL schema,
reviewable Alembic migrations, query guards, key lifecycle operations, static-analysis rules,
adversarial tests, and reproducible evidence. Its core security promise is bounded: supported writes
store protected values as authenticated ciphertext before PostgreSQL sees them, while successful
attacks and actual plaintext exposure are measured as separate outcomes.

## 2. What Cryptalis is—and is not

Cryptalis is simultaneously:

- an application-layer field-encryption library;
- a SQLAlchemy mapping and query-semantics layer;
- a PostgreSQL schema and Alembic migration compiler;
- a tenant/subject key-lifecycle and cryptographic-erasure system;
- a searchable-encryption research platform;
- Doctor, a progressive Python/SQLAlchemy SAST and configuration-analysis engine;
- Pentest, a hybrid integrated/internal adversarial-testing framework;
- Verify, a deterministic security-invariant and exposure-testing engine;
- a protection/evidence graph that connects fields, storage, keys, code, attacks and observations;
- a networking/PCAP and DevSecOps learning platform; and
- a complete, learning-first security engineering program.

It is not a promise to stop SQL injection, authorization bugs, XSS, arbitrary code execution, a
fully compromised application host, or deliberate misuse of already-decrypted plaintext. It is not
a custom cloud KMS/HSM, an assurance certification, or proof that no plaintext copy exists anywhere.

## 3. The security boundary

```text
trusted application process
  Python plaintext
       |
       v
  Cryptalis data plane
  encrypt / decrypt / query-token generation
       |
       v
untrusted-or-less-trusted persistence boundary
  PostgreSQL ciphertext + metadata + declared search terms
```

The application process is trusted because ordinary application logic must use plaintext. The
database, its credentials, operators, dumps and backups are outside the plaintext boundary. Root-key
custody is delegated to a local test provider or a real KMS/Vault provider, separate from Postgres.

Protection applies only to supported and declared paths. Raw SQL, direct drivers, external ETL,
reflection and unknown writers must be blocked, registered, detected, or reported as coverage gaps.

## 4. The central abstraction: Protection Manifest

The Protection Manifest is the source of truth. A field declaration eventually records:

- model, table, logical Python attribute and original database type;
- tenant, data subject and immutable record identity;
- physical ciphertext, envelope metadata and search representations;
- access mode: transparent or controlled;
- enabled query capabilities and leakage statement;
- normalization, null, uniqueness and index-domain versions;
- encryption, key, envelope and search-index versions;
- migration phase and previous readable formats;
- cache, rotation, revocation and shredding behavior; and
- supported ORM/Core/raw paths and required failure behavior.

Every other subsystem consumes the same compiled manifest. No subsystem independently guesses field
names, key domains, normalization or physical schema.

## 5. Complete subsystem map

```text
                           protect() declarations
                                     |
                                     v
                         Protection Manifest / IR
        +----------------------+-----+-----+----------------------+
        |                      |           |                      |
        v                      v           v                      v
 SQLAlchemy data plane   Schema/Alembic   Key lifecycle      Doctor / SAST
 encrypt/decrypt/query   columns/indexes  providers/cache    AST/CFG/taint
        |                      |           |                      |
        +----------------------+-----+-----+----------------------+
                                     |
                                     v
                                PostgreSQL
                                     |
                    +----------------+----------------+
                    |                                 |
                    v                                 v
              Verify engine                    Pentest engine
          invariants/state/exposure       crawl/mutate/attack/replay
                    |                                 |
                    +----------------+----------------+
                                     v
                            Protection Graph
                                     |
                           Evidence and reports
                    JSON / SARIF / JUnit / HTML / attestations
```

### 5.1 Core data plane

Encrypts before persistence, decrypts after loading, constructs authenticated context, generates
search tokens and refuses unsupported operations. It must remain local on normal hot paths; remote
KMS calls cannot hide inside synchronous SQLAlchemy attribute or scalar type hooks.

### 5.2 Schema and migration plane

Compiles logical protection into physical ciphertext/index columns, constraints and Alembic
operations. It plans reviewable expand/backfill/verify/cutover/contract migrations and never mutates
production schema at application startup.

### 5.3 Key lifecycle plane

Manages tenant branch material, subject key generations, wrapping providers, caches, rotation,
revocation, cache fencing, tombstones, shredding state and bounded receipts.

### 5.4 Doctor

Begins with manifest/model/schema/Alembic reconciliation and AST lint rules. Long term it develops a
stable Python semantic IR, symbols, qualified names, CFGs, call graphs, data flow, typed taint,
SQLAlchemy/query analysis, rule packs and runtime correlation.

### 5.5 Pentest

Starts by integrating ZAP and deterministic lab scenarios. Long term it may build an endpoint graph,
crawler, authentication/state engine, mutators, payload families, response/exposure oracles,
minimization and replay. All active work stays explicitly authorized and disposable.

### 5.6 Verify

Tests known invariants and state machines: envelope tamper/relocation, bypasses, tenant confusion,
query behavior, migration interruption, provider outage, stale caches, revocation, shredding,
restore and plaintext-marker exposure. A Pentest discovery can become a deterministic Verify test.

### 5.7 Protection graph and evidence

Connects logical fields to physical assets, readers/writers, keys, migrations, routes, attacks,
collectors and evidence. It preserves whether a claim is declared, statically modeled,
runtime-observed, actively exercised, exposure-confirmed or inconclusive.

## 6. Essential data flows

### 6.1 Protected write

1. Application assigns a normal Python value.
2. SQLAlchemy tracks the logical attribute as dirty.
3. `before_flush` resolves tenant, subject, record, field and manifest context.
4. The active key context supplies local key material; no hidden remote call occurs.
5. Cryptalis normalizes only for declared search capabilities.
6. It generates randomized authenticated ciphertext and companion search terms.
7. Hidden physical attributes receive the envelope and indexes.
8. SQLAlchemy emits only physical protected values.
9. Database constraints reject obvious plaintext/missing representations.
10. Tests inspect emitted SQL, stored rows and artifacts for seeded plaintext.

### 6.2 Protected read

1. SQLAlchemy loads hidden ciphertext and metadata.
2. The public descriptor obtains the active validated context.
3. Cryptalis parses and validates the envelope version.
4. It resolves the permitted key generation locally.
5. AEAD verifies tenant/subject/table/field/record context as AAD.
6. Transparent fields return their Python value; controlled fields require an explicit reveal flow.
7. Tampered, relocated, revoked, shredded or unknown data fails with a typed error.

### 6.3 Equality query

1. Application writes `User.email == value`.
2. A Cryptalis comparator recognizes the declared equality capability.
3. The active tenant/index context normalizes and tokenizes the right-hand value.
4. Query validation checks tenant scope, manifest version and expression shape.
5. SQLAlchemy compares the physical equality-token column.
6. Returned ciphertext is decrypted normally.
7. Unsupported operators fail before SQL rather than silently changing semantics.

### 6.4 Migration

1. Inspect manifest, models, live schema and Alembic graph.
2. Generate a reviewable plan and explicit compatibility window.
3. Expand schema with protected shadow columns and constraints.
4. Deploy compatible readers/writers if the plan requires coexistence.
5. Backfill in small, resumable, idempotent batches.
6. Verify envelope/index consistency and absence of plaintext residue.
7. Cut over reads/writes under an explicit manifest version.
8. Observe before irreversible contraction.
9. Remove plaintext only after recovery/rollback limits are accepted.
10. Record evidence and remaining backup/index consequences.

### 6.5 Rotation, revocation and shredding

1. Start a versioned lifecycle operation with an idempotency key.
2. Fence new cache loads through a new generation/epoch.
3. Obtain worker lease/acknowledgement evidence.
4. Rotate or disable wrapped key material according to provider semantics.
5. Delete subject-owned search artifacts where applicable.
6. Persist an external restore-resistant tombstone.
7. Test fresh and deliberately stale processes.
8. Restore an old snapshot and test resurrection prevention.
9. Keep Cryptalis state, provider state, cache state and data-path results separate.
10. Produce a bounded receipt that states assumptions and unresolved copies.

### 6.6 Doctor to Pentest to Verify

1. Doctor finds a possible protected-value or injection path.
2. Pentest attempts it in the authorized synthetic lab.
3. The exposure oracle observes DB, response, log and artifact collectors.
4. The protection graph identifies affected fields, storage and keys.
5. The report separates exploit success, extraction and plaintext exposure.
6. A reproducible discovery becomes a deterministic Verify regression.

## 7. Proposed package and file boundaries

These paths are a construction target, not current files:

```text
pyproject.toml
src/cryptalis/
  __init__.py
  errors.py
  manifest/
    model.py
    compiler.py
    naming.py
    diff.py
  crypto/
    aead.py
    envelope.py
    kdf.py
    normalization.py
    search.py
  keys/
    provider.py
    local.py
    cache.py
    lifecycle.py
    tombstones.py
  sqlalchemy/
    context.py
    mapping.py
    descriptor.py
    events.py
    comparators.py
    guards.py
  schema/
    physical.py
    compiler.py
    compare.py
  alembic/
    operations.py
    autogenerate.py
    renderers.py
  migration/
    plan.py
    state.py
    backfill.py
    verify.py
  doctor/
    workspace.py
    python_ast.py
    semantic_ir.py
    symbols.py
    cfg.py
    dataflow.py
    taint.py
    rules.py
    findings.py
  verify/
    invariants.py
    scenarios.py
    exposure.py
    collectors.py
  pentest/
    target.py
    endpoints.py
    auth.py
    mutate.py
    execute.py
    analyze.py
    replay.py
    adapters/
      zap.py
  evidence/
    model.py
    bundle.py
    sarif.py
    junit.py
  cli/
    main.py
tests/
  unit/
  integration/
  compatibility/
  adversarial/
  fixtures/
```

Files are split by responsibility so the solo builder can understand and test one concept at a time.
The actual tree may change only through an architecture/documentation decision before code is typed.

## 8. Solo learning and manual-typing contract

Cryptalis is built by one person. AI assistance follows these rules:

1. The assistant may directly create or edit documentation only.
2. The assistant does not create, patch or rewrite application source, tests, migrations, build
   configuration or CI files.
3. Implementation proceeds one file at a time, normally test first.
4. For each file, the assistant first explains its responsibility, dependencies, public interface,
   invariant and likely failure modes.
5. The assistant then provides the complete contents of exactly one file in the conversation.
6. The builder manually types the file rather than asking the assistant to write it into the repo.
7. The assistant gives one exact command and the expected failure/pass result.
8. The builder runs the command and shares the actual output.
9. The next file is not provided until the previous result is understood and any discrepancy is
   diagnosed.
10. At each phase gate, the builder explains the design back in their own words before continuing.

Small paired files may be discussed together, but their contents are still delivered separately.
No bulk source dump, generated scaffold or autonomous implementation is compatible with this
learning workflow.

## 9. Build principles

- Test behavior before implementation; prefer one failing test followed by the smallest passing
  implementation.
- Build vertical slices that persist and recover one protected value before expanding breadth.
- Freeze formats only after vectors and misuse cases exist.
- Use typed failures; never fall back to plaintext or guessed context.
- Keep remote key-provider calls out of hidden synchronous ORM paths.
- Never auto-apply production migrations.
- Record declared, static, observed and exercised evidence separately.
- Benchmark against a no-protection baseline and relevant reference implementations.
- Keep experimental crypto, payloads and vulnerable fixtures outside production packages.
- Do not move to the next phase merely because code imports; cross the explicit exit gate.

## 10. Dependency graph, not a scope gate

```text
tooling/evidence vocabulary
        |
        v
manifest -> crypto envelope -> local key provider
        |           |               |
        +-----------+---------------+
                    v
          minimal SQLAlchemy write/read
                    |
                    v
             equality search
                    |
                    v
         schema/Alembic/migration
                    |
                    v
        lifecycle/cache/shredding
                    |
        +-----------+-----------+
        v                       v
   Doctor/plan              Verify/evidence
        |                       |
        +-----------+-----------+
                    v
               Pentest lab
                    |
                    v
       hardening + advanced research
```

The arrows identify where one capability needs evidence from another before making an integrated or
production-facing claim. They do not prohibit early AST/CFG, DAST, networking, lifecycle, or
searchable-encryption research. All workstreams may begin with isolated fixtures, experiments,
interfaces and comparative benchmarks; integration evidence accumulates as dependencies become real.

## 11. Flat solo workstream catalogue

Every workstream below is active. The numbering describes a useful dependency spine and stable
reference order, not a rule that one workstream must finish before another begins. Within every
workstream, implementation is still delivered and typed one file at a time according to section 8.

### Workstream 0 — establish the evidence baseline

**Goal:** make every future claim distinguish planned, implemented, tested and measured behavior.

**Work:** agree Python/SQLAlchemy/Alembic/PostgreSQL versions; define test commands, repository
layout, result vocabulary and synthetic marker policy; record reference implementations.

**First future files:** `pyproject.toml`, `src/cryptalis/__init__.py`, `src/cryptalis/errors.py`,
`tests/conftest.py`.

**Learn:** packaging, dependency groups, pytest structure and typed error boundaries.

**Exit gate:** a clean environment can import the empty package and run one intentional test; no
security behavior is claimed.

### Workstream 1 — define the Protection Manifest

**Goal:** represent one protected model field deterministically without performing encryption.

**File order:** `manifest/model.py` → its tests → `manifest/naming.py` → tests →
`manifest/compiler.py` → tests → `manifest/diff.py` → tests.

**Learn:** immutable domain models, canonical serialization, validation, versioning, content hashes
and deterministic physical names.

**Exit gate:** the same declaration always compiles to the same manifest and invalid tenant/subject,
search, normalization and constraint combinations fail with exact errors.

### Workstream 2 — build the cryptographic envelope with a local provider

**Goal:** encrypt and authenticate one byte/string value under explicit context.

**File order:** `crypto/kdf.py` → `crypto/aead.py` → `crypto/envelope.py` → `keys/provider.py` →
`keys/local.py`, with a test file before each implementation file.

**Learn:** AEAD, nonces, AAD, HKDF/domain separation, envelope versioning, serialization and key
wrapping boundaries.

**Exit gate:** frozen positive vectors decrypt; nonce/context/tamper/relocation/unknown-version tests
fail correctly; logs and exceptions reveal no plaintext or key bytes.

### Workstream 3 — prove SQLAlchemy write/read paths

**Goal:** assign a normal Python value, persist ciphertext, reload and recover the value.

**File order:** `sqlalchemy/context.py` → `mapping.py` → `descriptor.py` → `events.py`, with a tiny
PostgreSQL integration model and test introduced incrementally.

**Learn:** mapper configuration, descriptors, attribute instrumentation, unit-of-work state,
`before_flush`, identity map, rollback/expire/refresh and sync/async internals.

**Exit gate:** one sync and one async path pass insert/update/reload/rollback tests; emitted SQL and
stored rows contain no seeded plaintext; a missing key context fails loudly without blocking.

### Workstream 4 — build searchable-encryption capabilities

**Goal:** query randomized ciphertext through separately declared, domain-separated capability
representations. Equality, `IN`, and scoped uniqueness establish the first production-candidate
path; equijoin, grouping, range/order, text/fuzzy and structured search advance concurrently as
isolated research profiles.

**File order:** `crypto/normalization.py` → `crypto/search.py` →
`sqlalchemy/comparators.py` → `sqlalchemy/guards.py`.

**Learn:** blind indexes, frequency leakage, low-entropy attacks, comparator semantics, typed binds,
expression traversal, tenant domains and dual-index rotation.

**Exit gate:** equality/`IN`/scoped uniqueness behave exactly; undeclared `LIKE`, range, sort, join
and raw/bulk paths fail before SQL; leakage is documented and measured.

### Workstream 5 — compile physical schema

**Goal:** derive columns, indexes, domains and constraints from the manifest.

**File order:** `schema/physical.py` → `schema/compiler.py` → `schema/compare.py`.

**Learn:** PostgreSQL catalogs, types, domains, indexes, constraints, nullability, naming and drift.

**Exit gate:** manifest, SQLAlchemy metadata and a clean live database agree; drift is reported
without changing the database; obvious plaintext/missing index forms are rejected where feasible.

### Workstream 6 — integrate Alembic and migrations

**Goal:** create reviewable migrations and safely protect one existing plaintext table.

**File order:** `alembic/operations.py` → `alembic/renderers.py` → `alembic/autogenerate.py` →
`migration/state.py` → `migration/plan.py` → `migration/backfill.py` → `migration/verify.py`.

**Learn:** Alembic plugin APIs, revision graphs, expand/contract, online backfill, idempotency,
compatibility windows, rollback and data-loss boundaries.

**Exit gate:** interruption at every migration phase resumes safely; cutover verifies every row and
companion index; irreversible contraction is never automated or hidden.

### Workstream 7 — implement key lifecycle and cache fencing

**Goal:** support tenant branch keys, subject generations, rotation, revocation and bounded caches.

**File order:** `keys/cache.py` → `keys/lifecycle.py` → `keys/tombstones.py`; local and production
provider-adapter research may proceed in parallel, while production integration depends on the
tested lifecycle state machine.

**Learn:** envelope hierarchy, leases, epochs, cache invalidation, idempotent distributed workflows,
provider semantics and failure recovery.

**Exit gate:** two workers, including an offline/stale worker, respect the declared fencing bound;
old ciphertext remains readable only as declared; provider outage never causes plaintext fallback.

### Workstream 8 — implement bounded shredding and restore tests

**Goal:** make one subject's protected data undecryptable under explicitly stated assumptions.

**Work:** add pending/completed/failed states, wrapped-key deletion, index cleanup, worker
acknowledgements, external tombstones, receipts and snapshot restoration scenarios.

**Learn:** technical cryptographic erasure, distributed uncertainty, backups, provider deletion
windows, audit evidence and claim boundaries.

**Exit gate:** fresh and stale processes fail after completion; an old DB snapshot cannot silently
resurrect access; receipts list shared-index and unmanaged-copy limitations.

### Workstream 9 — build `doctor` and `plan`

**Goal:** reconcile what the developer declared, mapped, migrated and actually deployed.

**File order:** `doctor/workspace.py` → `doctor/findings.py` → `doctor/python_ast.py` →
`doctor/semantic_ir.py` → `doctor/symbols.py` → `doctor/rules.py`.

**Learn:** CPython AST, source spans, imports, scopes, symbols, name resolution, rule design, false
positives/negatives and SARIF concepts.

**Initial rules:** raw/Core/bulk/direct-driver bypasses; protected plaintext to log/serialize/file
sinks; unsafe decrypt/reveal; migration/AAD mistakes; provider/cache/configuration mistakes.

**Exit gate:** a labeled safe/unsafe fixture corpus publishes per-rule precision/recall and explicit
unknowns; a finding identifies an exact field/path and evidence basis.

### Workstream 10 — build CFG, data flow, and taint

**Goal:** explain multi-step protected-data flow rather than only matching syntax.

**File order:** `doctor/cfg.py` → `doctor/dataflow.py` → `doctor/taint.py`, each behind its own fixture
corpus and compared with CodeQL/Semgrep.

**Learn:** basic blocks, exceptional/async flow, worklist fixed points, def/use, aliases, function
summaries, sources, sinks, propagators, sanitizers and path explanations.

**Exit gate:** positive, negative and mutant cases work; unresolved reflection/dynamic dispatch is
reported. Interprocedural experiments may begin immediately, but their integrated claims depend on
an explainable and measured local data-flow foundation.

### Workstream 11 — build the evidence model and Verify

**Goal:** run deterministic invariants and produce reproducible results.

**File order:** `evidence/model.py` → `verify/invariants.py` → `verify/collectors.py` →
`verify/exposure.py` → `verify/scenarios.py` → `evidence/bundle.py` → renderers.

**Learn:** evidence provenance, result schemas, collectors, positive/negative controls, semantic
mutation, differential testing, SARIF/JUnit and artifact integrity.

**Exit gate:** missing collectors are inconclusive; seeded leaks are detected; protection mutants
are killed; manifest/source/target/tool/artifact digests make a run reproducible.

### Workstream 12 — integrate mature DAST and build Pentest internally

**Goal:** exercise the reference application and correlate attack success with protected-data impact.

**File order:** `pentest/target.py` → `pentest/adapters/zap.py` → `pentest/endpoints.py` →
`pentest/auth.py` → `pentest/mutate.py` → `pentest/execute.py` → `pentest/analyze.py` →
`pentest/replay.py`.

**Learn:** target authorization, HTTP state, crawling, authentication, mutation, payloads,
differential oracles, minimization, replay and DAST false positives.

**Exit gate:** only disposable synthetic targets can run active profiles; the same exploit can be
replayed against baseline/protected/mutated deployments; exposure and exploit outcomes stay separate.

### Workstream 13 — expose a coherent CLI and CI workflow

**Goal:** make the completed slices usable without hiding risk.

**Commands:** `doctor`, `plan`, `schema explain`, `verify`, `pentest`, `evidence` and a passive
`check --ci` composition.

**Learn:** CLI design, configuration precedence, exit semantics, redaction, plugin boundaries,
release engineering and CI evidence.

**Exit gate:** active/destructive work cannot run accidentally; every exit code maps to documented
result states; a clean checkout reproduces the supported fast and release gates.

### Workstream 14 — harden integrated releases

**Goal:** turn the vertical slice into an honestly supportable release candidate.

**Work:** compatibility matrix, fuzz/property tests, malformed input corpus, benchmarks, provider
failure tests, migration recovery, dependency/license review, documentation, independent crypto and
migration review, package quarantine and reproducible builds.

**Exit gate:** claims exactly match measured compatibility and evidence. “Production-ready,” “zero
leakage,” “complete SAST/DAST,” and legal/compliance claims remain unavailable without proof.

### Workstream 15 — advanced construction and systems research

Advance these research tracks as active parts of the program:

1. interprocedural/async/FastAPI-aware Doctor;
2. writer provenance and deployment graph;
3. internal crawler/auth/state/payload depth;
4. PCAP/TShark/Zeek flow analysis;
5. controlled-access key release;
6. equijoins and grouping;
7. isolated range/order construction study;
8. text/prefix/fuzzy and structured/JSON search;
9. Acra-inspired SQL policy, anomaly and honeytoken experiments; and
10. signed rule/scenario plugins and independent assessment.

Each track needs its own threat model, learning score, reference implementation, correctness oracle,
fixture corpus, benchmark, maintenance decision and production/experimental classification.

## 12. Integrated evidence checkpoints

An early integrated checkpoint protects selected SQLAlchemy fields with randomized authenticated
ciphertext, equality/`IN`/scoped uniqueness, one safe existing-data migration, tenant/subject key
lifecycle, bounded cache fencing/shredding evidence, Doctor analysis, deterministic Verify scenarios
and ZAP-backed attack-impact evidence.

That checkpoint is not the scope of Cryptalis. Advanced encrypted search, interprocedural SAST, the
internal DAST engine, networking, distributed assurance and controlled access remain active
workstreams even when they have not yet joined an integrated release. No checkpoint promises
universal raw/Core protection, public scanning, or production readiness without evidence.

## 13. Solo flat-program workload control

All subsystems are active program scope. The solo builder may move among them, keep multiple research
threads alive, and implement independent experiments without waiting for an unrelated subsystem to
finish. Work remains understandable by limiting each manual coding cycle and commit to one coherent
invariant. Each workstream carries its own status, dependencies, unknowns and evidence gate.

Recommended rhythm:

1. read the owning architecture section;
2. explain the invariant in plain language;
3. receive one test file from the assistant and type it;
4. run it and confirm the expected failure;
5. receive one implementation file and type it;
6. run the narrow test, then the applicable suite;
7. inspect real evidence such as SQL, rows or artifacts;
8. explain why the result is secure or incomplete;
9. update the checklist/evidence documentation; and
10. commit the single learning outcome.

If a workstream becomes too large, split by invariant—not by arbitrary week or line count.

## 14. How future file-by-file assistance works

When requesting implementation help, name the current workstream and ask for the next file. The
assistant response should contain:

1. current workstream and relevant dependency/evidence gates;
2. exact file path;
3. why the file exists;
4. concepts to understand before typing;
5. complete contents of one file;
6. a short walkthrough of every important block;
7. one exact command to run;
8. expected result and common discrepancies; and
9. no next-file code until actual output is returned.

The builder should ask questions before typing anything they cannot explain. Manual typing is not
busywork: it creates deliberate pauses to notice imports, types, boundaries, error handling and test
expectations.

## 15. Stop conditions and common mistakes

Stop and redesign when:

- normal async use requires hidden blocking provider calls;
- row/tenant/subject/AAD context must be guessed;
- unsupported writes or queries silently pass;
- the migration cannot recover deterministically from interruption;
- cached keys outlive the documented revocation/shredding bound;
- tests cannot detect deliberately seeded plaintext or weakened controls;
- a static-analysis claim hides unresolved Python behavior;
- active testing cannot prove target authorization and containment;
- advanced crypto lacks primary references, vectors and a credible review path; or
- the solo workload expands faster than completed vertical slices.

Common mistakes are integrating advanced search into a production profile without its leakage and
review evidence, presenting experimental SAST/DAST as complete before the protected vertical slice
exists, calling KMS per field, treating blind indexes as encryption, auto-applying migrations,
equating scanner silence with safety, and treating a signed first-party report as independent proof.

## 16. Where to read next

- [Architecture blueprint](architecture/README.md): exact technical decisions and failure model.
- [Backend checklist](backend-build-checklist.md): current implementation status and exit gates.
- [Learning-first philosophy](learning-first-research-philosophy.md): why every ambitious workstream
  is active scope.
- [Security Assurance research](security-assurance-suite-research.md): Doctor, Pentest, Verify,
  safety, evidence and tool comparisons.
- [Prior art](prior-art.md): reference systems, attribution and public-claim discipline.
- [Engineering playbook](../ENGINEERING_PLAYBOOK.md): testing, review and release workflow.

## 17. Final build rule

Start every major workstream, but keep each coding change small enough to understand and verify.
Advance research, fixtures and experiments broadly; integrate capabilities only when their actual
dependencies and evidence are ready. Cryptalis is ambitious in breadth and rigorous per invariant.
