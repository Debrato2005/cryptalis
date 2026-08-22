# Cryptalis

Cryptalis is a planned SQLAlchemy-native data-protection platform for Python applications. It
compiles field-protection declarations into transparent application-layer encryption, protected
PostgreSQL storage, capability-specific search indexes, reviewed Alembic migrations, subject-key
lifecycle controls, and reproducible security evidence.

> **Repository status — 2026-08-22:** architecture and research only. No package, runtime,
> migration plugin, database schema, key provider, or verification harness has been implemented.
> Every API and command below is a design target until executable evidence says otherwise.

## Executive verdict

**BUILD CRYPTALIS AS AN AMBITIOUS, LEARNING-FIRST DATA-SECURITY SYSTEM. The complete architecture is
the active program from the beginning; evidence gates control claims, not which subsystem may be
studied or built.**

CipherStash and MongoDB are stronger reference systems for advanced encrypted search. Rails already
proves that transparent application-layer encryption is useful, and `pydantic-encryption` already
provides Python/SQLAlchemy encryption, blind indexes, AWS KMS integration, and deferred decryption.
Their existence is prior art and a source of testable reference behavior—not a reason to avoid
implementing similar capabilities for deep learning. Cryptalis's coherent center remains:

- a versioned Protection Manifest that is the source of truth for crypto, schema, query, lifecycle,
  and leakage decisions;
- SQLAlchemy 2.x query semantics and fail-loud compatibility analysis;
- automatic but reviewable PostgreSQL/Alembic migration planning for existing applications;
- tenant- and subject-scoped rotation, revocation, cache fencing, and bounded shredding evidence;
- minimum-leakage recommendations based on declared, statically observed, and runtime-observed
  query behavior; and
- verification that measures protected-data exposure after realistic attacks succeed.

Competitor overlap alone is never a stop condition. A feature may be built, integrated, or both after
considering learning value, system fit, correctness, testability, maintenance and production risk.
Known searchable-encryption and security-analysis techniques may be independently implemented in
research profiles with attribution and comparison. Novel or insufficiently reviewed cryptography
does not enter a production profile merely because implementing it is educational.

## Product thesis

The trusted boundary is the application process. Registered values remain ordinary Python values
inside that boundary and are encrypted locally before PostgreSQL persistence:

```text
Python plaintext -> Cryptalis data plane -> PostgreSQL ciphertext
PostgreSQL ciphertext -> Cryptalis data plane -> Python plaintext
```

The target declaration is intentionally small:

```python
cryptalis.protect(
    User,
    tenant="organization_id",
    subject="id",
    fields={
        "email": {"access": "transparent", "search": ["equality"]},
        "ssn": {"access": "controlled", "search": []},
    },
)
```

Transparent access is the default. Controlled fields are an optional strict profile for values
whose accidental disclosure through logs, tracing, serialization, or broad application flows is a
larger risk. Controlled access is meaningful only when an independently authenticated key authority
can refuse decryption; a local `reveal()` wrapper alone is not a security boundary.

## Security claim

Cryptalis is designed to reduce plaintext exposure from:

- stolen database dumps and leaked backups;
- compromised database credentials and direct SQL extraction;
- overprivileged database operators when keys are separated from PostgreSQL; and
- accidental plaintext persistence through supported SQLAlchemy paths.

It does not prevent SQL injection, broken authorization, XSS, arbitrary code execution in the
trusted process, full application-host compromise, deliberate plaintext export, or every logging
mistake. A successful attack and a plaintext disclosure are reported as separate outcomes.

## Complete architecture

```text
protect() declarations + observed queries
                  |
                  v
        versioned Protection Manifest
       /          |          |          \
      v           v          v           v
 ORM data plane  schema     lifecycle   explain/verify
 local AEAD +    compiler   control     doctor/plan
 query rewrite     |        plane
      |             v          |
      +--------> PostgreSQL <---+----> KMS / Vault
```

- The **data plane** runs in the application and performs local encryption, decryption, and search
  token generation. Remote KMS calls are forbidden from scalar ORM processors and normal hot paths.
- The **schema compiler** derives physical columns, indexes, constraints, and Alembic operations
  from the manifest. It generates plans; it never mutates production schema at application startup.
- The **lifecycle control plane** coordinates wrapped keys, generations, cache epochs, tombstones,
  audit checkpoints, and shredding receipts. It is not a per-field encryption gateway.
- The **analysis plane** powers `doctor`, `plan`, `schema explain`, and `verify`. Its active
  workstreams include manifest/model/schema linting, AST, symbols, CFG, call graphs, data flow,
  taint analysis and a substantial internal pentesting engine. Static and runtime evidence never
  becomes an unsupported guarantee.

The complete decision, leakage, migration, and failure model is in the
[architecture blueprint](docs/architecture/README.md).

## Search capability policy

Searchability is opt-in because every representation leaks information.

| Capability | Program status | Minimum consequence |
|---|---|---|
| No search | Core | Randomized authenticated ciphertext only |
| Equality, `IN`, scoped uniqueness | Active workstream | Repetition/frequency and access-pattern leakage within an index domain |
| Equijoin/grouping | Research gate | Cross-column equality leakage and difficult rotation domains |
| Range/order/`MIN`/`MAX` | Active construction-research workstream; reviewed production path only | Order and query-pattern leakage; high attack and migration complexity |
| Prefix/text/fuzzy | Active experimental workstream | Token/pattern leakage and substantial storage amplification |
| JSON/path search | Active experimental workstream | Schema/path/query-pattern leakage and companion-index complexity |

Unsupported operators fail loudly. Learning value can justify researching a capability; enabling it
still requires an explicit leakage, lifecycle, migration and correctness decision.

## Flat ambitious program

- **All workstreams are active:** core protection, advanced searchable encryption, schema and
  migrations, distributed key lifecycle, Doctor/SAST, Pentest/DAST, Verify, protection/evidence
  graphs, networking/PCAP analysis, DevSecOps integration, and controlled-access research.
- **Flat does not mean unverified:** each workstream may advance immediately and independently, but
  nothing enters a production profile or public claim until its own threat, correctness, leakage,
  safety, benchmark, compatibility, and review gates pass.
- **Solo does not mean narrow:** one builder may move among workstreams according to learning value,
  discovered dependencies, risk, and available experiments. Manual file-by-file implementation and
  explicit evidence remain mandatory.

The staged learning roadmap and build-versus-integrate decisions live in the
[learning-first research philosophy](docs/learning-first-research-philosophy.md).

## Solo build workflow

Cryptalis is built by one person. Implementation proceeds one file at a time: understand the
invariant, manually type a failing test, run it, manually type the corresponding implementation,
inspect the evidence, and cross the file's evidence gate before receiving the next file. AI assistance may
edit documentation directly, but does not write source, tests, migrations, configuration or CI into
the repository. See the [complete solo build guide](docs/cryptalis-build-guide.md).

## Active program scope

The active program includes the complete platform:

- Python 3.12+, SQLAlchemy 2.x, FastAPI-friendly sync and async examples, PostgreSQL, and Alembic;
- versioned manifest and explainable physical schema for randomized ciphertext and equality indexes;
- transparent insert/update/load through one declared ORM path with normal Python values;
- active tenant key context so no remote provider call occurs during synchronous attribute access;
- one local provider and one production KMS adapter behind a narrow wrapping interface;
- tenant branch keys, subject key generations, rotation, revocation, cache fencing, and a bounded
  shredding workflow;
- resumable expand/backfill/verify/cutover/contract migration for one existing table;
- `doctor`, `schema explain`, and `verify` with a versioned compatibility catalogue;
- Web Application Pentesting via OWASP ZAP plus deterministic database-exposure scenarios; and
- pinned benchmarks against baseline SQLAlchemy and `pydantic-encryption` where comparable.

It also includes independently researched range/order, equijoin/grouping, text, fuzzy and structured
search; Doctor syntax IR, CFG, data flow and interprocedural taint; an internal endpoint graph,
crawler, authentication/state engine, mutators, payloads, oracles and replay; writer provenance;
distributed lifecycle fault injection; PCAP/flow correlation; controlled-access authority; and
signed rule/scenario ecosystems.

Universal interception, autonomous production migration, public-target exploitation, custom root
key custody, and unsupported production-readiness or compliance claims remain excluded because they
violate the trust model or evidence discipline—not because they exceed a course schedule.

## Documentation

| Document | Owns |
|---|---|
| This README | Product promise, threat boundary, complete shape, and active program scope |
| [Learning-first research philosophy](docs/learning-first-research-philosophy.md) | Governing evaluation criteria, full learning architecture, matrices, and flat workstream roadmap |
| [Complete solo build guide](docs/cryptalis-build-guide.md) | Entire system in plain language, flat workstream map, dependencies, target files, learning goals, and evidence gates |
| [Architecture blueprint](docs/architecture/README.md) | Accepted design, query/leakage contract, lifecycle, migration, and fatal gates |
| [Prior art](docs/prior-art.md) | Competitive comparison and claim discipline |
| [Security assurance research](docs/security-assurance-suite-research.md) | Adversarial Doctor, Pentesting, Verify, evidence, integration, and safety decision |
| [Backend checklist](docs/backend-build-checklist.md) | Per-workstream implementation and evidence status |
| [Engineering playbook](ENGINEERING_PLAYBOOK.md) | Contribution, testing, migration, and release process |

The previous gateway-first ADR set was removed because it encoded a superseded Model B architecture
and repeated decisions now owned by the blueprint.

## Current next step

Begin the high-risk prototypes in the [backend checklist](docs/backend-build-checklist.md) while
advancing the other active workstreams through isolated research, fixtures and experiments. An
affected production claim must stop or be redesigned if transparent sync/async behavior, fail-loud
bypass handling, subject-key fencing, or migration safety cannot be demonstrated without
framework-scale fragility.
