# Cryptalis

Cryptalis is a planned data-protection and security-assurance system for Python and SQLAlchemy.
Its versioned Protection Manifest declares field policy. The proposed system connects this
policy to authenticated payload encryption, search capabilities, PostgreSQL schema, and reviewed
Alembic migrations. It also connects key lifecycle and application paths to controlled attacks
and reproducible exposure evidence.

**Status as of 2026-10-01: documentation and research only.** The repository has no package,
runtime, tests, migration plugin, provider adapter, scanner integration, or verification
harness. Every Cryptalis API and command is a proposed contract. The [capability
checklist](docs/backend-build-checklist.md) separates specified design from executable evidence.
No runtime version is supported.

## Purpose and boundary

Application engineers would use Cryptalis to protect selected sensitive model fields. Operators
would manage migrations and key access. Reviewers would interpret evidence within its stated
scope. The first target is a tenant-aware Python service with registered SQLAlchemy sessions,
PostgreSQL, stable record IDs, and host-issued identity and authorization grants. The
application process handles plaintext and is trusted.

The design requires supported paths to encrypt protected values before PostgreSQL receives them.
The intended protection covers database dumps, backup disclosure, direct SQL extraction, and
accidental persistence through supported paths. It does not prevent SQL injection, cross-site
scripting (XSS), business authorization bugs, application-host compromise, or deliberate export
of decrypted values. Search terms, IDs, and lengths reveal declared information.

Raw drivers, COPY, extract-transform-load (ETL) processes, and separate writers are explicit
coverage gaps. A successful exploit and exposure of protected plaintext are separate results.

Transparent fields remain ordinary Python values. Application serializers and logs can receive
these values. Controlled access is a separate profile that requires release bound to purpose and
identity.

A local reveal wrapper alone is not an independent security boundary. Key removal or restore
denial does not prove erasure of backed-up key bytes or unmanaged copies.

## System shape

```text
field declarations -> immutable Protection Manifest
                       |        |         |         |
                       v        v         v         v
                  ORM/crypto  schema/   lifecycle  Doctor/plan
                    queries   Alembic   key/fence   analysis
                       |        |         |
                       +---- PostgreSQL --+---- provider/denial ledger
                                      |
                      authorized synthetic Verify/Pentest/network lab
                                      |
                       derived Protection Graph + bounded evidence
```

The first candidate query profile includes randomized protection without search, equality, IN,
and scoped uniqueness. Join and grouping, range and ordering, extrema, prefix, substring and
text search, fuzzy search, and structured or JSON queries remain research tracks. Each track
requires a specific construction. The [search
contracts](docs/architecture/crypto-search-lifecycle.md) define leakage, cost, lifecycle, and
enablement gates.

The default design uses explicit key warm-up or prefetch, then local cryptography. This default
still requires comparison with actual greenlet-backed remote I/O and deferred batch
alternatives.

The multi-year program includes object-relational mapping (ORM), query compilation, migrations,
and distributed key lifecycle. It also includes Doctor analysis of abstract syntax trees (ASTs),
control-flow graphs (CFGs), and taint. Pentest covers state, mutation, and replay experiments.
Verify, network analysis, packet capture (PCAP), DevSecOps evidence, and advanced search
complete the program scope.

Dependencies govern integration and claims. They do not impose a course limit or a minimum
viable product (MVP) ceiling. Attribution and differential comparison take priority over
novelty.

## Start here

| Document | Responsibility |
|---|---|
| [Architecture blueprint](docs/architecture/README.md) | Authoritative ownership map, decisions, threats, invariants, and dependency graph |
| [Manifest/context/API](docs/architecture/manifest-context-api.md) | Semantic schema, identity provenance, public interfaces, modules, errors, and versions |
| [Crypto/search/lifecycle](docs/architecture/crypto-search-lifecycle.md) | Envelope, leakage, provider, cache, fence, restore, and receipt contracts |
| [ORM/schema/migration](docs/architecture/orm-schema-migration.md) | Query paths, async alternatives, physical schema, Alembic, and migration recovery |
| [Assurance/evidence](docs/architecture/assurance-evidence.md) | Doctor, Protection Graph, Verify, Pentest, collectors, network, bundles, and benchmarks |
| [Solo build guide](docs/cryptalis-build-guide.md) | Learning order, first files, and evidence checkpoints |
| [Research philosophy](docs/learning-first-research-philosophy.md) | Learning priorities, build-or-integrate choices, and broader research experiments |
| [Checklist](docs/backend-build-checklist.md) | Current implementation and evidence state |
| [Prior art](docs/prior-art.md) | Dated competitor comparisons and positioning limits |
| [Assurance research](docs/security-assurance-suite-research.md) | Analyzer and adversarial research, including falsification |
| [Engineering playbook](ENGINEERING_PLAYBOOK.md) | Manual implementation, contribution, verification, and release process |
| [Claims audit](docs/documentation-claims-audit.md) | W-1..W-5 closure, adversarial review, and recorded documentation checks |
| [Historical hardening dossier](docs/adversarial-architecture-hardening.md) | Original hostile-review hypotheses and superseded technical details |

The blueprint links ledgers of primary sources. Documented or source-inspected external
capabilities are separate from reproduced Cryptalis capabilities. Existing encryption, ORM,
search, and assurance systems are strong alternatives. The proposed differentiator is
application-specific correlation. Cryptalis does not claim universal superiority or new
cryptographic primitives.

## Next evidence

Start with the provenance, manifest and envelope, ORM state and bypass, and three-way async
prototypes in the [checklist](docs/backend-build-checklist.md). Lifecycle and restore,
interrupted migrations, equality uniqueness, and oracle controls each have falsifiable gates.
Research can proceed independently.

The solo builder manually types source, tests, migrations, and configuration, one explained file
at a time. AI assistance edits documentation and discusses the next file. It does not scaffold
or implement the repository. Documentation changes confer no production security claim.
