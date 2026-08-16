# Codebase Walkthrough

A living guide to every meaningful file in this repository: what it is, what it depends on, what it
takes in, what it produces, how it fails, and how it is tested.

**Read this after [README.md](../README.md).** The README says what the system is and why. This file
says where things are and how control actually flows through them.

> **Status — 2026-08-12.** This repository contains no source code. Part 1 and Part 2 below describe
> files that exist and have been read. Part 3 describes the execution path of code that has not been
> written yet; every entry there is marked **`PLANNED`** and carries the milestone that will create
> it. As each milestone lands, its Part 3 entry moves into Part 2 with real line references. That
> migration is not optional — see [Maintenance rule](#maintenance-rule).

---

## Contents

- [How to use this guide](#how-to-use-this-guide)
- [Part 1 — Repository map](#part-1--repository-map)
- [Part 2 — Files that exist today](#part-2--files-that-exist-today)
- [Part 3 — Execution path (planned)](#part-3--execution-path-planned)
- [Generated files](#generated-files)
- [Maintenance rule](#maintenance-rule)

---

## How to use this guide

If you are new to the project, read in this order:

1. [README.md](../README.md) — decisions AD-1 through AD-7. Nothing below makes sense without them.
2. [Part 1](#part-1--repository-map) — what is where.
3. [Part 3](#part-3--execution-path-planned) — follow one encrypt request from HTTP to the database,
   then one decrypt request back. Those two paths are the whole system.
4. [docs/architecture/](architecture/) — only when you need to know *why* a specific mechanism looks
   the way it does.

If you are looking for a specific behaviour, search this file for the endpoint or the error code;
every documented failure names the module that raises it.

---

## Part 1 — Repository map

### Present today (verified on disk, 2026-08-12)

| Path | Responsibility | State |
|---|---|---|
| `README.md` | Engineering source of truth: vision, principles, non-goals, architecture decisions, module boundaries, conventions, roadmap, commands. | Current |
| `ENGINEERING_PLAYBOOK.md` | Process: workflow, branching, commits, review, testing, releases, secrets, migrations, observability, decision-making. | Current |
| `docs/backend-build-checklist.md` | Ordered, verifiable milestones with tests-first sequencing and status. | Current |
| `docs/codebase-walkthrough.md` | This file. | Current |
| `docs/architecture/` | Seven design records (ADR-0001…0007) plus an index. | Current |
| `capstone-final-decision.md` | Planning input and authoritative reconciliation of the competing designs. | Preserved, not edited |
| `prior-art-research.md` | Planning input: prior-art research and caveats. | Preserved, not edited |
| `LICENSE`, `.gitignore` | Repository licensing and initial hygiene. | Present |

### Planned (created by the milestone shown)

| Path | Responsibility | Milestone |
|---|---|---|
| `pyproject.toml` | Package metadata, pinned dependencies, tool configuration. | 0.3 |
| `.env.example` | Configuration contract. | 0.3 |
| `src/ale_gateway/app/` | Composition root: settings, unseal, lifespan, application factory. | 0.3, 2.2, 2.4 |
| `src/ale_gateway/api/` | HTTP handlers, authentication, rate limiting, error mapping. | 2.4, 3, 4, 6, 7 |
| `src/ale_gateway/core/crypto/` | AEAD, envelope format, AAD, key wrapping, KDF, CSPRNG. | 1 |
| `src/ale_gateway/core/keys/` | DEK/KEK lifecycle: create, cache, rotate, revoke, shred. | 2, 6, 7 |
| `src/ale_gateway/core/policy/` | Pure policy evaluator and field registry. | 3 |
| `src/ale_gateway/core/audit/` | Hash chain, checkpoints, verification. | 4 |
| `src/ale_gateway/db/` | Models, repositories, Alembic migrations. Only place SQL appears. | 2, 3, 4, 6 |
| `sdk/python/` | Client library used by the protected application. | 5 |
| `cli/` | Operator commands: keygen, rotate, shred, key stats. | 2.2, 6, 7 |
| `educational/` | Quarantined course lab implementations, Labs 1–6. | 9 |
| `bench/` | Benchmark harness, results, generated graphs. | 8 |
| `tests/` | `unit`, `vectors`, `property`, `integration`, `e2e`, `fuzz`, `boundary`. | Throughout |
| `deploy/` | Dockerfile, docker-compose.yml, CI workflow. | 0.4 |

---

## Part 2 — Files that exist today

### `capstone-final-decision.md` — planning input, authoritative

**Responsibility.** Resolves the conflict between two earlier proposals and fixes the project's
direction. It is the reason [AD-1](../README.md#ad-1--encryption-happens-at-write-time-the-database-stores-ciphertext)
exists.

**What it establishes, section by section:**

- §1 tabulates the real difference between the two candidate designs: encryption on the way *out*
  (API response) versus on the way *in* (before the database write). Everything else was ~80% shared.
- §2 gives four reasons the write-time model wins. The load-bearing ones: the database-breach
  question has no good answer under the response-time model, and crypto-shredding is architecturally
  impossible without encryption at rest.
- §3 is unusually valuable — it lists where the larger research document is **wrong**: an 8-month
  roadmap against a 14–16 week budget, an overstated competitor gap (it notes Acra Community Edition
  is Apache-2.0 with KMS flags, contradicting the research document's "KMS is Enterprise-only"), a
  strawmanned comparison table, and two citations flagged as unverified. Treat the research
  document's confident numbers as argument, not evidence.
- §4 lists what is kept (14–16 weeks, ABAC role table, fail-closed default, hash-chained + Merkle
  audit log with ECDSA checkpoints, benchmarks with published percentiles, demo script) and the two
  changes (move encryption to write time; scope DEKs per subject and add crypto-shredding around
  Week 11).
- §4 also contains the demo script that [the release-verification section](backend-build-checklist.md#release-verification)
  turns into an executable gate.
- §5 lists interview questions the project must be able to answer — a useful completeness check on
  the design.

**Downstream effect.** AD-1, AD-3, AD-5, the 14–16 week roadmap, and Milestone 6's placement all
trace to this file. Where it conflicts with the research document, it wins.

### `prior-art-research.md` — planning input, research

**Responsibility.** The long-form research argument. Useful for the parts that are *design* rather
than *market claims*.

**What is worth reading:** the threat model sketch (assets, adversaries A1–A5, trust boundaries,
assumptions, out-of-scope), the cryptographic design section (AES-256-GCM with 96-bit nonces and
AAD binding, envelope KEK/DEK, HKDF, hash-chain plus signed checkpoints), the key-lifecycle stages,
the data model, the testing strategy, and the 35 interview questions.

**What to discount:** the scoring table (`capstone-final-decision.md` §3 calls it false precision),
the competitor-gap claims, and the 8-month roadmap. Its own §"Caveats" concedes that competitor
status is a point-in-time snapshot and that the project is not a novel cryptographic contribution.

**Downstream effect.** AD-2, AD-3, AD-5, the data model in the README, and much of Milestone 1's
test plan.

### Educational material — not present

`educational/` remains a deferred directory. No course material, lab manual, or educational source
is present in this repository, so the walkthrough deliberately records no curriculum or exercise
requirements. Add the source material and update [ADR-0006](architecture/0006-educational-module-quarantine.md),
the checklist, and this guide in the same change before starting that workstream.

### The documentation system itself

`README.md`, `ENGINEERING_PLAYBOOK.md`, `docs/backend-build-checklist.md`, this file, and
`docs/architecture/*` form a closed set with no duplicated ownership: decisions in the README,
process in the playbook, status in the checklist, mechanics here, rationale in the ADRs. Each links
to the others rather than restating them. If you find the same fact stated twice, one of the two is
about to go stale — delete it and link instead.

---

## Part 3 — Execution path (planned)

Everything in this part is **`PLANNED`**. It describes the intended control flow so that
implementation has a target, and so that each milestone knows exactly which entry it must replace
with real detail and line references.

### Startup, in order

#### `deploy/docker-compose.yml` — `PLANNED` (Milestone 0.4)

Brings up Postgres with a healthcheck and a named volume, then the gateway, then the demo
application. Credentials come from `.env`; none are hard-coded. The gateway depends on the database's
*health*, not merely its start, so the first migration does not race the server.

*Fails when:* the database port is taken, or `.env` is missing. Both surface as a container that
never becomes healthy.
*Tested by:* `tests/integration/test_db_connection.py`.

#### `src/ale_gateway/app/settings.py` — `PLANNED` (Milestone 2.2)

Reads configuration **once**, into a typed object: database URL, sealed KEK, bearer token, cache TTL
and size, rate limits, environment name.

*Inputs:* process environment. *Outputs:* an immutable settings object.
*Fails when:* any required value is missing or malformed — by aborting startup. There is no default
KEK and no fallback. This is the single most important failure behaviour in the system.
*Tested by:* `tests/unit/test_settings.py`.

#### `src/ale_gateway/app/unseal.py` — `PLANNED` (Milestone 2.2)

Unseals the KEK into process memory and marks the service unsealed. The plaintext KEK is never
written to disk, never logged, never returned by any endpoint.

*Fails when:* the sealed material does not unseal — the service stays sealed and every
key-dependent endpoint answers `503`. `/healthz` still answers 200, because the process is alive;
readiness is expressed through `503` and the `gateway_sealed` metric.
*Tested by:* `tests/unit/test_unseal.py`.

#### `src/ale_gateway/app/main.py` — `PLANNED` (Milestone 2.4)

Application factory. Builds the settings object, unseals, opens the database pool, constructs the
repositories, injects them into the core services, registers routes and error handlers, and exposes
`/healthz` and `/metrics`. This is the only file that knows how the pieces are wired together;
everything else receives its dependencies.

*Tested by:* `tests/e2e/`, which exercises the real factory rather than a stub.

### An encrypt request, in order

1. **`api/auth.py`** — `PLANNED` (2.4). Validates the bearer token, resolves the caller to a
   principal (identity + roles). Ambiguous or missing credentials → `401`. No token contents are
   logged.
2. **`api/routes/encrypt.py`** — `PLANNED` (2.4). Validates the request body with Pydantic
   (`subject_id`, `table`, `column`, `record_id`, `plaintext`), calls exactly one core service, maps
   the result. Thin by rule: no cryptography, no SQL, no policy logic. Malformed body → `400`.
3. **`core/policy/schema.py`** — `PLANNED` (3). Looks up `(table, column)` in the field registry. Not
   registered → `422`, audited. This is where "we forgot to classify a column" becomes loud instead
   of silent.
4. **`core/keys/service.py`** — `PLANNED` (2.3). Gets or creates the active DEK for
   `(subject_id, field_class)`. On a cache hit, returns the unwrapped DEK; on a miss, loads the
   wrapped DEK from `db/repositories/keys.py`, unwraps it under the KEK, and caches it with a TTL.
   A revoked or shredded key is never selected for encryption.
5. **`core/crypto/aad.py`** — `PLANNED` (1.2). Builds the canonical AAD from
   `(subject_id, table, column, record_id)` with a length-prefixed encoding, so component values
   cannot be shifted across boundaries to produce a colliding AAD.
6. **`core/crypto/aead.py`** — `PLANNED` (1.2). Generates a fresh 96-bit nonce internally, encrypts
   with AES-256-GCM, returns an envelope. **The function signature has no nonce parameter** — this is
   the mechanism behind AD-2, not a convention.
7. **`core/crypto/envelope.py`** — `PLANNED` (1.1). Serializes version, `key_id`, algorithm id,
   nonce, ciphertext, and tag into one self-describing blob.
8. **`core/audit/chain.py`** — `PLANNED` (4). Appends an entry recording actor, action, resource, and
   decision, hashed over the previous entry's hash.
9. **`api/errors.py`** — `PLANNED` (2.4). Anything raised on the way maps to the single error
   envelope. A test asserts that no error body contains key or plaintext bytes.

The response carries the ciphertext, `key_id`, and envelope version. The application stores those in
its own table. The gateway stores no ciphertext.

### A decrypt request, in order

1. **`api/auth.py`** — as above.
2. **`api/routes/decrypt.py`** — `PLANNED` (2.4). Validates the body (ciphertext, `key_id`, context,
   purpose).
3. **`core/policy/evaluator.py`** — `PLANNED` (3). A pure function over `(request context, policy
   set)` returning `Decision(allow, rule_id, reason)`. Deny overrides allow; an empty policy set
   denies; a policy load failure denies. Because it performs no I/O, its entire decision table is
   unit-tested cheaply. Denial → `403 policy_denied`, audited with the rule id.
4. **`core/keys/service.py`** — resolves `key_id`. State `revoked` → `403` with a distinct code;
   state `shredded` → `410`, deliberately different from `404`, because the data provably existed and
   was erased.
5. **`core/crypto/envelope.py`** — parses the blob. Unknown version → `400
   unsupported_envelope_version`; truncation or a corrupt header → `400 malformed_ciphertext`. The
   parser is a total function and is fuzz-tested; it must never raise an unhandled exception.
6. **`core/crypto/aead.py`** — decrypts with the reconstructed AAD. A tag mismatch — from tampering,
   from a bit flip, or from a ciphertext moved to a different row or column — fails with a single
   opaque error that reveals nothing about which check failed.
7. **`core/audit/chain.py`** — records the decrypt and its outcome.

Plaintext exists in exactly one place on this path: the response body of an authorized decrypt.

### Supporting paths

- **`core/keys/rotation.py`** — `PLANNED` (7). Creates a new KEK version, re-wraps DEKs lazily on
  access with a background sweep for the remainder. Old ciphertext keeps decrypting because
  `kek_version` travels with every ciphertext. Resumable after interruption.
- **`core/keys/shred.py`** — `PLANNED` (6). Evict cache → emit signed erasure certificate → destroy
  `wrapped_dek` → set state `shredded` → append audit entry. The ordering is chosen so that a crash
  at any step leaves a recoverable, auditable state and never leaves a readable key that is believed
  destroyed. Irreversible by design.
- **`core/audit/verify.py`** — `PLANNED` (4). Recomputes the chain, verifies checkpoint signatures,
  and reports the sequence number of the first break. Served by `GET /v1/audit/verify`.
- **`sdk/python/`** — `PLANNED` (5). Wraps the HTTP calls with typed errors, an explicit timeout, and
  no retry on denials. A gateway failure must surface as an SDK exception; the one behaviour the SDK
  must never have is falling back to writing plaintext.
- **`cli/`** — `PLANNED` (2.2, 6, 7). Operator entry points for keygen, rotation, shred, and key
  statistics. Every destructive command requires explicit confirmation.
- **`educational/`** — `PLANNED` (9). Labs 1–6. **Not part of any path above.** Imports in either
  direction are blocked by `tests/boundary/test_educational_quarantine.py`.

### How each area is tested

| Area | Primary tests | Property that must break the test when violated |
|---|---|---|
| `core/crypto` | `tests/vectors`, `tests/unit`, `tests/property` | Known-answer match; nonce never repeats; wrong AAD or key fails |
| `core/keys` | `tests/integration/test_key_service.py`, `test_dek_cache.py` | Revoked/shredded keys never used; cache respects TTL and invalidation |
| `core/policy` | `tests/unit/test_policy_eval.py` | Every decision-table row; deny-overrides; empty set denies |
| `core/audit` | `tests/integration/test_audit_chain.py`, `test_checkpoints.py` | Any mutation, deletion, or reorder is detected at the right index |
| `api` | `tests/e2e`, `tests/unit/test_error_envelope.py` | Status mapping; no secrets in error bodies |
| `db` | `tests/integration` against real Postgres | Constraints and state transitions enforced by the schema, not only by code |
| Boundaries | `tests/boundary` | Import rules and `educational/` quarantine |
| Robustness | `tests/fuzz` | Malformed input never crashes and never yields plaintext |

---

## Generated files

The following are **generated** and are documented by their generator, not line by line. Do not hand-edit.

| Path | Generated by | Note |
|---|---|---|
| `src/ale_gateway/db/migrations/versions/*.py` | `alembic revision --autogenerate` | Always reviewed and often hand-corrected before commit; autogenerate misses constraints and data migrations. Each file's docstring must state intent. |
| `bench/results/**` | `python -m bench.run` | Raw output. Committed only in summarized form; raw dumps are gitignored. |
| `bench/*.svg`, `bench/*.png` | The plotting script in `bench/` | Regenerate rather than edit. |
| `.venv/`, `__pycache__/`, `.pytest_cache/`, `.mypy_cache/`, `.ruff_cache/` | Tooling | Gitignored. |
| SBOM output in CI | CI workflow | Build artifact, not source. |
| `poetry.lock`-equivalent pin files | `pip-compile` or equivalent | Regenerate; review the diff for unexpected transitive changes. |

---

## Maintenance rule

**This guide is updated in the same change as the code it describes.** Not afterwards, not in a
cleanup pass.

A change is incomplete — and must not be merged — if it touches any of the following without a
corresponding edit here:

- source files under `src/`, `sdk/`, `cli/`, `bench/`, or `educational/`
- tests, including a new test directory or marker
- configuration: `pyproject.toml`, `.env.example`, settings fields, policy documents
- database migrations
- `deploy/Dockerfile`, `deploy/docker-compose.yml`
- CI workflows
- any frontend code, if a frontend is ever introduced

**What the edit must contain**

- **New file:** an entry in [Part 1](#part-1--repository-map) and a Part 2 subsection stating
  responsibility, dependencies, inputs, outputs, failure behaviour, and the tests that cover it.
- **Changed behaviour:** update the relevant path description. If the control flow order changed,
  reorder the steps — a stale order is worse than no order.
- **New failure mode or error code:** add it to the path description *and* confirm the README's
  error-handling table still matches.
- **Deleted file:** delete its entry. A walkthrough that documents a file which no longer exists
  teaches a newcomer something false.
- **Milestone landed:** move its Part 3 `PLANNED` entries into Part 2 with real line references, and
  tick the item in [docs/backend-build-checklist.md](backend-build-checklist.md).

**Review enforcement.** The PR self-review checklist in the
[playbook](../ENGINEERING_PLAYBOOK.md#pull-requests-and-review) contains this check. During release
verification, this file is diffed against `git diff` since the previous tag; a file added or removed
without a corresponding entry blocks the release.

**Why this rule is strict.** The guide's only value is that it can be trusted without verification.
One stale section teaches the wrong control flow to whoever reads it next, and it costs more to
rediscover the truth than the original edit would have cost.
