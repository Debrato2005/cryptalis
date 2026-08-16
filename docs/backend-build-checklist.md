# Backend Build Checklist

The executable plan for the application-layer encryption gateway. This is the **only** place
milestone status lives — [README.md](../README.md) states the roadmap shape, this file states what
is actually done.

**Product area:** backend. There is no frontend, no mobile client, and no platform/infrastructure
workstream in this repository. The demo backend (*Smolink*) is a separate repository consumed
through the SDK; work on it is tracked there, and appears here only as integration items.

## How to read this file

| Marker | Meaning |
|---|---|
| `[x]` | **Implemented and verifiable from this repository** — code present, test present, command runs green. |
| `[~]` | **In progress** — branch open, partially landed. |
| `[ ]` | **Planned** — not started. |
| `[-]` | **Deferred** — deliberately not doing this now; reason given. |

Nothing is marked `[x]` on the strength of an intention. A milestone is complete when its
verification commands pass on a clean checkout.

## Status summary — 2026-08-12

| Milestone | Weeks | Status |
|---|---|---|
| 0 — Repository bootstrap | 1 | **Planned** (documentation sub-milestone complete) |
| 1 — Cryptographic core | 2–3 | Planned |
| 2 — Key management and the encrypt/decrypt path | 4–5 | Planned |
| 3 — Policy-gated decryption | 6–7 | Planned |
| 4 — Tamper-evident audit log | 8–9 | Planned |
| 5 — SDK and demo integration | 10 | Planned |
| 6 — Crypto-shredding | 11 | Planned |
| 7 — Rotation, revocation, hardening | 12 | Planned |
| 8 — Benchmarks | 13 | Planned |
| 9 — Educational module | Deferred | Deferred — source materials are not present |
| 10 — Release | 15–16 | Planned |

**Verified repository state on 2026-08-12:** the initial Git commit, `LICENSE`, `.gitignore`, and
the documentation baseline exist. There is no application source, test suite, CI, or container
configuration. Week numbers are relative to Week 1; no start date is recorded, so no calendar dates
are claimed.

---

## Milestone 0 — Repository bootstrap

**Goal:** a repository where a test can fail. Nothing cryptographic yet — the point is to make every
later milestone verifiable.

### 0.1 Documentation baseline — `[x]` complete 2026-08-12

- [x] `README.md` — vision, principles, non-goals, AD-1…AD-7, boundaries, conventions, roadmap, commands
- [x] `ENGINEERING_PLAYBOOK.md` — workflow, branches, commits, PRs, testing, releases, secrets, migrations, observability
- [x] `docs/backend-build-checklist.md` — this file
- [x] `docs/codebase-walkthrough.md` — living guide, currently documenting a pre-code repository
- [x] `docs/architecture/` — ADR-0001…ADR-0006

*Verifiable by:* the files exist in this directory.

### 0.2 Version control — `[~]`

Tests first: none — this is infrastructure.

- [x] Git repository with an initial commit
- [x] `.gitignore` and `LICENSE` exist; expand `.gitignore` when the planned tooling creates its
      first local artifacts
- [ ] Record the licence identity in the README only after it is verified from `LICENSE`
- [ ] Select and apply a package name when `pyproject.toml`, the service name, and client metadata
      are created; do not claim that a package rename has occurred before then

Commands:

```bash
git init ; git add -A ; git status
```

```bash
git commit -m "chore: documentation baseline and planning inputs"
```

### 0.3 Package skeleton and tooling — `[ ]`

Tests first:

- [ ] `tests/test_smoke.py` — imports `ale_gateway`, asserts `__version__` is a string. Must fail
      before the package exists.
- [ ] `tests/boundary/test_import_rules.py` — asserts `core.crypto` imports nothing from `db`,
      `api`, or `core.keys`; asserts nothing imports `educational`. Both directories are empty at
      this point; the test must still run and pass, so it grows teeth for free later.

Implementation:

- [ ] `pyproject.toml`: project metadata, `requires-python = ">=3.12"`, dependencies
      (`fastapi`, `uvicorn`, `pydantic-settings`, `sqlalchemy`, `alembic`, `psycopg[binary]`,
      `cryptography`), dev extras (`pytest`, `pytest-cov`, `hypothesis`, `ruff`, `mypy`)
- [ ] `src/ale_gateway/__init__.py` with `__version__`
- [ ] Empty package directories with `__init__.py`: `app`, `api`, `core/crypto`, `core/keys`,
      `core/policy`, `core/audit`, `db`
- [ ] `pytest.ini` / `[tool.pytest.ini_options]`: markers `slow`, `integration`, `smoke`
- [ ] Ruff and mypy configuration; mypy strict on `src/`
- [ ] `.env.example` with names only

Commands:

```bash
python -m venv .venv ; .venv\Scripts\Activate.ps1 ; pip install -e ".[dev]"
```

```bash
pytest -q ; ruff check . ; mypy src
```

Docs: walkthrough gains a real repository map; README's toolchain table gains pinned versions.

Commit: `chore: package skeleton, tooling, and import-boundary test`

### 0.4 Containers and CI — `[ ]`

Tests first:

- [ ] `tests/integration/test_db_connection.py` — connects to the Compose Postgres, marked
      `integration`. Fails until Compose exists.

Implementation:

- [ ] `deploy/docker-compose.yml` — Postgres 16 with a named volume, healthcheck, non-default
      credentials from `.env`
- [ ] `deploy/Dockerfile` — multi-stage, non-root user, no build tools in the final image
- [ ] `.github/workflows/ci.yml` — matrix on Python 3.12, steps: install, `ruff check`,
      `ruff format --check`, `mypy`, `pytest` (with a Postgres service), upload coverage
- [ ] CI fails on any lint, type, or test error. No `continue-on-error`.

Commands:

```bash
docker compose -f deploy/docker-compose.yml up -d db ; docker compose -f deploy/docker-compose.yml ps
```

```bash
pytest -q -m integration
```

Docs: walkthrough documents the Compose file and the workflow line by line.

Commit: `chore(deploy): compose stack, container image, and CI pipeline`

**Milestone 0 exit criteria:** `pytest -q` runs green on a clean clone after documented setup; CI is
green on `main`; `docker compose up -d db` produces a healthy database.

---

## Milestone 1 — Cryptographic core

**Goal:** a correct, tested AEAD layer with gateway-owned nonces and a versioned envelope. No
database, no HTTP. Implements [AD-2](../README.md#ad-2--aes-256-gcm-as-the-field-aead-with-gateway-owned-nonces-and-mandatory-aad).

### 1.1 Envelope format — `[ ]`

Tests first:

- [ ] `tests/unit/test_envelope.py` — serialize/parse round-trip; unknown version raises
      `UnsupportedEnvelopeVersion`; truncated input raises `MalformedCiphertext`; a bit-flip anywhere
      in the header is detected
- [ ] `tests/property/test_envelope_property.py` — Hypothesis: parse(serialize(x)) == x for
      arbitrary valid components

Implementation:

- [ ] `core/crypto/envelope.py` — version byte, `key_id`, `kem`/algorithm id, nonce, ciphertext, tag;
      one serializer, one parser, both total functions returning typed errors
- [ ] Document the byte layout in the module docstring **and** in
      [ADR-0002](architecture/0002-envelope-key-management.md)

Commands:

```bash
pytest -q tests/unit/test_envelope.py tests/property/test_envelope_property.py
```

Commit: `feat(crypto): versioned self-describing ciphertext envelope`

### 1.2 AEAD wrapper — `[ ]`

Tests first:

- [ ] `tests/vectors/test_aes_gcm_vectors.py` — known-answer tests against published AES-GCM test
      vectors, committed as data files with their source recorded in the file header
- [ ] `tests/unit/test_aead.py` — encrypting the same plaintext twice yields different ciphertext;
      decrypt with wrong AAD fails; decrypt with wrong key fails; tag truncation fails
- [ ] `tests/property/test_nonce_uniqueness.py` — 100 000 encryptions produce 100 000 distinct nonces

Implementation:

- [ ] `core/crypto/aead.py` — `encrypt(dek, plaintext, aad) -> Envelope`, `decrypt(dek, envelope,
      aad) -> bytes`; nonce generated internally with `secrets`/`os.urandom`; **no nonce parameter
      exists in the signature**
- [ ] `core/crypto/aad.py` — canonical AAD construction from `(subject_id, table, column,
      record_id)`, with an unambiguous, length-prefixed encoding so that field values cannot be
      shifted between components
- [ ] Typed errors: `DecryptionFailed` carries no detail about *why*

Commands:

```bash
pytest -q tests/vectors tests/unit/test_aead.py tests/property
```

Docs: walkthrough gains `core/crypto/` in execution order; README AD-2 consequences updated if the
envelope size differs from what was assumed.

Commit: `feat(crypto): AES-256-GCM wrapper with gateway-owned nonce and canonical AAD`

### 1.3 Key wrapping and derivation — `[ ]`

Tests first:

- [ ] `tests/unit/test_wrap.py` — wrap/unwrap round-trip; unwrap with the wrong KEK fails; a wrapped
      DEK is not the DEK
- [ ] `tests/unit/test_kdf.py` — derivation is deterministic for the same inputs and diverges for
      any changed input

Implementation:

- [ ] `core/crypto/wrap.py` — AEAD-based DEK wrapping under the KEK, with the KEK version as AAD
- [ ] `core/crypto/kdf.py` — HKDF-SHA-256 for context separation
- [ ] `core/crypto/random.py` — the single CSPRNG entry point; nothing else calls `os.urandom`, and
      a boundary test enforces it

Commands:

```bash
pytest -q tests/unit ; mypy src
```

Commit: `feat(crypto): KEK wrapping and HKDF context derivation`

**Milestone 1 exit criteria:** all published vectors pass; property tests pass at scale; `core/crypto`
has no imports from `db`, `api`, or `core/keys`; coverage on `core/crypto` ≥ 95%.

---

## Milestone 2 — Key management and the encrypt/decrypt path

**Goal:** the first end-to-end write and read, with real keys in Postgres. Implements
[AD-3](../README.md#ad-3--envelope-encryption-with-per-data-subject-deks).

### 2.1 Schema and repositories — `[ ]`

Tests first:

- [ ] `tests/integration/test_key_repository.py` — create, fetch by `(subject_id, field_class)`,
      state transitions, uniqueness constraint on active keys per subject/class

Implementation:

- [ ] Alembic initial migration creating `keys` (see the data model in the README)
- [ ] `db/models.py`, `db/repositories/keys.py`
- [ ] Repository interface declared next to `core/keys/`, implemented in `db/` — core must not import
      SQLAlchemy

Commands:

```bash
alembic upgrade head ; pytest -q tests/integration/test_key_repository.py
```

Commit: `feat(db): keys table, migration, and repository`

### 2.2 Unseal and settings — `[ ]`

Tests first:

- [ ] `tests/unit/test_settings.py` — missing KEK aborts startup; malformed KEK aborts startup; there
      is no default KEK
- [ ] `tests/unit/test_unseal.py` — a sealed KEK unseals to the expected key; a wrong unseal input
      fails without revealing anything

Implementation:

- [ ] `app/settings.py` — typed settings, read once
- [ ] `app/unseal.py` — load and unseal the KEK into memory at startup; `gateway_sealed` state
- [ ] `cli/keygen.py` — generate a development KEK

Commands:

```bash
python -m ale_gateway.cli keygen --kek --out .env.local ; pytest -q tests/unit/test_settings.py
```

Commit: `feat(app): typed settings and fail-fast KEK unseal`

### 2.3 Key service — `[ ]`

Tests first:

- [ ] `tests/integration/test_key_service.py` — first encrypt for a subject creates one DEK; the
      second reuses it; a revoked key is never selected for encryption
- [ ] `tests/unit/test_dek_cache.py` — TTL expiry, bounded size, eviction on invalidate, and that the
      cache never returns a key for a non-active state

Implementation:

- [ ] `core/keys/service.py` — get-or-create DEK, unwrap, cache, invalidate
- [ ] `core/keys/cache.py` — in-process, bounded, TTL; never serialized

Commands:

```bash
pytest -q tests/integration/test_key_service.py tests/unit/test_dek_cache.py
```

Commit: `feat(keys): per-subject DEK lifecycle with TTL-bounded unwrap cache`

### 2.4 HTTP surface — `[ ]`

Tests first:

- [ ] `tests/e2e/test_encrypt_decrypt.py` — encrypt then decrypt returns the original plaintext;
      the response ciphertext is not the plaintext; decrypt with a mismatched context fails `400`
- [ ] `tests/unit/test_error_envelope.py` — every error path returns the documented envelope and no
      error body contains key or plaintext bytes

Implementation:

- [ ] `api/routes/encrypt.py`, `api/routes/decrypt.py` — thin handlers, ≤30 lines each
- [ ] `api/auth.py` — static bearer token for now, with the mutual-TLS gap recorded as a known
      limitation in the README
- [ ] `api/errors.py` — the single error envelope and status mapping
- [ ] `app/main.py` — application factory, lifespan wiring unseal and the database pool
- [ ] `GET /healthz`

Commands:

```bash
uvicorn ale_gateway.app.main:app --port 8000
```

```bash
curl http://localhost:8000/healthz ; pytest -q tests/e2e
```

Docs: walkthrough documents the request path end to end; README's API section confirmed against
reality.

Commit: `feat(api): authenticated encrypt and decrypt endpoints`

**Milestone 2 exit criteria:** a value written through `/v1/encrypt` is unreadable in the database
and recoverable through `/v1/decrypt`; the service refuses to start without a valid KEK.

---

## Milestone 3 — Policy-gated decryption

**Goal:** no decryption without an explicit allow. Implements
[AD-4](../README.md#ad-4--every-decrypt-is-a-policy-decision-and-the-default-is-deny).

Tests first:

- [ ] `tests/unit/test_policy_eval.py` — a decision table covering: allow by role; deny by role; deny
      overrides allow; condition mismatch on purpose, environment, classification, time window;
      unknown role; empty policy set (deny)
- [ ] `tests/unit/test_policy_schema.py` — an invalid policy document is rejected at load, not at
      first request
- [ ] `tests/integration/test_unregistered_field.py` — encrypting or decrypting a field absent from
      the schema policy returns `422` and is audited
- [ ] `tests/integration/test_policy_unavailable.py` — a policy load failure denies every decrypt
      rather than allowing any

Implementation:

- [ ] `core/policy/model.py` — policy document types
- [ ] `core/policy/evaluator.py` — pure function `(request_context, policy_set) -> Decision(allow,
      rule_id, reason)`; no I/O
- [ ] `core/policy/schema.py` — field registry mapping `(table, column) -> field_class`
- [ ] `db/repositories/policies.py`, migration for the `policies` table
- [ ] Wire the evaluator into the decrypt path *and* the encrypt path (registration check)

Commands:

```bash
pytest -q tests/unit/test_policy_eval.py tests/integration/test_unregistered_field.py
```

Docs: [ADR-0003](architecture/0003-policy-gated-decryption.md) updated with the final policy document
shape; walkthrough documents the evaluator.

Commit: `feat(policy): deny-by-default evaluator gating every decrypt`

**Milestone 3 exit criteria:** every branch of the decision table has a test; no code path reaches
`core/crypto.decrypt` without a `Decision(allow=True)`.

---

## Milestone 4 — Tamper-evident audit log

**Goal:** history that cannot be quietly rewritten. Implements
[AD-5](../README.md#ad-5--append-only-hash-chained-audit-log-with-signed-checkpoints).

Tests first:

- [ ] `tests/integration/test_audit_chain.py` — appending N entries produces a verifiable chain;
      mutating any single row is detected and the reported break index is correct; deleting a row is
      detected; re-ordering is detected
- [ ] `tests/integration/test_audit_coverage.py` — encrypt, decrypt, denial, key creation, rotation,
      and shred each produce exactly one entry with the documented fields
- [ ] `tests/integration/test_checkpoints.py` — a checkpoint signature verifies; a checkpoint over a
      tampered range fails verification
- [ ] `tests/integration/test_audit_failure_policy.py` — an audit write failure does not silently
      succeed; the documented failure behaviour per operation is exercised

Implementation:

- [ ] Migrations for `audit_log` and `checkpoints`
- [ ] `core/audit/chain.py` — `entry_hash = H(prev_hash || canonical(entry))`, with a canonical
      serialization that is version-stable
- [ ] `core/audit/checkpoint.py` — Merkle root over a sequence range, ECDSA P-256 signature
- [ ] `core/audit/verify.py` — full and ranged verification, reporting the first break
- [ ] `api/routes/audit.py` — `GET /v1/audit/verify`
- [ ] Append is transactional with the operation it records where the operation is destructive

Commands:

```bash
pytest -q tests/integration/test_audit_chain.py tests/integration/test_checkpoints.py
```

```bash
curl -H "Authorization: Bearer $env:GATEWAY_TOKEN" http://localhost:8000/v1/audit/verify
```

Docs: [ADR-0004](architecture/0004-tamper-evident-audit-log.md) records the canonical serialization
and the per-operation failure policy.

Commit: `feat(audit): hash-chained log with signed checkpoints and verification endpoint`

**Milestone 4 exit criteria:** a manual `UPDATE` against any audit row makes `audit/verify` fail with
the correct sequence number.

---

## Milestone 5 — SDK and demo integration

**Goal:** the demo runs from one command and the database visibly holds ciphertext. Implements
[AD-6](../README.md#ad-6--integration-is-a-python-sdk-not-a-proxy).

Tests first:

- [ ] `tests/unit/test_sdk_client.py` — timeout, retry policy, and that a gateway failure surfaces as
      a typed SDK error rather than a silent plaintext write
- [ ] `tests/e2e/test_demo_flow.py` — write a record through the demo application, assert with a raw
      SQL query that the protected columns do not contain the plaintext
- [ ] `tests/boundary/test_sdk_has_no_server_imports.py` — the SDK does not import the server package

Implementation:

- [ ] `sdk/python/ale_gateway_sdk/` — `encrypt_field`, `decrypt_field`, typed errors, configurable
      timeout, no retry on decrypt denials
- [ ] Demo backend integration in its own repository: register fields, call the SDK in the data layer
- [ ] `deploy/docker-compose.yml` extended: gateway + database + demo application
- [ ] A demo seed script producing synthetic data only

Commands:

```bash
docker compose -f deploy/docker-compose.yml up --build
```

```bash
docker compose -f deploy/docker-compose.yml exec db psql -U gateway -d gateway -c "select * from keys limit 5;"
```

Docs: walkthrough gains the SDK call path; README quickstart verified against a clean machine.

Commit: `feat(sdk): python client and one-command demo stack`

**Milestone 5 exit criteria:** `docker compose up --build` on a clean clone produces a running demo
where a `SELECT` on the protected table returns ciphertext. **This is the public `v0.1` release
point.**

---

## Milestone 6 — Crypto-shredding

**Goal:** the project's highest-value differentiator. Destroy a subject's key material; their data
becomes unrecoverable; the erasure is provable.

Tests first:

- [ ] `tests/integration/test_shred.py` — after shredding, decrypt returns `410`; the key row's
      material is gone, not merely flagged; a cached DEK does not survive the shred **and** the
      test asserts this within the cache TTL window
- [ ] `tests/integration/test_shred_audit.py` — the shred is audited, the audit chain still verifies
      after the shred, and prior audit entries for the subject remain (history is not erased, only
      the ability to read the data)
- [ ] `tests/integration/test_erasure_certificate.py` — the certificate signature verifies and names
      the destroyed `key_id`s and the timestamp
- [ ] `tests/integration/test_shred_is_idempotent.py` — shredding twice is safe and audited twice

Implementation:

- [ ] `core/keys/shred.py` — evict cache, emit certificate, overwrite/delete `wrapped_dek`, set state
      `shredded`, append audit entry, in an order that is safe if the process dies at any step
- [ ] `POST /v1/subjects/{subject_id}/shred` — admin-only, requires an explicit confirmation
      parameter
- [ ] `erasure_certificates` table and migration
- [ ] `cli/shred.py` for operator use

Commands:

```bash
pytest -q tests/integration/test_shred.py tests/integration/test_erasure_certificate.py
```

Docs: [ADR-0002](architecture/0002-envelope-key-management.md) gains the shred ordering and its
crash-safety argument; playbook's rollback section already states that shredding is irreversible.

Commit: `feat(keys): per-subject crypto-shredding with signed erasure certificates`

**Milestone 6 exit criteria:** a shredded subject's previously written ciphertext cannot be decrypted
by any path, including a direct database read plus a valid KEK.

---

## Milestone 7 — Rotation, revocation, and hardening

Tests first:

- [ ] `tests/integration/test_kek_rotation.py` — ciphertext written under KEK v1 still decrypts after
      rotation to v2; new writes use v2; the re-wrap is resumable after an interruption
- [ ] `tests/integration/test_revocation.py` — a revoked key denies decrypt with a distinct code from
      shredded
- [ ] `tests/fuzz/test_decrypt_fuzz.py` — malformed, truncated, and bit-flipped envelopes never crash
      the process and never return plaintext
- [ ] `tests/integration/test_rate_limit.py` — limits are enforced per client and audited

Implementation:

- [ ] `core/keys/rotation.py` — new KEK version, lazy re-wrap on access plus a background sweep
- [ ] `POST /v1/keys/rotate`, admin-only
- [ ] `api/ratelimit.py`
- [ ] Dependency pinning with hashes; SBOM generation in CI

Commands:

```bash
pytest -q -m "not slow" ; pytest -q tests/fuzz
```

Commit: `feat(keys): KEK rotation with lazy re-wrap; harden decrypt against malformed input`

---

## Milestone 8 — Benchmarks

Tests first:

- [ ] `tests/unit/test_bench_harness.py` — the harness reports percentiles correctly for a known
      distribution (a benchmark that lies is worse than no benchmark)

Implementation:

- [ ] `bench/run.py` — payload sweep 1 KB / 10 KB / 1 MB / 10 MB, ≥100 000 operations, warm-up
      discarded, p50/p95/p99 plus throughput
- [ ] Baseline demo application vs. demo application + gateway, end to end
- [ ] Micro-benchmarks: AEAD alone, unwrap alone, policy evaluation alone, database round-trip alone
      — so the bottleneck is attributable
- [ ] Storage overhead measurement: ciphertext bytes vs. plaintext bytes per field
- [ ] `bench/README.md` recording hardware, OS, Python version, Postgres version, and method
- [ ] Graphs committed as SVG/PNG with the generating script

Commands:

```bash
python -m bench.run --payloads 1KB,10KB,1MB,10MB --iterations 100000 --out bench/results
```

Docs: README gains a results table with a link to the method. The phrase "minimal overhead" does not
appear.

Commit: `feat(bench): payload sweep with published percentile method`

---

## Milestone 9 — Educational module — `[-]` deferred

Quarantined per [AD-7](../README.md#ad-7--the-educational-module-is-quarantined-from-the-production-path)
and [ADR-0006](architecture/0006-educational-module-quarantine.md). Scope comes from the two lab
source materials that are not currently in this repository.

Tests first:

- [ ] `tests/boundary/test_educational_quarantine.py` — nothing in `src/` imports `educational/`,
      nothing in `educational/` imports `src/`, and `educational/` is excluded from the built package
- [ ] Per-lab tests that demonstrate the weakness, not only the algorithm

Implementation:

- [ ] `educational/lab1_symmetric_basics/` — substitution and transposition ciphers with brute-force
      and known-plaintext breaks (Lab 1: Basic Symmetric Key Ciphers)
- [ ] `educational/lab2_symmetric_advanced/` — DES/3DES/AES, block modes including an ECB
      pattern-leakage artifact (Lab 2: Advanced Symmetric Encryption)
- [ ] `educational/lab3_asymmetric/` — RSA, ElGamal, Diffie–Hellman, with performance comparison
      (Lab 3: Asymmetric Key Ciphers)
- [ ] `educational/lab4_asymmetric_advanced/` — Rabin, ECC/ECDH/ECDSA, weak-prime factorization
      exercise (Lab 4: Advanced Asymmetric Key Cryptography)
- [ ] `educational/lab5_hashing/` — the manual's custom hash (initial value 5381, multiply by 33, add
      the character's ASCII value, bit mixing, 32-bit mask); a socket client/server integrity
      demonstration; MD5 vs SHA-1 vs SHA-256 timing and collision analysis over a generated dataset
      of 50–100 random strings (Lab 5: Hashing)
- [ ] `educational/lab6_signatures/` — digital signature creation and verification, including the
      manual's RSA key-pair exercise (Lab 6: Digital Signature)
- [ ] Every module header states: lab reference, that it is intentionally insecure or obsolete, and
      that it must not be used in production

Commands:

```bash
pytest -q tests/boundary/test_educational_quarantine.py educational
```

Docs: walkthrough gains an `educational/` section marked clearly as non-production.

Commit: `feat(edu): quarantined lab implementations with cryptanalysis demonstrations`

**Note:** course rules in the manuals govern how this code is produced (individual work, no LLM
assistance, no plagiarism). Those rules apply to `educational/` regardless of how the product code is
built. See the playbook's [educational module section](../ENGINEERING_PLAYBOOK.md#working-on-the-educational-module).

---

## Milestone 10 — Release

- [ ] Threat-model ADR finalized: assets, adversaries, trust boundaries,
      attack surfaces, assumptions, and an explicit out-of-scope list
- [ ] `SECURITY.md` — reporting process and response expectations
- [ ] `CONTRIBUTING.md` — pointing at the playbook rather than repeating it
- [ ] `CHANGELOG.md` complete from `v0.1`
- [ ] Demo recording following the script below
- [ ] README quickstart re-verified on a clean machine by someone who has not run it before
- [ ] `v1.0` tag

---

## Release verification

Run every item on a **clean clone**, in order, before tagging any release. A failure here blocks the
tag; it is not a follow-up ticket.

**Build and start**

- [ ] `git clone` into an empty directory, follow the README setup verbatim, no undocumented step
      required
- [ ] `pytest -q` green; `pytest -q tests/fuzz` green; `ruff check .` and `mypy src sdk` clean
- [ ] `docker compose -f deploy/docker-compose.yml up --build` reaches a healthy state
- [ ] `curl http://localhost:8000/healthz` returns 200

**Security behaviour** — each of these is the demo script *and* the release gate:

- [ ] Write a record through the demo application; `SELECT` the row; the protected columns are
      ciphertext
- [ ] An authorized role decrypts successfully
- [ ] An unauthorized role is denied with `403 policy_denied`, and the denial appears in the audit log
- [ ] A field not in the schema policy returns `422` at both encrypt and decrypt
- [ ] Flip one byte of a stored ciphertext; decrypt fails; the failure is audited
- [ ] Move a ciphertext to another row or column; decrypt fails on AAD mismatch
- [ ] Crypto-shred a subject; decrypt returns `410`; an erasure certificate verifies; the audit chain
      still verifies
- [ ] `UPDATE` one audit row; `GET /v1/audit/verify` reports the break at the correct sequence
- [ ] Restart the service without the KEK; it refuses to start
- [ ] Restart with the KEK; previously written data still decrypts

**Operational**

- [ ] Rotate the KEK; old ciphertext still decrypts; new writes use the new version
- [ ] Restore a database backup into a scratch instance; `audit/verify` passes; a known record
      decrypts
- [ ] Benchmarks re-run; published numbers updated if the data path changed
- [ ] Every command in the README executed as written
- [ ] [docs/codebase-walkthrough.md](codebase-walkthrough.md) reviewed against `git diff` since the
      last release — no file missing, no removed file still documented

---

## Future phases (post-v1.0)

Deliberately deferred. Each entry states the trigger that would justify starting it — none of these
begin without one.

| Phase | Work | Trigger |
|---|---|---|
| P1 | Pluggable KMS backend for the KEK (OpenBao/Vault Transit, cloud KMS) | A user needs the KEK outside the process boundary, or a production deployment is attempted |
| P2 | Mutual TLS between application and gateway | Any deployment outside a trusted network |
| P3 | Sidecar and proxy deployment modes | A non-Python adopter appears; not before |
| P4 | Non-Python SDKs (Go, TypeScript) | Same trigger as P3 |
| P5 | Blind-index searchable encryption | An adopter blocked by loss of equality search |
| P6 | Tokenization / format-preserving encryption | A payment-card use case with a concrete format constraint |
| P7 | AES-GCM-SIV envelope version | Evidence of a deployment where the gateway cannot own nonce generation |
| P8 | OpenTelemetry tracing | The benchmark bottleneck stops being attributable from metrics alone |
| P9 | Merkle transparency log with external anchoring | An auditor requires third-party verifiability |
| P10 | Multi-tenant key isolation | A second organization uses one deployment |

Adding an item here is free. Starting one requires an ADR that names the constraint it satisfies —
see the playbook's [decision-making guidelines](../ENGINEERING_PLAYBOOK.md#decision-making-guidelines).
