# Comprehensive release continuation implementation plan

> **For agentic workers:** Use the subagent-driven-development workflow. The user explicitly authorizes autonomous parallel implementation, verification, commits and non-forced Git pushes.

**Goal:** Resume audited checkpoint `5d6ff65`, preserve all 34 objectives and seven qualification gates, and remove substantive product and qualification blockers.

**Architecture:** Preserve the manifest/compiler, authenticated CF1, guarded SQLAlchemy adapter and common lifecycle engine. Extend these existing boundaries rather than adding a second encryption or database control plane. Independently implement provider correctness, typed storage, application integration and reproducible qualification inputs.

**Tech stack:** Python 3.12+, SQLAlchemy 2.x, psycopg 3, PostgreSQL 16, library AES-256-GCM-SIV/HKDF/HMAC; optional SQLModel.

**Spec:** Canonical architecture, security, lifecycle, compatibility, decisions and all 34 entries in `docs/BUILD_CHECKLIST.md`; user continuation instruction.

## Global constraints

- No plaintext protected writes, unauthenticated output, implicit authority selection or silent fallback.
- Preserve authenticated tenant/record/field/type/generation binding and existing formats/readers.
- No production gate passes without its exact evidence; AI review is not independent human qualification.
- All database tests use `scripts/test_postgres.py`, fresh private role probes and the authorized disposable PostgreSQL 16 target or isolated qualification clusters.
- Preserve prior receipts and failed outcomes; verify source stability before recording a result.
- Root integrates authoritative documentation and commits each verified slice. Specialists own distinct source files or explicitly separated hunks.

## Review focus

- Provider transfer must prove the target recovers the original root, including malformed return and identity changes.
- Native database functions can write indirectly; typed SELECT admission must not authorize an opaque writer or search-path substitution.
- Tenant scope follows original authenticated account authority and preauthorized public owner metadata; global admin and account deletion retain explicit transactional treatment.
- DATE must retain native values/NULL/default state and refuse nonrepresentable source values before effects; historical readers must reject new artifacts.
- A resolved dependency set does not establish an advisory-free environment, reproducible build inputs or production qualification.

## Task 1: Direct provider rewrap recovery proof

Owner: provider specialist. Files: `src/cryptalis/crypto/aws_kms.py`, `tests/test_aws_kms.py`.

- [x] Reproduce a target wrapper with valid metadata but wrong recovered root through the direct API.
- [x] Verify exact target material and stable identity before returning success, with safe typed failures.
- [x] Run focused provider/rewrap controls through the PostgreSQL wrapper; review, document and commit.

Extend the same direct proof to the development provider so the protocol remains
consistent. Fourteen RED failures, then 107 isolated GREEN controls with stable
source; scoped agent compliance/quality review accepts. Receipt:
`docs/_reset/direct-rewrap-20261027.json`. One target unwrap is the explicit cost.
Live KMS and independent human review remain UNKNOWN.

## Task 2: Database-function writer admission

Owner: security specialist. Files: new function-admission helper and regression tests; minimal FunctionElement hunk in `src/cryptalis/sqlalchemy.py`.

- [ ] Reproduce an attached typed SELECT calling a restricted-runtime invoker function that writes plaintext.
- [ ] Refuse opaque function effects before keys/driver while preserving explicitly admitted pure native functions and search-path safety.
- [ ] Run targeted native and original-application query controls; review, document and commit.

## Task 3: Exact storage-only DATE profile

Owner: type specialist. Files: compiler, CF1, Date-specific adapter/framing/lifecycle/restore hunks, dedicated Date controls, fresh-cluster harness.

- [ ] Establish native Date/NULL/client-default and invalid source-domain oracles.
- [ ] Encode exact Python date as signed four-byte days from 2000-01-01, with the codec bound by existing context/v2.
- [ ] Emit strict lock/v8 only for Date, preserving v1-v7. Refuse date search, custom conversions, online capture and unsupported source dates.
- [ ] Verify both layouts, root/payload rotation, fresh restore/adoption, current-data reverse and package-free native exit.
- [ ] Review, document bounded evidence and unresolved type admission/cost/application gates, and commit.

## Task 4: Reproducible HTTP qualification environment

Owner: release specialist. Files: separate `qualification/http` dependency project/lock and setup script if required. Root product pins remain unchanged.

- [ ] Resolve a compatible refreshed application dependency cell; preserve the original 26 application files and verify pinned hashes.
- [ ] Freeze transitive hashes and reproduce installation in an isolated environment.
- [ ] Record exact interpreter/package/advisory evidence and limitations.
- [ ] Run unchanged HTTP and fresh lifecycle qualification in the new cell; review, document and commit.

## Task 5: Authenticated tenant HTTP application

Owner: application specialist. Files: new tenant host, workload and application profile modules.

- [ ] Authenticate through original JWT/account dependency before selecting tenant keys or protected sessions.
- [ ] Preauthorize public Item owner metadata and recheck it at protected access.
- [ ] Preserve ordinary user, superuser pagination and account-delete/cascade outcomes through explicit host integration; measure all host changes.
- [ ] Exercise the full install/protect/CRUD/rotate/recover/current-data removal journey and cross-tenant/invalid-authority refusals.
- [ ] Review, document exact original/host boundaries and commit.

## Continuation ledger

## Task 6: Frozen isolated build backend

Owner: root. Files: root build-system requirement, `qualification/build-backend/requirements.in` and hash lock, `scripts/release_check.py`.

- [x] Pin the existing uv build backend and generate standard uv hash constraints.
- [x] Require isolated PEP 517 builds with backend hash verification in the release check.
- [x] Include exact tool/interpreter and constraint identity in release evidence.
- [x] Verify artifact-integrity controls and two byte-identical builds; document and commit.

Review resolved both findings: ambient isolation could bypass backend hashes;
the initial directory name was ignored by Git. Explicit isolation/configuration
flags, three real wrong-hash controls and the visible `build-backend` directory
address these. Final isolated verification: 15 artifact checks, byte-identical
wheel/sdist, source/RECORD/SBOM inspection. Evidence:
`docs/_reset/build-backend-20261027.json`. Scoped re-review accepts compliance and
quality; independent human release review remains required.

### Initial observations

- Read audited pause, canonical contracts, approved decisions, objective/gate ledgers and dated competitor evidence. No completed research repeated.
- Remote `main` and local HEAD both resolve to `5d6ff655a0f2a8b54a4aec76890f74d2b55d57ba`.
- Cloud baseline receipts predate this turn. Fresh readiness probes found the same development PostgreSQL cluster stopped; inspect and start it before tests.
- No live external provider credentials or outbound cloud identities are configured. G-PROVIDER and independent human review remain external prerequisites.
- User explicitly reaffirms continuation; no design or implementation permission request is pending.
