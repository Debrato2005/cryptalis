# Engineering Playbook

How work gets done in this repository. [README.md](README.md) owns *what* is being built and *why*;
this file owns *how*. Where the two disagree, the README's architecture decisions win.

**Context that shapes every convention here:** this is a solo, time-boxed project (14–16 weeks) that
is also intended to be a public open-source repository and a hiring artifact. The conventions are
therefore stricter than a solo project needs and lighter than a team of ten needs. Where a
convention exists mainly for the public-repo audience, it says so.

---

## Contents

- [Daily development workflow](#daily-development-workflow)
- [Branches](#branches)
- [Commits](#commits)
- [Pull requests and review](#pull-requests-and-review)
- [Testing conventions](#testing-conventions)
- [Releases](#releases)
- [Environments and secrets](#environments-and-secrets)
- [Migrations and rollback](#migrations-and-rollback)
- [Observability and operational checks](#observability-and-operational-checks)
- [Production readiness](#production-readiness)
- [Decision-making guidelines](#decision-making-guidelines)
- [Working on the educational module](#working-on-the-educational-module)

---

## Daily development workflow

The loop, in order. It is short on purpose.

1. **Open [docs/backend-build-checklist.md](docs/backend-build-checklist.md)** and pick the next
   unchecked item in the current milestone. Do not skip ahead — milestones are ordered so that each
   one is verifiable without the next.
2. **Branch** from `main` (see [Branches](#branches)).
3. **Write the test first.** Every checklist item names its tests before its implementation tasks.
   The test must fail for the right reason before any implementation exists.
4. **Implement the smallest change that makes it pass.**
5. **Run the local gate:**

   ```bash
   pytest -q
   ```

   ```bash
   ruff check . ; ruff format --check . ; mypy src sdk
   ```

6. **Update documentation in the same change** — the walkthrough always; the README when a decision
   or command changed; the checklist to tick the item.
7. **Commit** with a message that explains why (see [Commits](#commits)).
8. **Open a PR**, let CI run, self-review against the checklist, merge.
9. **Tick the checklist item** only after it is merged and green.

**Start-of-session sanity check** (30 seconds, catches most environment rot):

```bash
docker compose -f deploy/docker-compose.yml ps ; pytest -q -x -m smoke
```

**When blocked for more than ~30 minutes:** write down what you expected, what happened, and what
you have ruled out — in the PR description or the walkthrough. Half of these become ADR material.

## Branches

- `main` is always releasable and always green. No direct pushes once CI exists.
- Branch names: `<type>/<short-kebab-summary>` — `feat/dek-cache-ttl`, `fix/aad-column-rename`,
  `docs/adr-audit-checkpoints`, `chore/pin-deps`, `bench/payload-sweep`, `edu/lab-5-hashing`.
- One milestone item per branch. If a branch grows a second concern, split it.
- Rebase onto `main` before merge; keep history linear. Squash-merge when the branch has noisy
  work-in-progress commits, merge as-is when the commits are individually meaningful.
- Delete the branch after merge.

## Commits

Conventional-commit prefixes, imperative subject, ≤72 characters:

```
feat(keys): wrap DEKs with versioned KEK on creation
fix(crypto): reject ciphertext whose envelope version is unknown
test(policy): cover deny-overrides across role and purpose
docs(adr): record ECDSA choice for audit checkpoints
chore(ci): pin dependencies with hashes
```

Scopes match module directories: `crypto`, `keys`, `policy`, `audit`, `api`, `db`, `sdk`, `cli`,
`bench`, `edu`, `deploy`, `docs`.

**The body answers "why", not "what".** The diff already shows what changed. A commit that changes
security behaviour states the threat it addresses and the test that proves it:

```
fix(keys): invalidate cached DEK synchronously on shred

A shredded subject's DEK could still be served from the in-process cache
until TTL expiry, so a decrypt issued within 60s of a shred returned
plaintext for data that was supposed to be unrecoverable.

Shred now evicts before it deletes key material.

Covered by tests/integration/test_shred.py::test_decrypt_after_shred_is_410_immediately
```

**Never commit:** `.env`, key material, real personal data, `bench/results` raw dumps larger than a
few hundred KB, or anything under `.venv/`. A `.gitignore` covering these is a Milestone 0 item.

**Commit hygiene for a public repository:** history is part of the artifact. A reviewer reading the
log should be able to follow the project's reasoning. Avoid `wip`, `fix stuff`, `asdf`.

## Pull requests and review

Every change goes through a PR, including solo work. The PR is where the reasoning is recorded and
where CI proves the claim.

**PR description template:**

```
## What
One paragraph.

## Why
The problem, and why this approach over the alternative considered.

## Security impact
What an attacker could do before and after. "None" is a valid answer, stated deliberately.

## Verification
Commands run and their result. Test names that now cover this.

## Docs
Which documents changed and why. If none: why none was needed.
```

**Self-review checklist** — read the diff as a hostile reviewer before merging:

- [ ] Does any handler in `api/` contain logic that belongs in `core/`?
- [ ] Does anything outside `db/` contain SQL or ORM models?
- [ ] Does `core/policy/` do any I/O?
- [ ] Could plaintext or key material reach a log, error message, metric label, or trace?
- [ ] Is there a negative test, not just a happy-path test?
- [ ] Does any new failure mode fail *open*?
- [ ] Does a documented decision in the README now contradict the code?
- [ ] Is [docs/codebase-walkthrough.md](docs/codebase-walkthrough.md) updated for every file added,
      removed, or meaningfully changed?

**A PR touching cryptography, key lifecycle, policy evaluation, or the audit chain does not merge
without:** a test that fails on the old behaviour, and an ADR entry if the change revises a
documented decision.

**Merge gate:** CI green, self-review complete, docs updated. A red `main` is fixed or reverted
before any new work starts.

## Testing conventions

Layout under `tests/`, mirroring `src/`:

| Directory | Purpose | Speed |
|---|---|---|
| `tests/unit/` | Pure functions, no I/O. Crypto wrappers, policy evaluator, envelope parsing. | Milliseconds |
| `tests/vectors/` | Known-answer tests against published test vectors. Non-negotiable for AEAD. | Fast |
| `tests/property/` | Hypothesis: round-trips, ciphertext ≠ plaintext, nonce non-repetition, envelope parse/serialize symmetry. | Seconds |
| `tests/integration/` | Real Postgres via Compose. Key lifecycle, rotation, shred, audit chain. | Seconds |
| `tests/e2e/` | Full stack through the SDK and the demo backend. | Slower |
| `tests/fuzz/` | Malformed, truncated, bit-flipped ciphertext. Must fail closed, never crash. | Marked `slow` |
| `tests/boundary/` | Architectural constraints: import rules, `educational/` quarantine, no-secrets-in-errors. | Fast |

Markers: `@pytest.mark.slow`, `@pytest.mark.integration`, `@pytest.mark.smoke`. The pre-commit gate
runs everything except `slow`; CI runs everything.

**Rules**

- Tests are written before implementation, per checklist item.
- A security guarantee without a test that breaks when the guarantee breaks does not count as
  implemented, and is not ticked in the checklist.
- Negative tests are mandatory for every authorization and key-state path: denied, revoked,
  shredded, unregistered, unauthenticated, tampered.
- Never assert on a stack trace or an error string; assert on the stable error `code`.
- No `time.sleep` in tests; inject a clock.
- Randomness is seeded and injectable, except in the CSPRNG path, which is tested for
  non-repetition rather than for values.

## Releases

Semantic versioning. `v0.x` until the MVP demo runs end to end (Milestone 5), `v1.0` at Milestone 10.

Release procedure:

1. `main` green, checklist milestone fully ticked.
2. Update `CHANGELOG.md` — added / changed / fixed / security, with user-visible language.
3. Confirm every documented command in the README still works on a clean checkout.
4. Tag:

   ```bash
   git tag -a v0.3.0 -m "Policy engine and fail-closed decrypt"
   ```

   ```bash
   git push origin v0.3.0
   ```

5. Build and smoke-test the image:

   ```bash
   docker compose -f deploy/docker-compose.yml up --build -d ; curl http://localhost:8000/healthz
   ```

6. Record benchmark numbers for the release if the data path changed.

**Security-relevant releases** additionally state, in the changelog: what was vulnerable, who is
affected, whether re-encryption or key rotation is required, and the upgrade order.

## Environments and secrets

Three environments, differing only in configuration:

| Environment | Database | KEK source | Auth | Purpose |
|---|---|---|---|---|
| `local` | Compose Postgres | Dev KEK from `.env.local`, generated by CLI | Static bearer token | Development, tests |
| `demo` | Compose Postgres | Sealed KEK, injected at start | Bearer token | Recorded demo, benchmarks |
| `prod` (reference) | Managed Postgres | Sealed KEK from the platform's secret store; KMS deferred | Bearer token today, mutual TLS is the documented target | Reference deployment for anyone adopting the project |

**Rules**

- `.env` is never committed. `.env.example` is committed and contains names and shapes only —
  `GATEWAY_KEK_SEALED=<base64, 32 bytes sealed>`, never a real value.
- Configuration is read once, at startup, into a typed settings object. No `os.environ` reads
  scattered through modules.
- The service **fails to start** if a required secret is missing or malformed. It does not fall back
  to a default key. There is a test for this.
- The KEK is loaded at boot into memory and never written anywhere. A restart re-unseals.
- Rotating a leaked bearer token is a config change plus a restart; rotating a leaked KEK is a
  re-wrap of every DEK — the procedure lives in
  [ADR-0002](docs/architecture/0002-envelope-key-management.md) and must be rehearsed before any
  claim that the project supports rotation.
- Development KEKs are generated locally and are never reused across environments. If a dev KEK ever
  touches a non-dev database, treat it as compromised and rotate.
- Nothing generated into `bench/results` or logs may contain plaintext samples of real data. Demo
  data is synthetic.

## Migrations and rollback

Alembic, forward-only in intent, reversible where physically possible.

**Expectations for every migration**

- One migration per PR. A migration that needs a paragraph of explanation needs a docstring in the
  migration file itself.
- Reviewed for lock behaviour: no blocking rewrite of a large table without a stated plan.
- Additive first. Adding a column, backfilling, then switching reads is three deployable steps, not
  one.
- A migration that touches the `keys`, `audit_log`, or `checkpoints` tables requires an explicit note
  on what happens to existing ciphertext and existing chain entries. The audit chain must remain
  verifiable across the migration — there is a test for this.

**Encrypting an existing plaintext column** (the migration that actually matters here):

1. Add the ciphertext column and `key_id` column, nullable.
2. Deploy code that **writes both** and reads plaintext.
3. Backfill in batches through the SDK, recording progress; the backfill is resumable.
4. Deploy code that reads ciphertext, falls back to plaintext when `key_id IS NULL`.
5. Verify zero rows remain with `key_id IS NULL`.
6. Drop the plaintext column in a separate, later migration.

Steps 1–5 are individually reversible. Step 6 is not — it is the point of no return and is done only
after a verified backup exists.

**Rollback**

- Application rollback: redeploy the previous image tag. Safe as long as the schema is backward
  compatible, which the additive-first rule guarantees for one version.
- Migration rollback: `alembic downgrade -1` is acceptable only for migrations that are genuinely
  reversible and have not yet had data written under them. Otherwise the fix is a forward migration.
- **Crypto-shredding is never rollbackable.** Destroyed key material is destroyed. The shred endpoint
  requires an explicit confirmation parameter, is admin-only, and emits an erasure certificate before
  the destructive step.
- **Rollback across an envelope-version change is not supported** unless the older code can read the
  newer envelope version. Ship the reader before the writer, always: readers first, writers second.

## Observability and operational checks

**Logging**

- Structured JSON, one event per line, with `request_id`, `actor`, `action`, `decision`, `duration_ms`.
- Never log: plaintext, ciphertext bodies, DEKs, the KEK, bearer tokens, `subject_id` in a form that
  is itself sensitive. Log `key_id` and hashed subject references instead.
- Log level `INFO` for decisions, `WARNING` for denials, `ERROR` for failures that are not the
  caller's fault. A denial is not an error — it is the system working.

**Metrics** (Prometheus, `GET /metrics`)

- `encrypt_requests_total`, `decrypt_requests_total`, both by outcome.
- `policy_denials_total` by rule id — a sudden change here is the highest-signal alert in the system.
- `dek_cache_hits_total` / `misses_total` — the primary latency lever.
- `audit_append_failures_total` — must be zero.
- `key_unwrap_duration_seconds`, `encrypt_duration_seconds`, `decrypt_duration_seconds` as histograms.
- `gateway_sealed` gauge — 1 means the service is up but cannot serve.

**Health**

- `GET /healthz` — process liveness only, no dependencies, no auth. Never returns version or config.
- Readiness is implied by `503` responses when sealed or when the database is unreachable.

**Operational checks**

| Check | Frequency | Command |
|---|---|---|
| Audit chain integrity | Daily, and after any incident | `curl -H "Authorization: Bearer $env:GATEWAY_TOKEN" http://localhost:8000/v1/audit/verify` |
| Key state census | Weekly | `python -m ale_gateway.cli keys stats` |
| Sealed state | Continuous, via metric | `gateway_sealed == 0` |
| Backup restore rehearsal | Before any release claiming production readiness | Restore to a scratch database, run `audit/verify`, decrypt a known record |

**Alert on:** any `audit_append_failures_total > 0`, a denial-rate change of more than 3× the
7-day baseline, `gateway_sealed == 1` for more than 60 seconds, decrypt p99 above the published
budget for 5 minutes.

## Production readiness

The project must not claim production readiness before all of these are true and verifiable. This
list is also the honest answer to "would you run this?" in an interview.

- [ ] Transport is mutually authenticated, or the limitation is stated prominently in the README.
- [ ] KEK is sealed and sourced from a secret store, not a plain environment file.
- [ ] KEK rotation has been rehearsed end to end against a populated database.
- [ ] Backup and restore rehearsed, including verifying the audit chain after restore.
- [ ] Every documented security guarantee has a failing-when-broken test.
- [ ] Fuzzing has run against the decrypt path and the envelope parser without a crash.
- [ ] Dependencies pinned with hashes; an SBOM is generated in CI.
- [ ] Benchmarks published with method, hardware, and p50/p95/p99 — not adjectives.
- [ ] A written incident procedure exists for: leaked token, leaked DEK, leaked KEK, tampered audit
      log, accidental shred.
- [ ] The threat model's out-of-scope list is in the README, not buried.
- [ ] Rate limiting is enforced and tested.
- [ ] The service starts read-only-sealed and requires an explicit unseal, or documents why not.

Until every box is ticked, the README and the public description say "not yet production ready" in
those words.

## Decision-making guidelines

1. **Prefer the simplest solution that satisfies a constraint you can name today.** "We might need
   multi-region key replication" is not a constraint. "The demo must survive a laptop restart" is.
2. **Defer scale work until a measurement demands it.** The DEK cache exists because unwrapping on
   every read is measurably slow, and the benchmark shows it. Nothing else gets a cache without the
   same evidence.
3. **When two designs are close, choose the one that fails more loudly.** A misconfiguration that
   causes a `503` beats one that causes a silent plaintext write.
4. **Buy the vetted thing.** Any temptation to hand-roll a primitive, a chain construction, or a
   parser is answered with: use the library, and write the test that proves you used it correctly.
5. **Write the ADR when the decision is hard to reverse.** Reversible decisions go in a commit
   message. Irreversible ones — envelope format, key scoping, chain construction, the encryption
   boundary — go in [docs/architecture/](docs/architecture/) before the code.
6. **Scope creep is answered with the roadmap, not with a "yes".** Features that would be good live
   in the deferred list with a one-line reason. The deferred list is a feature of the project.
7. **When the plan and reality disagree, reality wins and the plan gets edited** — in the same
   change, with the reason. Stale plans are worse than no plans.
8. **A week spent choosing is a week not building.** `capstone-final-decision.md` §6 makes this
   point about project selection; it applies equally to library choices. Timebox comparisons, pick,
   record why in an ADR, move.

## Working on the educational module

`educational/` implements the course labs. It follows different rules on purpose.

- **It is quarantined.** No import may cross between `educational/` and `src/`, in either direction.
  A test in `tests/boundary/` enforces this and must never be skipped.
- **Every module carries a header** stating: which lab exercise it implements, that it is
  intentionally insecure or obsolete, and that it must never be used in production.
- **It is excluded from the installed package** and from coverage requirements, but it is not
  excluded from linting.
- **Its tests demonstrate the weakness**, not just the algorithm — a Caesar implementation ships with
  its brute-force break; an ECB demonstration ships with the pattern-leakage artifact; the hashing
  lab ships with the MD5/SHA-1 timing and collision comparison the manual asks for.
- **Lab scope, from the manuals in this repository:** Lab 1 Basic Symmetric Key Ciphers, Lab 2
  Advanced Symmetric Encryption, Lab 3 Asymmetric Key Ciphers, Lab 4 Advanced Asymmetric Key
  Cryptography, Lab 5 Hashing, Lab 6 Digital Signature.
- **Course rules apply to this module and not to the product.** The manual's instructions to students
  include implementing exercises individually and avoiding LLM assistance; the manual also prohibits
  plagiarism. Where course rules constrain how lab code is produced, they govern `educational/`
  regardless of how the rest of the repository is built.
