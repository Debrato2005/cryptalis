# ADR-0001 — Write-time encryption boundary

**Status:** Accepted
**Date:** 2026-08-12
**Contract:** [AD-1](../../README.md#ad-1--encryption-happens-at-write-time-the-database-stores-ciphertext)
**Source:** `capstone-final-decision.md` §1–§4

## Problem

Sensitive fields must be protected against an attacker who obtains database access — stolen backup,
leaked credentials, a rogue administrator, or a compromised read replica. Transport security and
transparent disk encryption do not help against any of those: both decrypt automatically for anyone
holding a valid database connection.

The design question is not *whether* to encrypt at the application layer but **where in the request
lifecycle the boundary sits**. Two candidate positions were on the table, and they produce different
systems:

- **Egress**: encrypt on the way out of the API, so responses and downstream log pipelines carry
  ciphertext. The database keeps plaintext.
- **Ingress**: encrypt before the database write. The database keeps ciphertext.

## Constraints

- The project must be able to answer "what happens when your database is breached?" with a
  demonstration, not an argument. This is the first question any reviewer asks.
- Crypto-shredding — erasure by key destruction — is the project's highest-value differentiator.
- A 14–16 week budget, one developer. The design must not require rewriting a query planner or a
  SQL parser.
- The protected application (*Smolink*, a separate repository) had already accepted additive
  changes for other reasons, so "requires no application changes" was not a hard constraint.
- No code exists yet; this decision is made on design grounds and must be re-validated against the
  first working integration in Milestone 5.

## Decision

**Encrypt at write time, in the application's data-access layer, through an SDK call.** The database
stores ciphertext for every registered field. Decryption happens on read and is gated by policy.

Registration is explicit: a field is `(table, column) -> field_class` in the schema policy. Fields
that are not registered are not encrypted, and are also not decryptable — the request fails rather
than silently passing plaintext through.

## Alternatives rejected

**Egress-only encryption (the original "CipherShield" model).** Rejected for three reasons, from
`capstone-final-decision.md` §2:

1. It leaves plaintext in Postgres, so it has no answer to the database-breach question — the one
   claim the project exists to make.
2. Its main pitch, "plaintext never reaches the logging pipeline," is largely solved by field
   redaction in a structured logger. A differentiator with a cheap, well-known counter is not a
   differentiator.
3. Crypto-shredding is architecturally impossible: destroying a key does not erase plaintext that is
   still sitting in a table.

It also carried the project's highest-risk implementation item — re-serializing nested JSON arrays in
API responses — which mostly disappears when encryption happens at the point where the application
already has the individual field value in hand.

**A SQL-rewriting proxy between the application and the database.** Rejected: transparent to the
application, but it must parse and rewrite arbitrary SQL, handle prepared statements, JSON operators,
and multi-row writes. Large, fragile surface; not achievable at quality in the time budget. Revisit
only under P3 in the [future phases](../backend-build-checklist.md#future-phases-post-v10).

**Database-native column encryption (pgcrypto or similar).** Rejected: key material ends up
accessible to the database process, which is exactly the adversary being defended against. It also
makes per-subject key scoping and crypto-shredding impractical.

**Full-disk or transparent database encryption only.** Rejected: protects a stolen disk, not a valid
connection. Explicitly the baseline this project improves on.

## Data flow

**Write**

```
application code
  → data-access layer calls sdk.encrypt_field(subject_id, table, column, record_id, plaintext)
    → gateway: authenticate → field registered? → get/create DEK → build AAD → AES-256-GCM
      → audit append
  ← envelope (ciphertext, key_id, version)
  → INSERT/UPDATE stores the envelope bytes and key_id
```

**Read**

```
SELECT returns envelope bytes
  → data-access layer calls sdk.decrypt_field(...)
    → gateway: authenticate → policy decision → key state check → parse envelope
      → AES-256-GCM decrypt with reconstructed AAD → audit append
  ← plaintext, or a typed denial
```

The gateway never touches the application's tables. The application never interprets envelope
structure.

## Error and security behaviour

- **Encrypt fails** (gateway down, unregistered field, timeout): the SDK raises. The data-access
  layer must let the write fail. **Falling back to writing plaintext is prohibited** and is the
  single most dangerous bug this design can have — Milestone 5 has a test for it.
- **Decrypt fails**: the application receives a typed error and must surface an error, not a
  placeholder that could be mistaken for real data.
- **What this protects against:** an attacker with full read access to the database or a backup gets
  ciphertext plus wrapped DEKs, neither of which is useful without the KEK, which is not in the
  database.
- **What this does not protect against:** a compromised gateway host with keys in memory; a
  compromised application that legitimately requests decryption; application-logic flaws;
  denial of service. Stated plainly in the README's non-goals and to be expanded in a future threat
  model record.
- **Availability coupling:** the gateway is now in the write path. If it is down, protected writes
  fail. That is the intended trade — see [ADR-0005](0005-sdk-integration-and-deployment.md) for the
  timeout and failure-domain treatment.

## Testing strategy

- `tests/e2e/test_demo_flow.py` — write through the application, then assert with a **raw SQL query**
  that the plaintext string does not appear in the protected column. This is the test that proves
  AD-1 and it must never be weakened to an application-level assertion.
- `tests/integration/test_unregistered_field.py` — an unregistered field fails closed at both ends.
- `tests/unit/test_sdk_client.py` — a gateway failure raises rather than degrading.
- Release verification repeats the raw-SQL check manually before any tag.

## Deferred

- Equality search over encrypted columns (blind index) — P5. Until then, encrypted columns cannot be
  filtered or joined on, and the field registry should be reviewed with that in mind.
- Sidecar and proxy deployment modes — P3.
- Encrypting nested JSON sub-paths: registration currently addresses whole columns. If a JSON
  sub-path needs protection, the field-path syntax is designed then, not speculatively now.
- Backfilling an existing plaintext column is specified as a six-step migration in the
  [playbook](../../ENGINEERING_PLAYBOOK.md#migrations-and-rollback) but is not exercised until a real
  table needs it.
