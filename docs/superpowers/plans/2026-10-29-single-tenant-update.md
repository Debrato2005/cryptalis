# Single-tenant mapped UPDATE implementation plan

> **For agentic workers:** Use superpowers:executing-plans for this one slice.

**Goal:** Preserve native mapped dictionary UPDATE on declared single-tenant tables.
**Architecture:** Extend the existing request, compiler and driver admission. Keep
SQLAlchemy responsible for grouping, primary-key predicates and row-count errors.
**Tech stack:** Python 3.12+, SQLAlchemy 2.1.3, psycopg 3, PostgreSQL 16.
**Spec:** [Canonical decision](../../decisions.md#single-tenant-mapped-dictionary-update-2026-10-29).

## Global constraints

No new crypto, dependency or artifact format. Fixed scope comes from the manifest.
Tenant-column tables retain explicit tenant predicates. No plaintext protected binds.
Use `scripts/test_postgres.py` with freshly probed private roles for database tests.
User authorized direct implementation, the existing disposable cluster, and push.

## Review focus

Wrong fixed scope; caller or driver predicate mutation; repeated and missing IDs;
VARCHAR/integer errors and savepoints; async preparation and native ORM state.
The test task covers these boundaries alongside the existing scoped-update corpus.

## Task 1: Admit and verify single-tenant UPDATE

**Files:** `src/cryptalis/sqlalchemy.py`, new `tests/test_bulk_update_single_tenant.py`,
canonical compatibility/security/status/checklist records and retained receipts.
**Interfaces:** Consume `attach`, native `Session.execute(update(Model), list[dict])`,
existing online activation and reverse APIs. Produce the same empty native result;
no new public API.

- [x] Add native-versus-protected sync/async journeys through activation, updates,
  refresh, rollback, savepoint errors and latest-value removal. Add pre-key and
  final-driver refusal controls, including wrong fixed scope and altered IDs/SQL.
- [x] Run the new module through the PostgreSQL wrapper. Expect refusal on the
  currently unsupported single-tenant route; retain the RED receipt.
- [x] Extend `update_context` and final bind validation for an absent tenant bind
  only on a declared fixed-scope table. Preserve the generated record predicate.
- [x] Run new and existing UPDATE, scalar, INSERT/result and online controls.
  Expect all selected tests to pass. Retain exact receipts and scope.
- [x] Request a fresh code review, resolve material findings, update canonical
  evidence, inspect the diff, commit and push the completed slice.

## Verification and review

The native RED fails at single-tenant admission. The new module then passes 28
checks; affected source regression passes 508 with six retained-reader skips.
The installed wheel passes 93 checks. Repeat artifacts and 47 installed files
pass the existing release inspection. Exact receipts and limits are in the
[status checkpoint](../../status.md#single-tenant-mapped-update-2026-10-29).

The fresh reviewer found no blocking defect or required code change. This slice
does not independently inject async fixed-scope failures or mutate the generated
predicate AST; existing shared admission checks remain in force. Full production
gates, custody, host writer exclusion and independent human review remain UNKNOWN.
