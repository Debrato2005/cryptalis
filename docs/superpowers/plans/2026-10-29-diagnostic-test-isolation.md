# Diagnostic Test Isolation Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement this focused maintenance slice in the existing isolated cloud checkout.

**Goal:** Keep the already-probed source-role connection available to online tests after development diagnostics run.

**Architecture:** Restore every inherited test-role variable at the diagnostic test helper's monkeypatch boundary. Keep the wrapper's deliberate credential clearing and fresh-file probes unchanged.

**Tech Stack:** Python 3.12, pytest 9.1, psycopg 3, PostgreSQL 16.

**Spec:** The restoration contract in `tests/test_development_preflight.py:runner`, and the mandatory three-role workflow in `docs/local-development.md`.

## Global Constraints

- Use the existing isolated checkout; create no worktree.
- Never print credential values or bypass `scripts/test_postgres.py`.
- Keep production credential clearing, private files, and database-role restrictions unchanged.
- Do not commit or push without user authorization.

## Review Focus

- An inherited source-role variable must survive diagnostics.
- An absent optional source role must stay absent.
- Diagnostic failures must still restore the caller's environment.
- Real online tests must execute rather than skip after the diagnostic file.
- Database probes must continue to precede tests.

### Task 1: Restore the outer three-role test environment

**Files:** Modify and test `tests/test_development_preflight.py`.

**Interfaces:** Keep the existing `runner(monkeypatch)` and diagnostic CLI interfaces.

- [x] Add a regression that executes real diagnostics inside a monkeypatch context and checks restoration of present/absent optional source-role state without exposing values.
- [x] Run the regression through the PostgreSQL wrapper and retain its failing result.
- [x] Update the helper to register the optional source variable for restoration when present.
- [x] Run the diagnostic file followed by the online/scalar/worker/tenant/access/recovery matrix through one fresh three-role wrapper; require online calls to execute with no skips.
- [x] Inspect the final diff and record precise counts. Complete review before the authorized commit and push.

## Execution record

- RED: present-source restoration failed; absent-source control passed.
- GREEN: 52 diagnostic, online scalar/worker/tenant/recovery/access and wrapper checks passed with no skips.
- The final combined 220-check affected selection also passed after the RETURNING slice.
- The user subsequently authorized committing and pushing the completed increment.
