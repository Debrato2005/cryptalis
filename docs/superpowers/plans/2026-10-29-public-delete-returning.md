# Public DELETE RETURNING Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans in the existing isolated checkout. The user requested direct continuation with faster bounded slices.

**Goal:** Return native public-column values from an already-admitted tenant-and-record DELETE.

**Architecture:** Reuse the existing immutable DELETE permit and native result machinery. Extend the permit with the exact returned public-column configuration, checked before key preparation, after callbacks and at driver dispatch. No encrypted value decoding or representation changes are needed.

**Tech Stack:** Python 3.12, SQLAlchemy 2.1, psycopg 3, PostgreSQL 16.

**Spec:** `docs/architecture/README.md` SQLAlchemy native-result contract and `docs/BUILD_CHECKLIST.md` OBJ-QUERY-04.

## Global Constraints

- Exact typed tenant/record predicates and `synchronize_session=False` remain required.
- Admit only direct native mapped public columns; preserve Row keys, scalar consumption, SQL types and transaction behavior.
- Protected fields, entities, labels, expressions, foreign columns and custom rendering require separate admission.
- Preserve the original permit through key callbacks and final SQL/parameter dispatch.
- No new dependencies, storage formats, schemas or worktrees. The user authorized commits and pushes.
- Validate through the mandatory PostgreSQL wrapper. Use focused affected suites during development.

## Approach

Public-only results are the first independently useful slice of the documented RETURNING gap. Protected result decoding requires a separate authenticated output contract. Bulk UPDATE uses executemany, whose native RETURNING restrictions also require separate investigation. Native public DELETE results can reuse the existing finite scoped grammar directly.

## Review Focus

- Missing and foreign-tenant rows return no results.
- Rollback restores the deleted row; commit removes only the selected row.
- Sync and async results retain native keys and scalar/tuple values.
- A callback cannot add, remove, reorder or retarget the original returned columns.
- Unadmitted/custom projections refuse before key resolution or data SQL.

### Task 1: Public result admission and native behavior

**Files:** Create `tests/test_scoped_delete_returning.py`; modify `src/cryptalis/sqlalchemy.py`; update the compatibility, architecture and current-status documentation.

**Interfaces:** Existing scoped mapped `session.execute(delete(Model).where(...).returning(...), execution_options={'synchronize_session': False})`; native SQLAlchemy Result.

- [x] Write native-versus-protected sync/async scalar and tuple result tests, zero-match/foreign-scope controls and transaction checks.
- [x] Run a positive case and retain the expected pre-implementation refusal.
- [x] Add public returning-column configuration to `_DeletePermit` and revalidate it at each existing boundary.
- [x] Run new cases, existing DELETE/native/driver-boundary cases and shared INSERT RETURNING cases; inspect failures before further changes.
- [x] Record exact verified scope and remaining admission limits. Complete review before the authorized commit and push.

## Execution record

- The user subsequently authorized committing and pushing the first completed increment.
- Initial positive regression refused as expected before implementation.
- A larger selection exposed an obsolete public-RETURNING refusal control; it now selects protected output.
- Independent review found that effective annotated types were not frozen. Three actual PostgreSQL regressions failed before the fix, then passed with canonical type identity checks.
- Final affected selection: 220 passed, no skips, unchanged Python source.
- Full source regression is partitioned across four independent wrapper processes using a complete non-overlapping file inventory. Each process probes all three restricted roles.
- Full boundary: all 160 files and 2,982 selected items covered; 2,969 test calls and 18 subtests passed. Keep nine call skips, four setup skips and fifteen collection skips distinct. All four wrappers have exit 0 and the same unchanged Python hashes.
- Repeat wheel/sdist builds, wheel integrity checks, SBOM generation and dependency consistency passed.
- Final review finding: fixed effective projection type substitution with three RED-to-GREEN PostgreSQL regressions; no deferred findings.
