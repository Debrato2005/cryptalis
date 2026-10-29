# Protected DELETE RETURNING Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans in the existing isolated checkout. The user authorized continuation, commits and pushes.

**Goal:** Return authenticated protected scalar and direct-column tuple values from the existing exact tenant-and-record DELETE route.

**Architecture:** Reuse the owned `_Payload` projection and `_ReadText` decoder. Bind returned carriers to the immutable DELETE permit's requested record and session tenant. Keep native Result objects and the exact two original driver parameters. Use a fixed compiler-owned hex-format literal in the DELETE carrier; add no user-controlled SQL or representation.

**Tech Stack:** Python 3.12, SQLAlchemy 2.1, psycopg 3, PostgreSQL 16.

**Spec:** SQLAlchemy integration and authenticated-output contracts in `docs/architecture/README.md`, `docs/security.md`, and OBJ-QUERY-04 in `docs/BUILD_CHECKLIST.md`.

## Global Constraints

- Require exact typed tenant/record equalities, `synchronize_session=False` and direct mapped columns. Protected columns can retain only the exact recorded original type annotation or their canonical owned physical type.
- Preserve native scalar/tuple keys, Python types, SQL NULLs, zero matches, commit and rollback.
- Validate effective projection types and callbacks at every existing admission boundary.
- Authenticate every protected result against its own field, the original requested row, and the session tenant. A DELETE result cannot use outer-join NULL context.
- Result authentication can fail after DELETE executes; callers must roll back before retry or commit. No extra prefetch query or automatic transaction boundary.
- Entity/label/expression/alias projections, broad DELETE and UPDATE RETURNING stay separate work.
- No schema, format, key policy, dependency, worktree or production qualification changes.
- Run tests only through `scripts/test_postgres.py`; keep Python files stable during each wrapper run.

## Review Focus

- SQL NULL, empty/Unicode text and admitted scalar codecs return native values and types.
- Corrupted stored frames and substituted valid frames from another row or field release no accepted result.
- Missing record/tenant context refuses even for a NULL protected value.
- Async key preparation cannot change the original projection or requested point.
- Callback/type/driver changes remain refused; the final driver receives only the original two authorized predicates.

### Task 1: Authenticated direct protected results

**Files:** Create `tests/test_scoped_delete_protected_returning.py`; modify `src/cryptalis/sqlalchemy.py`, the existing DELETE refusal controls, and contract/status documentation.

**Interfaces:** Existing `Session.execute(delete(Model).where(...).returning(...), execution_options={'synchronize_session': False})`; ordinary SQLAlchemy Result.

- [x] Write native-versus-protected sync/async scalar/tuple tests and real stored-frame corruption controls; observe the expected pre-implementation refusal.
- [x] Admit owned protected projection types, carry the original point into result authentication, and reject contextless NULL carriers.
- [x] Exercise field/row substitution, invalid effective types, callback changes, zero matches and transactions.
- [x] Run the affected DELETE/read/RETURNING suites, one independent review and the complete source corpus in non-overlapping wrapper batches.
- [x] Record exact outcome counts and limitations, verify repeat builds, commit and push to the existing branch.

## Execution record

- The initial positive case refused before implementation.
- Native ORM annotations retained original application types. A first attempt demonstrated raw storage bytes; compiling an owned physical-type projection copy restored authenticated decoding without mutating caller descriptions.
- A missing effective-type regression demonstrated an untyped failure and now refuses through the normal typed admission path.
- Independent review identified a fresh-permit authority issue at the clone boundary. Both sync and async record-retargeting regressions failed before the fix. The generated statement now validates against the original permit with only its projection states normalized.
- Final focused boundary: 71 checks passed, including all admitted scalar families, UUID/int64 contexts, actual corruption, field/row/tenant substitutions, NULL context, type/callback faults and cloning authority.
- Full source verification uses the complete 161-file inventory in four non-overlapping three-role wrapper processes.
- Initial whole-corpus results retain fifteen incomplete decoder-fixture failures and one shared-role privilege collision. The fixture now includes `scoped_delete=None`; all 43 UUID decoder, rotation lifecycle and privilege controls pass in a serialized run. Product hashes remain unchanged across every run.
- Final complete-corpus coverage: 3,020 test calls and 18 subtests passed; nine call skips, four setup skips and fifteen collection skips. The initial failed results remain in the combined evidence and rerun file outcomes are counted once.
- Same-host repeat wheel/sdist builds, archive checks, SBOM generation and dependency consistency passed.
- Future parallel runs require isolated clusters/roles, or serialized database-wide privilege tests. Shared role grants are global, despite separate Python processes and random application schemas.
