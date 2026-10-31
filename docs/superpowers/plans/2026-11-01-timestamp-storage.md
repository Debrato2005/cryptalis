# Timestamp storage implementation plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan inline.

**Goal:** Protect native finite `timestamp without time zone` values through the existing lifecycle and sync/async ORM.

**Architecture:** Reuse CF1 and the scalar path. Encode exact naive Python `datetime` values as eight signed big-endian microseconds since 2000-01-01. Emit lock v10 and pin the new reader; existing locks retain their versions. Admit default precision or explicit precision 6, storage only, with literal naive datetime defaults. Refuse timezone coercions, precision rounding, infinities and values outside Python's year range explicitly.

**Tech stack:** PostgreSQL 16, SQLAlchemy 2.1, psycopg 3, existing CF1.

**Spec:** Product requirement 6 in `docs/requirements.md`; compatibility, security and lifecycle contracts remain the owners. Native semantics: https://www.postgresql.org/docs/16/datatype-datetime.html.

## Task: Complete the timestamp storage slice

- [x] Add `tests/test_timestamp_storage.py`: native comparison through CRUD, defaults, RETURNING, savepoints, migration, rotations and current-value removal; async read/write; unsupported source-domain refusal before effects.
- [x] Run the deciding test through `scripts/test_postgres.py`; confirm current unsupported-type failure.
- [x] Extend `crypto/cf1.py`, compiler admission/reader validation, adapter assignment, temporal source-domain checks, restored-type checking and versioned public-slot paths. Preserve earlier reader behavior.
- [x] Run the new native journeys and affected Date/integer/UUID/default/lifecycle regressions through the wrapper. Retain failed and passing receipts.
- [x] Update current contracts, status and the objective ledger; refresh the local AST graph, check links, commit and push under Debrato's identity.

## Review focus

Test negative microseconds, year boundaries and NULL; naive/aware distinction; descriptor and lock drift; post-plan out-of-domain rows; current edits and independent installed recovery. Timestamp search, time-zone-aware values and smaller precisions remain separate implementation slices, not completed requirements.

Rulings: retain explicit precision in both native exit paths; recheck temporal source bounds only during first online expansion so status remains readable after later source drift. Reuse the temporal qualification fixtures for a genuine timestamp restore and an unchanged Date control.
