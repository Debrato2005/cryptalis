# Native numeric storage plan

Implement finite PostgreSQL NUMERIC storage using Decimal, including
unconstrained precision and native declared precision/scale (negative scales and
scale greater than precision included). Reuse authenticated CF1 and lifecycle
executors; version the reader and preserve native metadata on exit.

- [x] Add native CRUD/default/rounding/transaction/lifecycle oracles and record the failing native-behavior baseline.
- [x] Implement bounded decimal encoding, isolated native rounding, compiler/reader and lifecycle integration.
- [x] Verify online current writes, rotations, both layouts, installed behavior and older-reader refusal.
- [x] Record exact limits, read-only AI review, receipts and refreshed graph.

Verification and limits: [numeric boundary](../../_reset/numeric-storage-boundary-20261101.json).
Commit and push follow this verified slice under the active user authorization.

Numeric search/arithmetic and non-finite values remain required later work;
finite storage must not silently accept them. All production gates stay UNKNOWN.
