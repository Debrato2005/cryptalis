# Aware timestamp storage and order plan

Use the existing CF1/lifecycle paths with a distinct UTC-microsecond codec and
lock/v12. Standard DateTime/TIMESTAMP timezone=True mappings admit exact aware
datetime values at default precision or precision 6. Preserve native connection
timezone, local offset and fold on reads and original literal defaults before
refresh. Reuse opt-in order, ranges and direct MIN/MAX without new leakage.

- [x] Add native PostgreSQL CRUD/default/async/lifecycle oracles and observe type refusal.
- [x] Implement codec, strict mapping/reader/defaults, result-timezone snapshots and lifecycle checks.
- [x] Verify order, DST/fold/parameter mutation, online capture, rotations and both exits.
- [x] Verify installed/fresh recovery/old reader, preserve receipts and update contracts.
- [x] Refresh navigation and complete read-only AI review of the verified slice.

Evidence: [exact boundary](../../_reset/timestamptz-boundary-20261101.json).
Commit and push follow under the active user authorization.

Naive coercions, other precisions and arbitrary custom tzinfo remain explicit
unfinished scope. No production gate is qualified by this slice.
