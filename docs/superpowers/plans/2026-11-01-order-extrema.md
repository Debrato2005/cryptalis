# Authenticated MIN/MAX implementation plan

**Goal:** Admit direct MIN/MAX projections on explicitly order-enabled fields.

Reuse the existing order term, PostgreSQL's C-collated text aggregate and the
authenticated row reader. Prefix each opaque row packet with its fixed-width
hex order term, select its native minimum/maximum, then decode only that packet.
This uses constant aggregate state and exposes no new stored representation.

- [x] Extend the existing native query oracle, including empty/all-NULL inputs.
- [x] Add finite projection admission and reuse authenticated reader/result keys.
- [x] Verify lifecycle, async, scope, tamper and installed-package behavior.
- [x] Record bounded evidence, review, refresh graph, commit and push.

Grouping, window extrema, expressions and storage/equality-only fields remain
outside this slice. Existing completeness limits and UNKNOWN gates remain.
