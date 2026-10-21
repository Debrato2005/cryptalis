# Lock v2 source-metadata proposal

**PROPOSED — NOT APPROVED.** This document requests a format decision. It does not
change the lock, compiler, executor, or reader behavior.
[Status](../status.md) owns current evidence.
[Metadata research](metadata-preservation-and-format-evolution.md) owns the observed gaps.

## Problem

Protection and reverse now refuse metadata that the lock cannot restore. The refusal is
fail-closed and verified. It is not a restoration feature. A host that needs a protected
column comment, statistics target, storage or compression setting, column option, column
grant, constraint or index comment, or extended statistics must remove those facts before
planning.

Capture and restore needs an authenticated artifact. The journal is progress evidence,
not restore authority. A host inventory outside the lock weakens the deployment
authority rule. The lock is the existing artifact that binds source facts to the plan
digest.

## Proposed format

Introduce `cryptalis.lock/v2`. Keep every current top-level member. Add one member to
each model: `source_metadata`.

```json
"source_metadata": {
  "columns": {
    "name": {
      "comment": "customer name",
      "statistics": 500,
      "storage": "e",
      "compression": "pglz",
      "options": ["n_distinct=10"],
      "acl": ["app_role|SELECT|false"]
    }
  },
  "constraints": {"email_unique": {"comment": "unique login"}},
  "indexes": {"email_lookup": {"comment": "lookup path"}},
  "extended_statistics": [
    {"name": "customer_stats", "kinds": ["d", "f"], "columns": ["name", "label"],
     "statistics": -1, "comment": null, "definition_digest": "<sha256>"}
  ]
}
```

`columns` is keyed by database column name. It contains only protected columns. Plain
columns survive the switch and are not captured.

`acl` entries use role names, sorted by role. The form is
`GRANTEE|PRIVILEGES|GRANTABLE`. `PRIVILEGES` is the canonical ACL letter order.
`GRANTABLE` is `true` when the grant option is present. `PUBLIC` is a valid grantee.
Grantor names are not stored; restoration runs as the table owner.

`options` is the sorted `attoptions` array. `storage` and `compression` use the catalog
single-character values. `statistics` is the integer target. Empty values are `null` or
`[]`, not omission. Null and empty are distinct.

Extended statistics entries store names, kind letters, ordered column names, statistics
target, comment, and a digest over the canonical entry without the digest. Definitions
are rebuilt from these fields, not parsed from SQL text.

Owned sequences are **not** captured. A sequence owned by a protected column remains
refused. Its `last_value` and `is_called` move with forward writes during protection;
restoring an old state would change application data. This is an explicit exclusion, not
an omission.

## Authority and digests

`source_metadata` is inside the lock document. The existing canonical lock bytes and plan
digest bind it. No second signature or side artifact is added.

Capture is read-only and runs with the other compiler inspections. Every captured value
must equal the observed catalog value before the lock is emitted. Capture failure is a
typed planning failure, never an empty metadata section.

The lock contains no application values. Comments are schema text, not row data. ACL
entries contain role names. The lock still contains no connection string.

## Drift and refusal

The executor compares captured metadata with the current catalog before expand and
before the switch. A difference is `source_metadata_changed` with the model and object
name. It does not guess a merge.

The reverse planner and switch perform the same comparison against the lock. A change
after the protection plan is refused. The existing refusal codes remain valid for v1
locks, which carry no metadata.

## Reverse restore

After the column rename and the recorded constraint/index restoration, the reverse switch
applies metadata in this order:

1. Column comment, statistics target, storage, compression, and options.
2. Column grants. Each role must exist. A missing role refuses the switch; no automatic
   or name-mapped grant is attempted.
3. Constraint and index comments.
4. Extended statistics, created from the captured kinds and column names, then the
   statistics target and comment.
5. Full catalog comparison against `source_metadata`, excluding OIDs.

All statements run in the existing switch transaction. A failure rolls back the switch.
No metadata statement runs after the terminal phase is saved.

## Version and reader rules

- `cryptalis.lock/v1` remains readable for reverse, removal, and existing deployments.
  It carries no metadata, so v1 behaves as today.
- New protection plans emit `cryptalis.lock/v2`.
- A v2 reader accepts v1 and v2. An old reader rejects v2 because the key set differs.
  This is the required fail-closed behavior.
- A v1 operation cannot be upgraded in place. The host either finishes it or recompiles
  from the source schema after the source is available again.
- `cryptalis.transition/v1` keeps its top-level shape; the embedded lock schema changes.

## Fresh-cluster phase

The protected dump carries no source metadata for the dropped column. A restored target
therefore has no source metadata until reverse restores it. Adoption reads `lock/v2`;
reverse after adoption applies the captured metadata with the same rules.

The first implementation phase covers in-place reverse only. Fresh-cluster adoption of
v2 locks is a separate phase with its own tests.

## Test plan

- Capture: every field and object kind round-trips through canonical bytes; null and
  empty forms stay distinct.
- Restore: catalog oracle equality for comments, statistics target, storage,
  compression, options, ACLs, constraint/index comments, and extended statistics.
- Negative: missing role, unknown statistics kind, mismatched definition digest, extra
  or missing metadata entry, and invalid ACL text all refuse with a typed code.
- Drift: a change after planning refuses with `source_metadata_changed` at expand,
  switch, reverse plan, and reverse switch.
- Compatibility: v1 lock still reverses; v2 lock rejects under an old reader; v1 plan
  cannot emit metadata.
- Fresh-cluster: separate phase after in-place evidence.

## Implementation slices after approval

1. Emit and validate `lock/v2`; capture protected-column facts; stop refusing captured
   kinds; add drift checks and compatibility tests.
2. Restore captured facts in the reverse switch; add the catalog oracle and negative
   tests.
3. Extend fresh-cluster adoption and reverse after adoption.
4. Update status, lifecycle, compatibility, and receipts.

## Decisions requested

1. Approve `cryptalis.lock/v2` with a dual reader and v2-only new plans.
2. Approve the capture scope: protected-column attributes and ACLs, constraint/index
   comments, and extended statistics.
3. Approve the ACL rule: role names must exist; no mapping; PUBLIC allowed.
4. Confirm that owned sequences stay refused.
5. Approve in-place restore first, with fresh-cluster restore as a separate phase.
