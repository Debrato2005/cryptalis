# Lock v2 source-metadata proposal

**APPROVED 2026-10-21.** Slice A is implemented: new protection plans emit
`cryptalis.lock/v2`, capture protected-column metadata, and restore it during in-place
reverse. Column grants and owned sequences remain refused until slice B.
[Status](../status.md) owns current evidence.
[Metadata research](metadata-preservation-and-format-evolution.md) owns the observed gaps.

## Problem

Before lock v2, protection and reverse refused metadata that the lock could not restore.
The refusal is fail-closed and verified. Slice A now captures comments, statistics
targets, storage, compression, options, constraint and index comments, and extended
statistics. A host must still remove column grants and owned sequences before planning.

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
      "statistics": "500",
      "storage": "e",
      "compression": "p",
      "options": ["n_distinct=10"],
      "acl": []
    }
  },
  "constraints": {"email_unique": "unique login"},
  "indexes": {"email_lookup": "lookup path"},
  "extended_statistics": [
    {"name": "customer_stats", "kinds": ["d", "f"], "columns": ["label", "name"],
     "statistics": "-1", "comment": null, "definition_digest": "<sha256>"}
  ]
}
```

`columns` is keyed by database column name. It contains only protected columns. Plain
columns survive the switch and are not captured.

`acl` entries use role names, sorted by role. The form is
`GRANTEE|PRIVILEGES|GRANTABLE`. `PRIVILEGES` is the canonical ACL letter order.
`GRANTABLE` is `true` when the grant option is present. `PUBLIC` is a valid grantee.
Grantor names are not stored; restoration runs as the table owner.

`options` is the `attoptions` array. `storage` and `compression` use the catalog
single-character values (`p` is pglz, `l` is lz4). `statistics` is the decimal target
string, as a string because the manifest integer grammar is non-negative and bounded.
Empty values are `null` or `[]`, not omission. Null and empty are distinct.

Extended statistics entries store names, kind letters, sorted column names, statistics
target string, comment, and a digest over the canonical entry without the digest.
Definitions are rebuilt from these fields, not parsed from SQL text.

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
before the switch. A difference is `source_metadata_changed` with the operation id. It
does not guess a merge.

The reverse planner and switch cannot compare against the source column, because the
protection switch removed that metadata. They refuse any metadata found on the
ciphertext column or any extended statistics or owned sequence that references it.
Metadata expected from the lock is restored by the reverse switch. The existing refusal
codes remain valid for v1 locks, which carry no metadata.

## Reverse restore

After the column rename and the recorded constraint/index restoration, the reverse switch
applies metadata in this order:

1. Column comment, statistics target, storage, compression, and options.
2. Column grants. **Not implemented in slice A.** Column grants remain refused. Slice B
   must also apply the captured grants to the ciphertext column at the protection
   switch. Otherwise runtime column privileges are lost before reverse.
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

The first implementation phase covers in-place reverse. The adoption reader accepts v2,
and reverse after adoption shares the restore code. A dedicated fresh-cluster case with
captured metadata is still required before that path is qualified.

## Test status

Slice A evidence is in `tests/test_protection_compiler.py`,
`tests/test_deprotection.py`, and `tests/test_migration.py`.
- Capture: `test_source_metadata_is_captured` and
  `test_extended_statistics_are_captured` check the v2 lock fields.
- Restore: `test_source_metadata_is_preserved_through_decrypt_back` compares protected
  comments, statistics target, storage, compression, options, constraint and index
  comments, and extended statistics before protection and after removal.
- Drift: `test_metadata_added_after_planning_is_refused_before_effects` covers a late
  comment, statistics target, grant, extended statistics, and owned sequence.
- Refusal: column grants and owned sequences still refuse with typed codes in both
  directions.
- Compatibility: v1 locks remain readable. The v1 path has no metadata to restore.
- Slice B negative cases are not implemented: missing role, invalid ACL text, and
  forward grant application.
- A dedicated fresh-cluster case with captured metadata remains a separate phase.

## Implementation slices after approval

1. **DONE, slice A:** emit and validate `lock/v2`; capture protected-column facts;
   stop refusing captured kinds; add drift checks and compatibility tests.
2. **DONE, slice A:** restore captured facts in the reverse switch; add the catalog
   oracle.
3. **NEXT, slice B:** apply captured column grants at the protection switch and restore
   them during reverse; add missing-role and invalid-ACL tests.
4. Extend fresh-cluster adoption and reverse after adoption.
5. Update status, lifecycle, compatibility, and receipts.

## Approved decisions

1. Approved `cryptalis.lock/v2` with a dual reader and v2-only new plans.
2. Approved the capture scope: protected-column attributes and ACLs, constraint/index
   comments, and extended statistics.
3. Approved the ACL rule: role names must exist; no mapping; PUBLIC allowed.
4. Confirmed that owned sequences stay refused.
5. Approved in-place restore first, with fresh-cluster restore as a separate phase.
