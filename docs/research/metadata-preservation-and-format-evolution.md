# Metadata preservation and lock-format evolution (research)

**Status: research only.** This note compares gaps and options. It does not change
`cryptalis.lock/v1`, `cryptalis.protection/v1`, `cryptalis.transition/v1` or
`cryptalis.restore/v1`. It adds no runtime claim and no gate evidence.
A lock-format change needs explicit approval and a reviewed amendment.

## Recorded facts today

`_schema_facts` in `src/cryptalis/manifest/compiler.py` records these facts in the lock:

- **Relation:** `relkind`, `relpersistence`, row-security enable/force flags, `relhasrules`,
  inherited relation exists (boolean), and a non-internal trigger exists (boolean).
- **Column:** `attnum`, name, type, type schema, typmod, nullability, identity, generated,
  default digest, collation name/schema/determinism/provider.
- **Constraint:** name, kind, deferrable, deferred, validated, direction, column list,
  referenced columns, and the definition digest plus definition text in the plan artifact.
- **Index:** name, primary/unique/exclusion/null-not-distinct/immediate/valid/ready/live
  flags, replica identity, column counts, method, partial/expression flags, column list,
  dependency columns, operator classes, collations, constraint name, definition digest.
- **Dependency:** column name and dependent object kind (rewrite, attribute default,
  routine).

The in-place reverse restores a protected column as native `text` with its admitted
collation, resets `NOT NULL`, and recreates the recorded constraints and indexes from the
recorded definitions. Other columns are not rebuilt. Removal compares
`_metadata_diff(source_schema, current_facts)`, which ignores only `attnum`.

## Not recorded

These catalog facts have no field in the lock:

- Column comment, statistics target (`attstattarget`), storage (`attstorage`),
  compression (`attcompression`), column ACL (`attacl`).
- Table options (`reloptions`, e.g. fillfactor/autovacuum), tablespace, table ACL,
  owner, and partition key/bounds.
- Row-security policy definitions (`pg_policy`), rule bodies, trigger definitions,
  and index or constraint comments. Index storage options and tablespace are not separate
  fields, but `pg_get_indexdef` embeds them in the recorded definition text.
- Extended statistics objects (`pg_statistic_ext`).
- Sequence parameters, ownership and ACLs for non-identity keys.

Some of these survive in place because the table is not rebuilt: table comment, table
options, table ACL, owner, policies, rules and triggers stay attached to the relation.
Protected-column facts do not survive: the switch drops the source column and renames the
staging column. The same loss applies to index and constraint comments for recreated
objects. Index options survive because the recorded `CREATE INDEX` text carries them.

## Preservation matrix

| Metadata | In-place reverse | Fresh-cluster restore from protected dump |
|---|---|---|
| Protected column type, collation, nullability | Restored | Restored |
| Recorded constraints and indexes | Restored from definitions | Restored by `pg_dump` |
| Protected-column comment/statistics/storage/compression/ACL | Lost | Lost |
| Index options and tablespace | Restored through the recorded definition | Restored by `pg_dump` |
| Index and constraint comments | Lost | Lost |
| Table comment/options/ACL/owner/RLS/rules/triggers | Kept | Kept by `pg_dump` |
| Physical column position (`attnum`) | Changed | Changed |
| Extended statistics | Not recorded (UNKNOWN) | Not recorded (UNKNOWN) |

The protected dump carries `bytea` under the protected column name. The source column was
dropped when protection switched, so the dump cannot carry its old column metadata.

## Risks

- A comment or storage setting on a protected column disappears without a typed refusal.
  Removal does not detect it because the lock never recorded it.
- An index recreated from `pg_get_indexdef` keeps options and tablespace but loses its
  comment. Definition text carries storage parameters, not comments.
- A column statistics target loss changes planner behavior after decrypt-back.
- The fresh-cluster path is stronger than in-place reverse, but it is not a fix for the
  protected-column loss.

## Lock evolution options

### A. New lock version with a `source_metadata` section

Add per-model/per-column entries for comments, statistics, storage, compression, ACL and
index metadata. Bind each entry with a digest and restore it in the reverse switch.
Advantages: one authenticated artifact; offline review; exact drift detection.
Costs: a new `cryptalis.lock/v1`-incompatible version; admission code for every entry;
restoration statements for ACLs, comments and settings; role-name mapping on a fresh
cluster. Unknown entry kinds need an explicit policy: refuse, or preserve opaquely.

### B. Separate host inventory

Capture the same facts in a host-owned inventory and require it at reverse approval.
Advantages: no lock-format change. Costs: a second authority that is not in the lock
digest; drift between inventory and lock; the host must prove the inventory is current.
This option weakens the "database state is not restore authority" rule unless the
inventory is cryptographically bound to the plan.

### C. Differential dump oracle

Use `pg_dump --schema-only` as the verification oracle for both paths. Advantages:
covers every dumped fact, not a hand-picked list. Costs: it is not an in-place
restoration mechanism; it needs statement rewriting and owned-object filtering; it does
not preserve `attnum` either.

## Compatibility rules to evaluate

1. A reader rejects an unknown lock schema. The current `_previous_lock` already compares
   the full key set, so additive fields fail closed.
2. A new reader may admit the old lock with documented defaults, or refuse it. It must not
   guess missing metadata.
3. A format change needs an upgrade path for active deployments: recompile from the
   source schema, or refuse and require decrypt-back first.
4. Every restored fact needs a native PostgreSQL oracle test, a negative admission test,
   and a drift refusal.
5. No entry is dropped silently. Unknown kinds have an explicit refusal or an opaque
   preserved form with a digest.

## Observed in the isolated probe: 2026-10-19

`tests/test_deprotection.py::test_unrecorded_column_metadata_is_lost_without_detection`
builds a table with a table comment, a protected-column comment, a plain-column comment,
a statistics target, external storage, a column ACL, an index comment and an index
fillfactor. It protects and fully reverses the table, then reads the catalog again.
The focused runs report **61 passed** for
[SQLAlchemy 2.1.3](../_reset/metadata-gap-focused-sa21-20261019.json) and
[SQLAlchemy 2.0.51](../_reset/metadata-gap-focused-sa20-20261019.json). The full suites
report **1,307 passed, 2 skipped**
([2.1.3](../_reset/metadata-gap-full-sa21-20261019.json)) and **1,279 passed, 30 skipped**
([2.0.51](../_reset/metadata-gap-full-sa20-20261019.json)).

Observed results:

- Table comment, plain-column comment and plain-column ACL survive.
- Protected-column comment, statistics target, storage setting and ACL are lost.
- The index comment is lost. The index fillfactor survives because the recreated index
  definition text carries it.
- `_metadata_diff` reports no difference after the losses. The gap is silent.
- A metadata change after plan compile is refused when it enters the recorded facts.
  `ALTER INDEX ... SET (fillfactor=...)` changes the definition digest, and the executor
  refuses with `source_schema_changed`.

## Guard implemented: 2026-10-19

Option 2 is implemented without a lock change. Protection planning refuses protected
columns with a comment, non-default statistics target, storage or compression setting, or
column grant, and refuses comments on constraints and indexes that it recreates. Reverse
planning, the protection switch, and the reverse switch refuse the protected-column
attributes when they appear after planning. The failure codes are
`unsupported_protected_metadata` and `unsupported_recreated_metadata`; planning remedies
say to remove the metadata.

The former characterization test is now
`test_surviving_metadata_is_preserved_through_decrypt_back`. Refusal evidence is in
`tests/test_protection_compiler.py`, `tests/test_deprotection.py` and
`tests/test_migration.py`. Focused runs report **128 passed** for
[SQLAlchemy 2.1.3](../_reset/metadata-refusal-focused-sa21-20261019.json) and
[SQLAlchemy 2.0.51](../_reset/metadata-refusal-focused-sa20-20261019.json). The full suites
report **1,316 passed, 2 skipped**
([2.1.3](../_reset/metadata-refusal-full-sa21-20261019.json)) and **1,288 passed, 30 skipped**
([2.0.51](../_reset/metadata-refusal-full-sa20-20261019.json)).

## Next steps

1. Extend the probe to compression, RLS, rules, triggers, table options and partition
   bounds; compression needs built-in lz4 support.
2. Capture the refused facts at compile time and restore them in the reverse switch.
3. Only then propose a lock version, canonical bytes, digests, and the reader matrix.

## Open questions

- Physical column order needs a table rewrite. Does any safe rewrite meet the
  near-zero-downtime requirement?
- Do ACL digests suffice, or does the lock need full grant statements?
- How are role names mapped on a fresh cluster with different principals?
- Which object kinds (partitioned tables, extensions, sequences) stay out of scope?
- Can storage and compression be set on admitted `text` columns without data rewrite?
