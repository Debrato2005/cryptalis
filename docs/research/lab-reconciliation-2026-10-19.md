# Research-lab reconciliation: 2026-10-19

**Status: research only.** This note records what the external research lab contains at
commit `123bcea`. It does not adopt code, tests, formats or claims. No lab experiment is
promoted. All seven production gates remain UNKNOWN.

Repository: `https://github.com/debgh-workspace/cryptalis-research-lab`
Commit: `123bcea` "Record six-worker mandate and pending S16 qualification without
promotion". The previous promoted runtime is S14. S16 is **held**.

## S16 counts

| Cell | Result |
|---|---|
| SQLAlchemy 2.1.3 | 2047 passed, 7 failed, 0 skipped |
| SQLAlchemy 2.0.51 | 2029 passed, 7 failed, 18 skipped |

The same seven assertions fail on both cells. They are not product regressions in this
repository. They are **RED tests for an unintegrated lab experiment**.
The failing module is `candidate/tests/test_deprotection_ordinals.py`:

1. `test_reverse_refuses_unhandled_public_suffix_comment_before_staging`
2. `test_changed_public_staging_refuses_switch`
3. `test_public_copy_participates_in_chunk_byte_bound`
4. `test_reverse_refuses_unhandled_suffix_attributes[column_grant]`
5. `test_reverse_refuses_unhandled_suffix_attributes[statistics]`
6. `test_reverse_refuses_unhandled_suffix_attributes[storage]`
7. `test_reverse_refuses_unhandled_suffix_attributes[compression]`

## What the lab experiment covers

The module tests a reverse design that keeps public plaintext "suffix" columns and a
`_copy_` staging layout. It expects these behaviors:

- Native `SELECT *` column order is preserved through reverse.
- A public-copy tamper refuses the switch with `public_copy_verification_failed`.
- The chunk byte bound includes the public copy (`row_exceeds_chunk_byte_limit`).
- Unhandled suffix metadata refuses **before staging** with
  `unsupported_reverse_suffix_metadata`, and the error text says "Keep protection
  enabled".
- An old staging layout without `layout_version` refuses with
  `reverse_staging_layout_requires_inspection`.

S16 does not include the implementation, so the module fails. That is the recorded
"same 7 legacy profile assertions".

## Reconciliation with this repository

This repository uses a different reverse design: companion staging columns, an in-place
switch, and recorded constraint/index definitions. The lab's suffix design is not a
drop-in replacement and was not reviewed here. Do not port the module or the branch.

The safety signal is still useful, but the surfaces differ. The lab refuses metadata on
the retained public suffix column. Our 2026-10-19 probe shows silent loss for the
protected column: comments, statistics targets, storage, compression and column ACLs are
lost, and `_metadata_diff` reports no difference. Both cases share one requirement: when
reverse cannot preserve metadata, it must refuse explicitly instead of dropping it.
The correct product response is one of two explicit choices:

1. Capture and restore the metadata under a versioned, digest-bound artifact, or
2. Refuse reverse before staging when the lock does not cover observed metadata.

Option 2 is smaller and matches the explicit-failure policy. This repository implemented
option 2 on 2026-10-19 for protection planning and switches, and for reverse planning,
without a lock change. Option 1
(capture and restore) remains a reviewed format change.

## Other lab state

- **B2 REVERSE-PREDECESSOR-01:** a corrected branch reports 94 passed on the affected
  SA2.1 suite and 31 passed on SA2.0. The lab calls this internal review, not independent
  review. Not integrated.
- **C2 ORDER-TEXTUAL-LABEL-01:** corrections continue. A `TypeCoerce` wrapper gap
  reproduced 12 failures and 18 passes. No protected ordering support is promised.
- **E review:** the unprojected protected FROM-label ordering hypothesis is held. No
  confirmed result.
- **Fresh-cluster credentials:** approval remains PENDING in the lab.
- **Build evidence:** wheel and sdist rebuilt identically; package-origin check matched
  all modules. Real FastAPI replay was in progress. These are lab claims, not evidence in
  this repository.

## Next steps

1. Keep option 2 as the interim fail-closed guard. Option 1 (capture and restore) needs a
   reviewed format change.
2. Extend the product probe to compression, RLS, rules, triggers and partition bounds.
3. Re-check the lab at the next checkpoint. Promote nothing without independent review
   and the seven gates.
