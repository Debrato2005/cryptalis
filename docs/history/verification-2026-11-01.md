# Pruning verification: 2026-11-01

Base revision: `af0166acac6149ff368e7ed04fb99b2978b1d86b`.
This follows the [incomplete earlier audit](completion-2026-10-31.md#partial-mutation-check-of-the-pruned-suite-2026-10-31).
The [machine boundary](../_reset/pruning-audit-boundary-20261101.json) binds the
test changes and [receipt archive](../_reset/pruning-audit-receipts-20261101.tar.gz).
Current capability and remaining gates belong to [status](../status.md).

## Method and results

The ten original mutation recipes were recovered from the earlier run. Each is
applied alone to a separate Git snapshot and restored after its process exits.
The existing PostgreSQL 16.2 target and fresh private role files are used through
`scripts/test_postgres.py`, on Python 3.13.12. Tests run sequentially to avoid the
earlier memory pressure. No runtime implementation changes reach `main`.

The healthy baseline passes 79 tests and 18 subtests without skips. The final
Project module passes 70 tests, with seven setup skips for unavailable source-role
profiles. No skipped profile is qualified. All completed receipts report stable
source and imported runtime bytes during their own run.

| Disabled check | Final observation |
|---|---|
| Sealed-value tenant at the driver | Survives 22 native driver-boundary cases; unresolved |
| Parameter logging refusal | Related admission subtests fail |
| One-tenant rule for sorting | Unsupported-query regression fails |
| Malformed saved plan refusal | Strengthened Project status regression fails before database access |
| Plaintext consent | Public application lifecycle regression fails |
| Removal approval | Application lifecycle and removal regressions fail |
| Restore approval | Adoption approval regression fails |
| Small search-domain refusal | Compiler security-evidence regression fails |
| State-file privacy | Project privacy regression fails |
| Invalid session tenant before shared-policy lookup | New public attachment regression fails |

The saved-plan check now edits a real protected Project's persisted plan and
requires typed rejection before a database connection. The tenant check uses a
mixed shared/tenant deployment without the unavailable online source-role fixture.
It observes no policy callback for an unknown tenant, and proves the observer
works by requesting a known tenant. Existing lifecycle and native data controls
remain in place.

## Limits and retained failures

The sealed-value guard still exists. Its values are frozen and admission also
checks ownership, record context and exact prepared bytes, but this audit does
not prove the surviving mutation equivalent. Nine detected mutations are bounded
evidence; they do not establish that every deleted test was redundant or that
the product is secure. All seven production gates remain UNKNOWN.

Initial focused runs exposed the two missing regression scenarios; the old
online tenant test skipped because its source role was unavailable. Those
receipts remain in the archive. A first snapshot attempt lacked Git metadata and
stopped before pytest; metadata for the exact base revision was added. An initial
version of the new regression attempted a second attachment to the same guarded
engine and correctly failed `UnsafeDriverEvent`; a fresh fixture resolves that
test setup error. Its failed receipt is retained alongside the final passing runs.

The archive includes recipes, runner scripts and public machine receipts. It
excludes private role files, database files and raw service logs.
