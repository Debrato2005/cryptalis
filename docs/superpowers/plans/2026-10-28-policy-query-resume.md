# Policy and query continuation: preserved resume point

> Historical plan. Current work is routed by the [objective ledger](../../BUILD_CHECKLIST.md) and [documentation map](../../README.md). Task-time instructions below do not override current user authorization.


The verified continuation branch contains the SDK cell and the completed early
tenant-resolution guard. All 34 objectives and all seven UNKNOWN production
gates remain. The release is unfinished.

Specialist turns stopped with an account usage-limit error. No unverified policy
or aggregate implementation was promoted. The remaining work is preserved at:

- Branch: `wip/policy-count-unverified-20261028`.
- Commit: `7c0dd6bbec01c722cb18ca961caddf5cdf6896d7`.
- Base: `d7f2dbaa266a9561576ab7e9e8a03263c2a1396f`.
- Existing worktree: `/workspace/.cryptalis-cloud/policy-count-wip`.
- Bundle: `docs/_reset/policy-count-unverified-20261028.bundle`.
- Bundle SHA-256: `91390b3a868ae3ddca6d35d1ef509f685a7482ef9077eda58d5f0b2d264a3449`.

The bundle passes Git verification and requires the already pushed base commit.
If the local branch is absent, inspect and fetch it without force:

```sh
git bundle verify docs/_reset/policy-count-unverified-20261028.bundle
git fetch docs/_reset/policy-count-unverified-20261028.bundle refs/heads/wip/policy-count-unverified-20261028:refs/heads/wip/policy-count-unverified-20261028
```

Use the existing worktree when present; otherwise create a new isolated worktree
for that branch. Read current AGENTS.md and canonical contracts first. Reconcile
the already completed SDK profile and early UUID/membership guard rather than
repeating or overwriting them. The WIP branch contains those earlier deltas too.

## Tenant policy provisioning — unverified

Files include new `src/cryptalis/tenancy.py`, lifecycle/access/restore/rotation
hooks, new `tests/test_tenant_provisioning.py`, and the existing tenant HTTP
host/source/restore profiles. Proposed strict successors v15/v16 add one explicit
host-approved empty tenant while preserving all prior policy digests, lock,
schema, access contract and frames. Reuse existing maintenance locks, source
SUPERSEDED/new PENDING state, externally retained publication/ACTIVATING pin,
inspected retry and cancellation. Verify all rotations, restored adoption and
latest-data exit with the enlarged key set. Initial O(N) frame verification and
global writer pause are explicit unqualified costs, not scalable signup support.
The source admission UUID guard has since been completed separately.

## Count reporting — unverified

Files include declaration/compiler changes, new `_sqlalchemy_aggregates.py`,
aggregate SELECT admission and `tests/test_count_reporting.py`. Proposed
declaration/v2 separates aggregate consent from search intent; lock/v9 and exact
reader tags must preserve v1 canonical bytes. Cover COUNT presence for supported
types and COUNT DISTINCT only for declared text equality, plus finite FILTER,
public grouping/key joins, HAVING and pagination. Prove each protected alias's
original tenant constraint before keys. Keep outer-join empty groups native.
No hidden filtering, full decryption scan, general protected GROUP BY or extra
search representation is permitted. Counts retain the existing unauthenticated
cardinality/completeness boundary; they do not authenticate every stored frame.
Already-ACTIVE permission changes need a separately verified successor path.

## Performance — no integrated patch

The valid 10k wrapper observation misses the equality target at 3.5577 ms added
p95. Full profiling identifies repeated traversal across three required admission
boundaries. A local per-admission graph memoization candidate was slower and was
reverted; its security checks passed, but it is not a performance fix. The
isolated profiling worktree is clean. A later execution-context/template-cache
architecture investigation was stopped by the same usage limit. Never cache
per-result keys, weaken lease/context proofs or skip an admission boundary to
meet a benchmark. Preserve failed observations and measure any future candidate.

## Resume verification

Do not assume the WIP imports, tests or new formats work. Read its current code
and saved receipts, establish RED/affected source evidence through the mandatory
wrapper, then finish each capability with native application/lifecycle oracles.
Use unique receipt paths. Keep actual installed-wheel and historical-reader
proof separate. Independent human review, live KMS authority, production policy
publication/fencing, cost admission and controlled release remain required.
