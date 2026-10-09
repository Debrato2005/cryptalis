# Scope-recording assumptions: 2026-10-08

This file records interpretation only. Existing owners define the contracts. All assumptions below are SPECIFIED, not executable evidence.

- Six-gate admission means the six technical gates G-ADAPTER/G-CRYPTO/G-QUERY/G-LIFECYCLE/G-PROVIDER/G-POLICY. G-RELEASE remains an additional release requirement.
- The seven build slices differ from full qualification gates. A PostgreSQL-tested slice permits the next slice, without promoting any full gate.
- Equality/IN do not implicitly admit `!=`, NOT IN, protected joins, grouping, or a spike's COUNT DISTINCT rewrite. Unadmitted grammar fails safely.
- Application-generated IDs include explicitly assigned numeric IDs. Historical sequence preallocation remains spike evidence and conflicts with the approved contract.
- The 2× storage target compares the protected column plus equality index with the matched plaintext column plus equality index. Whole-table ratios do not prove it.
- Finalization means explicit retirement of recovery dependencies through the existing lifecycle. Finalization adds no command, mode, timer, or live plaintext mirror.
- No decision selects a production provider or trusted publication/restore procedure. Provider, policy, and independent review requirements remain UNKNOWN.
- Exact public tenant-declaration syntax belongs to the compiler slice. This pass records the required declaration without inventing a frozen API.
- This pass invents no numeric small-domain threshold, write-throughput budget, pause budget, or CPU/memory budget. Existing non-scope security decisions remain unresolved.
- Historical receipts and archive claims keep their recorded revisions and scope. Neither cost receipt measures the latest DISTINCT rejection.

This pass keeps existing local changes and edits only documentation. The user reviews the uncommitted changes.

## Slice 3 checkpoint: 2026-10-08

- IMPLEMENTED: bounded `cryptalis.sqlalchemy.attach`, sync/async ORM storage, context projections, and guarded public driver routes.
- VERIFIED: main-thread native comparisons; 41 adapter cases and 777 full-suite cases on restricted PostgreSQL 16.15.
- The withheld output was unavailable in the main-thread context. Its findings supplied no relied-upon evidence.
- Cache regression used an isolated current-source/test copy. Native sync/async entity/scalar: 4 passed without the fix. Attached: 4 failed. Restored copy: 8 passed.
- Defensive checks retained and strengthened: valid-frame tenant/row context, driver-bind privacy, unsupported-query refusal, real cancellation/rollback, failed flushes, and mapping mutation.
- No security contract changed. The cache proof left the original source unchanged. Existing work was preserved with focused corrections.
- Native controls found and checked fixes for expired context, single-tenant outer joins, Python default mappings, and schema-specific row preparation.
- Defensive checks now reject ambiguous columns, alternate protected mappings, target/catalog mismatches, and attachment with existing native connections.
- Async cancellation before key preparation completes leaves PostgreSQL unchanged. Real database cancellation and recovery retain native behavior.
- [Verification receipt](slice3-verification.json) records commands and hashes. [Profile receipt](slice3-performance.json) records bounded costs and limits.
- The historical million-row plaintext-page anomaly remains UNKNOWN; the current small profile cannot explain it.
- BLOCKED advancement: separate non-owning runtime credentials are absent. Fixture-owner tests do not prove privilege isolation. No roles or permissions were added.
- Next run: finish slice 3 with provisioned restricted runtime credentials, native CRUD controls, and DDL/ownership refusal evidence. Then start slice 4.
- All seven full gates remain UNKNOWN. No production provider, independent review, authenticated deployment procedure, commit, or push.

## Slice 4 checkpoint: 2026-10-08

- IMPLEMENTED: exact-text equality/IN through full CF1 keyed terms and built-in expression indexes; native tenant-scoped uniqueness.
- VERIFIED: 75 real PostgreSQL search cases, four frozen query-term vectors and 864 full-suite cases. Owner setup and non-owning runtime application paths remain separate.
- Fifteen isolated protection removals fail their oracle-backed tests; copied originals restore passing results without changing the worktree.
- The final million-row source is hash-stable. Added p95 is 2.336 ms point, 2.561 ms equality and 3.005 ms IN-20; isolated column/index storage is 1.4928× native.
- Real key expiry stopped an earlier seed. Bounded rollback/retry preserves the lease and recovered one final chunk. Expiry failure/recovery also has sync/async PostgreSQL evidence.
- Read-only spike source inspection corrects the old plaintext-only page label: its filters are plaintext but its entity includes protected email. Historical cause remains UNKNOWN; the old receipt is retired as current-product evidence.
- [Verification](slice4-verification.json), [performance](slice4-performance.json) and the [60-line walkthrough](../walkthrough-search.md) record the exact local boundary.
- Independent writers can hide matches or replay values. Fresh-deployment key/policy binding and writer exclusion remain unqualified; grants do not prove them.
- Existing work and all 60 hashed spike files are preserved. No slice 5, commit or push. All seven gates remain UNKNOWN; no production provider or independent review exists.

## Slice 5 checkpoint: 2026-10-09

- IMPLEMENTED: maintenance `plan`/`apply`/`verify`, atomic PostgreSQL journal chunks, full value verification, publication-gated switch, and pre-switch abort.
- VERIFIED: 53 migration cases within 917 suite cases; 20 isolated safety removals fail and copied restorations pass.
- Fresh private probes passed for both roles. Application sync/async CRUD uses the restricted runtime role; owner credentials perform setup and transitions.
- Process kills, real lost replies, corruption, concurrent paused writers, an older own-schema snapshot restore, and metadata/authority refusals have scoped evidence.
- Final million-row backfill: 3,942 rows/s; writer pause: 508.7 s. Earlier source: 11,559 rows/s and 197.0 s; variation cause UNKNOWN.
- Fixed storage/WAL guesses were replaced with explicit host observations. Measurements are not bounds or an approved pause ceiling.
- SQL switch drops the original column. No live plaintext rollback mirror remains; heap tuples, WAL, snapshots and backups can still contain plaintext.
- Host writer exclusion, pin provenance, restore quarantine, production provider, real exhaustion, retained-backup recovery and independent review remain unqualified.
- All seven gates remain UNKNOWN. No slice 6/7 implementation, spike edits, commit or push. [Receipt](slice5-verification.json) owns the evidence boundary.

## Step 0 protection-pause checkpoint: 2026-10-09

- Uninterrupted protection now verifies and switches in one transaction. Saved VERIFIED checkpoints still require a fresh pass and unchanged digest.
- Native EXCLUSIVE lock tests allow plain reads and block writes/locking reads. DDL lock timeout preserves source data and the BACKFILLED marker.
- Printing the plan shows native row count, measured rates, and an uninterrupted pause estimate. Extra passes, drain, DDL, indexes, and publication are excluded.
- [Verification](step0-verification-c72bb439d7e13334.json): 982 passed. [Regression proofs](step0-regressions-c72bb439d7e13334.json): seven targeted removals fail/restoration passes; the original engine gives six failures/one pass.
- Twenty prior migration safety removals still fail/restoration passes. The tag attack now changes a bit unconditionally.
- No new million-row timing or slice 6/7 work. Timing variation, production provider, independent review, and all seven gates remain UNKNOWN. No commit or push.
