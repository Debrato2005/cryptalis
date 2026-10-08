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
