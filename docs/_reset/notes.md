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
