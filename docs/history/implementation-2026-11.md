# Implementation observations: November 2026

Current contracts belong to [compatibility](../compatibility.md),
[security](../security.md) and [lifecycle](../lifecycle.md).
[Status](../status.md#current-orm-boundary) owns the latest verification.
These observations do not qualify production or replace independent review.

## Parameterized single-record UPDATE: 2026-11-01

Development `0.1.0a2.dev2`, based on JSONB equality commit `4d1daa5`, resolves
ordinary record/tenant and SET binds into the existing guarded point executor.
The original statement and result-label objects remain reusable. Defaults,
execute-time overrides, mixed literal/named assignments and physical-key direct
assignments retain native behavior within the explicit bind contract. JSONB
SET binds preserve their own NULL modes. No ciphertext or lock format changes.

Review identified a native correctness defect in the initial normalization:
different binds sharing one name could be resolved independently, while native
SQLAlchemy merges their placeholder. The corrected route refuses repeated
effective names before keys, including context/SET collisions and inferred
physical assignments. Native controls observe zero matches for shared record/
tenant names and joint SET values for shared defaults; protected refusal leaves
stored bytes unchanged and permits a healthy request afterward.

Direct SQL-hook checks and snapshots now use captured native defaults, including
decorator implementations. Datetime observations capture structural fields and
timezone identity without invoking an unsupported timezone callback. Explicit
PostgreSQL TIMESTAMP precision-six binds retain the existing native admission.
The bounded native corpus covers SQLAlchemy sync/async, a renamed fixed-scope
SQLModel journey, signed-int64 identities, all admitted scalar bind families,
JSONB NULL typing, nested mutation during await, final driver mutations,
RETURNING keys/types, stale identity/refresh, savepoints and current-value exit.

### Retained verification observations

- The first focused run passed 150 calls and failed two existing mutation
  fixtures. They selected generated parameter names that normalization changed,
  so neither reached its injection. Value-based selectors retain the intended
  record/tenant mutation; all four final driver cases pass.
- The first review-control run passed 155 calls and failed two test assertions.
  A Text-specific class-hook patch is ignored by the pinned psycopg dialect's
  Text-to-String adaptation; the corrected native control patches String and
  observes uppercase values through a fresh dialect. The timezone control had
  incorrectly forbidden key preparation, although value assignment validation
  follows it. It now requires typed refusal, no offset callback, no UPDATE and
  no callback-detail leak. All 23 final new controls pass.
- The first complete source run passed 4,027 calls plus 18 subtests and failed
  four UPDATE variants of the existing named-result oracle. The new snapshot
  had rejected native anonymous RETURNING labels. A dedicated label snapshot
  now validates the original label through the existing projection contract,
  preserving its native name type/spelling/quoting and original object. Physical
  column/schema names retain strict validation. The affected label and new-bind
  corpus passes all 76 calls.
- Initial repeat-built dev2 distributions and two clean installs passed before
  that anonymous-label fix. They are retained privately as superseded artifacts;
  final package evidence must bind the corrected runtime.

The [machine boundary](../_reset/point-update-parameters-boundary-20261101.json)
and [receipt archive](../_reset/point-update-parameters-receipts-20261101.tar.gz)
retain final results and earlier failures. Source/runtime hashes are authoritative
for each run; earlier snapshots do not silently inherit a later pass.

Final complete source verification passes 4,031 calls plus 18 subtests with
26 call, 41 setup and nine collection skips. Python 3.12.16 and 3.13.12 each
pass 364 installed calls without skips on separately generated private-role
clusters. All 328 Python inputs, 52 build inputs and stable 45-module runtime
bytes match the final package. Repeat artifacts, SBOM, hashed fresh installs,
dependency checks, 50 installed-file checks and CLI inspection pass.

Final wheel SHA-256 is
`d779522b9fa89ed8642f07b2181e0ad8df64c486a11e9c6f5550c70fb3cc80b3`;
sdist SHA-256 is
`a7b86eec49a650c480d1fc2526b70c62fef7bf3b7ba39ec78912516d4a0a4cd3`.
The 33-file receipt archive SHA-256 is
`b2d88a2b3b053613032d54b02be342fd52f57acb2434de701127473aa32305c7`.
All final test clusters stopped. The refreshed code graph is navigation only.

These fixtures use synthetic values and public fixture key custody. They do not
qualify production providers, deployment fencing, performance, arbitrary SQL or
independent human review. Broader DML/upserts/expressions and all seven production
gates remain open. The earlier VARCHAR InternalError and mutation survivor are
separate unresolved observations.


## Hosted parameterized UPDATE verification: 2026-11-01

The original push `41305071412` and PR `41305131672` workflows both pass for
implementation `1d4124b549bb8b36f9c5022c94c3f489d9da901f`. Each source run passes
4,030 calls plus 18 subtests; 27 call, 41 setup and nine collection skips remain.
Each installed set passes 1,251 calls with three earlier-reader skips. New bind
controls pass 23/23 and RETURNING-label controls 53/53 in both source and
installed receipts. All 24 release steps pass. All 328 Python inputs across 18
inventories, 52 build inputs, stable 45-module runtime and wheel/sdist match the
immutable implementation head and final local artifacts.

The push checkout is exactly `1d4124b`; PR checkout is merge
`af38ba735979a6669c543a7fd379537c70d2c397`, with the recorded source head and
`4d1daa5` as parents. Uploaded artifact ZIP digests match GitHub metadata. Clean
repeat builds pass. The [boundary](../_reset/point-update-parameters-hosted-boundary-20261101.json)
and [95-file archive](../_reset/point-update-parameters-hosted-receipts-20261101.tar.gz)
retain those bindings. Archive SHA-256 is
`066028fadd4a0a39591987b620c60e74229930a02572a0dbedeb5540f20a7649`.
Both original handles ended successfully; neither was rerun.

Existing fresh profiles cover JSONB defaults/equality in both layouts,
application recovery, integer public slots and search enable/disable. Project
recovery has a passing command result, but its dedicated phase receipts were
not uploaded. Google SDK/native-PostgreSQL checks pass 50 calls without a real
cloud account. Pinned OpenBao 2.7.2 checks pass 140 calls under the recorded
single-node TLS/Raft/audit/outage/restart/snapshot/PostgreSQL fixture limits.
Recovery children deny Cryptalis imports with the wheel still installed; no
package-uninstalled environment or distinct parameterized UPDATE-after-restore
journey follows. The separate old VARCHAR cause and all seven production gates
remain UNKNOWN. The follow-up changes only documentation and retained evidence.

## First-contact, admission and real-application continuation: 2026-11-02

A run from a fresh wheel using only public documentation found that a new developer
could not restart: the only built-in provider lost custody on exit. `Project` tests had
hidden this by sharing one provider object through a simulated restart. The same run
found the README omitted `hide_parameters=True`, refusals named no field, and nothing
said the plaintext role needs its own grants. `examples/quickstart.py` now exercises
this route in separate operating-system processes.

The first local regression at that point retains `Verification.SourceChanged`, because
`scripts/ci_qualification.py` was edited while the wrapper ran. Its 172 passes are not a
valid binding. The complete hosted run at `059f886` is the evidence for that commit.

A test written for a performance shortcut exposed an older defect. A statement replaced
by a host `before_execute` listener passed final SELECT admission and reached PostgreSQL,
which refused it with SQLSTATE 42883. A clean build of `09be1f6` behaves the same way, so
the shortcut did not cause it. Direct admission refused the statement while admission
inside the operation accepted it: compiling a protected predicate had registered its nodes
as generated, and final admission ran after compilation. [Status](../status.md#final-admission-no-longer-trusts-compilation)
owns the current result.

Review of the first shortcut draft also found two flaws before any test run. Its memo keyed
on `id(node)` without keeping the node alive, so a freed temporary could alias a live node,
and `None is None` could have skipped admission for a statement with no admitted SELECT.
Both were corrected, and the remaining hazard is documented where the memo lives.

The first Smolink pair, taken before the last admission memo, is retained only as the
post-rotation storage observation in `superseded/`. Its `native.json` predecessor ran
beside a test regression and is not used. The final pair alternates modes on two clusters.

Upsert first lost native results: re-entering the bulk route returned a null result
instead of a `CursorResult`. A native oracle exposed this, so `.values(...)` now stays in
SQLAlchemy's `orm` strategy. The same oracle corrected a wrong test assumption: native
INSERT reports `rowcount` -1 unless `preserve_rowcount=True`, which is now admitted.

Mutation evidence for the seven upsert safety checks ran in an isolated copy. The first
attempt printed SURVIVED for all seven, but the wrapper had crashed because the copy was
not a Git repository, and no test ran. That output is not evidence. The corrected script
reads outcomes from each receipt and reports NOT RUN when no call executed. All seven
mutants are then caught, each by the test naming it, with 20 calls per run. Earlier
mutation lessons held: the working tree was never modified.
