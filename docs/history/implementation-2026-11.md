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
