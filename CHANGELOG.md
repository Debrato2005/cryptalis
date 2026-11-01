# Changelog

## 0.1.0a2.dev2 — development

- Security: final SELECT admission no longer accepts a statement replaced after
  admission, including one that would send a plaintext comparison value. This also
  affects `0.1.0a1`; exploiting it needs code inside the host process.
- `insert().values(...)` is admitted with its native result, and PostgreSQL
  `ON CONFLICT DO NOTHING` and primary-key `DO UPDATE` are admitted within the
  [bounded upsert](docs/compatibility.md#bounded-upsert) contract.
- Protected reads repeat less work, with every check retained: warm p50 is about
  20–27% lower in a local diagnostic.
- `examples/quickstart.py` runs the complete lifecycle from the installed package,
  in separate processes, ending with a restart that cannot import Cryptalis.
- `DevelopmentKeyProvider(path)` keeps synthetic-data custody in an owner-only key
  file, so a new developer can restart without running an external provider.
- `UnsupportedProtectedOperation` names the protected fields in the refused
  statement and what each declares, without values. `Project.decrypt` explains a
  reused runtime role before planning; `PolicyMismatch` mentions the restart rule.

- Single-record mapped UPDATE accepts reusable native binds for the record,
  tenant and assigned values, including bind defaults and execute-time overrides.
- Ordinary literal and named SET values can share a statement. Existing
  encryption, row authority, native results and transaction handling are reused;
  incompatible bind behavior refuses before key preparation.
- JSONB SET binds retain their own NULL mode. Input changes during synchronous
  or awaited preparation refuse before UPDATE dispatch.
- No ciphertext or lock format changes. Production qualification remains open.

- Public-table mapped DELETE accepts direct and explicitly named column RETURNING
  through sync/async SQLAlchemy and SQLModel, preserving native transactions and
  result keys. Test isolation and cancellation diagnostics retain safe failures.

## 0.1.0a2.dev1 — development

- Whole-document JSONB equality, IN and scoped uniqueness reuse full blind-index
  terms, with lock/v17 reader admission and explicit leakage/domain review.
- Nested numeric scale is ignored for search while payload bytes stay lossless.
  Native JSONB bind typing, both NULL modes and provider-time input mutation
  checks are retained through lifecycle operations.
- SQLAlchemy DBAPI/connection failure reports retain validated SQLSTATE and repository location while
  suppressing SQL, parameters, driver messages and credential diagnostics.
- JSON path/containment search and production qualification remain open.

## 0.1.0a2.dev0 — development

- Native JSONB literal client defaults retain omission/NULL behavior, Python
  values until refresh, and the existing encrypted lifecycle. New default-bearing
  locks require v16 and `pg-jsonb-default/v1`; no-default JSONB keeps v15.
- Mutable default configuration is checked against its pinned literal. Generated
  defaults and JSON search remain unadmitted. Production gates remain UNKNOWN.
- The frozen 0.1.0a1 preview and its separate Smolink evidence remain unchanged.

## 0.1.0a1 — unreleased research preview candidate

- Package metadata labels the candidate Alpha and limits Python to the selected
  CPython 3.12 and 3.13 cells. PostgreSQL 16, SQLAlchemy 2.1.3 and psycopg 3.3.6
  remain the selected stack.
- The public `Project` API and CLI expose the existing bounded protection,
  attachment, policy-change, rotation, recovery and current-data removal flows.
  The [compatibility matrix](docs/compatibility.md) owns exact behavior and limits.
- Reproducible wheel/sdist inspection, installed-byte checks and CycloneDX SBOM
  reuse the existing packaging system. Demonstration applications and reports
  remain outside the distributed package.
- Added installation and release preparation guidance. The
  [current status](docs/status.md) owns exact verification, failed targets and
  remaining evidence. All seven production gates remain UNKNOWN.

This candidate is not a public package-index release. No production security,
universal SQL compatibility or comparative performance claim is made. The full
34-objective product remains in development.
