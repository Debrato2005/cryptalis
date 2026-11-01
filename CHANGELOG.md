# Changelog

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
