# Cryptalis 0.1.0a1 — internal installed-library checkpoint

**Draft only. Do not publish this release or upload to a public package index
without explicit approval.** The single comprehensive public-release policy
remains active. All seven production gates remain UNKNOWN.

The MIT-licensed Python library installs independently of Smolink or a proxy.
CPython 3.12/3.13, PostgreSQL 16, SQLAlchemy 2.1.3 and psycopg 3.3.6 define the
selected cell. The public Project API and CLI orchestrate the existing bounded
protection, attachment, rotations, recovery and latest-value removal workflows.
[Compatibility](../docs/compatibility.md) defines exact operation/type limits.

Frozen library: `v0.1.0a1`, commit `655d52271d90effb4df918a9547f61c89055fbc7`.
Both jobs in [run 41280665577](https://github.com/Debrato2005/cryptalis/actions/runs/41280665577)
pass at its PR merge commit. All 323 inventoried Python files and 52 build inputs
separately match the frozen library head. Hosted artifacts exactly match local
repeat builds. Eight clean pip/uv × wheel/sdist × Python 3.12/3.13 installs pass.

| Reviewed distribution | SHA-256 |
|---|---|
| cryptalis-0.1.0a1-py3-none-any.whl | eedecae8fd72a06bdf8ed95bd0aae377cabdfd51df325c50463f4f4f4b65060a |
| cryptalis-0.1.0a1.tar.gz | 7e64f4a36a6ddc6ab4a5693d326f41f8b7aadf97bcee670ead437bd99e4eb077 |

The separate [Smolink demonstration](https://github.com/Debrato2005/smolink/blob/269aed4bcfcbbf40ffea444f2e2a748013c862d4/cryptalis_demo/REPORT.md)
uses unchanged original routes/models, the installed wheel, real PostgreSQL,
Redis and TLS OpenBao. It proves ciphertext observation, current edits, wrapping
and payload rotations, source-stopped fresh restore, latest-value removal and an
environment without Cryptalis serving the original API. Supplemental independent
backend journeys cover equality/IN/uniqueness and distinct search rotation.

Measured point-read added p95 is **4.849 ms** at concurrency 1: the 3 ms target is
**missed**. Destination bytes are 1.5114× native; observed total relation/index
allocation is 2.5987×. Smolink destination search is storage-only, so encrypted
equality/IN-20 and indexed-storage targets remain unqualified. These are local
warm ASGI measurements with raw samples, explicit resource/ordering limits and
separate real-network Swagger evidence. No matched competitor benchmark ran.

Installation, operator procedures, API reference, security limits and
troubleshooting start at [the installation guide](../docs/installation.md).
Independent human review, real production provider/deployment evidence, broader
queries/types, performance and all remaining objectives stay open.

Attach only the reviewed wheel, sdist, SHA256SUMS, SBOM and sanitized build/install
receipts. Keep application demonstration reports in the separate application
repository and keep all credentials, raw backups and recovery keys private.
