# Application and artifact qualification

Use [local development](local-development.md) for prerequisites and the full CI commands.
This page owns optional application/profile selection. Skips and old receipts do not qualify current code.

## Installed baseline

The release harness runs the built wheel through ORM/DML controls and the shared
initialization/Doctor context, including refusals, read-only database observations,
cleanup and output failure. These checks run on a fresh PostgreSQL 16 cluster.
Real OpenBao and independent PostgreSQL recovery follow in separate stages.
The installed shared configuration runs all three rotation workflows, native
write capture, empty-tenant publication/cancellation and current-value removal.
The actual OpenBao journey also covers capture/onboarding through AppRole;
native mappings are rebuilt for plaintext application reads after removal. A dedicated `fresh_cluster_qualification.py --application-config`
profile restores a retained TEXT backup, plans rotations against its explicit
restore binding and removes protection after current edits. CI runs this profile
as well as the keyword/public-slot recovery profile and retains separate receipts.
Use [local development](local-development.md#automated-checks) for the complete command.

### Receipt outcome fields

Receipts also record `pytest_report_counts`. It separates ordinary `test_calls`,
`subtest_calls`, `setup`, `teardown`, and failed/skipped `collection` reports.
Each bucket counts final raw pytest outcomes. `selected_items` counts collected
items after selection, including items whose setup prevents a call.
Keep these buckets separate. Their sum is not a test count.

Expected failures retain raw skipped outcomes. Non-strict unexpected passes
retain raw passed outcomes. These fields do not reproduce terminal categories.
The legacy `counts` and `modules` retain their original call/error aggregation,
which includes subtest calls and omits collection/setup skips.
The counter checks run with pytest 9.1.1 and its built-in pytest/unittest subtests.
Other versions and external report plugins remain unverified.

### Pinned external application check

`tests/test_smolink_application.py` extracts Smolink revision
`498d24bae999ed53ad85e1c1f1a09ea7fa151aa4` from a local checkout with Git.
It never imports the checkout's working files or settings file.
It checks source hashes and import origins before recording adoption evidence.

Use a separate Python 3.13 interpreter with Smolink's dependencies and Cryptalis.
Install no package into the application checkout for this test.
Supply an available `redis-server` executable. The test starts a disposable server
on a private Unix socket. PostgreSQL access still uses both fresh private files
through the mandatory wrapper.

```bash
CRYPTALIS_SMOLINK_CHECKOUT=/path/to/smolink \
  /path/to/python3.13 scripts/test_postgres.py -- tests/test_smolink_application.py -q
```

An explicit opt-in fails if its interpreter, packages, source revision, or services
are unavailable. Without the opt-in, the ordinary suite skips this external test.
The [status record](history/implementation-2026-10.md#pinned-smolink-adoption-2026-10-22) names the two tested
dependency cells and their limits. The workload protects only `Url.destination`.
HTTP covers URL creation and refusal cases. Repository and ORM calls cover other CRUD operations.
The host replaces the session dependency and supplies protection policy and maintenance authority.

### Automated application qualification matrix

Run the online HTTP row through `scripts/online_qualification.py --http`.
Use `--http-fresh` for its protected export, source-cluster shutdown and new-cluster recovery.
Run the other selected rows through `scripts/fresh_cluster_qualification.py`.
The fresh-cluster harness runs export and isolated restore through `scripts/test_postgres.py`.
The online harness creates three private role files on an isolated cluster and probes all three before the application test.
The `fresh_cluster_qualification.py` phases reload two private files and probe both roles.
All `online_qualification.py` phases reload three private files and probe all three roles.
If a probe fails, stop. Do not retry or substitute a database.
Use the pinned snapshots and the exact dependency cell recorded in status.
Keep each work directory new. The installed qualification runner must resolve
Cryptalis imports from the reviewed wheel instead of the source checkout.

| Row | Profile | Application journey | Evidence boundary |
|---|---|---|---|
| Tenant-scoped online lifecycle | `online_qualification.py -- tests/test_online_tenants.py -q` | Native capture and tenant moves, scoped uniqueness, protected backup, source-schema decommission, adoption, all rotations and current-data native exit | Synthetic mixed-scope SQLAlchemy fixture; second database on the same cluster; in-process development custody. Source and installed evidence remain separate |
| Original online HTTP fresh recovery | `online_qualification.py --http-fresh` | Online adoption, protected backup, checked source shutdown, fresh restore/adoption, root/payload/search rotations, original HTTP and latest-value native exit | 26 unchanged files, three freshly probed roles per cluster, reconstructible public custody. No production fencing or pause claim |
| Original HTTP online adoption | `online_qualification.py --http` | Concurrent original signup, native HTTP during capture, fenced cutover, protected HTTP/search, latest-value reverse and package-free HTTP restart | 26 unchanged pinned files. Three roles. No backup/rotation repeat or production downtime qualification |
| Original HTTP/authentication | `--sqlmodel-http` | Native routes, Doctor, protection, search, backup, fresh adoption, root/payload/search rotation, latest-value removal, package-free HTTP restart | 26 pinned files. TestClient and loopback SMTP. Explicit single tenancy and public fixture keys |
| Original SQLModel CRUD | `--sqlmodel-public-slots` | Three protected fields, public slots, fresh adoption, direct restore-binding search rotation, native exit | Six pinned files. Positive control for the shared harness |
| Original Smolink | `--smolink` | Async URL routes/repository operations, protected backup, fresh adoption, rotations and native exit | Separate pinned revision and historical qualification. No new execution claim follows from the HTTP row |

Supply `CRYPTALIS_SQLMODEL_HTTP_SOURCE` for the HTTP row.
Supply `CRYPTALIS_SQLMODEL_APP_SOURCE` for the CRUD row.
Supply `CRYPTALIS_SMOLINK_CHECKOUT` and a local Redis executable for Smolink.

```bash
CRYPTALIS_SQLMODEL_HTTP_SOURCE=/path/to/pinned-http-snapshot \
  /path/to/python3.13 scripts/fresh_cluster_qualification.py \
  --sqlmodel-http --workdir /tmp/cryptalis-http-fresh-new-run
```

The integer recovery row also accepts `--integer 32 --column-name integer`.
This keeps the Python property while exercising PostgreSQL's keyword identifier
spelling through payload rotation, backup, fresh adoption and current-data exit.
Add `--public-slots` for original column-position preservation and
`--installed-wheel /path/to/reviewed.whl` to bind both phases to that artifact.
Use its installed interpreter with an empty `PYTHONPATH`. See the
[keyword recovery boundary](history/implementation-2026-10.md#keyword-identifier-fresh-recovery-2026-10-28).

The earlier original HTTP CLI journey owns initialization and five actual
SIGKILL/resume checkpoints. The new HTTP fresh row owns genuine restore and
post-adoption authentication. Neither row proves every step or an external KMS.
Retain these separate boundaries when reporting the full developer journey.
