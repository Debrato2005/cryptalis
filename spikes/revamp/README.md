# Isolated revamp experiments

These are synthetic research experiments, not a Cryptalis runtime.
They use public lab keys and deliberately small frames. Never connect them to customer data or a production database.
No dependency installation or production source change is required in the recorded environment.
[Status](../../docs/status.md) owns capability claims. [Revamp evidence](../../docs/research/revamp-evidence.md) records scope and unfinished work.

## Integrated local candidate: 2026-10-07

The older experiments below use public lab keys. The new `integration_*` candidate uses random memory-only development roots
and actual bounded CF1 text frames. Both are research fixtures for the authorized disposable database.
No production provider, deployment procedure or independent human review is available; all seven full gates remain UNKNOWN.
The [current status](../../docs/status.md#current-integrated-checkpoint-2026-10-07) and
[semantic audit](../../docs/research/revamp-evidence.md#integrated-continuation-and-semantic-audit-2026-10-07) distinguish tested invariants from pending requirements.

With the private environment already supplied, run a required suite from the repository root:

```bash
spikes/.venv/bin/python spikes/revamp/run_gate_retrofit.py
spikes/.venv/bin/python spikes/revamp/run_gate_boundary.py
spikes/.venv/bin/python spikes/revamp/run_gate_async.py
spikes/.venv/bin/python spikes/revamp/run_gate_context.py
spikes/.venv/bin/python spikes/revamp/run_gate_lifecycle.py
spikes/.venv/bin/python spikes/revamp/run_gate_faults.py
spikes/.venv/bin/python spikes/revamp/run_gate_write_cost.py
```

The final counts are 51, 25, 14, 48, 23, 13 and 2 respectively.
Each receipt records safe outcome codes, implementation hashes and owned-schema cleanup; a failure exits nonzero.
Connections are pinned to `127.0.0.1:55432/cryptalis_test` as `cryptalis_migrator`.
Do not print or put the private URL into command arguments, diagnostics, files or commits.

Receipts: [retrofit](results/gate-retrofit.json), [boundary](results/gate-boundary.json),
[async](results/gate-async.json), [context](results/gate-context.json), [lifecycle](results/gate-lifecycle.json),
[faults](results/gate-faults.json), [current cost](results/gate-write-cost.json).
The lifecycle receipt also contains the fresh package-free child's 35 checks and actual lost-reply transport observations.
The frozen original three-model source and its 29 assertions remain unchanged; only one opaque writer is replaced in a temporary adapted copy.

The already completed [million-row actual CF1 receipt](results/gate-performance.json) has 3 passing checks and full paired application measurements.
`run_gate_performance.py` requires roughly 130 seconds of protection/verification pause plus load and cleanup in this local run.
Reuse that receipt unless representation/index/scale behavior changes. The 10,000-row cost run covers the later assignment-admission changes.
The [first failed scale receipt](results/gate-performance-first-failed.json) preserves the stale compiled VARCHAR-cast failure that required correction.
The existing 612-test and document/link/inventory receipts were not rerun in this final pass.

The planner rejects unknown/unexcluded writers, untested multi-field mappings and unsupported text/default/collation contracts before transformation.
Independent privileged connections remain unguarded. The fixture login owns the schema; non-owning runtime-role enforcement is pending.
The journal deliberately ends at `SWITCHED_DATABASE_POLICY_PENDING`; no external publication is invented.
Memory-only keys and fork-inherited recovery do not prove independent startup, durable backup recovery or production custody.
Advanced encrypted range/prefix, full SQL grammar, format upgrades, disk/WAL exhaustion and production budgets remain pending.

## SQLite experiments

Run each command from the repository root:

```bash
spikes/.venv/bin/python spikes/revamp/run_adapter.py
spikes/.venv/bin/python spikes/revamp/run_native_types.py
```

The first reports 28 passing cases and a raw-driver bypass negative control.
It rejects a same-ID ciphertext transplant between two logical fields.
It changes exact string type. The second preserves exact str through 13 public-parameter-preparation cases.
Neither provides a complete ORM grammar, raw/COPY boundary, async implementation or PostgreSQL driver test.
The scripts create disposable in-memory SQLite databases. JSON receipts are written under `results/`.

## Current authorized service

This section preserves the earlier service experiments. The integrated checkpoint above supplies the later retrofit evidence.

Use only the user-authorized disposable database through its protected environment configuration.
[probe_service.py](probe_service.py) validates that target without printing its URL. It creates no database objects.
Run the safe probe with the existing isolated interpreter:

```bash
spikes/.venv/bin/python spikes/revamp/probe_service.py
```

The earlier executor failed before authentication because TCP socket creation was blocked and the environment variable was absent.
On 2026-10-07, the user explicitly authorized a separate network-enabled workspace-write session for this disposable target.
The private launcher loaded the URL from an owned `0600` file. The probe then exited 0 with `CONNECTED_RESTRICTED_ROLE`.
A fresh Codex CLI shell repeated the result. [service-probe.json](results/service-probe.json) records the current sanitized observation.
The PostgreSQL plaintext baseline passed 29 checks and dropped its own synthetic schema.
This exception does not authorize global sandbox changes, another database, or weaker acceptance tests.
Three further service suites now provide narrow adapter, physical-query and lifecycle observations.
The complete protected original application still requires implementation and execution.

With the same private environment already loaded, run one suite at a time:

```bash
spikes/.venv/bin/python spikes/revamp/run_native_service.py
spikes/.venv/bin/python spikes/revamp/run_physical_service.py
spikes/.venv/bin/python spikes/revamp/run_lifecycle_service.py
```

The native candidate passes 43 checks. It preserves exact str through selected PostgreSQL/psycopg ORM operations,
rejects generated IDs and selected unprepared writes, and observes ORM tamper/relocation failure.
Two async sessions, driver cancellation/recovery, and one concurrent full-term uniqueness race pass.
An independent privileged COPY stores arbitrary bytes. That control preserves kill criterion 6 as FAIL → REDESIGN.
The old lab frame, single text field/context and incomplete clause coverage prevent a full adapter claim.

The physical suite loads one million synthetic rows through two COPY streams and builds ordinary indexes.
It checks exact equality/range/prefix IDs, selective plans, native operator classes and packed uniqueness.
Expect about 855 MB for the protected relation/index bundle plus 155 MB for its plaintext control,
with additional WAL and temporary index storage. These are observed relation sizes, not a maximum disk budget.
The current run took 45.90 s including cleanup. Prefix was slower than its control.
The packed surrogate and incomplete name/age payload paths provide physical evidence only.

The lifecycle suite uses 1,000 synthetic rows and public CF1 text roots.
It holds a source-table lock, observes one blocked writer, ends a process after its chunk commit,
inspects the marker, resumes idempotently, and runs full verification mutants.
It exercises actual companion transport, payload/search rotation and current-data decrypt-back.
A separate ordinary two-column SQLAlchemy process reads and updates recovered rows with Cryptalis/crypto/lab-reader imports blocked.
This is not the original three-model application or a retained-backup reader test.
Post-commit process exit suppresses completion reporting; it does not inject a real lost COMMIT reply.

Each suite validates the restricted connection, creates a uniquely named scratch schema, and drops only that schema.
Failure output records the stage and safe exception type. Cleanup failure remains FAIL and includes the owned schema name in the receipt.
Receipts record source/dependency hashes and limits. No URL, credentials, payloads or search terms are recorded.
No full gate passes from these experiments.

## Historical PostgreSQL setup

The earlier executor denied Unix-socket binding. The current authorized service connection works through the scoped launcher.
The earlier experiments use `postgres --single`, which bypasses the service authentication and driver boundary.
`SET ROLE` still exercises PostgreSQL permission checks. It does not establish real managed-service compatibility.

These earlier reproduction recipes are historical. They do not authorize another database for the current service test.
The scripts expect this existing bundled executable and an owned stopped disposable cluster:

```text
spikes/.venv/lib/python3.12/site-packages/pgserver/pginstall/bin/postgres
/tmp/cryptalis-revamp-pg/data
```

Do not reuse another project's cluster. Do not run a single-user backend against a live server.
For a fresh reproduction, choose an empty owned scratch directory and update the single `DATA` constant if needed.
Initialize it with the bundled `initdb`. The recorded path was:

```bash
spikes/.venv/lib/python3.12/site-packages/pgserver/pginstall/bin/initdb -D /tmp/cryptalis-revamp-pg/data --no-locale --encoding=UTF8 --auth=trust
```

The `trust` setting belongs only to the stopped socket-free lab. It is not a deployment recommendation.
Through one single-user SQL invocation, bootstrap these role grants as the local initializer:

```sql
CREATE ROLE revamp_owner NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT CREATE ON SCHEMA public TO revamp_owner;
```

Every experimental table/index/query then runs after `SET ROLE revamp_owner`.
Role bootstrap is separate from the ordinary migration-role DDL proof.
No extension is installed. Only the cluster's default trusted plpgsql exists.

## Historical physical million-row search

On a fresh owned cluster with the role above:

```bash
spikes/.venv/bin/python spikes/revamp/run_stock_postgres.py
spikes/.venv/bin/python spikes/revamp/run_packed.py
```

The stock script generates one million synthetic encrypted email values and client HMAC search terms.
It also stores synthetic plaintext controls in separate lab tables. That is benchmark setup, not a protected write path.
Name-prefix and age-range arrays are generated client-side. Their fields do not have complete encrypted payloads in the first combined fixture.
Benchmark nonces are hash-derived from fixture record IDs. This is not the runtime OS-RNG rule or a nonce-uniqueness proof.
The packed script tests a CF1-shaped physical frame and expression index. It does not authenticate CF1.

Setup needs temporary SQL input, table/index storage, and WAL. The initial stock input occupied 210,431,760 bytes.
No measured disk/pause requirement for an application follows from this fixture.
`run_stock_postgres.py --measure-only` reuses its own already-loaded fixture. It does not recreate tables or indexes.
`run_packed.py --measure-only` similarly reuses the packed fixture.
Do not run a full setup a second time over existing tables and treat the resulting errors as success.

The stock script runs 21 EXPLAIN executions per query/control and excludes the first.
It checks selected ID arrays, role attributes, extension inventory, forbidden C-language/role creation and duplicate uniqueness.
SQL errors can leave the single-user process exit code at zero. The helper inspects ERROR/FATAL/PANIC and exact expected negative controls.
Raw synthetic `.log` output remains local and can be ignored by Git. The JSON receipts and generators provide reviewable results.
Do not infer complete execution from an exit code alone.

## Historical transition experiment

On a fresh owned cluster with no existing lifecycle tables:

```bash
spikes/.venv/bin/python spikes/revamp/run_lifecycle.py
```

This creates 100 synthetic plaintext rows, adds an encrypted shadow, commits a first chunk,
ends that backend, inspects progress, retries idempotently, resumes and fully verifies.
It corrupts a ciphertext, observes authentication failure, repairs the fixture, switches,
changes current encrypted data, decrypts back, verifies and removes generated storage.
The local provider rewrap and external-generation model are explicit substitutes.
Package-free SQL is tested. A complete application without Cryptalis is not tested.

`--resume-from-first-chunk` is only for this script's exact durable first-chunk state.
It was used after a JSON-output parsing failure during the recorded lab.
Do not use it to guess an arbitrary partial transition. Inspect the exact owned state first.
The completed lab cannot be rerun through that resume option.

## Receipts and limits

| Receipt | Claim |
|---|---|
| [adapter.json](results/adapter.json) | Listed first-adapter cases and exposed raw-driver bypass |
| [native-types.json](results/native-types.json) | Narrow exact-type alternative |
| [token-checks.json](results/token-checks.json) | Finite range/prefix exactness and frequency attacks |
| [stock-postgres.json](results/stock-postgres.json) | Actual physical index/role/ID/timing/storage observations |
| [packed-expression.json](results/packed-expression.json) | Packed expression plan/size; surrogate frame |
| [mirror-comparison.json](results/mirror-comparison.json) | Atomic mirror, failed dual write, stale-mirror control and current-data recovery |
| [service-probe.json](results/service-probe.json) | Actual authorized-service access limit, with no URL recorded |
| [native-service.json](results/native-service.json) | Listed restricted-service native-type/async/uniqueness cases and COPY bypass control |
| [physical-service.json](results/physical-service.json) | Actual million-row service plans, IDs, database timings and storage |
| [lifecycle-service.json](results/lifecycle-service.json) | Actual service interruption, verification mutants, transport, rotations and narrow package-free exit |
| [lifecycle.json](results/lifecycle.json) | Actual 100-row transition and substitute/model results |

The service receipts observe authentication, selected async cases, one uniqueness race and a narrow package-free application.
No receipt qualifies complete async/provider behavior, other PG majors, live KMS/Vault/GCP, authenticated deployment/restore,
advanced SQLAlchemy queries, whole-backend performance or the original application's package-free removal.
The goal remains incomplete until its required full-scope observations exist.

The [mirror comparison](run_mirror_comparison.py) ran before the service instruction on the same earlier 100-row single-user lab.
It supports the decrypt-back choice. It does not authorize further use of that cluster in the current task.

## Offline CF1 fixture

```bash
spikes/.venv/bin/python spikes/revamp/run_cf1.py
```

The fixture passes 30 meaningful framing/context/metadata-change checks and writes [cf1.json](results/cf1.json).
Its roots and vector values are public synthetic inputs. Fixed nonces apply only to reproducible vectors.
The same AEAD library seals and opens them. No independent cryptographic review, generic SQL codec or provider claim follows.
This experiment makes no database connection.

## Offline token and attack checks

```bash
spikes/.venv/bin/python spikes/revamp/run_stock_postgres.py --offline-only
```

The offline option checks token algorithms and synthetic frequency attacks without opening a database connection.
The ranking step receives visible class counts and independent auxiliary frequencies. It receives neither keys nor private labels.
Fixture generation and recovery scoring use the known synthetic values.

## Ordinary application baseline

The [plain application](plain_app.py) has three native SQLAlchemy models and no Cryptalis attachment or protected types.

```bash
spikes/.venv/bin/python spikes/revamp/plain_app.py --sqlite-baseline-only
```

The SQLite baseline passes 29 checks for CRUD, generated identities/defaults, tenant scope, uniqueness, NULLs, ranges,
ordering/pagination, literal prefixes, joins, relationships, decimal aggregates, ORM state, bulk/raw writes, and background sessions.
It does not qualify PostgreSQL or a protected retrofit.

With no arguments, the script selects only the authorized disposable service:

```bash
spikes/.venv/bin/python spikes/revamp/plain_app.py
```

The default path checks the endpoint before any mutation and checks the restricted role on every connection.
It uses an owned scratch schema. Cleanup failure reports FAIL and the schema name.
The current service baseline exits 0 with 29 checks and removes its owned schema.
The separate service candidate covers selected async/COPY/concurrency cases; the original application has no protected comparison or measured adoption edits.
See [SQLite receipt](results/plain-app-sqlite.json) and [service receipt](results/plain-app-service.json).
