# Run the local project

Use a disposable local environment for development and verification. These checks
exercise the implemented prototype. They do not complete every objective in the
[product ledger](BUILD_CHECKLIST.md#objective-ledger).

## Prerequisites

- Python 3.12 or later and uv.
- PostgreSQL **16** server and client tools, including `initdb`, `pg_ctl` and `pg_dump`.
- A normal, non-root operating-system account. PostgreSQL refuses `initdb` as root.

The development interpreter defaults to Python 3.12 through `.python-version`,
matching CI. Use uv's `--python` option for another supported interpreter. An existing
`.venv` on a different interpreter is replaced unless you pass it, for example
`uv sync --frozen --all-extras --python .venv/bin/python`.

On Ubuntu 24.04, the server tools are available from the distribution:

```bash
sudo apt-get install postgresql-16
```

The harness discovers `/usr/lib/postgresql/16/bin` automatically. Other
installations must put their PostgreSQL 16 tools on PATH. It starts its own
cluster on an available loopback port; it does not use an existing database.

## Install and run

From the repository root:

```bash
uv sync --frozen --all-extras --compile-bytecode
uv audit --frozen
uv run --frozen --all-extras python scripts/online_qualification.py \
  --workdir /tmp/cryptalis-local-check -- tests -q
```

Choose a **new** work directory for each run. An existing directory is refused.
The harness creates separate migration-owner, encrypted-runtime and native-source
roles with generated private credentials. Every test runs through
`scripts/test_postgres.py`, which reloads and probes those credentials. The
cluster stops when the test process finishes. A failed probe stops the run.

The test receipt is `/tmp/cryptalis-local-check/receipt.json`. It records the
source hashes, selected tests, outcomes and unchanged-source check. Keep skips
visible. Optional original-application and fresh-restore profiles need their
explicit source snapshots or export artifacts; a skipped profile is not a pass.

For a shorter demonstration of online protection and tenant isolation:

```bash
uv run --frozen --all-extras python scripts/online_qualification.py \
  --workdir /tmp/cryptalis-local-online -- \
  tests/test_online_protection.py tests/test_online_tenants.py -q
```

## Explain and measure

Start with the [illustrated guide](professor-guide.md), then open its linked raw
receipts when a result needs explanation. Regenerate the historical figures with:

```bash
uv run --locked scripts/render_performance.py
```

The plotting environment is separate from the runtime dependency lock. This
command redraws existing measurements; it does not run a new database benchmark.

Measure the current column-lineage inspection implementation with:

```bash
uv run --frozen --all-extras python scripts/benchmark_admission.py \
  --output /tmp/cryptalis-admission.json
```

Use a new output path. The receipt includes every sample, source identity and
runtime versions. This microbenchmark performs no database work and measures
neither full query latency nor encryption throughput.

Measure native and protected non-NULL/distinct counts on matched local data:

```bash
CRYPTALIS_COUNTS_REPORT=/tmp/cryptalis-counts.json \
uv run --frozen --all-extras python scripts/online_qualification.py \
  --workdir /tmp/cryptalis-local-counts -- tests/profile_protected_counts.py -q
```

Choose new report and work-directory paths. The report retains raw alternating
samples for 1,000 and 10,000 rows. The harness receipt binds source hashes and
database preflight. This optional synchronous fixture profile runs separately
from the default suite and does not measure the migration lifecycle.

## Automated checks

Recover a scalar backup on a separately initialized PostgreSQL cluster, then
decrypt current values and restart without Cryptalis imports:

```bash
uv run --frozen --all-extras python scripts/online_qualification.py \
  --workdir /tmp/cryptalis-local-date-recovery --fresh-scalar date --public-slots
```

The same entry point supports `timestamp`, `timestamptz`, `numeric`, `numeric-equality`, `uuid`, `boolean`, `int16`, `int32` and `int64` profiles.
Each profile uses its fixed export/restore selection and private credentials.
Use `--public-slots` for dates, timestamps, numeric, UUIDs or integers when checking original column positions.

The [GitHub Actions workflow](../.github/workflows/local-checks.yml) uses the
same entry points as local qualification:

```bash
uv run --frozen --all-extras python scripts/ci_qualification.py source \
  --workdir /tmp/cryptalis-source-check --evidence /tmp/cryptalis-source-evidence
uv run --frozen --all-extras python scripts/ci_qualification.py release \
  --workdir /tmp/cryptalis-release-check --evidence /tmp/cryptalis-release-evidence
```

Use new, separate absolute paths. The release profile needs Docker for the real
OpenBao provider checks; see [OpenBao](openbao.md). Artifacts are named
`source-evidence-RUN-ATTEMPT` and `release-evidence-RUN-ATTEMPT`. They contain
sanitized receipts, not private credentials. The source profile audits the frozen
lock and records the lineage microbenchmark. The release profile checks built
artifacts and installed-package behavior.

## Existing isolated test target

For an already authorized test cluster, set `CRYPTALIS_TEST_CONFIG_DIR` to its
private credential directory. It must contain owner-only, mode-0600 files
`.cryptalis-test-url`, `.cryptalis-test-runtime-url` and, for native-source
controls, `.cryptalis-test-source-url`. Do not print them, commit them or change
`HOME` to redirect discovery. The wrapper validates file ownership, permissions,
role separation and the configured target before executing tests:

```bash
CRYPTALIS_TEST_CONFIG_DIR=/absolute/private/credentials \
uv run --frozen --all-extras python scripts/test_postgres.py --source-role \
  --receipt /tmp/cryptalis-focused-receipt.json --scope focused -- \
  tests/test_online_protection.py -q
```

Use a new receipt path. A failed preflight stops the run; diagnose the cause
before retrying. Never silently substitute another database. The provisioning
harness above is the simpler route when a new disposable cluster is authorized.
