# Run the local project

Use a disposable local environment for the college demonstration. These checks
exercise the implemented prototype. They do not complete every objective in the
[product ledger](BUILD_CHECKLIST.md#objective-ledger).

## Prerequisites

- Python 3.12 or later and uv.
- PostgreSQL **16** server and client tools, including `initdb`, `pg_ctl` and `pg_dump`.
- A normal, non-root operating-system account. PostgreSQL refuses `initdb` as root.

The development interpreter defaults to Python 3.12 through `.python-version`,
matching CI. Use uv's `--python` option for another supported interpreter.

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
uv sync --frozen --extra sqlmodel --compile-bytecode
uv audit --frozen
uv run --frozen --extra sqlmodel python scripts/online_qualification.py \
  --workdir /tmp/cryptalis-college-check -- tests -q
```

Choose a **new** work directory for each run. An existing directory is refused.
The harness creates separate migration-owner, encrypted-runtime and native-source
roles with generated private credentials. Every test runs through
`scripts/test_postgres.py`, which reloads and probes those credentials. The
cluster stops when the test process finishes. A failed probe stops the run.

The test receipt is `/tmp/cryptalis-college-check/receipt.json`. It records the
source hashes, selected tests, outcomes and unchanged-source check. Keep skips
visible. Optional original-application and fresh-restore profiles need their
explicit source snapshots or export artifacts; a skipped profile is not a pass.

For a shorter demonstration of online protection and tenant isolation:

```bash
uv run --frozen --extra sqlmodel python scripts/online_qualification.py \
  --workdir /tmp/cryptalis-college-online -- \
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
uv run --frozen --extra sqlmodel python scripts/benchmark_admission.py \
  --output /tmp/cryptalis-admission.json
```

Use a new output path. The receipt includes every sample, source identity and
runtime versions. This microbenchmark performs no database work and measures
neither full query latency nor encryption throughput.

Measure native and protected non-NULL/distinct counts on matched local data:

```bash
CRYPTALIS_COUNTS_REPORT=/tmp/cryptalis-counts.json \
uv run --frozen --extra sqlmodel python scripts/online_qualification.py \
  --workdir /tmp/cryptalis-college-counts -- tests/profile_protected_counts.py -q
```

Choose new report and work-directory paths. The report retains raw alternating
samples for 1,000 and 10,000 rows. The harness receipt binds source hashes and
database preflight. This optional synchronous fixture profile runs separately
from the default suite and does not measure the migration lifecycle.

## Automated checks

The [GitHub Actions workflow](../.github/workflows/local-checks.yml) runs the same
restricted-role PostgreSQL harness on Ubuntu 24.04. It also audits the frozen
lock and records the lineage microbenchmark. Its `local-evidence` artifact
contains the sanitized receipts, not the private connection files.
