# Install the research preview

Cryptalis is an MIT-licensed Python library. It needs no Smolink checkout or
mandatory proxy. Version `0.1.0a1` is an unreleased preview candidate, with bounded
behavior and **no production-security qualification**. Public package-index
publication requires explicit approval. Use an inspected wheel supplied with its
`SHA256SUMS`, build receipt and exact source revision.

## Environment

| Component | Preview environment |
|---|---|
| Python | CPython 3.12 or 3.13; package metadata rejects other minor versions |
| Database | PostgreSQL 16 |
| ORM / driver | SQLAlchemy 2.1.3 and psycopg 3.3.6, pinned by the package |
| Optional SQLModel | SQLModel 0.0.48 through `cryptalis[sqlmodel]` |
| Cryptography | cryptography 50.0.2; its available native wheel must suit the host |
| OS | Recorded Linux cells only; another OS needs its own installation and lifecycle evidence |

An installation check establishes package behavior in that interpreter. It does
not qualify every query or deployment. The [compatibility matrix](compatibility.md)
and revision-bound [status](status.md) define the exact supported behavior and
executed evidence. Python 3.14 and later are intentionally excluded until checked.

## Install a wheel outside the source checkout

Use a new directory and virtual environment. Replace the absolute artifact path
with the wheel you received; do not use an editable install or set `PYTHONPATH`.
Verify its checksum against the accompanying trusted checksum file first.

With pip:

```console
python3.12 -m venv /tmp/myapp-cryptalis
/tmp/myapp-cryptalis/bin/python -m pip install /absolute/artifacts/cryptalis-0.1.0a1-py3-none-any.whl
/tmp/myapp-cryptalis/bin/python -m pip check
/tmp/myapp-cryptalis/bin/cryptalis --help
```

With uv:

```console
uv venv --python 3.12 /tmp/myapp-cryptalis-uv
uv pip install --python /tmp/myapp-cryptalis-uv/bin/python /absolute/artifacts/cryptalis-0.1.0a1-py3-none-any.whl
uv pip check --python /tmp/myapp-cryptalis-uv/bin/python
/tmp/myapp-cryptalis-uv/bin/python -I -c "from cryptalis import Project; print(Project.__name__)"
```

Optional integrations use the same wheel, for example:

```console
uv pip install --python /tmp/myapp-cryptalis-uv/bin/python '/absolute/artifacts/cryptalis-0.1.0a1-py3-none-any.whl[sqlmodel,openbao]'
```

Extras are `sqlmodel`, `openbao` and `gcp`. AWS SDK integration accepts a caller
supplied compatible client; it does not install boto3 in the core package.
FastAPI, Redis, browsers and demonstration dependencies are application concerns.
For repeatable deployments, export and review the application's complete
dependency lock with hashes; a direct wheel install alone does not pin every
transitive dependency.

## Check a manifest without a database

Save this as `cryptalis.json` in an empty working directory:

```json
{
  "schema": "cryptalis.protection/v1",
  "profile": "cf1",
  "domain_id": "10000000-0000-0000-0000-000000000001",
  "models": [{
    "model": "Customer",
    "table_id": "20000000-0000-0000-0000-000000000001",
    "tenancy": {"single_tenant": true},
    "fields": [{
      "name": "note",
      "field_id": "30000000-0000-0000-0000-000000000001",
      "protect": true,
      "queries": [],
      "accept_leakage": []
    }]
  }]
}
```

Run the installed CLI:

```console
/tmp/myapp-cryptalis-uv/bin/cryptalis manifest inspect cryptalis.json --json
```

It reports storage-only intent for `Customer.note`. This checks declaration
syntax only. Your real model, schema, writer inventory, provider and authority
still need Doctor and staging lifecycle checks. Allocate distinct stable IDs
for the actual deployment and keep them through compatible changes.

## Run the complete example

[`examples/quickstart.py`](../examples/quickstart.py) takes an ordinary SQLAlchemy
application through Doctor, protection, search, uniqueness, all three rotations,
current-value decryption, removal and a restart that cannot import Cryptalis.
Each step is a separate process. It needs three roles and an empty PostgreSQL 16
database; its header gives the exact commands. It uses `DevelopmentKeyProvider`
with a key file, so it needs no external service. Synthetic data only.

## Integrate and complete the lifecycle

1. Inventory every writer and query touching the chosen fields. Check native
   types, constraints and query shapes against [compatibility](compatibility.md).
   Keep stable application-assigned record IDs and explicit tenancy. Existing
   raw SQL/COPY routes and server-generated protected record IDs may need changes.
2. Write a [manifest](manifest.md#implemented-compiler-syntax) with stable domain,
   table and field IDs. Start with storage-only fields. Equality/IN and uniqueness
   require explicit leakage acceptance and a search-domain review.
3. Configure an external [`KeyProvider`](security.md#key-hierarchy-and-providers),
   separate owner/runtime database roles, protected logging and a private state
   directory outside database backups. [OpenBao](openbao.md) supplies a documented
   self-hosted option. `DevelopmentKeyProvider` suits only disposable synthetic
   data: it loses custody on process exit unless given a key file, and that file
   is not production custody.
4. Construct `Project` and run Doctor and protection through the
   [small API](application.md#project-the-small-api). The state directory needs
   its own protected backup. The host supplies real writer exclusion and search
   review; acceptance strings do not establish those facts.
5. Replace the application's session factory with `project.attach(engine)`
   before creating instances, sessions or statements. Create that engine with
   `hide_parameters=True`. Await attachment for an async engine; pass
   `adapter="sqlmodel"` for SQLModel. Authenticate tenant scope in the application. Run its actual complete workflows on a disposable target.
6. Exercise updates and the declared search operations. Compare native results
   and independent database inspection. Unsupported behavior must raise a typed
   error; plaintext fallback is never an integration option.
7. Follow the [operator walkthrough](walkthrough-migration.md) for policy changes,
   interruption/resume, wrapping-key rewrap, payload rotation and search-key
   rotation. These are separate operations. Restart workers after publication.
8. Restore a backup into a genuinely separate, quarantined target and use
   `Project.recover` with retained state, keys and explicit source fencing. Keep
   required old readers and backup keys until their retirement is approved.
9. Create a plaintext role distinct from the protected runtime role and grant it
   the application's table privileges; `decrypt` grants nothing. Stop writers, call
   `Project.decrypt` to recover the **latest committed values**, verify native
   schema and behavior, then `Project.remove`. Restart with the
   native session factory and verify the application with Cryptalis imports
   denied. Uninstall only after that check; uninstalling first cannot decrypt data.

The [API reference](application.md) gives exact arguments and authority rules.
For CLI operations, use `cryptalis --help` and [host contexts](host-contexts.md).
Command factories supply application configuration; the CLI never guesses keys,
authorization, deployment pins or maintenance permission.

## Troubleshooting

| Symptom | Action |
|---|---|
| Resolver rejects Python or dependency versions | Use the selected interpreter and pinned ORM/driver. Create a clean environment before diagnosing resolver conflicts. |
| Doctor reports UNKNOWN or unsupported behavior | Read its scope and the compatibility matrix. UNKNOWN is missing evidence; adapt the application or leave the field unprotected before adoption. |
| `ProjectError` reports a pending operation | Inspect `project.status(owner)`. Repeat the same lifecycle call to resume after resolving the cause; follow the documented abort rules before a switch. |
| `KeyUnavailable` / provider authentication failure | Check the exact external provider identity, admitted wrappers, credentials and lease policy. Preserve ambiguous effects; do not create replacement keys to bypass the failure. |
| Authentication/context error | Stop affected use and inspect keys, pins, tenant/record context, possible tampering and trusted backups. Never decode unauthenticated bytes. |
| `PolicyMismatch` on a second attach | A mapping attaches once per process. Restart the worker after a lifecycle change; never re-attach in place. |
| `UnsupportedProtectedOperation` | Its message names the protected fields in the statement and what each declares. Change the query, or declare the search and review its leakage. |
| Runtime role is refused | Remove owner/schema/database creation powers through the host's approved administration procedure; do not weaken the library guard. |
| Native restart fails after removal | Preserve the reverse plan, backups and readers. Reconcile the native application/schema before uninstalling or retiring recovery material. |

Report issues through the repository's [issue tracker](https://github.com/Debrato2005/cryptalis/issues)
with the version, safe error code and sanitized environment facts. Never attach
credentials, keys, raw dumps, protected values or provider exception bodies.

## Build the candidate yourself

Use the existing [release procedure](release.md). It builds and compares both
wheel and sdist, checks archive contents and records the dependency SBOM. Core
distribution contents exclude demonstrations, tests and their configuration.
See the [changelog](../CHANGELOG.md) for the candidate boundary.
