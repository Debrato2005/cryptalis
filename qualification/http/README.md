# Original HTTP application qualification cell

This separate uv project pins the dependencies for the unchanged FastAPI/SQLModel
application profiles. It does not change the product runtime dependency lock.
The recorded cell uses Python 3.13.5, uv 0.12.23, SQLAlchemy 2.1.3,
SQLModel 0.0.48, FastAPI 0.162.0 and Starlette 1.10.0.

From the repository root:

```sh
UV_PROJECT_ENVIRONMENT=/tmp/cryptalis-http-env uv sync --project qualification/http --locked --python 3.13.5
```

The Cryptalis dependency is editable for source qualification. The mandatory
wrapper checks that imports resolve to this checkout. An installed-wheel run
requires a separate environment, the inspected wheel and explicit
`--installed-wheel /absolute/path/to/cryptalis.whl`; the wrapper checks every
Cryptalis Python module against the wheel before and after pytest.

Provide PostgreSQL 16 binaries in PATH and set `CRYPTALIS_SQLMODEL_HTTP_SOURCE`
to an unmodified checkout of `fastapi/full-stack-fastapi-template` at
`d40de23896d27d15c17a7bf9649123fd167a0aa8`. The fixture verifies all 26 retained
source-file hashes. Run the approved-cohort tenant journey with:

```sh
/tmp/cryptalis-http-env/bin/python scripts/online_qualification.py --workdir /tmp/cryptalis-new-tenant-run --tenant-http-fresh
```

The work directory must be new. The harness creates disposable local source and
restored clusters, generates private credentials, probes three roles, stops the
source before starting recovery, and retains receipts in that directory.
The tenant host is application-specific integration code. Global account
authentication stays native; Item payloads use preapproved owner scopes. Dynamic
tenant provisioning remains unfinished and new-owner Item writes refuse before
key lookup. This is not a production deployment procedure.

The current upstream `fastapi[standard]` extra conflicts with the pinned app's
`sentry-sdk<2` requirement through an unrelated CLI dependency. This cell uses
FastAPI's base runtime and `uvicorn[standard]`, with the unchanged application
imports and HTTP workflows verified separately. Do not describe this as an
unchanged upstream dependency installation.

The earlier Starlette 0.46.2 pin is replaced. Recorded PyPI per-release fields
reported no advisory entries for the locked registry packages; OSV access was
unavailable. This is limited advisory information, not a complete security audit.
All seven production gates remain UNKNOWN.
