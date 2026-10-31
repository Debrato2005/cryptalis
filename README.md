# Cryptalis

Manifest-first application-layer encryption for PostgreSQL, integrated with
SQLAlchemy and optional SQLModel. Declare protected fields, attach Cryptalis,
and use ordinary ORM operations within the [admitted compatibility matrix](docs/compatibility.md#full-capability-matrix).

**Research prototype; not production-security-qualified.** The
[product requirements](docs/requirements.md) and all 34 objectives remain required.
[Current status](docs/status.md) identifies the
verified revision and limits; the [objective ledger](docs/BUILD_CHECKLIST.md)
records unfinished work. Safe refusal does not make an unsupported feature complete.

## Start here

- [Documentation map](docs/README.md): routes and one owner for each topic.
- [Architecture](docs/architecture/README.md): components and data flow.
- [Local development](docs/local-development.md): install, test and reproduce CI.
- [Manifest reference](docs/manifest.md): declaration and compiler contract.
- [Application attachment](docs/walkthrough-sqlalchemy.md): sync/async SQLAlchemy and SQLModel.
- [Operator walkthrough](docs/walkthrough-migration.md): protect, diagnose, rotate, recover and remove.
- [OpenBao](docs/openbao.md): optional external key custody and real local qualification.

## Quick start

You supply a manifest, a key provider and a private state directory:

```python
from cryptalis import Project

project = Project("cryptalis.json", Base.registry,
                  provider=my_key_provider, state_dir="/etc/myapp/cryptalis")

project.doctor(owner_engine)                    # Read-only compatibility check.
project.protect(owner_engine, runtime_role="app",
                writers_stopped="Deploy job stopped the API and workers.",
                search_reviewed="Emails are not enumerable.")

SessionLocal = project.attach(engine)           # Replaces your sessionmaker.
with SessionLocal(tenant_id=tenant) as session:
    session.get(Customer, customer_id).email = "new@example.com"
    session.commit()
```

Applications with no tenant-column tables call `SessionLocal()`. Models and queries stay
as they are, within the
[admitted operations](docs/compatibility.md#full-capability-matrix). Rotation and recovery
are one call each; removal is `decrypt` then `remove`. See
[`Project`](docs/application.md#project-the-small-api). Repeat a failed lifecycle call to
resume it after a crash.

Security decisions stay visible. Statements such as `writers_stopped` are required
and recorded in the plan. You still authenticate the tenant you pass to the session.
Cryptalis never infers authorization or lets a restored PostgreSQL database authorize
its own deployment. Hosts needing their own publication system can use
[`ApplicationConfig`](docs/application.md#configure-once) and
[explicit host contexts](docs/host-contexts.md).

## Core behavior

Sensitive values are authenticated and encrypted before PostgreSQL receives them.
CF1 uses AES-256-GCM-SIV, random nonces, HKDF-derived keys and authenticated tenant,
field and record context. Independent HMAC-SHA-256 terms implement declared exact
search. PostgreSQL never receives plaintext key material.

The implementation includes bounded sync/async storage and query support,
resumable protection, three distinct key-rotation workflows, current-data
plaintext reversal/removal, fresh-cluster adoption and scoped Doctor checks.
Integer and date fields can opt in to [range and sorting](docs/compatibility.md#order-search),
which reveals their order in a database dump. The [compatibility matrix](docs/compatibility.md)
is the authoritative support list. Prefix/fuzzy, JSON and other unadmitted operations fail
explicitly.

Provider custody is abstracted through `KeyProvider`. Development custody is
for synthetic local data. Optional AWS, Google Cloud KMS and OpenBao adapters have
different verification boundaries; [status](docs/status.md) records them. Passing local
service checks does not qualify production identity, backup custody or destruction.

## Develop from this checkout

Use Python 3.12+ and uv. From the repository root:

```console
uv sync --frozen --all-extras
```

Follow [local development](docs/local-development.md) for an authorized disposable
PostgreSQL 16 target, mandatory role probes and reproducible source/installed
checks. Do not run tests against production data.

Before implementation, read [AGENTS.md](AGENTS.md) and the
[engineering playbook](ENGINEERING_PLAYBOOK.md). Historical evidence is routed
through [history](docs/history/README.md); it is not current setup guidance.
