# Cryptalis

Manifest-first application-layer encryption for PostgreSQL, integrated with
SQLAlchemy and optional SQLModel. Declare protected fields, attach Cryptalis,
and use ordinary ORM operations within the [admitted compatibility matrix](docs/compatibility.md#full-capability-matrix).

**Research prototype; not production-security-qualified.** The full SRS and all
34 objectives remain required. [Current status](docs/status.md) identifies the
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

## Intended adoption

1. Declare fields, tenancy, supported search and leakage acceptance in a manifest.
2. Supply authenticated tenant scope, key-provider configuration, writer inventory
   and deployment/maintenance authority through the host integration.
3. Run Doctor and inspect the protection plan; resolve unsupported application routes.
4. Apply and verify protection, then publish the matching deployment pin.
5. Attach the session factory and use the admitted native ORM operations.

This describes the intended workflow, not universal zero-change adoption.
The current [host context reference](docs/host-contexts.md) makes the necessary
inputs explicit. Cryptalis never infers tenant authorization or lets a restored
PostgreSQL database authorize its own deployment.

## Core behavior

Sensitive values are authenticated and encrypted before PostgreSQL receives them.
CF1 uses AES-256-GCM-SIV, random nonces, HKDF-derived keys and authenticated tenant,
field and record context. Independent HMAC-SHA-256 terms implement declared exact
search. PostgreSQL never receives plaintext key material.

The implementation includes bounded sync/async storage and query support,
resumable protection, three distinct key-rotation workflows, current-data
plaintext reversal/removal, fresh-cluster adoption and scoped Doctor checks.
The [compatibility matrix](docs/compatibility.md) is the authoritative support list.
Range, ordered, prefix/fuzzy and other unadmitted operations fail explicitly;
they require separate research, leakage guarantees and admission.

Provider custody is abstracted through `KeyProvider`. Development custody is
for synthetic local data. Optional AWS and OpenBao adapters have different
verification boundaries; [status](docs/status.md) records them. Passing local
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
