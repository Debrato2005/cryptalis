# Cryptalis

Cryptalis is a manifest-driven field-protection layer for existing SQLAlchemy backends.
After finalized protection, its designed runtime stores selected payloads as ciphertext and supports declared equality/IN/uniqueness.
Approved lifecycle steps can retain or create plaintext copies. Migration and safe removal are part of the design.

**Current code is a research foundation, not this runtime.**
The [status page](docs/status.md) separates DESIGNED, IMPLEMENTED and VERIFIED capabilities.
No production attachment, encrypted query adapter, live key authority or lifecycle executor exists today.

## Intended adoption

The final production design is AWS-only: Linux CPython, pinned SQLAlchemy/psycopg, AWS RDS PostgreSQL,
KMS custody, regional DynamoDB current authority and an independent S3 receipt bucket.
It requires reviewed IAM roles, workload identity, worker drain/termination evidence, monitoring and backup/key ownership.
Authority outage denies even warm-key operations. There is no offline production override.

Declare fields in one public JSON manifest. Attach before any model instance/session/query cache exists, with a dedicated registry/engine.
Refactor unsupported mappings, identity generation and queries. Replace session construction. Review physical schema changes.
Plan maintenance downtime, full verification, rollback capacity and recovery readers before activation.
Admitted attribute/query syntax keeps its ordinary shape after those changes. This is a constrained retrofit, not zero-change adoption.
The [complete example and schema](docs/architecture/README.md#manifest) define the declaration.

This example shows the designed workflow. These commands are not implemented today:

```bash
cryptalis init
# Edit cryptalis.json and configure public deployment resource references.
cryptalis doctor --live
cryptalis plan protect --out protect.plan.json
cryptalis apply protect.plan.json
cryptalis status
# After verifying rollback and recovery obligations:
cryptalis finalize OPERATION
```

The intended application shape is:

```python
sessions = attach(
    registry=Base.registry, engine=engine,
    manifest="cryptalis.json", deployment="production",
)

with sessions(identity=host_verified_grant) as session:
    user.email = "alice@example.com"
    session.add(user)
    session.commit()
    found = session.scalar(select(User).where(User.email == email))
```

Startup, session construction and a reviewed physical schema transition change.
The host still authenticates users and authorizes access. Immutable identities and supported mappings are required.
Unsupported queries fail explicitly. There are no business-code encryption or key-management calls.

## Protection boundary

The design targets stolen dumps, snapshots, backups and database readers without the external key authority.
Public source, configuration and algorithms do not supply payload keys.
This claim assumes admitted encrypted storage, reviewed cryptography and explicitly accepted search leakage.
Finalized ordinary writes persist encrypted selected values and declared terms.
Approved protection rollback mirrors and deprotection staging can persist plaintext. Historical WAL/backups may retain it.
Their exposure lasts until their declared disposition. Subject `revoke` is managed denial, not cryptographic erasure;
domain `destroy` has a separate delayed, evidence-dependent custody claim.

It does not protect plaintext inside a compromised application, broken authorization, legitimate exports or host logs.
Equality indexes reveal classes/frequency. Observed queries, volumes and chosen inputs can reveal more.
Database writers can omit data, replay old values in the same context, or replace nullable fields with NULL.
The [security contract](docs/security.md) states these limits without treating partial mitigation as prevention.

## Run the current research code

The existing environment can run the commands below from the repository root.
These commands inspect local files or fixed fake data. They do not activate protection or authenticate external authority.

```bash
.venv/bin/python -m cryptalis manifest inspect examples/manifests/genesis.json --json
.venv/bin/python -m cryptalis manifest inspect-history examples/manifests/genesis.json examples/manifests/successor.json --json
.venv/bin/python examples/demo_smolink_crypto.py --json
.venv/bin/python -m pytest -q
```

The [executable entry points](docs/status.md#executable-entry-points) describe their exact scope and failure behavior.
The synthetic Smolink example reads no Smolink database, application or production key.

## Read next

1. [Architecture](docs/architecture/README.md): integration, manifest, storage and command surface.
2. [Security](docs/security.md): threat model, key authority, crypto and leakage.
3. [Lifecycle](docs/lifecycle.md): migration, rollback, restore, revocation/destruction and removal.
4. [Compatibility](docs/compatibility.md): exact intended stack and query/type limits.
5. [Status](docs/status.md), then [build guide](docs/build-guide.md): existing evidence and next implementation slice.

The [decision ledger](docs/decisions.md) records chosen designs and production proof gates.
The [prior-art comparison](docs/prior-art.md) links dated primary evidence.
The [engineering playbook](ENGINEERING_PLAYBOOK.md) preserves the manual, one-file learning workflow.
