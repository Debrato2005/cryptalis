# Hardening source and observation record

Accessed 2026-10-07 Asia/Calcutta. These primary sources establish publication/API/service facts, not Cryptalis runtime support.
No AWS service API or credential was used. Sources were read as public documentation.

| Selected pin/fact | Primary source | Established / still unknown |
|---|---|---|
| CPython 3.14.8 | [release](https://www.python.org/downloads/release/python-3148/) | Release exists. Local spike uses 3.12.3, target artifact/cell not tested |
| SQLAlchemy 2.1.3 | [release](https://www.sqlalchemy.org/blog/2026/10/02/sqlalchemy-2.1.3-released/), [PyPI](https://pypi.org/project/SQLAlchemy/2.1.3/) | Exists and installed locally. Complete public mapping/Result surface not qualified |
| psycopg 3.3.6 | [PyPI](https://pypi.org/project/psycopg/3.3.6/) | Exists and installed with binary wheel. Target libpq/artifact cell untested |
| PostgreSQL/RDS 18.6 | [PostgreSQL release](https://www.postgresql.org/docs/release/18.6/), [RDS release calendar](https://docs.aws.amazon.com/AmazonRDS/latest/PostgreSQLReleaseNotes/postgresql-release-calendar.html) | Publication and RDS support listed. No target resource/build/Region or failover exercised |
| Alembic 1.20.0 | [PyPI](https://pypi.org/project/alembic/1.20.0/) | Exists, not installed/exercised here |
| boto3 1.43.108 | [PyPI](https://pypi.org/project/boto3/1.43.108/) | Exists, not installed/exercised here. No cloud calls |
| cryptography 50.0.2 | [versioned changelog](https://cryptography.io/en/50.0.2/changelog/), [PyPI](https://pypi.org/project/cryptography/50.0.2/) | Exists. Wheel update records OpenSSL 4.0.3. Local backend reports that version |
| AESGCMSIV | [versioned API](https://cryptography.io/en/50.0.2/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCMSIV), [OpenSSL requirement changelog](https://cryptography.io/en/50.0.2/changelog/) | Library API exists. Compatible OpenSSL required (introduced with OpenSSL 3.2+). S4 actual 32-byte key/12-byte nonce/16-byte tag pass. Other wheels/builds UNKNOWN |
| Wheel platforms | [installation](https://cryptography.io/en/50.0.2/installation/) | Statically linked wheels documented for supported platforms. Exact Linux target artifact/hash must still be admitted |
| Restricted canonical JSON | [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html) | Exact owned restrictions now select member order, escaping, UTF-8 and integer bytes. Two first-party encoders agree on local edge fixtures; full independent schema vectors remain required |
| Ordinary driver wire adaptation | [psycopg public adaptation](https://www.psycopg.org/psycopg3/docs/api/adapt.html) | Public get_dumper_by_oid/Dumper.dump documented. Installed 3.3.6 TEXT OID 25 exercised. Full type/dumper inventory and actual immutable DML-wire emission remain UNKNOWN |
| HKDF extract+expand | [library HKDF](https://cryptography.io/en/50.0.2/hazmat/primitives/key-derivation-functions/#hkdf), [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html) | Explicit salt/info and random roots fit intended API. Whole construction/exact byte vectors need independent review |
| GCM-SIV bounds/nonces | [RFC 8452 sections 6/9](https://www.rfc-editor.org/rfc/rfc8452.html#section-9) | Maximum sizes and nonce-misuse analysis exist. Chosen caps are conservative design limits, not a reproduced composition/forgery proof |
| Public state/event behavior | [set_committed_value](https://docs.sqlalchemy.org/en/21/orm/session_api.html#sqlalchemy.orm.attributes.set_committed_value), [before_flush](https://docs.sqlalchemy.org/en/21/orm/session_events.html#before-flush), [async run_sync](https://docs.sqlalchemy.org/en/21/orm/extensions/asyncio.html#running-synchronous-methods-and-functions-under-asyncio) | Committed state cancels history. Callbacks can mutate. Documented async bridge exists. S1 keeps pending logical data separate and uses a SQL guard |
| Predicate evaluation | [PostgreSQL expressions](https://www.postgresql.org/docs/18/sql-expressions.html#SYNTAX-EXPRESS-EVAL) | Evaluation order is not fixed. M5 locally reproduces hidden-projection error and rejects non-total atoms |
| Authority transactions | [DynamoDB transactions](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis.html), [capacity](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/read-write-operations.html) | Service-scoped transactions/capacity semantics, not cross-service atomicity or worker termination |
| Costs | [KMS](https://aws.amazon.com/kms/pricing/), [DynamoDB](https://aws.amazon.com/dynamodb/pricing/), [S3](https://aws.amazon.com/s3/pricing/) | Regional service inputs available. No measured deployment bill or fixed all-in price claimed |
| Local PostgreSQL fixture | [pgserver 0.1.4](https://pypi.org/project/pgserver/0.1.4/) | Installed package bundles PostgreSQL 16.2 here. Not the production topology |

## Limits and architecture changes from observations

S1 initially failed when explicit refresh read an expired ID attribute. It now reads public inspection identity.
The unchanged late-write oracle also defeated the first before_flush-only seal. The guard now runs at SQL emission.
This changes the selected mechanism. It does not excuse the failure or claim all callback surfaces are safe.
Later S1 failures exposed refresh autoflush and missing query autoflush in private collection. The fixes suppress autoflush
during refresh and explicitly invoke the guarded query flush. Async preparation now checks its original seal after await; it never
accepts a newly changed write set by resealing it. Exact failed outputs and final assertions are linked in [spikes](../../spikes/README.md).
The real PG supplement also commits two immutable batch markers in one transaction. It does not establish the full request inventory.
M5 confirms determinism alone cannot justify a hidden projection. The canonical grammar now rejects such expressions.
S2 finds empty DB locks with outstanding registered ownership. The canonical drain contract retains that ownership.
S3/S4 positively exhibit hostile uniqueness corruption, authentic replay and historical presence-marker replay.
Those limits remain explicit. The prototype does not introduce a freshness or query-completeness service.

Raw S3 EXPLAIN includes public synthetic tenant/term literals generated from committed fixture keys.
It is deliberately labeled lab evidence. It is not an example of permitted production diagnostics.
Provider capacity, IAM, worker terminality, restore lineage, latest receipt history and customer acceptance remain UNKNOWN.
