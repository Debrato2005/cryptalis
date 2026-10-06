# Leakage, normalization and integration evidence

Access date for every source: **2026-10-06**.
This is an external evidence ledger. It defines no second architecture.
Primary papers establish attack assumptions and examples, not a local attack reproduction or audit.

## Applicability to the selected construction

Full-width deterministic HMAC equality terms reveal repeated normalized values within each tenant-field domain.
Randomized payloads do not hide those classes. Domain separation removes cross-domain identical-token comparison, not auxiliary-data inference.
An attacker who can insert known values and observe their terms can label equality classes.
Query/access/response and update volumes remain visible to their respective observers.
Unique-constraint outcomes can also supply a value-testing oracle.

The papers below justify treating this leakage as meaningful.
Their numerical recovery rates are not predictions for this dataset or HMAC construction.
OPE/ORE-specific ordering attacks concern excluded operators.
Advanced DSSE privacy properties do not automatically apply to a stable equality index.
No ORAM/PIR/noise or a new cryptographic defense enters the design merely because the literature describes an attack.

Frozen normalization is an equivalence decision independent of payload encryption.
NFC differs from compatibility folding. PostgreSQL collation, Numeric rounding and text restrictions remain real adoption/removal obligations.
The selected profile narrows admission to values that its original plaintext mapping can retain.
These are Cryptalis design choices, not capabilities granted by a vendor or paper.

## Opened primary sources

| ID | Actual source | Publication/version observation | What this established |
|---|---|---|---|
| LS01 | [Ristenpart author publication index](https://rist.tech.cornell.edu/papers.html) | CCS 2015, IEEE S&P 2017 and later papers identified by author | Navigation and original venue dates for leakage-abuse literature |
| LS02 | [Cash, Grubbs, Perry and Ristenpart](https://eprint.iacr.org/2016/718) | CCS 2015. Archive received 2016-07-21, revised 2019-09-05 | Leakage profiles and prior knowledge can support query/plaintext inference. Abstract and corrected-version metadata inspected. PDF fetch failed |
| LS03 | [Naveed, Kamara and Wright publication](https://www.microsoft.com/en-us/research/publication/inference-attacks-property-preserving-encrypted-databases/) and [paper](https://www.microsoft.com/en-us/research/wp-content/uploads/2017/02/edb.pdf) | CCS October 2015. PDF hosting path is not publication date | DTE frequency/auxiliary-data and OPE order leakage enable inference in studied datasets. No attack-rate extrapolation to Cryptalis |
| LS04 | [Zhang, Katz and Papamanthou publisher page](https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/zhang) and [paper](https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_zhang.pdf) | USENIX Security August 2016, pages 707–720 | Known injected files plus observed access patterns can reveal search queries. Record insertion/term observation is a related Cryptalis risk, not an identical experiment |
| LS05 | [Grubbs et al. ORE leakage-abuse paper](https://eprint.iacr.org/2016/895) | IEEE S&P 2017. Archive received 2016-09-14, revised 2017-05-24 | Ordering schemes can permit auxiliary-data recovery. Abstract inspected. PDF fetch failed. Selected equality terms do not expose order |
| LS06 | [Xu et al. dynamic leakage-abuse paper](https://arxiv.org/abs/2309.04697) and [full paper](https://arxiv.org/pdf/2309.04697) | Submitted September 9, revised September 13, 2023. Short version CCS 2023 | Forward/backward-private DSSE can retain exploitable query equality and operation-volume leakage. This is a boundary lesson, not a claimed Cryptalis property |
| LS07 | [Unicode reports index](https://www.unicode.org/reports/) and [current UAX 15](https://www.unicode.org/reports/tr15/) | Unicode 18.0.0, revision 58, 2026-08-12 | Current publication differs from the deliberately frozen chosen catalogue |
| LS08 | [Frozen UAX 15 revision 57](https://www.unicode.org/reports/tr15/tr15-57.html) | Unicode 17.0.0, 2025-07-30 | NFC canonical equivalence, version stability and conformance differ from compatibility/case folding |
| LS09 | [PostgreSQL character types](https://www.postgresql.org/docs/current/datatype-character.html) | PostgreSQL 18 rolling documentation | Text cannot store zero octets. Protect/deprotect must preserve original type admissibility |
| LS10 | [PostgreSQL numeric types](https://www.postgresql.org/docs/current/datatype-numeric.html) | PostgreSQL 18 rolling documentation | Numeric(p,s) applies declared-scale rounding and bounds. Cryptalis explicitly narrows mapped Decimal admission |
| LS11 | [PostgreSQL function volatility](https://www.postgresql.org/docs/current/xfunc-volatility.html) | PostgreSQL 18 rolling documentation | Repeated volatile/side-effecting evaluation need not preserve value. Protected query verification rejects it |
| LS12 | [SQLAlchemy Session Basics](https://docs.sqlalchemy.org/en/21/orm/session_basics.html) | 2.1 documentation, current family | Identity maps, autoflush, expire and refresh have distinct behaviors. Buffered verification must preserve pending state |
| LS13 | [Boto3 documentation index](https://docs.aws.amazon.com/boto3/latest/) | Header 1.43.108 at access | Mature selected SDK provides KMS, DynamoDB and S3 clients. A docs header alone is not an artifact lock |
| LS14 | [Boto3 1.43.108 release](https://pypi.org/project/boto3/1.43.108/) | PyPI release/upload October 2, 2026. Python >=3.10 | Exact selected SDK release exists. Complete transitive hashes still need build-time admission. Package upload metadata alone proves no safety |
| LS15 | [Boto3 low-level clients](https://docs.aws.amazon.com/boto3/latest/guide/clients.html) | Page header 1.43.105, rolling | Clients have thread-sharing caveats and cannot be shared across processes. Sessions/resources differ |
| LS16 | [Boto3 credentials](https://docs.aws.amazon.com/boto3/latest/guide/credentials.html) | Page header 1.43.97, rolling | Credential-provider chain supports temporary role credentials. Cryptalis must restrict fallback to its admitted workload source |
| LS17 | [Boto3 retries](https://docs.aws.amazon.com/boto3/latest/guide/retries.html) | Page header 1.43.105, rolling | Config total_max_attempts includes initial request. Avoid hidden nested retry multiplication |
| LS18 | [Python asyncio tasks](https://docs.python.org/3/library/asyncio-task.html) | CPython 3.14.8 documentation | Thread offload can prevent blocking the event loop. Coroutine cancellation does not prove synchronous remote work ceased |
| LS19 | [AWS S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html) | Rolling documentation, no publication date shown | Compliance retention protects exact versions for a finite interval. New versions/delete markers remain possible. It does not prove latest-journal completeness |
| LS20 | [DynamoDB transaction behavior](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis.html) | Rolling documentation, no publication date shown | Transactions have item/byte limits and finite request-token idempotency. Durable operation identity must outlive those windows |

The key-commitment papers, RFC 8452 and provider/destruction sources are recorded in [crypto/authority evidence](reset-crypto-authority-evidence.md).
Competitor and beacon sources appear in [integration/search evidence](reset-integration-search-evidence.md).
Supply-chain incident and publishing evidence appears in [operations/release evidence](reset-operations-release-evidence.md).

## Required empirical evidence

Run the selected leakage demonstrations with synthetic data, explicit observer capabilities and controls.
Compare supported expressions with a normal plaintext backend on the same semantics.
Freeze independent byte vectors, Unicode tables and Decimal examples.
Test original mapping round trips, dirty identity-map projections, bind handling, volatility rejection and cancellation.
Current authority, provider, journal and release gates require real service/artifact evidence.
No result from this literature review advances runtime status.
