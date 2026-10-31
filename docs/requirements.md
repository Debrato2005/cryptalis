# Product requirements

**Goal:** build an open-source, production-grade, application-layer encryption
library that is easier to use, maintain and remove than CipherStash, with
competitive or better security and functionality.

**Core principle:** complex security internally. Simple developer experience
externally. Searchable encrypted data. Exact behavior. Complete reversibility.
No silent failures. No unnecessary complexity.

These 18 consolidated requirements (2026-10-31) are the primary product
obligation. The [objective ledger](BUILD_CHECKLIST.md#objective-ledger) tracks the
work as 34 objectives; the mapping is many-to-many and drops none.
[Compatibility](compatibility.md) defines admitted behavior, [status](status.md)
records executed evidence, and the seven
[release gates](status.md#missing-evidence-and-promotion-criteria) define the proof
still required. Requirement text is an obligation, not a claim of implementation.

| # | Requirement | Objective IDs |
|---|---|---|
| 1 | **Minimal integration.** Developers provide a manifest and external key-provider configuration. Cryptalis must require almost no backend code changes. | DX-01, DX-03, DX-04 |
| 2 | **Simple abstraction.** Hide encryption, decryption, indexes, key management, migrations and recovery behind a small, clear API. Keep security-critical decisions visible. | DX-01, DX-02, DX-05, LIFE-01 |
| 3 | **Strong encryption.** Encrypt sensitive data before PostgreSQL receives it. Use authenticated encryption, established cryptographic algorithms and separated keys. Never fall back to plaintext. | SEC-01, SEC-02, SEC-04, SEC-05 |
| 4 | **Threat model.** Assume the attacker has the complete backend source, Cryptalis source, manifest and database dump, but does not have the external cryptographic keys or authorization to use them. | SEC-01, SEC-02, SEC-05, SEC-06, SEC-07 |
| 5 | **Searchable encryption.** Support equality, `IN` and uniqueness through blind indexes. Expand to useful range, ordering, text, JSON and other searches with explicit leakage limits. | QUERY-01, QUERY-02, QUERY-03, SEC-06, RESEARCH-01 |
| 6 | **Native database behavior.** Preserve correct SQLAlchemy, SQLModel and PostgreSQL behavior, including queries, data types, transactions, constraints, bulk operations, concurrency and errors. | QUERY-02, QUERY-04, QUERY-05, DX-03, DX-04 |
| 7 | **KMS independence.** Support interchangeable external key providers. Never require a proprietary Cryptalis KMS. Keep secret keys outside the database. | SEC-05, LIFE-08 |
| 8 | **Access control and isolation.** Bind ciphertext to its tenant, field, record and key generation. Enforce declared policy and context checks without replacing application authorization. | SEC-02, SEC-03, QUERY-01 |
| 9 | **Complete lifecycle.** Support manifest → Doctor → protection → search → modification → migration → verification → key rotation → recovery → rollback → uninstall. | LIFE-01 to LIFE-09, DX-02 |
| 10 | **Complete reversibility.** Allow developers to modify or remove Cryptalis. Restore the latest committed data, original database types, schema behavior, constraints, indexes and permissions. The application must work without Cryptalis after removal. | LIFE-05, LIFE-06, LIFE-09 |
| 11 | **Key lifecycle.** Support wrapping-key rewrap, payload-key rotation, search-key rotation, revocation and controlled key retirement. Investigate subject-scoped keys, policy-gated decryption, tamper-evident audits and cryptographic shredding. Make erasure claims only when they can be proved. | SEC-05, LIFE-07, LIFE-08, RESEARCH-01 |
| 12 | **Fail loudly and safely.** Detect unsupported operations, plaintext bypasses, tampering, wrong keys, invalid contexts, schema drift and partial failures. Refuse unsafe operations and give actionable errors. Never silently return incorrect results. | SEC-03, SEC-04, QUERY-05, LIFE-01, DX-02 |
| 13 | **Safe operations.** Support resumable, low-downtime migrations, concurrent workloads, backup/restore, crash recovery, deployment fencing and reliable rollback. | LIFE-02, LIFE-03, LIFE-04, LIFE-06, DX-04, PERF-03 |
| 14 | **High performance.** Minimize latency, memory, storage, CPU and migration downtime. Initial targets are ≤3 ms added p95 for point/equality reads, ≤8 ms for `IN`-20, and ≤2× protected-column/index storage where applicable. | PERF-01 to PERF-04, LIFE-03 |
| 15 | **Production assurance.** Use real PostgreSQL and independent applications for end-to-end tests. Preserve essential cryptographic and failure tests. Require independent security review and evidence for all seven production gates. | SEC-07, DX-03, OPS-01, RESEARCH-02 |
| 16 | **Maintainability.** Apply KISS, DRY, YAGNI and Ponytail practices. Keep code modular, readable, reusable and free of unnecessary dependencies, duplicated machinery and speculative features. | DX-05, OPS-02, RESEARCH-02 |
| 17 | **Competitive value.** Study CipherStash and other established systems. Use proven solutions where suitable. Deliver useful, measurable advantages rather than novelty without practical value. | RESEARCH-01, PERF-01 |
| 18 | **Delivery.** Target one comprehensive first public release, not a restricted beta. Work autonomously, use parallel agents when useful, automate repetitive tasks to save tokens, prioritize complete E2E functionality, update documentation after each verified slice, and commit and push each completed slice to GitHub. | OPS-01, OPS-02, DX-05, RESEARCH-02 |

Each short ID has the `OBJ-` prefix in the ledger. A bounded verified subcase does
not complete a requirement. Cryptalis is **not production-security-qualified**.

**Architecture clarification.** The original vision included a self-hosted
encryption gateway, subject-level shredding and tamper-evident auditing. The
selected architecture is Python SDK-first, without a mandatory proxy. The broader
security features remain research and product ambitions until their contracts and
guarantees are approved and verified.

## Earlier 20-point SRS

The earlier summary is retained because it records specific choices the list above
states more generally. It remains binding where the list above does not supersede it.

| SRS | Requirement | Objective IDs |
|---|---|---|
| 1 | Manifest-first configuration: declare fields, encryption profiles, search permissions, tenant rules and key settings. | DX-01, LIFE-01 |
| 2 | Minimal backend changes: a small SQLAlchemy setup step, preserving normal models, queries and workflows wherever supported. | DX-01, DX-03, DX-04, QUERY-02, QUERY-04 |
| 3 | Application-layer encryption: encrypt sensitive data before PostgreSQL; store authenticated ciphertext instead of plaintext. | SEC-01, SEC-04 |
| 4 | Strong cryptography: AES-256-GCM-SIV, random nonces, HKDF-derived keys and authenticated context binding; no invented cryptographic algorithms. | SEC-02, SEC-05, SEC-07 |
| 5 | Searchable encryption: exact equality, IN and tenant-scoped uniqueness using separate keyed HMAC-SHA-256 tokens. Range, prefix and fuzzy search require separate research and explicit security guarantees. | QUERY-01, QUERY-02, QUERY-03, SEC-06, RESEARCH-01 |
| 6 | KMS independence: a common KeyProvider interface that can support AWS KMS, Google Cloud KMS and HashiCorp Vault without vendor binding. | LIFE-08, SEC-05 |
| 7 | Automatic database integration: manage encrypted columns, search indexes, constraints, query transformations and schema changes with minimal manual work. | LIFE-01, QUERY-01, QUERY-02, QUERY-04, DX-01 |
| 8 | Complete lifecycle: install, configure, modify, upgrade, rotate, roll back, decrypt, remove protection and uninstall. | LIFE-01, LIFE-05, LIFE-06, LIFE-07, LIFE-09 |
| 9 | Safe removal: verified decryption restores current plaintext values, integrity, NULLs, application behavior and relevant constraints. | LIFE-05, LIFE-09 |
| 10 | Automated migrations: existing databases, resumable backfills, integrity verification, safe activation, interruption recovery and minimal downtime. | LIFE-01, LIFE-02, LIFE-03, LIFE-04, LIFE-06 |
| 11 | Fail closed and loudly: no skipped encryption, unsafe plaintext fallback or unverified success; unsupported operations produce clear typed errors. | SEC-01, SEC-03, SEC-04, QUERY-05, DX-02 |
| 12 | Cryptalis Doctor: static configuration/code checks, dynamic database/runtime checks, drift detection and clear reports; insufficient evidence is UNKNOWN. | DX-02, QUERY-05 |
| 13 | Strong tenant isolation: bind ciphertext and search to the correct tenant, field and record; prevent cross-tenant and wrong-record decryption. | SEC-02, SEC-03, QUERY-01 |
| 14 | Transparent ORM: synchronous/asynchronous SQLAlchemy, transactions, joins and supported expressions retain expected semantics. | QUERY-02, QUERY-04, DX-03, DX-04 |
| 15 | Reliable operation: safely handle concurrency, multiprocessing, interruption, connection failures, retries, stale state, partial failures and restores. | SEC-05, LIFE-02, LIFE-04, LIFE-06, DX-04, PERF-03 |
| 16 | Key lifecycle security: envelope encryption, rotation, rewrapping, revocation and controlled destruction without exposing plaintext keys to PostgreSQL. | SEC-05, LIFE-06, LIFE-07, LIFE-08 |
| 17 | Performance/scalability: minimize crypto overhead, round trips, locking, migration downtime and unnecessary index leakage. | PERF-01, PERF-02, PERF-03, PERF-04, LIFE-03, LIFE-04, SEC-06 |
| 18 | Security by default: least privilege, defense in depth, explicit authorization, integrity checks, secure defaults and independent verification. | SEC-01, SEC-02, SEC-03, SEC-04, SEC-05, SEC-06, SEC-07, OPS-01 |
| 19 | Simple public API: hide formats, tokens, state machines, key handling and recovery machinery behind a stable abstraction. | DX-01, DX-02, DX-05, LIFE-01 |
| 20 | Maintainability: modular, testable, versioned, auditable and extensible architecture without unnecessary complexity or vendor lock-in. | QUERY-05, DX-05, LIFE-09, OPS-01, OPS-02, RESEARCH-01, RESEARCH-02 |
