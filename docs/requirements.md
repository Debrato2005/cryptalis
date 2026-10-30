# Core requirements and acceptance routing

Cryptalis is a highly abstracted application-layer encryption system for
PostgreSQL. Users declare requirements in a manifest; Cryptalis manages the
cryptographic, database and lifecycle mechanics within explicit host authority.

**Complex internals. Simple external interface.** The intended workflow is to
declare protected fields and requirements, attach Cryptalis, and use the
application normally within declared capabilities. Simplicity must never weaken
security, correctness or failure visibility.

This page records the user's primary SRS summary. The [objective ledger](BUILD_CHECKLIST.md#objective-ledger)
tracks all 34 implementation objectives; the mapping below is many-to-many and
drops none. [Compatibility](compatibility.md) defines currently admitted behavior,
[status](status.md) records executed evidence, and the seven [release gates](status.md#missing-evidence-and-promotion-criteria)
define the proof still required. Requirement text is an obligation, not a claim of
implementation or production qualification.

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

Each short ID above has the `OBJ-` prefix in the objective ledger. A requirement
can need several objectives, and an objective can support several requirements.
A bounded verified subcase does not complete the requirement as a whole.

Equality/IN search, authenticated encryption and SQLAlchemy integration form the
established baseline. Broad search, universal near-zero-change adoption and
complete production lifecycle automation remain end goals. Cryptalis is **not
production-security-qualified**. Broader capability admission requires its own
security and semantic proof; safe refusal preserves correctness but does not
complete an outstanding objective.
