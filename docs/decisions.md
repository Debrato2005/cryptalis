# Simplification decisions

**SPECIFIED:** this ledger records the approved scope and selected architecture.
It does not preserve old IDs as implementation obligations. Historical dispositions remain in [archived revamp evidence](research/revamp-evidence.md).
[Status](status.md) owns IMPLEMENTED/VERIFIED claims. All seven full gates remain UNKNOWN.

## Approved scope decisions: 2026-10-08

These decisions are final. Scope-only D blockers are resolved. No decision supplies executable qualification.

| Decision | Approved contract | Resolution/evidence limit |
|---|---|---|
| 1. Stack | Python 3.12+, SQLAlchemy 2.x, psycopg 3 sync/async, PostgreSQL 16 | Scope D resolved. Exact cell tests remain required |
| 2. First protected type | Text only. Every other type is UNSUPPORTED BY DESIGN until admission | Type-scope D resolved. Text/ID descriptors and collation evidence remain required |
| 3. Capabilities | SUPPORTED: storage-only, equality, IN, tenant-scoped uniqueness | Capability/grammar scope D resolved. Every other operation rejects until admission |
| 4. Tenancy | Each protected table declares a tenant column or declares itself single-tenant | Tenant-scope D resolved. Missing tenancy blocks plan |
| 5. Primary keys | Require application-generated UUID, Snowflake-style, or other app-assigned ID. Reject serial/identity/database-default keys at plan time with a plain explanation | Identity-scope D resolved. Historical sequence-preallocating spikes do not implement this contract |
| 6. Targets | Added p95 ≤ 3 ms point/equality, ≤ 8 ms IN-20. Protected column with equality index ≤ 2× storage | Read/storage-budget D resolved as targets, not achievements. Write-throughput and pause budgets remain D |
| 7. Authorities/review | No designated production key provider and no independent review. Local provider is functional evidence only | G-PROVIDER, G-POLICY, and review requirements remain UNKNOWN. No production publication/restore procedure is selected |
| 8. Build order | Compiler → crypto/KeyProvider/dev provider → sync/async SQLAlchemy → equality/IN/uniqueness → plan/apply/verify → decrypt-back/remove → three rotation operations | One slice per run. Each requires real PostgreSQL tests before the next. Advanced work requires all seven slices, then six-gate admission and leakage opt-in |

**VERIFIED, earlier revision only:** the million-row receipt records equality p95 about 6.5 ms versus 0.93 ms native and IN-20 about 16.1 ms versus 1.1 ms.
Both miss the approved added-latency targets. Point reads also miss. These are known performance work, not current-revision qualification.
A plaintext range/prefix/page query with no protected field cost about 5× native: p95 about 127 ms versus 24 ms.
Its cause is UNKNOWN and must be profiled in the integration slice.
[Compatibility](compatibility.md#performance-targets-and-recorded-costs) owns exact values, target accounting, storage denominator, and revision mismatch.

## Selected choices

All choices below are SPECIFIED. Research mechanisms remain INTERNAL ONLY until admission.

| Problem | Choice and reason | Rejected alternative | Failure/limit and deciding evidence |
|---|---|---|---|
| Small integration | One attachment through public SQLAlchemy hooks with native mapper/history/Result | Wire proxy, manual crypto calls, bootstrap remap, custom publication frames | Exact types/state, guarded writers, async behavior, app-assigned IDs and complete admitted grammar need G-ADAPTER evidence |
| Query scope | Text storage, equality/IN, tenant-scoped uniqueness. Other operations are UNSUPPORTED BY DESIGN | Universal encrypted SQL or declaring research arrays supported | Exact semantics, leakage opt-in and measured targets. G-QUERY |
| SQL storage | Built-in bytea packed term/expression index or admitted constraint-driven separate term | Mandatory custom type/extension | Complete compiler DDL and isolated column/index cost remain unproved. G-QUERY |
| Payload primitive | Library AES-256-GCM-SIV with fresh random nonce and small HKDF/HMAC composition | Deterministic payload, new primitive, distributed nonce counter by default | CF1 vectors, usage bounds, portability and cross-key review. G-CRYPTO |
| Key custody | Independent payload/search roots per tenant generation, mature external wrapping provider, bounded process cache | Per-field remote call or persisted raw-key cache | No production provider designated. Each provider qualifies separately. G-PROVIDER |
| Current authority | Deployment-controlled policy/target/wrapper identities outside database restore. Host current authorization remains separate | Database self-admission or a mandatory authority service | Publication/restore procedure and writer exclusion remain unqualified. G-POLICY |
| Lifecycle | One PG journal, cooperating advisory lock, writer pause, full verify, separate artifact publication | General workflow engine or distributed dispatcher | Lost replies, independent recovery, retained backups and exclusion need full G-LIFECYCLE evidence |
| Rollback | Transform current data through the removal engine until explicit finalization | Timed live plaintext mirror or stale snapshot restore | Compatible readers/keys and full current-data proof. G-LIFECYCLE |
| Diagnostics | Reuse init/plan/apply/status/startup checks | Separate diagnostic platform or SQL parser | No missing observation becomes PASS. Package CLI remains SPECIFIED |
| Erasure | Host managed denial and separately observed provider/tenant destruction | Instant arbitrary-process revocation or default per-subject key topology | Backups, surviving wrappers and cached keys can recover values |
| Supply chain | Mature lock/SBOM/build/provenance/Trusted Publishing tools | Custom signer/scanner platform | Independent artifact and release review. G-RELEASE |

## Deleted mechanisms

The former DynamoDB authority, S3 receipts, distributed fencing, registered-worker protocol, per-request mutation ledger,
receipt dispatcher, shared crypto quotas, custom mapper/publication frames, timed plaintext mirror, doctor, shred/tombstone,
and break-glass/restore-admit command families are removed from the selected contract.
These are historical dispositions, not dependencies or public capabilities.
Their absolute guarantees are also removed: immediate arbitrary-worker denial, atomic multi-service lifecycle,
whole-result publication, subject cryptographic erasure, and hostile-database completeness/freshness.
A removed mechanism cannot retain its old guarantee through wording alone.

## Complexity budget

| Retained mechanism | Essential reason | Mature dependency | User exposure | Deciding test / removal |
|---|---|---|---|---|
| Compiler/lock | Preserve schema/query meaning and detect changed intent | SQLAlchemy inspection, JSON | Manifest and concrete plan | Native application/schema diff. Retire eligible lock after package-free exit |
| Row context/projection | Reject relocation without business crypto calls | Public SQLAlchemy hooks, PG binary functions | One attachment | Entity/scalar/type/state oracle. Ordinary mapping after decrypt-back |
| Payload/equality core | Encrypt before DB and execute declared predicates | cryptography, HMAC/HKDF, native indexes | Profile and leakage opt-in | Vectors, attacks, exact indexed queries. Decrypt-back and index removal |
| Wrapped roots/cache | External custody without per-field RPC | Mature provider, process memory | Provider configuration | Cold/outage/recovery/deletion observations. Retain backup route until approved retirement |
| Deployment pin | Prevent restored DB from selecting stale authority | Existing deployment/auth system | Deployment prerequisite | Interrupted publication/restore/stale-worker tests. Explicit retained obligations |
| Journal/locks | Resumable atomic chunks, single cooperating executor | PG transactions/advisory locks | Apply/status/resume/abort | Faults and verification mutants. Remove eligible journal last |

These dependencies can reduce code. They do not establish low operational cost.
Plan reports writer pause, temporary disk/WAL, provider costs, and ownership. Only write-throughput and pause budgets remain budget D items.
Other security decisions, usage limits, provider topology/cache policy, upgrade compatibility, and host publication procedure remain unresolved where status records them.
Assumptions from this pass are in [reset notes](_reset/notes.md), not another contract owner.

## Independent expert review

**SPECIFIED requirements, UNKNOWN evidence:** an independent cryptographer reviews implemented CF1 vectors, text/ID codecs,
AAD, exact-key resolution, full-HMAC assumptions, leakage, and usage bounds.
A security reviewer reviews provider identity/cache, writer bypass, deployment provenance, restore/revocation, logs/caches/exports, supply chain, and retained-copy limits.
A database/SQLAlchemy reviewer reviews admitted grammar, constraints, async state, interruption, verification, and package-free exit.
Any advanced admission adds review of its exact representation and leakage attacks.
AI council criticism and vendor documents do not replace these reviews. No independent review is available.
