# Architecture decision ledger

Decision date: 2026-10-07, Asia/Calcutta. This ledger records choices and rationale. Linked owners define the contracts.
`DECIDED` closes a scope or policy choice. `DECIDED-BLOCKED-ON-TEST` closes the design choice but blocks its production claim.
Neither state means implemented, verified, independently reviewed, or audited.

Sources: [integration](research/reset-integration-search-evidence.md), [crypto and authority](research/reset-crypto-authority-evidence.md),
[operations](research/reset-operations-release-evidence.md), and [attack literature](research/reset-leakage-semantics-evidence.md).
Confidence concerns the chosen design, not the probability that an unbuilt implementation is correct.

## Integration score

Weights: bypass resistance 30%, query transparency 30%, SQL-parser attack surface 20%, async support 10%, removal 10%.
Scores are first-party design judgments from 1 to 5, not measurements. They make the tradeoff visible.

| Choice | Bypass | Transparency | Parser | Async | Removal | Weighted score |
|---|---:|---:|---:|---:|---:|---:|
| Attached SQLAlchemy session factory, expression rewrite, schema guards | 3 | 5 | 5 | 4 | 5 | 4.3 |
| PostgreSQL wire proxy | 4 | 3 | 1 | 4 | 3 | 3.0 |
| Explicit repository calls throughout business code | 3 | 1 | 5 | 5 | 3 | 3.0 |
| Scalar type decorator alone | 1 | 3 | 5 | 2 | 4 | 2.8 |

The primary model changes startup and session creation. Business attributes and admitted queries keep their ordinary shape.
No secondary integration model is supported. A failing transparent-integration test blocks release. It does not silently select a repository fallback.
Schema guards and doctor are necessary because no ORM hook intercepts every database writer.
Maintenance downtime is an explicit usability cost. A SQL proxy adds deployment and SQL parsing without removing every bypass.

## Decisions

Every row states the problem, compared options, choice, reason, rejected alternatives, limitation, confidence, and status.
The linked owner supplies user behavior, mechanism, failure, cost, lifecycle, and acceptance evidence.

| ID and problem | Options and chosen default | Reason and rejected alternatives | Residual limitation / confidence | Status and proof gate | Owner |
|---|---|---|---|---|---|
| D01 Minimal retrofit | Choose attached SQLAlchemy session factory over wire proxy, scalar decorator, or explicit repository | Row context and expression trees support safe transformation without business crypto calls | Public-hook state and result adaptation need proof. High | DECIDED-BLOCKED-ON-TEST G-ORM | [Integration](architecture/README.md#integration) |
| D02 Configuration integrity | Human JSON manifest plus generated public lock, externally pinned active digest | One declaration. Review and operator transition authorize weakening. No secret configuration, mandatory custom signature service, or automatic activation | Authorized malicious deploy/operator remains trusted. High | DECIDED-BLOCKED-ON-TEST G-MANIFEST | [Manifest](architecture/README.md#manifest) |
| D03 Current non-restored authority | One pinned regional DynamoDB table, transaction reads, conditional updates, permanent tombstones and independently retained S3 intents | Managed consistency and exact append-before-effects receipts instead of restored DB metadata or a custom distributed service | Region or unprovable authority loss denies old-domain access. Journal prefixes do not prove latestness. High | DECIDED-BLOCKED-ON-TEST G-AUTHORITY | [Authority](security.md#external-authority) |
| D04 Primary primitive | AES-256-GCM-SIV, OS random 96-bit nonce, HKDF-SHA-256, cryptography 50.0.2 | Library-native misuse resistance. Reject GCM nonce-counter orchestration, deterministic payloads, new cipher, and multi-algorithm defaults | RNG health and composed bounds need expert review. High | DECIDED-BLOCKED-ON-TEST G-CRYPTO | [Format](security.md#cryptographic-format) |
| D05 Exact key resolution | One externally admitted scope/generation resolves one root, then one field key | No attacker registration, password keys, trial-key loop, or header-selected provider | No key-commitment guarantee. Trusted registry model must withstand cross-key review. Medium | DECIDED-BLOCKED-ON-TEST G-CROSSKEY | [Format](security.md#cryptographic-format) |
| D06 Relocation | Authenticate stable domain, tenant, subject, record, model/table/field, incarnation, descriptor, format, generation, purpose and header | Renames preserve logical IDs. Reject mutable-name-only or ciphertext-self-declared context | General query completeness and malicious host authorization remain outside claim. High | DECIDED-BLOCKED-ON-TEST G-BINDING | [Binding](security.md#context-and-replay) |
| D07 Replay | Prevent retired-format, revoked-scope, stale-policy and restore-authority resurrection. Exclude same-context historical row replay | External lifecycle state has value. A per-row freshness service exceeds scope | Old authentic values under still-admitted context remain accepted. High | DECIDED | [Replay](security.md#context-and-replay) |
| D08 Search | Separate full 256-bit HMAC-SHA-256 terms for equality, IN and tenant-field uniqueness | Exact SQL candidate semantics without planned truncation collisions. Reject deterministic payload, short beacons, partitioned beacon tuning | Equality/frequency/query/access/volume leakage and negligible collision probability. High | DECIDED-BLOCKED-ON-TEST G-SEARCH | [Search](security.md#search-and-leakage) |
| D09 Dangerous search | Reject known low-cardinality classifications, warn on correlation, require explicit leakage acceptance | No automatic entropy certification or hidden privacy machinery | Unknown distributions and attacker-chosen inserts can make accepted search unsafe. High | DECIDED-BLOCKED-ON-TEST G-DOCTOR | [Search](security.md#search-and-leakage) |
| D10 Query breadth | Equality, IN, NULL presence, Boolean composition, bounded entity/scalar projection. Exclude range/order/text/regex/fuzzy/joins/grouping/JSON over protected fields | Useful vertical product with one understandable leakage model | No arbitrary encrypted SQL or implicit client scan. High | DECIDED | [Semantics](compatibility.md#query-semantics) |
| D11 Normalization | Bare codec 2 for text/bytes/fixed-width integers/mapped fixed-scale decimal, explicit ASCII email/phone and frozen NFC profiles. No locale guessing | Versioned equivalence preserves original payloads and deliberate reindex | International email/phone canonicalization and timestamp/float/JSON codecs excluded. High | DECIDED-BLOCKED-ON-TEST G-SEMANTICS | [Normalization](compatibility.md#types-and-normalization) |
| D12 NULL integrity | SQL NULL plus all companions NULL, NULLS DISTINCT uniqueness | Ordinary SQL behavior. Reject implicit encrypted-null or NULLS NOT DISTINCT profile | A DB writer can substitute NULL in nullable fields without AEAD detection. High | DECIDED | [NULL](compatibility.md#query-semantics) |
| D13 Bypass coverage | Private physical slots, non-owner role, shape/coherence checks, guarded session/engine and doctor authentication | Reject ordinary accidental raw plaintext and report unknown coverage. Reject universal ORM prevention claim or SQL firewall | Forged framing and privileged writers can store plaintext until inspection. High | DECIDED-BLOCKED-ON-TEST G-BYPASS | [Storage](architecture/README.md#physical-storage-and-writer-coverage) |
| D14 Async and key preparation | Awaited session operations buffer rows, batch material preparation, then local decode before handoff | No provider I/O in scalar hooks, no custom greenlet bridge; SQLAlchemy asyncio dependency explicitly pinned, no explicit decrypt calls | Streaming and implicit protected lazy/expired loading excluded. Medium | DECIDED-BLOCKED-ON-TEST G-ASYNC | [Integration](architecture/README.md#integration) |
| D15 Key custody | Dedicated AWS-generated single-region KMS symmetric KEK per protection domain, exact ARN, workload identity | Mature external custody and temporary credentials. Reject raw root .env, custom KMS, interchangeable provider fiction | AWS coupling, cold provider latency and outage. High | DECIDED-BLOCKED-ON-TEST G-PROVIDER | [Keys](security.md#keys-and-caches) |
| D16 Hierarchy | Direct KMS-wrapped independent payload roots for tenant or subject scope and separate tenant-field search roots | Remove tenant branch and custom W1 wrapper. HKDF separates payload fields | Cold subject-heavy reads cost one unwrap per distinct uncached root. High | DECIDED-BLOCKED-ON-TEST G-PROVIDER | [Keys](security.md#keys-and-caches) |
| D17 Authority loss and escrow | Standard KMS durability plus tested same-region recovery inventory. No raw root export or automatic old-ledger restore. Unprovable permanent authority loss denies the old domain | Backups preserve data and policy evidence without reviving revoked state | Permanent KEK loss makes dependent data unrecoverable. Unprovable current ledger stops recovery. High | DECIDED-BLOCKED-ON-TEST G-RESTORE | [Recovery](lifecycle.md#restore-and-authority-loss) |
| D18 Cache and revocation | Bounded memory cache, fresh operation authority, current checks before plaintext handoff and commit, managed drain | Material TTL is separate from authorization. No Redis keys or indefinite offline lease | Already returned plaintext, copied keys and invisible VM-memory clones cannot be recalled. High | DECIDED-BLOCKED-ON-TEST G-REVOCATION | [Caches](security.md#keys-and-caches) |
| D19 Quota and fork | Durable bounded invocation/byte reservations, burn unused quota, fresh OS nonce, PID invalidation | Preserve usage bound across workers/crash instead of in-memory-only counters | Reservations add authority writes. RNG degradation is not universally detectable. Medium | DECIDED-BLOCKED-ON-TEST G-CRYPTO | [Format](security.md#cryptographic-format) |
| D20 Rotation | Separate KEK rewrap, payload generation/re-encryption, and search reindex | Reader-first compatibility and no automatic old-key destruction | Copied old ciphertext remains exposed after compromise. High | DECIDED-BLOCKED-ON-TEST G-ROTATE | [Rotation](lifecycle.md#rotation-and-upgrades) |
| D21 One engine | Target-bound plan, prepare, transform, verify, switch, observe, finalize | One durable journal for protection, reconfiguration, keys, restore, deprotect and remove | No general workflow framework or independent subsystem activation. High | DECIDED-BLOCKED-ON-TEST G-TRANSITION | [Engine](lifecycle.md#maintenance-transitions) |
| D22 Migration concurrency | Maintenance write pause, role exclusion, drained transactions and exclusive overlap lock | Reject online transformation and mixed-generation write machinery | Write downtime scales with full verification and backfill. High | DECIDED-BLOCKED-ON-TEST G-TRANSITION | [Engine](lifecycle.md#maintenance-transitions) |
| D23 Rollback window | Default 24 hours, absolute maximum first switch plus 7 days, explicit finalization, current atomic mirror | Easy verified rollback, with visible plaintext exposure. Reject stale snapshot rollback, renewal beyond absolute cap, or automatic destructive expiry | Deadline blocks complete mirrored writes. Historical copies persist after cleanup. High | DECIDED-BLOCKED-ON-TEST G-ROLLBACK | [Rollback](lifecycle.md#rollback-and-finalization) |
| D24 Target identity | AWS RDS PostgreSQL resource identity plus registry incarnation, TLS destination and database/schema identity | Pin infrastructure identity instead of hostname/OID/row marker alone | Primary production topology is AWS RDS. Local target is development-only. High | DECIDED-BLOCKED-ON-TEST G-TARGET | [Restore](lifecycle.md#restore-and-authority-loss) |
| D25 Removal | Verify plaintext shadow, switch, run package-free application, retain backup reader/keys, retire metadata, package last | Data recoverability is the exit gate. Reject pip uninstall as decommission | Retained encrypted backups can keep external recovery obligations after application exit. High | DECIDED-BLOCKED-ON-TEST G-REMOVE | [Removal](lifecycle.md#deprotect-and-remove) |
| D26 Subject revocation | Managed subject denial with permanent tombstone and retained shared-search leakage. No per-subject cryptographic erase | Dedicated KMS key per subject and puncturable custom crypto add cost/complexity | Surviving KEK plus backed-up subject wrappers can recover payloads. Shared terms remain linkable. High | DECIDED | [Revocation/destruction](lifecycle.md#revocation-and-destruction) |
| D27 Scope destruction | Dedicated protection-domain KEK deletion only after inventory, approval, drain, wait and provider observation | Bounded destruction claim tied to custody/copies, not local row deletion | Delayed/cancelable provider deletion and unmanaged copies. High | DECIDED-BLOCKED-ON-TEST G-DESTRUCTION | [Revocation/destruction](lifecycle.md#revocation-and-destruction) |
| D28 Doctor | Manifest/mapping/schema/writer/provider/lifecycle/backup/logging checks with PASS/WARN/FAIL/UNKNOWN | High-confidence checks. No custom whole-program analyzer | Dynamic paths and unknown external writers prevent clean coverage claims. High | DECIDED-BLOCKED-ON-TEST G-DOCTOR | [Doctor](architecture/README.md#doctor) |
| D29 Supply chain | PyPA OIDC, isolated protected publisher, hash lock, SBOM, attestation and artifact inspection | Mature tools. No custom signer or assertion that provenance proves safe code | Malicious trusted builds or dependencies can steal plaintext and keys. High | DECIDED-BLOCKED-ON-TEST G-RELEASE | [Release](../ENGINEERING_PLAYBOOK.md#release-gate) |
| D30 Remove platform breadth | Generic SAST/DAST, Protection Graph, network analyzer, controlled-release gateway and custom evidence-bundle framework excluded | Keep doctor and ordinary scoped reports within product boundary | Use established host AppSec tools and independent audit. High | DECIDED | [Non-goals](compatibility.md#unsupported-by-design) |
| D31 Performance | Baseline whole backend, hot/cold/outage, sync/async, lifecycle and storage/WAL budgets | No per-field KMS call, no primitive microbenchmark as product evidence | No measured runtime performance exists. Medium | DECIDED-BLOCKED-ON-TEST G-PERFORMANCE | [Matrix](compatibility.md#performance-evidence) |
| D32 Evidence and public UX | Small CLI, typed errors, one manifest, internal lock/state/journal, three maturity axes | Sophisticated mechanisms stay internal. Missing evidence blocks claim | Proposed command/API examples cannot run today. High | DECIDED | [Architecture](architecture/README.md#public-surface) |

Original D01–D32 subtotal: 6 scope choices and 26 blocked choices. These choices define intended scope. Unresolved feasibility and independent review remain explicit.
Implementation and independent review remain mandatory. A failed gate requires an explicit reviewed decision change, never a hidden fallback.


## Hardening decisions and feasibility triage

| ID | Choice / rejected alternative | Residual limitation | Status / gate / canonical owner |
|---|---|---|---|
| D33 H1 ownership | Fence before admission, DB-checked monotonic token, durable mutation/worker ownership. No TTL-based transfer | Managed termination proof and unkillable external requests can block availability | DECIDED-BLOCKED-ON-TEST G-AUTHORITY / [security](security.md#admission-and-fencing) |
| D34 H2 outcomes | Same-transaction per-flush immutable markers and original transaction/batch-ID reconciliation. Reject row-presence/absence inference | Exact canonical/attribute/wire inventory, failover lineage and marker retention need live evidence | DECIDED-BLOCKED-ON-TEST G-TRANSITION / [lifecycle](lifecycle.md#ordinary-commit-evidence) |
| D35 H3/H4 public ORM | Bootstrap remap, independent pending state, one publication frame and final SQL write-set guard | Small spike is not full declarative/Result/cascade qualification | DECIDED-BLOCKED-ON-TEST G-ORM/G-ASYNC / [integration](architecture/README.md#integration) |
| D36 M5 total grammar | Closed total plain atoms plus exact protected leaves. Reject even stable executable expressions | Narrower host query surface. Unknown nodes reject | DECIDED / [semantics](compatibility.md#query-semantics) |
| D37 M6 capacity | Per-generation current/mirror/retry and physical/provider preflight. Pause on exhaustion | Operator observations may expire. No uninterrupted-progress guarantee | DECIDED-BLOCKED-ON-TEST G-TRANSITION/G-ROLLBACK / [capacity](lifecycle.md#capacity-preflight-and-exhaustion) |
| D38 M7 uniqueness | One all-row tenant/field index, NULLS DISTINCT. Exclude soft-delete reuse/partial/composite/global | Requires honest term production and constraint integrity. Conflict leaks membership | DECIDED / [semantics](compatibility.md#query-semantics) |
| D39 M8 recovery | Original proposal resume, read-only reconciliation, reversible abort and proof-only break-glass | Unknown effect/owner can remain pending permanently | DECIDED-BLOCKED-ON-TEST G-TRANSITION/G-RESTORE / [catalogue](lifecycle.md#recovery-catalogue) |
| D40 A1 footprint | AWS-only small internal provider with fake test implementation. No new daemon or interchangeable-production fiction | Two read snapshots plus mutation ownership writes, IAM and regional coupling | DECIDED-BLOCKED-ON-TEST G-AUTHORITY/G-PERFORMANCE / [footprint](security.md#control-plane-footprint) |
| D41 A3 cheap integrity | Keep concurrency revision. Exclude presence MAC/current-row proof, with explicit customer ineligibility | Fresh NULL substitution and same-context replay/omission remain | DECIDED / [assessment](security.md#context-and-replay) |
| D42 A6 budgets | Registered latency/sustainable-capacity/cost and integration/pause/drain/recovery/exit TARGETS | Local index/primitive observations do not meet these unmeasured budgets | DECIDED-BLOCKED-ON-TEST G-PERFORMANCE / [targets](compatibility.md#performance-evidence) |

Counts: **DECIDED: 9. DECIDED-BLOCKED-ON-TEST: 33. Total: 42.**
The earlier 32-row count is historical. The complete ledger count above includes D33–D42.

INVALIDATING means failure can require changing the architecture or intended customer scope.
D01–D06, D08–D09, D11, D13–D25, D27–D29, D31, D33–D35, D37, D39–D40 and D42 are INVALIDATING.
All 33 blocked decisions contain an invalidating property. None is globally tuning-only.
Batch size, cache size/age below ceilings, SDK concurrency below caps, indexes and performance optimization are TUNING
only while the blocked decision's safety/semantics/eligibility targets hold. A failed invariant cannot be tuned away.
The [fatal feasibility sequence](build-guide.md#invalidating-feasibility-first) precedes compiler/provider implementation.

## Independent expert review

No item in this ledger is audited. A human cryptographer/security reviewer must examine D04–D08, D11, D15–D20 and D26–D27.
The scope includes AEAD/nonce bounds, hashed AAD/canonical context, exact-key assumptions, HKDF hierarchy, blind-index full width,
rotation/rewrap, restore resistance, and destruction claims. Database and ORM specialists must examine D01, D12–D14 and D21–D25.
Release review must examine D29, including what trusted publishing and provenance do not prove.
