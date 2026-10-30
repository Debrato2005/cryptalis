# Current design decisions

This index owns governing choices and their rationale. Technical details belong
to the [contract owners](README.md#document-owners); implementation evidence
belongs to [status](status.md). Detailed dated decisions remain in
[decision history](history/decisions-2026-10.md). Old pauses and branch-specific
instructions do not override the user's current work authorization.

## Approved scope decisions: 2026-10-08

The baseline fixed the stack, explicit tenancy, application-assigned identities,
authenticated storage and exact/IN/tenant-unique search. Later admitted operations
and scalar types are listed only in the [compatibility matrix](compatibility.md#full-capability-matrix).
The [baseline record](history/decisions-2026-10.md#approved-scope-decisions-2026-10-08)
retains its original choices and evidence limits. It is not the current support list.

## Current extensions

| Decision family | Current owner | Rationale / evidence |
|---|---|---|
| Typed storage, reader versions, query and DML admission | [Manifest](manifest.md), [compatibility](compatibility.md) | [Dated choices](history/decisions-2026-10.md); both Date codec families remain exact and distinct |
| Online capture, public slots, tenant provisioning and three rotations | [Lifecycle](lifecycle.md) | Reuse atomic journal/verification/publication; preserve current edits and retained readers |
| Context factories, operational CLI and Doctor | [Host contexts](host-contexts.md), [operator procedures](walkthrough-migration.md) | Explicit authority and safe diagnostics; no hidden publication or tenant inference |
| Provider choice | [OpenBao](openbao.md), [provider comparison](research/key-provider-selection.md) | Optional real OpenBao for self-hosted custody; retain optional AWS; no cloud purchase or vendor dependence required |
| Test and artifact binding | [Engineering playbook](../ENGINEERING_PLAYBOOK.md), [local checks](local-development.md) | Private role probes, exact runtime/source hashes, frozen builds and explicit skips |

## Comprehensive first public release: 2026-10-23

Target one comprehensive, production-grade first public release covering the full
SRS and all 34 product objectives. Internal checkpoints and release candidates
support engineering progress. A restricted beta, MVP or partial public product
is not the release plan. This direction supersedes earlier permanent feature
exclusions where they conflict with the full SRS.

Current runtime admission remains narrow and fail-closed. Missing capability
support is unfinished product work. Safe refusal does not complete its objective.
Investigate secure practical alternatives when a competitor's approach conflicts
with Cryptalis's threat model. Escalate an irreducible trade-off with evidence
rather than silently remove the objective. Existing host-compromise limits and
security invariants remain unchanged.

Use the living [competitive capability matrix](research/capability-matrix.md) to
choose high-value work and reuse dated source evidence. Prioritize independent
real-application E2E journeys. Keep focused crypto, concurrency and deterministic
failure checks where E2E cannot establish the invariant. Preserve existing tests
and admission gates. Measure completed capabilities, real application journeys
and resolved production requirements. Test totals, commits and slice counts do
not establish completion. All seven production gates need their own evidence
before the first public release.


## Selected choices

These are governing design choices. Their implementation state is in status; research mechanisms remain INTERNAL ONLY until admission.

| Problem | Choice and reason | Rejected alternative | Failure/limit and deciding evidence |
|---|---|---|---|
| Small integration | One attachment through public SQLAlchemy hooks with native mapper/history/Result | Wire proxy, manual crypto calls, bootstrap remap, custom publication frames | Exact types/state, guarded writers, async behavior, app-assigned IDs and complete admitted grammar need G-ADAPTER evidence |
| Query scope | Use the current compatibility matrix; full-SRS capabilities outside it remain engineering objectives pending secure admission | Universal encrypted SQL or declaring research arrays supported | Exact semantics, leakage opt-in and measured targets. G-QUERY |
| SQL storage | Built-in bytea packed term/expression index or admitted constraint-driven separate term | Mandatory custom type/extension | Compiler/lifecycle checks and isolated column/index cost require revision-specific evidence. G-QUERY |
| Payload primitive | Library AES-256-GCM-SIV with fresh random nonce and small HKDF/HMAC composition | Deterministic payload, new primitive, distributed nonce counter by default | CF1 vectors, usage bounds, portability and cross-key review. G-CRYPTO |
| Key custody | Independent payload/search roots per tenant generation, mature external wrapping provider, bounded process cache | Per-field remote call or persisted raw-key cache | No production provider designated. Each provider qualifies separately. G-PROVIDER |
| Current authority | Deployment-controlled policy/target/wrapper identities outside database restore. Host current authorization remains separate | Database self-admission or a mandatory authority service | Publication/restore procedure and writer exclusion remain unqualified. G-POLICY |
| Lifecycle | One PG journal, cooperating advisory lock, writer pause, full verify, separate artifact publication | General workflow engine or distributed dispatcher | Lost replies, independent recovery, retained backups and exclusion need full G-LIFECYCLE evidence |
| Rollback | Transform current data through the removal engine until explicit finalization | Timed live plaintext mirror or stale snapshot restore | Compatible readers/keys and full current-data proof. G-LIFECYCLE |
| Diagnostics | Reuse init/plan/apply/status/startup checks, including bounded Doctor admission | Separate diagnostic platform or SQL parser | No missing observation becomes PASS. Broader Doctor checks remain UNKNOWN |
| Erasure | Host managed denial and separately observed provider/tenant destruction | Instant arbitrary-process revocation or default per-subject key topology | Backups, surviving wrappers and cached keys can recover values |
| Supply chain | Mature lock/SBOM/build/provenance/Trusted Publishing tools | Custom signer/scanner platform | Independent artifact and release review. G-RELEASE |


## Deleted mechanisms

The former DynamoDB authority, S3 receipts, distributed fencing, registered-worker protocol, per-request mutation ledger,
receipt dispatcher, shared crypto quotas, custom mapper/publication frames, timed plaintext mirror, doctor, shred/tombstone,
and break-glass/restore-admit command families are removed from the selected contract.
These are historical dispositions, not dependencies or public capabilities.
The later [bounded Doctor decision](history/decisions-2026-10.md#bounded-doctor-diagnosis-2026-10-23)
supersedes the removed Doctor command scope. The former diagnostic subsystem
and its absolute guarantees remain removed.
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
