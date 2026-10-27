# Simplification decisions

**SPECIFIED:** this ledger records the approved scope and selected architecture.
It does not preserve old IDs as implementation obligations. Historical dispositions remain in [archived revamp evidence](research/revamp-evidence.md).
[Status](status.md) owns IMPLEMENTED/VERIFIED claims. All seven full gates remain UNKNOWN.

## Finite SELECT function authority: 2026-10-27

Typed SELECT syntax does not establish that a database function is read-only.
Use a finite native function class/name/namespace/dispatch admission table.
Compile ordinary admitted calls with explicit `pg_catalog` resolution, retaining
native special expressions and all protected-lineage checks. Preserve standard
count/public-expression/window/cancellation behavior through native controls.
Unknown database functions require separate admission and fail before keys or
driver effects. No SQL parser, general purity inference or extra database service
is introduced. Writer inventory and production exclusion remain separate obligations.

## Direct provider custody transfer proof: 2026-10-27

Require direct provider rewrap to prove target recovery of the original root,
in addition to exact wrapper context and stable provider identity. Use existing
provider unwrap and constant-time comparison; add no new format or primitive.
Retain source custody on refusal. The extra unwrap requires target decrypt
permission and can incur one provider request. Higher-level rotation retains
its existing independent preparation and publication checks. Local protocol
tests and agent review do not qualify external custody or deletion.

## Frozen isolated build inputs: 2026-10-27

Pin the existing uv build backend to an exact version and retain standard
hash constraints under `qualification/build-backend`. Release checks force
isolated PEP 517, require backend hashes and disable ambient configuration
discovery. Contradictory environment settings must fail before artifact creation.
Record tool/interpreter identity and the constraint digest with artifact evidence.
Offline checks require the admitted backend in the normal uv cache. Preserve
runtime pins and all existing release requirements. Same-cell reproducibility
and agent review do not establish independent provenance or production safety.

## Online capture and access transfer: 2026-10-24

**APPROVED, bounded implementation:** keep the existing maintenance path and add
an explicit initial-protection protocol. Use PostgreSQL row triggers to invalidate
staged ciphertext when native application values change. Native source columns
remain authoritative during capture. Exclude owner and DDL writers throughout.
Refuse column grants, inherited runtime roles and undeclared table access.

Keep the final fence durable across process death. Seal current membership and
authenticated frames into a host-retained activation artifact before cutover.
Recheck its proof in the switch transaction. Transfer source and target grants
in that transaction. A database journal cannot replace the sealed host artifact.
Retain the preparation as a superseded predecessor so rotations, restored adoption
and eventual removal inspect the complete operation chain.

Use new strict plan versions for online protection and every successor that
carries its access contract. Historical readers refuse these artifacts.
Current-data decrypt-back must restore the recorded source role and revoke
the encrypted target. Do not claim plaintext erasure or a bounded final pause.
All seven production gates remain UNKNOWN.

**APPROVED, tenant-scoped extension:** P1 remains the single-tenant
`cryptalis.online-protection/v1` contract. P2 uses v2 only when the host supplies
`native_tenants` as a tuple of at most 1,024 unique UUID values. The canonical
artifact stores the UUID strings in sorted order. The nil UUID is a valid tenant
value. An omitted tuple keeps P1 behavior.

P2 binds exactly one key policy for each approved tenant, including tenants with
no current rows, plus the fixed table UUID policy for each single-tenant table.
Reject UUIDs outside the approved native and fixed scope union before host key
resolution. A native row must belong to `native_tenants`, even if its UUID also
identifies an approved fixed scope. Lock the tables and
recheck existing rows before any DDL. The existing `cryptalis.transition/v8`
activation artifact and access-contract successor chain remain unchanged.
Keep all production gates UNKNOWN until their separate admission evidence passes.



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

## Approved scope decisions: 2026-10-08

These decisions record the baseline admission and dependency order. The later
[comprehensive release direction](#comprehensive-first-public-release-2026-10-23) supersedes permanent feature exclusions.
No decision supplies executable qualification.

| Decision | Approved contract | Resolution/evidence limit |
|---|---|---|
| 1. Stack | Python 3.12+, SQLAlchemy 2.x, psycopg 3 sync/async, PostgreSQL 16 | Scope D resolved. Exact cell tests remain required |
| 2. First protected type | Text first. VARCHAR extends the text family. Boolean has bounded storage admission. Other types remain CURRENTLY UNADMITTED pending secure admission | Type-scope D resolved. Text/ID descriptors and collation evidence remain required |
| 3. Capabilities | SUPPORTED: storage-only, equality, IN, tenant-scoped uniqueness | Capability/grammar scope D resolved. Every other operation rejects until admission |
| 4. Tenancy | Each protected table declares a tenant column or declares itself single-tenant | Tenant-scope D resolved. Missing tenancy blocks plan |
| 5. Primary keys | Require application-generated UUID, Snowflake-style, or other app-assigned ID. Reject serial/identity/database-default keys at plan time with a plain explanation | Identity-scope D resolved. Historical sequence-preallocating spikes do not implement this contract |
| 6. Targets | Added p95 ≤ 3 ms point/equality, ≤ 8 ms IN-20. Protected column with equality index ≤ 2× storage | Read/storage-budget D resolved as targets, not achievements. Write-throughput and pause budgets remain D |
| 7. Authorities/review | No designated production key provider and no independent review. Local provider is functional evidence only | G-PROVIDER, G-POLICY, and review requirements remain UNKNOWN. No production publication/restore procedure is selected |
| 8. Build order | Compiler → crypto/KeyProvider/dev provider → sync/async SQLAlchemy → equality/IN/uniqueness → plan/apply/verify → decrypt-back/remove → three rotation operations | Baseline dependencies require real PostgreSQL tests. Independent workstreams can proceed within available capacity. New capabilities retain six-gate admission and leakage opt-in |
| 9. Lock v2 metadata | Add `cryptalis.lock/v2` `source_metadata`; dual v1/v2 reader; new plans emit v2; in-place restore first, fresh cluster separate | Approved 2026-10-21. Column attributes, grants, comments, and extended statistics are captured and restored. Owned sequences stayed refused at that checkpoint; the [sequence extension](#owned-sequence-metadata-and-restored-identity-2026-10-24) defines the next contract |

**VERIFIED, earlier revision only:** the million-row receipt records equality p95 about 6.5 ms versus 0.93 ms native and IN-20 about 16.1 ms versus 1.1 ms.
Both miss the approved added-latency targets. Point reads also miss. These are known performance work, not current-revision qualification.
A range/prefix/page query with plaintext filters cost about 5× native: p95 about 127 ms versus 24 ms.
Slice 4 source inspection corrects its earlier label: it projects the full Customer, including protected email.
Its cause is UNKNOWN and must be profiled in the integration slice.
[Compatibility](compatibility.md#performance-targets-and-recorded-costs) owns exact values, target accounting, storage denominator, and revision mismatch.

## Selected choices

All choices below are SPECIFIED. Research mechanisms remain INTERNAL ONLY until admission.

| Problem | Choice and reason | Rejected alternative | Failure/limit and deciding evidence |
|---|---|---|---|
| Small integration | One attachment through public SQLAlchemy hooks with native mapper/history/Result | Wire proxy, manual crypto calls, bootstrap remap, custom publication frames | Exact types/state, guarded writers, async behavior, app-assigned IDs and complete admitted grammar need G-ADAPTER evidence |
| Query scope | Current admission: text storage, equality/IN and tenant-scoped uniqueness. Other full-SRS capabilities remain engineering objectives pending secure admission | Universal encrypted SQL or declaring research arrays supported | Exact semantics, leakage opt-in and measured targets. G-QUERY |
| SQL storage | Built-in bytea packed term/expression index or admitted constraint-driven separate term | Mandatory custom type/extension | Complete compiler DDL and isolated column/index cost remain unproved. G-QUERY |
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
The later [bounded Doctor decision](#bounded-doctor-diagnosis-2026-10-23)
supersedes the removed Doctor command scope. The former diagnostic subsystem
and its absolute guarantees remain removed.
Their absolute guarantees are also removed: immediate arbitrary-worker denial, atomic multi-service lifecycle,
whole-result publication, subject cryptographic erasure, and hostile-database completeness/freshness.
A removed mechanism cannot retain its old guarantee through wording alone.

## Optional exact SQLModel bridge: 2026-10-23

Add an explicit optional SQLModel attachment for synchronous PostgreSQL only.
Pin SQLModel 0.0.48 and retain the four base runtime pins. Normalize only its
exact stock AutoString through shared native type admission. Reject changed
hooks, subclasses, variants and other unsupported protected types.
Reuse native `Session.exec` and existing SQLAlchemy transaction/result guards.
Keep the ordinary SQLAlchemy attachment behavior unchanged.

Reject top-level SQLModel absence, unsupported version tags and async SQLModel
attachment before database or key work. Internal package import failures retain
their native failure behavior. Keep CF1, readers, tenancy, key authority and
leakage contracts unchanged. Pinned external CRUD evidence remains separate
from full application, authentication, deployment and broader ORM qualification.

## Wheel dependency metadata consistency: 2026-10-23

Compare wheel Python and dependency declarations with `pyproject.toml` through
standard packaging parsers. Accept normalized equivalent requirements and preserve
multiplicity with a multiset. Refuse missing, malformed or changed declarations.
Keep the parser in development dependencies. Metadata consistency establishes
no installed dependency resolution or production qualification.

## Expanded SELECT admission and finite DELETE: 2026-10-23

Expand selected entity/table columns and all descendants before SELECT admission.
Use the same node snapshot for type, operation and owned-lineage checks.
Protected outputs must retain the existing authenticated decryption path.
Preserve admitted public expressions and Python codecs. Reject unsupported
protected expressions before key resolution or SELECT execution.

Admit mapped DELETE through `execute()` only with exact typed tenant/record
equalities and `synchronize_session=False`. Reject RETURNING, external parameters,
Core DELETE, custom AST classes and unsupported predicates or options. Bind
compiled and final driver parameters to the original tenant/record authority.
Preserve native results and transaction behavior. Claim no stored-frame
authentication for a DELETE that returns no protected value.

Check native AST classes and compiler dispatch for ordinary ORM flush DELETE
before its existing admission exception. Preserve native single/batch flush,
state and transaction behavior without imposing the scoped route's predicate
shape. Refuse unsupported custom nodes before driver execution.

## Finite SELECT type compilation: 2026-10-23

Admit SELECT types through exact native compiler dispatch and explicit hook
checks before generated-node exceptions. Reject variants, user-defined type
spelling, literal-execution binds and SQL-producing type customizations. Recurse
through decorator and container types. Permit only the exact owned physical
payload output hook, while retaining every other check. Preserve ordinary
Python bind/result processors and tested native types. Keep public write-type
admission and hostile host execution outside this SELECT-specific decision.

## Preserve early configuration refusal: 2026-10-23

Mapping admission must refuse changed configuration before host key resolution.
The regression accepts rejection during session creation or execution and keeps
zero-driver and healthy-restored assertions. Do not weaken this check to match
the former later timing. Keep the separate CLI timeout failure and its UNKNOWN
cause visible. Do not extend product or test timeouts without supporting evidence.

## Native VARCHAR mapped dictionary UPDATE: 2026-10-23

Extend only the existing mapped dictionary UPDATE route to native VARCHAR.
Keep exact tenant equality, typed application IDs, a nonempty dictionary list
and `synchronize_session=False`. Keep the route exclusive to `execute()`.
Preserve all other admission limits and native result/transaction behavior.

Apply native assignment coercion before sealing valid text. Keep omitted fields
omitted and query values unchanged. For invalid text, admit only the private
owned CASE and public constants for that emitted group. Preserve the tested
native custom, generic and warmed automatic plan behavior, including its
zero-match/error boundary. This refines early length-failure wording only for
this bulk route. Protect the caller's text from SQL error parameters.

Map only the known owned carrier's DBAPI 22001 to its retained
`VarcharLengthExceeded`. Keep other native DBAPI errors native. Ordinary flush
and INSERT retain their existing length-failure paths. Capture exact typed
requests before provider callbacks in sync and async paths. Preserve the ordered
immutable ledger and exact compiled/final driver checks.

The internal CASE gives no public expression or type-hook waiver. Keep CF1,
readers, provider authority, leakage acceptance and search representations unchanged.
This decision supersedes only the earlier VARCHAR bulk UPDATE refusal.

## Scoped mapped TEXT bulk UPDATE: 2026-10-23

Admit mapped dictionary UPDATE with one direct tenant-column equality, typed
application IDs and `synchronize_session=False`. Preserve native grouping,
result and transaction behavior. Refuse VARCHAR, single-tenant, Core, RETURNING,
extra predicates, dynamic defaults, read-only properties and SQL-producing types.
Use ordered input proofs and final exact scope/record/frame checks. Extend
shared identity admission to attachment and pre-resolver configuration checks.
The [compatibility owner](compatibility.md#full-capability-matrix) defines the route.
The later [native VARCHAR UPDATE decision](#native-varchar-mapped-dictionary-update-2026-10-23) supersedes its VARCHAR refusal.

## Bounded rotation row recovery: 2026-10-23

Admit one exact-expiry retry across a row's pure payload/search crypto steps.
Check both pinned policies and retained roots before fresh admission. Keep
the three-frame logical budget and withhold effects until successful work.
Preserve terminal expiry in source-only observations and outer return checks.
Do not change generation policy, public APIs, activation artifacts or publication.

## Exact native identity codecs: 2026-10-23

Reject dialect-specific variants on record and tenant identity mappings during
planning. A matching top-level type cannot authorize SQL-side context changes.
This narrows admission to the existing native codec contract. It adds no codec.

## Safe inspection remedies: 2026-10-23

Reuse the current CLI failure envelope for the public plan operation UUID and
fixed remedies for known runtime-role and external-pin refusals. Preserve codes,
exit classes and unknown observations. Keep all authority changes manual through
the existing trusted host process. No diagnostic service or automatic repair is added.

## Restored-frame expiry recovery: 2026-10-23

Extend the existing local row retry to restored-frame authentication. Keep
exact retained-policy admission, the one-retry limit and custody failure codes.
Run effectful CHECK probes only after every retained frame authenticates.
Do not change restore approval, target identity, binding format or host authority.
The [lifecycle owner](lifecycle.md#restored-protected-backup-adoption-2026-10-19) defines adoption.

## Optional external SDK bridge: 2026-10-23

Add an optional AWS KMS implementation of the existing provider protocol.
The caller supplies a configured SDK client, a provider UUID and one full key
ARN. Pin both requests and responses to that identity and SYMMETRIC_DEFAULT.
Use fixed versioned public context for exact domain/tenant/root/generation binding.
Do not discover credentials, select aliases, administer keys or add a mandatory
SDK dependency. Keep CF1 and key policies unchanged.
The [security owner](security.md#optional-aws-kms-sdk-adapter) defines the boundary.
SDK tests do not designate or qualify a production provider. All seven gates remain UNKNOWN.

## Mapped protected scalar RETURNING: 2026-10-23

Extend mapped dictionary INSERT with exactly one direct protected mapped column
in `returning()`. Preserve native one-column Row/scalar results, parameter-order
requests, grouping, paging and transaction behavior. Tuple/entity results,
labels, expressions, aliased columns and loader options need separate admission.
Caller `return_defaults()` remains refused. Admit only the native derived
primary-key/defaults forms associated with the validated scalar request.
Resolve owned column lineage because ordinary ORM annotations can retain native types.

Capture each native group's immutable record-to-prepared-frame expectations
during compilation. Allow distinct prepared frames for duplicate input IDs so
an earlier result does not replace a later native uniqueness failure.
Require the returned tenant, real record identity and exact prepared frame or
NULL before plaintext release. Keep SELECT outer-join NULL extension separate.
Processors retain prepared keys and immutable expectations, without the operation
or session. Lease checks occur at actual cryptographic use.

Reuse the installed dialect's native insertmanyvalues generator. Validate its
processed input against the admitted batch before paging. Compare each page's
input rows with the original frozen slice before accepting its SQL/parameters.
This prevents an earlier callback from changing a future page unnoticed.
Consume one exact page permit on its cursor/context at final driver dispatch.
Keep the shared first-capture and completed-dispatch checks.

Do not parse generated parameter suffixes, compile replacement SQL, assemble a
replacement Result or change CF1. The private dialect hook needs native evidence
in each selected compatibility cell. [Status](status.md) owns that evidence.

Native supplemental RETURNING can decrypt during `execute()`.
Later iteration can therefore read plaintext that already passed authentication.
Expired keys must fail before a later cryptographic use, without provider refresh.
Result failure can follow successful uncommitted SQL. Require rollback before retry.
This adds no hostile-database completeness, ordering or general freshness guarantee.

## Shared driver event boundary: 2026-10-23

Extend final driver admission to ordinary flush and protected read paths.
Capture SQLAlchemy's native processed statement/parameters before cursor
listeners, then compare at the guarded dialect dispatch. Snapshot each native
insertmanyvalues page. Reuse its compilation, ordering, RETURNING and transaction
mechanics instead of implementing another SQL compiler or batch association.
Freeze SQL, binary buffers, containers and ordinary typed primitive/identity
values. Keep unknown unprotected adapters by identity, without claiming to
freeze their internal state.
For psycopg Binary objects, require exact native buffer types and read the
buffer directly. Custom `__bytes__` behavior cannot stand in for bytes that the
driver actually sends.

SQLAlchemy's inspected Connection event implementation does not forward
`insert=True` as a prepend instruction. Check actual effective callback order
at capture and dispatch. Require the capture first and exactly once. Refuse
preexisting engine listeners before connection and effective Connection
listeners before catalog validation. Only later engine-instance observers are
admitted. Any captured SQL/value mutation, unsafe order or missing capture raises the typed
`UnsafeDriverEvent`. No event callback receives a driver permit.
After-cursor admission also requires a completion marker set only after the
guarded raw execute succeeds. This prevents a preexisting or newly installed
dialect callback from returning `True` and silently skipping an INSERT.
Reset both markers for every native page. This retains harmless dialect
observers without a separate dialect-listener policy.

This strengthens the existing boundary without changing CF1, provider trust,
search leakage, transaction objects or public DML scope. Separate clients,
host authorization, custom adapter internals and external qualification keep
their existing limits. [Status](status.md) owns executable evidence.

## Mapped dictionary INSERT: 2026-10-23

Admit ordinary `Session.execute(insert(Model), list[dict])` through the existing
sync/async attachment. Reuse CF1 frames, native ORM dispatch and PostgreSQL
constraints. Copy each row and bind every supplied protected value to its own
field, typed identity, tenant and operation. Match final driver values against
the admitted batch after cursor events. No new cryptographic format, provider
authority, query representation or transaction state machine is introduced.

The later [scalar RETURNING decision](#mapped-protected-scalar-returning-2026-10-23)
supersedes the original blanket RETURNING refusal.
Keep other RETURNING shapes, embedded values, SQL row expressions, Core INSERT, upserts,
INSERT SELECT, legacy bulk methods and used context-sensitive defaults outside
this admission. Explicit values can bypass unused defaults.

VARCHAR validation precedes encryption. For a known invalid row, execute only
its valid prefix first so an earlier native constraint error wins. Invoke the
invalid row through the same native ORM path so autoflush retains precedence.
After its owned bind failure, PostgreSQL 16's three-argument VARCHAR assignment
function receives public constants and raises SQLSTATE 22001. This preserves
native aborted-transaction/savepoint behavior without sending protected text.
Any unavailable or unexpected carrier outcome raises a separate typed failure.
The [PostgreSQL 16 implementation](https://raw.githubusercontent.com/postgres/postgres/REL_16_15/src/backend/utils/adt/varchar.c)
defines this assignment coercion. The native oracle exercises its transaction
behavior. A supplied invalid text value never becomes an error SQL parameter.

Admit exact stock savepoint-control clauses separately, with empty parameters,
native SQL compilation and unchanged configuration. Do not wrap or replace
native transactions. These controls confer no data permit. Other write routes
and the seven production gates retain their separate evidence requirements.

## Boolean storage format extension: 2026-10-23

**IMPLEMENTED, bounded local admission:** add authenticated Boolean storage
for practical application flags without equality terms. Preserve every existing
text descriptor and CF1 byte sequence. Use strict `cryptalis.context/v2` with
`value_codec: boolean-u8/v1`, identity normalization, SQL NULL and storage-only
representation. False encodes as byte 00; true as byte 01. Authenticate before
accepting exactly one of these bytes. Keep the existing AEAD, KDF, nonce and
row/tenant/field/generation composition; the descriptor digest binds the type.
Use the shared authenticated CF1 implementation.

Lock/v4 and `boolean-u8/v1` reject old readers before use.
Native Boolean mappings and admitted literal Boolean application defaults need
exact recorded facts and current mapping checks. Server/callable/on-update
protected defaults remain refused. Preserve the native Boolean input processor,
omission/None/default behavior, pending Python state, errors and rollback.
Do not substitute Python truthiness or text/int casting for the native contract.

Independent vectors, native differential controls, unchanged SQLModel journeys,
mixed rotations and fresh-cluster latest-value removal have bounded evidence in
the [Boolean checkpoint](status.md#boolean-storage-checkpoint-2026-10-23).
The native processor accepts zero/one numeric inputs. The public codec accepts only Boolean or SQL NULL.
Invalid native inputs retain exception classes and rollback, with redacted diagnostics.
Boolean search remains unadmitted under
the current small-domain policy. This does not complete other practical type,
JSON, range or string-search requirements. All seven production gates remain UNKNOWN.

## Pre-adoption CLI host configuration: 2026-10-23

Expose the existing Python preflight through one explicit trusted `module:factory`
reference. Reuse bounded local inputs, CLI-owned inspection connection and the
read-only compiler. The factory supplies only registry, writer inventory and
search reviews; no automatic discovery, keys or alternative configuration engine.
Keep ACTIVE plan/pin inputs separate. Admit modes before loading host code.
Report host-code effects as UNKNOWN and scope no-effects claims to compiler
inspection. Sanitize loader failures and suppress Python stream output without
retaining it. Host imports remain trusted executable code, not a sandbox.

## Deterministic database-default exact search: 2026-10-23

Admit inspected `pg_catalog.default` with provider `d`, determinism and an
implicit mapped collation for existing exact text equality/IN and uniqueness.
Retain the native C branch and exact source/index collation identity.
PostgreSQL 16 documentation/source and the native oracle establish deterministic
byte equality; they do not admit locale-sensitive ordering or normalization.
Preserve serialized source validation and old-reader refusal. Keep CF1 framing,
authenticated text descriptors and full-width search terms unchanged.
Reuse the existing pinned AutoString recognizer for original SQLModel search
binds. Do not add a weaker type whitelist or modify application models/queries.
Fixture email leakage review does not qualify arbitrary production identities.

## Manifest preflight and canonical recovery observations: 2026-10-23

Expose pre-adoption manifest/schema diagnostics through the existing read-only
compiler. Report actionable schema failures without application rows or keys.
A compatible schema can pass its named check, while aggregate and unobserved
security/operational checks remain UNKNOWN. Keep the existing ACTIVE Doctor and
CLI contracts separate. Do not duplicate the compiler or add an authority.

Read guard facts under the compiler's existing canonical catalog context.
Retain exact comparisons and fail-closed drift handling. Older paused records
that do not match canonical facts still refuse. This slice admits no automatic
journal upgrade. Preserve crypto formats, lifecycle authority and native transactions.

## Bounded Doctor diagnosis: 2026-10-23

The current product mandate requires a useful `cryptalis doctor`. Add a thin
read-only interface over existing runtime deployment admission. It introduces
no new authority, diagnostic framework, SQL parser, or application scan.
`migration.diagnose_deployment` accepts an immutable migration plan, exact
ACTIVE pin, actual runtime connection, and optional matching restore binding.
It admits host artifacts before connection and checks one repeatable-read,
read-only snapshot through `check_attachment`. ACTIVE/PENDING status also
repeats the shared effective privilege checks.

A passed runtime check leaves the overall Doctor result UNKNOWN. Provider
keys, frame authentication, query routes, writer exclusion, host authority,
and recovery capacity remain unobserved. Exit 0 means only scoped admission
passed. Later ACTIVE edits remain valid; Doctor does not repeat frozen
activation frame proofs. The host still authenticates deployment publication.
[The walkthrough](walkthrough-migration.md#diagnose-an-active-deployment)
owns command inputs and results. [Status](status.md) owns executable evidence.
All seven full gates remain UNKNOWN.

## Rotation preparation diagnostics: 2026-10-23

Reuse the existing payload/search P status APIs in `cryptalis status` through
exact artifact-format dispatch. Keep P separate from publication artifact A.
Recorded progress remains keyless, read-only, and `NOT_PERFORMED`; it never
returns application deployment admission. Repeat shared runtime privilege
checks in every recorded phase. Refuse P restore bindings before reading
them or connecting. This adds no artifact format or lifecycle state machine.

Admit the source plan and pin before search-planner field inspection.
Missing preparation and activation failures use the actual payload/search
purpose. [The walkthrough](walkthrough-migration.md#inspect-rotation-preparation)
owns diagnostic codes and command behavior. [Status](status.md) owns evidence.
All seven full gates remain UNKNOWN.

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

## Native VARCHAR text admission: 2026-10-22

**IMPLEMENTED, bounded:** admit PostgreSQL `text` and native
`varchar`, with or without a character limit, as the text family.
Keep custom types, domains, `char`/`bpchar`, and non-text values unadmitted.
This extends the approved text scope without a new cryptographic construction,
search representation, leakage profile, or source of deployment authority.

Emit `cryptalis.lock/v3` when a protected field uses native `varchar`.
Require `pg-varchar/v1` in that lock's reader list. Preserve v1/v2 reading and
v2 emission for text-only declarations. The complete source schema already
records each native typmod. Keep the field-source member shape unchanged.
A v3 reader must check the native type, typmod, and mapped length together.
Restore the same native type and typmod during decrypt-back.

Apply native VARCHAR assignment rules before payload encryption.
Preserve character counts, accepted excess ASCII spaces, and exact stored values.
Preserve pending ORM attributes until native refresh or expiration changes them.
Do not apply assignment coercion to equality query values.
An overlength non-space value raises a safe typed error before protected SQL.
The error carries SQLSTATE `22001`. Callers must roll back before retry.
The [bulk UPDATE decision](#native-varchar-mapped-dictionary-update-2026-10-23) defines its separate native plan-sensitive length-failure boundary.
Read-time validation must refuse an authenticated value beyond its native limit.

Keep CF1, `utf8-exact/v1`, and `identity/v1` unchanged.
The codec encrypts the exact value after native assignment coercion.
The existing 16 MiB codec limit still applies. Search still requires qualified
exact C equivalence and explicit leakage acceptance.

The native oracle must cover Unicode character counts, trailing spaces, overlength
errors, unchanged pending state, refresh, equality/IN, scoped uniqueness, async
writes, decrypt-back, native metadata, and package-free restart.
Do not claim external-application adoption from these type tests alone.

Source: [PostgreSQL 16 character types](https://www.postgresql.org/docs/16/datatype-character.html).

## Root-rewrap successor artifacts: 2026-10-23

**IMPLEMENTED, bounded:** root custody changes use `cryptalis.transition/v2`
with `kind: rewrap`. Existing v1 protection plans remain readable. The successor
keeps the same compiled lock and CF1 context, but receives a new immutable
operation ID and digest. Its host artifact records the rewrap proposal digest,
expected frame/membership observations and a flat ordered predecessor list.
CF1, key generations, search representations and leakage remain unchanged.
The [adopted-target extension](#adopted-target-root-rewrap-2026-10-24) adds
rewrap/v2 and transition/v5 without changing this ordinary path.

Use the existing maintenance executor, advisory lock, table locks and writer
guard implementation. Full source/target authentication, a successor PENDING
row and predecessor SUPERSEDED marker commit together. The old row retains its
original operation ID and plan digest. It names its exact successor.
The host publishes the successor independently. Existing activation verifies
target data against host observations before removing the guard. An ACTIVATING
retry also checks those observations when a journal already claims ACTIVE.
An ACTIVE pin permits later ordinary edits and metadata inspection.

Runtime and reverse/removal admission validate each predecessor's exact digest,
SUPERSEDED phase and reciprocal successor link. An arbitrary SUPERSEDED row is
not admitted. Known ancestors remain in the journal until approved removal.
Do not recursively embed complete predecessor plans or rewrite their identities.

Deploy a transition/v2-capable host reader before successor publication.
Older transition readers fail format admission. Ciphertext readers and retained
old wrappers remain separate recovery dependencies. No wrapper/key deletion,
automatic backup retirement, new authority service or stronger revocation
guarantee follows from this format. Production providers, authenticated host
publication and independent review remain UNKNOWN.

## Adopted-target root rewrap: 2026-10-24

Use `cryptalis.rewrap/v2` when an explicit restore binding or inherited restore
lineage supplies the adopted target. Keep the previous proposal fields and add
`restore`: a complete `cryptalis.restore/v1` document or JSON `null` for inherited lineage.
Ordinary rewrap/v1 proposals and transition/v2 successors keep their existing contract.

The successor uses `cryptalis.transition/v5`, `kind: rewrap` and a nonempty,
flat `restore_lineage` list of complete restore/v1 documents. Keep the flat
predecessor list. Each binding's source operation/digest must occur once among
predecessors, in increasing ancestor order. Adoption identities must be distinct.
Each later binding starts at the previous binding's target. All owner principals
stay unchanged. The latest binding target equals the successor target.

Validate bindings before provider or maintenance effects. Every restated frame
CHECK must match its compiled field's exact recognized PostgreSQL 16 form and
carry `probe: rejected-malformed-frames`. Shared schema admission merges these
immutable definitions in order. The newest definition wins, then the optional
current binding takes precedence. Later backup adoption retains inherited forms,
even without a new restatement. Historical custody/state observations do not
become current authority.
For an explicit binding, every recorded custody tenant and policy digest must
match the original source's key-policy map before provider or maintenance effects.
The binding can record a subset of that map. Historical inherited bindings do
not need to match the successor's later rewrapped policy.

The first execution validates the original source and explicit binding. A PENDING
retry validates its immutable successor and reciprocal predecessors. It does not
reuse the superseded source's former ACTIVE state digest. Cancellation restores
the exact original source state under its ACTIVE pin and original binding.
Terminal retries inspect current authority and preserve later edits. An old
binding cannot authorize the successor as its original source.

Repeated rewrap carries flat lineage without recursive source artifacts.
The [payload extension](#adopted-target-payload-rotation-2026-10-24) defines the
separate v5/v6 payload route. The [search extension](#adopted-target-search-rotation-2026-10-24)
defines search rotation with inherited lineage.
Host custody, restore approval, source fencing and publication remain external
assertions. No cryptographic format, key deletion or authority relaxation follows.
**VERIFIED, bounded native profile:** one
[source export](_reset/fresh-cluster-export-20261024-5.json) and
[17 fresh-target controls](_reset/fresh-cluster-restore-20261024-4.json) pass.
The [earlier expanded run](_reset/fresh-cluster-restore-20261024-3.json) retains
15 passes and two failures. All seven production gates remain UNKNOWN.

## Pending root-rewrap cancellation: 2026-10-23

**IMPLEMENTED, bounded native verification:** cancellation uses the original
proposal and the exact source ACTIVE pin, republished by the trusted host while
writers remain stopped. A successor pin cannot authorize source writers.
The target provider can remain unavailable because cancellation changes no roots
or frames. The source policy and retained readers must still authenticate data.

Use the shared executor and maintenance approval. Under table locks, require the
exact PENDING successor, source SUPERSEDED link, original source state digest,
schema, guard, and proposal frame/membership observations. Restore the original
source ACTIVE state and remove only successor guards in one transaction.
Retain the successor as ABORTED with exact proposal and source linkage.
An already-ACTIVE successor requires a new rewrap, rather than cancellation.
The original contract excluded adopted restored targets. The
[extension](#adopted-target-root-rewrap-2026-10-24) adds their bounded cancellation path.
Admit the caller's source ACTIVE pin separately. The deterministic successor
selects the shared executor identity and current verification cost. Its internal
PREPARED pin supplies no host publication authority. Historical protection work
does not repeat and supplies no cancellation pause estimate.

A retry after an uncertain commit inspects the terminal marker and current
source authority. It cannot reapply snapshot data or resurrect a source that
a later operation superseded. Ordinary source edits after cancellation remain
valid. Keep retained policies and backup dependencies until explicit retirement.

## Payload-rotation preparation and activation: 2026-10-23

**SPECIFIED:** use two immutable host artifacts. A preparation proposal P pins
the current source plan, ACTIVE pin, source frame/membership observations, exact
retained policies, batch limits and measured costs. P reserves a distinct
successor operation ID. It supplies no application deployment authority.

The target retains every exact source wrapper and reader root. It adds exactly
one independent payload root with a generation above all retained payload
generations. The selected search generation and wrapper remain unchanged.
Rewrap and search rotation remain separate workflows. No normal rotation deletes
retained roots or backup dependencies.

The staged executor will commit fresh target ciphertext and chunk progress
together in operation-owned shadows. Original public frames remain intact.
Before destructive switch, sealing must authenticate both exact active
generations, compare exact decoded values/NULLs and unchanged search headers,
and compare original frames/membership against P. Sealing returns an immutable
activation plan A with observed target frame digests. Repeated sealing of the
same committed bytes must produce identical A, without new nonces or timestamps.
The host must persist A before switch and publication.

The final switch must repeat paired verification under maintenance locks.
Source SUPERSEDED to P, P SUPERSEDED to A, and A PENDING commit together.
A's flat predecessor list includes both source and preparation identities.
Its target digests supply publication verification, including an ACTIVATING
retry when the database journal already claims ACTIVE. Journal hashes cannot
replace host-pinned observations. A genuine ACTIVE pin permits later edits.

Preparation planning and staged execution remain separate evidence boundaries.
Row limits alone do not bound logical memory. Scan length metadata before frame
retrieval and bound the aggregate source/target/decoded-text budget across all
fields and tenants. Python, driver, database and provider overhead remain outside
this logical bound. Estimates require host measurements and qualify no capacity.

Payload preparation uses EXPANDED and BACKFILLED progress under P's unchanged
identity. Each chunk holds write-excluding locks across length probes, frame
reads, shadow writes and the journal commit. No chunk overwrites an already
populated unprocessed shadow. Resume authenticates the committed prefix and
preserves its ciphertext and nonces. BACKFILLED requires a complete paired
source/target pass on every successful return, including a terminal retry.
An unkeyed status call reports recorded progress and NOT_PERFORMED verification.

Derive each shadow from the original field's reserved payload name plus
`_rotation`. It is nullable bytea without defaults, constraints or indexes during
preparation. Existing shadow names cause refusal. Validate the exact guard and
shadow definitions, remove only those facts from catalog observations, and bind
the remaining source facts to P's host-pinned schema digest. Source journal
identity and original state remain unchanged until the final switch.
Ordinary source attachment refuses the changed staging schema. Keep workers
stopped until cancellation or completed publication.

Pre-switch cancellation needs the republished source ACTIVE pin and source keys.
It authenticates the source against P, removes only P's shadows and guards, and
records P ABORTED atomically. Target custody can remain unavailable. Repeated
cancellation inspects the terminal marker and current source authority without
replaying old data. A later source supersession prevents an old cancellation
from reviving it. The [adopted-lineage extension](#adopted-target-payload-rotation-2026-10-24)
defines preparation after a published lineage-bearing successor. Direct planning
from an explicit restore binding follows the
[separate v2 contract](#direct-restore-binding-generation-planning-2026-10-24).

The initial final-switch implementation must preserve the existing public
columns, their constraints, native expression indexes, grants and metadata.
Use a server-side ciphertext UPDATE from the verified shadows under final
maintenance locks, then remove the shadows and exchange P's guards for A's
guards in the same transaction. Verify the copied target observations against
A before commit. This choice requires another complete-table write in the
terminal transaction. Measure and report its WAL and pause cost. Bounded
preparation chunks do not make that terminal write a bounded committed chunk.
A future column swap needs separate metadata-preservation evidence.

If A already records PENDING, retry must authenticate the current target and
exact reciprocal lineage against A. Original source frames no longer supply a
retry comparison. Missing A with partially superseded source or P is an
inconsistent state, not permission to reconstruct a commit. Preparation resume
and cancellation must reject the switched P.

Without restore lineage, activation uses `cryptalis.transition/v3` with `kind: payload_rotation`.
Its exact fields include `payload_rotation_plan_digest`,
`payload_rotation_observations`, `payload_batch_limits`, and the flat predecessor
list. Scopes match the observed model identities and row counts. Construct
scope order from the source lock, independent of JSON object key order.
Sealing verifies and serializes these observations. It does not create a
cryptographic signature or replace trusted host persistence and current authority.

A requires measured native copy throughput and copy WAL bytes per row. Its
terminal estimate counts one source pass, both sides of paired verification,
one post-copy target pass, one publication pass, and the atomic copy. Preparation,
sealing, DDL, lock drain, provider overhead and capacity guarantees stay outside
that estimate. The journal records copy wall nanoseconds and the cluster-wide
WAL delta around the native UPDATE loop. Those diagnostic observations cannot
supply host authority or isolated operation cost.

Before payload publication, validate the exact predecessor chain, journal
progress shape, table owner, public metadata and complete journal inventory.
ACTIVATING repeats bounded target authentication against A, including a journal
claim of ACTIVE. A genuine ACTIVE pin permits later edits. The sealed target
snapshot does not become an immutable-data requirement for ordinary operation
or subsequent current-value decrypt-back/removal.

## Adopted-target payload rotation: 2026-10-24

**IMPLEMENTED, bounded verification:** payload rotation accepts a current ACTIVE
v5 rewrap or v6 payload successor that already carries validated restore lineage.
The preparation proposal keeps `cryptalis.payload-rotation/v1` and its complete
embedded source. This v1 encoding adds no restore member or publication authority.
The [direct-binding extension](#direct-restore-binding-generation-planning-2026-10-24)
defines its separate v2 route.

With inherited lineage, activation uses `cryptalis.transition/v6`,
`kind: payload_rotation`. Keep every v3 payload proof, observation, batch limit,
scope, policy and cost requirement. Add the source's nonempty, flat
`restore_lineage` unchanged. The flat predecessor list retains all source
ancestors, then the exact source and preparation identities. Payload activation
without lineage remains v3.

Apply the existing pure lineage admission before provider or maintenance effects.
Require exact source/digest ancestor order, distinct adoption identities,
continuous physical targets and unchanged owner principals. The latest binding
target must equal the successor target. Restated frame CHECK definitions must
match recognized compiled-field PostgreSQL 16 forms and carry the required
`rejected-malformed-frames` probe. Historical binding custody remains history,
rather than current policy or publication authority.

Preparation, prefix-preserving resume, source-only cancellation, sealing,
atomic cutover and separate host publication retain their existing rules.
PENDING retries verify the successor and reciprocal ancestry. Genuine ACTIVE
authority permits later edits and current-value removal. A later ordinary root
rewrap of v6 uses rewrap/v2 and produces a v5 successor with the same restore
lineage. Fractional native copy rates must round-trip in v6 and embedded v6
sources without changing their artifact identities.

Readers that cannot admit the embedded source or v6 activation must refuse
before effects and publication. Deploy compatible readers first.
[Search rotation with lineage](#adopted-target-search-rotation-2026-10-24) uses its
separate successor format. Direct restore-binding generation planning follows its
[separate v2 contract](#direct-restore-binding-generation-planning-2026-10-24). CF1, retained-reader requirements, root retirement, maintenance approval,
host fencing and publication authority do not change. All seven production gates
remain UNKNOWN. See the [lifecycle contract](lifecycle.md#payload-rotation-after-adopted-lineage-2026-10-24).
Native TEXT/VARCHAR and installed TEXT profiles verify this path. The unchanged
Smolink application also verifies the final artifact through current-value exit.
[Status](status.md#payload-rotation-after-adopted-lineage-2026-10-24) records exact
counts, failed attempts and artifact boundaries.

## Restored payload generations and privilege admission: 2026-10-23

**IMPLEMENTED, bounded:** adopt a backup of published payload activation A through
the existing restore binding. Require A's exact source/preparation ancestry,
strict progress shape, current schema and selected generation before admission.
Authenticate the backup's current rows under its retained policy. Do not compare
ordinary postpublication edits against A's historical cutover frame digest.
The host must authorize restore, quarantine and writer exclusion separately.

Check effective runtime privileges and protected-column metadata before effectful
schema probes or provider access. Reject journal writes through table or column
grants. Reject database/schema CREATE and protected-table TRIGGER/TRUNCATE.
Apply the shared role check during initial planning, active admission, adopted
binding admission and shared maintenance execution. Later grant changes require
a new admission check. These observations do not enforce every external writer
boundary or replace host credential control.

Keep the restore binding format unchanged. Retain old keys for approved recovery
obligations, but refuse an old-generation frame under the selected new policy.
Fresh-cluster backup recovery alone does not admit a new generation rotation.
The [adopted-lineage extension](#adopted-target-payload-rotation-2026-10-24) defines
payload rotation after a published v5/v6 successor. The
[search extension](#adopted-target-search-rotation-2026-10-24) defines its separate route.
Direct restore-binding generation planning follows its
[separate v2 contract](#direct-restore-binding-generation-planning-2026-10-24).
Search reindex, qualified production providers and all seven full gates remain
open or UNKNOWN. See the [recorded evidence](status.md#payload-backup-recovery-and-runtime-admission-checkpoint-2026-10-23).

## Reverse publication selects the runtime boundary: 2026-10-23

**IMPLEMENTED, bounded:** repeat the shared effective-privilege check during
reverse execution and status. Select the role from the trusted host pin.
Prepublication pins through PLAINTEXT_PENDING require the source runtime.
PLAINTEXT_ACTIVATING, PLAINTEXT_ACTIVE and REMOVING require the declared plaintext
runtime. Database progress cannot change that selection. Plaintext planning
checks the selected role before provider access.

Preserve package-free terminal retries. When REMOVED matches an actually absent
journal, inspect the native schema without either former runtime role check.
An existing journal cannot use that exception. Preserve native metadata and later application edits after retirement. Privilege observations do not authenticate the
host, freeze later administrative grants or prove credential deletion. See
[status](status.md#reverse-runtime-admission-checkpoint-2026-10-23).

## Search-generation preparation and sealed activation: 2026-10-23

**IMPLEMENTED, bounded native verification:** use the existing writer-paused preparation and publication
protocol for search-key rotation. Keep payload selection and every retained
wrapper/root unchanged. Each selected search policy adds exactly one independent
root above all retained search generations. A search-less policy remains exact.
Storage-only frames remain byte-identical. Searchable frames require a fresh
OS nonce and authenticated resealing because CF1 binds the search header.
The cryptographic construction and CF1 format remain unchanged.

Preparation P uses `cryptalis.search-rotation/v1`. Without restore lineage, sealing emits immutable
activation A as `cryptalis.transition/v4`, with `kind: search_rotation`.
A binds `search_rotation_plan_digest`, `search_rotation_observations` and
`search_batch_limits`. Deploy a v4-capable host reader before publication.
Retain v1 protection, v2 rewrap and v3 payload artifact readers.

Share the concrete encrypted-shadow, cursor, guard, copy and publication
mechanics across the two generation workflows. Keep their policy and header
checks explicit. Paired verification requires exact text, NULL, type, identity
and selected generations. It recomputes target search terms under the new root.
Source-to-P-to-A lineage and public-frame replacement commit atomically.
Post-copy and ACTIVATING retries require A's actual target frame hashes.
A genuine ACTIVE pin permits later ordinary edits.

Keep one active query namespace. Admit retained search readers only under an
exact bound deployment policy. Never query multiple generations with OR.
Native public UPDATE maintains expression and unique indexes inside the
terminal transaction. Native conflicts roll back the entire switch.
Host copy-rate and WAL estimates must include this index work.

Restore uses the existing approved binding and selected-generation checks.
Search rotation with adopted lineage follows the
[search extension](#adopted-target-search-rotation-2026-10-24). The
[payload extension](#adopted-target-payload-rotation-2026-10-24) defines the separate
lineage-bearing payload route. Rotation deletes no
retained keys and supplies no unlinkability or cryptographic-erasure claim.
Production custody, authority and independent review remain unqualified.

## Adopted-target search rotation: 2026-10-24

**IMPLEMENTED, bounded source and installed verification:** search rotation uses the current ACTIVE
v5/v6/v7 successor. Require validated restore lineage and its own host pin.
The `cryptalis.search-rotation/v1` preparation proposal keeps its complete embedded
source and existing members. The [direct-binding extension](#direct-restore-binding-generation-planning-2026-10-24)
defines a separate v2 encoding for an explicit binding.

Activation uses `cryptalis.transition/v7` with `kind: search_rotation`. Retain
every v4 search proof, observation, batch limit, scope, policy and cost requirement.
Add the source's unchanged, nonempty flat `restore_lineage`. Keep inherited
predecessors, then append the exact source and preparation identities.
Without lineage, search activation remains v4.

Reuse existing pure lineage rules for ordered source/digest ancestors,
distinct adoption identities, continuous targets and unchanged owners.
Require exact recognized frame CHECK definitions with rejection probes.
Historical bindings cannot supply current policy or publication authority.
Existing source-only cancellation, terminal current-authority checks, atomic
switch and separate successor publication remain required.

Searchable frames receive new terms and authenticated headers. Storage-only
bytes and selected payload generation stay unchanged. Keep one active query
namespace and the existing index representation, native uniqueness and rollback.

Rewrap of v7 produces rewrap/v2 and a v5 successor. Payload rotation of v7
produces v6. Both preserve lineage. Fractional copy rates must round-trip in
direct and embedded v7 sources. Deploy compatible readers before publication.
Unsupported readers must refuse before effects. CF1, journal formats, host
authority and retained-key obligations do not change. All seven gates remain UNKNOWN.
See the [lifecycle contract](lifecycle.md#search-rotation-after-adopted-lineage-2026-10-24).
Source TEXT/VARCHAR and installed TEXT controls verify this boundary.
[Status](status.md#search-rotation-after-adopted-lineage-2026-10-24) owns exact
receipts, affected regressions and application qualification limits.
The unchanged six-file SQLModel [adoption journey](status.md#original-searchable-sqlmodel-adoption-2026-10-24)
adds bounded source and installed-wheel application evidence for this existing
contract. Its fixture-only email domain and explicit single tenancy do not
qualify production email populations or change leakage admission.

## Direct restore-binding generation planning: 2026-10-24

**IMPLEMENTED, bounded source and installed verification:** add `restore=None` to the public payload and
search planners. No binding retains the exact purpose/v1 proposal, including
sources with inherited lineage. A nonnull existing `RestoreBinding` selects
`cryptalis.payload-rotation/v2` or `cryptalis.search-rotation/v2`. Keep all v1
members and add mandatory `restore` with the complete binding. Reject null
`restore`, missing/extra members and wrong purpose/version pairs.

Retain the complete original source, ACTIVE pin, policies, target_id and journal
identity. Evaluate its physical target through the binding without rewriting
the source artifact. Before provider work, validate source/binding identity,
original-source custody, frame CHECK/probe forms, unchanged owner and prospective
flat lineage. The proposal `journal_state_digest` must equal the binding's recorded
journal state digest. Binding custody remains an observed subset of source policies.

Reuse maintenance, staging, status, sealing and cancellation with the embedded
binding and actual target. Source identity and journal state remain unchanged
before switch. Cancellation requires the source ACTIVE pin, source custody and
maintenance approval, without target custody. Terminal retries preserve current
edits and cannot revive superseded source authority. PENDING switch retries keep
target-only authentication and reciprocal ancestry checks.

Activation remains v6/payload_rotation or v7/search_rotation. Append the explicit
binding to inherited flat lineage and retain source-to-preparation-to-activation
identities with every existing proof. Old proposal readers must refuse v2 before
execution. Compatible existing v6/v7 readers can read the unchanged activation
formats. Crypto, provider, host-authority and retained-key contracts do not change.
All seven production gates remain UNKNOWN. See the
[lifecycle contract](lifecycle.md#generation-planning-from-a-restore-binding-2026-10-24).
[Status](status.md#direct-restore-binding-generation-planning-2026-10-24) records
19 controls each for source TEXT/VARCHAR and installed TEXT, refusal/recovery scope,
and the unchanged SQLModel direct source/installed and legacy installed journeys.

## Native UUID lookup inputs: 2026-10-24

Preserve the original Session.get/get_one arguments, SQL binds and identity-map keys.
For admitted UUID SELECT predicates, derive only the expected authenticated row UUID.
Accept PostgreSQL ASCII UUID spellings with paired optional braces and optional hyphens between four-digit groups.
The crypto context still uses the native 16-byte UUID.
Text identity lookups retain native SQL execution and object reuse.

The column and every matching bind require the qualified native Uuid contract.
Both type flags must be true. Native input and result processor methods must remain unchanged.
Existing callable, collision, SQL hook, dispatch and variant checks still apply.
Malformed strings and integer inputs retain native UUID bind errors and rollback requirements.
Their expected point authorizes no result, including an outer-join NULL.
One malformed IN member invalidates the whole expected set.
A genuine empty IN list retains native NULL-extension behavior.
Other input types remain unadmitted. DML and tenant identities keep their typed-value rules.

This changes input compatibility, not the record codec, CF1 framing, keys or search terms.
The original application and JWT logic stay unchanged.
The native oracle and original HTTP journey must pass before qualification.
All seven production gates remain UNKNOWN.

## Unprotected mapped DELETE: 2026-10-24

**IMPLEMENTED, bounded admission:** an attached session can execute a finite
native DELETE on an unprotected table in the same registry. The original
FastAPI administrator route needs this operation to remove a user's Items
before the protected User flush delete.

Admission requires an exact mapped local table and native compiler dispatch.
The table cannot share a protected physical address. Predicates admit direct
equality with typed literal binds and AND composition. Core targets, caller
RETURNING, fetch synchronization, custom AST nodes, functions and subqueries
remain unadmitted. Default, auto, evaluate and False synchronization retain
native ORM execution and transaction behavior.

The request captures table and column metadata plus immutable predicate values
before key resolution. Checks repeat after callbacks and at compiled and final
driver dispatch. The existing driver guard remains active. A changed target,
predicate, SQL string or bind raises a typed failure before execution.
Protected scoped DELETE keeps its existing contract.

Native identifier comparison uses text and quoting flags. A plain str and a
quoted_name with quote=None emit the same SQL and remain equivalent.
Effective annotated column/table metadata must match its original physical node.
Deannotation alone does not establish physical ownership.

This bounded path changes no cryptographic format, provider authority or tenant
policy. It does not admit arbitrary public DML. Native PostgreSQL and unchanged
HTTP application evidence belong to the status checkpoint. All seven production
gates remain UNKNOWN.

## Owned-sequence metadata and restored identity: 2026-10-24

**IMPLEMENTED, bounded verification:** preserve an ordinary persistent sequence
automatically owned by an admitted protected column. The sequence and table must
keep the same schema and owner. Existing generated-key and protected server-default
refusals remain required. Extension, internal and other unrecorded sequence
dependencies require separate admission.

Use `cryptalis.lock/v5` when any protected column owns an admitted sequence. Add
`owned_sequences` to each model's existing source metadata. Capture qualified name,
OID, owner, type, configuration, comment, effective ACL with grantor and ownership
dependency. Validate the complete inventory before destructive DDL. Preserve the
existing lock bytes and format selection for applications without owned sequences.

Forward and reverse switches transfer ownership in their existing transaction:
detach the sequence, replace the column, then attach the same sequence to its
replacement. Repeat identity and metadata checks after native sequence locking.
Never recreate the sequence or replay its counter. Current increments and native
rollback gaps remain PostgreSQL behavior. See PostgreSQL 16
[ownership and locking](https://www.postgresql.org/docs/16/sql-altersequence.html)
and [counter semantics](https://www.postgresql.org/docs/16/functions-sequence.html).

Sequence-bearing adoption uses `cryptalis.restore/v2`. Keep existing binding
members and add a complete ordered `sequences` inventory with model, schema,
name, column, source OID and target OID. Compare every logical sequence fact
before admitting the restored OID. Later checks require that exact target OID.
Compose mappings through flat lineage without changing the original source or
journal authority. Sources without sequences retain restore/v1.

CF1, key policy, retained readers and host fencing remain unchanged. Existing
outer transition formats retain the new embedded lock. The previous installed
reader refuses lock/v5 and restore/v2 before database or provider effects.
Native tests cover lifecycle, rollback, uncertain COMMIT, exact restored identity,
second-adoption mapping, latest-value removal and a package-free restart.
The current owner and ACL remain exact; the test owner cannot inject transfer
to another owner. Do not claim that live control as passed. Sources without
sequences retain the existing format and application adoption paths.

The [status checkpoint](status.md#owned-sequence-preservation-and-restore-2026-10-24)
owns executable results and their source boundary. Native sequence cache gaps
and counter changes survive rollback as PostgreSQL defines. No sequence counter
snapshot, reset or replay is admitted. All seven production gates remain UNKNOWN.

## Column-preserving conversion design inputs: 2026-10-24

This section records the native-only checkpoint before product implementation.
The [implementation decision](#original-slot-layout-and-restore-authority-2026-10-24)
supersedes its pending implementation state. Its native evidence keeps the
original source and three-row measurement boundary.

**VERIFIED, native SQL oracle only. Product design remains SPECIFIED.**
One PostgreSQL 16 table retains its relation OID, original public `attnum` values
and visible column order. Each direction uses one batched `ALTER COLUMN TYPE ... USING`
with staged values. The fixture uses fixed public CF1-like bytes. It does
not call the protection or deprotection APIs and proves no cryptographic property.
See the [native observations](_reset/column-identity-native-observations-20261024.json)
and [test receipt](_reset/column-identity-native-20261024.json).

This is a third design candidate alongside the historical drop/rename and
retained-native approaches. The public protected column becomes bytea. No native
filler remains. The experiment observes heap and index storage rewrites and an
ACCESS EXCLUSIVE lock. Its three rows establish no production pause, WAL or
resource budget. Existing operational artifacts keep their drop/rename behavior.

The candidate must carry its strategy in the immutable lock so that root,
payload and search successors retain it. A proposed lock/v6 would require the
exact member `layout: "preserve-public-slots/v1"` and the v5 metadata shape.
Earlier lock formats and their selection must retain their current semantics.
Unknown layout values must refuse before effects. This encoding is not implemented.

The proposed public opt-in is `layout=None` on `compile_protection()` and
`migration.plan()`. The planner must forward it to the compiler. None retains
the current selector and bytes. Only the exact new layout token selects v6.
Invalid values must refuse before connections or providers. Attachment, reverse
and rotation derive the strategy from the validated lock. A previous lock is
comparison evidence, not an implicit opt-in. No manifest schema change is proposed.

A logical restore can compact dropped slots while preserving visible column
order. Do not tighten the shared legacy metadata comparison. The proposed
restore/v3 would instead require a complete ordered public-column map with
`model`, `column`, `source_attnum` and `target_attnum`, plus the complete sequence
map or an empty list. Each source slot must match the current inherited mapping.
Target slots must be positive and unique per model, with unchanged visible name
order. Flat lineage must compose these maps without changing source artifacts,
journal authority or host pins. Existing v1/v2 bindings cannot authorize the new
layout. This mapping and its failure controls remain unimplemented.

The implementation must rebuild frame CHECKs and equality indexes against the
public column before dropping its shadow. Reverse must remove those generated
dependencies, change the same public attribute to its native type and restore
the captured constraints, indexes, statistics and column metadata. Sequence
ownership can stay on the original attribute. Exact mapped inventory checks
remain required. The oracle observes that comments, statistics targets, options
and grants survive the bytea conversion, while storage and compression change.
Define exact ACTIVE metadata rules for those facts. Do not waive drift checks.

Product admission still needs real authenticated values, equality/IN/uniqueness,
phase interruption and uncertain COMMIT recovery, old-reader refusal, a genuine
compacted restore, repeated adoption, wrong-map refusal before providers and
latest-value package-free positional reads. CF1 and key/tenant/host authority
contracts remain unchanged. All seven production gates remain UNKNOWN.

## Original-slot layout and restore authority: 2026-10-24

**IMPLEMENTED, bounded evidence in the [status checkpoint](status.md#public-column-slot-preservation-2026-10-24):**
`compile_protection()` and `migration.plan()` accept `layout=None` or the exact
string `preserve-public-slots/v1`. None retains existing lock/v2-v5 selection and
bytes. The explicit token selects lock/v6 with a required top-level layout member
and the v5 metadata shape, including empty sequence inventories. Unknown values
refuse before compiler connections. A previous lock does not select the layout.
Structural parsing requires distinct, increasing native integer source slots
in the range 1 through 32767. Attachment derives its strategy from the lock.

The new switch uses one batched ALTER TYPE USING verified shadows per model.
It removes only admitted native dependencies and generated shadow dependencies,
rebuilds exact public-bound CF1 CHECKs and equality indexes, then drops its shadows.
The original public attributes remain bytea, with their original slots and order.
Reverse changes those same attributes to their native types and restores the
captured constraints, indexes, extended statistics and column metadata. Existing
lock/v1-v5 artifacts keep their earlier drop/rename path. CF1, key policy, tenant
addresses, retained readers and publication authority remain unchanged.

ACTIVE metadata requires exact recorded comments, statistics targets, options and
grants. Storage must be EXTENDED with the default compression policy. Captured
native constraints, indexes and extended statistics must be absent until reverse.
Expression statistics refuse during planning and later admission, including
expression-only objects whose ordinary column list is empty. This closes a
reproduced late-metadata failure in the new path. Native sequence ownership stays
on the original public attribute. Full mapped sequence identity checks remain.

Restore/v3 requires all existing binding members plus `columns` and `sequences`.
The columns list covers every public source column exactly once using `model`,
`column`, `source_attnum` and `target_attnum`. Slots are native integers from 1
through 32767. Entries sort by model and source slot. Source and target slots
are unique per model, and target slots increase in original visible name order.
The sequence list is complete or empty, according to the source inventory.

Logical restore may compact dropped slots. Adoption compares complete logical
facts and visible name order before admitting the actual target slots. Later
checks require those exact slots. Flat lineage composes source-effective to
target slots through reverse, root rewrap and both generation workflows. Original
source artifacts, pins and journal authority stay unchanged. Restore/v1-v2 cannot
authorize lock/v6, and old operational readers refuse the new formats before effects.
Legacy metadata comparison retains its ordinal normalization.

Each switch rewrites heap and index storage under a native exclusive lock.
Current rate, temporary-space and WAL estimates do not include that DDL cost.
No production pause or resource budget is qualified. Existing maintenance
approval, quarantine and host fencing remain required. The new layout is an
explicit opt-in and does not convert already replaced legacy slots. All 34
objective states and all seven UNKNOWN production gates remain unchanged.

The [original three-field application checkpoint](status.md#original-three-field-sqlmodel-fresh-adoption-2026-10-24)
extends this contract's verification through genuine fresh adoption and direct
restore-binding search planning. Source and restored target table identities have
separate evidence. The observed target public slots remain fixed through removal.
This test profile adds no product contract or production qualification.

## Expression-statistics admission across layouts: 2026-10-24

**IMPLEMENTED, verification in the [status checkpoint](status.md#legacy-expression-statistics-admission-2026-10-24):**
all layouts refuse expression statistics on an admitted model table with
`unsupported_dependency`. Compiler planning already refuses these objects.
The runtime catalog guard now applies to legacy source, protected and reverse
admission as well as the explicit public-slot layout.

Expression-only statistics can have an empty ordinary column list. Admission
checks `pg_statistic_ext.stxexprs IS NOT NULL` before key resolution or transition
effects. The query tests catalog existence without evaluating the expression.
Removing the unadmitted object permits the same plan to resume after inspection.
This extends an existing dependency refusal and changes no lock, transition,
restore, ciphertext or key contract. Production qualification remains UNKNOWN.

## Host-configured protection CLI: 2026-10-24

**VERIFIED within the source and installed profiles in the [status checkpoint](status.md#operational-cli-protection-workflow-2026-10-24):**
`plan` and protection `apply` compose the existing planner and executor.
They add no transition engine, artifact format or key provider.
Rotation, reverse and removal commands remain required follow-up work.

An explicit synchronous `MODULE:FACTORY` supplies one exact typed context.
`PlanningContext` contains the owned engine, registry, writer inventory, search
reviews, key resolver, runtime role, target and measured planner inputs.
`ApplyContext` contains the owned engine, key resolver, current deployment pin
and maintenance approval. The CLI infers none of these inputs.
Doctor retains its separate exact key-free tuple and existing read-only routes.

Planning produces a proposal, with `HOST_SUPPLIED_CONTEXT` authority.
Apply and abort retain `HOST_SUPPLIED_PIN` authority. Resume and abort must name
the supplied artifact's operation. Default apply stops at PENDING.
ACTIVE publication requires the host's actual ACTIVATING pin.
Aborting after switch refuses instead of transforming or discarding current data.

The factory transfers a synchronous PostgreSQL psycopg engine with safe logging
and transactional connections. Fresh, unshared ownership remains a host assertion.
The CLI disposes accepted engines on success and failure.
It suppresses Python streams during factory, API and disposal calls.
Host code, native descriptor writes and existing logger effects remain UNKNOWN.
The CLI does not authenticate or sandbox host code.

Plan output uses private, complete temporary files and exclusive atomic publication.
It never replaces an existing destination. Success requires file and directory durability.
Diagnostics retain observed publication or returned committed progress after output
or cleanup failure. An unreturned executor outcome requires journal inspection.
The same immutable artifact remains the recovery input.
Exceptions, credentials, keys and application rows are not diagnostic messages.
The focused source profile passes 22 cases. Existing source CLI and Doctor
controls pass 189 cases. The actual installed wheel passes their combined 211
cases, including the unchanged application, process interruption and independent
resume. These checks do not qualify the full lifecycle or release gates.
All seven production gates remain UNKNOWN.

## Saved reverse plans and approved removal CLI: 2026-10-24

**VERIFIED within the bounded source and installed profiles in [status](status.md#operational-cli-reverse-and-removal-2026-10-24):**
`plan --reverse SOURCE` creates a
read-only current-value reverse proposal. `rollback REVERSE` executes the saved
proposal through the existing decrypt-back executor. `apply REVERSE` shares that
execution path. Rollback does not implicitly create a plan or plaintext consent.
The existing protection manifest input and `--reverse` are mutually exclusive.

The host must review the persisted reverse artifact before supplying its exact
`PlaintextApproval`. Reverse planning uses an explicit ACTIVE source pin and an
explicit restore binding or None. The reverse artifact records any supplied
binding. Apply, abort and removal use that recorded target without an override.

Default reverse apply stops at PLAINTEXT_PENDING. Plaintext publication requires
the host's actual PLAINTEXT_ACTIVATING pin. Removal requires the existing
maintenance, plaintext and removal approvals. Its context contains no keys.
An approved retry with a REMOVED pin reuses the existing removal verifier.
A missing journal alone does not authorize success or retirement.

These commands compose the existing lifecycle APIs. They do not uninstall the
package, destroy provider keys or prove retained-backup disposition. Doctor's
key-free context remains separate. Production qualification remains UNKNOWN.
The focused source profile passes 41 controls. The affected-source suite passes
260. The actual installed wheel passes their combined 301 controls. Each primary
run skips the case that needs a separate restored cluster. Source and installed
fresh-cluster export and restore pass one each. Both real application process
interruptions, independent resumes and current-value native exit pass. These
checks leave all seven production gates UNKNOWN.

## Root-rewrap CLI artifacts and authority: 2026-10-24

**VERIFIED within the bounded source and installed profiles in [status](status.md#operational-cli-root-rewrap-2026-10-24):**
`keys rotate rewrap` composes the
existing plan, apply, activation and cancellation APIs. Payload and search
rotation CLI workflows remain required work.

Planning persists proposal P. Apply persists its deterministic successor A
before host loading or database execution. Ordinary output collisions refuse.
Explicit resume may re-sync an existing private, regular, non-symlink file only
after exact byte comparison with A. It never replaces a different artifact.
Keeping P permits recovery of A without creating another proposal.

Four exact host contexts separate planning, apply, activation and abort.
Planning and apply require both source and target custody. PENDING apply retry
still requires both. Activation uses only target custody and the actual successor
publication pin. Cancellation uses only source custody and the separately
republished source ACTIVE pin. The cancellation context contains no target keys.
Restore authority enters through planning and remains embedded in P and A.

Artifact publication facts remain separate from database progress. A saved
PREPARED artifact does not establish the database phase. An API call that returns
no Progress requires journal inspection. Returned Progress and file facts survive
output or cleanup errors. Commands create no provider, root, deployment pin or
approval. Existing ciphertext, key isolation and format contracts remain unchanged.
Rewrap-specific denial classification stays separate from existing commands.
Two native controls reproduce the earlier candidate's changed refusal exit code.
The correction preserves exit 3 for protection and reverse publication mismatches.
The focused 54 and affected 363 source controls pass. The actual installed wheel
passes their combined 417 controls. Primary runs skip two separate fresh-target
cases. Source and installed genuine fresh-cluster export and restore each pass
one. All 214 Python hashes remain stable at the recorded boundary. These checks
leave all seven production qualification gates UNKNOWN.

## Payload CLI sealing and retained activation artifacts: 2026-10-24

**IMPLEMENTED:** `keys rotate payload` composes the existing preparation,
status, seal, switch, activation and cancellation APIs.
Search rotation CLI remains required work.

Preparation P reserves a successor UUID. It cannot supply A's digest or sealed
frame observations. Seal must authenticate the completed BACKFILLED shadows and
return the existing activation artifact A. Seal changes no journal phase.
If its output is lost before switch, repeat authenticated sealing with the same
staged ciphertext and explicit copy measurements. Do not derive A from P or
recorded journal claims.

Persist private P and A. Before switch, verify A through one bounded regular
non-symlink descriptor, compare its exact bytes, and sync that descriptor and
its parent directory. Retain both artifacts after an uncertain COMMIT reply.
After switch, P is superseded and staging is gone. Recovery requires an external
copy of the exact sealed A. The CLI must fail closed if every copy is lost.

Explicit contexts separate preparation, key-free status, sealing, switching,
target-only activation and source-only cancellation. P and A have distinct
operation UUIDs and host pins. Status reports recorded progress with value
verification NOT_PERFORMED. Seal reports artifact facts without synthetic
database Progress. No context creates keys, providers, pins or approvals.
Existing cryptographic, format and tenant contracts remain unchanged.

**VERIFIED within the bounded source and installed profiles:** the
[source profile](_reset/payload-cli-source-focused-final-20261024.json) passes
70 tests. The [affected source suite](_reset/payload-cli-source-affected-20261024.json)
passes 492. The [actual installed suite](_reset/payload-cli-installed-affected-20261024.json)
passes 562. Primary runs skip three genuine-fresh setup cases and one fresh-only
module collection where applicable. They do not prove that skipped module's controls.
Source and installed genuine fresh-cluster export and restore each pass one test.
The real binding embeds directly in P/v2 and A/v6. Wrong authority refuses before custody.
Both original-application profiles retain six unchanged files and four actual SIGKILL
checkpoints, including target-only payload recovery and latest-value native exit.
The [final boundary](_reset/payload-cli-final-boundary-20261024.json) binds seven
current PostgreSQL receipts, both application receipts and the exact installed wheel.
All 215 Python hashes stay stable. All 34 objective states and seven UNKNOWN gates
remain unchanged. This evidence supplies no current full-suite or production qualification.

## Search CLI generation and saved activation authority: 2026-10-24

**IMPLEMENTED:** `keys rotate search` composes the existing search preparation,
status, sealing, switch, publication and cancellation APIs.
The payload and search CLI adapters share their bounded generation flow.
Each purpose retains its own strict proposal kind, digest, scopes and exact contexts.
Existing protection, reverse, rewrap and payload denial classifications stay unchanged.

Search rotation retains the selected payload generation and exact storage-only CF1
bytes. Searchable fields receive authenticated ciphertext with a fresh nonce and
new search terms. The CLI must use the existing API proof and custody checks.
It creates no keys, provider, pin, approval or restore authority.

The [payload artifact-retention decision](#payload-cli-sealing-and-retained-activation-artifacts-2026-10-24)
also governs search P+A. Seal reports artifact facts without a database phase.
First switch uses both custody resolvers. Committed switch retry and activation
use target custody alone. Abort uses source custody and the separate source ACTIVE pin.
Status uses no keys and reports recorded progress with NOT_PERFORMED verification.
A real restore binding can embed directly in search P/v2 and A/v7.
No intermediate root rewrap can substitute for the required binding.

**VERIFIED within the bounded source and installed profiles:** the
[source profile](_reset/search-cli-source-focused-initial-20261024.json) passes
79 tests. The [affected source suite](_reset/search-cli-source-affected-20261024.json)
passes 449. The [actual installed suite](_reset/search-cli-installed-affected-20261024.json)
passes 528. Focused primary and installed runs skip four separate genuine-fresh setup cases.
Source and installed genuine export and restore each pass one test.
The real binding embeds directly in search P/v2 and A/v7.
Wrong binding refuses before key access. Both original-application profiles retain six
unchanged files and five actual SIGKILL checkpoints. Search rotation preserves storage-only
frames exactly, retains payload generation 2 and publishes search generation 2.
Current CRUD, search, Boolean values and latest-value native exit pass.
The [final boundary](_reset/search-cli-final-boundary-20261024.json) binds seven
current PostgreSQL receipts, both application receipts and the exact installed wheel.
All 216 Python hashes stay stable. The 23 exact host contexts retain the previous
16 declarations and all earlier denial classifications unchanged. All 34 objective
states and seven UNKNOWN gates remain unchanged. This evidence supplies no current
full-suite or production qualification.

## Declaration initialization and read-only admission: 2026-10-24

**IMPLEMENTED:** `init --host-context MODULE:FACTORY --out DECLARATION`
creates a private canonical declaration after existing read-only schema inspection.
`--json` selects structured output. The trusted factory returns exactly
InitializationContext(engine, mapping, declaration, writers, search_reviews).
The declaration contains explicit public bytes. The host selects all stable UUIDs,
tenancy, fields, query capabilities and leakage acceptance. The CLI infers none.

Parse the bounded declaration before canonicalization. Canonicalization must not
supply leakage consent that the input omitted. Use the existing declaration format
and exact canonical bytes. Compute manifest_digest from those saved bytes.
The existing Doctor preflight supplies the inspection report unchanged.
Publish only when manifest_schema is PASS. Aggregate status and all six unobserved
checks remain UNKNOWN. Initialization creates no migration plan, layout, keys,
provider, pin, runtime role, target identity or deployment approval.

The command owns and disposes the supplied safe synchronous PostgreSQL psycopg
engine. Refuse an existing output path before host import. Publish exclusively
and sync the private file and parent directory through existing artifact helpers.
Output separates initialization artifact facts from the unchanged nested inspection.
It creates no operation UUID, journal phase or synthetic database Progress.
Failure retains known inspection and file facts. Database effects remain NONE within
compiler inspection. Trusted host-code effects remain UNKNOWN on every outcome.

**VERIFIED within the bounded source and installed profiles:** the
[source profile](_reset/init-cli-source-focused-initial-20261024.json) passes
94 tests. The [affected suite](_reset/init-cli-source-affected-20261024.json)
passes 373. The [actual installed suite](_reset/init-cli-installed-affected-20261024.json)
passes 467. Focused and installed runs retain four separate genuine-fresh setup skips.
Initialization itself uses real PostgreSQL and no key access. Both original-application
profiles consume its private canonical declaration through the existing five SIGKILL
checkpoints and latest-value native exit. Six pinned application files stay unchanged.
The [final boundary](_reset/init-cli-final-boundary-20261024.json) binds three current
PostgreSQL receipts, both application receipts and the exact installed wheel.
All 217 Python hashes stay stable. The previous 23 context declarations and four
denial classifications remain unchanged. All 34 objective states and seven UNKNOWN
gates retain their previous states. This slice repeats no fresh-cluster qualification.
The unchanged core retains its historical boundary at `c612727`.

## Original HTTP application and operational CLI acceptance: 2026-10-24

**VERIFIED within the bounded source and installed profiles:** join the existing
operational CLI lifecycle to the pinned original HTTP, JWT and loopback SMTP
application journey.
This acceptance profile adds no application, model, query, router or authentication edits.
Only the original request-session dependency can receive an attached factory.
Original authorization, password hashing and token validation remain in use.

Exercise initialization, protection, root rewrap, payload generation 2 and search
generation 2 through saved CLI artifacts and explicit host pins and approvals.
Reuse the existing committed-checkpoint interruption protocol. Finish all requests
and background mail before each approved maintenance pause. Reload the entire
original dependency and router graph with the mapping after successor publication.
Observe native row identities before reverse. Finish latest-value reverse/removal
and an original HTTP child that refuses Cryptalis imports.

Keep all 26 pinned source files unchanged. Protect User.email, User.full_name and
User.is_active under the existing explicit fixture policy. Native password hashes
and Item storage remain outside that protection declaration. Compare original HTTP
and local SMTP controls after each relevant publication. Record no JWT, password,
reset token, response body or private database URL in evidence.

Reuse the verified installed wheel when every release-source input and product
module remains identical. Do not label an unchanged artifact as a new build.
Current evidence must identify its own test hashes and runtime origins.
This first join qualifies no browser, deployment, external mail, live custody or
new fresh-cluster cell. All 34 objective states and seven UNKNOWN gates remain unchanged.

The [source run](_reset/http-cli-source-20261024.json) passes both the new joined
profile and the existing HTTP regression. The [joined application report](_reset/http-cli-source-application-20261024.json)
records six HTTP boundaries, four loopback SMTP messages at each boundary and five
actual committed-checkpoint SIGKILLs followed by fresh-process continuation. Native
row counts grow from three before protection to 15 before reverse. Exact latest
plaintext, inactive False, index identities and public slots survive the journey.
The package-free child exercises original HTTP with Cryptalis imports refused;
SMTP is excluded from that child. The [reuse check](_reset/http-cli-artifact-reuse-20261024.json)
confirms unchanged historical wheel bytes and all 43 release-source inputs.
Only the new acceptance profile changes Python source; all 217 previous files remain exact.

The [installed run](_reset/http-cli-installed-20261024.json) passes the same two
profiles. Source and installed wrapper durations are 48.88 and 47.20 seconds,
respectively, with no skips. Both runs keep all 218 Python hashes stable. Their
joined controls and checkpoint observations agree. The existing HTTP regression
passes after the new journey, which checks application reload and teardown.
One existing Starlette deprecation warning occurs in each run. No product defect
was reproduced, so this acceptance slice has no fabricated failing test or product fix.
The [installed application report](_reset/http-cli-installed-application-20261024.json)
and [final boundary](_reset/http-cli-final-boundary-20261024.json) bind the joined
evidence to the unchanged wheel, current Python files and six documents.
This slice repeats no full suite or fresh-cluster qualification.

## Synchronous KMS client admission: 2026-10-24

The existing AWS SDK adapter requires synchronous encrypt/decrypt callables.
Reject recognized coroutine or async-generator functions and callable objects
before storing the client. Keep InvalidContext redaction and existing synchronous
SDK behavior. The separate async unwrap API retains its existing thread boundary.
This admission check supplies no live provider qualification or credentials.

## Native search-expression dispatch admission: 2026-10-24

Reject custom binary compilation paths before rewriting protected predicates.
A subclass or per-instance renderer can change native SQL semantics; replacing
it with an ordinary equality predicate is not compatible. Reuse the existing
exact native/annotated-node admission check. For async SELECT, perform existing
configuration and statement admission before key preparation, then retain the
normal execution check. Preserve ordinary equality, negative predicates, IN,
NULL and Boolean expression behavior. This admits no new public operation.

## Declared retained-backup status references: 2026-10-24

**IMPLEMENTED, bounded source verification:** extend `status` with optional explicit
`--host-context MODULE:FACTORY` for public metadata only. Preserve the existing
plan, pin, private connection file, restore binding and status exit behavior.
Doctor and status without this option keep their existing output contracts.

Use frozen, repr-disabled RetainedObligationsContext(operation_id, plan_digest,
records) and RetainedBackupObligation(backup_id, source_plan, dump_sha256,
reader_sha256, drill_sha256). The context carries no engine, key resolver, provider,
credential, pin or deletion authority. The operation and digest must match the
current status artifact. Validate the existing input artifacts before host loading.
Host Python effects remain UNKNOWN.

Each bounded record supplies explicit saved MigrationPlan bytes and digest
references. Require the source identity in the current protection artifact or its
flat predecessors; reverse uses its embedded source and that source's predecessors.
Report exact policy digests from the supplied source artifact. Require unique
nonzero backup UUIDs and lowercase SHA-256 references. Reader and drill references
may be explicit None. Bound the tuple to 64 records and source bytes to 16 MiB
in aggregate, with the existing per-artifact bound.

Label the inventory HOST_SUPPLIED_METADATA, verification NOT_PERFORMED and
completeness, reader availability and provider availability UNKNOWN. Hashes remain
host-declared references, not observed file identity or current recovery results.
An empty declaration does not prove no obligations. Terminal REMOVED status must
retain supplied obligations despite the absent journal. Refuse malformed or
unrelated metadata before command-managed database access. Never fetch keys,
retire material or infer safe deletion. Public key inventory and independent
recovery qualification remain separate required work.

The [RED run](_reset/retained-status-source-red-20261024.json) reproduces the
missing optional command with one failure in 1.29 seconds. The
[source run](_reset/retained-status-source-green-20261024.json) passes 131 checks
in 76.37 seconds, including 23 new controls. One inherited fresh-cluster setup
case is skipped. All 220 Python hashes remain stable. Exact legacy JSON/text
output, key-free UNKNOWN declarations, strict bounds, malformed input, host
failure, ancestry, journal-free REMOVED status and output failure controls pass.
Installed and optional genuine-fresh reference qualification remain pending.
This evidence grants no external inventory, provider or recovery qualification.

## Pinned public key-policy status metadata: 2026-10-24

**IMPLEMENTED, bounded source verification:** optional `status --key-policy-context
MODULE:FACTORY` accepts a frozen, repr-disabled KeyPolicyStatusContext with
operation_id, plan_digest and a tuple of public KeyPolicy values. Bind the exact
operation and artifact digest before command-managed database access. Admit only
protection or activation MigrationPlan artifacts and reverse plans with their
embedded source policy. Refuse preparation P for this new option before host
loading. Existing preparation status, Doctor and no-option output stay unchanged.

Validate exact native policy, wrapper and context values and the complete
per-tenant policy set. Bound the tuple to 64 policies, each policy's existing
32-wrapper bound and 16 MiB aggregate sealed-wrapper bytes. Preserve the existing
canonical policy document, wrapper order and digest through one pure helper.
No new crypto or artifact format follows.

Report selected payload/search generations and public domain, tenant, provider,
root, context and wrapper-digest identities in a separate metadata object. Never
report sealed bytes or material. DIGEST_MATCH means local agreement with the
pinned artifact only. Authority remains HOST_SUPPLIED_METADATA, verification
NOT_PERFORMED and provider availability, material correctness, inventory
completeness and recovery capacity UNKNOWN. Host effects remain UNKNOWN.
Allow this option with retained-backup metadata, with independent matching
contexts. Neither option grants custody, authentication, retirement or loss rights.

The source profile passes 113 checks with 25 new controls after one test-only
preparation snapshot correction. Earlier parser RED and failed initial receipts
remain intact. All 223 Python hashes remain stable. Generation2 publication and
latest-value removal retain both public policy metadata and declared old-backup
references without keys. Installed and production qualification remain separate.

## Invalid native-coroutine SDK response cleanup: 2026-10-24

Close an exact native CoroutineType returned by a synchronous SDK callback before
rejecting the invalid response. Never await it or enter its body. Keep the existing
KeyUnavailable redaction and healthy synchronous retry behavior. Already-closed
coroutines remain safe to close. Do not run generic foreign awaitables or introduce
an event loop for invalid responses. Protocol and local actual-SDK controls verify
this boundary; live custody and installed qualification remain separate.

## Integrated query, provider and retained-status qualification: 2026-10-24

**VERIFIED within the named installed and local PostgreSQL profiles:** combine the
native search-dispatch fix, synchronous KMS client admission and declared retained
backup status. The current source run passes 74 checks, including the unchanged
original HTTP lifecycle. The installed affected run passes 357 with one inherited
fresh setup skip. Both keep all 221 Python hashes stable.

One offline reproducible wheel contains 39 modules; 43 installed-file checks and
44 release-source hashes pass with the unchanged 72 dependency pins. Actual
installed fresh backup recovery passes one export and 24 restore controls, with
one generation-specific setup skip. After actual removal, status retains the
original backup and policy references with no journal and no key preparation.
The fixture computes real dump/wheel hashes; the command still reports declared
references and UNKNOWN current availability and completeness. Its drill reference
is None because the current receipt is written after the test.

The source and installed original HTTP reports preserve all 26 pinned files,
five interruption/recovery checkpoints and latest-value package-free exit. This
qualifies local TestClient and loopback SMTP behavior only. The initial build
invocation's wrong revision stopped at admission before building or installing;
the corrected invocation used exact HEAD. No assertion was bypassed.

The [combined boundary](_reset/integrated-hardening-final-boundary-20261024.json)
binds the current receipts, artifact and six documents. Earlier RED and attempted
fix receipts remain intact. All 34 objective states and seven UNKNOWN production
gates remain unchanged. This checkpoint repeats no full suite and grants no live
AWS, host authority, deployment or independent security qualification.

The [installed actual-SDK profile](_reset/integrated-hardening-installed-sdk-20261024.json)
passes all 12 local Stubber cases with credential discovery and HTTP transport
forbidden. The preserved SDK target adds no dependency changes to the installed
environment. This fifth current database wrapper keeps the same 221 Python hashes
stable and supplies no live AWS custody evidence.

## Integer assignment failure evidence before admission: 2026-10-24

Native int2/int4/int8 range errors occur at the server with SQLSTATE 22003,
including zero-match UPDATE. Protected integer implementation must preserve
failure and transaction behavior without sending private integer values to
PostgreSQL. Investigate a static public coercion sentinel for the native failure.
It must retain write ordering, autoflush, rollback and savepoint behavior.
The native oracle selects the required failure behavior.

It admits no integer codecs, lock formats, mappings or query operators. Keep all six technical
admission gates unpassed until their full executable evidence exists.

## Current public-policy and provider cleanup artifact: 2026-10-24

The current source and actual installed profiles each pass 168 checks with all
223 Python hashes stable. A reproducible wheel contains 40 modules; 44 installed
files and 45 source inputs pass verification with 72 unchanged dependency pins.
The build helper initially selected a historical receipt path. Its output guard
stopped before building or installing. A new immutable path fixed that helper;
the historical receipt remained unchanged. No guard was bypassed.
Installed metadata agreement remains separate from custody, material correctness
or key retirement. All production gates remain UNKNOWN.

The current installed direct-generation profile passes one export and 19 restored
target controls. An initial run omitted the required previous-reader interpreter;
17 passed and two stopped at that configuration assertion. Both mandatory probes
passed. The configured run verifies the unchanged prior reader, direct planning,
cancellation, process/COMMIT recovery and latest-value exit. Preserve both receipts.
The [final boundary](_reset/key-policy-final-boundary-20261024.json) binds the exact
current artifact and qualification. No production gate changes.

## Storage-only PostgreSQL integer contract: 2026-10-24

**IMPLEMENTED, internal candidate:** add signed native int2, int4 and int8
storage with exact SmallInteger, Integer and BigInteger mappings. No protected
integer equality, ordering, range, arithmetic, aggregate or join is admitted.
Keep strict built-in int values and SQL NULL. Refuse bool, subclasses and other
Python coercions. Native width bounds remain exact.

Use pg-int2-be/v1, pg-int4-be/v1 and pg-int8-be/v1 signed big-endian codecs of
2, 4 and 8 bytes. Bind each codec through the existing typed context/v2 digest
and AAD. Existing text and Boolean descriptor/frame bytes remain unchanged.
Storage CF1 frames have exact non-NULL lengths 44, 46 and 50. Authenticate before
decoding; reject malformed authenticated widths and cross-codec relocation.
Use existing AEAD, KDF, root policy and fresh nonce rules.

Integer locks use cryptalis.lock/v7 and always include layout as None or
preserve-public-slots/v1. Source metadata always includes owned_sequences,
including an empty list. Require an integer field and the exact codec reader set;
refuse relabeled old locks. Existing v1-v6 emission and reader behavior stay exact.
Both default replacement and public-slot layouts must retain native width,
constraints, defaults policy and metadata through restore and removal. Initially
refuse protected defaults and generated values; completing those remains required.

Preserve the measured native failure and transaction/savepoint behavior without
sending private numeric values to PostgreSQL. A prepared custom plan raises
22003 even for zero-match UPDATE; a generic plan returns zero rows and retains
an active transaction. A universal early overflow refusal would break that case.
Use bound public coercion constants in the existing ordered write paths.
The owned carrier also preserves stale ORM updates and INSERT batch error order.
Fail explicitly if native failure behavior cannot be established. SQLAlchemy
entity, dictionary INSERT and scoped dictionary UPDATE need separate native
controls. All six technical admission gates remain unpassed until their full
proofs, leakage statement and measured costs exist. No production gate changes.

The [source checkpoint](status.md#integer-storage-source-checkpoint-2026-10-24)
records executable progress. This decision selects construction scope; full type
admission and production qualification remain incomplete.

The [installed checkpoint](status.md#integer-installed-lifecycle-checkpoint-2026-10-24)
extends this evidence across all three widths and both layouts on genuine fresh
PostgreSQL clusters. Full admission and workload-cost approval remain pending.

## Literal integer application default construction: 2026-10-24

**IMPLEMENTED, bounded source checks:** permit an exact in-range Python int scalar
client default for native int2/int4/int8 storage. Preserve native pending, NULL,
render_nulls, refresh and rollback behavior. Server, callable, SQL, on-update and
generated defaults remain outside this slice and remain required admission work.

Add application_default to an integer field only when a literal default exists.
Encode it as a canonical signed decimal string, including zero. This preserves
the restricted manifest number grammar and exact signed 64-bit extrema. Reject
leading zeroes, plus signs, negative zero, whitespace and other numeric syntax.
The literal default is public application configuration. The lock records its
decimal value; record values remain encrypted.
Require pg-integer-default/v1 in that lock's reader set. Existing v7 locks without
defaults retain their exact grammar and bytes. Older readers must still accept
those locks and refuse a default-bearing lock before SQL. No descriptor, CF1,
key-policy, nonce or ciphertext format changes follow. Full type admission and
all production gates remain unchanged.

The [source checkpoint](status.md#integer-defaults-and-orm-state-source-checkpoint-2026-10-24)
records native and retained-reader checks. Valid integer ORM writes retain native
loaded attributes. Only a known range failure selects the public coercion
expression. This preserves async pending-state access without implicit I/O.

The [installed checkpoint](status.md#integer-literal-default-installed-checkpoint-2026-10-24)
qualifies this bounded default/state behavior across both layouts and all three
widths with genuine fresh PostgreSQL restores. It does not pass full admission.


## Integer cost observation scope: 2026-10-24

**VERIFIED, bounded observation:** record storage-only integer costs separately
from the protected equality-column/index target. Publish column bytes and whole
relation context separately. Retain raw paired samples, seed identity and cell.
Public-ID batches do not establish encrypted-value IN performance. Process peaks
do not establish incremental app memory. Ordinary VACUUM does not prove erasure.
The [observation](status.md#integer-storage-cost-observation-2026-10-24) records
actual values. These checks approve no workload budget and pass no admission gate.

## Application journey qualification: 2026-10-24

Use complete existing-application journeys to select implementation work.
Extend the current mandatory PostgreSQL and fresh-cluster harnesses instead of
creating a parallel framework. Keep source revisions, application changes,
installed artifact identity and exact journey boundaries in the evidence.

The [HTTP checkpoint](status.md#original-http-application-fresh-recovery-2026-10-24) joins the original authentication and mail
routes to protected restore, all three rotations and latest-value native exit.
The public-slot CRUD row remains a regression control. These local checks do not
qualify production custody, deployment fencing, browser operation or independent
review. Preserve all 34 objectives and seven UNKNOWN production gates.

## Supplied query structure diagnostics: 2026-10-24

Extend pre-adoption Doctor with an optional bounded SELECT corpus.
Reuse the runtime admission rules and compiler descriptors. Do not activate an
attachment, resolve keys, execute samples or modify mapping types during inspection.
Accept only a tuple with at most 128 samples. Report fixed indexes and safe
remedies. Do not print SQL, bind values or private exception details.

A scoped query_samples PASS means supplied structures passed admission only.
Keep overall route coverage UNKNOWN after success. Known unsupported structures
set query_routes FAIL. Inspection uncertainty must remain UNKNOWN with an explicit
issue. DML samples require separate runtime qualification and do not pass this
SELECT-only check. Existing schema-only contexts and reports retain their defaults.

The original HTTP profile captures native ORM SELECT structures through the
existing session event, then removes that observer before inspection or attachment.
This is workload evidence, not a complete static scanner or route inventory.
The [checkpoint](status.md#supplied-application-query-preflight-2026-10-24) records
its bounded implementation and application journey.

The [installed checkpoint](status.md#installed-application-query-diagnostics-2026-10-24) verifies the bounded query diagnostic and matching CLI
child package. It does not qualify a complete scanner or deployment authority.
