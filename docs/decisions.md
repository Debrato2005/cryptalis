# Simplification decisions

**SPECIFIED:** this ledger records the approved scope and selected architecture.
It does not preserve old IDs as implementation obligations. Historical dispositions remain in [archived revamp evidence](research/revamp-evidence.md).
[Status](status.md) owns IMPLEMENTED/VERIFIED claims. All seven full gates remain UNKNOWN.

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
