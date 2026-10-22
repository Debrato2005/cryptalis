# Simplification decisions

**SPECIFIED:** this ledger records the approved scope and selected architecture.
It does not preserve old IDs as implementation obligations. Historical dispositions remain in [archived revamp evidence](research/revamp-evidence.md).
[Status](status.md) owns IMPLEMENTED/VERIFIED claims. All seven full gates remain UNKNOWN.

## Approved scope decisions: 2026-10-08

These decisions are final. Scope-only D blockers are resolved. No decision supplies executable qualification.

| Decision | Approved contract | Resolution/evidence limit |
|---|---|---|
| 1. Stack | Python 3.12+, SQLAlchemy 2.x, psycopg 3 sync/async, PostgreSQL 16 | Scope D resolved. Exact cell tests remain required |
| 2. First protected type | Text first. The 2026-10-22 VARCHAR admission extends the text family. Other types remain UNSUPPORTED BY DESIGN until admission | Type-scope D resolved. Text/ID descriptors and collation evidence remain required |
| 3. Capabilities | SUPPORTED: storage-only, equality, IN, tenant-scoped uniqueness | Capability/grammar scope D resolved. Every other operation rejects until admission |
| 4. Tenancy | Each protected table declares a tenant column or declares itself single-tenant | Tenant-scope D resolved. Missing tenancy blocks plan |
| 5. Primary keys | Require application-generated UUID, Snowflake-style, or other app-assigned ID. Reject serial/identity/database-default keys at plan time with a plain explanation | Identity-scope D resolved. Historical sequence-preallocating spikes do not implement this contract |
| 6. Targets | Added p95 ≤ 3 ms point/equality, ≤ 8 ms IN-20. Protected column with equality index ≤ 2× storage | Read/storage-budget D resolved as targets, not achievements. Write-throughput and pause budgets remain D |
| 7. Authorities/review | No designated production key provider and no independent review. Local provider is functional evidence only | G-PROVIDER, G-POLICY, and review requirements remain UNKNOWN. No production publication/restore procedure is selected |
| 8. Build order | Compiler → crypto/KeyProvider/dev provider → sync/async SQLAlchemy → equality/IN/uniqueness → plan/apply/verify → decrypt-back/remove → three rotation operations | One slice per run. Each requires real PostgreSQL tests before the next. Advanced work requires all seven slices, then six-gate admission and leakage opt-in |
| 9. Lock v2 metadata | Add `cryptalis.lock/v2` `source_metadata`; dual v1/v2 reader; new plans emit v2; in-place restore first, fresh cluster separate | Approved 2026-10-21. Column attributes, grants, comments, and extended statistics are captured and restored. Owned sequences stay refused |

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
An adopted restored target remains outside this cancellation contract.
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
from reviving it. Restored-target preparation remains outside this contract.

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

Activation uses `cryptalis.transition/v3` with `kind: payload_rotation`.
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
