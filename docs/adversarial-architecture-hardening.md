# Adversarial Architecture Hardening Dossier

Status: Point-in-time research and falsification input; no implementation evidence

Historical review: 2026-08-23; supersession notice added 2026-09-30

This document preserves the historical hostile review from August 2026. It does **not** own the
architecture or implementation status. The [architecture blueprint](architecture/README.md) owns
accepted technical decisions, and the [backend checklist](backend-build-checklist.md) owns work
state. Every result below is researched or proposed unless an executable artifact is linked.

## Supersession and historical interpretation

2026-10-05: The authoritative architecture handoff was reconciled into the [canonical owners](architecture/README.md#documentation-ownership).
See their [unresolved gates](architecture/README.md#unresolved-research-questions). This dossier remains historical and its F-number findings supply no normative authority.

All technical tables, version proposals, provider/vendor claims, migration orders and prototype
thresholds below are historical inputs, not current specifications. The September consolidation
supersedes them through the [ownership hub](architecture/README.md). Current exact ORM versions,
async alternatives, query/schema/migration semantics belong to [ORM contracts](architecture/orm-schema-migration.md);
crypto/search/provider/lease/restore semantics to [crypto contracts](architecture/crypto-search-lifecycle.md);
context/manifest/API to [shared contracts](architecture/manifest-context-api.md); graph/results/
collector safety/benchmarks to [assurance contracts](architecture/assurance-evidence.md).

In particular: SQLAlchemy 2.1 beta-only and old Alembic version caps are historical; migration
coexistence precedes backfill in the live protocol; tombstones enforce managed restore denial but do
not destroy recoverable offline wrapped backup keys; suite candidates here are not approved;
`COMPLETE_BOUNDED` is not a universal erasure status. P0-P10 risk meanings remain identifiers, with
current quantified gate definitions at canonical owners. Dated sources below are not represented
as September reverified facts. The [claims audit](documentation-claims-audit.md) records reconciliation.

## 1. Executive finding

The central thesis survives, but only after narrowing several claims.

Cryptalis can plausibly protect a named SQLAlchemy ORM compatibility profile, reject additional
registered paths, detect some bypasses operationally, and document paths it cannot observe. It
cannot honestly promise transparent coverage of “SQLAlchemy” or “all writes.” SQLAlchemy has several
execution planes, while raw drivers, uninstrumented engines, `COPY`, external ETL, and database-side
writers can bypass an in-process library entirely.

The Protection Manifest remains a useful canonical declaration. The Protection Graph remains a
plausibly differentiating *derived evidence view* if it correlates field semantics with physical
schema, migration, lifecycle, attack, collector, and exposure observations. It becomes redundant or
harmful if it merely copies the manifest or scanner output.

Five load-bearing corrections follow:

1. Tenant and subject provenance is an authorization boundary separate from cryptography.
2. “Transparent” applies only to an enumerated ORM profile; all other paths have an explicit
   transparent/reject/detect/unobservable classification.
3. SQLAlchemy's greenlet bridge makes remote async I/O from synchronous-looking ORM code possible;
   therefore explicit warm-up is a preference to test, not a technical inevitability.
4. Database checks for obvious plaintext depend on a frozen recognizable envelope and index
   representation. They cannot precede that format decision.
5. Migration, rotation, revocation, and shredding are distributed state machines whose completion
   must be provider- and worker-specific, never a single `destroyed = true` abstraction.

Any failed prototype constrains the affected claim. It does not erase the educational value of an
isolated experiment.

## 2. Falsifiers before implementation

The architecture must be redesigned or reclassified if any of these cannot be bounded:

| Thesis | Disproving observation | Required response |
|---|---|---|
| Ordinary ORM fields can be transparent | Correctness requires replacing the public plaintext with ciphertext, or state diverges after rollback/refresh/merge | Redesign the mapping or make values controlled/opaque |
| Supported writes fail closed | A supported profile can persist plaintext or stale search terms without rejection | Remove that path from the supported profile until fixed |
| Tenant isolation is cryptographically enforced | Request-controlled tenant/subject values can select keys or AAD without an authenticated grant | Stop; redesign context authority before any data-plane work |
| Async behavior is operationally acceptable | A cold path blocks the loop, hides unbounded I/O, or produces cancellation-unsafe partial state | Require explicit warm-up, controlled access, or a gateway for that profile |
| Equality search is acceptable | Low-entropy or frequency attacks recover unacceptable information under the declared attacker model | Disable that capability for the domain or require a different product boundary |
| Migration is resumable | Crash, retry, version skew, or two workers can corrupt or irreversibly contract unverified rows | Stop automatic planning beyond inspect/expand |
| Shredding is bounded and truthful | A fresh authorized process can recover a covered key after reported completion | Completion semantics are false; redesign provider/tombstone/fencing logic |
| Protection Graph adds value | A pinned ZAP plus database-inspection workflow gives equivalent conclusions at lower cost | Integrate existing tools and remove the graph product claim |
| Exposure oracle supports negative evidence | Positive controls, collector health, or interval boundaries cannot be established | Result is `inconclusive`, never pass |

### 2.1 Ranked fatal-risk prototype queue

Every prototype is disposable and manually implemented later. Priority reflects information value,
not the order of all research.

#### P0 — authenticated context provenance

- **Question:** Can tenant/subject authority remain explicit across requests, sessions, pools, tasks,
  workers, administration, migration, and restore?
- **Hypothesis / competitor:** an immutable grant plus one-tenant session prevents substitution;
  ambient/request identifiers are sufficient.
- **Fixture / variables:** two tenants with colliding record/subject IDs; header/path/body/model
  substitutions; identity-map hits; task spawn; cancellation; pool reuse; expired worker/job grant.
- **Expected observation:** every protected operation names the grant provenance; substitutions fail
  before key lookup/SQL; no authority survives cleanup accidentally.
- **Failure / acceptance:** any attacker-controlled selection or cross-tenant identity-map reuse
  fails the gate; all substitution/reuse cases must fail deterministically with redacted evidence.
- **Redesign:** separate sessions/batches more aggressively, require a gateway/identity-aware key
  release, or reject transparent multi-tenant use.

#### P1 — ORM logical/physical state coherence

- **Question:** Can ordinary plaintext attributes and hidden physical values survive the complete
  state lifecycle without divergence?
- **Hypothesis / competitor:** descriptor plus public SQLAlchemy events is sufficient; a controlled
  opaque value or explicit repository is required.
- **Fixture / variables:** the section 4.1 matrix across sync/async, mapping forms, loaders,
  savepoints, rollback, retry, expire, refresh, merge, detach, mutable values, and serialization.
- **Expected observation:** logical/history/physical/SQL/database state agrees after each transition.
- **Failure / acceptance:** any silent stale ciphertext/token, plaintext SQL, or wrong post-rollback
  value fails that cell; a useful named subset must pass without private internals.
- **Redesign:** narrow the transparent profile, switch affected types to controlled access, or use an
  explicit persistence service.

#### P2 — interception and bypass boundary

- **Question:** Can supported paths be transparent and registered unsupported paths fail before SQL?
- **Hypothesis / competitor:** T/R/D/U classification yields a defensible boundary; library-local
  interception is too porous to make a persistence claim.
- **Fixture / variables:** ORM UoW/bulk/upsert, Core, `text()`, executemany, raw DBAPI/driver, `COPY`,
  ETL, trigger, migration, registered and separate engines.
- **Expected observation:** each path matches its declared class and emitted SQL/rows prove it.
- **Failure / acceptance:** plaintext through T/R is fatal; D/U paths must be visible as coverage
  gaps and excluded from the claim.
- **Redesign:** require registered writer roles/gateway, restrict the claim to a smaller ORM profile,
  or reject automatic persistence protection.

#### P3 — async/KMS access design

- **Question:** Which warm-up, greenlet-bridge, or deferred design has acceptable semantics?
- **Hypothesis / competitor:** explicit warm-up gives best bounded behavior; greenlet/deferred access
  provides superior usability without hidden operational risk.
- **Fixture / variables:** provider latency/outage/throttle, cache state/stampede, cancellation at
  every await, detached access, simultaneous first reads, loader strategy, event-loop lag.
- **Expected observation:** I/O and cancellation boundaries, calls, latency, cleanup, and returned
  value state are reproducible.
- **Failure / acceptance:** no provider-induced loop blocking, plaintext fallback, unresolved partial
  state, or unbounded surprise calls; select by predeclared latency/complexity budgets.
- **Redesign:** reclassify async transparency, require deferred reveal, or move key release to a
  service boundary.

#### P4 — AAD identity and legitimate migration

- **Question:** Can strong relocation binding coexist with legitimate field/table/record moves?
- **Hypothesis / competitor:** stable logical IDs plus explicit decrypt/re-encrypt migration work;
  name-bound AAD is either too weak or permanently strands data.
- **Fixture / variables:** rename, table split/merge, primary-key change, tenant/subject transfer,
  restore under old schema, crash/retry mid-re-encryption.
- **Expected observation:** raw relocation always fails; authorized migration resumes and only the
  declared old/new identities are readable during its bounded window.
- **Failure / acceptance:** ambiguity, downgrade, or unreadable committed rows fails the gate.
- **Redesign:** bind different stable identities, add a signed migration context, or reject the move.

#### P5 — equality uniqueness and rotation

- **Question:** Can one authoritative uniqueness domain survive concurrency, nulls, and dual terms?
- **Hypothesis / competitor:** a composite database unique constraint plus a versioned transition is
  sufficient; rotating equality domains makes continuous uniqueness unsafe.
- **Fixture / variables:** concurrent equivalent normalized inserts/updates, `NULL`, conflicts,
  retries, old/new writers, partial backfill, dual-query and dual-term phases.
- **Expected observation:** exactly one logical value commits and every conflict maps to the same
  declared semantics throughout rotation.
- **Failure / acceptance:** duplicates, false conflicts, or an unenforced window fail uniqueness.
- **Redesign:** pause writes during rotation, use one stable uniqueness key distinct from search
  rotation, or reject automatic scoped uniqueness.

#### P6 — migration crash/concurrency recovery

- **Question:** Does the section 9 protocol recover across every state and irreversible boundary?
- **Hypothesis / competitor:** durable checkpoints, leases/CAS, fencing, and explicit DDL boundaries
  suffice; migration automation adds more risk than it removes.
- **Fixture / variables:** failure matrix in section 9.2 on a large table with concurrent writers,
  mixed apps, replica, rotation, invalid index, backup restore, and retries.
- **Expected observation:** resume reaches one valid state without stale overwrite, skipped rows,
  hidden invalid artifacts, or premature contraction.
- **Failure / acceptance:** any irrecoverable pre-approved transition or inconsistent successful
  state blocks planning beyond inspect/expand.
- **Redesign:** operator-run migrations with Cryptalis diagnostics only, or a narrower offline path.

#### P7 — lifecycle fencing and bounded shredding

- **Question:** Can fresh/stale processes and restored state satisfy a measurable completion bound?
- **Hypothesis / competitor:** epochs, leases, TTL, acknowledgements, tombstones, and provider-specific
  observations suffice; distributed caches/backups make the receipt misleading.
- **Fixture / variables:** two workers, partition/offline/crash, clock skew, provider outage and
  permission change, delayed/restored deletion, database/provider/VM restore, shared index residue.
- **Expected observation:** completion remains pending until declared deadlines/tests pass; fresh and
  stale decrypt outcomes match the receipt.
- **Failure / acceptance:** fresh-process recovery after completion is fatal; every exclusion and
  residue must be explicit and provider-specific.
- **Redesign:** weaken the claim, require stronger external tombstone authority, remove cache/offline
  policy, or reject shredding for the profile.

#### P8 — exposure oracle and Protection Graph value

- **Question:** Can the evidence system detect semantic mutants and materially beat mature tools plus
  manual inspection without leaking sensitive material?
- **Hypothesis / competitor:** field-aware correlation improves impact decisions; ZAP/SIEM/manual
  workflows are equivalent and cheaper.
- **Fixture / variables:** pinned protected/vulnerable apps, positive/negative/mutant controls,
  missing/unhealthy/stale/duplicated collectors, redaction, timing races, three comparison workflows.
- **Expected observation:** watermarked evidence yields correct field-specific classifications and a
  measurable explanation benefit with no sensitive artifact sink.
- **Failure / acceptance:** missed controls, false absence, unverifiable graph edges, sensitive bundle,
  or no material benefit fails the product claim.
- **Redesign:** retain Verify only, integrate mature tools, and remove graph/assurance differentiation.

#### P9 — Doctor usefulness without fictional soundness

- **Question:** Can a bounded analyzer find protection-specific flows at tolerable noise/cost?
- **Hypothesis / competitor:** Cryptalis IR/overlays add precise value; CodeQL/Semgrep plus review are
  sufficient.
- **Fixture / variables:** labeled positive/negative/ambiguous/mutant families across Python and
  framework features, compared with mature analyzers and human labels.
- **Expected observation:** rule-family precision/recall, unresolved rate, path explanations, and
  analysis time are reproducible.
- **Failure / acceptance:** no invented resolution; initial high-value rules meet predeclared
  precision and explanation thresholds.
- **Redesign:** ship models/rules for mature analyzers and keep only manifest/schema reconciliation.

#### P10 — cryptographic suite freeze

- **Question:** Which candidate meets misuse, platform, overhead, interoperability, and compliance
  needs without custom cryptography?
- **Hypothesis / competitor:** AES-GCM-SIV is the best non-FIPS default; AES-GCM, XChaCha20-Poly1305,
  or a high-level library has a better operational fit.
- **Fixture / variables:** section 6.2 vectors/faults/platforms/payload sizes plus exact FIPS module
  evidence if required.
- **Expected observation:** known vectors, parser/tamper behavior, availability, overhead, and nonce
  failure consequences match the specification.
- **Failure / acceptance:** no suite freezes without cross-process vectors, dependency evidence, and
  a credible independent-review path.
- **Redesign:** select another reviewed library/suite, constrain platforms, or keep production crypto
  unresolved.

## 3. Authority and context provenance

Correct encryption under an attacker-selected tenant is still a cross-tenant vulnerability.
`ContextVar`, session metadata, headers, route parameters, and model attributes are transport
mechanisms; none is authority.

### 3.1 Required context object

A protected operation needs an immutable, short-lived context established by an authentication and
authorization adapter. Its proposed evidence fields are:

- authenticated principal and authentication method;
- authorized tenant set and the exact selected tenant;
- operation class and purpose;
- subject-derivation rule and provenance;
- grant issuer, issuance/expiry, and request/job correlation ID;
- manifest digest and allowed key/index generations; and
- an explicit administrative or migration scope when normal subject rules are bypassed.

Raw request values may be inputs to authorization, but cannot become the selected tenant or subject
without a successful binding decision. The context carries the result and provenance of that
decision, not merely an identifier.

### 3.2 Invariants

1. One ordinary protected `Session` has one immutable tenant authority for its transaction.
2. An identity-map entry is never reused after changing tenant authority.
3. Subject identity comes from an authenticated persisted relation or a declared creation rule, not
   from an arbitrary request field.
4. Cross-tenant administration uses an explicit multi-tenant grant and separate sessions or bounded
   batches; it never swaps ambient context mid-session.
5. Background and scheduled jobs use service grants naming permitted tenants, purpose, and replay
   policy. A serialized tenant ID is not a grant.
6. Migrations and restores use separate principals and contexts whose broader powers are auditable
   and unavailable to web requests.
7. A spawned asyncio task receives a copied context by default. Task creation must either bind an
   explicit derived grant or start with protection authority cleared.
8. Pooled connections cannot be the authority store. Pool reset normally rolls back transactional
   state but does not guarantee removal of arbitrary connection/session state.
9. Context expiry, cancellation, rollback, and task completion invalidate operation-scoped key
   handles even if bounded cache entries remain usable by later independently authorized contexts.
10. Missing, ambiguous, stale, or conflicting provenance fails before key selection or SQL.

### 3.3 Adversarial fixtures

- substitute tenant and subject values independently in path, header, body, token claims, and ORM
  objects;
- reuse one session across two tenants and through an identity-map hit;
- spawn a fire-and-forget task before request cleanup and attempt a protected read afterward;
- reuse pooled connections after successful, failed, cancelled, and timed-out requests;
- replay a scheduled job after its grant expires or tenant membership changes;
- run support tooling with a broad grant and prove every selected tenant is explicit in evidence;
- restore a queued job plus old database snapshot after a subject tombstone exists; and
- attempt migration/backfill with a normal web principal and a migration principal with the wrong
  manifest digest.

## 4. SQLAlchemy enforcement contract

The four classes below are part of the security contract:

- **T — transparent:** transform and validate automatically within a tested compatibility profile;
- **R — reject:** reliably intercept and fail before SQL on a registered path;
- **D — detect:** observe or diagnose, but cannot reliably prevent;
- **U — unobservable:** outside the instrumented process or connection; only external controls can
  provide evidence.

`do_orm_execute` covers ORM statements sent through `Session.execute()` and loaders, but not SQL
emitted inside the unit-of-work flush and not Core-only `Connection.execute()`. Engine events see
registered connection executions, but a low-level SQL string no longer reliably carries logical
field, subject, or authorization semantics. A scalar `TypeDecorator` sees value and dialect, not
row authority.

| Path | Initial class | Hardening requirement |
|---|---:|---|
| ORM instance insert/update via `Session.flush()` | T candidate | `before_flush`, stable row identity, separate logical/physical state, exact history tests |
| Ordinary mapped load | T candidate | authenticated context, envelope/AAD verification, no unauthenticated plaintext release |
| Equality/`IN` through declared comparator | T candidate | typed token binds, complete expression validation, tenant/index domain binding |
| Eager, lazy, select-in, joined, deferred, expire/refresh loaders | T candidate per loader | execute-hook coverage, async implicit-I/O rules, detached/missing-context failure tests |
| Autoflush and `begin_nested()` | T candidate | account for unconditional pre-savepoint flush and post-rollback expiration |
| `merge()`, detach/reattach, pickle/serialization | R until proven | define authoritative logical/physical state and reject ambiguous imported ciphertext |
| Mutable values changed in place | R until instrumented | require SQLAlchemy mutable tracking or immutable/copy-on-write values |
| ORM bulk INSERT/UPDATE/DELETE via `Session.execute()` | R initially | no instance state; only admit a separately tested parameter/expression transformer |
| Legacy bulk mapping/object APIs | R | bypass unit-of-work semantics; no compatibility promise |
| ORM upsert/`RETURNING` and dialect extensions | R until proven | operation-specific compile and result-state tests |
| Core DML through the registered `Session`/Engine | R or D | engine guard can reject known protected targets; logical context may be incomplete |
| `text()` through a registered Engine | R for obvious target, otherwise D | reject protected table/column references conservatively; do not claim complete SQL parsing |
| `executemany` through a registered Engine | R until explicit adapter | validate every parameter set and partial-failure behavior |
| Raw DBAPI connection obtained from registered Engine | D | connection instrumentation may observe cursor traffic, but semantics are already erased |
| Separate engine, raw driver, `COPY`, external ETL, database trigger/writer | U | database roles/constraints/audit/operations; cannot be made transparent by the library |
| Alembic/backfill worker | Separate T candidate | explicit migration adapter, authority, manifest checkpoint, resumable protocol |
| Background worker | Same profile as web only with explicit grant | no inherited request context; one tenant authority per normal session |

Database constraints can reject missing or malformed protected representations after the envelope is
frozen. They cannot authenticate the application writer, prove correct tenant context, or detect a
validly shaped attacker-generated blob.

### 4.1 State and loader experiments

The minimum compatibility corpus crosses sync and async sessions with insert, update, delete,
autoflush, nested savepoint, rollback, retry, expire-on-commit, explicit expire/refresh, merge with
and without load, detach/reattach, lazy/eager/deferred loading, inheritance, composites, synonyms,
hybrids, dataclass mappings, mutable values, server defaults, relationship cascades, bulk DML,
upsert, and Pydantic/FastAPI serialization.

Each fixture records public logical value, hidden physical state, SQL parameters, identity-map
state, history/dirty state, and database representation before and after success, rollback, refresh,
and retry. A path joins class T only after the fixture passes on every declared SQLAlchemy/driver
version. Unsupported constructs fail at mapping or statement construction, not after partial SQL.

## 5. Async and KMS decision experiment

The current preference—local crypto on the hot path with explicit async warm-up—remains the leading
candidate, but the greenlet counterexample invalidates “remote I/O is impossible” as its rationale.

`AsyncSession.run_sync()` and SQLAlchemy's greenlet adaptation can let synchronous-looking
SQLAlchemy code await SQLAlchemy async-driver I/O without blocking the event loop. The
`pydantic-encryption` package documents a related design that defers async decryption and batches
siblings. This proves feasibility, not suitability. SQLAlchemy also warns that bundling await points
inside a synchronous-looking function hides where I/O may occur; unrelated synchronous I/O inside
that function still blocks the loop.

Compare three prototypes:

| Design | Strength | Failure/complexity to measure |
|---|---|---|
| Explicit warm/prefetch + local crypto | Visible I/O boundary; predictable attributes; provider-independent local work | Ceremony, overfetch, cold failures, cache lifecycle, cancellation during setup |
| Greenlet-bridged provider fetch/decrypt | Transparent-looking call sites; technically awaitable in adapted context | Hidden latency, context dependence, detached access, cancellation, provider client compatibility, surprise N+1 I/O |
| Deferred opaque value/batch reveal | Batches remote work and makes I/O explicit at reveal/finalize | Changes Python/Pydantic ergonomics; values are not ordinary strings; lifecycle of unresolved values |

The experiment pins provider latency distributions and tests cache hit/miss, simultaneous first
access, cancellation at each await, timeout, task cancellation cleanup, detached instances, lazy
loads, nested transaction rollback, provider outage, event-loop lag, and duplicate provider calls.
It must distinguish SQLAlchemy-adapted I/O from arbitrary synchronous provider SDK calls.

Adopt explicit warm-up only if it has materially better latency predictability, cancellation
behavior, and testability at tolerable API cost. Otherwise reclassify async transparent access or
offer another field profile. Never state that the rejected option cannot work.

## 6. Cryptographic suite decision matrix

No suite is frozen. All candidates use versioned envelopes, canonical unambiguous AAD, authenticated
metadata, domain-separated keys, and test vectors. Decryption never releases unauthenticated
plaintext.

| Candidate | Nonce/reuse consequence | Ecosystem and operations | Decision status |
|---|---|---|---|
| AES-256-GCM | 96-bit nonce preferred; reuse under one key is catastrophic | Widely available, hardware acceleration, clearest FIPS-module path | Candidate only; requires robust nonce allocation and per-key limits |
| AES-256-GCM-SIV | 96-bit nonce; reuse leaks equality but avoids GCM's catastrophic failure | RFC 8452; available in current `cryptography` when OpenSSL supports it; two-pass and not automatically a FIPS-approved deployment | Leading non-FIPS candidate, pending availability/performance/review |
| XChaCha20-Poly1305 | 192-bit random nonce makes accidental collision remote; reuse still forbidden | Mature libsodium construction, good software performance, weaker standard-library/interoperability/FIPS story | Comparative candidate |
| ChaCha20-Poly1305 | 96-bit nonce; reuse catastrophic | Broad IETF/library support and good software performance | Comparative candidate; no misuse-resistance advantage |
| High-level Tink/keyset envelope | Misuse-resistant API surface depends on selected template | Cross-language vectors and keyset management; adds a second envelope/keyset lifecycle | Integrate/prototype candidate, not a primitive |

FIPS is a deployment property of an exact validated cryptographic module and configuration, not a
checkbox attached to an algorithm name. If FIPS becomes a requirement, record platform, module
certificate, provider configuration, permitted key sizes, self-tests, and operational boundary.

### 6.1 Domain and version specification

Freeze explicit byte encodings for:

- envelope magic, suite, key generation, nonce, ciphertext, tag, and metadata lengths;
- AAD fields: protocol label, manifest version, tenant, subject, model/table, logical field, immutable
  record identity, access profile, and envelope version;
- HKDF extract salt policy and expand labels for encryption, equality, join, migration, audit, and
  receipt keys;
- normalization type tag, Unicode/case/whitespace policy, null policy, normalization version, and
  index version; and
- old-version readability, downgrade rejection, unknown-field behavior, and maximum lengths.

Concatenation without a canonical length-delimited or structured encoding is forbidden. Renaming a
bound identity is a cryptographic migration, not a metadata edit.

### 6.2 Freeze experiments

1. Cross-process and cross-language known-answer vectors for every suite/derivation/version.
2. Nonce collision analysis plus concurrency, fork, crash, retry, snapshot, and forced-RNG-failure
   injection.
3. Tamper, truncation, reordering, version confusion, relocation, oversized input, and malformed
   envelope corpora.
4. Availability on pinned Python/OpenSSL/platform builds and any FIPS module evidence.
5. Microbenchmarks for realistic 0/8/32/256/4096-byte values, including allocation and envelope
   overhead.
6. Dependency maintenance, license, vulnerability response, interoperability, and independent
   cryptographic review.

## 7. Search capability decisions

Search metadata is a separate leak-bearing representation. Encrypting the payload does not redeem a
search token whose leakage violates the threat model.

| Capability | Candidate representation | Dominant leakage/attack | Rotation, migration, shredding | Classification |
|---|---|---|---|---|
| Equality / `IN` | HMAC/PRF over canonical value and explicit domain | Equality/frequency, query/access pattern, auxiliary and low-entropy inference | Dual-version query/backfill; tenant-domain residue survives subject-key deletion | Production candidate only for accepted domains |
| Scoped uniqueness | Equality token plus tenant/domain composite unique index | Equality plus existence/conflict oracle | Race-safe DB enforcement; null and dual-token transition need a protocol | Production candidate with equality |
| Equijoin/grouping | Shared join-domain PRF token | Cross-column/table linkability and frequency | Shared key frustrates field/subject shredding; broad reindex | Research only |
| Range/order/`MIN`/`MAX` | OPE/ORE-family construction | Order, distance/volume depending construction, query/access patterns; strong leakage-abuse results | Expensive version coexistence and index rebuild | Research only; no default production path |
| Prefix/substring | Prefixes, trigrams, Bloom/filter tokens with candidate verification | Token overlap, length/pattern and query leakage; chosen-query inference | High amplification and dual-index rebuild; delete all companion rows | Experimental |
| Fuzzy/text | n-gram/phonetic/full-text token families | Vocabulary, overlap, score/access pattern, false positives | Very high update/storage/version cost | Experimental |
| Structured/JSON | Path/type/value companion-token rows | Structure, paths, cardinality, repeated values, query/access patterns | Path schema and array semantics drift; large reindex/shred surface | Experimental |

MongoDB Queryable Encryption demonstrates that even a mature, reviewed design has explicit operator,
rename, migration, uniqueness, array, and update restrictions. CipherStash documents its own
equality, range/order, and text leakage. CipherSweet demonstrates separated blind-index keys and
explicit threat-model responsibility. Cryptalis should match this fail-loud discipline, not feature
count.

For each capability, acceptance requires a published construction/reference implementation,
declared leakage function, auxiliary-information attacker, query/access observation model, update
and snapshot attacker, storage/write amplification, normalization and false-positive semantics,
rotation/migration/shredding protocol, compatibility table, benchmark budget, and external review
requirement. A generic “searchable encryption” approval is invalid.

## 8. Physical schema dependencies

The manifest-to-PostgreSQL compiler must decide at least:

- ciphertext type/domain and whether metadata is embedded or separated;
- equality term type/length, version representation, and composite tenant/domain indexes;
- logical null versus SQL `NULL`, including `NULLS DISTINCT`/`NULLS NOT DISTINCT` uniqueness;
- deterministic collision-checked names and stable logical field IDs across renames;
- same-table scalar companions versus child tables for variable-cardinality tokens;
- immutable record identity and effects of composite keys/inheritance;
- prohibition or explicit design for server defaults, generated columns, triggers, cascades, and
  foreign keys touching protected payloads; and
- schema/version checks that remain safe during mixed-version migration windows.

PostgreSQL `CHECK` succeeds when its expression is true **or null**, so presence still needs
`NOT NULL` where required. PostgreSQL also assumes check expressions are immutable with respect to stored
rows; changing a helper function does not retroactively validate old data. Generated expressions
must be immutable and cannot perform application-authorized key operations.

Therefore the order is:

```text
canonical envelope/index bytes
  -> malformed/unknown-version parser behavior
  -> physical type and null model
  -> database domain/CHECK predicate
  -> migration coexistence predicate
  -> failure-injection and downgrade tests
```

A database check designed before the first two steps is speculation and cannot be an early fatal-risk
prototype.

## 9. Migration protocol under attack

The proposed durable state machine is:

```text
INSPECTED -> EXPANDED -> BACKFILLING -> VERIFIED -> COEXISTING
          -> CUTOVER -> OBSERVING -> CONTRACT_ELIGIBLE -> CONTRACTED
                  \-> PAUSED / FAILED / REPAIR_REQUIRED
```

Every checkpoint binds migration ID, manifest digest, source/target formats, normalization/index/key
versions, application compatibility set, schema fingerprint, cursor/range, counts, errors, writer
lease/fence, and evidence artifact IDs. Checkpoints contain no plaintext.

### 9.1 Required mechanics

- Expansion is additive and compatible with every application version admitted to the window.
- Backfill claims chunks with durable leases and uses row version/CAS semantics so a concurrent
  writer cannot be overwritten by stale plaintext.
- Dual write is an explicit protocol with one authoritative value and repair behavior; “both
  versions write both shapes” is not a design.
- Verification separates full coverage/count/index invariants from sampled decrypt round trips.
- Cutover is fenced and requires all active writers/readers to advertise a compatible protocol.
- Observation uses a zero-legacy-read criterion over a declared interval and healthy telemetry.
- Contract is a separately authorized operation. Autogeneration only proposes DDL.

### 9.2 Failure-injection matrix

| Injection | Safe expected result |
|---|---|
| Process death before/after every checkpoint write | Resume or repeat without skipping/duplicating irreversible work |
| Two backfill workers claim the same chunk | Lease/CAS prevents conflicting final state; evidence records contention |
| Concurrent application update during backfill | Newer authoritative value wins; stale backfill cannot overwrite it |
| Old and new app versions overlap | Compatibility matrix either permits exact behavior or deployment is blocked |
| Key rotation mid-backfill | Each row/version is explicit; verifier accepts only declared generation set |
| Normalization/index version changes | New migration identity; no silent reinterpretation of existing tokens |
| Unique-token collision or pre-existing duplicates | Expansion/backfill pauses before unique enforcement or data loss |
| `CREATE INDEX CONCURRENTLY` fails | Invalid index is detected, repaired/dropped deliberately, never treated as usable |
| Transaction rollback around non-transactional DDL | Planner records real boundaries and compensating recovery |
| Replica lag exceeds window | Cutover/contract pauses; read replicas do not serve incompatible shapes |
| Backup restored to an old phase | External migration/tombstone authority prevents replay as current state |
| Rollback after plaintext contraction | Report irreversible loss of the old path; require separately approved recovery source |

PostgreSQL concurrent index construction performs multiple scans, cannot run inside a transaction,
and may leave an invalid index after failure. Unique enforcement can begin before the index becomes
valid. A planner must model these facts and lock/replica/WAL budgets; Alembic autogeneration is not
migration safety.

### 9.3 Irreversible points

Treat these as separate signed approvals: deleting or overwriting the last plaintext copy; dropping
old columns/constraints; removing old reader/writer compatibility; retiring an old normalization or
index version; destroying a key version; expiring the last approved recovery snapshot. No automatic
rollback claim crosses one of these points.

## 10. Lifecycle state, not a fictional provider abstraction

The provider interface may normalize commands, never completion semantics. Track at least:

1. Cryptalis requested/authorized state;
2. wrapped-key record state;
3. provider resource/version state and last observation;
4. live worker leases, epochs, acknowledgements, and cache deadlines;
5. decryptability from a fresh process;
6. decryptability from a stale/partitioned process;
7. database/key-provider/VM backup and restore conditions;
8. subject-owned and shared search-index residue; and
9. known unmanaged copies and exclusions.

AWS KMS deletion has a configurable waiting period and can be cancelled while pending; imported key
material can be reimported if an external copy remains. Google Cloud KMS schedules destruction after
a restoration window and rotation does not destroy old versions. Vault Transit rotation retains old
versions, minimum-decryption policy is not physical destruction, and deletion/exportability depend
on mount/key configuration and storage backups. These are distinct state machines.

Proposed Cryptalis lifecycle transitions:

```text
ACTIVE -> ROTATING -> ACTIVE(new write generation)
ACTIVE -> REVOKE_REQUESTED -> FENCING -> REVOKED
REVOKED -> SHRED_REQUESTED -> CACHE_DRAINING -> KEY_RECORD_REMOVED
        -> PROVIDER_PENDING/OBSERVED -> RESTORE_TESTED -> COMPLETE_BOUNDED
        -> FAILED/PENDING_EXTERNAL
```

`COMPLETE_BOUNDED` requires the receipt's exact worker set/deadlines, provider observations,
fresh-process negative decrypt test, stale-process result, restore exercise, index treatment, and
exclusions. It never means “the data no longer exists.”

## 11. Doctor and typed-taint limits

Doctor should build the Cryptalis-specific semantic overlay, not a new Python parser or a fictional
sound analyzer. A defensible progression is:

```text
CPython AST + spans
 -> stable Cryptalis syntax IR
 -> imports/scopes/qualified names with unknowns
 -> bounded CFG and local data flow
 -> function summaries and selected framework models
 -> call graph / interprocedural expansion where evidence justifies it
 -> SQLAlchemy query IR + Protection Manifest overlay
 -> findings with paths, confidence, and unresolved alternatives
```

Integrate or differentially benchmark Pyright's type information, CodeQL global/local data-flow
queries, Semgrep rules/taint, Ruff, and Bandit. Do not rebuild their generic coverage. Python
reflection, descriptors, decorators, monkey patching, dynamic imports, generated code, framework
dependency injection, and SQLAlchemy declarative magic make whole-program soundness unavailable.
`unknown` and `ambiguous` are result classes, not errors to suppress.

### 11.1 Taint labels and transformations

Use independent labels rather than one safe/unsafe bit:

- protected plaintext, untrusted input, secret, key material;
- ciphertext, equality/search metadata;
- tenant identifier, subject identifier, authorization grant;
- SQL fragment/code, sensitive metadata, and redacted/derived evidence.

Transformations are sink-specific. Encryption changes protected plaintext to ciphertext only after
successful authentication; normalization remains plaintext; a blind index becomes searchable
metadata; SQL parameterization removes the SQL-code-injection interpretation but does not make the
value non-sensitive; redaction for a log does not authorize a database write.

Fixture families need positive, negative, ambiguous, and semantic-mutant cases across functions,
modules, async tasks, decorators, FastAPI dependencies, declarative mappings, query builders, raw
SQL, logging, serialization, migrations, and provider clients. Report precision/recall by rule
family against CodeQL/Semgrep and human labels, plus analysis time and unresolved rate.

## 12. Protection Graph and assurance falsification

The manifest declares intended protection. The graph records derived claims and observations; it
must never become a competing policy source.

### 12.1 Identity and evidence rules

- Logical assets use stable manifest IDs, not mutable field names alone.
- Physical assets combine deployment/database identity with schema/catalog identity and epoch.
- Code assets bind repository digest, path, symbol, and span.
- Runtime assets bind deployment and run/scenario IDs.
- Provider key IDs are provider-qualified and redacted/pseudonymized in exported evidence.
- Every edge records source artifact, collector, observation interval, manifest/schema/deployment
  versions, confidence/exactness, and active/superseded/conflicted state.
- Unknown nodes, unresolved aliases, ambiguous edges, and contradictory observations remain visible.
- Negative observation is attached to marker, collector set, interval, target, and health; it is not
  a timeless `not_exposed` edge.

`contradicts` preserves both observations and their provenance. Reconciliation can produce a
decision, but cannot delete inconvenient evidence.

### 12.2 Differentiation experiment

On the same pinned vulnerable and protected applications, compare:

1. ZAP plus manual database/log inspection;
2. ZAP plus generic SIEM/scanner correlation; and
3. Cryptalis scenario packs plus Protection Graph.

Score correct field-specific impact classifications, time to explain, setup/maintenance cost,
false/ambiguous relations, evidence reproducibility, and ability to distinguish exploit, database
access, extraction, and plaintext exposure. The graph claim fails if it adds no material accuracy or
explanation benefit.

## 13. Pentest, exposure, and network boundaries

Build only the parts that teach application state or add protection-aware evidence: a bounded
OpenAPI/route graph, authentication/role state, deterministic mutations, IDOR/tenant substitutions,
response/timing differentials, replay/minimization, and evidence adapters. Integrate ZAP for
crawling, authentication, passive/active scanning, OpenAPI import, and mature rule coverage; use
Nuclei for explicit template comparisons and sqlmap only in disposable authorized scenarios.

### 13.1 Exposure result dimensions

Never collapse these states:

```text
scenario executed
 -> vulnerability/exploit condition reached
 -> database authority obtained
 -> protected column extracted
 -> candidate decoded/decrypted
 -> exact synthetic plaintext observed
```

Each may be `yes`, `no`, `not_applicable`, `not_executed`, or `inconclusive`, with reason and
evidence. “No plaintext observed” must name marker, target, scenario, collector set, collection
interval/watermarks, collector health, redaction behavior, and limitations.

Before a negative run, drain stale artifacts, establish collector start watermarks, and prove a
seeded positive control is observable. Afterward establish end watermarks, deduplicate by marker and
artifact identity, separate hits outside the interval, and run a narrow semantic mutant that should
expose the marker. Missing/unhealthy/timed-out collectors or a failed positive/mutant control yield
`inconclusive`.

### 13.2 Network evidence

Passive PCAP under ordinary TLS can establish endpoints, handshakes, certificate and protocol
metadata, sizes, timing, retransmissions, DNS/flow relationships, and some traffic-analysis leakage.
It cannot establish HTTP/database plaintext absence. Wireshark/TShark can decrypt controlled lab
traffic when session secrets are supplied; those secrets are sensitive evidence and must be scoped
and quarantined. Zeek is valuable for normalized flow/protocol events, not magical TLS bypass. Nmap
supports exposure and service discovery, not field-protection conclusions.

## 14. Reproducible benchmark protocol

Keep crypto microbenchmarks, ORM end-to-end workloads, migration tests, and provider/cache tests
separate. Pin source revision, manifest, schema, Python/SQLAlchemy/Alembic/driver/PostgreSQL/OpenSSL,
dependencies, OS/kernel, CPU/memory/storage, database settings, process/thread/client counts, payload
distribution, tenant/subject cardinality, dataset seed, and cache state.

### 14.1 Comparable scenarios

| Family | Variants |
|---|---|
| Baseline | SQLAlchemy plaintext, same schema shape where possible, sync and async |
| Cryptalis candidate | randomized payload only; equality; uniqueness; rotation dual terms; warm/cold cache |
| `pydantic-encryption` | only matching field/provider/access semantics; document architectural differences |
| CipherStash | only reproducible equivalent PostgreSQL/query/security profile; otherwise qualitative |
| Migration | expand, backfill, verify, cutover, concurrent writes, crash/restart, index build, contract |
| Failure | provider latency/outage/throttle, cache stampede, worker cancellation, replica lag |

Measure throughput, offered versus completed load, p50/p95/p99 and distributions, failures/retries,
CPU, allocations/RSS, event-loop lag, provider calls/latency/cost, cache hit/miss/stampede, ciphertext
bytes, row/TOAST/table/index/database size, WAL bytes, lock wait, replica lag, migration rows/second,
and recovery time. Correctness assertions and exposure controls run with performance measurements;
fast corrupted output is not a result.

Use multiple isolated processes/runs, warm-up, randomized variant order, raw machine-readable output,
uncertainty, and an instability check. `pyperf` is suitable for local Python microbenchmarks;
PostgreSQL's `pgbench`, statistics views, relation-size functions, and WAL/replication metrics support
database load and storage evidence. Do not publish a single laptop number as a product claim.

Predeclare budgets per scenario rather than choosing them after measurement. Include absolute and
relative results; short protected fields may have high percentage overhead even when absolute cost
is small.

## 15. Build-versus-integrate decisions

| Subsystem | Build | Integrate / benchmark | Verdict |
|---|---|---|---|
| Payload crypto and KDF | Canonical envelope/AAD/domain/version specification and provider-independent vectors | Established AEAD/HKDF/signature libraries and expert review | Build specification and adapters; never implement primitives |
| Equality/uniqueness | Manifest domains, normalization, SQLAlchemy comparators, schema/migration/lifecycle behavior | Established PRF/HMAC library; CipherSweet/CipherStash/MongoDB as references | Build + benchmark, production candidate only per accepted domain |
| Range/text/fuzzy/JSON search | Isolated educational constructions only when a paper, oracle, and budget exist | Reviewed products/libraries first | Research/integrate; no default production implementation |
| KMS/Vault | Narrow adapters, provider-state mapping, cache/lifecycle orchestration | Official provider SDKs, IAM/audit/control planes | Build + integrate; never rebuild custody systems |
| SQLAlchemy/Alembic | Manifest compiler, mapping/query guard, custom operations and explainability | Public framework APIs and their test suites | Build on public APIs; reject private-internal dependence unless isolated |
| Doctor | Cryptalis syntax/query IR, protection overlay, bounded rules, unknown/conflict reporting | CPython AST, Pyright, CodeQL, Semgrep, Ruff, Bandit | Build differentiated layer; integrate generic analysis |
| Pentest/DAST | Protection-aware state/role mutations, replay, oracle, correlation | ZAP, Burp, Nuclei, sqlmap in authorized disposable labs | Build narrow learning/correlation layer; integrate rule breadth |
| Network | PCAP metadata/flow-to-scenario correlation and evidence adapters | TShark/Wireshark, Zeek, Nmap | Integrate protocol engines; do not build packet decoders by default |
| Protection Graph | Stable asset IDs, derived/provenanced/conflicting evidence relations | Generic scanner/SIEM/manual baseline | Build only if the differentiation experiment wins |
| Evidence signing | Canonical redacted evidence schema, witness/checkpoint workflow | Established signature formats/libraries and append-only stores | Build workflow, integrate cryptography; exact format unresolved |
| Supply-chain/posture | Manifest-aware import and causal correlation | Trivy, Grype, Gitleaks and enterprise platforms | Integrate; do not build another generic scanner |
| SQL firewall/policy | Protection-specific experiments and findings | Acra, PostgreSQL roles/audit, mature gateways | Integrate or research only; not the core data plane |

## 16. Proposed initial compatibility envelope

This is a **test proposal**, not support. The first lane is deliberately narrower than every version
upstream currently supports so failures can be attributed before the matrix expands.

| Layer | First reference lane | Expansion lane after reference fixtures pass | Reason / hazard |
|---|---|---|---|
| Python | CPython 3.13 latest patch | CPython 3.12 and 3.14 | 3.13 avoids choosing the newest interpreter and retains current ecosystem maturity; annotation/dataclass and extension-wheel behavior still varies |
| SQLAlchemy | 2.0.52 exactly | later 2.0.x one patch at a time; 2.1 only after final release | 2.0 is stable; 2.1 was still beta at review and changes loading/typing/greenlet installation |
| Alembic | 1.19.1 exactly | `>=1.18,<1.20` after fixtures | structured `Plugin` API begins at 1.18; Alembic does not follow SemVer, so minor upgrades require explicit tests |
| PostgreSQL | 18 current minor | 17, then 16 | start with one catalog/DDL behavior; widen only after schema, concurrent-index, lock, WAL, replica, and restore fixtures |
| Primary driver | Psycopg 3.3 release line, sync and async | its pure/C/binary implementations where relevant | one driver family limits variables; implementation/libpq differences still enter evidence |
| Alternate async driver | not supported initially | asyncpg comparison lane | separate protocol, codecs, prepared statements, pools, raw/COPY bypass, and error behavior multiply the matrix |
| FastAPI/Pydantic | no core dependency | current Pydantic 2/FastAPI serialization fixtures selected at test time | API serialization is an exposure/compatibility boundary, not authority over the data plane |
| Python free-threaded build | excluded | research after ordinary builds | SQLAlchemy 2.1 notes greenlet compatibility limitations; concurrency/key-cache assumptions need a separate model |

Prefer documented public surfaces: SQLAlchemy events, `Session`/`AsyncSession`, inspection and
attribute-history APIs, mapped descriptors/comparators, Core expression visitors, `TypeDecorator`,
and engine connection events; Alembic `Plugin`, `Operations`, `MigrateOperation`, implementations,
renderers, comparators, and documented environment configuration. Treat direct use of
`sqlalchemy.util.*`, `AttributeImpl`, `ClassManager`, compiler internals, Alembic internal dispatch
registries, private async proxy recovery, or private dialect state as a stop-and-review event. A
greenlet experiment may inspect an internal counterexample, but a supported design cannot silently
depend on it.

The compatibility matrix crosses interpreter, ORM, migration tool, driver implementation,
PostgreSQL, sync/async, mapping form, operation, and loader strategy. “Works on latest” is not an
entry. Each cell links exact tests and evidence; a missing cell is unsupported.

## 17. Decisions carried into the architecture

Accepted as design constraints, still unimplemented:

- authenticated tenant/subject provenance and immutable per-session tenant authority;
- the T/R/D/U interception taxonomy and named compatibility profiles;
- explicit prototype comparison of warm-up, greenlet bridging, and deferred access;
- crypto suite remains unfrozen pending the matrix experiments;
- equality/`IN`/scoped uniqueness remain candidates, not general searchable-encryption approval;
- envelope/index representation freezes before database malformed-shape checks;
- durable migration phases, writer fencing/CAS, non-transactional DDL recovery, and signed
  irreversible points;
- provider-specific lifecycle observations and `COMPLETE_BOUNDED` receipts;
- Doctor unknowns and sink-specific multi-label taint;
- derived/versioned/conflict-preserving Protection Graph evidence; and
- watermarked controls for every exposure result plus a reproducible benchmark protocol.

## 18. Primary sources

Sources were inspected for the 2026-08-23 review. Version-specific compatibility still needs
executable reproduction.

- SQLAlchemy: [ORM events](https://docs.sqlalchemy.org/en/20/orm/events.html),
  [session events](https://docs.sqlalchemy.org/en/20/orm/session_events.html),
  [asyncio](https://docs.sqlalchemy.org/en/20/orm/extensions/asyncio.html),
  [custom types](https://docs.sqlalchemy.org/en/20/core/custom_types.html), and
  [Core events](https://docs.sqlalchemy.org/en/20/core/events.html)
- Compatibility: [Python releases](https://www.python.org/getit/source/),
  [SQLAlchemy 2.0 changelog](https://docs.sqlalchemy.org/en/20/changelog/changelog_20.html),
  [Alembic plugins](https://alembic.sqlalchemy.org/en/latest/api/plugins.html),
  [Alembic version policy](https://alembic.sqlalchemy.org/en/latest/front.html),
  [Psycopg supported systems](https://www.psycopg.org/psycopg3/docs/basic/install.html), and
  [asyncpg compatibility](https://magicstack.github.io/asyncpg/current/)
- Python: [`asyncio` tasks and context](https://docs.python.org/3/library/asyncio-task.html)
- Async counterexample: [`pydantic-encryption`](https://pypi.org/project/pydantic-encryption/)
- Cryptography: [`cryptography` AEAD APIs](https://cryptography.io/en/stable/hazmat/primitives/aead/),
  [RFC 8452 AES-GCM-SIV](https://www.rfc-editor.org/rfc/rfc8452),
  [libsodium XChaCha20-Poly1305](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction),
  [Tink supported key types](https://developers.google.com/tink/supported-key-types),
  [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final),
  [NIST SP 800-56C Rev. 2](https://csrc.nist.gov/pubs/sp/800/56/c/r2/final), and
  [FIPS 140-3](https://csrc.nist.gov/pubs/fips/140-3/final)
- Search: [CipherStash cryptography](https://cipherstash.com/docs/security/cryptography),
  [MongoDB Queryable Encryption limitations](https://www.mongodb.com/docs/manual/core/queryable-encryption/reference/limitations/),
  [CipherSweet](https://github.com/paragonie/ciphersweet), and
  [leakage-abuse attacks](https://www.cs.lewisu.edu/~perryjn/ccs15.pdf)
- Schema/migration: [Alembic autogenerate](https://alembic.sqlalchemy.org/en/latest/autogenerate.html),
  [Alembic plugins](https://alembic.sqlalchemy.org/en/latest/api/plugins.html),
  [PostgreSQL constraints](https://www.postgresql.org/docs/18/ddl-constraints.html), and
  [`CREATE INDEX`](https://www.postgresql.org/docs/18/sql-createindex.html)
- Lifecycle: [AWS hierarchical keyring](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/use-hierarchical-keyring.html),
  [AWS KMS deletion](https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html),
  [Google Cloud KMS destroy/restore](https://docs.cloud.google.com/kms/docs/destroy-restore), and
  [Vault Transit](https://developer.hashicorp.com/vault/docs/secrets/transit)
- Analysis: [CodeQL Python data flow](https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-python/),
  [Pyright internals](https://github.com/microsoft/pyright/blob/main/docs/internals.md), and
  [Semgrep rule concepts](https://semgrep.dev/docs/writing-rules/glossary)
- Assurance/network: [ZAP Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/),
  [Nuclei templates](https://docs.projectdiscovery.io/templates/structure),
  [Wireshark TLS secrets](https://www.wireshark.org/docs/wsug_html/), and
  [Zeek](https://docs.zeek.org/en/current/)
- Benchmarks: [`pyperf`](https://pyperf.readthedocs.io/en/stable/run_benchmark.html),
  [`pgbench`](https://www.postgresql.org/docs/18/pgbench.html), and
  [PostgreSQL size/statistics functions](https://www.postgresql.org/docs/18/functions-admin.html)

