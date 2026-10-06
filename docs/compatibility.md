# Compatibility, query semantics and performance

Status: DESIGNED. No production runtime cell is implemented or verified.
`SUPPORTED` below selects the final design scope. It does not assert released software support.
Exact pins are design inputs, rechecked against [primary-source and local evidence](research/hardening-evidence.md) on 2026-10-07 Asia/Calcutta.
Version existence does not qualify artifact interoperability. Local spike versions differ from the selected production cell.

## Stack

| Component/path | Final design disposition | Proof required |
|---|---|---|
| Linux, ordinary GIL CPython 3.14.8 | SUPPORTED target. Current local package still permits Python >=3.12 | Pin interpreter, OS and Unicode tables. Execute complete cell |
| SQLAlchemy 2.1.3 | SUPPORTED target, public extension APIs only | Mapping/history/result/query/loader/rollback and emitted-SQL evidence |
| psycopg 3.3.6, libpq and native artifacts pinned | SUPPORTED sync and async driver target | Driver transaction, cancellation, pooling, parameter and error behavior |
| PostgreSQL 18.6 on AWS RDS, one writer resource | SUPPORTED production topology | Exact engine build/settings, RDS identity, restore and failover exercises |
| Alembic 1.20.0 | SUPPORTED reviewed proposal/rendering target | Public operations, drift comparison, second autogenerate and destructive downgrade refusal |
| cryptography 50.0.2 | SUPPORTED selected primitive library | Actual wheel/backend capability, vectors, limits and review. No silent algorithm fallback |
| AWS KMS + regional DynamoDB + independent S3 receipt journal, ECS/EKS/EC2 temporary credentials | SUPPORTED custody/authority profile | Exact SDK/service/Region/IAM artifacts and fault/recovery evidence. boto3 1.43.108, bounded thread offload for async, transitive artifact hashes and fault/cancellation evidence |
| Sync Session and AsyncSession from attached factory | SUPPORTED designed paths | One task/session/tenant, explicit I/O, no blocking sync provider call on event loop |
| SQLAlchemy built-in pooling | SUPPORTED target | Grants never persist in pooled connection state, pool reset/cancel/session isolation |
| Direct psycopg prepared statement cache | SUPPORTED target | Shape/binds remain ephemeral and tenant-specific, schema change invalidates incompatible statements |
| PgBouncer | UNSUPPORTED BY DESIGN | A proxy pool adds target/fence/prepared behavior without necessary product value |
| asyncpg | UNSUPPORTED BY DESIGN | One psycopg driver serves both modes and reduces cells |
| Logical replication/CDC of protected assets, writable replicas, prepared transactions | UNSUPPORTED BY DESIGN | Doctor refuses topology, including downstream plaintext/replay obligations |
| Multi-region authority/keys, automatic cross-region DR | UNSUPPORTED BY DESIGN | Standard profile has one current consistency/custody realm |
| Self-managed/local PostgreSQL and synthetic local keys | INTERNAL ONLY development fixtures | Cannot confer production target/restore/key-custody support |
| Other Python/SQLAlchemy/driver/PostgreSQL versions | UNSUPPORTED until an explicit reviewed cell change | No generic version-range guarantee or automatic compatibility fallback |

Binary release patches require new pinned artifact evidence. Internal reader format compatibility can span package releases without changing product architecture.
Free-threaded Python, Windows/macOS runtime cells, other ORMs, databases and languages are excluded from the selected support scope.
Upstream publication/release dates are in research. Source versions do not mean those artifacts are installed locally.

## Query semantics

Encrypted value queries require declared equality and its explicit leakage acceptance.
Normal SQLAlchemy expressions remain ordinary expressions. Logical comparators defer term generation until execution authority is known.
The runtime parses expression objects, not SQL strings. Unknown nodes that can affect protected semantics reject the entire statement before SQL.

| Expression/path | Final semantics |
|---|---|
| `select(User)`, `session.get(User, expected_id)` | Bounded entity buffer with hidden complete binding, current authority and authentication |
| `select(User.email)` and admitted simple column tuples | Fetch hidden identity/context companions, verify complete buffer, return exact logical projection/Result shape |
| `User.email == value` | Exact normalizer equivalence, tenant-field term lookup and returned predicate validation |
| `User.email.in_(values)` | At most 1,000 materialized logical members, exact types. Empty list false. Duplicates can be coalesced after limit validation |
| Named `bindparam` equality or expanding IN | Resolve exact typed values at execution, before tokenization. Missing/extra security-relevant binds and executemany reject |
| `IN (..., None)` | SQL three-valued logic. NULL is not transformed into `IS NULL`. All-NULL list selects no rows in WHERE |
| `field == None`, `.is_(None)`, `.is_not(None)` | SQL NULL/presence predicates, including explicit leakage/integrity limit |
| AND/OR of admitted predicates | Preserve parentheses and SQL three-valued truth tables. One OR branch cannot replace globally required tenant criteria |
| LIMIT/OFFSET, ordering on ordinary columns | Preserve caller SQL exactly. No overfetch/refill or implicit client scan. Ordinary DB nondeterminism without ORDER BY remains |
| Declared UNIQUE | One UNIQUE(tenant_id, full_term) per declared field/index generation over all rows, with non-null tenant. NULLS DISTINCT |
| `!=`, NOT IN, general NOT on protected predicates | UNSUPPORTED BY DESIGN. Rejection is safer than broadening unreviewed null/negative semantics |
| Encrypted sort/range/min/max, LIKE/ILIKE/regex/prefix/fuzzy/full text | UNSUPPORTED BY DESIGN |
| Protected joins, GROUP BY/DISTINCT/aggregate/count of encrypted semantics | UNSUPPORTED BY DESIGN |
| Protected casts/functions/collations, RHS column expressions, JSON paths/arrays | UNSUPPORTED BY DESIGN |
| CTE/union/correlated subquery, arbitrary custom compiler, literal/text SQL involving protected models | UNSUPPORTED BY DESIGN |

Unprotected SQL is host behavior through a separate declared engine or admitted plain expression paths.
An ordinary relation on unprotected IDs does not create encrypted join capability. Unsupported protected joins/load shapes reject visibly.
For each maximal unprotected predicate subtree, SQL adds a hidden Boolean outcome evaluated by PostgreSQL.
Combine those TRUE/FALSE/UNKNOWN outcomes with locally checked protected leaves through exact SQL three-valued truth tables.
Volatile or unclassified executable functions/operators reject in protected SELECT predicates, projection and ordering.
Deterministic does not mean total: division/casts/functions can fail on rows the original WHERE could skip.
Admit only the following closed, total plain atoms on original built-in scalar columns: IS NULL/IS NOT NULL;
same-type exact-bind =, !=, <, <=, >, >= and bounded IN; Boolean columns tested with IS TRUE/FALSE/UNKNOWN;
and literal TRUE/FALSE/NULL. Plain atoms combine with AND/OR/NOT using SQL three-valued logic.
Bindings must pass original type/range/length validation before SQL. No expression can coerce, overflow or call host code.
Ordering/projection use those original plain columns only, without executable expressions.
Arithmetic, division, casts, COLLATE, any function (including stable/deterministic), custom operator/type, subquery or join
in a protected statement rejects as `UnsupportedProtectedQuery` before SQL. Case-insensitive equality is available only
through a declared frozen normalizer; ILIKE/lower() is not an alternate spelling. Protected general NOT/!=/NOT IN still reject.
Validate every node including unused OR branches. Do not rely on PostgreSQL evaluation order or short circuiting.
The plain outcomes remain unauthenticated database assertions. Cryptalis does not reinterpret arbitrary SQL collation/functions as Python comparisons.
Tenant criteria apply outside the caller Boolean tree for every protected target.
Declared encrypted comparisons use their normalizer rather than PostgreSQL text collation. Adoption must approve any changed application equivalence.
Existing locale/collation-dependent uniqueness cannot silently become byte equality. Doctor blocks unexplained semantic changes.

Every returned non-null ciphertext is authenticated and every active term recomputed before handoff.
A wrong candidate fails the whole buffer. Full-width HMAC has no designed truncation collisions or filtering step.
Rare unexplained term collisions are explicit consistency failures. Hostile database omissions and corrupted unreturned rows remain undetected by a query.
Full verification can detect stored mismatches at its declared snapshot. It is not proof against writes after that interval.
No query success proves result completeness against a database-write attacker.

SQL NULL uses no ciphertext or equality term. All companions must be NULL together.
NULL differs from empty text/bytes and zero. Multiple NULLs are permitted by default uniqueness.
Nullable presence is not cryptographically authenticated. Replacing a complete nullable field with NULL can evade payload authentication.
Encrypted NULL and NULLS NOT DISTINCT are UNSUPPORTED BY DESIGN. Required fields use NOT NULL constraints.

Uniqueness scope is exactly one tenant/field across all rows, including soft-deleted rows. No partial/predicate index,
multi-field/composite logical uniqueness, global cross-tenant constraint, collation-dependent equivalence or soft-delete reuse
is admitted. Existing requirements for those semantics block adoption rather than weakening the constraint.
PostgreSQL arbitrates concurrent equivalent non-null writes: at most one commits. Retry uses the original mutation identity.
The host receives a redacted field conflict, no value/term/SQL/other-row identity. Conflict existence is a membership oracle;
host authorization and rate limits must constrain it. Full-width HMAC collisions are negligible, not impossible.
This logical guarantee assumes honest adapter term production and intact unique constraint/index/tenant metadata.
A database-write attacker can alter an unreturned term and then permit a logical duplicate. S3 demonstrates that counterexample.
Returned-row term verification cannot restore global uniqueness against that attacker. Full verification detects observed
corruption at its snapshot. Adoption requiring adversarial global uniqueness is ineligible.

| Failure/edge | Required outcome | Invariant |
|---|---|---|
| Empty IN / IN(NULL) / mixed NULL list | FALSE / UNKNOWN / exact SQL three-valued result | No implicit IS NULL rewrite |
| Unsupported cast/division/function/join/negative protected tree | Typed rejection before SQL, including unused branches | No hidden predicate error or wrong result |
| Candidate mismatches payload/term/predicate | Fail whole buffer | No silent filtering or LIMIT refill |
| Concurrent equal normalized values | One commit, one redacted conflict | Database-enforced tenant/field uniqueness |
| Soft-delete duplicate / partial or composite declaration | Conflict / unsupported declaration | No undeclared uniqueness scope |
| Malicious unreturned term change or row omission | No global integrity/completeness claim. Verification required | Missing observations are not PASS |

## Types and normalization

Payload codec and search normalizer are independent. Returned values preserve exact original payloads.
The [format owner](security.md#cryptographic-format) defines bare codec-2 payload bytes within a 1 MiB bound.
The existing candidate codecs are executable syntax evidence, not approved runtime crypto.

| Type/profile | Payload and equality definition |
|---|---|
| Exact `str`, `exact-v1` | Strict UTF-8, no added BOM, no lone surrogate or implicit normalization. Equal code points produce equal terms. Leading U+FEFF and whitespace remain content. Mapped PostgreSQL text rejects U+0000 |
| Exact `bytes`, `exact-v1` | Exact bytes, no bytes-like coercion or encoding guess |
| Exact `int`, `exact-v1` | Fixed-width signed 2/4/8-byte payload for the original mapped integer. Search uses minimal ASCII decimal. Bool/subclasses reject |
| Exact finite `Decimal`, `exact-v1` | Codec 2 stores an exact signed coefficient with descriptor-fixed scale. Mapped Numeric accepts only declared scale and nonnegative zero. Numeric equality strips trailing zeros without ambient rounding or float |
| `email-ascii-v1` | ASCII dot-atom local part and DNS LDH domain, domain lowercase only. Exact acceptance rules below. No provider-specific rewriting |
| `phone-e164-v1` | Require `+` followed by 2–15 ASCII digits, first digit nonzero. No country guessing, punctuation or national-number conversion. Equality is exact validated form |
| `unicode-nfc-v1` | NFC using a frozen Unicode 17.0.0 data catalogue, assigned code points only. Original payload unchanged. Exact normalized equality |

`exact-v1` resolves to immutable type-specific catalogue IDs. It does not use generic `str(value)` or repr serialization.
Mapped types are closed: String/Text -> exact str, LargeBinary -> exact bytes, SmallInteger/Integer/BigInteger -> exact int,
and Numeric with explicit precision/scale -> exact Decimal. Database and client encoding must both be UTF8.
Mapped text rejects U+0000, which ordinary PostgreSQL text cannot retain after deprotection.
Preserve SQL String length, signed integer range and Numeric limits before encryption.
Mapped Numeric requires 1 <= precision <= 1000 and 0 <= scale <= precision.
Values must be finite exact Decimal with exponent exactly -scale, no negative zero, and magnitude strictly below 10**(precision-scale).
No implicit quantization, value-changing rounding or extra quantum is accepted.
Applications explicitly quantize before assignment if desired. The original psycopg/PostgreSQL mapping must return the same declared quantum.
Generic candidate vectors retain other Decimal forms as INTERNAL ONLY syntax evidence. They are not all admitted mapped values.
Text/LargeBinary also use the encoded-byte cap. CHAR, Enum, domains, variants, custom TypeDecorator/UserDefinedType,
coercing processors and ambiguous mappings reject. An unsigned context ID must still fit its actual signed PostgreSQL identity column.
Lock codec parameters are `max_characters` for bounded String, `storage_bits`=16/32/64 and `min_value`/`max_value` as minimal decimal strings for integers,
and `precision`/`scale` integers for Numeric. Parameterless Text/bytes use `{}`. No rounding or custom executable codec is admitted.
`email-ascii-v1` local part is 1–64 ASCII bytes. Dot-separated nonempty atoms use letters, digits and the ASCII punctuation set ``!#$%&'*+-/=?^_`{|}~``.
The domain is 1–253 ASCII bytes, with 1–63-byte labels containing letters/digits/hyphen and letter/digit endpoints.
The complete address is at most 254 bytes. Controls, whitespace, consecutive/edge local dots, quoted forms, comments,
IP literals and trailing domain dot reject. Domain letter case folds ASCII only. Local letter case remains significant.
This is a product normalizer, not a claim to implement every RFC-valid email address.
Mapped Decimal scale follows the declared 0..precision rule. Search numeric canonicalization has its own frozen vectors and bounded output.
Existing SQL NUMERIC constraints remain declared. Overflow rejects, never truncates or silently rounds.
Only text fields can use the text-specific normalizers. No algorithm changes based on field names.
Changing a normalizer ID or its frozen tables requires deliberate reindex and duplicate-conflict review.
The [security owner](security.md#search-and-leakage) freezes exact output bytes and post-normalization limits.
An interpreter Unicode upgrade never changes an existing index in place.
Unicode 18.0.0 upstream documentation exists, but the chosen frozen 17.0.0 catalogue is deliberate compatibility state, not a latest-version claim.
Locale casefolding, automatic full-email lowercase, SQL locale collation, timestamps/timezones, floats/NaN, JSON/mutable collections and arrays are UNSUPPORTED BY DESIGN.
Applications may format phone/email values before assignment. Cryptalis validates the declared equivalence rather than supply a general identity-validation service.

## ORM state and write paths

| Path | Designed disposition and required behavior |
|---|---|
| Instance insert/update/delete, add, explicit flush/commit, autoflush | SUPPORTED. Prepare exact identity/material, stage coherent physical row/terms, inspect emitted SQL for absence of logical plaintext |
| Full eager scalar fields, get, explicit refresh | SUPPORTED. Buffer before publication and validate identity-map hits. Ordinary select/get preserves pending assignments. Full protected refresh discards unflushed assignments after verification. Partial protected refresh rejects |
| Rollback/failed flush | SUPPORTED. Discard staged ciphertext/terms and invalidate affected decoded caches. Fresh authorized reload required |
| Expire/expire_all | SUPPORTED invalidation, not implicit reload. Protected access raises until explicit refresh |
| Session close/delete/expunge | Clear adapter values/handles. Detached protected access rejects. No memory zeroization claim |
| Bulk ORM/Core DML, executemany, upsert/RETURNING, legacy Query/bulk helpers | REJECTED before SQL through attached factory/engine |
| Sync/async begin context | SUPPORTED protected wrapper. Context exit uses current preparation/fence/commit, including cold-key and cancellation paths |
| Raw `text`, direct physical-column DML through guarded engine | REJECTED. No public bypass flag |
| Raw DBAPI from same pool | DETECTED/UNKNOWN unless explicit role/framing test proves rejection. SQLAlchemy engine hooks are insufficient |
| Separate driver/engine, COPY, ETL, arbitrary owner migration | Requires role/constraint inventory, full verification and doctor findings. No automatic encryption claim |
| Protected relationship lazy/deferred loading, streaming/yield_per | UNSUPPORTED BY DESIGN. Use explicit bounded selects/eager scalar fetch |
| Nested transactions, merge/reattach, pickle, dataclass/inheritance/composite/hybrid encrypted mappings | UNSUPPORTED BY DESIGN |
| Direct AsyncSession.sync_session, selective flush(objects), protected load/reconstructor/refresh callbacks | UNSUPPORTED BY DESIGN |

Result budget: at most 10,000 candidate rows, 16 MiB fetched ciphertext/companions, and 32 MiB counted decoded value bytes.
Object overhead is additional process memory and must be measured. These caps are not a total RSS guarantee.
Applications may lower limits. Overflow publishes no partial buffer.
Async tasks never share sessions or mutable grants. Cancellation before/after DB/provider preparation cannot publish unverified data or silently reuse poisoned state.
Ambiguous commit requires reconciliation. An async cancellation is not evidence that a transaction rolled back.

## Unsupported by design

No wire SQL proxy, secondary repository integration, universal SQL firewall, raw driver encryption, custom crypto/KMS/HSM,
general SAST/DAST/penetration tool, Protection Graph, network analyzer, compliance platform, custom package signer or controlled-release gateway is included.
No opaque local value wrapper claims protection from malicious application code.
No per-row anti-replay service, universal secure deletion, strong per-subject cryptographic erasure or source/config secrecy is promised.
ORAM/PIR, privacy-noise machinery, truncated/partitioned beacons and advanced query operators do not belong to this architecture.
The exclusion is final design scope, not a delayed product generation.

## Performance evidence

There is no Cryptalis runtime benchmark today. Primitive demo latency is not product performance.
Measure application -> ORM -> current authority/cache/KMS -> PostgreSQL -> authenticate/decode -> application against the same unprotected backend.
Current authority checks are real remote cost even when KMS material is hot. Report them rather than call the whole path local.

| Workload | Required evidence | Current state |
|---|---|---|
| Hot single-row read/write and entity/projection | p50/p95/p99, throughput, CPU/RSS, authority calls, no KMS call per warm field | UNMEASURED |
| Cold many-subject read, cold start and batch key preparation | Provider calls per distinct root, throttling, wall/event-loop latency, memory and cancellation | UNMEASURED |
| Equality/IN/uniqueness at varied tenant size/skew/payload length | Query plans/selectivity, DB/index bytes, WAL/write amplification, contention and no wrong results | UNMEASURED |
| Rewrap/reencrypt/reindex/protect/remove | Rows/bytes per second, downtime, full verification throughput, locks/temp/disk/WAL, provider budget | UNMEASURED |
| Outage/expiry/fork/restart/rolling deploy | Tail latency, bounded calls/retries, failed operation state, no fallback or false completion | UNMEASURED |

Pre-register a workload-specific latency/throughput/storage budget before measuring. The initial numerical targets below are unmeasured acceptance budgets, not capability claims.
Reference workload: same-region deployment, 100 offered operations/second, <=50% of baseline saturation,
one tenant/session, <=5 admission items, one 256-byte protected field, 100,000 rows, 1% cold-root misses,
same semantic indexes/data/hardware, 30-minute steady trials with raw runs and confidence intervals.
The fixed offered-load trial measures latency only. Separately sweep offered load for each backend to find sustainable capacity:
the highest completed operations/second held for 30 minutes with failure rate <=0.1%, no growing queue and identical
absolute p95<=200 ms / p99<=500 ms limits. Report offered/completed rates, errors and all latency distributions.
Compare protected versus baseline sustainable capacity under those same limits; two backends both serving 100 ops/s is not a throughput proof.
Measure overhead as the difference between protected and identical unprotected whole-backend latency quantiles;
report each distribution and failure rate as well. Do not subtract unrelated clocks or imply per-request attribution.

| TARGET workload | p50 / p95 / p99 budget | Other TARGET | State |
|---|---|---|---|
| Hot one-row read | +10 / +30 / +75 ms | >=70% baseline sustainable capacity under the shared limits | UNMEASURED |
| Hot one-row mutation, including ownership/commit acknowledgement | +20 / +60 / +150 ms | >=60% baseline sustainable capacity under the shared limits | UNMEASURED |
| One cold-root operation, total added latency | +50 / +150 / +500 ms | Zero key calls per warm field | UNMEASURED |
| Maintenance transform plus full verification, 1-KiB field/one tenant root | No request-latency promise during pause | >=2,000 rows/s and >=1 MiB/s combined. Report each phase | UNMEASURED |
| Async hot/cold operations | Same path budgets | p99 added event-loop lag <=10 ms | UNMEASURED |
| Dependency outage | Fail within applicable 5-s preparation/30-s operation deadline | No plaintext/stale-authority fallback. Unknown effects remain PENDING | UNMEASURED |

Initial operating-burden TARGETS are chair assumptions for an eligible existing AWS backend, not observed usability or customer approval.
Register customer-approved limits before F05 and require explicit eligibility decisions for unresolved-worker/outage cases.

| TARGET task / denominator | Limit | State |
|---|---|---|
| Integrate one eligible model/five protected fields, excluding full product implementation/audit | <=16 engineer-hours plus <=4 operator-hours for service/IAM setup | UNMEASURED |
| Maintenance including drain/transform/full verification/switch, 100,000 rows/1-KiB field/one root | <=15 minutes domain pause | UNMEASURED |
| Routine observed worker drain | p95<=10 s / p99<=30 s | UNMEASURED |
| Recover a known-terminal, recoverable interrupted operation | <=15 minutes elapsed, <=5 documented commands and <=30 operator-minutes | UNMEASURED |
| Package-free live-host exit for one eligible model | <=8 engineer/operator-hours; named ongoing backup dependencies | UNMEASURED |

Unknown worker/backend/request terminality has no bounded completion promise. Inject that case and report the deployment
ineligible for the bounded task until proof exists, while denial stays PENDING. Customer-required bounded availability/offline
operation excludes this profile. No deadline manufactures safe completion. A customer may require tighter limits, not waived safety.
Large-buffer/cold-subject workloads get separate registered budgets. These targets do not apply universally.
Failure invalidates production eligibility at the intended load and triggers architecture/product review before full expansion.
Use identical data, semantics, hardware, offered load, indexes and driver settings. Record versions, cache state, raw repetitions and uncertainty.
Measure short and long values separately, include authority/quota cost, and count failures/retries instead of hiding them.
Storage overhead includes the 96-byte payload envelope, exact payload bytes, 32-byte terms, B-tree entries, rollback mirrors and transition shadows.
Only selected fields transform. Query and migration amplification must remain within explicit observed deployment budgets.
If a budget fails, block production support or record a reviewed design change. Never bypass protection for speed.
