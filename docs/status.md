# Implementation status

**IMPLEMENTED:** research prototype with a product manifest compiler, CF1 text primitives, a local development provider,
bounded sync/async SQLAlchemy storage/search, a PostgreSQL maintenance protection transition, an in-place
decrypt-back/removal path for that transition format, and an approved fresh-cluster protected-backup
recovery and adoption path. Root rewrap and payload/search generation rotation
share bounded maintenance and publication mechanics.
Separate runtime-role verification is complete for the local cell.
No PostgreSQL/provider/runtime cell, production key provider, independent review, or release is qualified.
VERIFIED below refers only to the named checks and their exact revisions.
All other contract and promotion requirements are SPECIFIED. All seven full gates remain UNKNOWN.

## Keyring held-mutex fork checkpoint: 2026-10-23

**VERIFIED, local Linux / Python 3.12.3:** the parent holds the mutex across an actual POSIX fork.
A bounded join limits test duration. In the child, public sync/async
preparation promptly raises `KeyUnavailable` before it locks the inherited mutex.
Fresh keys in the child complete a CF1 roundtrip. Retained and newly prepared
keys in the parent still work after lock release. Failure cleanup kills and reaps a live child.

The specialist regression passes **71 tests**, including CF1 and provider controls.
The integrated fork control passes once. Each run retains 155 stable Python hashes.
Product source and crypto formats stay unchanged. The full suite retains its earlier source boundary.
Production custody, deletion, zeroization and other platforms remain unqualified.
All seven production gates remain UNKNOWN.

Evidence: [specialist regression](_reset/keyring-held-mutex-fork-20261023.json),
[exact boundary](_reset/keyring-held-mutex-fork-boundary-20261023.json), and
[main integration](_reset/keyring-held-mutex-fork-integration-20261023.json).

## Artifact dependency metadata checkpoint: 2026-10-23

**IMPLEMENTED, bounded offline verification:** the release checker compares wheel
`Requires-Python` with the project Python constraint through `packaging.specifiers.SpecifierSet`.
It compares the `Requires-Dist` multiset with project dependencies through
`packaging.requirements.Requirement`. Standard parsing accepts equivalent spelling and ordering.
The multiset retains duplicates. Missing, malformed or changed declarations refuse.
`packaging>=26.3` is an explicit development dependency. The lock refresh changes
no runtime pins. Runtime product source and cryptographic contracts stay unchanged.

The RED records nine failed subtests and one failed test, with two passing tests.
The first GREEN records 13 passes, 54 passed subtests and one installed-check
failure because the development dependency left the lock stale. The final suite
passes **14 tests and 60 subtests** in 3.53 seconds. All four recorded file hashes
stay unchanged during that run.

Current repeat-build archives, SBOM, 37 installed-file comparisons and CLI startup
pass. Wheel metadata declares Python `>=3.12` and the four exact runtime requirements,
including the psycopg binary extra. The wheel hash remains unchanged.
These checks cover artifact metadata and exact installed bytes. Installed dependency
resolution and production qualification remain UNKNOWN. Database suites were not
repeated for this tooling slice. All seven production gates remain UNKNOWN.

Evidence: [RED](_reset/artifact-dependency-metadata-red-20261023.json),
[first GREEN failure](_reset/artifact-dependency-metadata-green-20261023.json),
[final GREEN](_reset/artifact-dependency-metadata-green2-20261023.json), and
[current release](_reset/artifact-dependency-metadata-release-20261023.json).

## Defensive projection and DELETE integration checkpoint: 2026-10-23

**VERIFIED, local combined source:** the serial PostgreSQL 16 primary regression
passes **2,250 tests and 18 subtests**, with four skips and 48 existing deprecation warnings.
The skips comprise one test and three collection skips. The run takes 758.81
seconds. All 154 Python hashes stay unchanged. Both mandatory role probes pass.
This checkpoint combines expanded SELECT descendant admission, authenticated
output regressions, finite mapped DELETE and native-node checks for ordinary
ORM flush DELETE. The receipts bind the combined worktree based on `5b3362b`.

The earlier wrong-password CLI timeout does not recur. Product and test timeouts
stay unchanged. The original timeout's cause remains UNKNOWN. The earlier
`351789e` failed checkpoint remains below, with its original evidence.
See the [full primary receipt](_reset/defensive-projection-delete-full-20261023.json).

The current release check passes repeat-build wheel/sdist hashes, archive
inspection, SBOM, all 37 installed-file comparisons and CLI startup. All 33 wheel
modules match the recorded 38-file source bundle. The wheel SHA-256 is
`75821785bbb1fdab70b56265c1d4b91df1237f979c753076ddf3a182bd4cd1b7`.
See the [release receipt](_reset/defensive-projection-delete-release-20261023.json).

Pinned Smolink revision `498d24b` passes one separate lifecycle check with real
Redis. All 38 application files stay unchanged. Native/protected URL operations,
current-value removal and a package-free child pass. Only `Url.destination` is
protected. Authentication endpoints and deployed startup remain unqualified.
See the [application observations](_reset/defensive-projection-delete-smolink-app-20261023.json)
and [mandatory wrapper](_reset/defensive-projection-delete-smolink-wrapper-20261023.json).

The current 10,000-row native-matched profile passes all six latency targets
and the isolated storage target. Each workload uses 100 paired samples after
ten warmup pairs. Native and attached values match. Other database jobs stop
during sampling. The product completes protection, verification and pinned
ACTIVE attachment.

| Workload | Scalar/tuple added p95, ms | Entity added p95, ms | Budget, ms |
|---|---:|---:|---:|
| Point | 2.2091 | 1.7067 | 3 |
| Equality | 2.3908 | 2.1547 | 3 |
| IN-20 | 2.9629 | 3.2268 | 8 |

Isolated name-column/equality-index storage measures **1.52483× native**.
This warm synchronous TEXT/public-key cell does not qualify larger datasets,
async traffic, concurrent traffic, writes or remote custody. Shared-host load
remains uncontrolled. The application and profile runs retain the same 154-file
source bundle. All seven production gates remain UNKNOWN.
See the [matched profile](_reset/defensive-projection-delete-performance-20261023.json)
and [mandatory wrapper](_reset/defensive-projection-delete-performance-wrapper-20261023.json).

## Expanded SELECT projection checkpoint: 2026-10-23

**IMPLEMENTED, bounded verification:** SELECT admission expands full entity and
table projections before applying existing type, operation and owned-lineage
rules. One shared snapshot includes each selected column and its descendants.
The type check and both general admission checks use that snapshot.

Two native PostgreSQL controls first reproduced a public output hook that
returned CF1 frame hex through an unrelated public attribute. Both attached
entity/table projections now refuse before key resolution or SELECT execution.
A benign mapped `length(protected_field)` control also exposed different admission
for direct and entity projections. Both now refuse. Direct/entity
`length(public_field)` retains the native value.

Ten projection controls cover those refusals, separately constructed table
lineage, ordinary entity/table reads, a public nested SELECT, protected Unicode
and safe Python codecs. The existing authenticated result processor and exact
owned payload exception stay unchanged. No new query grammar or cryptographic
format results from this repair.

The final affected suites each pass **284 checks** with 151 stable Python hashes.
The primary uses Python 3.12.3 / SQLAlchemy 2.1.3. The alternate uses Python 3.13.12 /
SQLAlchemy 2.0.51 with pure psycopg. Both runs reload the private URLs and pass
both mandatory role probes.

Earlier evidence stays visible: the original entity/table RED has two failures.
The first expansion regression has 279 passes and one invalid nested fixture
failure. Its corrected focused control passes once, and its alternate passes
280 checks. The later mapped-expression RED has three passes and one missing
refusal. The final 284-case runs supersede those earlier source boundaries.
The [combined checkpoint](#defensive-projection-and-delete-integration-checkpoint-2026-10-23) passes the full primary regression.
All seven production gates remain UNKNOWN.

Evidence: [entity/table RED](_reset/select-entity-type-hooks-red-20261023.json),
[initial expansion boundary](_reset/select-expanded-columns-boundary-20261023.json),
[mapped-expression RED](_reset/select-expanded-expression-red-20261023.json),
[final primary regression](_reset/select-expanded-expression-primary-20261023.json),
[final alternate regression](_reset/select-expanded-expression-alternate-20261023.json), and
[exact final boundary](_reset/select-expanded-expression-boundary-20261023.json).

## Mapped DELETE admission checkpoint: 2026-10-23

**IMPLEMENTED, bounded verification:** sync/async mapped `execute()` admits one
record DELETE with exact tenant and application-record equalities. It requires
`synchronize_session=False`, no RETURNING and no external parameters. The route
supports tenant-column TEXT/VARCHAR mappings and UUID/int64 application IDs.
Core DELETE, scalar entry points and broader predicates remain unadmitted.

Exact native AST classes and compiler dispatch must pass before key resolution.
Original tenant/record authority stays fixed across provider callbacks, compiled
binds and final driver arguments. Native controls cover row counts, zero matches,
identity-map behavior, autoflush, foreign-key failure, savepoints and rollback.
This route authenticates no stored frame because it returns no protected value.

Ordinary ORM flush DELETE also checks native nodes before its existing early
return. Four benign single/batch TEXT/VARCHAR controls replace a DELETE with an
equivalent subclass that inherits the native compiler. The corrected RED records
four missing refusals. The guard now refuses before DELETE execution and leaves
rows unchanged. Removing the hook restores native flush and rollback behavior.
The guard adds no scoped tenant-predicate requirement to ordinary ORM flush.

The scoped route passes **55 integrated checks**. Its earlier primary affected
run passes 258 existing checks. The final flush-guard bundle passes **65 checks**
in each primary and alternate cell, including scoped/native DELETE and existing
sync/async ORM state controls. All runs keep their recorded source hashes stable.

The earlier alternate affected run records 312 passes and one VARCHAR restart
failure. Its isolated child lacked psycopg. A test-only interpreter option now
permits a disposable Python 3.13 child with psycopg and no Cryptalis. The default
interpreter and `-I` remain unchanged. The single failed control then passes.
This does not replace the original 312-pass/one-failure receipt with a full pass.
The [combined checkpoint](#defensive-projection-and-delete-integration-checkpoint-2026-10-23) passes the full primary regression.
All seven production gates remain UNKNOWN.

Evidence: [native oracle](_reset/scoped-delete-native-lifecycle-20261023.json),
[scoped controls](_reset/scoped-delete-green2-lifecycle-20261023.json),
[scoped integration](_reset/scoped-delete-integration-20261023.json),
[existing primary regression](_reset/scoped-delete-primary-existing-lifecycle-20261023.json),
[earlier alternate failure](_reset/scoped-delete-alternate-lifecycle-20261023.json),
[isolated native child](_reset/scoped-delete-alternate-varchar-child-environment-lifecycle-20261023.json),
[corrected restart control](_reset/scoped-delete-alternate-varchar-restart-lifecycle-20261023.json),
[initial flush RED](_reset/flush-delete-dispatch-red-lifecycle-20261023.json),
[corrected flush RED](_reset/flush-delete-dispatch-red2-lifecycle-20261023.json),
[final primary flush bundle](_reset/flush-delete-dispatch-primary-lifecycle-20261023.json), and
[final alternate flush bundle](_reset/flush-delete-dispatch-alternate-lifecycle-20261023.json).

## Post-admission 10k profile checkpoint: 2026-10-23

**VERIFIED, local profile only:** committed `3a21096` passes the existing
10,000-row native-matched profile after shared identity and SELECT type checks.
All six latency targets and the isolated storage target pass. Each workload
uses 100 paired samples after ten warmup pairs. Native and attached results match.
The product completes protection, verification and pinned ACTIVE attachment.

| Workload | Scalar/tuple added p95, ms | Entity added p95, ms | Budget, ms |
|---|---:|---:|---:|
| Point | 1.5218 | 1.4839 | 3 |
| Equality | 2.2998 | 2.0060 | 3 |
| IN-20 | 3.7486 | 2.9876 | 8 |

Isolated name-column/equality-index storage measures **1.52483× native**.
All 150 recorded Python hashes stay unchanged. The test passes in 4.82 seconds.
Process CPU measures 3.175 seconds, elapsed time 4.608 seconds and lifetime peak
RSS 94,004 KiB. These include fixture work and imports, with no server-resource
or streaming-memory claim. The team holds other database jobs during sampling.
Shared-host load remains uncontrolled. This warm synchronous TEXT/public-key cell
does not qualify larger datasets, async traffic, writes or remote custody.
All seven production gates remain UNKNOWN. Full combined follow-up remains required.

Evidence: [matched observations](_reset/select-type-performance-20261023.json) and
[mandatory wrapper](_reset/select-type-performance-wrapper-20261023.json).

## Finite SELECT type admission checkpoint: 2026-10-23

**IMPLEMENTED, bounded verification:** attached SELECT checks every typed AST
node before generated-node exceptions, including nested statements and compiled
forms. Native controls first exposed public type hooks that returned CF1 hex
or changed a matching predicate. The original RED retains three failures and
one safe-codec pass.

Admission now refuses SQL bind/output hooks, dialect variants, dynamic type
implementations, user-defined SQL type spelling and literal-execution binds.
Current compiler dispatch must be an actual bound method with exact native
function identity and the correct bound type object. Decorator and container
inner types also pass these checks. Only the exact owned physical payload type
may use its internal output hook. That exception waives no other check.
Tested ordinary Python bind/result processors and native Boolean/Enum values
retain their native behavior.

All **12 controls** pass on the final primary integration source. The final
alternate affected run passes **274 checks** on Python 3.13.12 / SQLAlchemy 2.0.51.
Earlier primary evidence records 272 passes and the already corrected assertion
that expected configuration rejection later. Two final primary delta controls
also pass. Earlier receipts stay separate from the final-source evidence.
These checks cover SELECT admission. Public write-type hooks and hostile Python
execution have separate boundaries. Full combined follow-up remains required.
All seven production gates remain UNKNOWN.

Evidence: [initial native RED](_reset/select-type-hooks-red-20261023.json),
[earlier primary controls](_reset/select-type-hooks-green-20261023.json),
[earlier affected failure](_reset/select-type-hooks-affected-20261023.json),
[final primary delta controls](_reset/select-type-hooks-dispatch-mapping-20261023.json),
[final primary integration](_reset/select-type-hooks-integration-20261023.json),
[final alternate regression](_reset/select-type-hooks-sa20-20261023.json), and
[exact admission and evidence boundary](_reset/select-type-hooks-boundary-20261023.json).

## Combined integration checkpoint: 2026-10-23

**IMPLEMENTED, bounded checks:** the full regression is incomplete.
Checkpoint `351789e` combines KMS, restore, diagnostics, native identity admission, rotation
row recovery and scoped bulk UPDATE. Its full primary run reports 2,167 passed,
two failed, four skipped, 48 existing warnings and 18 passed subtests.
All 149 Python hashes stay unchanged during the run.

One failure expects configuration rejection only during execution. The new
pre-key check correctly refuses session creation earlier. The corrected test
accepts refusal at either boundary and retains zero-driver and healthy-restored
mapping checks.

The other failure is a wrong-password search-status CLI process
that exceeds the test's 10-second limit. Both focused controls pass afterward.
The CLI case takes 1.30 seconds. Product and test timeouts stay unchanged.
The original timeout's cause remains UNKNOWN. A full follow-up remains required.

Pinned unchanged Smolink passes its separate lifecycle check with real Redis,
current-value removal and a package-free child that denies Cryptalis imports.
All 38 application files match. This covers storage lifecycle, not authentication
endpoints or deployed startup. Reproducible archives, SBOM, all 37 installed
files and CLI startup pass. The installed wheel SHA-256 is
`fe6856a8a501c6208920a82b2c1e8342435a1f0335dfb6b8aaf867ddfd1beea9`.

These artifacts match the product source. The later assertion correction changes
only test code. A separate SELECT type-hook repair remains outside this checkpoint.
All seven production gates remain UNKNOWN.

Evidence: [full run with two failures](_reset/parallel-integration-full-20261023.json),
[focused failure controls](_reset/parallel-integration-failure-controls-20261023.json),
[unchanged application](_reset/integrated-smolink-app-lifecycle-20261023.json),
[application wrapper](_reset/integrated-smolink-wrapper-lifecycle-20261023.json),
[reproducible archives](_reset/parallel-integration-release-20261023.json), and
[installed wheel](_reset/parallel-integration-installed-20261023.json).

## Scoped mapped bulk UPDATE checkpoint: 2026-10-23

**IMPLEMENTED, bounded verification:** attached sync/async sessions admit mapped
TEXT dictionary UPDATE with one explicit tenant equality and
`synchronize_session=False`. Inputs require a nonempty list of dictionaries
with typed application IDs. Protected fields can be omitted, NULL or exact text.
Public Python bind processors retain native behavior. The route preserves
contiguous groups, repeated IDs, zero matches, autoflush, savepoints, errors,
identity-map behavior and the native empty Result.

The route refuses Core, RETURNING, embedded values, extra predicates, tenant
assignments, version counters, dynamic defaults, read-only mapper properties,
SQL-producing type hooks and type variants. VARCHAR and single-tenant bulk
UPDATE remain unadmitted. It adds no rowcount promise. Exact owned-column
lineage, ordered input proofs, scope/ID binds, sealed bytes and final driver
snapshots bind every emitted group to its prepared inputs.

Attachment also requires exact native row-context types and flags. Repeated
configuration checks refuse changed identities before host key resolution.
Native bulk and flush INSERT controls demonstrate SQL-transformed UUID values
before protection, then refuse the changed mapping under the original valid plan.
These shared checks cover initial attachment and later metadata changes.
A late public type change refuses with rollback and unchanged rows. The same
factory has no recovery promise after native DML type caches capture that change.

The primary and alternate affected runs each pass **143 cases** on the same
141-file source bundle. The primary uses Python 3.12.3 / SQLAlchemy 2.1.3.
the alternate uses Python 3.13.12 / SQLAlchemy 2.0.51 with pure psycopg.
The original 12-case native oracle and intermediate failure receipts remain
separate. Review controls exposed read-only property handling and hidden SQL
type transformations before final admission. All seven full gates remain UNKNOWN.

Evidence: [native oracle](_reset/bulk-update-native-first-20261023.json),
[initial protected RED](_reset/orm-bulk-update-red-20261023.json),
[read-only property RED](_reset/orm-bulk-update-readonly-red-20261023.json),
[SQL hook RED](_reset/orm-bulk-update-sql-hooks-red-20261023.json),
[final primary regression](_reset/orm-bulk-update-ready-primary-20261023.json), and
[final alternate regression](_reset/orm-bulk-update-ready-alternate-20261023.json).

## Rotation row lease recovery checkpoint: 2026-10-23

**IMPLEMENTED, bounded verification:** payload/search staging and paired-frame
verification share one expiry retry per row. The retry checks both exact pinned
policies before fresh preparation and verifies the retained-root relationship.
It retries only a failed pure crypto step. The singleton staging transform also
includes its internal lease checks. No generic provider or policy fault retries.
SQL, progress and digest effects follow complete successful work.

Verification releases source frames before target decoding. The existing
three-frame logical budget remains unchanged. Source-only observations, activation
target observations and outer executor/return lease checks retain terminal expiry.
Their unchanged final behavior has source review, without new expiry-injection evidence.
This checkpoint does not claim automatic recovery throughout every rotation phase.

All 20 new controls pass inside each **83-case** primary and alternate regression.
The cells use Python 3.12.3 / SQLAlchemy 2.1.3 and Python 3.13.12 / SQLAlchemy 2.0.51.
Both receipts match the same 141 Python files. Native controls force actual
post-AEAD source/target expiry, policy drift, provider outage and second expiry.
They check source/shadow/journal rollback and explicit healthy resume. The original
RED run retains 20 failures. All seven production gates remain UNKNOWN.

Evidence: [original RED controls](_reset/rotation-lease-red-lifecycle-20261023.json),
[primary regression](_reset/rotation-lease-green-lifecycle-20261023.json), and
[alternate regression](_reset/rotation-lease-alternate-lifecycle-20261023.json).

## Identity variant planning checkpoint: 2026-10-23

**IMPLEMENTED, planning boundary:** identity codec admission rejects mappings
with dialect-specific type variants. Exact native UUID or bigint types must
represent the record and tenant context declared by the lock.

Two native PostgreSQL controls first insert with a UUID SQL variant. The real
stored record or tenant UUID differs from the supplied UUID. Each transaction
rolls back before planning, and rows stay unchanged. The preceding compiler
accepts both mappings, so both RED controls fail. The corrected compiler and
existing compiler/VARCHAR regression pass **105 cases**.

This checkpoint covers read-only protection planning. Attachment and later
mapping mutation require their separate adapter controls. All seven production
gates remain UNKNOWN.

Evidence: [native RED controls](_reset/context-type-red-20261023.json) and
[planning regression](_reset/context-type-green-20261023.json).

## Actionable inspection failures checkpoint: 2026-10-23

**IMPLEMENTED, bounded verification:** Doctor and status inspection failures
include the selected plan's public operation UUID. Known runtime-role and
external-pin refusals give fixed reasons and bounded remedies. Other codes
retain their generic reason. Cleanup failures also retain the operation UUID.
The CLI omits private connection values and raw exception details.
Existing codes, exit classes and UNKNOWN observations stay unchanged.

Seven new native PostgreSQL controls pass through the lead integration.
The specialist's affected regression passes 128 cases. JSON and text output
retain safe context, and read-only snapshots show no database changes.
The original RED receipt retains seven failures. Two initial expectations used
a different connection-failure code and were corrected to the existing contract.
All seven production gates remain UNKNOWN.

Evidence: [original RED controls](_reset/inspection-diagnostics-red-lifecycle-20261023.json),
[affected regression](_reset/inspection-diagnostics-green-lifecycle-20261023.json), and
[lead integration](_reset/inspection-diagnostics-integration-20261023.json).

## Restored-frame lease recovery checkpoint: 2026-10-23

**IMPLEMENTED, bounded verification:** restored-frame scans retry one unfinished
row after actual key expiry. Fresh admission checks the exact retained policy.
Provider failure, changed policy and repeated expiry remain `KeyUnavailable`.
Authentication and generation faults retain their existing typed failures.
No binding or probe write precedes complete frame authentication.
Host approval, target identity, schema and runtime-role checks retain their order.

The lead integration passes nine scan/admission checks. Separate genuine fresh
PostgreSQL clusters pass ten public restore controls for TEXT and ten for VARCHAR.
Each profile first exports a protected backup through the normal product path.
Controls cover post-AEAD expiry recovery, deployment admission, provider and
policy refusal, repeated expiry, corrupt frames, generations and authority order.
All 139 recorded Python hashes match the integrated files. No durable rows,
journal state or catalogs change on failed adoption.

The original RED receipt retains four failures and three passes. The first
implementation run also failed because fixture bookkeeping passed prepared keys
to a keyring policy helper. The corrected run passes. Both failures remain
separate from successful evidence. All seven production gates remain UNKNOWN.

Evidence: [original RED controls](_reset/restore-lease-red-lifecycle-20261023.json),
[first implementation failure](_reset/restore-lease-green-lifecycle-20261023.json),
[corrected scan checks](_reset/restore-lease-green2-lifecycle-20261023.json),
[lead integration](_reset/restore-lease-integration-20261023.json),
[TEXT export](_reset/fresh-cluster-export-20261023-17.json),
[TEXT restore](_reset/fresh-cluster-restore-20261023-17.json),
[VARCHAR export](_reset/fresh-cluster-export-20261023-18.json), and
[VARCHAR restore](_reset/fresh-cluster-restore-20261023-18.json).

## Optional AWS KMS SDK adapter checkpoint: 2026-10-23

**IMPLEMENTED, bounded verification:** a caller-supplied synchronous KMS client
wraps and unwraps roots under an exact full key ARN and fixed public context.
Aliases, wrong response identity/algorithm, invalid material, inherited providers
and relabeled context refuse. Async cancellation publishes no late cached key.
The host supplies SDK credentials, endpoint, timeout, retry and logging settings.
CF1 and the existing provider/key-policy interfaces stay unchanged.

The specialist and lead integration each pass **86 checks**, including 36 new
SDK-shaped protocol controls and 50 existing CF1/keyring/rewrap cases.
An explicit isolated boto3 1.42.89 / botocore 1.42.97 profile passes **12 cases**.
It verifies actual SDK model acceptance, serialized binary/context requests,
modeled service errors, malformed replies and cancellation. Synthetic credentials
and working transport/discovery tripwires prevent live AWS access.
Its first run retains one serialization-observer ordering error; the corrected
run and lead integration pass. No adapter correction was needed for that error.
Reproducible wheel and source archives, the SBOM, all 37 installed files and
CLI startup pass. The installed wheel SHA-256 is
`876a5e15666387050cd32079dea9410fa6d8db6d19ab7f5b980ab8d18cd136be`.
Production custody, IAM, workload identity, live transport/logging, provider
revocation/deletion and all seven full gates remain UNKNOWN.

Evidence: [official references and context](_reset/aws-kms-research-20261023.json),
[specialist protocol checks](_reset/aws-kms-protocol-20261023.json),
[lead protocol integration](_reset/aws-kms-integration-20261023.json),
[isolated SDK versions and limits](_reset/aws-kms-sdk-environment-20261023.json),
[initial SDK observer failure](_reset/aws-kms-sdk-profile-20261023.json),
[corrected SDK profile](_reset/aws-kms-sdk-profile-green-20261023.json), and
[lead SDK integration](_reset/aws-kms-sdk-integration-20261023.json),
[reproducible archives and SBOM](_reset/aws-kms-release-20261023.json), and
[installed wheel](_reset/aws-kms-installed-20261023.json).

## Bounded row lease recovery checkpoint: 2026-10-23

**IMPLEMENTED, bounded verification:** protection and decrypt-back retry local
row crypto once after actual lease expiry. They check the exact host policy
before fresh admission. Failed row work changes no SQL, progress marker or
verification digest. Provider failure, changed policy and repeated expiry
still stop the operation. Public diagnostics remain `KeyUnavailable`.
The [security contract](security.md#implemented-cf1-primitives-and-local-custody) owns the precise retry boundary.

The initial million-row profile failed during protection. A diagnostic replay
located expiry at the final payload check after real encryption in backfill.
Both failed receipts remain separate from successful performance evidence.
A later run stopped at bounded table-lock admission with SQLSTATE `55P03`.
It produced no performance measurements. The explicit profiler now completes
named-table `VACUUM (ANALYZE)` after seeding each disposable fixture, before
product planning. Its separate 120-second statement limit is restored afterward.
Product lease durations and lock limits stay unchanged.

Four new success controls fail against the immutable preceding product source.
The fix passes all 16 new PostgreSQL controls across protection/decrypt-back
and backfill/verification. They force expiry after the real AEAD call, using
an isolated key clock. They verify fresh admission, native rows, independent
frame decoding and verification digests. Failed refresh, repeated expiry and
policy changes retain exact rows and journal state before explicit healthy resume.
The existing primary crypto/provider/lifecycle run passes 111 checks.
The alternate Python 3.13.12 / SQLAlchemy 2.0.51 cell passes all 127 checks.
One extra check passes for pinned unchanged Smolink, including real Redis and
current-value removal with Cryptalis imports denied in a fresh process.
All 38 app source hashes match, with no model/query changes.
This storage/lifecycle boundary excludes authentication endpoint qualification.
Reproducible archives, SBOM, all 36 installed files and CLI startup pass.
The prepared million-row profile completes the product transition and all six
native-matched read targets. The full primary regression passes **2,034 tests
and 18 subtests**, with three separate-environment skips and 48 existing warnings.
The wrapper records 594.06 seconds. Its 137 Python hashes stay stable and
match the final worktree, as do the million-row and app wrapper hashes.
The earlier focused receipts differ only at the later profiler fixture revision.
Later restore and rotation checkpoints extend their stated scan/staging boundaries.
All seven full gates remain UNKNOWN.


Evidence: [initial million-row failure](_reset/performance-million-current-wrapper-20261023.json),
[diagnostic replay](_reset/performance-million-trace-wrapper-20261023.json),
[safe failure origin and diagnostic source](_reset/performance-million-lease-origin-20261023.json),
[bounded lock refusal](_reset/performance-million-row-lease-wrapper-20261023.json),
[previous-product RED control](_reset/row-lease-red-20261023.json),
[control product hashes](_reset/row-lease-red-product-source-20261023.json),
[new lease controls](_reset/row-lease-green-20261023.json),
[existing primary checks](_reset/row-lease-existing-20261023.json),
[alternate cell](_reset/row-lease-sa20-20261023.json),
[unchanged app wrapper](_reset/row-lease-smolink-20261023.json),
[app source and lifecycle evidence](_reset/row-lease-smolink-app-20261023.json),
[reproducible archives](_reset/row-lease-release-20261023.json),
[installed wheel](_reset/row-lease-installed-20261023.json), and
[full primary regression](_reset/row-lease-full-20261023.json).

## Current pinned performance checkpoint: 2026-10-23

**VERIFIED, bounded local measurement:** an explicit wrapper-run profile compares
two identical 10,000-row applications with unique 53-byte names.
Both seed and query through the separate runtime role. The protected path
replans seeded data, completes the product protection/ACTIVE publication path,
and attaches with its deployment pin. Timings retain every product guard and
include native execution plus complete scalar/tuple materialization.
The primary cell is Python 3.12.3 / SQLAlchemy 2.1.3 / psycopg 3.3.6 /
cryptography 50.0.2 / PostgreSQL 16.15 on the recorded local WSL2 host.

Each workload discards ten warmup pairs, then measures 100 pairs with alternating
native/attached order. Added p95 means attached p95 minus native p95.
Raw samples retain exact values. The following table records the initial projection run.

| Workload | Native p95 ms | Protected p95 ms | Added p95 ms | Local target |
|---|---:|---:|---:|---|
| Point name scalar | 0.3841 | 2.0135 | 1.6294 | PASS, at most 3 ms |
| Equality `(id, name)` | 0.3319 | 2.3426 | 2.0107 | PASS, at most 3 ms |
| IN-20 `(id, name)`, native ID order | 0.5291 | 3.0620 | 2.5330 | PASS, at most 8 ms |

The isolated name column plus equality index measures **1.5248× native**,
within the 2× target for this distribution. Whole relation sizes remain context
in the receipt. They are outside that isolated denominator.
The wrapper passes one explicit profile case. Both receipts retain stable
136-file Python hashes. Product bytes match the preceding full regression and wheel.

A subsequent profile extends the same fixture and predicates to full ORM
entities with all four attributes materialized. It retains no identity-map objects
between samples. All six workloads pass exact native-result checks.
Added entity p95 measures **1.2622 ms point**, **2.6119 ms equality**, and
**2.8613 ms IN-20**, within the respective 3/3/8 ms local targets.
Both subsequent receipts retain stable 136-file hashes at the extended profiler.
Their raw projection measurements remain separate from the initial table.

A bounded row-count option now admits 10,000, 100,000 or 1,000,000 rows.
The **100,000-row** run passes all six workload targets and exact result checks.
Added entity p95 measures **1.2667 ms point**, **1.7083 ms equality**, and
**2.5670 ms IN-20**. Isolated storage measures **1.5296× native**.
The process uses 11.96 CPU seconds over 18.03 elapsed seconds, including setup
and cleanup. Its lifetime peak RSS is 182.5 MiB, including pytest imports.
These resource observations exclude PostgreSQL server CPU and memory.
Both 136-file receipts stay stable at the configurable profiler revision.

The subsequent **1,000,000-row** run completes the full product protection,
verification and ACTIVE attachment path. Both receipts retain stable 137-file
hashes. All six read workloads match native results and meet local targets.
This profiler revision includes the bounded row lease fix and explicit fixture
maintenance before planning. It keeps the original product lease and lock limits.

| Workload | Projection added p95 ms | Entity added p95 ms | Local maximum ms |
|---|---:|---:|---:|
| Point | 1.8239 | 2.4646 | 3 |
| Equality | 1.8742 | 2.1569 | 3 |
| IN-20 | 0.9442 | 2.5735 | 8 |

Isolated storage measures **1.4372× native**. The process uses 110.78 CPU seconds
over 172.69 elapsed seconds, including fixture maintenance and cleanup.
Its lifetime peak RSS is 1,064.9 MiB, including pytest imports.
This peak also includes the full generated input list, temporary identity/name
sets and seed serialization. It does not bound streaming backfill or adapter memory.
These observations exclude database-server CPU and memory.
The earlier lease failures and lock refusal remain separate evidence.

These are warm synchronous TEXT observations with in-process public fixture keys.
Shared-host load remains uncontrolled. Remote/cold providers, async/VARCHAR,
concurrent load, throughput and maintenance pauses remain unmeasured here.
The historical million-row receipts keep their earlier source and query-shape boundaries.
All seven full gates remain UNKNOWN.

Evidence: [raw samples, cell, lifecycle and storage](_reset/performance-current-20261023.json)
and [mandatory wrapper receipt](_reset/performance-current-wrapper-20261023.json),
then [full-entity samples](_reset/performance-entities-20261023.json)
and [full-entity wrapper receipt](_reset/performance-entities-wrapper-20261023.json),
then [100,000-row samples and resources](_reset/performance-100k-20261023.json)
and [100,000-row wrapper receipt](_reset/performance-100k-wrapper-20261023.json),
then [million-row samples and resources](_reset/performance-million-prepared-20261023.json)
and [million-row wrapper receipt](_reset/performance-million-prepared-wrapper-20261023.json).
The [fixture smoke samples](_reset/performance-row-lease-smoke-20261023.json)
and [smoke wrapper](_reset/performance-row-lease-smoke-wrapper-20261023.json)
retain the preceding small-fixture check.

## Mapped protected scalar RETURNING checkpoint: 2026-10-23

**IMPLEMENTED, bounded native verification:** attached sync/async mapped bulk
INSERT admits exactly one direct protected mapped column in `returning()`.
Native one-column Rows/scalars keep mapped keys, Python types, NULL/grouping,
paging, explicit parameter-order requests and an empty identity map.
Caller dictionaries stay unchanged. The driver observer sees the public
Unicode marker before protection. The same observer sees no plaintext marker afterward.

Tuple/entity results, labels, expressions, aliases, loader options and caller
`return_defaults()` remain refused. No format or provider contract changes.

Each returned scalar must match its input tenant, real record identity and
exact prepared ciphertext or NULL. Immutable expectations come from each native
group and survive operation cleanup. Native supplemental RETURNING authenticates
during `execute()` in the exercised cells. Lease expiry before that use refuses.
Later iteration retains plaintext that already passed authentication without
new provider work. Outstanding Results survive later session operations.
SELECT outer-join NULL behavior remains separate.

The native insertmanyvalues generator retains SQL construction, parameter
association, fetches and sentinel ordering. The guard validates full processed
input, then compares every page's rows with the original frozen slice.
It binds exact generated SQL/parameters to one cursor/context and dispatch.
Current-page and future-page mutation controls refuse before the altered page
reaches raw psycopg. The shared first-capture/completion checks remain active.

**VERIFIED:** the initial eight native baselines pass, then protected execution
fails at the original RETURNING refusal. Intermediate receipts retain admission
failures and fixture errors. Ordinary ORM annotations retain native types even
in fresh mappings. Owned column lineage now drives admission, as for SELECT.
Both native derived defaults forms pass. Test reads now use admitted explicit
primary-key IN, and refusal counters exclude the factory's tenant-policy check.
The first combined run passes 91 cases with one obsolete RETURNING refusal
expectation. That control now checks an unadmitted public-ID result instead.
The next run passes **100 cases**. The wrapper records 33.55 seconds.
Controls include current/future page tampering, returned-frame/identity/NULL substitution, leases, duplicate-ID
precedence, savepoint recovery and renamed/signed single-tenant fields.

The final alternate Python 3.13.12 / SQLAlchemy 2.0.51 / psycopg-Python cell
passes **103 cases**. The wrapper records 34.72 seconds.
It adds TEXT/VARCHAR current-value removal
after RETURNING insertion and a later ORM edit, plus unchanged pinned Smolink.
All 38 app source hashes match with no model/query changes. Its real Redis,
runtime application and import-denied package-free removal checks pass.
All final 135 Python hashes stay stable and match the worktree.
The full primary regression passes **2,018 tests and 18 subtests**.
The wrapper records 624.76 seconds, with three separate-environment skips and
48 existing DISTINCT warnings.
Its 135 Python hashes also stay stable and match the final worktree.
Reproducible offline archives, SBOM and all 36 installed package files pass,
including CLI startup. Fresh-cluster/full-alternate profiles retain their prior
revision boundaries. All seven full gates remain UNKNOWN.

Evidence: [initial native controls](_reset/bulk-returning-red-20261023.json),
[first integration](_reset/bulk-returning-green-20261023.json),
[native annotation admission](_reset/bulk-returning-native-green-20261023.json),
[derived-form admission](_reset/bulk-returning-lineage-green-20261023.json),
[native read fixtures](_reset/bulk-returning-derived-green-20261023.json),
[driver/result controls](_reset/bulk-returning-boundary-20261023.json),
[native recovery and identity controls](_reset/bulk-returning-recovery-20261023.json),
[full primary regression](_reset/bulk-returning-full-20261023.json),
[final alternate regression](_reset/bulk-returning-sa20-20261023.json),
[final app evidence](_reset/bulk-returning-smolink-app-20261023.json),
[reproducible archives](_reset/bulk-returning-release-20261023.json), and
[installed wheel](_reset/bulk-returning-installed-20261023.json).

## Test receipt checkpoint: 2026-10-23

**IMPLEMENTED, bounded verification:** the PostgreSQL wrapper adds
`pytest_report_counts` without changing historical `counts` or `modules`.
It separates final ordinary calls, subtest calls, setup, teardown and
failed/skipped collection reports. It also records selected item count.
The wrapper retains report references until session finish because pytest can
change a parent outcome after a failed subtest. No product or crypto behavior changes.
The [build guide](build-guide.md#receipt-outcome-fields) owns each field's meaning.

**VERIFIED:** real isolated pytest subprocesses cover ordinary tests and
pytest/unittest subtests. They also cover skips, phase errors, collection
failure, expected failures and non-strict unexpected passes.
The initial repository control fails all three cases on the missing field.
The corrected focused wrapper run passes **24 cases** in 2.69 seconds,
including source-stability and development-preflight regressions.
A mistaken test path produced no tests and exit 4. Its receipt remains separate.
The alternate Python 3.13 cell passes the same 24 cases in 3.08 seconds.

The full primary regression passes **1,978 tests and 18 subtests** in
552.20 seconds, with three separate-environment skips and 48 existing DISTINCT warnings.
The new receipt separates 1,978 passed/one skipped ordinary call, 18 passed
subtests and two collection skips. It records 1,979 selected items.
All 132 Python source hashes stay unchanged and match the worktree.
This full run also covers the shared driver's final exact-buffer fix below.

Other pytest versions and external report plugins remain unverified.
These counters do not qualify a production gate. Product package bytes retain
the preceding reproducible archive evidence. No new wheel build was needed.

Evidence: [initial missing-field failures](_reset/report-counts-red-20261023.json),
[invalid test path](_reset/report-counts-green-20261023.json),
[focused reporter/preflight regression](_reset/report-counts-focused-20261023.json),
[alternate reporter/preflight regression](_reset/report-counts-sa20-20261023.json), and
[full primary regression](_reset/report-counts-full-20261023.json).

## Shared driver event checkpoint: 2026-10-23

**IMPLEMENTED, bounded native verification:** the shared guard captures each
native processed statement/parameter set at the first cursor event, then checks
the actual values at dialect dispatch. It freezes native SQL, binary bytes,
containers and typed primitive/identity values. It retains unknown unprotected
driver adapters by object identity, without freezing their mutable internals.
Capture consumption covers ordinary flush/read paths, sync/async dispatch and
each native insertmanyvalues RETURNING page. The bulk route retains its
independent sealed-batch checks. No crypto format, key authority or DML scope
changes.

Capture must be first and unique in effective Connection dispatch. Preattachment
engine listeners refuse before connection. Effective Connection listeners
refuse before the first catalog query. Later class/connection cursor hooks also
refuse before data dispatch. Register unchanged engine-instance observers after
attachment. Native `insert=True` does not reorder these Connection events.
Changed SQL/values, unsafe order, missing capture and SQL string subclasses
raise `UnsafeDriverEvent`. Named-key comparison freezes native text and type
identity, without calling supplied equality overrides. No callback receives a
driver permit. Independent clients, host authorization, earlier expression
admission and custom adapter internals keep their separate trust limits.
An after-cursor check requires actual guarded dispatch completion before native
result/UOW success. A dialect callback cannot return `True` to silently skip
an INSERT, including a class callback installed during a later cursor callback.
Each page resets and consumes its own markers. Deliberate removal of Cryptalis
callbacks is trusted-host guard tampering, outside this boundary.

**VERIFIED:** the initial run retains 13 failures. Eleven expose cursor
changes that reached the real driver or changed observable read behavior.
Two reveal RETURNING fixture errors: the existing mapper cached default metadata
before the test changed it. Fresh imperative mappings with eager defaults now
establish the native five-row, three-page baseline without private cache edits.
The first corrected primary run passes **59 cases** in 22.53 seconds, including
all 44 bulk cases. Controls cover in-place plaintext/valid-frame substitution,
identity and tenant mutation, ordinary UPDATE, point/equality query changes,
SQL and spoofed-string replacement, connection-local hooks, preattachment
refusal before connection/key work, native observer results, RETURNING page
tampering, async failure/rollback and clean retry. Raw psycopg call collectors
remain empty during each refused injection.

The alternate Python 3.13.12 / SQLAlchemy 2.0.51 / psycopg-Python cell passes
those cases plus the pinned unchanged Smolink lifecycle: **60 cases** in
18.67 seconds. All 38 app source hashes match, with no model/query changes.
Its import-denied current-value removal child also passes. The full primary
regression was interrupted to add the completion control after source review.
Its receipt retains 975 passed tests, 18 passed subtests, two collection skips
and one real reattachment exception-class failure before interruption.
`UnsafeDriverEvent` now retains the existing unsupported-operation category.
The completion, reattachment, deprotection and bulk run passes **80 cases** in
35.90 seconds. The final alternate cell passes **62 cases** in 28.53 seconds,
including both dialect-skip controls and the unchanged Smolink lifecycle.
The subsequent broad primary run passes **1,974 tests and 18 subtests** in
586.08 seconds, with three separate-environment skips and 48 existing DISTINCT
warnings. This run precedes the following narrow buffer-admission fix.

A real PostgreSQL negative control then exposes a custom Binary buffer bypass:
a bytearray subclass reports the original frame through `__bytes__`, while
psycopg sends its different native buffer. The inserted row reached the driver
without the required typed refusal. The guard now requires exact native buffer
types and reads them through `memoryview`, without custom byte conversion.
The final affected primary run passes **227 cases** in 58.70 seconds across
the event, bulk, deprotection, adapter, search and runtime boundaries.
The final alternate cell passes **63 cases** in 28.38 seconds, including the
buffer control and unchanged Smolink lifecycle. Both final 131-file Python
bundles match the current worktree. The broad run above remains bounded to its
recorded pre-buffer-fix source. Fresh-cluster profiles and the full alternate
cell were not rerun for this guard.
Completed runs retain stable 131-file Python hashes. Reproducible final offline
archives, SBOM and all 36 installed package files pass, including CLI startup.
All seven full gates remain UNKNOWN.

Evidence: [initial failures](_reset/driver-event-red-20261023.json),
[primary guard and bulk regression](_reset/driver-event-green-20261023.json),
[interrupted broad run](_reset/driver-event-full-20261023.json),
[completion and deprotection controls](_reset/driver-event-completion-20261023.json),
[broad primary run](_reset/driver-event-full-final-20261023.json),
[native masked-buffer failure](_reset/driver-event-buffer-red-20261023.json),
[final affected primary regression](_reset/driver-event-buffer-green-20261023.json),
[alternate guard and app](_reset/driver-event-sa20-20261023.json),
[app evidence](_reset/driver-event-smolink-app-20261023.json),
[final alternate guard and app](_reset/driver-event-sa20-final-20261023.json),
[final app evidence](_reset/driver-event-smolink-app-final-20261023.json),
[final buffer/app alternate run](_reset/driver-event-sa20-buffer-20261023.json),
[final buffer/app evidence](_reset/driver-event-smolink-app-buffer-20261023.json),
[final reproducible archives](_reset/driver-event-release-buffer-20261023.json), and
[final installed wheel](_reset/driver-event-installed-buffer-20261023.json).

## Mapped bulk INSERT checkpoint: 2026-10-23

**IMPLEMENTED, bounded native verification:** attached sync/async sessions admit
`Session.execute(insert(Model), list[dict])` without RETURNING. Each row supplies
its stable typed identity and declared tenant. Single-tenant mappings use their
declared table UUID. The route copies caller dictionaries, prepares distinct
row/field-bound CF1 frames, and delegates grouping, dispatch and constraints to
the native ORM. It adds no crypto format, representation or provider authority.

Native checks cover heterogeneous rows, omitted/explicit NULL, `render_nulls`,
exact Unicode and VARCHAR space truncation, uniqueness, empty identity maps,
closed no-row Results, rollback and nested savepoint recovery. An earlier native
row constraint retains precedence over a later VARCHAR length error. Failed
pending ORM autoflush also retains precedence. A known bulk length failure
uses public constants in PostgreSQL assignment coercion, then returns the typed
failure with native Session activity and aborted-transaction behavior. Protected
text never becomes an error-carrier parameter.

The final bulk driver guard checks actual SQL, row identity, tenant and payload
bytes against the admitted batch after cursor listeners. Compiled parameters
alone cannot waive that check. Late context and payload replacements refuse
before the real psycopg INSERT methods. This strengthened processed-value check
is scoped to this bulk route. Exact stock savepoint-control clauses separately
require native SQL, empty parameters and unchanged attachment configuration.
They grant no data permit and retain native transaction objects and cleanup.

RETURNING, Core INSERT, upserts, statement-embedded values, INSERT SELECT,
SQL row expressions, legacy bulk methods and used callable/context/SQL/server
defaults remain unadmitted. Explicit values can bypass unused defaults.
Missing/cross-tenant context and unavailable/expired keys refuse without a
partial prefix. Async preparation cancellation reaches no data SQL and permits
a fresh retry. TEXT/VARCHAR single-tenant mappings with renamed attributes pass
bulk insertion, latest ORM edit, decrypt-back and native current-value removal.
Separate independent-process package-free evidence retains its earlier scope.

**VERIFIED:** the first 26-case run retains 15 admission failures and
11 passing controls. An intermediate implementation run retains 15 failures,
including invalid test read shapes and the missing native savepoint route.
After correcting those helpers and the guard, all 26 pass in 8.41 seconds.
The expanded driver, cancellation, autoflush and removal run passes 38 cases
in 14.82 seconds. Two subsequent multi-field UUID/signed-int64 cases pass in
0.58 seconds, including nil UUID, zero and signed limits.

The Python 3.12.3 / SQLAlchemy 2.1.3 full regression passes **1,953 tests and
18 subtests** in 611.83 seconds, with three separate-environment skips and
48 existing DISTINCT deprecation warnings. These are pytest terminal counts.
The receipt's call-report aggregate includes subtests and excludes two
collection skips. All 130 Python files remain stable during that run.
The subsequent test-only change strengthens final-driver injection controls.
All **44 bulk cases** pass in 13.26 seconds at the final 130-file bundle.
They cover valid CF1 in same-type Binary substitution, in-place Binary mutation,
coherent compiled/driver row substitution, actual SQL replacement, and a
savepoint replacement that must not grant a data-write permit.

The alternate Python 3.13.12 / SQLAlchemy 2.0.51 cell passes these 44 cases
and the pinned unchanged Smolink lifecycle, **45 cases** in 22.91 seconds.
It uses existing read-only installed dependency paths and psycopg 3.3.6's
Python implementation. The initial bare interpreter lacked psycopg and stopped
before database probes. No package was installed into Smolink. Its 38 original
Python source hashes match. The HTTP/repository/ORM lifecycle, real disposable
Redis, current-value removal and import-denied child pass at the recorded
single protected `Url.destination` scope. The full alternate cell, complete
external application suite and fresh-cluster backup profiles were not rerun.
All product bytes match the full regression and release receipts. Both final
cell receipts have stable 130-file hashes that match the final worktree.

Reproducible offline wheel/sdist builds, SBOM inspection and all 36 installed
package files pass, including CLI startup. Provider custody, independent review,
other event-mutation routes and the seven full production gates remain UNKNOWN.

Evidence: [native oracle](_reset/bulk-insert-native-oracle-20261023.json),
[initial admission failures](_reset/bulk-insert-red-20261023.json),
[intermediate failures](_reset/bulk-insert-first-20261023.json),
[guarded native behavior](_reset/bulk-insert-guard-20261023.json),
[adversarial and removal cases](_reset/bulk-insert-boundary-20261023.json),
[multi-field context](_reset/bulk-insert-context-20261023.json),
[full regression](_reset/bulk-insert-full-20261023.json),
[final primary matrix](_reset/bulk-insert-final-20261023.json),
[alternate matrix and application](_reset/bulk-insert-sa20-20261023.json),
[pinned app evidence](_reset/bulk-insert-smolink-app-20261023.json),
[reproducible archives](_reset/bulk-insert-release-20261023.json), and
[installed wheel](_reset/bulk-insert-installed-20261023.json).

The later [shared guard checkpoint](#shared-driver-event-checkpoint-2026-10-23)
extends cursor-event mutation checks to flush/read routes. Exact receipt count
reporting remains open. Broader DML/RETURNING, used defaults,
online lifecycle and external qualification remain separate product gaps.

## Rotation preparation status checkpoint: 2026-10-23

**IMPLEMENTED, bounded native verification:** `cryptalis status` now reads
payload and search preparation artifacts through their existing typed public
status APIs. It reports PREPARED, EXPANDED, BACKFILLED or ABORTED progress,
the source operation and its own operation, and the supplied preparation pin.
The scopes are `payload_rotation_preparation` and `search_rotation_preparation`.
Every preparation result keeps `runtime_metadata_matches: false`,
`verification: NOT_PERFORMED`, `effects: NONE` and exit 3. Recorded preparation
does not authorize an active application deployment.

Both Python and CLI preparation status repeat effective runtime privilege
admission before observing progress. Inspection uses a read-only repeatable
snapshot, without provider work or maintenance locks. An invalid preparation
pin fails before connection. A supplied restore binding is refused before its
file is read. Doctor continues to refuse preparation artifacts. This change
adds no adopted-target rotation support or publication authority.

Search planning now admits source types before reading source fields. Invalid
sources raise `external_policy_mismatch`, without connection or key work.
Missing search preparation and activation rows now use `missing_search_operation`
and `missing_search_activation`. Existing payload error codes remain unchanged.
Refusals retain source values, staged ciphertext, progress and native catalogs.

**VERIFIED:** the initial native run retains 23 failures and three passing
payload controls. The affected CLI, manifest inspection, Doctor, source/pin
admission, runtime privilege and generation workflows pass **369 cases** in
178.30 seconds. New cases cover both purposes and all four recorded phases,
exact public-API counters, unsafe grants and recovery after REVOKE, invalid
authority before connection, missing forward-pinned operations, no-key and
read-only paths, wrong credentials, typed invalid source and missing activation.

The eight phase/purpose cases pass again in 7.59 seconds with actual runtime
credentials after strengthening that single test function. The final run's
127 Python source/test/script hashes match at start, end and final inspection.
All product bytes still match the 369-case regression and release receipts.
The wheel and sdist build reproducibly offline. All 36 installed files match the wheel, and
installed CLI startup plus rotation-status help pass.
The previous full regression and fresh-cluster profiles below remain
revision-bound. They were not rerun for this interface and diagnostic change.
Provider custody, host authority, frame freshness and the complete operational
status contract remain unqualified. All seven full gates remain UNKNOWN.

At this checkpoint, next work targeted ordinary ORM bulk inserts. The later
[bulk checkpoint](#mapped-bulk-insert-checkpoint-2026-10-23) records that bounded
admission. Broader DML and RETURNING remain product gaps.

Evidence: [initial native failures](_reset/rotation-status-red-20261023.json),
[affected regression](_reset/rotation-status-regression-20261023.json),
[actual runtime credentials](_reset/rotation-status-runtime-20261023.json),
[final reproducible archives](_reset/rotation-status-release-final-20261023.json), and
[final installed wheel](_reset/rotation-status-installed-final-20261023.json).

## Doctor and runtime status checkpoint: 2026-10-23

**IMPLEMENTED, bounded native verification:** `cryptalis doctor` inspects an
existing ACTIVE deployment through its actual declared runtime connection.
`migration.diagnose_deployment` admits the immutable plan, exact ACTIVE pin,
and optional matching restore binding before connection. It repeats shared
attachment admission in one read-only, repeatable-read catalog snapshot.
The check covers runtime identity, target, lineage, effective privileges and
schema. It requests no keys, authenticates no frames, takes no maintenance
locks and changes no rows, journal or schema.

Doctor reports `runtime_deployment: PASS` only after inspection and connection
cleanup succeed. Provider keys, frame authentication, query routes, writer
exclusion, host authority and recovery capacity remain UNKNOWN. The aggregate
result also remains UNKNOWN. Exit 0 means the scoped observed check passed.
Typed observed refusals report FAIL. Unavailable inspection, cleanup and output
failures report UNKNOWN. Diagnostics retain safe primary and cleanup codes
without raw connection or exception details.

Ordinary ACTIVE/PENDING `migration.status` now repeats shared runtime privilege
admission before reporting matching metadata. Previously it could return
success after unsafe schema CREATE or journal-column UPDATE grants. Restored
status already used the shared check. All status remains keyless and reports
`verification: NOT_PERFORMED`.

**VERIFIED:** the initial Doctor controls retain 12 failures. Two separate
native controls directly expose the unsafe ACTIVE status success. The corrected
focused run passes 88 cases in 39.50 seconds. They include real runtime and
owner connections, unsafe ACTIVE/PENDING grants, same-artifact recovery after
REVOKE, malformed/unpublished authority before connection, wrong credentials,
native transaction settings, forbidden provider work, unchanged native
snapshots, lost output and actual post-close failures. Doctor accepts later
ACTIVE edits after search rotation and refuses a changed predecessor chain.
Two final cleanup controls pass in 0.68 seconds after adding sanitized close
stage evidence alongside the primary refusal.

Search TEXT and VARCHAR fresh-cluster profiles each pass one export and
30 restore cases in the approved isolated-cluster harness. Doctor accepts
the adopted binding through the actual runtime role. A source-incompatible
binding fails before connection. The same profiles still complete latest-value
CRUD, decrypt-back and native removal. The wheel and sdist build reproducibly
offline. All 36 installed files match the wheel, and installed CLI startup and
Doctor help pass. These checks qualify no release or production provider.

**VERIFIED, Python 3.12.3 / SQLAlchemy 2.1.3 local cell:** full regression passes
**1,887 tests and 18 subtests**, with three separate-environment skips and
48 existing DISTINCT ON deprecation warnings, in 519.66 seconds. The wrapper
counts subtests with passed cases. All 125 Python source/test/script hashes
match at run start, run end and final inspection. The fixing fingerprint is
`worktree-c6c36eaa97093f1b`; cleanup, both fresh-cluster profiles and release
checks match the same current product bytes. The SQLAlchemy 2.0.51 cell and
pinned Smolink application were not rerun for this slice. Earlier evidence
below remains revision-bound.
The command does not scan pre-adoption applications, qualify providers,
authenticate host policy, prove freshness or observe all query/write routes.
All seven full gates remain UNKNOWN.

The later [preparation status checkpoint](#rotation-preparation-status-checkpoint-2026-10-23)
adds both preparation formats and purpose-correct search diagnostics.
Pre-adoption application scanning and provider diagnostics remain product gaps.

Evidence: [initial Doctor failures](_reset/doctor-native-red-20261023.json),
[direct status failures](_reset/doctor-status-privilege-red-20261023.json),
[first corrected native controls](_reset/doctor-native-green-20261023.json),
[expanded native controls](_reset/doctor-native-final-20261023.json),
[final cleanup diagnostics](_reset/doctor-cleanup-final-20261023.json),
[TEXT adopted recovery](_reset/fresh-cluster-restore-20261023-15.json),
[VARCHAR adopted recovery](_reset/fresh-cluster-restore-20261023-16.json),
[reproducible archives](_reset/doctor-release-20261023.json),
[installed wheel](_reset/doctor-installed-20261023.json), and
[full regression](_reset/doctor-full-20261023.json).

## Search-key rotation and backup checkpoint: 2026-10-23

**IMPLEMENTED, bounded native verification:** search rotation now has planning,
encrypted staging, status, source-only cancellation, deterministic sealing and
atomic cutover through the shared publication engine. P uses
`cryptalis.search-rotation/v1`. Sealed activation A uses
`cryptalis.transition/v4`, with exact target observations, policy digests,
batch limits and source-to-P-to-A ancestry. Current code retains v1/v2/v3 artifact reading. Older host readers must upgrade
before v4 publication.

The target retains exact source wrappers and root material. Each selected
search policy adds one independent root above every retained search generation.
Payload selection stays unchanged. Searchable frames receive new terms and
fresh authenticated nonces. Storage-only frames and search-less tenant policies
remain exact. The adapter admits retained search readers only under an exact
bound deployment policy and pins one active query namespace. It never queries
multiple generations with OR.

The two generation workflows share encrypted shadows, atomic cursor commits,
guards, paired verification and publication mechanics. Their policy and header
checks remain explicit. Native public UPDATE maintains equality and unique
indexes inside the terminal transaction. A target uniqueness conflict rolls
back the entire switch. Host copy-rate and WAL estimates must include index
maintenance. Bounded preparation does not bound the full-table terminal copy,
memory overhead, storage capacity, pause or WAL.

**VERIFIED:** 92 focused cases pass in 70.64 seconds. They include 32 search
crypto controls with independent frame composition, 13 retained-reader controls,
12 native search lifecycle cases, three actual lost-COMMIT/SIGKILL recovery
cases and 32 existing payload cases. The search cases cover TEXT/VARCHAR,
multiple tables/tenants, exact storage-only bytes, Unicode/NULL, equality/IN,
uniqueness, latest-value removal, target outage cancellation, authentic target
resealing, late proof/counter/ancestor drift, post-UPDATE/guard-drop rollback,
an injected target HMAC collision with native SQLSTATE `23505`, and a
search/payload/rewrap/search chain. A fresh process publishes the same saved
artifacts after SIGKILL. Native conflict and recovery tests preserve committed
source or target bytes and recorded progress.

Search TEXT and VARCHAR fresh-cluster profiles each pass one export and
**29 restore cases**. A protected edit after publication differs from A's sealed
snapshot and survives recovery. A separate KDF/HMAC decoder authenticates the
generation-two search term under the unchanged payload root. The existing
`cryptalis.restore/v1` binding admits the backup, current edits and native removal.
A valid old search-generation frame remains refused despite retained keys.
Original protection and root-rewrap profiles pass 23 and 26 restore cases,
respectively, with one rotation-only skip each. The payload/VARCHAR profile
passes 29 cases. Each also passes its own export on the same product source.

**VERIFIED, Python 3.12.3 / SQLAlchemy 2.1.3 local cell:** full regression passes
**1,869 tests and 18 subtests**, with three separate-environment skips, in
505.01 seconds. The wrapper counts subtests with passed cases. The 48 existing
warnings concern SQLAlchemy DISTINCT ON deprecation. All start/end Python hashes
match. The SQLAlchemy 2.0.51 cell and pinned Smolink application were not rerun
for this slice.

After the full run, one trailing blank line was removed from the recovery test.
Its AST and source locations remain identical. The three native lost-COMMIT
and SIGKILL controls pass again in 20.35 seconds at the final test hashes.
All product bytes still match the full and release receipts.

The wheel and sdist build reproducibly offline. A disposable installed wheel
matches all 36 packaged files and starts its CLI. Initial extraction errors
and a test-clock defect remain in the failed receipts. The corrected focused
run above reruns every affected control.

All three rotation workflows now have bounded local product paths. Rotation
on adopted targets, production custody/retirement, authenticated host authority,
online migration and independent review remain open. All seven full gates
remain UNKNOWN. Search rotation deletes no retained keys and establishes no
unlinkability or cryptographic-erasure guarantee.

The later [Doctor checkpoint](#doctor-and-runtime-status-checkpoint-2026-10-23)
adds bounded diagnosis and aligns ACTIVE/PENDING status with deployment
privilege admission. Status remains a metadata observation and reports
cryptographic verification as `NOT_PERFORMED`.

Evidence: [first extraction failures](_reset/search-foundation-first-20261023.json),
[corrected extraction and clock failures](_reset/search-foundation-corrected-20261023.json),
[native lifecycle and recovery](_reset/search-rotation-native-first-20261023.json),
[full regression](_reset/search-rotation-full-20261023.json),
[test-only normalization](_reset/search-rotation-test-normalization-20261023.json),
[final recovery controls](_reset/search-rotation-final-recovery-20261023.json),
[TEXT search recovery](_reset/fresh-cluster-restore-20261023-10.json),
[VARCHAR search recovery](_reset/fresh-cluster-restore-20261023-11.json),
[older payload recovery](_reset/fresh-cluster-restore-20261023-12.json),
[older rewrap recovery](_reset/fresh-cluster-restore-20261023-13.json),
[original protection recovery](_reset/fresh-cluster-restore-20261023-14.json),
[reproducible archives](_reset/search-rotation-release-20261023.json), and
[installed wheel](_reset/search-rotation-installed-20261023.json).

## Reverse runtime admission checkpoint: 2026-10-23

**IMPLEMENTED, bounded native verification:** decrypt-back rechecks effective
runtime privileges before staging, resume, publication and journal retirement.
Read-only reverse status uses the same admission. Plaintext-role planning now
uses the shared privilege predicate before provider work, while preserving
`unsafe_plaintext_runtime_role` for unsafe plaintext credentials.

The trusted host pin selects the runtime boundary. PREPARED, EXPANDED,
BACKFILLED, VERIFIED and PLAINTEXT_PENDING require the source protected runtime.
PLAINTEXT_ACTIVATING, PLAINTEXT_ACTIVE and REMOVING require the declared plaintext
runtime. A mutable journal phase cannot select a different role. An actually
absent journal with REMOVED skips both role checks and retains native metadata
inspection. The old protected runtime can retire after plaintext publication.
Checks observe effective privileges. They do not freeze later administrative
changes or authenticate publication, writer fencing or credential retirement.

**VERIFIED:** the initial native controls expose **19 failures** and retain one
passing removal retry. After the fix, all **20 cases pass** in 11.34 seconds.
They cover unsafe journal-column and schema grants across every admitted host
phase, initial plaintext planning, forged journal phase selection, unchanged
rows/progress on refusal and preserved native edits after removal. Terminal
retries succeed after the former runtime restrictions change. These tests do
not delete the shared roles or prove a production credential-retirement process.

**VERIFIED, Python 3.12.3 / SQLAlchemy 2.1.3 local cell:** full regression passes
**1,809 tests and 18 subtests**, with three separate-environment skips, in
473.95 seconds. The wrapper counts subtests with passed cases. The 48 existing
warnings concern SQLAlchemy DISTINCT ON deprecation. All start/end Python hashes
match.

TEXT and VARCHAR payload backups each pass one export and **28 restore cases**
on new PostgreSQL 16 clusters at the final Python hashes. The adopted paths
retain independent generation-two decoding, later edits, decrypt-back, native
metadata and package removal under the stricter runtime admission.

The wheel and sdist build reproducibly offline. The installed wheel matches all
35 packaged files and starts its CLI. Search reindex and rotation on adopted
restored targets remain SPECIFIED. Production custody, authenticated authority,
independent review and all seven full gates remain unqualified or UNKNOWN.

At this reverse checkpoint, search rotation remained SPECIFIED. The later
[search checkpoint](#search-key-rotation-and-backup-checkpoint-2026-10-23) above
adds bounded native preparation, publication and backup evidence.

Evidence: [native failures](_reset/reverse-runtime-red-20261023.json),
[phase-aware controls](_reset/reverse-runtime-first-20261023.json),
[full regression](_reset/reverse-runtime-full-20261023.json),
[TEXT recovery](_reset/fresh-cluster-restore-20261023-8.json),
[VARCHAR recovery](_reset/fresh-cluster-restore-20261023-9.json),
[reproducible archives](_reset/reverse-runtime-release-20261023.json), and
[installed wheel](_reset/reverse-runtime-installed-20261023.json).

## Payload-backup recovery and runtime admission checkpoint: 2026-10-23

**IMPLEMENTED, bounded native verification:** the fresh-cluster harness accepts
`--payload-rotation`, with optional `--varchar`. It exports a published activation
plan A, its retained source/preparation ancestry and current protected data.
An attached application edits data after publication and before the dump.
Recovery preserves that edit, even though its frame differs from A's sealed
cutover snapshot. Existing `cryptalis.restore/v1` approval, fencing and binding
remain required. A database journal supplies no external authorization.

Restore admission now checks the host-pinned plan, exact predecessor chain,
strict journal state and inventory before behavioral schema probes or key work.
It also checks effective runtime privileges and protected-column metadata first.
The shared role check rejects owner membership, dangerous role attributes,
database/schema CREATE, protected-table TRIGGER/TRUNCATE and journal writes,
including column grants. Initial protection planning, active admission, adopted
binding admission and the shared maintenance executor use this check.

The initial recovery controls exposed ten failures. After the fixes, TEXT and
VARCHAR payload profiles each pass one export and **28 restore cases** on new
PostgreSQL 16 clusters. A separate decoder derives generation-two fixture keys
and authenticates current CF1 payloads and search terms. A valid generation-one
frame still fails adoption under the selected generation-two policy, even with
retained old keys. Other controls cover altered ancestry/proofs, unsafe grants,
late binding drift, attached search/edits, decrypt-back and native removal.
The older rewrap/VARCHAR profile passes one export and **26 restore cases**.
Its payload-only case is explicitly skipped. Seven ordinary native cases also
refuse unsafe privileges before provider work or database changes.

**VERIFIED, Python 3.12.3 / SQLAlchemy 2.1.3 local cell:** full regression passes
**1,789 tests and 18 subtests**, with three separate-environment skips, in
456.88 seconds. The 48 existing warnings concern SQLAlchemy DISTINCT ON
deprecation. All start/end Python hashes match.

The wheel and sdist build reproducibly without network access. A disposable
installed wheel matches all 35 packaged files and starts its CLI.
Search reindex and rotation on adopted restored targets remain SPECIFIED.
Production custody, authenticated host authority and independent security review
remain unqualified. All seven full gates remain UNKNOWN.

Evidence: [initial failures](_reset/fresh-cluster-restore-20261023-3.json),
[TEXT recovery](_reset/fresh-cluster-restore-20261023-6.json),
[VARCHAR recovery](_reset/fresh-cluster-restore-20261023-5.json),
[older rewrap recovery](_reset/fresh-cluster-restore-20261023-7.json),
[shared role controls](_reset/restore-runtime-focused-20261023.json),
[full regression](_reset/restore-runtime-full-20261023.json),
[reproducible archives](_reset/restore-runtime-release-20261023.json), and
[installed wheel](_reset/restore-runtime-installed-20261023.json).

## Sealed payload cutover checkpoint: 2026-10-23

**IMPLEMENTED, bounded native verification:** `rotation.seal_payload_rotation`
authenticates a complete BACKFILLED preparation P against its original source
and actual target frames. It returns a deterministic immutable transition/v3
activation plan A without changing database data or authority. A pins target
frame/membership observations, target policies, validated scan limits, explicit
copy/WAL estimates and the exact source/preparation ancestor chain. The host must
persist A before `rotation.switch_payload_rotation`.

Cutover repeats source and paired target authentication under maintenance locks.
It compares the target observations to host-pinned A, copies ciphertext into the
existing public columns, removes P's shadows and exchanges its guards for A's.
Source SUPERSEDED to P, P SUPERSEDED to A and A PENDING commit atomically. The
public columns keep their physical identities, constraints, grants and equality
indexes. A bounded post-copy pass authenticates the installed target against A.
A PENDING retry uses target custody and A's exact lineage. It does not replay the
retired original source. Switched preparation cannot resume or cancel.

Shared `migration.apply` admits A only for ACTIVATING/ACTIVE publication. An
ACTIVATING retry repeats target verification even when the journal claims ACTIVE.
A genuine ACTIVE pin permits later application edits. Publication also checks
current owner, metadata, inventory and strict progress shape before provider work.
Native controls preserve current edits through decrypt-back and package removal,
including a payload/rewrap/payload chain with five exact ancestors.

**VERIFIED:** 37 final native cases pass in 51.77 seconds. They cover text/VARCHAR,
multiple tables and tenants, storage-only fields, exact Unicode/NULL values,
equality/IN/uniqueness, deterministic sealing, scope ordering across artifact
reload, authentic target reseal after sealing, forged ACTIVE journals, late ACL
or inventory drift, malformed artifacts and journal counters, missing ancestry,
rollback after native public UPDATE and guard removal, real cutover/publication
COMMIT reply loss, SIGKILL and fresh-process disk-artifact publication. The initial
17 cases and expanded 33-case run also pass after the missing-API red controls.

**VERIFIED, Python 3.12.3 / SQLAlchemy 2.1.3 local cell:** full regression passes
**1,782 tests and 18 subtests**, with three separate-environment skips, in
450.53 seconds. The wrapper counts subtests with passed cases. The 48 existing
warnings concern SQLAlchemy DISTINCT ON deprecation. All start/end Python hashes
match. Fresh-cluster and pinned Smolink harnesses were not rerun for this cutover
slice.

The wheel and sdist build reproducibly without network access. The installed wheel matches all 35 packaged
files and starts its CLI. Dependency installation remains outside that check.

The final server copy is one complete-table write in an atomic terminal
transaction. It has no committed chunk bound. Host estimates include five
verification passes and the copy. A seven-row local observation records 3.70 ms
inside the native copy and 114.09 ms for the whole switch call. The cluster WAL
counter advances 2,056 bytes during the copy interval and 13,640 bytes across the
whole call. These are one synthetic sample and cluster-wide observations, not
isolated operation attribution, throughput, capacity or pause guarantees.

Search reindex and rotation on adopted restored targets remain SPECIFIED.
At this cutover checkpoint, fresh-cluster payload backups remained unqualified.
The later [recovery checkpoint](#payload-backup-recovery-and-runtime-admission-checkpoint-2026-10-23)
adds that bounded evidence. Production provider/authority evidence and independent
security review remain open. All seven full gates remain UNKNOWN.

Evidence: [missing APIs](_reset/payload-cutover-red-20261023.json),
[first native run](_reset/payload-cutover-first-20261023.json),
[expanded recovery](_reset/payload-cutover-expanded-20261023.json),
[final native controls](_reset/payload-cutover-final-native-20261023.json),
[full regression](_reset/payload-cutover-full-20261023.json),
[copy observation](_reset/payload-cutover-copy-observation-20261023.json),
[reproducible archives](_reset/payload-cutover-release-20261023.json), and
[installed wheel](_reset/payload-cutover-installed-wheel-20261023.json).

## Payload staging and cancellation checkpoint: 2026-10-23

**IMPLEMENTED, bounded native verification:** `rotation.apply_payload_rotation`
stages encrypted payloads under the immutable preparation artifact P. The source
public frames, equality indexes and source ACTIVE journal remain intact. The
executor checks source authority, schema, journal inventory, retained custody and
both policies before expansion. Exact P guards and nullable bytea shadows commit
together. Existing source attachments reject the changed maintenance schema.
Keep all application workers stopped during preparation.

Each chunk holds write-excluding table locks across its length probe, reads,
shadow writes and progress marker. Complete rows obey P's aggregate logical byte
budget. Python, driver, database and provider overhead remain outside that budget.
This establishes no RSS or capacity bound. Resume authenticates the committed
prefix and preserves its randomized frames. It rejects copied source-generation
frames, unauthentic target frames, inconsistent cursors and altered guards or schema.
BACKFILLED requires a complete source/target value, NULL, generation and search-header
check. Every BACKFILLED retry repeats authentication. `max_chunks` can stop after
the last data chunk while phase remains EXPANDED. A later call performs the final
verification and records BACKFILLED.

`status_payload_rotation` reads recorded progress without keys. It reports
`NOT_PERFORMED` and no runtime metadata match. It supplies no data-verification or
publication authority. `abort_payload_rotation` requires the external source ACTIVE
pin. It authenticates the source, removes only P's exact shadows and guards, and
records P as ABORTED in one transaction. It needs no target provider. Terminal
retries preserve later source edits and reject a superseded source. Adopted restore
is outside this implementation.

**VERIFIED:** 26 native execution/recovery cases pass in 30.54 seconds. Controls
cover text/VARCHAR, multiple tables and tenants, equality and storage-only fields,
NULL and exact Unicode values, source edits after planning, prior rewrap lineage,
provider outage, invalid authority, tampering, cancellation before expansion and
after full backfill, process death after a committed chunk, and fresh-process
artifact reload. Real proxies discard committed chunk and cancellation replies.
Injected failures after native shadow UPDATE and guard DROP preserve the previous
committed state and writer fence. Resume preserves committed prefix nonces and
source bytes/index identity.

**VERIFIED, Python 3.12.3 / SQLAlchemy 2.1.3 local cell:** full regression passes
**1,745 tests and 18 subtests**, with three separate-environment skips, in
386.13 seconds. The wrapper counts subtests with passed cases. The 48 existing
warnings concern SQLAlchemy DISTINCT ON deprecation. All start/end Python hashes
match. The separate fresh-cluster and pinned Smolink harnesses were not rerun for
this preparation slice.

The wheel and sdist build reproducibly without network access. The installed-wheel check matches all 34
packaged files and starts its CLI under a fresh bytecode cache. Dependency
installation remains outside that check. Receipt source hashes match the worktree.
The initial red run reports the missing execution APIs. The first 13 native
controls pass before the expanded recovery cases. Review found no additional
concrete bypass. That review supplies no independent security qualification.

At this staging checkpoint, sealing A, final cutover and publication remain
SPECIFIED. The later [sealed cutover checkpoint](#sealed-payload-cutover-checkpoint-2026-10-23)
adds these operations. P cannot enter `migration.apply`. The
[two-artifact decision](decisions.md#payload-rotation-preparation-and-activation-2026-10-23)
requires host persistence of A before the destructive switch. A journal marker
cannot replace that authority. Search rotation, restored-target rotation,
production custody and independent review remain open. All seven full gates
remain UNKNOWN.

Evidence: [initial controls](_reset/payload-stage-red-20261023.json),
[first implementation](_reset/payload-stage-first-20261023.json),
[expanded native recovery](_reset/payload-stage-recovery-20261023.json),
[full regression](_reset/payload-stage-full-20261023.json),
[reproducible release](_reset/payload-stage-release-20261023.json), and
[installed wheel](_reset/payload-stage-installed-wheel-20261023.json).

## Payload-rotation planning checkpoint: 2026-10-23

**IMPLEMENTED, bounded native verification:** `plan_payload_rotation` emits an
inactive source-pinned `PayloadRotationPlan`. It checks current deployment,
schema and journal inventory in one read-only repeatable-read snapshot. The
target retains every exact source wrapper/root and adds one independent payload
root above all retained payload generations. Search custody remains unchanged.
Historical readers and tenants with no current rows remain necessary.

The artifact records source frame/membership/schema observations, public contexts,
policy digests, distinct preparation/successor IDs, aggregate batch limits and
host-measured backfill/verification/storage/WAL estimates. It contains no wrapper
bytes, root material or plaintext digest. The length probe uses bigint arithmetic
and admits only the complete-row prefix within the aggregate logical budget
before retrieving frames. Python, driver, database and provider overhead remain
outside that budget. This establishes no capacity or RSS bound.

**VERIFIED:** 163 focused native cases pass in 68.45 seconds across new planning,
root-rewrap planning/execution/cancellation, and the independent payload-batch
controls. They include real multi-field/multi-tenant budgets, historical/deleted
tenant readers, exact retained-wrapper refusal, fresh payload generation,
snapshot stability under a concurrent commit, safe artifact/input admission and
cleanup-time expiry. The shared offline rewrap protocol also passes five groups
with synthetic artifacts. That offline run establishes no PostgreSQL behavior.

**VERIFIED, Python 3.12.3 / SQLAlchemy 2.1.3 local cell:** full regression passes
**1,719 tests and 18 subtests**, with three separate-environment skips, in
367.59 seconds. The wrapper counts subtests with passed cases. The 48 existing
warnings concern SQLAlchemy DISTINCT ON deprecation. All start/end Python hashes
match. This run includes the root-rewrap cancellation API from the preceding
checkpoint as well as the new planner. The separate fresh-cluster and pinned
Smolink harnesses were not rerun for this read-only slice.

Initial controls found the missing API. The first implementation passes 84 cases.
Review then reproduces three boolean estimate-counter acceptances and a lease
expiry mislabeled as a policy change. Explicit supplied-counter validation and
preserved `KeyUnavailable` classification close those defects. Full regression
also covers current-value edits, text/VARCHAR, provider/data/inventory failures,
RNG failure and unrepresentable estimates. Afterward, a test-only strengthening
supplies a matching preparation pin to the application executor. Its native
control passes and refuses preparation as publication authority before connection.
Product source is unchanged from the full run.

The wheel and sdist build reproducibly without network access. The installed-wheel
check matches all 33 packaged files, starts its CLI under a fresh bytecode cache,
and inspects the genesis manifest. Dependency installation remains outside this
check. Current release source hashes match the artifact receipt.

At this planning checkpoint, staged execution, paired sealing, final cutover and
cancellation remain SPECIFIED. The later [staging checkpoint](#payload-staging-and-cancellation-checkpoint-2026-10-23)
adds preparation and cancellation. The preparation cannot enter the application publication executor.
The [two-artifact decision](decisions.md#payload-rotation-preparation-and-activation-2026-10-23)
requires actual verified target observations in a separate immutable activation
artifact before destructive switch. No journal result hash supplies authority.
Search rotation, adopted-restore rotation, production custody and independent
review remain open. All seven production gates remain UNKNOWN.

Evidence: [initial controls](_reset/payload-plan-red-20261023.json),
[first implementation](_reset/payload-plan-first-20261023.json),
[counter review](_reset/payload-plan-review-red-20261023.json),
[lease control](_reset/payload-plan-lease-red-20261023.json),
[focused native run](_reset/payload-plan-focused-20261023.json),
[full regression](_reset/payload-plan-full-20261023.json),
[final publication refusal](_reset/payload-plan-final-admission-20261023.json),
[offline protocol](_reset/payload-plan-offline-20261023.json), and
[installed wheel](_reset/payload-plan-installed-wheel-20261023.json).

## Pending rewrap cancellation checkpoint: 2026-10-23

**IMPLEMENTED, bounded native verification:** `rotation.abort_rewrap` cancels
an exact PENDING successor under the republished source ACTIVE pin. The source
pin supplies host authority. The deterministic successor selects shared executor
locks, target/owner checks and the current verification estimate. Cancellation
does not repeat historical protection work or require target-provider access.

Under maintenance locks, cancellation checks exact source/successor digests and
lineage, original source state, source policy and retained roots, current frames,
membership, schema and guards. Source ACTIVE, guard removal and a retained
ABORTED successor marker commit together. A terminal retry checks current source
authority and leaves later application edits intact. A later operation that
supersedes the source prevents an old retry from reviving it.
Use the source plan and its current pin for read-only status. The canceled
successor cannot activate. Generic protection abort remains a pre-switch operation.

**VERIFIED:** all 18 initial cancellation cases pass. The expanded native run
passes **177 cases** in 118.36 seconds across cancellation, cutover/planning,
protection, reverse/removal and multi-table protection. Controls cover target
outage, source outage, wrong keys/pins/approval, digest/link/guard/schema/frame
and membership tampering, unknown operations, current pause admission, wrong
native target before key access, and transaction rollback after guard removal.
An actual proxy loses the terminal cancellation COMMIT reply. Inspection and
retry retain the committed terminal state. A process dies after committed
cancellation; an independent process reloads disk artifacts and resumes without
target custody. Frame bytes and equality-index identity remain unchanged.
A second rewrap can be canceled after application edits, then decrypt-back and
approved removal recover the latest native values.

After one additional multi-table/multi-tenant control, all **52 cancellation and
cutover cases** pass in 38.39 seconds. The control rejects writes on both paused
tables, then releases their shared guard function atomically. It preserves all
three protected fields and independently decodes their public-fixture frames.
Attached source-policy reads match both tenant datasets after cancellation.
Product source is unchanged from the expanded run. The final receipt retains
matching Python hashes.

Initial controls failed because the API was absent. Review found a conservative
pause refusal against historical protection estimates. Cancellation now uses the
successor estimate after separate source-authority admission. One expanded
invocation named a nonexistent test module and ran no tests. The corrected run
above passes with matching start/end Python hashes.

The updated wheel and sdist build reproducibly without network access. The
installed-wheel check matches all 33 packaged files and starts its CLI under a
fresh bytecode cache. Dependency installation remains outside that check.
The full 1,647-test suite and text/VARCHAR fresh-cluster drills below precede
this additive cancellation API. They were not repeated for this slice.
Adopted-restore rewrap/cancellation, payload rotation, search reindex, production
provider/host authority qualification and independent review remain open.
All seven production gates remain UNKNOWN.

Evidence: [initial controls](_reset/rewrap-abort-red-20261023.json),
[first implementation](_reset/rewrap-abort-first-20261023.json),
[invalid test path](_reset/rewrap-abort-focused-20261023.json),
[expanded native run](_reset/rewrap-abort-focused-corrected-20261023.json),
[final cancellation/cutover run](_reset/rewrap-abort-final-20261023.json), and
[installed wheel](_reset/rewrap-abort-installed-wheel-20261023.json).

## Active root-rewrap checkpoint: 2026-10-23

**IMPLEMENTED, bounded native verification:** a rewrap proposal now derives a
deterministic `cryptalis.transition/v2` successor plan. `apply_rewrap` uses the
existing maintenance executor, locks and writer guards. It rechecks current
source policy, schema, journal and complete source/target frame observations.
One transaction preserves payload/search bytes, creates a successor PENDING row
and marks the old immutable operation SUPERSEDED. No key or wrapper bytes enter
PostgreSQL. Both complete policies remain host-owned recovery artifacts.

The host publishes the successor separately. Existing `migration.apply` with
an ACTIVATING pin authenticates the target and compares host-pinned observations
before dropping guards. An already-ACTIVE journal claim also undergoes that check
on an ACTIVATING retry. True ACTIVE pins allow later ordinary application edits.
Runtime and reverse/removal admit only the exact host-pinned predecessor chain.
Known ancestors are removed only through the existing approved removal path.

**VERIFIED so far:** 165 focused lifecycle cases pass. The expanded native
recovery/planner run passes 60 cases, including unchanged frames, native search
and edits, two custody changes followed by latest-value decrypt-back/removal,
wrong policy/pin/approval, altered source/journal, malformed successor artifacts,
predecessor tampering, and false journal ACTIVE claims. An actual local transport
proxy discards a terminal COMMIT reply. Inspection then resumes the same pending
operation without changing frames. A process is killed after committed pending
progress; an independently started process reloads disk artifacts and public
fixture keys, inspects, resumes and activates. Frame bytes and equality-index
OID/relfilenode remain unchanged in that restart control.

The first execution run found a callable-only test helper. Review controls then
reproduced a journal-claim bypass and raw invalid-input errors. Admission now
precedes dispatch, and publication retry verifies host observations.
The source review found no additional concrete defect in that pass. AI review
supplies no independent security qualification.

**VERIFIED, local Python 3.12.3 / SQLAlchemy 2.1.3 cell:** full regression passes
**1,647 tests and 18 subtests**, with three separate-environment skips, in
300.23 seconds. The wrapper counts subtests with passed cases. The 48 existing
warnings concern SQLAlchemy DISTINCT ON deprecation. All start/end Python hashes match.

After that run, fresh-cluster profile checks gained explicit manifest/successor
admission and a negative original-policy adoption control. Product source did
not change. Each rewrapped source type, text and VARCHAR, then passes one export
and 15 restore cases on a new PostgreSQL 16 cluster. These cover retained-frame
recovery, exact target-policy admission, stale authority refusal, approved adoption,
latest-value decrypt-back/removal, and native metadata. The original public-root
oracle remains independent of the target-policy factory. Profile labels alone
cannot satisfy successor admission. Both runs retain matching Python hashes.
The separate pinned Smolink harness was not rerun for this slice.

The wheel and sdist build reproducibly without network access. The disposable
installed-wheel check matches all 33 packaged files, imports verified source
under a fresh bytecode cache, starts the CLI and inspects the genesis manifest.
Installation used `--no-deps` and does not qualify dependency installation.

At this checkpoint, pre-publication rewrap abort, rewrap on an adopted restored target, payload
rotation, search reindex, production provider qualification and independent
review remained open. The later cancellation checkpoint above closes the bounded
pending-abort gap. Host writer exclusion and publication remain operator
assertions. The rotation build slice is incomplete. All seven gates remain UNKNOWN.

Evidence: [initial acceptance](_reset/rewrap-execution-red-20261023.json),
[first implementation](_reset/rewrap-execution-first-20261023.json),
[review controls](_reset/rewrap-execution-review-red-20261023.json),
[focused lifecycle](_reset/rewrap-execution-focused-20261023.json), and
[process/transport recovery](_reset/rewrap-execution-recovery-20261023.json),
[full regression](_reset/rewrap-execution-full-20261023.json),
[text backup recovery](_reset/fresh-cluster-restore-20261023.json),
[VARCHAR backup recovery](_reset/fresh-cluster-restore-20261023-2.json), and
[installed wheel](_reset/rewrap-execution-installed-wheel-20261023.json).

## Development environment recovery: 2026-10-23

**VERIFIED:** the default sandbox denies IPv4 socket creation with errno 1 and
mounts `.git` read-only. Both private test files are present, parse correctly,
and have mode `0600`. The user authorized environment repair and supported
scoped execution approval. That path passes a temporary Git write/read/delete
check and both private-role PostgreSQL probes. No credential, service, database,
ownership, mount, or sandbox-policy change was needed. The failed operation
was not repeated under the unchanged execution boundary.

`scripts/test_postgres.py --development-preflight` now diagnoses Git writes,
dependencies, tools, private test-file provenance, socket creation, PostgreSQL
16, same-target role separation, and observed privileges. It uses read-only
database transactions, runs no pytest test, and never prints connection values
or raw exceptions. Runtime must lack database CREATE, cannot assume the owner,
and cannot own application schemas or relations. PostgreSQL tool discovery checks
actual major versions. Missing separate-harness tools remain UNKNOWN.
Target authorization remains UNKNOWN: file provenance and successful probes
cannot establish that an operator authorized a database as disposable.

**VERIFIED:** the [default-sandbox diagnostic](_reset/development-preflight-sandbox-final-20261023.json)
reports Git and socket failures as `authorized_alternative`, before database access.
The [approved diagnostic](_reset/development-preflight-approved-final-20261023.json)
reports all observed prerequisites PASS. Other diagnostics classify automatically
repairable tool discovery, external prerequisites, and implementation defects.
The [engineering procedure](../ENGINEERING_PLAYBOOK.md#development-environment-checks)
states the invocation and approval boundary.

Initial controls found the missing diagnostic mode. A first combined run then
found that in-process CLI tests cleared the outer runner's admitted URLs.
The tests now restore those environment values. A later controlled CREATE
observation exposed a false acceptance. The final gate rejects it without any
native grant change. Failed controls remain separate from successful evidence.

**VERIFIED, local Python 3.12.3 / SQLAlchemy 2.1.3 cell:** the full suite passes
**1,620 tests and 18 subtests**, with three separate-environment skips, in
314.88 seconds. Its wrapper count includes the 18 subtests. The 48 existing
warnings concern SQLAlchemy DISTINCT ON deprecation. After the final
diagnostic-only CREATE guard and tool-discovery classification, **76 focused
checks pass** in 17.24 seconds, including native rewrap/provider and source-evidence
regression. Both runs retain matching start/end Python hashes.
The full suite was not repeated after that final diagnostic-only change.
Fresh-cluster and pinned Smolink harnesses were not rerun in this step.

Git integrity checks pass. Existing dangling objects were left untouched.
The planner and offline-test files retain their original checkpoint hashes.
The native planner tests changed only to use the documented `KeyUnavailable`
diagnostic. The original branch, HEAD ancestry, prior commits and receipts remain
preserved. Ordinary reads still use the default sandbox. Required Git writes
and PostgreSQL verification use the scoped approved execution path.
All seven production gates remain UNKNOWN.

Evidence: [initial mode controls](_reset/development-preflight-red-20261023.json),
[test-isolation failure](_reset/development-preflight-focused-20261023.json),
[runtime CREATE control](_reset/development-runtime-create-red-20261023.json),
[full suite](_reset/environment-rewrap-full-20261023.json), and
[final focused run](_reset/development-preflight-final-20261023.json).

## Inactive rewrap planning checkpoint: 2026-10-23

**IMPLEMENTED, VERIFIED in the named local cell:** `cryptalis.rotation.plan_rewrap`
creates an inactive `RewrapPlan` for an ACTIVE protection plan. It inspects the
host pin, native target, journal and protected schema in one read-only
repeatable-read transaction. It compares exact source and target roots,
including historical readers and tenants with no remaining rows, then
authenticates current frames under both policies. The artifact contains policy,
membership, frame and schema digests, public contexts, required readers and a
host-measured verification estimate. It contains no root or wrapper bytes.

Planning changes neither database state nor current publication authority.
Current writers can continue. Observations describe one snapshot and cannot
authorize a later switch. Execution must recheck current data and host policy
under maintenance. Structural artifact validation does not authenticate host
inputs or reconstruct root identities from an opaque source-policy digest.

**VERIFIED:** all 35 native planner cases pass within the 55-case planner/provider
run and the later full and focused suites above. Cases cover ordinary application
edits, concurrent commits during the snapshot, retained roots, deleted tenants,
missing/wrong roots, pin/journal/schema/frame mutations, malformed artifacts,
invalid rates, cleanup-time expiry and random-ID failure. Refusals preserve
native source state and suppress private provider/error markers.
The first native run found seven diagnostic-spelling mismatches in the tests.
The tests now expect the existing security-contract code `KeyUnavailable`.

Five standalone offline protocol groups also pass. The local wheel installs
without network access into a disposable Python environment, matches all 33
installed files against the archive, starts the CLI with a fresh bytecode cache,
and inspects the supplied genesis manifest. Repeat builds match.
Installation used `--no-deps` and does not qualify dependency installation.

Earlier default-sandbox probes stopped before pytest. Their blocker is resolved
through the approved path above. The original collection-only and offline
receipts remain historical evidence. This checkpoint covered inactive planning.
The [later execution checkpoint](#active-root-rewrap-checkpoint-2026-10-23)
adds successor cutover and shared activation. Payload rotation and search reindex
remain unimplemented.
The rotation build slice remains incomplete. All seven full gates remain UNKNOWN.

Evidence: [first native run](_reset/rewrap-plan-native-first-20261023.json),
[planner/provider run](_reset/rewrap-plan-native-green-20261023.json),
[offline checkpoint](_reset/rewrap-plan-offline-final-20261023.json), and
[installed artifact](_reset/rewrap-plan-installed-wheel-20261023.json).

## Numeric API admission: 2026-10-22

**IMPLEMENTED:** protection and reverse planners share safe numeric input and
duration checks. Integers that overflow float conversion fail as invalid measured
rates or invalid maintenance approval. A positive finite rate that produces an
infinite or unrepresentable duration fails with `unrepresentable_pause_estimate`.
Estimated seconds must fit the canonical integer range before artifact creation.

The change preserves fractional rates and separate backfill, verification, and
combined pause estimates. It adds no rate floor or substitute estimate.
An invalid maintenance approval fails before a transition starts.

**VERIFIED, initial controls:** ten native public API cases reproduced raw
`OverflowError`. They cover both rate fields in both planners, minimum positive
float rates, huge integer rates, and huge maintenance pauses in both executors.
Catalog facts, rows, journal inventory, schema relations, and function definitions
stay unchanged during these failures. Twelve existing rate controls pass.

**VERIFIED, corrected controls:** all 119 focused native tests pass in 63.15 seconds.
They include the ten refusals, fractional-rate artifact reload and both complete
transitions, artifact admission, crash/resume, protection, and reverse controls.
All 97 Python files retain their start/end hashes. The wheel and sdist build
reproducibly; the installed-wheel check matches 32 files and starts the CLI.

The full suite and fresh-cluster checks were not repeated for this input-only
change. Their evidence in the next section belongs to the preceding restore-policy
revision.
All seven production gates remain UNKNOWN.

Evidence: [initial controls](_reset/numeric-admission-red-20261022.json),
[corrected controls](_reset/numeric-admission-focused-20261022.json), and
[installed wheel](_reset/numeric-admission-release-installed-20261022.json).

## Restore frame policy admission: 2026-10-22

**IMPLEMENTED:** restore adoption accepts two exact PostgreSQL 16 forms of the
declared CF1 frame check. Both forms use the same length bounds, header bytes,
generation rules, and quoted column. The shared storage check refuses any other
admitted expression. Malformed-frame probes remain additional evidence.
They cannot establish general SQL equivalence.

Binding identity checks also compare every recorded restatement with its source
field and known forms. This applies when a reverse plan embeds a restore binding.
An older binding with weaker bounds cannot supply policy authority.
Constraint comparison uses schema, table, and name so an incoming foreign key
cannot hide a declared frame CHECK with the same name.

**VERIFIED, initial fault reproduction:** the native isolated-cluster run passes
ten existing controls and reproduces four false acceptances. Lowering the minimum
frame length by one or raising the maximum by one still passed the finite probes.
Adoption issued a binding, and a matching older binding passed deployment checks.
The source journal and retained values stayed unchanged in these controls.
The same run records the exact flattened PostgreSQL expression used by the fix.

Evidence: [initial export](_reset/fresh-cluster-export-20261022-26.json) and
[initial restore controls](_reset/fresh-cluster-restore-20261022-26.json).

**VERIFIED, corrected local controls:** 172 native storage and lifecycle tests pass.
Both text and VARCHAR fresh-cluster paths pass one export and 15 restore cases.
These include the four refusals, the valid same-name foreign key, and the full
adopted attach/search/edit/decrypt-back/removal path. The native restored expression
matches the known flattened form exactly. Journal and row snapshots stay unchanged
on refusal. The pinned Smolink lifecycle also passes in its existing alternate
Python 3.13 / SQLAlchemy 2.0.51 cell.

The wheel and sdist build reproducibly. The installed-wheel check matches 32 files
and starts the CLI. No new dependency, artifact format, provider, or publication
authority is introduced.

The [full native suite](_reset/frame-policy-full-sa21-20261022.json) passes
**1,567 tests and 18 subtests**, with three separate-environment skips and
48 existing SQLAlchemy warnings. All 97 Python files retain their start/end
hashes. The wrapper records 279.31 seconds in the unchanged local dependency cell.
All seven production gates remain UNKNOWN.

Evidence: [focused controls](_reset/frame-policy-focused-20261022.json),
[text restore](_reset/fresh-cluster-restore-20261022-27.json),
[VARCHAR restore](_reset/fresh-cluster-restore-20261022-28.json),
[Smolink](_reset/frame-policy-smolink-sa20-20261022.json), and
[installed wheel](_reset/frame-policy-release-installed-20261022.json).

## Host plan input admission: 2026-10-22

**IMPLEMENTED:** protection artifacts now pass compiler lock admission before
use. This check uses PostgreSQL identifier quoting without opening a connection.
Compiler root, model, and field members use explicit canonical sets.
Required row and pause estimates must be nonnegative integers; booleans are refused.
Display limits must be nonempty text. Measured rates, when present, must form
a complete positive finite pair. Historical protection artifacts may omit both rates.

Reverse artifacts require a mapping of table IDs to catalog snapshots.
They reuse the compiler's catalog structure checks for relation, columns,
constraints, indexes, and dependencies. Recorded column names must match the
source model. Estimate checks also run before reverse maintenance admission.
Live catalog and host-policy checks remain separate.

**VERIFIED:** the initial run reproduced 14 failures and passed two controls.
The first corrected run passes 138 tests. The final focused run passes 64,
including 24 plan-admission controls. Empty compiler locks and model inventories,
malformed catalog containers and scalar types, missing estimates, unknown compiler
members, and invalid pause values now fail during artifact construction.
Valid v1/v2 artifacts with no measured rates retain their bytes, legacy display,
and public PREPARED status. Ordinary valid protection and reverse reloads also pass.

The first full run passed 1,564 tests and 18 subtests, with three failures in
VARCHAR controls that expected rejection during apply. They now expect constructor
rejection and retain their original native PREPARED-state check.
That correction changes tests only. All 64 VARCHAR and admission checks pass.

The [final full native suite](_reset/plan-admission-full-final-sa21-20261022.json)
passes **1,567 tests and 18 subtests**, with three separate-environment skips
and 48 existing SQLAlchemy warnings. All 97 Python files retain their start/end
hashes. The wrapper records 319.37 seconds in the unchanged local dependency cell.

An initial native control demonstrated vacuous ACTIVE metadata acceptance with
an empty model inventory, a matching changed host pin, and a changed journal digest.
This required coordinated malformed host input; it was not a database-only bypass.
The constructor now rejects that artifact before the journal can change.
CLI controls use an unreachable database address and receive exit 2,
`InvalidInput`, at the input stage. No private marker or traceback appears.
Previously those calls attempted connection and returned operational exit 4.

The final pinned Smolink lifecycle passes in its existing alternate Python 3.13 /
SQLAlchemy 2.0.51 cell. Both final fresh-cluster paths pass one export and ten
restore cases. The reproducible wheel and sdist retain the current product bytes;
the installed-wheel check matches 32 files and starts the CLI.

This admission check validates artifact structure and selected compiler invariants.
It does not authenticate the host, validate values, qualify providers, or establish
writer exclusion. All seven production gates remain UNKNOWN.

Evidence: [initial controls](_reset/plan-admission-red-20261022.json),
[first focused run](_reset/plan-admission-focused-20261022.json), and
[final controls](_reset/plan-admission-final-focused-20261022.json).
Further evidence: [VARCHAR controls](_reset/plan-admission-varchar-final-20261022.json),
[Smolink](_reset/plan-admission-final-smolink-sa20-20261022.json),
[VARCHAR restore](_reset/fresh-cluster-restore-20261022-24.json),
[text restore](_reset/fresh-cluster-restore-20261022-25.json), and
[installed wheel](_reset/plan-admission-release-installed-20261022.json).

## Host-bound staged schema: 2026-10-22

**IMPLEMENTED:** paused protection and reverse operations now compare staged
catalog facts with host artifacts as well as their journal snapshots.
The validated plan kind selects the transformation. No new artifact format,
publication authority, key policy, or plaintext fallback is introduced.

Protection retains the native columns, constraints, indexes, and dependencies
from the source lock. It adds the declared nullable bytea shadows and checks
their CF1 frame constraints and equality indexes against the physical shadow names.
Reverse inspection uses the protected catalog snapshot in the host-pinned
reverse plan, captured after source admission. It adds only the declared nullable
plaintext staging columns, with native type limits and collation from the source lock.
Logical comparison permits different physical column slots.

**VERIFIED:** 24 initial native controls reproduced false acceptance.
The correction passes 175 focused tests. The attacks cover extra columns,
native type and constraint changes, missing indexes, shadow and staging defaults,
nullability and type changes, weaker frame checks, changed equality expressions,
index ordering and uniqueness, and a reverse VARCHAR(64) stage changed to VARCHAR(63).
The valid writer fence remains unchanged while each test forges the matching
journal schema. Status, backfill, verification, and abort refuse the change.
Journal state, counters, catalog, guard, and row values remain unchanged on refusal.

The [full native suite](_reset/paused-schema-full-sa21-20261022.json) passes
**1,543 tests and 18 subtests**, with three separate-environment skips and
48 existing SQLAlchemy warnings. All 96 Python files retain their start/end
hashes. The wrapper records 278.15 seconds; the local dependency cell is unchanged.
Both fresh-cluster paths pass one export and ten restore cases. The pinned
Smolink lifecycle passes in its existing alternate Python 3.13 / SQLAlchemy 2.0.51 cell.
The wheel and sdist build reproducibly. The installed-wheel check matches 32 files
against the wheel and starts the CLI.

The reverse baseline is a host-pinned snapshot, not database authority.
The later [input admission slice](#host-plan-input-admission-2026-10-22) adds
shared catalog structure checks. Structural validity does not establish live semantics.
The check covers recorded catalog facts. It does not establish value verification,
unchanged external function bodies, freshness, or host writer exclusion.
All seven production gates remain UNKNOWN.

Evidence: [initial controls](_reset/paused-schema-red-20261022.json),
[focused checks](_reset/paused-schema-focused-20261022.json),
[Smolink](_reset/paused-schema-smolink-sa20-20261022.json),
[VARCHAR restore](_reset/fresh-cluster-restore-20261022-20.json),
[text restore](_reset/fresh-cluster-restore-20261022-21.json), and
[installed wheel](_reset/paused-schema-release-installed-20261022.json).

## Host-bound paused writer fence: 2026-10-22

**IMPLEMENTED:** every paused protection and reverse inspection now checks the
writer fence against the host plan. The shared check also runs before plaintext
publication. It requires the operation's expected function body, invoker security,
owner, search path, enabled statement trigger, and absence of extra user triggers.
The journal's guard snapshot remains an additional continuity check.
It cannot authorize a different function or trigger inventory.

**VERIFIED:** 18 initial controls reproduced false acceptance. Two protection
resumes committed PENDING before the previous final check detected the change.
The correction moves admission before backfill, verification, switch, abort,
status, and plaintext publication. All 22 adversarial cases now pass.
Each case first observes SQLSTATE `55000` from the restricted runtime login.
It then replaces the guard body or enables `SECURITY DEFINER` and forges the
matching journal snapshot. The damaged guard admits an actual UPDATE.
The probe write rolls back. The refused operation preserves journal state,
counters, catalog, guard, and row values, including staging columns.

Two revised fault controls also pass. A native row lock stops the second chunk
after its first update; the test kills the worker and checks rollback before
an independent process resumes. A journal trigger suppresses the marker update;
the typed `journal_marker_write_failed` failure leaves zero committed rows,
chunks, and frames. These controls replace application-trigger injections that
the stricter fence admission now refuses.

The pinned Smolink lifecycle passes in its existing alternate Python 3.13 /
SQLAlchemy 2.0.51 cell. Both fresh-cluster paths pass one export and ten restore
cases. The wheel and sdist build reproducibly; the installed-wheel check matches
32 files against the wheel and starts the CLI.

The [full native suite](_reset/paused-guard-full-sa21-20261022.json) passes
**1,519 tests and 18 subtests**, with three separate-environment skips and
48 existing SQLAlchemy warnings. The wrapper records 255.69 seconds.
All 95 Python files retain their start/end hashes. The local dependency cell
is unchanged. Independent release and provider qualification remain UNKNOWN.

This check does not establish host writer exclusion or protect against an
authorized owner changing the database after inspection. Staged schema admission
is separate; the later [staged schema slice](#host-bound-staged-schema-2026-10-22)
adds that host check. All seven production gates remain UNKNOWN.

Evidence: [initial controls](_reset/paused-guard-red-20261022.json),
[first integration run](_reset/paused-guard-focused-20261022.json), and
[24 final controls](_reset/paused-guard-final-focused-20261022.json).
Further evidence: [Smolink](_reset/paused-guard-smolink-sa20-20261022.json),
[VARCHAR restore](_reset/fresh-cluster-restore-20261022-18.json),
[text restore](_reset/fresh-cluster-restore-20261022-19.json), and
[installed wheel](_reset/paused-guard-release-installed-20261022.json).

## Host-bound protected schema: 2026-10-22

**IMPLEMENTED:** protection status, deployment checks, attachment, activation,
and reverse planning now check the live protected catalog against the host's
source lock and the declared CF1 transformation. A database journal can no
longer redefine that contract by recording the same unauthorized schema change.
No new authority artifact or format is introduced.

The shared check retains unchanged native columns, constraints, indexes,
and dependencies from the lock. It verifies protected bytea columns, validated
frame checks for storage and search, and the declared equality index expression,
uniqueness, flags, opclasses, collation, and sort options.
PENDING also requires the host-derived pause function, enabled trigger,
and absence of extra user triggers. Native constraints with equal names on
different tables remain distinct. Logical column slots may change on restore.

Restore adoption uses the same host check. A changed live frame check that
matches a forged journal receives no automatic exception. Existing explicit
CHECK restatements still require the adoption probes and exact binding match.
Catalog deparsing uses a shared temporary search path and restores the caller's
setting. A SQL failure retains its original error for caller rollback.

**VERIFIED:** the initial 14 native controls reproduced false acceptance.
The corrected lifecycle run passes 89 tests. The expanded run passes 219 tests,
including 38 host-contract controls for altered native metadata, weakened frame
checks, changed equality expressions, ordering and uniqueness, rewritten or
disabled pause functions, and additional triggers. Each attack changes the
catalog and its journal snapshot together.

The pinned Smolink lifecycle also passes in its existing alternate Python 3.13 /
SQLAlchemy 2.0.51 cell. Both fresh-cluster paths pass one export and ten restore
cases, including three new pre-adoption forgery controls. Existing retained-frame
reads, admitted CHECK restatements, decrypt-back, metadata restoration, removal,
and native writes pass on each new cluster.

The [full native suite](_reset/active-contract-full-sa21-20261022.json) passes
**1,497 tests and 18 subtests**, with three separate-environment skips and
48 existing SQLAlchemy warnings. All 94 Python files retain their start/end
hashes; the wrapper records 248.70 seconds. The local dependency cell is unchanged.
The wheel and sdist build reproducibly. The installed-wheel check verifies
32 files against the wheel and starts the CLI. These are local release checks;
signing, publication, and independent rebuild remain UNKNOWN.

This check binds the catalog properties recorded by the source lock and the
declared CF1 storage objects. It does not prove unchanged bodies of external
functions, domain definitions, or collation implementations. Generated index
tablespaces and storage options are outside this check. Status still performs
no key or value verification. Writer exclusion, freshness, provider qualification,
and independent review remain separate requirements. All seven gates remain UNKNOWN.

Evidence: [initial controls](_reset/active-contract-red-20261022.json),
[focused checks](_reset/active-contract-adversarial-20261022.json),
[Smolink](_reset/active-contract-smolink-sa20-20261022.json),
[VARCHAR restore](_reset/fresh-cluster-restore-20261022-16.json),
[text restore](_reset/fresh-cluster-restore-20261022-17.json), and
[installed wheel](_reset/active-contract-release-installed-20261022.json).

## Verification source stability: 2026-10-22

**IMPLEMENTED:** the PostgreSQL test wrapper now captures Python source hashes
before pytest and compares them with a second snapshot after pytest.
It resolves the checkout from its own file and runs pytest in that checkout.
The starting revision and source hashes identify the input bundle.
Previously, the receipt recorded only the final files.
A source edit during tests could therefore describe bytes that the run did not load.

Different start/end bytes, added files, or removed files force wrapper exit 4.
This check also applies when no receipt is requested.
The receipt retains the original `pytest_exit_code`, the wrapper `exit_code`,
starting `source_test_sha256`, and a `source_stability` result with changed paths.
`source_after_sha256` records only changed paths. A removed file has a null hash.
Unchanged sources preserve the original pytest exit code.
Unreadable source produces an explicit failure without raw filesystem diagnostics.
Both private credential files still reload and both database roles still probe first.
No failed database probe is retried.

**VERIFIED:** eight initial controls failed. The corrected focused run passes
12 wrapper controls and ten real reverse-status CLI tests.
The wrapper controls use disposable source trees and controlled inner pytest results.
They check successful and failed pytest outcomes, no-receipt runs, additions,
removals, and equal-size edits that retain the original modification time.
These controlled outcomes do not establish application correctness.
The following real CLI cases also pass, which checks fixture environment cleanup.

The snapshot covers Python files under `src/cryptalis`, `tests`, and `scripts`.
It compares two observations. It does not detect an edit that is restored between them.
Keep the checkout stable during verification. Dependencies, interpreter state,
configuration, and human review remain separate evidence boundaries.
Historical receipts remain immutable and predate this stability check.
All seven production gates remain UNKNOWN.

Evidence: [RED controls](_reset/evidence-stability-red-20261022.json) and [focused verification](_reset/evidence-stability-final-focused-20261022.json).

The [pinned Smolink rerun](_reset/evidence-stability-smolink-sa20-20261022.json)
also passes after the shared plaintext-metadata correction. It retains the
alternate Python 3.13 / SQLAlchemy 2.0.51 scope and the unchanged 38-file app snapshot.
Both [VARCHAR](_reset/fresh-cluster-restore-20261022-14.json) and
[text](_reset/fresh-cluster-restore-20261022-15.json) fresh-cluster paths pass
one export and seven restore cases. Each new receipt records unchanged start/end
source hashes. The existing product release bytes remain unchanged by this
wrapper-only slice. No dependency or provider qualification is added.

The [full native run](_reset/evidence-stability-full-sa21-20261022.json) passes
**1,459 tests and 18 subtests**, with three separate-environment skips and
48 existing SQLAlchemy warnings. The wrapper records 238.73 seconds.
Its receipt reports identical start/end hashes for all 93 Python files,
`pytest_exit_code: 0`, and `exit_code: 0`. The exact local dependency cell
remains Python 3.12.3, SQLAlchemy 2.1.3, psycopg 3.3.6, and cryptography 50.0.2.

## Read-only reverse status: 2026-10-22

**IMPLEMENTED:** `cryptalis status` now accepts a `cryptalis.reverse/v1` plan.
The Python API is `cryptalis.deprotection.status(plan, engine, pin=pin)`.
The existing protection status behavior remains available.
Reverse output uses `scope: reverse_transition` and includes the source operation ID.

The API reads one PostgreSQL read-only, repeatable-read snapshot.
It checks the target, supplied reverse pin, source journal identity, operation
inventory, phase, committed counters, schema, and writer fence.
Before the plaintext switch, it checks the protected source or paused schema.
After that switch, it checks native plaintext metadata and captured column metadata.
The restored-target path uses the binding already embedded in the reverse plan.
An additional CLI binding must match that embedded binding exactly.

The output retains `verification: NOT_PERFORMED`, `authority: HOST_SUPPLIED_PIN`,
and `effects: NONE`. No key resolver or maintenance consent is required.
Status neither decrypts data nor changes publication policy.
Exit 0 requires metadata that matches the supplied `PLAINTEXT_ACTIVE` or `REMOVED` pin.
Other phases remain incomplete. Existing input, uncertainty, and operational exit
classes remain 2, 3, and 4.

After removal, the journal is absent. Status reports null counters in JSON
and UNKNOWN counters in text. It does not substitute zero or a plan estimate.
It checks the native schema and captured metadata before reporting REMOVED.
A missing journal under an earlier pin remains an explicit failure.
A false removed pin over protected tables also fails.

**VERIFIED, local PostgreSQL 16:** the focused status, CLI, protection, and reverse
run passes 81 tests. The additional adversarial run passes 41 tests.
The native controls cover all reverse phases, aborted work, terminal removal,
concurrent commits, malformed progress, source/pin mismatch, schema and comment
drift, disabled guards, and safe connection, cleanup, and output failures.
A real write attempt receives SQLSTATE 25006 in the status transaction.
The snapshot test sees the old committed prefix while another executor advances.
The next status call sees the new committed prefix.

The RED controls first showed the missing API and CLI rejection of reverse plans.
An initial test listener intercepted executor setup. The corrected listener
isolates the status transaction. Missing evidence never becomes a successful status.
A later negative control changed both the plaintext schema and its journal copy.
It first produced a false match. Shared plaintext inspection now compares the
native schema with the original host lock, checks the exact enabled guard,
and checks captured metadata. Status, activation, and removal use that same check.
Three removal regressions exposed a changed error code. The correction preserves
`metadata_not_restored:source_metadata` and the existing journal-retention behavior.
No fresh value verification, retained-backup disposition, key/provider qualification,
or deployment-wide writer exclusion follows from metadata inspection.
All seven full gates remain UNKNOWN.

Evidence: [focused](_reset/reverse-status-green-20261022.json), [adversarial](_reset/reverse-status-adversarial-20261022.json), and [CLI RED](_reset/reverse-status-cli-red-20261022.json).
The [final metadata controls](_reset/reverse-status-metadata-final-20261022.json) pass seven cases,
including the [forged-journal negative control](_reset/reverse-status-journal-red-20261022.json).
Fresh PostgreSQL 16 clusters each pass one export and seven restore cases:
[VARCHAR](_reset/fresh-cluster-restore-20261022-12.json) and
[historical text](_reset/fresh-cluster-restore-20261022-13.json).
Those runs observe reverse PREPARED, PLAINTEXT_PENDING, PLAINTEXT_ACTIVE, and
REMOVED through the embedded adoption binding.
The [final release check](_reset/reverse-status-release-installed-final-20261022.json)
passes repeat-build identity, archive and SBOM checks, 32 installed-file comparisons,
and isolated CLI startup. Installation uses `--no-deps`; runtime dependency
qualification remains separate.


The [final full suite](_reset/reverse-status-full-sa21-20261022-2.json) passes
**1,447 tests and 18 subtests**, with three separate-environment skips and
48 existing SQLAlchemy warnings. The wrapper records 244.89 seconds.
All 92 source/test hashes match the final worktree. The exact local cell uses
Python 3.12.3, SQLAlchemy 2.1.3, psycopg 3.3.6, and cryptography 50.0.2.
The skipped external-app and fresh-cluster modules retain their separate evidence.
The external Smolink suite was not rerun for this status slice.
No production provider, host publication system, or independent review is qualified.

## Pinned Smolink adoption: 2026-10-22

**VERIFIED, bounded:** Smolink revision `498d24bae999ed53ad85e1c1f1a09ea7fa151aa4`
completes a native, protected, and post-removal workload on PostgreSQL 16.
The test extracts 38 Python files with local Git. It checks their hashes and
import origins. It changes no application source, model declaration, or query.
The original FastAPI app supplies the URL endpoint, authentication dependency,
service, repositories, Snowflake IDs, and response validation.
HTTP checks cover URL creation, duplicates, invalid authentication, invalid
aliases, expired URLs, invalid input, and real Redis rate-limit refusal.
Repository and ORM calls cover reads, current-value updates, deletion, and refresh.

Only `Url.destination` is protected. The profile uses storage-only VARCHAR(2048)
and an explicit single-tenant declaration. `owner_id` remains application data.
The test does not infer authorization or tenant scope from that foreign key.
Protected cursor parameters contain no destination marker. Native database
reads find CF1 frames. Decrypt-back retains the latest destination and restores
the native character limit. A fresh process runs the original app again with
all Cryptalis imports denied.

Adoption requires a manifest, key resolver, writer inventory, maintenance
approval, deployment pins, and a replacement session dependency.
The test also uses a private schema through connection settings, public test
settings, a seeded verified user, and disposable Redis through a Unix socket.
No external key custody or deployment-wide writer exclusion is established.
Email search, password-hash protection, other endpoints, the complete application
suite, a second external app, and packaged Python 3.13 installation remain open.

The run exposed two product defects. Catalog definition digests depended on
the caller's search path. Catalog reads now use the compiler's canonical
`pg_catalog` path and restore the caller's setting. Database failures retain
their primary SQLSTATE and require rollback. A real division-by-zero control
checks the original error and the restored path after rollback.
Attachment also clears each protected mapper's flush cache. The engine cache
alone did not remove INSERT and UPDATE processors compiled before attachment.
Both native and external controls first failed, then passed after this change.
The first full run found eight read-only route assertions. Canonical reads now
use SELECT-based setting functions, so those strict assertions remain unchanged.
The mapper cache is a private SQLAlchemy dependency. Keep its regression when
upgrading SQLAlchemy.

Two external cells pass: Python 3.13.12 with FastAPI 0.139.0 and SQLAlchemy
2.0.51 or 2.1.3. Both use greenlet 3.5.3, psycopg 3.3.6 in Python mode, and
cryptography 50.0.2. SQLAlchemy 2.1.3 uses its Python implementation.
The tests reuse existing packages and compatible cached modules without installation.
These cells differ from the pinned release dependencies. It is compatibility
evidence, not release qualification. All seven full gates remain UNKNOWN.

The [focused correction run](_reset/smolink-readonly-green-20261022.json) passes 154 tests.
The pinned app passes separately with [SQLAlchemy 2.0.51](_reset/smolink-final-sa20-20261022.json)
and [SQLAlchemy 2.1.3](_reset/smolink-final-sa21-20261022.json).
The source and cost records are [SA 2.0](_reset/smolink-application-final-sa20-20261022.json)
and [SA 2.1](_reset/smolink-application-final-sa21-20261022.json).
These receipts include all 38 source hashes and exact runtime versions.

The [full pinned-dependency run](_reset/smolink-full-sa21-20261022-3.json) passes
**1,405 tests and 18 subtests**, with three skips and 48 existing SQLAlchemy warnings.
The final wrapper receipt records 208.23 seconds. The skips cover the two fresh-cluster modules and
the external app, which has its own interpreter and receipts above.
The [release check](_reset/smolink-release-installed-20261022.json) passes matching
repeat builds, archive and SBOM checks, 32 installed-file comparisons, and isolated
CLI startup. Installation uses `--no-deps`; it does not qualify runtime dependencies.
The first build attempt could not write the default uv cache. The existing cache
under `/tmp` permits an offline run without a permission change.

Each source type also passes one export and seven restore/adoption/removal tests
on a new PostgreSQL 16 cluster: [VARCHAR](_reset/fresh-cluster-restore-20261022-10.json)
and [historical text](_reset/fresh-cluster-restore-20261022-11.json).
The [normalization record](_reset/smolink-evidence-binding-20261022.json) binds these
runs to the final helper file. The only later difference removes one trailing
blank line. Its Python syntax tree is identical, and all other 89 source/test
hashes match. The historical receipts remain unchanged.
A sandbox approval-review timeout prevented the first command from starting.
The permitted retry passed both private-role probes and completed the harness.
No failed database probe was retried, and no host permission policy changed.

## Native VARCHAR support: 2026-10-22

**IMPLEMENTED:** the text family now includes native PostgreSQL `varchar(n)` and
unbounded `varchar`, with matching standard SQLAlchemy `String` or `VARCHAR` mappings.
Native `text` keeps its existing `Text` mapping contract.
The compiler rejects mismatched lengths, custom types, domains, and dialect variants.

Plans with a protected VARCHAR field emit `cryptalis.lock/v3` and require
`pg-varchar/v1`. Text-only plans still emit v2. Readers retain v1/v2 support.
The source schema records the native typmod. No field-source member or CF1 byte
format changes. Attachment now validates the full compiler lock before connection,
including standalone targets without a transition journal.

Protected writes preserve PostgreSQL character counts and excess-ASCII-space rules.
They encrypt the exact stored value after assignment coercion.
Pending ORM attributes retain their assigned value until refresh or expiration.
Equality query values receive no assignment coercion.
An overlength non-space value raises `VarcharLengthExceeded`, with SQLSTATE `22001`.
The error occurs during binding, before cursor execution. The failed session requires
rollback, as the native PostgreSQL flush does. Diagnostics omit the supplied value.
Authenticated plaintext beyond the declared character limit raises `RepresentationMismatch`.

Reverse staging uses the captured native type and typmod. Removal checks native
schema and metadata after journal retirement. The test restarts an isolated process
that imports no Cryptalis module, then completes native insert, update, read, and delete.
A fresh-cluster mode repeats backup, adoption, status, decrypt-back, and removal
with a VARCHAR source. The default mode retains historical text coverage.

The native oracle covers Unicode, composed/decomposed text, NULL, empty values,
ASCII and non-ASCII whitespace, trailing-space uniqueness conflicts, pending state,
refresh, exact typed query binds, async writes, and post-removal length enforcement.
Adversarial controls reject reader downgrades, missing reader dependencies, invalid
typmods, transformed mappings, transformed query binds, and overlength authenticated frames.
SQL parameter capture contains no protected input marker.

The [focused run](_reset/varchar-final-focused-20261022.json) passes 179 tests and 18 subtests.
This is local type and lifecycle evidence. It does not prove Smolink adoption,
a production provider, host writer exclusion, or independent security review.
All seven full gates remain UNKNOWN.

The [full suite](_reset/varchar-full-sa21-20261022.json) passes **1,402 tests and 18 subtests**, with two fresh-cluster
modules skipped and 48 existing SQLAlchemy warnings. The run took 186.02 seconds.
The local cell uses Python 3.12.3, SQLAlchemy 2.1.3, psycopg 3.3.6, and
cryptography 50.0.2. No SQLAlchemy 2.0.51 rerun occurred.

The separate orchestrator passes one export and seven restore tests for each
source type: [historical text](_reset/fresh-cluster-restore-20261022-9.json)
and [native VARCHAR(64)](_reset/fresh-cluster-restore-20261022-8.json).
Both paths preserve captured metadata through approved adoption and removal.
The VARCHAR path also checks the restored native character limit.
The [repeat release builds](_reset/varchar-release-20261022.json) match. Archive checks, SBOM export, isolated CLI startup,
and all 32 installed-file comparisons pass. Installation uses `--no-deps`.

Review exposed three admission gaps: standalone reader fences, failed-flush state,
and hidden dialect transformations. Negative controls first reproduced each gap.
The corrected tests pass. Earlier intermediate failures also included test-fixture
errors: a non-admitted index shape, an extraneous storage-only review, a duplicate
native restart value, and incorrect context-manager use for prepared keys.
The logging control now rejects its incomplete lock before connecting.
These changes strengthen admission. Valid connection paths retain real PostgreSQL coverage.

This slice removes the native VARCHAR type blocker. A pinned external application
still needs its own lifecycle and deployment evidence.
All seven full gates remain UNKNOWN.

## Source retrieval workflow: 2026-10-22

The repository instructions now define the reusable retrieval fallback.
Use local Git and files for product source, Firecrawl for external research,
and Playwright only when ordinary HTTP cannot retrieve the required rendered content.
Every Firecrawl scrape supplies its required `objective` with the URL.
A failed valid call switches retrieval method without an unchanged retry.

**VERIFIED:** the corrected call retrieved the official PostgreSQL 16 character-type
page with status 200, the expected final URL and title, and relevant body passages.
The earlier missing-objective response remains a failed retrieval.
This workflow change does not establish a product runtime capability.
No database suite ran for this documentation-only checkpoint.
New prose lint scores 0.66 per 100 words.

## Fractional measured rates: 2026-10-22

**IMPLEMENTED:** protection and reverse plans now reload their own decimal rate
observations. Previously, both planners accepted finite floating-point inputs,
but their artifact reader rejected every decimal JSON number.
Even a measured rate of `1000.0` could not pass that reader.

The transition reader shares the existing structural JSON limits.
It admits positive finite decimals only in `estimates.backfill_rows_per_second`
and `estimates.verify_rows_per_second`. A reverse artifact also admits those
same paths inside its embedded `source_plan`. Counters, target facts, locks,
and cryptographic policy keep their integer-only number contract.
Manifest inspection also keeps its integer-only contract.
The fix preserves the bytes and formats that the planners already emit.
It does not introduce a new rate encoding or change cryptographic formats.

**VERIFIED, local PostgreSQL 16 cell:** three lifecycle regressions first failed
([negative control](_reset/transition-rates-red-20261022.json)).
The corrected cases reload integer, integral-float, and fractional protection
plans, then protect and decrypt-back through a fractional reverse plan.
Independent native reads retain all seven current values in each case.
Negative controls refuse floating counters, target ports, lock facts, zero and
negative rates, NaN, infinity, and an overflowing exponent.
The [focused parser, status CLI, and transition run](_reset/transition-rates-green-20261022-2.json) passes 157 tests.

Throughput rates remain host observations. Pause estimates exclude drain, DDL,
index builds, publication delays, and capacity guarantees.
No production provider, authenticated deployment authority, or independent review
is qualified. All seven full gates remain UNKNOWN.

The full current-revision suite passes **1,363 tests and 18 subtests**, with two
fresh-cluster modules skipped and 48 existing SQLAlchemy warnings.

The [full receipt](_reset/transition-rates-full-sa21-20261022.json) records current source and test hashes.
The run took 178.81 seconds on Python 3.12.3, SQLAlchemy 2.1.3, psycopg 3.3.6,
and cryptography 50.0.2. No SQLAlchemy 2.0.51 rerun occurred.

One [export](_reset/fresh-cluster-export-20261022-6.json) and seven
[restore cases](_reset/fresh-cluster-restore-20261022-6.json) pass separately on a new PostgreSQL 16 cluster.
These cases retain the historical integer-rate artifact path through restore adoption,
status, decrypt-back, and package-free removal.

The [repeat release builds](_reset/transition-rates-release-20261022.json) match. Archive checks, SBOM export, isolated CLI startup,
and all 32 installed-file comparisons pass. Installation uses `--no-deps`.
This evidence does not qualify runtime dependencies or a production deployment.

## Read-only protection status: 2026-10-22

**IMPLEMENTED:** `cryptalis status PLAN --pin PIN --database-url-file PRIVATE_FILE`
reports one committed protection-transition snapshot. The Python API is
`cryptalis.migration.status(plan, engine, pin=pin, restore=binding)`.
The optional restore binding refers to an approved adopted backup.

The command checks the planned target, supplied external pin, journal identity,
and phase-specific schema or maintenance fence. It reports the committed phase,
row and chunk counts, external phase, metadata match, and a safe next action.
It uses a PostgreSQL read-only repeatable-read transaction. It needs no keys,
maintenance approval, or executor advisory lock. Concurrent executor progress
appears on the next request, rather than partway through the current snapshot.

`verification: NOT_PERFORMED` means that this request does not authenticate data,
check providers, or qualify host writer exclusion. An ACTIVE metadata match is
not production admission. Pin provenance remains the host's responsibility.
This command covers protection transitions. Reverse transitions, rotation,
retained-key obligations, and the full Doctor remain open.

Plan admission rejects missing or unknown top-level members, invalid identities,
and malformed basic containers before connection. Private inputs use bounded
regular-file reads. Diagnostics omit connection details and input values.

**VERIFIED, local PostgreSQL 16 cell:** the full suite passes **1,351 tests and
18 subtests**, with two fresh-cluster modules skipped and 48 existing SQLAlchemy
warnings. The [full receipt](_reset/status-full-sa21-20261022.json) records source and test hashes.
The run took 191.19 seconds. The current cell uses Python 3.12.3,
SQLAlchemy 2.1.3, psycopg 3.3.6, and cryptography 50.0.2.
No SQLAlchemy 2.0.51 rerun occurred.

The regressions cover all seven protection phases, one stable snapshot during
another executor's commit, enforced read-only writes, and inspection without the
executor lock. CLI tests cover private malformed inputs, wrong credentials,
text and JSON results, and actual output failure.
The [plan-shape negative control](_reset/status-plan-shape-red-20261022-2.json) recorded five failures and two passing refusals.
An earlier draft used an incorrect expected diagnostic code. Its separate RED
[receipt](_reset/status-plan-shape-red-20261022.json) remains historical test-development evidence.

One [export](_reset/fresh-cluster-export-20261022-5.json) and seven
[restore cases](_reset/fresh-cluster-restore-20261022-5.json) pass on a new PostgreSQL 16 cluster.
The adopted protected backup reports ACTIVE metadata through the new status API
before its native metadata checks, decrypt-back, and removal.
The standalone release suite passes eleven test groups. Repeat builds match,
[archive inspection and SBOM export](_reset/status-release-20261022.json) pass, and the installed wheel matches all
32 checked files. Installation uses `--no-deps`. Isolated CLI help passes.
Without runtime dependencies, the installed status command reports
`DependenciesUnavailable` with exit 4 and no traceback.
No production provider, authenticated host fencing, independent security review,
or release qualification is complete. All seven full gates remain UNKNOWN.

## Removal metadata and restored backups: 2026-10-22

**IMPLEMENTED:** removal now compares the current native catalog with lock v2
`source_metadata`, as well as the structural schema. A changed captured comment,
statistics target, or column grant raises `metadata_not_restored:source_metadata`.
The failed removal transaction retains the journal and its `PLAINTEXT_ACTIVE` state.
`check_removed` and repeated terminal removal requests use the same comparison.
A terminal retry first checks whether the retired journal exists, then checks the
actual package-free state. It does not query a deleted table or recreate a journal.
Lock v1 retains its existing boundary because it carries no `source_metadata`.

**VERIFIED, local PostgreSQL 16 cell:** six regressions first failed because drift
passed silently. The first correction exposed three terminal retries that queried the
missing journal. After both corrections, all 22 focused lifecycle, independent
application, and restore cases pass ([receipt](_reset/removal-metadata-green-20261022-2.json)). Native reads retain every current value.

The fresh-cluster scenario now seeds comments, a column grant with grant option,
statistics target, storage, compression, column options, index options, and extended
statistics. Native catalog assertions check both plaintext backup restoration and
adopted protected-backup recovery through decrypt-back and removal.
One export and seven restore cases pass on a new isolated cluster
([export](_reset/fresh-cluster-export-20261022-4.json),
[restore](_reset/fresh-cluster-restore-20261022-4.json)).

The full current-revision suite reports **1,322 passed, 2 skipped, 18 subtests passed**
in 175.32 seconds, with 48 existing SQLAlchemy deprecation warnings
([receipt](_reset/removal-metadata-full-sa21-20261022.json)). The skipped fresh-cluster
modules pass separately through the orchestrator above. The local runtime uses
Python 3.12.3, SQLAlchemy 2.1.3, psycopg 3.3.6, and cryptography 50.0.2.
No SQLAlchemy 2.0.51 rerun occurred.
The standalone release suite passes eleven test groups. The
[rebuilt artifact receipt](_reset/removal-metadata-release-20261022.json) records
matching repeat builds, archive inspection, SBOM export, and 32 installed-file
comparisons with isolated CLI startup. Installation still uses `--no-deps`.

A temporary pytest mutation removed the protected-column comment after restoration.
Before the fix, removal reported success and the native assertion found the missing
comment. That [expected failure](_reset/fresh-cluster-metadata-control-20261022.json) remains
recorded separately from positive evidence.
The mutation changed no product file. Qualification uses public synthetic roots.
No external provider, authenticated host fencing, or independent review is qualified.
All seven full gates remain UNKNOWN.

## Sandbox access recovery: 2026-10-22

The user authorized repair of the execution blockers and resumption of engineering.
Read-only inspection found correct filesystem ownership and readable credential files.
The sandbox mounted `.git` read-only and denied TCP socket creation with errno 1.
These observations identify execution restrictions, not a PostgreSQL authentication failure.

**VERIFIED:** approved execution outside the sandbox creates and removes a temporary
file in `.git`. The required `scripts/test_postgres.py --preflight-only` then passes
both fresh private-role probes. Credentials, database configuration, host permissions,
and sandbox policy remain unchanged. Ordinary repository reads still use the sandbox.
Required database tests and Git writes use scoped approved execution.

**VERIFIED, Python 3.12.3, SQLAlchemy 2.1.3, psycopg 3.3.6, cryptography 50.0.2:**
the full wrapper run reports **1,316 passed, 2 skipped, 18 subtests passed** in
188.95 seconds. The 48 warnings concern deprecated SQLAlchemy DISTINCT ON syntax.
The two skipped modules require the separate fresh-cluster orchestrator.
The [receipt](_reset/resumed-full-sa21-20261022.json) records current source hashes.
The standalone release suite also passes all eleven test groups.

The earlier failure receipts remain immutable historical evidence. Their blocked status
does not describe the successful approved execution path. Production provider selection,
deployment authority, and independent reviews remain external prerequisites.
All seven full gates remain UNKNOWN.

## Installed artifact identity: 2026-10-22

**IMPLEMENTED:** `scripts/release_check.py --python PATH` compares installed file bytes
with the wheel from the current build. It checks every original wheel file except installer-rewritten `RECORD`.
It rejects extra package files and requires the selected virtual environment.
It also checks the imported package origin. Isolated Python subprocesses use
a fresh bytecode cache, so preexisting unchecked bytecode cannot replace verified source.
The [receipt](_reset/release-install-binding-20261022.json) records the wheel hash and the number of compared files.

**VERIFIED, offline local cell:** the standalone release suite passes eleven test groups.
Four mutations previously passed incorrectly: changed module bytes, metadata, license,
and an extra package module. The corrected checker refuses all four.
A review probe showed that unchecked stale bytecode could execute despite matching
source. The corrected checker ignores that bytecode and executes the verified source.
An actual offline uv installation uses a new Python 3.13.12 environment.
It passes all 32 file comparisons and the isolated CLI help check. Installation used `--no-deps`.
This verifies package identity and the standard-library CLI, not runtime dependencies.

A startup-hook negative control exposed raw child diagnostics on failure.
Failures now report `Release.CommandFailed`, the tool name, and its exit status.
The injected private marker stays absent from the checker output.
Two builds also match, and archive inspection and SBOM export pass.

**Limits:** this check trusts the interpreter, installer, and host filesystem.
It does not sandbox Python startup hooks or prove dependency safety.
No production runtime, independent rebuild, or publication authority is qualified.
This checkpoint originally lacked PostgreSQL and Git access.
The sandbox recovery above supplies the later full-suite evidence and Git write path.
All seven full gates remain UNKNOWN.

## Release archive integrity correction: 2026-10-22

**IMPLEMENTED:** the release checker requires each wheel file exactly once in `RECORD`.
Every file except `RECORD` requires its SHA-256 hash and exact size.
Duplicate archive members, noncanonical paths, links, and special files are refused.
Wheel metadata must match the project name and version in `pyproject.toml`.
Directory entries must be empty and agree with their declared type.
The sdist checker applies exclusions below its single root directory and requires
project metadata at that root. These checks inspect archives without extraction.
The checker targets Cryptalis's unsigned artifacts, not every permitted wheel variant.

**VERIFIED, offline local cell:** the standalone command
`.venv/bin/python scripts/test_release_check.py` passes ten test groups.
Before the correction, the same tests reported 25 failing cases and four errors.
Review exposed seven further failures for directory payloads and distribution metadata.
The valid archive controls pass, including an empty wheel directory.
Two offline builds produce identical wheel and sdist hashes, and both archives pass
the corrected inspector. The SBOM export also passes. The [receipt](_reset/release-integrity-20261022.json) records source
and test hashes, artifact hashes, commands, and verification limits.

**BLOCKED:** `.venv/bin/python scripts/test_postgres.py --preflight-only` returns
`OperationalError`, exit 2. The run does not retry or substitute a database.
The full pytest suite remains unrun because its admission hook requires that preflight.
No database-dependent implementation changes or capability claims follow.
At this checkpoint, the optional clean-install probe lacked installed-artifact identity.
The installed-artifact correction above closes that gap with its own evidence.
Independent rebuild, publication, provider qualification, and human review remain open.
All seven full gates remain UNKNOWN.

## Lock v2 metadata capture and restore: 2026-10-21

**IMPLEMENTED:** new protection plans emit `cryptalis.lock/v2`. Each model records
`source_metadata` for protected columns: comment, statistics target, storage,
compression, options, and column grants; constraint and index comments; and extended
statistics with kind letters, sorted columns, statistics target, comment, and a
definition digest. Grants use `GRANTEE|PRIVILEGES|GRANTABLE` with canonical privilege
letters and `PUBLIC` as a valid grantee. The protection switch applies captured grants
to the ciphertext column. A catalog change after planning raises
`source_metadata_changed`; the reverse switch refuses changed grants and late metadata
on the ciphertext column, then restores the captured facts. A missing role raises
`acl_role_missing`. The restore compares the resulting catalog with `source_metadata`
and raises `metadata_restore_mismatch` on any difference. Extended statistics with
expressions and sequences owned by a protected column remain refused.

The reader accepts `cryptalis.lock/v1` and `cryptalis.lock/v2`. A v1 lock restores no
metadata because it carries none.

**VERIFIED, local PostgreSQL 16.15 cell:** capture, grant forwarding at `PENDING`,
drift, reverse refusal, and exact catalog restore pass in
`tests/test_protection_compiler.py`, `tests/test_deprotection.py`, and
`tests/test_migration.py`. The full suite reports **1,316 passed, 2 skipped** on
SQLAlchemy 2.1.3 ([receipt](_reset/lock-v2-full-sa21-20261021-3.json)).

**UNKNOWN:** the SQLAlchemy 2.0.51 cell was not rerun because its local virtual
environment is absent. The missing-role path is implemented but has no executable test
because the least-privilege owner cannot create or drop roles. Owned sequences remain
refused. Tablespace moves remain UNKNOWN (the local cell has no additional tablespace
and the least-privilege owner cannot create one). Physical column order still changes.

## Release artifacts and SBOM: 2026-10-21

**IMPLEMENTED:** `scripts/release_check.py` builds the wheel and sdist twice, compares
SHA-256 hashes, verifies every wheel `RECORD` digest and size, rejects forbidden archive
members, requires project metadata and the license file, scans runtime source for
network or telemetry import terms, and exports a CycloneDX 1.5 SBOM from the locked
runtime dependency set. Package metadata declares the MIT license and includes the
license file.

**VERIFIED, local Python 3.12.3 and uv 0.12.12 cell:** two consecutive builds produced
identical wheel and sdist hashes. The wheel has 39 members; its `RECORD` hashes and sizes
match. The sdist has 39 members. The SBOM contains `cryptalis`, `cryptography`,
`psycopg`, `sqlalchemy`, and their locked transitive components. A wheel installed into
a new virtual environment imports from that environment and starts `cryptalis --help`.
The runtime source scan found no network or telemetry import terms.
`uv lock --check` passes. The [receipt](_reset/release-check-20261021.json) records
source hashes, artifact hashes, and the clean-install path. G-RELEASE remains UNKNOWN.

**Limits:** reproducibility is same-host and same-uv only. There is no independent
rebuild, signed provenance or attestation, Trusted Publishing, vulnerability scan,
old-reader compatibility, upgrade/uninstall matrix, or controlled release identity.
The clean install resolved dependencies from the network; it did not use an offline,
hash-verified install. Independent review and publication remain external blockers.

## Independent application adoption and package-free restart: 2026-10-19

**IMPLEMENTED:** `tests/independent_app.py` is an ordinary three-model application
(accounts, customers with a real foreign key, notes) that imports no Cryptalis component
and refuses such imports when `CRYPTALIS_FORBIDDEN` is set.
`tests/test_independent_application.py` runs the complete host workflow against it:
schema creation and seeding through application code, manifest planning, protection to
`ACTIVE`, ORM reads and exact search under attachment, edits and inserts during
protection, decrypt-back, approved removal, metadata comparison, and a fresh package-free
process that edits, inserts, deletes, and reads through the application's own code.

**VERIFIED, local PostgreSQL 16.15 cell:** the lifecycle case passes on SQLAlchemy 2.1.3
and 2.0.51, including a zero-row protected table, two tenants, Unicode, empty and
trailing text, a deleted row, and a real foreign key. The package-free child process
reports `cryptalis` in no output and matches the expected native values. Full suites
report **1,300 passed, 2 skipped** on 2.1.3
([receipt](_reset/independent-app-full-sa21-20261019.json)) and **1,272 passed, 30 skipped**
on 2.0.51 ([receipt](_reset/independent-app-full-sa20-20261019.json)).

**Limits:** the application is an in-repo fixture, not a pinned external application; the
package-free restart does not exercise a web framework, connection-pool warm-up, or a
second independent codebase. G-LIFECYCLE remains UNKNOWN.

## Fresh-cluster protected-backup recovery and adoption: 2026-10-19

**IMPLEMENTED:** `scripts/fresh_cluster_qualification.py` initializes a new PostgreSQL 16
cluster, creates same-named roles and databases, and runs the recovery suite through the
mandatory credential wrapper with a temporary HOME. `tests/test_fresh_cluster_export.py`
writes a plaintext pre-protection dump, a protected dump after attached edits, and a
manifest of expected values and retained artifacts. `tests/test_fresh_cluster_restore.py`
runs only against the new cluster. `cryptalis.restore/v1` (`restore.py`) issues a
`RestoreBinding` after a read-only adoption scan; `migration.check_deployment(...,
restore=binding)`, `attach((plan, pin, binding))`, and `deprotection.plan(..., restore=
binding)` evaluate the binding.

**VERIFIED, isolated PostgreSQL 16.15 cluster:** the plaintext dump restores natively and
matches the pre-protection rows. The protected dump restores with the same roles; the
payload column is `bytea`; the runtime role reads ciphertext only; the retained key policy
and descriptor recover every exact value (NULL, empty, Unicode, trailing space, edited,
added) through both the product decoder and the independent decoder oracle. Without a
binding, the restored journal cannot become current authority: `check_deployment` and
reverse planning refuse with `deployment_not_current`, and `attach` refuses with
`PolicyMismatch`. With an approved binding, the restored schema attaches, serves exact
search, accepts edits and deletes, reverses to plaintext, and removes the package objects
with matching native values and schema facts. Refusals are typed:
`restore_approval_required`, `restore_source_is_current`, `invalid_restore_binding`,
`restored_frame_verification_failed`, `restored_state_changed`, `restore_target_mismatch`,
`restore_binding_mismatch`, `restored_schema_mismatch`, `restored_schema_changed`,
and `restored_constraint_probe_failed`. Post-adoption drills also refuse structural
schema drift, definition-only drift, and journal-state drift on the restored copy.
[Export](_reset/fresh-cluster-export-20261019-3.json) and
[adoption](_reset/fresh-cluster-restore-20261019-3.json) receipts record the wrapper runs.
The full suites remain green with the qualification modules skipped outside the
orchestrator: **1,302 passed, 2 skipped** on SQLAlchemy 2.1.3
([receipt](_reset/restore-full-sa21-20261019.json)) and **1,274 passed, 30 skipped**
on 2.0.51 ([receipt](_reset/restore-full-sa20-20261019.json)).

**Limits:** the host asserts source fencing and quarantine; the package does not
authenticate either and has no cryptographic evidence of source isolation. Adoption
refuses a restated frame constraint with no retained frame
row, and it qualifies the restated text behaviorally, not textually. A pinned external
application, physical column order, and the owned-sequence limit remain. G-LIFECYCLE
remains UNKNOWN.

## In-place decrypt-back and removal: 2026-10-19

**IMPLEMENTED:** `cryptalis.deprotection` adds `cryptalis.reverse/v1` for an admitted
`cryptalis.transition/v1` source. Reverse state shares the source journal and advisory
lock; the source row remains `ACTIVE`. Expand stages native plaintext columns and fences
inventoried schemas, backfill decrypts current frames, verification re-authenticates every
value, and switch replaces the ciphertext column without `CASCADE`, restoring recorded
constraints, indexes, and collation. Pre-switch abort removes reverse-owned objects.
Removal requires a literal `RemovalApproval`, matching external pins, an empty metadata
diff against the recorded source schema, and no remaining `_cryptalis` relations or
functions in inventoried schemas.

**VERIFIED, local PostgreSQL 16.15 cell:** seven lifecycle cases pass on SQLAlchemy 2.1.3
and 2.0.51. The [full 2.1.3 run](_reset/reverse-full-sa21-20261019.json) reports
**1,299 passed**; the [full 2.0.51 run](_reset/reverse-full-sa20-20261019.json) reports
**1,271 passed, 28 skipped**. The cases cover edits and deletes during protection, a row
added while protected, wrong custody, corrupt frames, disabled guards, lost COMMIT replies,
abort, repeated terminal requests, metadata restoration, and unsafe plan/removal refusals.
These counts are not gate evidence.

**Limits:** in-place reverse cannot restore physical column order (`attnum`). The compiler
lock records no comments, statistics targets, storage, or compression settings, so those
remain UNKNOWN. Fresh-cluster restore, a real package-free application run, retained-backup
reader proof, and production pause budgets remain open. The
[layout evaluation](_reset/layout-evaluation-20261019.md) records why retained-native is
not promoted. All seven gates remain **UNKNOWN**.


## Direct driver inspection failures: 2026-10-19

**IMPLEMENTED:** compiler inspection maps both SQLAlchemy and direct psycopg errors
to `InspectionUnavailable`. SQLSTATE is read from the driver error, whether it is
wrapped by SQLAlchemy or raised directly by an event listener. Raw driver text and
SQL binds remain outside the public failure.
Before this change, a direct psycopg error from a `before_cursor_execute` listener
escaped on SQLAlchemy 2.0.51 while the same case was mapped on 2.1.3.

**VERIFIED, local PostgreSQL 16.15 cell:** focused compiler and diagnostics suites
report **61 passed** on each profile.
[Full SQLAlchemy 2.1.3](_reset/inspection-errors-full-sa21-20261019.json) reports
**1,292 passed** and [full SQLAlchemy 2.0.51](_reset/full-sa20-20261019.json) reports
**1,264 passed, 28 skipped**. These counts are not gate evidence; all seven gates
remain UNKNOWN.

## Inactive payload-rotation batches: 2026-10-19

**IMPLEMENTED, internal only:** `cryptalis.crypto._payload_rotation.prepare_payload_rotation_batch`
decodes current frames under the exact source payload generation and reseals the same
exact text under the target generation. It preserves record identity and the source
search-header bytes, and returns a complete immutable tuple or raises.
It admits one field and tenant, distinct source/target payload roots, an unchanged
search generation, bounded rows/bytes, and unique records. The source and target
leases are rechecked after transformation, so an expired lease cannot yield an earlier
successful batch. No SQL, provider, policy, schema, or publication effect occurs.
The function does not implement a rotation executor or active-policy switch.

**VERIFIED, local cell:** the focused wrapper run reports **40 passed** for
[SQLAlchemy 2.1.3](_reset/payload-rotation-focused-sa21-20261019.json) and the
[full SQLAlchemy 2.1.3 suite](_reset/payload-rotation-full-sa21-20261019.json) reports
**1,292 passed**. Focused SQLAlchemy 2.0.51
([receipt](_reset/payload-rotation-focused-sa20-20261019.json)) reports **90 passed**.
The tests use frozen CF1 vectors, an independent framing/AEAD oracle, source/target
root separation, record and header preservation, bounded-batch refusals, and lease
faults. These counts are not gate evidence; all seven gates remain UNKNOWN.

## Internal rewrap candidate preparation: 2026-10-19

**IMPLEMENTED, internal only:** `cryptalis.crypto._rewrap.prepare_rewrap(source, target)`
prepares an inactive replacement policy. It resolves every admitted source root under
the existing lease, wraps each root with the target provider, unwraps and compares the
exact bytes and context, and returns the same contexts and generations under the target
provider identity. The source policy and cache stay unchanged.
Invalid target identity, provider faults, wrong roots/contexts/providers, identity
drift, and source expiry return `KeyUnavailable` without a partial candidate.
Interruption propagates. No rotation executor, active-policy publication, persistent
custody, payload rotation, search reindex, or retained-artifact update exists.

**VERIFIED, local cell:** the focused wrapper run reports **16 passed** for
[SQLAlchemy 2.1.3](_reset/rewrap-preparation-focused-sa21-20261019.json) and **54 passed**
for [SQLAlchemy 2.0.51](_reset/rewrap-preparation-focused-sa20-20261019.json).
The [full SQLAlchemy 2.1.3 suite](_reset/rewrap-preparation-full-sa21-20261019.json)
reports **1,252 passed**. The tests use an independent
development provider, old-frame reads, and bad-provider oracles. These counts are not
gate evidence; all seven gates remain UNKNOWN.

## Local provider outage, revocation and lease drills: 2026-10-19

**VERIFIED, local cell:** `tests/test_provider_failures.py` drives `Keyring` and both the
migration and attachment executors against a real PostgreSQL 16 cluster with a synthetic
local provider. The drill reports **4 passed** for
[SQLAlchemy 2.1.3](_reset/provider-failures-focused-sa21-20261019.json) and
[SQLAlchemy 2.0.51](_reset/provider-failures-focused-sa20-20261019.json).

The drills prove these behaviors:
- A second-chunk provider outage returns typed `KeyUnavailable` through
  `TransitionFailure`, rolls back the failing chunk, keeps the committed prefix
  (2 journal rows, 1 chunk), and a healthy retry resumes to `PENDING`.
- Revoked provider identity and malformed short material refuse before any backfill
  write (0 journal rows, 0 ciphertext rows), and a healthy retry completes.
- An attached sync commit with an expired lease and an offline provider fails closed
  with no committed row; a healthy retry commits.
- An attached async commit with an expired lease and an offline provider fails closed
  with no committed row; a healthy retry commits.

Wrong-root material, cancellation and replay remain covered by the CF1 and adapter
oracles in `tests/test_cf1.py` and `tests/test_sqlalchemy_adapter.py`.

The [full SQLAlchemy 2.1.3 suite](_reset/provider-failures-full-sa21-20261019.json)
reports **1,306 passed, 2 skipped** and the
[full SQLAlchemy 2.0.51 suite](_reset/provider-failures-full-sa20-20261019.json)
reports **1,278 passed, 30 skipped**. These counts are not gate evidence; all seven
gates remain UNKNOWN.

## Negative predicate boundaries: 2026-10-19

**IMPLEMENTED:** protected text admits simple `!=`, `NOT IN`, `IS NULL`, and
`IS NOT NULL` predicates in sync and async statements. Value predicates reuse the
declared authenticated equality term. NULL presence uses the SQL NULL check, so a
storage-only field needs no equality capability.
For NULL and `NOT IN` predicates, the tenant guard is the declared scope OR the
record key is NULL. This preserves SQL three-valued truth for NULL-extended
outer-join rows. The record key resolves by lineage and must match exactly once;
otherwise the attachment refuses.
General Boolean NOT around a compound expression remains refused because it could
invert the embedded tenant guard. No new leakage class is admitted; the existing
equality enumeration and frequency limits remain.
Before this change the same shapes were refused. A naive negation port would have
dropped absent outer-join rows, so the guard change is part of the admission.

**VERIFIED, local PostgreSQL 16.15 cell:**
[focused SQLAlchemy 2.1.3](_reset/negative-predicates-focused-sa21-20261019.json)
reports **366 passed** and [full SQLAlchemy 2.1.3](_reset/negative-predicates-full-sa21-20261019.json)
reports **1,236 passed**. Focused SQLAlchemy 2.0.51
([receipt](_reset/negative-predicates-focused-sa20-20261019.json)) reports **202 passed**.
The native-oracle matrix covers typed, reversed, late, and mixed NULL binds,
empty lists, aliases, pagination, OR composition, and outer joins. The RED run
before the change reported 57 failures and 2 passes. These counts are not gate
evidence; all seven gates remain UNKNOWN.

## Engine logging preflight: 2026-10-19

**IMPLEMENTED:** `attach` refuses an engine with `echo` enabled or `hide_parameters`
disabled before it opens a connection or resolves a key. The refusal is a typed
`UnsafeEngineLogging` failure with stage `engine logging admission` and a concrete
remedy. The earlier check ran during post-connect validation, so an unsafe engine
could reach the driver and key access before refusal.
No manifest, crypto, storage, or query-plan capability changed.

**VERIFIED, local PostgreSQL 16.15 cell:**
[focused SQLAlchemy 2.1.3](_reset/engine-preflight-focused-sa21-20261019.json) and
[full SQLAlchemy 2.1.3](_reset/engine-preflight-full-sa21-20261019.json) report
**307 passed** and **1,177 passed**. Focused SQLAlchemy 2.0.51
([receipt](_reset/engine-preflight-focused-sa20-20261019.json)) reports **143 passed**.
The deterministic preflight tests use a `do_connect` sentinel and key sentinel. They
assert that no connection or key access occurs and that no URL credential appears in
the failure. These counts are not gate evidence; all seven gates remain UNKNOWN.

## Textual reference admission correction: 2026-10-19

**IMPLEMENTED:** protected textual names in `ORDER BY`, `GROUP BY`, `DISTINCT ON`,
window ordering/partitioning, and `WITHIN GROUP`/aggregate ordering resolve against
the native SQL name spaces. The attachment refuses before the driver when any
resolved candidate is a protected column. Public output labels and FROM names that
shadow protected names retain native resolution.
Without this check, PostgreSQL can sort or group by randomized ciphertext and
silently change results. The earlier check inspected only selected output keys. It
missed unprojected FROM names, aliases, table-qualified names, window clauses, and
ordered aggregates.
The attachment resolves names with an empty native compilation state. It does not
render protected columns, capture keys, or add SQL. No manifest, crypto, storage, or
query-plan capability changed.

**VERIFIED, local PostgreSQL 16.15 cell:**
[focused SQLAlchemy 2.1.3](_reset/textual-admission-focused-sa21-20261019.json) reports
**303 passed**, including 164 textual-boundary cases and the existing adapter/search suites.
[Full SQLAlchemy 2.1.3](_reset/textual-admission-full-sa21-20261019.json) reports
**1,173 passed**, with 48 upstream `distinct_on` deprecation warnings.
[focused SQLAlchemy 2.0.51](_reset/textual-admission-focused-sa20-20261019.json) reports
**275 passed and 28 native-version skips**.
The native execution path is the oracle in every case. Both sync and async paths run.
The RED reproduction failed four attached unprojected `GROUP BY` cases before the change.
Admission adds one name-resolution pass per SELECT that contains textual references.
Performance was not separately measured because admitted SQL, plans, and crypto bytes are unchanged.
All seven full gates remain **UNKNOWN**.

## Membership performance correction: 2026-10-09

**IMPLEMENTED:** membership scans select row/tenant identities without protected source values.
Backfill and complete source/frame verification keep their original projections. Ordered digest bytes, cursors, journal, locks and public API are unchanged.
The user approved this bounded correction before Slice 6; no online or parallel protocol was authorized.
**VERIFIED:** [full current suite](_reset/audit-verification-31ac368e2bbf3bd3.json): **1,009 passed** in 102.12 s at `worktree-31ac368e2bbf3bd3`, based on Git `7edd164`.
[Regression proof](_reset/membership-regressions-31ac368e2bbf3bd3.json): committed source fails four native column-permission cases; fixed source passes all five tests.
The independent oracles check exact journal membership, UUID/bigint boundaries, both tenancy forms, multiple fields/tenants, pagination and all 1,007 decoded application values.
Projection, tenant-binding and pagination removals each fail/restoration passes. [Twenty prior safety removals](_reset/slice5-regressions-audit-d6a6b23daa40d329.json) retain their failure/restoration evidence.
Existing corruption, atomic commit, process interruption, lost reply, fence, lock queue, generation and external-pin tests still pass.
Graphify was refreshed; source confirms `_scope` serves expansion/verification, while backfill and value verification retain their value projections. Graph `scope()` test fixtures are unrelated.

[Same-connection wide-text control](_reset/membership-paired-32768-a81d3cf873c3edd8.json): median membership time **302.48→16.92 ms** for 5,000 rows with two 32 KiB fields.
[Separate-process before](_reset/membership-profile-32768-a94d3d18190b80fb.json)/[after](_reset/membership-profile-32768-a81d3cf873c3edd8.json): traced Python peak **131.84→0.59 MB**, process RSS **286.7→98.4 MiB**.
For two 32-byte fields, the [paired median](_reset/membership-paired-32-a81d3cf873c3edd8.json) was 32.54→30.33 ms. These are warm synthetic scan measurements, not backfill memory bounds.
A matched 30,000-row transition observed pause 3.741→2.813 s and expansion reader latency 0.224→0.113 s.
Unchanged backfill also ran faster; cache/scheduling variation prevents attributing the whole-pause difference to this patch. Verification membership was slower in that pair.
The [research assessment](research/performance-checkpoint.md) owns exact phase/CPU/WAL conditions, primary sources, ranked opportunities, byte-budget analysis and an unimplemented online proposal.
[Clock control](_reset/performance-clock-control-7edd164.json) observes raw/CPU versus monotonic rate discrepancy; cause and historical timing effects remain UNKNOWN.
No new million-row measurement, crypto/cache redesign, index-timing change, Slice 6 or concurrency protocol. The historical million-row pause remains 116.291 s.
All seven full gates remain **UNKNOWN**. No production provider or independent review exists.

## Step A corrective checkpoint: 2026-10-09

**IMPLEMENTED:** same-schema tables share the existing operation guard function, with a separate trigger on each table.
Expand creates the function once per schema. Activation/abort inspect every fence, drop every operation trigger, then drop each function without CASCADE in the same transaction.
An existing function is never replaced or adopted; `guard_function_conflict` reports native `42723`. Names, artifacts, pins and journal state are unchanged.
Frozen field descriptors are validated once per backfill chunk and once per model verification pass. No descriptor, tenant key or row context is retained across operations.
AEAD, field/tenant/row binding, fresh nonces, key expiry/generation checks, full verification and bounded lock retries remain unchanged.

**VERIFIED:** [final checkpoint](_reset/step-a-corrective-final-030b935c0581cb72.json) at content revision `worktree-030b935c0581cb72`;
[full suite](_reset/step-a-corrective-final-verification-030b935c0581cb72.json): **1,004 passed**, including 18 same-schema E2E/attack cases.
The tests assert exact NULL/empty/Unicode values across two tables, three fields and two tenants; both write fences; five process-kill/resume phases;
idempotent pre-switch abort; atomic failure during second-table expansion/retirement; conflict preservation; fence-drift refusal; and rejection of valid wrong-field/tenant/row frames before switch.
[Corrective proofs](_reset/step-a-corrective-regressions-030b935c0581cb72.json): original engine fails the native two-table application test, fixed engine passes;
six isolated removals fail/restoration passes, and all five old single-table checkpoint phases resume through the new engine.
[Twenty prior safety removals](_reset/slice5-regressions-audit-729b0f0ba9f8fea6.json) and [five bounded-lock removals](_reset/step-a-lock-regressions-0fadd110317d7e85.json) still fail/restoration passes.
Graphify was refreshed; source confirms guard creation/retirement and descriptor call paths. All database commands used the fresh-credential wrapper.

| Instrumented one-million-row measurement | Recorded baseline | Corrected engine |
|---|---:|---:|
| Backfill / throughput | 98.126 s / 10,191 rows/s | 67.804 s / 14,748 rows/s |
| Backfill main CPU / descriptor CPU | 64.588 s / 17.739 s | 35.658 s / 0.030 s |
| Verification / descriptor CPU | 65.404 s / 16.214 s | 42.214 s / 0.000062 s |
| Writer pause / observed expansion reader wait | 169.145 s / 5.496 s | 116.291 s / 6.106 s |

The [paired 20,000-row control](_reset/step-a-corrective-summary-c64053e2b5558c3f.json) measured backfill 2.065→1.128 s and verification 1.579→1.131 s before the single new million-row run.
[New measurement](_reset/step-a-optimized-million-1000000-a94d3d18190b80fb.json) reuses the baseline data, chunks and instrumentation: 500 UPDATE batches, 5,027 inspection/marker calls and 500 pipeline sync points remain unchanged.
Backfill SQL-call wall time was 37.560 s, including 29.340 s combined server/network/scheduling time; commits took 2.887 s. Exact database execution/wait time is unavailable.
Cluster-wide backfill WAL was 1,189,163,448 bytes; equality-index growth was 88,588,288 bytes. Physical per-index writes are UNKNOWN; no database/WAL optimization is claimed.
WSL still exposed 20 CPUs, 7.47 GiB RAM and 2 GiB swap with no overrides. Starting load was 0.864/0.682/0.467, versus 0.154/0.352/0.353;
available memory was 3.94 versus 6.12 GiB. New process peak RSS was 98.31 MiB. Cache/checkpoint/load differences and instrumentation limit causal claims.
The observed writer-pause reduction is 31.2%; the paired CPU/descriptor evidence supports a real reduction in Python work. Remaining sealing/verification work and expansion locking still cost time.
The engine verified all million values; an independent decoder checked eight representative rows, and the smaller E2E cases independently decoded every field.
The small-run receipt label was overwritten by an instrumentation-loop variable; source hashes identify baseline/fixed runs. The label was corrected before the million-row run; timing/workload logic was unchanged.
No Slice 6, parallelism, dual writes, public configuration or security-contract change. All seven gates remain **UNKNOWN**; no production provider or independent review exists.

## Step A protection measurement and lock checkpoint: 2026-10-09

**VERIFIED, instrumented one-million-row PostgreSQL run at Git `0383cec`:** [measurement](_reset/step-a-protection-0383cec.json).
The user confirmed that unrelated programs were closed. WSL exposed 20 logical CPUs (20 reported cores, one thread per core), 7.47 GiB RAM and 2 GiB swap;
no `.wslconfig` overrides or narrower cgroup CPU/memory limits were found. Load averages changed from 0.154/0.352/0.353 to 1.133/0.791/0.532.

| Phase | Wall time | Main client CPU |
|---|---:|---:|
| Expand | 5.521 s | 4.711 s |
| Backfill, 500 chunks of 2,000 rows | 98.126 s; 10,191 rows/s | 64.588 s |
| One final verification and switch | 65.433 s; verification 65.404 s | 63.865 s |
| Local ACTIVE acknowledgement | 0.023 s | 0.009 s |

Writer pause was **169.145 s**, excluding seed/plan/drain and real publication delay. Expansion index creation took 0.229 s over NULL shadows.
DDL SQL calls took 0.062 s at expansion and 0.0013 s at switch; these overlap phase times.
Lock-request calls took 0.114/0.252/0.143 ms at expansion/verification/activation. No executor lock wait was sampled; exact server wait time is unavailable.
The plain reader waited 5.496 s during expansion. Client-observed ACCESS EXCLUSIVE intervals were 5.512/0.018/0.016 s at expansion/switch/activation.
Backfill/verification reads continued; their maximum observed latencies were 156/37 ms, with no sampled reader lock wait in those phases.
Backfill CPU: seal 32.371 s, repeated descriptor preparation 17.739 s, key preparation 0.025 s. Client CPU dominates this workload with public test roots.
There were 500 UPDATE batches, 5,027 inspection/marker calls, 500 pipeline sync points and 504 driver commits; exact wire round trips are unavailable.
SQL-call wall time was 40.831 s, including 8.854 s client CPU and 31.977 s non-CPU time. The latter includes server/network/scheduling, not isolated database wait.
Sampled database waits included 73 WALSync, 22 WALWrite and 79 DataFileWrite observations; variable sampling intervals do not establish wait seconds.
Backfill cluster-wide WAL advanced 1,269,621,872 bytes. Equality-index size grew 76,800,000 bytes; per-index physical writes and table-attributed WAL remain UNKNOWN.
Instrumentation adds overhead and its component timers overlap. A [failed observer run](_reset/step-a-failed-instrumentation-0383cec.json) is retained as failed evidence;
restricted-role activity fields were NULL. Corrected instrumentation passed a [1,000-row control](_reset/step-a-smoke-1000-0383cec.json) before the million-row run.

**IMPLEMENTED local fix:** the executor keeps a 5 s session lock timeout. ACCESS EXCLUSIVE acquisition now uses three 100 ms attempts, with 50 ms gaps and savepoint rollback.
Cutover explicitly upgrades before DDL; rollback releases partial upgrades but retains EXCLUSIVE verification locks. Exhaustion reports `table_lock_busy_retry`/`55P03` without switching.
These limits bound individual acquisition attempts, not time spent holding a granted lock or an entire multi-table operation.
[Regression proof](_reset/step-a-lock-regressions-e137d3240bd453e9.json): `0383cec` gives three failures/one native-control pass; fixed code gives four passes. Five safety removals fail and restoration passes.
[Full verification](_reset/step-a-lock-verification-e137d3240bd453e9.json): **986 passed** at content revision `worktree-e137d3240bd453e9`.
[Twenty prior safety removals](_reset/slice5-regressions-audit-0e01c8924bb16893.json) still fail their tests and restoration passes. All database work used the fresh-credential wrapper.
Graphify was refreshed and findings were checked in source. A [same-schema two-table control](_reset/step-a-guard-reproduction-e137d3240bd453e9.json) reproduced duplicate guard-function creation (`42723`) with atomic rollback. The corrective checkpoint above fixes it; this control remains historical evidence.
Parallel workers are **not recommended before slice 7** on this evidence. First evaluate preparing the immutable descriptor once, then repeat a controlled profile.
Disjoint workers would need atomic per-range coverage, stable context/key generations, crash reconciliation, terminal original transactions, serialized cutover, and mandatory global verification; the current single cursor does not supply that protocol.
The historical 508.7/197.0 s variation is still UNKNOWN: source, instrumentation, load, chunking and cache conditions were not controlled across those runs.
Slice 6/7, decrypt-back measurements and package-free removal remain unimplemented. No dual writes or parallelism were added. All seven gates remain **UNKNOWN**.

## Step 0 protection-pause checkpoint: 2026-10-09

**IMPLEMENTED:** uninterrupted apply verifies and switches in one transaction, with one full verification pass.
Saved VERIFIED checkpoints still require fresh verification and an unchanged frame digest before switch.
Verification uses PostgreSQL EXCLUSIVE locks: plain reads continue, while writes and locking reads wait.
DDL still acquires ACCESS EXCLUSIVE. A reader that delays DDL past the lock timeout leaves source data and the BACKFILLED marker unchanged.
`print(plan_result)` reports native row count, supplied measured rates, and the estimated uninterrupted writer pause.
Extra verification checkpoints/retries, drain, DDL, index construction, and publication delay are excluded; this is not a pause bound.
**VERIFIED, bounded PostgreSQL 16 cell:** content revision `worktree-c72bb439d7e13334`, based on Git `9f335c6`.
[Full verification](_reset/step0-verification-c72bb439d7e13334.json): **982 passed**, including seven new native lock/SQL and independent-decoder cases.
[Step 0 proofs](_reset/step0-regressions-c72bb439d7e13334.json): committed engine gives six failures and one pass; fixed copy gives seven passes.
Seven isolated Step 0 mutations and [20 existing safety removals](_reset/slice5-regressions-audit-72f0a976a1fe9d8f.json) fail their behavioral checks; restoration passes.
The authentication attack now flips a tag bit instead of assigning a byte that could already have that value.
No new million-row pause was measured. The historical 508.7 s receipt and unexplained timing variation remain historical evidence.
No protocol change, dual writes, slice 6/7, production provider or independent review is added. All seven gates remain **UNKNOWN**.

## Corrective audit checkpoint: 2026-10-09

**VERIFIED, bounded PostgreSQL 16 cell:** source/test revision `audit-a07004dfcda8cd05`, based on `fe2b061`.
This is a content-bound worktree revision, not a Git commit. [Full receipt](_reset/audit-verification-a07004dfcda8cd05.json): **975 passed**.
[Slice 3](_reset/slice3-audit-a07004dfcda8cd05.json): 64 cases; [slice 4](_reset/slice4-audit-a07004dfcda8cd05.json): 75;
[slice 5](_reset/slice5-audit-a07004dfcda8cd05.json): 53 existing plus 40 audit cases. Old receipts remain unchanged.
Earlier slice 3 and 4 row-isolation claims did **not** cover grouped or callable primary-key binds.
The fix captures grouped AND/scalar-IN identities, normalizes explicit bind values and rejects ambiguous forms before SQL.
Protected primary-key lookups in HAVING or JOIN ON also reject. Plain projections retain native primary-key grammar.
All maintenance entries require approval before connection or locks. Read-only plan/deployment/attachment checks are exempt.
Acquisition, phase and cleanup failures retain safe diagnostics, operation identity and both primary/cleanup outcomes.
The credential wrapper reloads both private files and probes both roles; three real authentication-failure controls verify suite redaction.
[Audit regressions](_reset/audit-regressions-a07004dfcda8cd05.json) compare original and fixed code in isolated copies;
[20 existing safety removals](_reset/slice5-regressions-audit-1407433d842664f6.json) fail without their mechanism and pass after restoration.
No slice 6 work, production provider or independent review is added. All seven gates remain **UNKNOWN**.

## Slice 5 checkpoint: 2026-10-09

**IMPLEMENTED:** `cryptalis.migration.plan`, `apply`, `verify`, and pre-switch `abort`.
One phase loop uses a PostgreSQL journal, cooperating session advisory lock, transactional DDL, and bounded atomic chunks.
Plans bind the native schema, compiler lock, target, runtime role, inventoried tenant key policies, writer assertions, and host cost estimates.
Expand drains table access and installs an owner-controlled statement trigger that rejects restricted-runtime writes across chunk commits and process crashes.
Resume preserves committed ciphertext. Full verification checks membership, native value/type/NULL parity, authentication, terms, generations, constraints/indexes, and trigger inventory.
At that recorded revision, switch repeated verification under exclusive table locks and retired the original SQL column without CASCADE.
Database switch remains PENDING until the host supplies the exact externally published ACTIVATING pin.
After acknowledgement, startup requires the externally current ACTIVE pin, target/schema agreement, planned runtime role, and matching tenant key policies.

**VERIFIED, local PostgreSQL 16.15:** **53 migration cases** within **917 passing full-suite cases**.
The original native application supplies plaintext/type/NULL oracles; a separate stdlib HKDF/HMAC and AEAD decoder checks migrated frames against those values.
Independent child processes are killed at durable phase boundaries and during a partly completed backfill, then resume without replacing committed frames.
A real PostgreSQL transport fault discards an already-terminal COMMIT reply. Resume inspects the committed marker and retains the first chunk's bytes.
Connection faults during expand, verify, and transactional switch preserve the original representation and prevent false completion.
Concurrent runtime writes committed before fencing are included; writes during maintenance reject with `55000`, and an attached retry works after publication.
The runtime can read progress but cannot mutate the journal, disable the fence, alter its schema, or acquire ownership.
Real corruption, missing rows, changed source/index/trigger metadata, missing markers, and wrong active generations refuse switch.
A real own-schema `pg_dump`/`psql` older-snapshot restore cannot advance under the current external ACTIVE pin.
Missing publication, stale pins, altered keys, owner attachment, and competing executors refuse.
**Twenty isolated safety removals** fail their behavioral oracles; restoring each copied source restores a passing result.

[Verification](_reset/slice5-verification.json), [regression proofs](_reset/slice5-regressions.json), and
[performance](_reset/slice5-performance.json) retain commands, hashes, scope, and costs.
The final isolated million-row run backfilled **3,942 rows/s** in 253.7 s; the measured write pause was **508.7 s**.
Expand took 5.3 s, verify 148.6 s, and repeated verification plus database switch 100.9 s.
The pause ends at local ACTIVE acknowledgement; actual host publication delay adds to it.
Runtime write attempts in all four paused phases returned `55000`; an attached post-switch edit/read succeeded.
The observed phase maximum for the customer heap and indexes was 600,793,088 bytes; cluster-wide WAL increased about 1.396 GB.
These do not prove secure erasure, attributed WAL, storage bounds, or a production pause budget.
The earlier source measured 11,559 rows/s and 197.0 s pause. The cause of the run-to-run difference remains **UNKNOWN**.
An underestimated fixed WAL multiplier was replaced with required host staging cost inputs; no multiplier is presented as a bound.
The [60-line walkthrough](walkthrough-migration.md) explains plaintext retention and deployment responsibilities.

**Limits:** protection is a maintenance operation. It does not admit online plaintext writes during backfill.
Owner/DDL writers must be excluded by the host. The tests do not qualify a deployment's worker termination, credential control, policy provenance, or restore quarantine.
A supplied pin is a host assertion, not authentication implemented by this package. A restored journal never selects current authority.
Same-context row replay, hostile result omission, nullable substitution, and writers that bypass attachment remain outside the claimed boundary.
Only inventoried tenant policies are admitted. One protection operation per schema is currently admitted; an aborted journal remains for inspection.
Decrypt-back, package-free removal, rotation, finalization, retained-backup recovery, and production provider integration are not implemented by this slice.
No source mirror survives SQL switch, but dropped-column bytes can remain in heap tuples, WAL, snapshots, and backups. No erasure claim follows.
Storage/WAL and rate estimates require host staging observations; they are not bounds. Real exhaustion and production pause budgets remain UNKNOWN/D.
No production provider or independent review exists. All seven gates remain **UNKNOWN**. No commit or push occurred.

## Slice 4 checkpoint: 2026-10-08

**IMPLEMENTED:** declared exact-text equality/IN, mapped aliases, AND/OR and native tenant-scoped uniqueness.
The attachment hashes ordinary text query values with the existing independent search-root composition.
PostgreSQL uses a B-tree over the full term inside the CF1 frame, with tenant first when declared. No extension or companion column is needed.
One bytea write updates payload and term together. Native constraints arbitrate races and preserve distinct NULLs.
Attachment validates exact index/check definitions, keys, operator classes, uniqueness and valid/ready/live state.
Catalog deparsing uses `pg_catalog` resolution to reject function shadowing. Search key changes within an attachment refuse.
Protected predicates/projections compile per operation; plain projections keep native compilation caching.

**VERIFIED, local PostgreSQL 16.15:** **75 search cases**, **four independent frozen-term vector cases**, and **864 full-suite cases**.
The application path uses the separate non-owning runtime role; owner setup grants only schema USAGE and customer CRUD in disposable schemas.
Native sync/async controls compare text membership, SQL NULL/empty-IN truth, aliases, typed/reverse/late/shared binds and two protected fields.
Concurrent same-tenant insert races produce one commit and one native `23505`; cross-tenant duplicates and distinct NULLs commit.
Uniqueness failures roll back payload/term updates; later writes and queries recover. Duplicate backfill blocks unique-index creation.
Wrong-tenant queries expose no protected value. Known small domains, absent review/leakage acceptance and malformed physical contracts reject.
Listed unsupported grammar, forged/wrapped aliases, protected JOIN/derived tables, codecs, callables and ambiguous bind names refuse before SQL.
Real elapsed key-lease expiry leaves PostgreSQL unchanged; fresh sync/async sessions recover.
Independent writers can still hide search membership or install structurally plausible invalid AEAD. Point reads reject changed frames.
Returned-row authentication supplies no freshness, presence, result completeness or adversarial global-uniqueness guarantee.

[Verification receipt](_reset/slice4-verification.json) records exact source/test hashes, test intent and isolated regression removals.
[Performance receipt](_reset/slice4-performance.json) records the million-row runtime ORM measurements and their limits.
The earlier page-query source includes a protected entity projection; its former plaintext-only label is retired.
Its historical timing and causal explanation remain historical/UNKNOWN. Current profiling separates plain projections from protected entities with plaintext filters.
Empty-schema fixture conversion is not product migration. Fresh-deployment policy binding, writer exclusion, lifecycle and key rotation remain unqualified.
No production provider or independent human review exists. All seven full gates remain **UNKNOWN**. No commit or push occurred.
See the [60-line search walkthrough](walkthrough-search.md). This run stops at slice 4.

## Slice 3 checkpoint: 2026-10-08

**IMPLEMENTED:** `cryptalis.sqlalchemy.attach` returns a tenant-scoped Session factory.
Async attachment is awaited. The target must already store protected fields as `bytea`.
The host supplies a trusted compiler lock and exact tenant keyrings. Attachment does not migrate data or authenticate deployment authority.
Only ordinary ORM flush writes and admitted SELECTs are implemented. Search rewriting belongs to slice 4.
Prepared CF1 frames replace driver binds while mapped attributes remain ordinary text or NULL.
Read projections carry payload, record identity, and declared tenant context. Authentication precedes each value's release.
Protected SELECTs disable compilation caching so operation-specific result processors cannot retain another tenant, point, or key set.
Unprotected SELECTs retain native compilation caching. Public raw-driver, COPY, opaque SQL, and unprepared-write routes reject.

**VERIFIED, earlier restricted fixture-owner run:** the adapter suite returned **41 passed in 8.01 s**; the full suite returned **777 passed in 18.41 s**.
Commands: `.venv/bin/python -m pytest -q tests/test_sqlalchemy_adapter.py --tb=short`
and `.venv/bin/python -m pytest -q --tb=short`.
The cell uses Linux/WSL, Python 3.12.3, SQLAlchemy 2.1.3, psycopg 3.3.6, cryptography 50.0.2, and PostgreSQL 16.15.
The URL stayed private. Tests created and dropped only their own schemas under the restricted fixture owner.
Native and attached controls exercise exact text/NULLs, state/history, autoflush, merge, refresh/expiry, rollback,
entities/scalars/labels, aliases, outer joins, relationships, batches, streaming, and interleaved tenants.
Async controls exercise concurrent tenant tasks and cancellation observed through PostgreSQL's `PgSleep` wait event.
Cancellation during awaited key preparation leaves the database unchanged and permits a later write.
Sync and async updates/deletes work after commit expires context attributes.
Single-tenant bigint outer joins retain native NULLs. Same-named tables in separate schemas retain distinct values.
Cancellation is propagated; rollback removes the pending row; a later tenant session recovers.
Defensive checks verify driver-bind privacy with a visible unprotected control, valid-frame wrong-tenant refusal,
wrong returned point, relocated/changed ciphertext, unsupported grammar before driver execution, mapping mutation, failed-flush cleanup, and guarded reconnects.
Ambiguous columns and alternate protected mappings reject. Attachment refuses existing checked-out connections.
Target translation, changed primary-key mappings, and catalog nullability/default mismatches reject.

**VERIFIED regression sensitivity:** the main thread used an isolated copy of the current source and tests.
Only the copy lost the protected SELECT cache-disable call. All four native sync/async entity/scalar controls passed.
All four attached cases failed with `AuthenticationFailed`. Restoring the copy gave eight passes.
The original source remained unchanged during this proof. No assertion was weakened.
The withheld output was unavailable in the main-thread context. Its findings supplied no relied-upon evidence.
[Verification receipt](_reset/slice3-verification.json) binds these observations to source/test hashes.

**VERIFIED bounded cost:** 5,000 synthetic rows, 40 paired samples, warm local keys, fully consumed results.
Point p50/p95: native 0.435/0.618 ms and attached 1.715/2.903 ms. The p95 difference was 2.285 ms.
Plaintext page p50/p95: native 1.428/1.906 ms and attached 2.238/2.810 ms. Both paths recorded 60 cache hits.
[Compatibility](compatibility.md#slice-3-local-profile-2026-10-08) owns profiling details and limits.

### Restricted runtime-role completion: 2026-10-08

**VERIFIED, local slice 3 cell:** the adapter suite returned **49 passed in 9.00 s**.
The full suite returned **785 passed in 20.27 s**, with no failures, errors, or skips.
Commands: `.venv/bin/python -m pytest tests/test_sqlalchemy_adapter.py -q --tb=line`
and `.venv/bin/python -m pytest -q --tb=line` (the full run also wrote a temporary JUnit receipt).
Each database shell command loaded both URLs fresh from the private files before a psycopg `SELECT 1` check.
The SHA-256 prefixes were `0f63934e` for the fixture owner and `4e551e31` for the runtime login.
Both roles are restricted, use the same PostgreSQL 16.15 target, and have distinct identities.
The runtime login cannot inherit or `SET ROLE` to the fixture owner.

Only owned fixture objects received grants: schema `USAGE`, customer `SELECT/INSERT/UPDATE/DELETE`, and article `SELECT`.
The article read is required by native SQLAlchemy relationship lookup during customer deletion.
The first run without it failed equally in native and attached sync/async cases; the corrected grant passed.
Effective privilege checks reject schema `CREATE`, ownership, grant options, `TRUNCATE`, `REFERENCES`, and `TRIGGER`.
Sync/async native and attached controls verify exact NULL/empty/Unicode values, CRUD, refresh, and flushed-update rollback.
An independent connection observes committed protected bytes. A bind collector sees an unprotected marker and no supplied protected insert markers.
Opaque DDL rejects through the attachment before driver execution.

Independent sync and async psycopg connections receive SQLSTATE `42501` for nine operations:
create table, add column, create index, truncate, drop table, change table owner, change schema owner, drop schema, and switch to the fixture-owner role.
Each refusal rolls back; later queries succeed; inspected ownership and schema remain unchanged.
These denials concern the owned persistent schema. The runtime login retains database `TEMP` privilege; no universal DDL-denial claim follows.

A separate runtime writer can reconnect and commit data changes without the attachment.
Fresh connections observe its changed ciphertext, replayed historical frame after a legitimate application update, NULL substitution, and deletion.
Sync/async attached reads reject changed ciphertext but accept the older authenticated value, nullable NULL, and row absence.
This proves the tested schema privilege separation and read-time tamper refusal. It does not prove writer exclusion, freshness, presence, completeness, or host authorization.
Deployment enforcement, lifecycle-metadata permissions, provider custody, and independent review remain UNKNOWN.
The [runtime verification receipt](_reset/slice3-runtime-verification.json) records hashes, cases, grants, and limits.
Product source, all existing tests, both earlier receipts, and `spikes/revamp` remain unchanged.
All fixture schemas were removed. No roles or global grants changed. Slice 4 was not started.
All seven full gates remain **UNKNOWN**. This run stops at the local slice 3 checkpoint.

### Earlier prerequisite failures (historical)

The completion above supersedes these connection and role-availability blockers. The records remain preserved.

**BLOCKED advancement:** separate non-owning runtime credentials are unavailable. `cryptalis_runtime` is absent;
the only additional membership reported is the built-in non-login role `pg_database_owner`. No roles or permissions were added.
The fixture owner cannot prove runtime privilege isolation or deployment writer exclusion.
Finish this slice with provisioned restricted runtime access, native CRUD controls, and DDL/ownership refusal evidence before slice 4.

**Latest connection recheck, 2026-10-08 19:40 UTC:** this agent process has `CRYPTALIS_TEST_DATABASE_URL` set,
but psycopg reports `FATAL: password authentication failed for user "cryptalis_migrator"`.
Neither `CRYPTALIS_TEST_RUNTIME_DATABASE_URL` nor `CRYPTALIS_RUNTIME_DATABASE_URL` is set in this process.
The runtime connection could not be attempted. No fixture, privilege, or runtime test ran during this recheck.
The earlier role-catalog observation above is historical; this attempt does not establish whether the runtime role now exists.
Resume in a process that receives both working connection variables. Do not put credentials in repository files or diagnostics.

**Connection recheck, 2026-10-08 20:04 UTC:** both `CRYPTALIS_TEST_DATABASE_URL` and
`CRYPTALIS_TEST_RUNTIME_DATABASE_URL` are present in this agent executor.
One psycopg connection attempt per role returned `SELECT 1 = 1` for the runtime connection.
The migration connection failed with `FATAL: password authentication failed for user "cryptalis_migrator"`.
The required two-connection prerequisite did not pass. No database objects changed and no runtime tests ran.
Authorized CRUD, DDL/ownership denial, and sync/async attachment under separate runtime credentials remain unverified.
This recheck supersedes the earlier missing-runtime-credentials observation; it does not establish role privileges.
Supply working migration credentials privately, then recheck both connections before fixture work.
The [connection receipt](_reset/slice3-runtime-recheck-20261008T200458Z.json) records the exact failure and preservation snapshot.

The historical million-row anomaly remains UNKNOWN. No production provider, independent review, deployment admission,
transition executor, search rewriting, rotation, or release qualification follows from this checkpoint.
All seven full gates remain **UNKNOWN**. See the [walkthrough](walkthrough-sqlalchemy.md).

## Slice 2 checkpoint: 2026-10-08

**IMPLEMENTED:** `cryptalis.crypto` seals and authenticates bounded text with trusted compiler descriptors and prepared keys.
It uses library AES-256-GCM-SIV, HKDF-SHA-256, and full HMAC-SHA-256.
Strict UTF-8 preserves exact text. SQL NULL remains SQL NULL. The encoded text limit is 16 MiB.
The product implements storage-only and packed equality frames, UUID/bigint records, and both declared tenancy codecs.
It rejects unknown flags, companion representations, malformed frames, missing generations, and invalid text.

`Keyring` pins a finite policy and exact provider identities. Frame headers cannot select provider authority.
Sync and async preparation publish keys only after all roots pass checks.
The cache has fixed expiry, with a 60-second default and 300-second maximum. Access does not extend it.
Inherited providers and keys refuse use after fork. A child can create and prepare fresh local material.
The ephemeral development provider wraps, unwraps, and rewraps roots in memory.
[Security](security.md#implemented-cf1-primitives-and-local-custody) owns these operational limits and APIs.

**VERIFIED:** the focused CF1 suite returned **30 passed**, including **eight real PostgreSQL persistence cases**.
The full suite returned **736 passed** with `.venv/bin/python -m pytest -q --tb=short`.
The environment uses PostgreSQL 16.15, Python 3.12.3, cryptography 50.0.2, SQLAlchemy 2.1.3, and psycopg 3.3.6.
Those cases compare recovered values with native text under actual compiled descriptors.
They cover both frame formats, both record codecs, and both tenant codecs, including nil UUIDs and bigint endpoints.
Eight frozen CF1 vectors use a separate RFC 8452 reference with OpenSSL AES blocks and separate HKDF/HMAC code.
Published RFC 8452, RFC 5869, and RFC 4231 vectors check that reference and the installed primitives.
The fixture reproduction command is `.venv/bin/python tests/reference_cf1_vectors.py`.

Attack and failure cases cover byte changes, relocation, wrong roots, retirement, expiry, failed/canceled preparation, and fork.
Local rewrap preserves existing frames. Failure diagnostics exclude supplied secrets and raw provider errors, including during RNG failure.
AI review found and corrected nil-UUID refusal and writable-policy retention of old cache entries.
AI review does not replace independent human security review.

**Limits at slice 2:** SQLAlchemy attachment, query rewriting, database transitions, and deployment rotations remained pending.
The slice 3 checkpoint above records the later bounded attachment evidence.
The local provider cannot recover after process loss. No production provider exists.
SQL NULL substitution and same-context replay remain accepted scope limits.
Remote cancellation, custody, independent recovery, usage bounds, collision assumptions, and independent review remain unqualified.
All seven full release gates remain **UNKNOWN**.

## Slice 1 checkpoint: 2026-10-08

**IMPLEMENTED:** `cryptalis.manifest.compiler.compile_protection` parses field intent, resolves a supplied registry,
and inspects PostgreSQL catalogs. A fresh read-only transaction holds a repeatable schema snapshot.
Unqualified mappings resolve through the original PostgreSQL search path.
The result contains canonical lock bytes, a digest, and semantic changes. Compilation creates no database effects and reads no application values.

**VERIFIED:** `.venv/bin/python -m pytest -q --tb=short` returned **706 passed**, including **58 compiler cases**.
The compiler tests use PostgreSQL **16.15**, Python **3.12.3**, SQLAlchemy **2.1.3**, and psycopg **3.3.6** under the restricted disposable role.
They compare native schema and data before and after planning. They execute proposed additive DDL only in test-owned schemas.
A real INSERT injection fails with SQLSTATE `25006`, including through an AUTOCOMMIT engine.

This compiler admits native text, application-assigned UUID or bigint keys, explicit UUID tenancy or a single-tenant declaration,
and qualified native uniqueness. Storage-only fields need no search review or search collation.
Searchable fields require `pg_catalog.C` equivalence, matching leakage acceptance, and an explicit host review of the value domain.
Small or unknown domains block search. The host declares complete writer coverage and excluded routes. These records remain host assertions.

Known unsafe schemas and inconsistent prior locks raise typed errors.
The lock includes original admitted constraints, additive DDL, immutable context descriptors, and reader requirements.
A tenant change requires resealing. A SQL rename preserves the descriptor.
Missing or changed stable identities cannot silently replace existing identities.
[Architecture](architecture/README.md#implemented-compiler-syntax) owns the exact syntax.

**Slice 1 limits:** this checkpoint did not implement attachment, encryption, a provider, transitions, or runtime query rewriting.
Other ID codecs, protected varchar/custom types, non-UUID tenant columns, protected defaults, unsupported dependencies, and schema translation reject.
A new unique request needs a qualified native source constraint first.
The additive DDL does not qualify CF1 framing or authorize a switch.
External writer exclusion and domain assertions remain unverified. All seven full gates remain **UNKNOWN**.

## Approved scope and build order

[Approved decisions](decisions.md#approved-scope-decisions-2026-10-08) resolve scope-only D items. They do not supply implementation evidence.
Python 3.12+, SQLAlchemy 2.x, psycopg 3 sync/async, PostgreSQL 16 are the selected stack.
SUPPORTED design scope: text storage, equality, IN, and tenant-scoped uniqueness.
Each protected table declares a tenant column or declares itself single-tenant. Primary keys must be application-generated.
Plan rejects serial, identity, and database-default-generated keys, unsupported types, small-domain searchable fields, missing tenancy, and unsupported writers.
All other protected types/operators are UNSUPPORTED BY DESIGN until admission. Internal research helpers remain INTERNAL ONLY.

Implement one slice per run: compiler → crypto/KeyProvider/dev provider → sync/async SQLAlchemy → equality/IN/uniqueness
→ plan/apply/verify → decrypt-back/remove → three rotation operations. Each slice needs real PostgreSQL 16 tests before the next.
Range/order/prefix/text-search work starts only after all seven slices, then [six-gate admission](compatibility.md#capability-admission) and leakage opt-in.
The [build guide](build-guide.md#ordered-build-slices) owns behavior, invariants, tests, failures, and definitions of done.

### Targets and known performance work

SPECIFIED targets: added p95 ≤ 3 ms point/equality, ≤ 8 ms IN-20, and ≤ 2× protected-column-plus-equality-index storage.
VERIFIED, earlier revision: million-row equality p95 6.517 ms versus 0.928 ms native, IN-20 16.148 ms versus 1.093 ms.
Point p95 4.150 ms versus 0.897 ms also misses its added-latency target. These are known performance work, not achieved targets.
A plaintext range/prefix/page query with no protected column cost 127.098 ms p95 versus 23.852 ms, about 5.3× native.
Its cause is UNKNOWN and must be profiled in the SQLAlchemy integration slice.
The million-row and 10,000-row receipts both predate the latest DISTINCT change. Neither establishes current-adapter service cost.
The whole-relation storage ratio does not prove the isolated column/index target.
[Compatibility](compatibility.md#performance-targets-and-recorded-costs) owns exact measurements and accounting.
Write-throughput and pause are the only undecided budget categories (D). No numeric CPU/memory or adoption budget is invented.
Non-budget security decisions and every external/review requirement remain unresolved where stated below.

## Final gap audit: 2026-10-08

All seven full gates remain **UNKNOWN**. This historical gap record retains named local observations at their recorded scope.
The [audit supplement](../spikes/revamp/results/gate-gap-audit.json) records the latest delta without replacing any previous receipt.

One concrete local correctness gap existed: `SELECT DISTINCT` could compare randomized protected payloads instead of logical values.
The isolated spike now rejects protected SELECT DISTINCT and DISTINCT ON shapes, including nested selects and ORM entities.
The [offline admission probe](../spikes/revamp/run_gate_grammar.py) passes 13 checks. It preserves the scoped COUNT DISTINCT rewrite.
Its inert connection proves expression admission only. It bypasses the planner, provider, driver and PostgreSQL.
Complete grammar, actual database results and service regression of this latest change remain unqualified.

The [primitive vector probe](../spikes/revamp/run_crypto_vectors.py) passes nine checks against three published
[RFC 8452 Appendix C.2 vectors](https://www.rfc-editor.org/rfc/rfc8452.html#appendix-C.2).
It checks AES-256-GCM-SIV encryption, decryption and changed-tag rejection with cryptography 50.0.2.
These independent expected bytes qualify only those primitive cases. They do not freeze or qualify the CF1 composition.

The original [final verification receipt](../spikes/revamp/results/gate-final-verification.json) remains unchanged.
Its implementation-match assertions describe its recorded adapter revision, not the latest DISTINCT admission change.
The seven completed service probes, 35-check child and million-row measurements remain evidence for their recorded revisions.
That audit session recorded no database URL and did not repeat service probes or substitute another database.
The latest spike adapter needs focused real-service retrofit/boundary/async regression before a current-service claim.
The CF1 format, crypto path, transition code and indexes did not change. Their prior observations retain their recorded scope.
Neither prior costs nor these new offline checks measure the latest adapter's service performance.

### Missing evidence and promotion criteria

Classifications: **L** = locally obtainable now. **E** = external infrastructure, provider or deployment.
**H** = independent human/security review. **D** = explicit product/security decision or approved budget.
A local implementation task is not an external guarantee. Unimplemented contracts remain gaps even when their development needs no cloud service.
No promotion occurs until every applicable criterion passes for an identified release artifact and compatibility cell.

| Full gate | Exact missing evidence and classification | Required evidence before PASS |
|---|---|---|
| G-ADAPTER | SPECIFIED: stack, text/ID mapping scope and admitted grammar decisions resolve scope D. L: Implement that scope and plan-time refusals. E: Non-owning runtime credentials, external writer exclusion, exact selected cell and latest DISTINCT service regression | Use separate migration/runtime principals. Positive CRUD controls with application-assigned IDs must work. Plan must reject serial, identity and database-default-generated IDs before effects. Runtime DDL, lifecycle metadata mutation, schema ownership and privilege escalation must fail. Inventory every writer credential/route. Prove excluded writers cannot reconnect or write during maintenance. Compare native/protected results, types, ORM state and async behavior for every admitted shape. Reject other shapes before SQL. Run the latest code on the exact OS/interpreter/SQLAlchemy/driver/PostgreSQL cell. The selected PostgreSQL 16 cell and each managed service need their own suite. Other majors remain UNSUPPORTED BY DESIGN until admission |
| G-CRYPTO | L: Primitive vectors now pass. D/H: Freeze admitted text/ID descriptors and nonce/aggregate usage limits. L after those decisions: Full independent CF1/KDF/HMAC/companion vectors. D/E: Fork invalidation and fresh preparation under the selected provider. H: Composition review | Publish expected intermediate and final bytes from an independent reference for every admitted codec/format. Check malformed bounds, context relocation, exact-key resolution and companion changes. Implement fork invalidation and test a child cannot use inherited material before fresh preparation. A reviewer must approve nonce/key lifetime limits, collision assumptions and cross-key behavior. Resolve material review findings. Primitive vectors and same-library roundtrips cannot satisfy this gate alone |
| G-QUERY | SPECIFIED: text/equality/IN/tenant-uniqueness scope and read/storage targets resolve scope/budget D. D: Write-throughput budget. E: Exact PostgreSQL 16/service semantics. L: Admitted integration, leakage attacks, target measurements and anomaly profiling. Advanced evidence applies only after admission | Compare all admitted predicates, NULLs, constraints, joins, projections and pagination with native PostgreSQL. Exercise restricted-role built-in DDL and selective million-row plans. Run published attacks for each admitted advanced representation with dataset and attacker assumptions. Measure per-capability table/index/temporary storage, sustained writes and GIN maintenance where applicable. Meet the approved added-p95 read and isolated column/index storage targets. Measure throughput, CPU and memory. Write-throughput remains D, without an invented threshold. Profile the unexplained plaintext-page overhead on the current revision. Plaintext age/name queries and physical arrays cannot qualify encrypted advanced fields |
| G-LIFECYCLE | E: Deployment-wide exclusion, durable independent recovery, retained readers/keys, actual disk/WAL faults and external provider transforms. D: Upgrade compatibility and pause budget. SPECIFIED: storage target resolves storage-budget D. L after implementing a versioned reader contract: Upgrade/rollback and pre-switch abort | Kill an executor and resume in an independently started process with no inherited keys or attachment. Restore a real retained backup using immutable reader/lock/wrapper artifacts and the designated provider. Compare full current membership, values, types and constraints. Upgrade mixed old/new formats under stopped writers. Inject failures before and after database/artifact switch. Transform current edits back without snapshot loss. Unsupported old types or missing keys must block rollback. Induce real bounded disk/WAL exhaustion, temp-space failure, memory/CPU pressure and timeouts on a disposable isolated target. Prove no switch, atomic failed chunks, retained completed chunks and inspected resume. Test provider rewrap/rotation and backup dependencies before retirement. Package-free removal must preserve current data and retained obligations |
| G-PROVIDER | D: Select provider, key topology and cache policy. E: Real workload identity, custody, remote cancellation, recovery and deletion. H: Identity/cache/destruction review | Exercise exact wrap/unwrap/rewrap context and wrong provider/key/workload identities. Test cold, warm, expired, disabled, outage and canceled remote calls. Discard late material and inspect ambiguous native effects before retry. Recover roots in an independent process. Observe native deletion completion, cached-use limits and every retained wrapper/backup recovery route. A deletion request or local random KEK is insufficient |
| G-POLICY | D: Select the trusted host publication/restore procedure. E: Authenticated policy startup, target binding, stale workers and quarantine | Use the real authenticated deployment artifact outside database restore. Interrupt both database/artifact switch boundaries. Keep writers stopped and deny mismatches until inspection completes publication. Reject wrong targets, old artifacts and restored old policy. Prove old workers and alternate credentials cannot resume writes. Restore in quarantine with current host authorization, then admit only a fully matched representation. The local attachment's immediate installation does not enforce this host procedure |
| G-RELEASE | SPECIFIED: approved release scope and read/storage targets resolve those D items. D: Write-throughput and pause budgets. H: Independent human reviews with resolved findings. E: Controlled release identity, build and publication. L after the runtime artifact exists: Locked hashes, SBOM and artifact inspection | Satisfy all applicable gates and the engineering release gate. Supply named review reports, material-findings resolutions and accepted residual risks. Compare the same backend in hot/cold/outage and lifecycle workloads against approved budgets. Count actual model, business-query, writer, deployment and operator changes. Inspect the exact wheel/sdist, dependencies, hashes, SBOM and provenance. Test old-reader compatibility and critical-flaw recovery. Verify controlled publication identity and security-response ownership. Existing research-package artifacts do not qualify an unbuilt runtime |

### Adversarial consistency findings

The recorded audit compared the isolated implementation, its then-current probes, gate definitions, status, security, compatibility, lifecycle and final receipts.
The latest SELECT DISTINCT rejection corrects a fail-open grammar case. Earlier references to rejected grammar cover only their listed cases.
Scoped COUNT DISTINCT evidence never established general SELECT DISTINCT or GROUP BY support.

The lifecycle checkpoint's source-constraint observation covers inspected source index definitions, validity/readiness and the fixture's scoped uniqueness.
It is not generic CHECK/FK/default/collation or dependency preservation. The executor has no format-upgrade or pre-switch abort path.
Its writer inventory is a caller assertion. Advisory and chunk/table locks cannot exclude unrelated credentials between chunks.
`retained_local_backup_reader_route` decodes an in-memory row copy with the same live provider. It proves neither backup durability nor independent recovery.
Fork-inherited restart retains authority. The package-free child proves plaintext exit, not encrypted backup recovery.
Injected division-by-zero and local-provider failures do not establish storage-exhaustion or resource-pressure behavior.

Public CLI remedies, authenticated startup/publication, production custody and artifact provenance remain intended contracts.
Local database switching remains `SWITCHED_DATABASE_POLICY_PENDING`. It is not production activation.
No new public configuration, provider identity, deployment service or security guarantee results from this audit.
This documentation-only pass authorizes no runtime changes. The unimplemented and external criteria remain explicit blockers.
The seven criterion rows remain seven UNKNOWN rows. Rows with unresolved D criteria change from seven to six because G-ADAPTER scope is resolved.
The remaining D items are non-budget security/authority decisions and the two undecided budget categories, not reopened scope decisions.

## Current integrated checkpoint: 2026-10-07

**VERIFIED, recorded 2026-10-07 spike revision:** this checkpoint supersedes older observations only for its listed cases.
The implementation remains isolated under `spikes/revamp`; the public package is unchanged.
All seven full gates remain **UNKNOWN**. No production compatibility cell is qualified.

The spike attachment protects one declared `Customer.email` field in the original three-model application.
Its original 29 assertions remain unchanged. Adoption uses one manifest and attachment, zero model/query edits,
and one opaque SQL writer changed to an equivalent typed Core update. Age/name range, prefix and ordering queries
remain ordinary plaintext queries. This is not encrypted advanced-query evidence.

| Final service command under `spikes/revamp/` | Observed checks | Scope |
|---|---:|---|
| `run_gate_retrofit.py` | 51 | Original application, historical generated int32 identities (outside approved scope), native values/state, bulk and guarded raw/COPY rejection |
| `run_gate_boundary.py` | 25 | Bound/reverse predicates, NULL/membership, aliases, scoped DISTINCT, tenant moves, concurrent sequence/uniqueness and rejected grammar |
| `run_gate_async.py` | 14 | Native AsyncSession, generated relationships/bulk, streaming, task isolation, real driver cancellation/recovery and guarded raw paths |
| `run_gate_context.py` | 48 | Host-requested point, typed context, malformed frames, inventory/schema mismatch, unsupported multi-field plans and local cache/outage/generation failures |
| `run_gate_lifecycle.py` | 23 | 1,000 rows; interrupted/resumed chunks, real lost COMMIT reply, verification mutants, rotations, current-data rollback and removal |
| `run_gate_faults.py` | 13 | Real SQL failure, injected local-provider failure, atomic marker/data rollback and expression/admission-spoof rejection |
| `run_gate_write_cost.py` | 2 | Earlier adapter revision before latest DISTINCT change; identical paired workloads and committed 400-row update readback on 10,000 rows |
| `run_gate_performance.py` | 3 | One million actual CF1 rows, exact results/NULL membership, selective equality index and paired application costs |

The million-row receipt was reused after assignment-admission fixes because the CF1 representation and index expression did not change.
The smaller cost run measures that changed adapter before the latest DISTINCT fix. Both remain earlier-revision evidence. The lifecycle fresh child also passes 35 checks:
all 29 original assertions, four blocked crypto/package imports, full current-data/type comparison and an ordinary committed edit.
Every final service suite removes only its owned schema. Sanitized receipts are linked from the [experiment guide](../spikes/revamp/README.md).
The recorded **612-passing-test** result and historical document/link/inventory checks are retained evidence, not repeated here.

| Full gate | Verdict | Exact remaining reason |
|---|---|---|
| G-ADAPTER | UNKNOWN | Non-owning runtime principal and external writer exclusion are unqualified; approved app-assigned-ID/text/tenant mappings, complete admitted grammar, plan refusals and selected cell remain pending |
| G-CRYPTO | UNKNOWN | Frozen independent admitted text/ID vectors, nonce/usage/fork bounds and independent human composition review remain pending |
| G-QUERY | UNKNOWN | Complete admitted PostgreSQL 16 semantics, leakage evidence, read/storage target measurements and anomaly profiling remain pending. Write-throughput remains D; advanced queries remain out of scope until admission |
| G-LIFECYCLE | UNKNOWN | Real deployment writer exclusion, independent fresh-process recovery/backup reader provenance, format upgrades, storage exhaustion and external provider transformations remain pending |
| G-PROVIDER | UNKNOWN | The user has selected no production provider. Memory-only local functional evidence cannot qualify custody, native deletion or remote cancellation |
| G-POLICY | UNKNOWN | The user has selected no deployment procedure. Authenticated publication/startup pin, stale workers, restore quarantine and restored-old-policy denial have no executable host evidence |
| G-RELEASE | UNKNOWN | Independent human review is unavailable (`external-review-required`); write-throughput/pause budgets and locked artifact/provenance qualification remain pending |

`cryptalis_runtime` is absent. The migration login is restricted but owns these fixtures; it cannot prove non-owning runtime enforcement.
An independent privileged driver can still bypass attachment. Unknown or unexcluded writers now block the local plan before transformation.
The database transition reports `SWITCHED_DATABASE_POLICY_PENDING`; it does not invent an authenticated external publication.
The memory-only keyring cannot recover after independent process/provider loss. Fork-inherited lab recovery does not prove that route.
The spike tests a 16 MiB UTF-8 bound, narrower than unbounded PostgreSQL varchar. It does not freeze the product text bound.
Its sequence-generated IDs conflict with the approved application-generated-key contract. Refusal of those schemas remains an implementation gap.
Unknown collation/default/constraint semantics must reject rather than silently change results.
Same-context replay, nullable-field substitution with SQL NULL and hostile omitted rows remain the explicit [security limits](security.md).

## Existing package

The current package has the product compiler, CF1 primitives, and bounded SQLAlchemy attachment above, structural record decoding/canonicalization, bounded manifest/header inspection,
local crypto/search examples, and local transition-admission research.
The slice 3/4 attachment supplies stated storage and search behavior only within the tested boundaries above.
These APIs do not qualify managed key custody, safe deployment admission, or production lifecycle.
Architecture drives replacement. Existing research formats and tests are not permanent runtime requirements.

The existing suite returned **612 passed in 7.95 s**, exit 0, after canonical documentation replacement.
No production source, test, fixture, dependency, build, container, or CI file changed in this revamp pass.
The starting dirty AGENTS/playbook edits and deleted files remain preserved.
The service continuation reran `.venv/bin/python -m pytest -q`: **612 passed in 15.59 s**, exit 0.

## New isolated evidence

**VERIFIED, historical research only:** earlier SQLite/public-hook experiments, single-user PostgreSQL physical probes,
CF1 text fixtures, restricted-service probes, synthetic frequency attacks, and current-data decrypt-back supplied narrow observations.
Their raw receipts and exact counts remain in [spikes](../spikes/revamp/README.md) and [archived provenance](research/revamp-evidence.md).
All these mechanisms are INTERNAL ONLY. Non-text algorithms, encrypted range/prefix arrays, shared joins, and generated-ID candidates do not change approved scope.
The 2026-10-07 integrated checkpoint above supersedes only the specific earlier limitations for which it records new evidence.

Historical surrogate bundle storage was about 5.5× its control. That bundle includes different representations/indexes and does not measure the selected equality column target.
Frequency attacks recovered 100% of synthetic equality/prefix classes and rows, and 27.211% of range rows under the recorded auxiliary-distribution assumptions.
These rates do not predict customer recovery. Structural/order attacks remain unexecuted and required for their applicable advanced admission.
Local rewrap/policy models do not qualify mature-provider custody, authenticated host publication, independent recovery, or deletion.
Raw-driver negative controls demonstrate that separate privileged writers can bypass attachment. Full writer exclusion remains UNKNOWN.

## Blocking evidence

Slices 1–5 have bounded product evidence for app-assigned-key planning, storage/search admission and protection transitions.
Earlier receipts omit grouped and callable primary-key binds; their row-isolation claims do not cover those forms.
The [corrective checkpoint](#corrective-audit-checkpoint-2026-10-09) records their repair. No runtime release is qualified.

Full independent recovery, deployment writer exclusion, retained-backup readers, format upgrades,
real resource-exhaustion faults, production provider custody, authenticated policy publication/restore, and independent review remain required.
[Gate criteria](#missing-evidence-and-promotion-criteria) state the deciding observations without restoring the deleted control plane.
No production provider is designated. The local provider is functional evidence only.
G-PROVIDER, G-POLICY, all review requirements, and the [release gate](../ENGINEERING_PLAYBOOK.md#release-gate) remain UNKNOWN.
