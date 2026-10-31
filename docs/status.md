# Current implementation status

Cryptalis implements a bounded research prototype. **No production release or compatibility cell is qualified.**
This page owns current verification and release gates; the [34-objective ledger](BUILD_CHECKLIST.md) owns remaining work.
Use the [documentation map](README.md) to find contracts and procedures.

**Latest complete hosted pass: `be836b0`.** Both jobs in
[run 41245812702](https://github.com/Debrato2005/cryptalis/actions/runs/41245812702)
pass for aware timestamps and UTC order. The full source run passes 3,800 test
calls and 18 subtests. Twenty call skips, 41 setup skips and eight collection
skips remain explicit. All 303 recorded Python files match that revision and
source/runtime stability passes. The installed recovery job passes; wheel and
sdist match the retained local timestamp artifacts.
[Exact hosted boundary](_reset/github-timestamptz-green-20261101.json).
The preceding [numeric source failure and repair](_reset/numeric-compiler-ci-boundary-20261101.json)
remain retained.

**Earlier complete hosted pass: `54218cf`.** Both jobs in
[run 41239335699](https://github.com/Debrato2005/cryptalis/actions/runs/41239335699)
pass for naive timestamp storage and ordering, before the subsequent MIN/MAX slice.
The [storage run 41238374566](https://github.com/Debrato2005/cryptalis/actions/runs/41238374566)
also passes at `d828a94`.
The preceding [run 41236215265](https://github.com/Debrato2005/cryptalis/actions/runs/41236215265)
also passes at `1aee8b9`. The earlier
[failed run at `10b3c78`](https://github.com/Debrato2005/cryptalis/actions/runs/41232706573)
retains the Doctor procfs observation race; the
[test-only repair](_reset/doctor-timeout-race-boundary-20261101.json) passes local
checks and the complete hosted rerun. [Hosted result](_reset/github-doctor-timeout-green-20261101.json).
The preceding [run 41227354271](https://github.com/Debrato2005/cryptalis/actions/runs/41227354271)
at `bc94495` records the parallel source job taking about 9 minutes and passing
3,622 test calls and 18 subtests, with 12 call
skips, 41 setup skips and 8 collection skips across 3,675 selected items. No skipped cell is
qualified, and all seven production gates remain UNKNOWN.

Test pruning is **not fully proven safe**. The [follow-up audit](history/verification-2026-11-01.md)
replays the ten previously unresolved mutations in an isolated copy. Nine produce
relevant failures after strengthening saved-plan and tenant-policy regressions.
The extra sealed-value tenant check survives the selected driver attacks;
equivalence is not proven and the guard remains. Healthy focused checks pass 79
tests and 18 subtests; the full Project module passes 70 tests with seven explicit
skips. [Machine boundary](_reset/pruning-audit-boundary-20261101.json).

The previous `1c7b8e0` run on `main`, [41192438108](https://github.com/Debrato2005/cryptalis/actions/runs/41192438108),
passes 4,216 test calls and 18 subtests with 12 call skips, 86 setup skips and 18 collection
skips across 4,314 selected items, which closes the missing clean full-source rerun noted below.

The earlier `2900173` run below keeps its retained receipts. The original `2d53867`
source-role failure and later UUID fixture failures remain repaired.
[Retained failure](_reset/github-point-update-returning-failed-boundary-20261030.json)
and [repair evidence](_reset/point-delete-returning-ci-fix-boundary-20261030.json)
remain available.

## Finite NUMERIC equality, IN and scoped uniqueness

**VERIFIED, bounded source and installed wheel:** finite NUMERIC search uses
full HMAC terms under lock/v13 and `pg-numeric-equality/v1`. Equality ignores
scale and signed zero; authenticated payloads retain native fractional scale.
Native oracles cover unrounded query pivots, inferred/mixed/expanded integer
bind casts, NULL logic, aliases, predicate results, DISTINCT representatives and
counts, sync/async CRUD, savepoints and concurrent uniqueness. PostgreSQL
canonical bytes also match a separate HMAC/framing path using the same AEAD
backend.

The affected source regression passes 397 calls, with eight call skips and one
collection skip. The clean Python 3.12 wheel passes 132 calls with two skips.
Actual v12 reader controls execute: numeric storage is accepted and v13 search
refuses before SQL. All rotations and current-value native exit pass in both layouts. Separate
profiles verify enable/disable/reenable and online capture with incomplete-catch-up
refusal, inspection and resume. Both installed fresh-cluster layouts pass
export, isolated adoption, tamper refusal, current edits, removal and an
import-denied native restart. All final inventories match the same 306 Python
files and 43-module runtime. Repeat artifacts, SBOM, 48 installed files and CLI
inspection pass. [Exact boundary](_reset/numeric-search-boundary-20261101.json)
retains failures, test repairs, scopes and skips.

The complete hosted run for this slice is pending. Numeric order/ranges,
arithmetic, nonfinite values, broader coercions, performance acceptance and
independent human review remain open. All seven production gates stay UNKNOWN.

## Native aware timestamp storage and order

**VERIFIED, bounded source and installed wheel:** timezone-bearing DateTime and
TIMESTAMP mappings preserve native UTC instants, actual-connection timezone,
offset and DST fold. Native comparisons cover sync/async CRUD, RETURNING,
defaults including uncached ZoneInfo, delayed results across replaced pools,
order/ranges/IN, aliases and direct MIN/MAX. Fold/scale provider mutations and
public datetime driver mutations refuse before dispatch. PostgreSQL binary
payload bytes match a separate framing decoder using the same AEAD primitive.

The affected source regression passes 407 tests with eight explicit earlier-reader
skips; the installed Python 3.12 wheel passes 153 with four skips. The actual v11
reader accepts a Numeric control and refuses v12 before SQL. Both installed
fresh-recovery layouts pass all rotations, tamper refusal, owned-sequence drift
refusal/OID binding, current counter/value removal and an import-denied native
restart. All final receipts bind identical 43-module runtime bytes. Reproducible
artifacts, SBOM, 48 installed files and CLI inspection pass.
[Exact boundary](_reset/timestamptz-boundary-20261101.json) retains failures and
limits. The complete hosted run is recorded above. Naive coercions,
custom tzinfo, other precisions, broader queries, performance and independent
review remain open; all seven production gates remain UNKNOWN.

## Finite native NUMERIC storage

**VERIFIED, bounded source and installed wheel:** standard Numeric/NUMERIC
storage preserves native finite Decimal values, declared precision/scale,
rounding, NULLs, literal default state, sync/async CRUD and RETURNING. Native
oracles cover negative scales, scales larger than precision, full digit bounds,
savepoints, constraint-error precedence and prepared zero-match behavior.
Authenticated values incompatible with the pinned typmod refuse before release
or decrypt-back. Online capture preserves current writes, resume and explicit
nonfinite-row failure with readable progress.

The affected source regression passes 337 checks with ten explicit older-reader
skips; the installed Python 3.12 wheel passes 146 with four skips. An actual
retained v10 reader accepts a timestamp control and refuses numeric before SQL.
Both installed fresh-recovery layouts pass export, adoption, rotations,
current-value removal and an import-denied native restart. All final receipts
bind identical runtime bytes; reproducible artifacts and installation inspection
pass. [Exact boundary](_reset/numeric-storage-boundary-20261101.json) and
[observations](history/types-2026-11.md#finite-native-numeric-storage-2026-11-01)
retain failures, limits and hashes. No complete local full-suite rerun follows
this slice. Numeric search/arithmetic, nonfinite support and broader mappings
remain open; performance and all seven production gates remain UNKNOWN.

## Native naive timestamp storage

**VERIFIED, bounded source and installed wheel:** standard timestamp without time
zone at default precision or explicit precision 6 now uses the existing CF1 and
lifecycle paths. Native comparisons cover sync/async CRUD, literal defaults,
RETURNING, all rotations, both layouts and latest-value removal. Source and
installed online scalar profiles each pass 18 checks; the installed scalar/CF1
regression passes 233 checks with eight explicit skips. Genuine fresh recovery
and an import-denied native restart pass for Timestamp and the existing Date
profile. [Exact boundary](_reset/timestamp-boundary-20261101.json) and
[observations](history/types-2026-11.md) retain failures and source/runtime hashes.
Explicit opt-in timestamp order now passes 71 focused source checks (two
explicit skips), 40 installed checks and 20 source online scalar checks. Native
comparisons include microsecond boundaries, ranges, sorting, pagination, async,
rotations, profile changes and current-value removal. An actual retained v10
storage reader accepts storage plans and refuses timestamp order before SQL.
Timezone-bearing bind casts refuse after a native DST counterexample.
[Order evidence](_reset/timestamp-order-boundary-20261101.json).
Other precision/default forms remain open; aware mappings follow their separate
[contract](compatibility.md#aware-timestamp-storage).
No production gate changes; all seven remain UNKNOWN.

## Direct authenticated MIN/MAX

**VERIFIED, bounded source and installed wheel:** direct MIN/MAX on opt-in order
fields matches native signed integer, Date and naive timestamp results, including
NULL/empty sets, ranges, aliases, original expression/label keys, async, rotations,
profile changes and current-value removal. Scope, selected-packet tamper and
explicit result-conversion controls pass. The source aggregate/search regression
passes 227 checks; the installed aggregate regression passes 152, and the source
online scalar profile passes 20. All bind identical runtime bytes. Reproducible
artifacts and inspected installation pass. [Exact boundary](_reset/extrema-boundary-20261101.json).
This scans opaque packets in PostgreSQL with constant aggregate state; no speed
acceptance or new fresh-recovery claim follows. Grouping, window/FILTER forms,
protected expressions and explicit result-type overrides remain open. All seven
production gates remain UNKNOWN.

## Local Git consolidation: 2026-10-31

**VERIFIED, bounded:** consolidation retains main `f082cf3`, pushed work
`585300c`, and completion merge `19657a6`. Original PRs #1/#2 are merged.
The [boundary record](_reset/consolidation-boundary-20261031.json) preserves
exact receipts and failures. The complete source run passes 4,128 tests and
18 subtests, with 154 skips; two merged test-helper cases fail. Restoring the
missing helper branches and earlier internal cases passes all 169 predicate
checks. Product and script bytes remain unchanged after that repair.

The inspected installed wheel passes **653 checks**, with three explicit skips,
including native SDKs, HTTPS OpenBao, ORM/SQLModel and packaged Doctor behavior.
Full-run, repaired-module and installed receipts bind identical runtime bytes.
The reproducible artifact check verifies hashed build inputs, SBOM, CLI and 55
installed files. No clean local full-source rerun follows the test-only repair;
hosted run 41192438108 above supplies that full run. Historical hosted results below
retain their own revisions; main-history merge
`19657a6` also passes [hosted CI](https://github.com/Debrato2005/cryptalis/actions/runs/41186233396).
Skipped cells and all seven production gates remain UNKNOWN.

## Retained complete CI qualification

**VERIFIED at `290017371aed0caf79b9d59eb2bed6d2829acdc2`:** GitHub
[run 41095408264](https://github.com/Debrato2005/cryptalis/actions/runs/41095408264)
passes Source / PostgreSQL 16 and Reproducible artifacts / installed recovery.
The [retained CI boundary](_reset/github-boolean-negation-boundary-20261030.json)
binds GitHub archive digests and actual source/installed receipts to this revision.

The complete default source run passes 3,700 test calls and eighteen subtests.
Twelve call skips, 86 setup skips and eighteen collection skips remain explicit;
all 3,798 selected items complete. All 313 Python hashes match the recorded checkout,
and source/imported-runtime stability passes. No skipped cell is qualified.

The installed wheel passes 15 code-inventory and 676 ORM/configuration/status
controls, 50 Google SDK and 149 OpenBao/provider checks, four exports and five
genuine fresh PostgreSQL recovery checks. Local and GitHub wheel/sdist hashes
are identical. Repeat archives, SBOM, installed-file inspection and dependency
consistency pass. The frozen audit reports 39 packages, zero known vulnerabilities
and zero adverse statuses; this is not proof of absence of unknown vulnerabilities
or independent review. [Earlier CI](_reset/github-point-update-rows-boundary-20261030.json)
remains retained. The separate performance profile fails latency targets;
passing default CI does not qualify performance.

The 34-objective [ledger](BUILD_CHECKLIST.md#objective-ledger) retains seven
bounded VERIFIED entries, 23 PARTIAL entries, one SPECIFIED, one BLOCKED, one
IMPLEMENTED and one ONGOING. These are implementation labels, not production
completion. Remaining work includes broader manifest/host integration,
ORM/query/type coverage and lower-leakage research, complete route inventory,
versioned upgrades, authenticated deployment/failover authority, retained-backup
obligations and controlled destruction, production provider identity/audit/HA,
combined disaster drills, and performance acceptance. Independent human review
remains unavailable; selected live cloud cells need authorized accounts.
All 34 objectives remain in scope and all seven production gates remain UNKNOWN.

<a id="named-single-record-returning-results"></a>
<a id="named-returning-results"></a>
## Current ORM boundary

**VERIFIED locally, source and installed wheel:** the
[point UPDATE values boundary](_reset/point-update-values-boundary-20261030.json)
admits ordinary scalar `.values(...)` assignments for one exact typed record,
with explicit tenant equality or declared fixed scope. Mapped keywords and
mapped/physical column dictionaries use the existing prepared encryption and
final driver checks. External parameters must be omitted for this form.

Assignments are captured before key preparation and rechecked afterward,
including async preparation. An owned statement copy receives encrypted values;
the caller's original statement remains reusable. Native SQLAlchemy/SQLModel
sync/async journeys preserve affected-row counts, NULL, supported types, stale
identity/refresh behavior, savepoints, SQLSTATE failures and current-value
removal. The real OpenBao journey exercises returned and non-returned updates.

The owned compiler selects authenticated RETURNING readers while preserving
original ORM projection objects. INSERT and point UPDATE/DELETE results retain
lookup by the caller's original label objects and native string keys. Existing
record/tenant and exact prepared-frame authentication remain enforced.

The final focused source run passes 55 new workflow and boundary checks. The
broader run passes 444 controls and retains four INSERT fixture failures from
an UPDATE-only synchronization option; that fixture is corrected in the final
run. Product and script hashes are identical between those two runs. Earlier
receipts retain the missing capability, native column-key normalization, ordered
assignment guard and original-label lookup failures and their subsequent fixes.

Installed qualification passes 783 application controls, 15 Doctor checks,
50 Google checks, 149 real OpenBao/provider checks, four exports and five genuine
fresh PostgreSQL recovery checks. All final inventories bind the same 315 Python
files, with stable source and imported runtime bytes. Reproducible artifacts,
SBOM, installed-file inspection and dependency consistency pass.

[Boolean NOT and predicate-result keys](_reset/boolean-negation-boundary-20261030.json),
[point UPDATE row counts](_reset/point-update-rows-boundary-20261030.json),
[named INSERT results](_reset/insert-labels-boundary-20261030.json) and
[named point UPDATE/DELETE results](_reset/returning-labels-boundary-20261030.json)
retain their bounded contracts. Mixed embedded/external assignments, explicit
SQL/bind expressions, ordered assignments, upserts, broader DML, protected
joins/grouping and unsupported search leaves remain open. All seven production
gates remain UNKNOWN; performance and independent review are unqualified.

## Bounded capability evidence

The current contracts below define admitted behavior. Detailed checkpoint
counts, failures and limits live in history and their retained machine receipts;
they do not qualify a production release.

| Capability | Current contract | Retained verification |
|---|---|---|
| <a id="disable-search-while-retaining-encryption"></a>Disable search while retaining encryption | [Search-profile lifecycle](lifecycle.md#enable-exact-search-on-active-encrypted-text) | [Evidence](history/implementation-2026-10.md#retained-2026-10-30-disable-search-while-retaining-encryption) |
| <a id="modification-query-preflight"></a>Modification query preflight | [Application configuration](application.md#modify-active-fields) | [Evidence](history/implementation-2026-10.md#retained-2026-10-30-modification-query-preflight) |
| <a id="active-field-search-modification"></a>Active-field search modification | [Application configuration](application.md#modify-active-fields) | [Evidence](history/implementation-2026-10.md#retained-2026-10-30-active-field-search-modification) |
| <a id="single-record-delete-returning"></a>Single-record DELETE RETURNING | [ORM compatibility](compatibility.md#full-capability-matrix) | [Evidence](history/implementation-2026-10.md#retained-2026-10-30-single-record-delete-returning) |
| <a id="single-record-update-returning"></a>Single-record UPDATE RETURNING | [ORM compatibility](compatibility.md#full-capability-matrix) | [Evidence](history/implementation-2026-10.md#retained-2026-10-30-single-record-update-returning) |
| <a id="orm-process-ownership"></a>ORM process ownership | [Process contract](compatibility.md#process-ownership) | [Evidence](history/implementation-2026-10.md#retained-2026-10-30-orm-process-ownership) |
| <a id="static-python-route-inventory"></a>Static Python route inventory | [Doctor inventory](walkthrough-migration.md#inventory-python-code-routes) | [Evidence](history/implementation-2026-10.md#retained-2026-10-30-static-python-route-inventory) |
| <a id="shared-application-configuration"></a>Shared application configuration | [Application configuration](application.md) | [Evidence](history/implementation-2026-10.md#retained-2026-10-30-shared-application-configuration) |
| <a id="google-cloud-kms-sdk-boundary"></a>Google Cloud KMS SDK boundary | [Google provider](google-kms.md) | [Evidence](history/implementation-2026-10.md#retained-2026-10-30-google-cloud-kms-sdk-boundary) |
| <a id="openbao-workload-authentication"></a>OpenBao workload authentication | [AppRole contract](openbao.md#approle-workload-authentication) | [Evidence](history/implementation-2026-10.md#retained-2026-10-30-openbao-workload-authentication) |
| <a id="authentication-across-lifecycle-and-runtime"></a>Authentication across lifecycle and runtime | [Provider contract](openbao.md) | [Evidence](history/implementation-2026-10.md#retained-2026-10-30-authentication-across-lifecycle-and-runtime) |
| <a id="native-openbao-audit-boundary"></a>Native OpenBao audit boundary | [Audit contract](openbao.md#native-audit-configuration) | [Evidence](history/implementation-2026-10.md#retained-2026-10-30-native-openbao-audit-boundary) |

## Current performance boundary

Further optimization is deferred until functional objectives are implemented,
following the current user priority. Existing failures and targets remain recorded.

At `09c635a`, the matched warm 10k native/protected profile fails all six added-p95
read targets. Scalar/tuple point, equality and IN-20 add 4.898, 7.206 and 20.788 ms;
full-entity paths add 4.249, 7.504 and 9.262 ms. Targets remain 3/3/8 ms.
Indexed-column storage passes at 1.52483× against the 2× target. These are 100-pair
observations on a shared local host, not a deterministic regression diagnosis.

Diagnostic profiling identifies repeated query admission and expression traversal
as a material CPU cost. A per-admission scratch-cache candidate still failed all
targets and increased every paired median; it was discarded. The
[retained boundary](_reset/application-performance-boundary-20261030.json) keeps
both failed observations, the instrumented run, plugin and candidate patch.
The [dated analysis](history/implementation-2026-10.md#current-admission-cost-investigation-2026-10-30)
records limits. Performance acceptance remains open.

## Capability summary

| Area | Implemented boundary | Contract / instructions |
|---|---|---|
| Front door | `Project`: a manifest, key provider and state directory drive the whole lifecycle, with resume after a crash | [Project](application.md#project-the-small-api), [evidence](history/completion-2026-10-31.md#project-front-door-2026-10-31) |
| Application setup | One key-free configuration for diagnosis, protection/capture, tenant onboarding, active-field changes, rotations, attachment and removal | [Application configuration](application.md) |
| Manifest | Bounded JSON declaration, mapping/schema validation, generated locks and semantic diff | [Manifest](manifest.md) |
| Crypto | CF1 AES-256-GCM-SIV, random nonces, HKDF, independent HMAC search roots and authenticated context | [Security](security.md) |
| ORM/search | Bounded sync/async SQLAlchemy and optional SQLModel; exact/IN/uniqueness, opt-in [range and sorting](compatibility.md#order-search) on integers and dates, and explicitly admitted forms | [Compatibility matrix](compatibility.md#full-capability-matrix) |
| Lifecycle | Maintenance and bounded initial online protection, resumable verification, bounded active-field changes, three rotations, current-data reverse/removal, fresh restore/adoption | [Lifecycle](lifecycle.md), [operator walkthrough](walkthrough-migration.md) |
| Providers | Development custody, optional AWS/Google SDK adapters, local OpenBao AppRole/TLS/outage/revocation/snapshot evidence | [OpenBao](openbao.md), [Google](google-kms.md); no production custody qualification |
| Doctor | Pre-adoption schema/supplied SELECT checks, ACTIVE deployment admission, explicit cold-provider access | [Diagnosis](walkthrough-migration.md#diagnose-before-adoption), [provider checks](openbao.md) |

SUPPORTED selects an admitted design scope. VERIFIED applies only to the named
revision, artifact and compatibility cell. Neither means production-qualified.
Unimplemented capabilities remain obligations; safe refusal does not complete them.

## Missing evidence and promotion criteria

All seven gates remain UNKNOWN. Each requires current evidence for a named release
artifact and compatibility cell. Local work, external infrastructure, product
decisions and independent human review are separate prerequisites. Historical
passes, unavailable tests and AI reviews do not replace any requirement below.

| Gate | Status | Required evidence before PASS |
|---|---|---|
| G-ADAPTER | UNKNOWN | Use separate migration/runtime principals. Positive CRUD controls with application-assigned IDs must work. Plan must reject serial, identity and database-default-generated IDs before effects. Runtime DDL, lifecycle metadata mutation, schema ownership and privilege escalation must fail. Inventory every writer credential/route. Prove excluded writers cannot reconnect or write during maintenance. Compare native/protected results, types, ORM state and async behavior for every admitted shape. Reject other shapes before SQL. Run the latest code on the exact OS/interpreter/SQLAlchemy/driver/PostgreSQL cell. The selected PostgreSQL 16 cell and each managed service need their own suite. Other majors remain UNSUPPORTED BY DESIGN until admission |
| G-CRYPTO | UNKNOWN | Publish expected intermediate and final bytes from an independent reference for every admitted codec/format. Check malformed bounds, context relocation, exact-key resolution and companion changes. Implement fork invalidation and test a child cannot use inherited material before fresh preparation. A reviewer must approve nonce/key lifetime limits, collision assumptions and cross-key behavior. Resolve material review findings. Primitive vectors and same-library roundtrips cannot satisfy this gate alone |
| G-QUERY | UNKNOWN | Compare all admitted predicates, NULLs, constraints, joins, projections and pagination with native PostgreSQL. Exercise restricted-role built-in DDL and selective million-row plans. Run published attacks for each admitted advanced representation with dataset and attacker assumptions. Measure per-capability table/index/temporary storage, sustained writes and GIN maintenance where applicable. Meet the approved added-p95 read and isolated column/index storage targets. Measure throughput, CPU and memory. Write-throughput remains D, without an invented threshold. Profile the unexplained plaintext-page overhead on the current revision. Plaintext age/name queries and physical arrays cannot qualify encrypted advanced fields |
| G-LIFECYCLE | UNKNOWN | Kill an executor and resume in an independently started process with no inherited keys or attachment. Restore a real retained backup using immutable reader/lock/wrapper artifacts and the designated provider. Compare full current membership, values, types and constraints. Upgrade mixed old/new formats under stopped writers. Inject failures before and after database/artifact switch. Transform current edits back without snapshot loss. Unsupported old types or missing keys must block rollback. Induce real bounded disk/WAL exhaustion, temp-space failure, memory/CPU pressure and timeouts on a disposable isolated target. Prove no switch, atomic failed chunks, retained completed chunks and inspected resume. Test provider rewrap/rotation and backup dependencies before retirement. Package-free removal must preserve current data and retained obligations |
| G-PROVIDER | UNKNOWN | Exercise exact wrap/unwrap/rewrap context and wrong provider/key/workload identities. Test cold, warm, expired, disabled, outage and canceled remote calls. Discard late material and inspect ambiguous native effects before retry. Recover roots in an independent process. Observe native deletion completion, cached-use limits and every retained wrapper/backup recovery route. A deletion request or local random KEK is insufficient |
| G-POLICY | UNKNOWN | Use the real authenticated deployment artifact outside database restore. Interrupt both database/artifact switch boundaries. Keep writers stopped and deny mismatches until inspection completes publication. Reject wrong targets, old artifacts and restored old policy. Prove old workers and alternate credentials cannot resume writes. Restore in quarantine with current host authorization, then admit only a fully matched representation. The local attachment's immediate installation does not enforce this host procedure |
| G-RELEASE | UNKNOWN | Satisfy all applicable gates and the engineering release gate. Supply named review reports, material-findings resolutions and accepted residual risks. Compare the same backend in hot/cold/outage and lifecycle workloads against approved budgets. Count actual model, business-query, writer, deployment and operator changes. Inspect the exact wheel/sdist, dependencies, hashes, SBOM and provenance. Test old-reader compatibility and critical-flaw recovery. Verify controlled publication identity and security-response ownership. Existing research-package artifacts do not qualify an unbuilt runtime |

## Evidence routing

- [Latest complete CI receipt](_reset/github-boolean-negation-boundary-20261030.json): exact source and installed bindings, counts, skips and artifact digests.
- [Implementation history](history/implementation-2026-10.md): earlier bounded capabilities, failures and measurements.
- [Decision history](history/decisions-2026-10.md): rationale and superseded choices.
- [Research index](research/README.md): external sources and historical review material.
- [Build plan](build-guide.md): next implementation priority and verification order.

Update the current boundary in place. Keep detailed machine receipts in `_reset`
and revision-specific narrative in history; do not prepend another chronological
log to this page or repeat it in the objective ledger.
