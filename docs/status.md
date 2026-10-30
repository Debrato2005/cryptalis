# Current implementation status

Cryptalis implements a bounded research prototype. **No production release or compatibility cell is qualified.**
This page owns current verification and release gates; the [34-objective ledger](BUILD_CHECKLIST.md) owns remaining work.
Use the [documentation map](README.md) to find contracts and procedures.

**Latest complete hosted run: PASS at `2900173`.** Both jobs in
[run 41095408264](https://github.com/Debrato2005/cryptalis/actions/runs/41095408264)
pass, including Boolean NOT with tenant guards, original predicate-result keys,
point UPDATE row counts and named DML results. The original `2d53867` source-role failure and later UUID fixture failures
remain repaired. [Retained failure](_reset/github-point-update-returning-failed-boundary-20261030.json)
and [repair evidence](_reset/point-delete-returning-ci-fix-boundary-20261030.json)
remain available.

## Current complete CI qualification

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
| Application setup | One key-free configuration for diagnosis, protection/capture, tenant onboarding, active-field changes, rotations, attachment and removal | [Application configuration](application.md) |
| Manifest | Bounded JSON declaration, mapping/schema validation, generated locks and semantic diff | [Manifest](manifest.md) |
| Crypto | CF1 AES-256-GCM-SIV, random nonces, HKDF, independent HMAC search roots and authenticated context | [Security](security.md) |
| ORM/search | Bounded sync/async SQLAlchemy and optional SQLModel; exact/IN/uniqueness and explicitly admitted forms | [Compatibility matrix](compatibility.md#full-capability-matrix) |
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
