# Current implementation status

Cryptalis implements a bounded research prototype. **No production release or compatibility cell is qualified.**
This page owns current verification and release gates; the [34-objective ledger](BUILD_CHECKLIST.md) owns remaining work.
Use the [documentation map](README.md) to find contracts and procedures.

## Current complete CI qualification

**VERIFIED at `a2d8230a72c2c19b0ab3006b0a38cf28cc47df84`:** GitHub
[run 41018215391](https://github.com/Debrato2005/cryptalis/actions/runs/41018215391)
passes both Source / PostgreSQL 16 and Reproducible artifacts / installed recovery.
The [retained CI boundary](_reset/github-openbao-audit-boundary-20261030.json)
contains verified GitHub archive digests and the actual source/installed receipts.

The complete default source run passes 3,255 test calls and eighteen subtests.
Twelve call skips, 76 setup skips and seventeen collection skips remain explicit;
all 3,343 selected items complete. All 287 Python hashes match the recorded checkout,
and source/imported-runtime stability passes. The original source-role fixture
failure at `2d53867` remains fixed; no skipped cell is treated as qualified.

The installed wheel passes 105 ORM/configuration controls, 50 Google SDK and 119 OpenBao/provider
checks, two exports and three genuine fresh PostgreSQL recovery checks. Local and GitHub
wheel/sdist hashes are identical. Repeat archives, SBOM, installed-file inspection
and dependency consistency pass. The frozen audit reports 39 packages, zero known
vulnerabilities and zero adverse statuses; this is not proof of absence of unknown
vulnerabilities or independent review. Earlier CI is retained in
[history](history/implementation-2026-10.md#complete-ci-at-7e7d1c5-2026-10-30).
The separate explicit performance profile below fails latency targets; a green
default CI run does not qualify performance.

Documentation consolidation is `26e882b`; shared init/Doctor is `15ffdb3` and
shared application configuration is `09c635a`; lifecycle integration is `b92cfc7`.
Google KMS is `bda4fb3`; AppRole is `743b5e9`; shared rotations are `ccf7d12`.
Doctor authentication diagnostics are `7e7d1c5`; native audit is `a2d8230`.
The subsequent online configuration extension has a separate local boundary.

The 34-objective [ledger](BUILD_CHECKLIST.md#objective-ledger) retains seven
bounded VERIFIED entries, 23 PARTIAL entries, one SPECIFIED, one BLOCKED, one
IMPLEMENTED and one ONGOING. These are implementation labels, not production
completion. Remaining work includes simpler manifest/host integration, broader
ORM/query/type coverage and lower-leakage research, complete static/dynamic route
inventory, versioned upgrades, authenticated deployment/failover authority,
retained-backup obligations and controlled destruction, production provider
identity/audit/HA, combined disaster drills, and performance acceptance.
Independent human review remains unavailable; selected live cloud cells need
authorized accounts. All 34 objectives stay in scope and all seven production
gates remain UNKNOWN.

## Shared application configuration

**VERIFIED locally and in complete GitHub CI:** [ApplicationConfig](application.md)
shares one key-free declaration/mapping/evidence configuration across init, Doctor,
planning, apply/resume, status, attachment and decrypt-back/removal. Manifest and
writer/search-evidence drift refuses before database/key access, including reverse
operations against the protected source. Existing lifecycle executors and explicit
host pins, maintenance, plaintext and removal approvals remain authoritative.

The [lifecycle boundary](_reset/application-lifecycle-boundary-20261030.json) records
146 passing affected source checks with one explicit skip, 96 installed
ORM/configuration checks, 69 real OpenBao/provider checks, one export and one genuine fresh PostgreSQL recovery.
Original and restored applications preserve their latest values through removal.
A failed second chunk retains its first committed chunk and resumes without
replacing that ciphertext. Missing pin/maintenance/plaintext/removal authority
refuses before database or key access. Repeat artifacts, SBOM, installed-file
inspection and dependency consistency pass; all 282 Python hashes and runtime
bytes are stable. The complete remote run above additionally verifies this
lifecycle extension. Sample inspection does not establish full application coverage. All production gates remain UNKNOWN.

The later [rotation boundary](_reset/application-rotations-boundary-20261030.json)
adds shared manifest checks to root rewrap, payload rotation and search reindex,
their staging/status/sealing/switching, and source-only cancellation. Native
oracles verify unchanged rewrap ciphertext, payload rotation's stable terms,
search rotation's changed terms, resumed chunks, uniqueness and current-value
removal. The installed wheel passes 105 application/ORM checks, 50 Google checks,
115 OpenBao/provider checks, two exports and three fresh-restore checks. The
native service journey rewraps from OpenBao version 1 to 2 using AppRole.

The separate restored-TEXT journey authenticates the backup, carries explicit
restore authority through all three rotation plans, preserves current edits and
completes removal. All 287 Python hashes and runtime bytes are stable. Initial
pin-code assertions, two service test timing failures and an omitted restore
prerequisite remain archived with corrections. A separate 45s source Doctor startup
timeout has no established cause; its isolated rerun is retained separately. The final source and installed
checks pass. Complete remote CI above also verifies this extension; all gates stay UNKNOWN.

The subsequent [online/tenant boundary](_reset/application-online-boundary-20261030.json)
extends that same configuration through native capture, key-free progress,
fencing/catch-up, sealing/switching, pre-cutover cancellation and approved empty
scope publication/cancellation. Committed chunks survive custody failure; current
native edits and NULLs survive capture, protected edits and verified removal.
The real AppRole/OpenBao journey also verifies equality/IN and tenant uniqueness.

Verification passes nine focused source checks, 65 surrounding regressions with
two explicit skips, 120 native provider checks, 114 installed application checks,
50 Google checks, two exports and three fresh-restore checks. All 288 Python
hashes and runtime bytes are stable; repeat artifacts, SBOM and installation pass.
Four failed source runs retain incorrect fixture assumptions about pending guards,
error types, repeated attachment and old-worker queries. The final journey uses
stale-pin startup refusal and fresh native mappings after removal. Existing
workers still require host drain/restart; no automatic process fencing is claimed.
The two regression skips require a separate restore target and pre-provisioning
reader. Complete remote CI still covers the preceding audit boundary.

## Google Cloud KMS SDK boundary

**VERIFIED locally and in complete CI, SDK protocol and real PostgreSQL:** the optional
[Google provider](google-kms.md) supports context-bound root wrap/unwrap, async
preparation, verified rewrap, CRC32C, explicit version/level checks, bounded calls
without automatic retries, fork refusal and redacted errors. Its decrypt-version
visibility limit is explicit; no ciphertext or header selects provider authority.

The [retained boundary](_reset/google-kms-boundary-20261030.json) records 174 passing
source checks, 49 installed Google checks, 96 installed application/ORM checks,
69 real OpenBao checks and genuine fresh PostgreSQL export/recovery. All 285
Python files and runtime bytes remain stable. Repeat archives, SBOM, install and
dependency checks pass. The frozen audit covers 39 packages with zero known
vulnerabilities/adverse statuses. The initial erroneous cancellation assertion and
one invalid test-file selection remain in the archive with their corrections.

Google checks use the actual SDK/protobuf with a local opaque-handle transport.
The authorized-live test remains a collection skip: no Google account, billing,
IAM or custody verification is claimed. Production identity/audit/HA,
combined recovery, controlled retirement
and independent review remain open. All production gates stay UNKNOWN.

## OpenBao workload authentication

**VERIFIED locally and in complete GitHub CI:** [AppRole authentication](openbao.md#approle-workload-authentication)
supplies fresh short-lived Transit tokens from explicitly supplied workload
credentials. Exact policy, role name, service-token TTL, current SecretID binding
and finite role SecretID lifetime are checked before release. Ambient token
discovery, automatic retries, fork reuse and unsafe role drift refuse. A failed
login or validation retains UNKNOWN native effects because a token may exist.

The [retained boundary](_reset/openbao-approle-boundary-20261030.json) records 232
source checks, 114 installed real OpenBao/protocol checks, 96 installed application
checks, 50 Google checks and fresh PostgreSQL export/recovery. All 286 Python
hashes and imported runtime bytes are stable. Repeat archives, SBOM and installed
checks pass. Native controls prove the policy denies key administration and
SecretID minting; single-use credentials refuse replay and recover with a fresh
callback value. AppRole drives current-value PostgreSQL removal and independent
Raft snapshot recovery with the source service offline. The old authentication
endpoint fails during that recovery. Complete remote CI above also verifies AppRole.

Host credential delivery, historical SecretID retirement, policy contents, audit
sinks, production HA and combined deployment recovery remain unqualified. Current
role inspection cannot prove past settings or prevent future administrator edits.
All seven production gates remain UNKNOWN.

The subsequent [Doctor boundary](_reset/doctor-authentication-boundary-20261030.json)
preserves `Provider.AuthenticationUnavailable`, UNKNOWN native effects and explicit
no-retry guidance through Python and CLI diagnostics. It keeps individual outcomes
and caller leases unchanged. Local verification passes 76 source checks, 105
installed application checks, 50 Google checks, 117 OpenBao/provider checks, two
exports and three fresh-restore checks. All 287 Python hashes and runtime bytes
are stable; repeat artifacts and installation checks pass. Native AppRole refusal
and subsequent recovery are exercised. Complete remote CI above also verifies
this boundary; it does not establish production audit or custody.

## Native OpenBao audit boundary

**VERIFIED locally and in complete GitHub CI:** the isolated runner configures
native file audit without unsafe API creation. The [audit boundary](_reset/openbao-audit-boundary-20261030.json)
records 119 passing real OpenBao/provider checks, 105 installed application
checks, 50 Google checks, two exports and three fresh-restore checks. Native
hash comparisons verify credential/root/context/wrapper fields, request IDs,
visible metadata and runtime audit-administration denial. File reopen preserves
history and hash identity. Independent snapshot recovery retains the device salt,
produces target audit records and leaves stopped-source records unchanged.

All 287 Python hashes and imported runtime bytes remain stable. Repeat artifacts,
SBOM, installed-file inspection and dependency consistency pass. The initial
incorrect audit field assertion and premature request before writable Raft
leadership remain retained; the harness now waits for explicit native health and
leader readiness after unseal. Runtime provider retries remain disabled.

Raw audit records, service logs, credentials and snapshots remain private. This
single-file boundary does not qualify external shipping, redundant sinks,
disk exhaustion, all-sink failure, production audit custody or HA. Native
unaudited paths and visible metadata remain explicit in the
[procedure](openbao.md#native-audit-configuration). Complete remote CI above also
verifies this boundary. All production gates remain UNKNOWN.

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
| Application setup | One key-free configuration for diagnosis, protection/capture, tenant onboarding, rotations, attachment and removal | [Application configuration](application.md) |
| Manifest | Bounded JSON declaration, mapping/schema validation, generated locks and semantic diff | [Manifest](manifest.md) |
| Crypto | CF1 AES-256-GCM-SIV, random nonces, HKDF, independent HMAC search roots and authenticated context | [Security](security.md) |
| ORM/search | Bounded sync/async SQLAlchemy and optional SQLModel; exact/IN/uniqueness and explicitly admitted forms | [Compatibility matrix](compatibility.md#full-capability-matrix) |
| Lifecycle | Maintenance and bounded initial online protection, resumable verification, three rotations, current-data reverse/removal, fresh restore/adoption | [Lifecycle](lifecycle.md), [operator walkthrough](walkthrough-migration.md) |
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

- [Latest complete CI receipt](_reset/github-approle-boundary-20261030.json): exact source and installed bindings, counts, skips and artifact digests.
- [Implementation history](history/implementation-2026-10.md): earlier bounded capabilities, failures and measurements.
- [Decision history](history/decisions-2026-10.md): rationale and superseded choices.
- [Research index](research/README.md): external sources and historical review material.
- [Build plan](build-guide.md): next implementation priority and verification order.

Update the current boundary in place. Keep detailed machine receipts in `_reset`
and revision-specific narrative in history; do not prepend another chronological
log to this page or repeat it in the objective ledger.
