# Current implementation status

Cryptalis implements a bounded research prototype. **No production release or compatibility cell is qualified.**
This page owns current verification and release gates; the [34-objective ledger](BUILD_CHECKLIST.md) owns remaining work.
Use the [documentation map](README.md) to find contracts and procedures.

## Current complete CI qualification

**VERIFIED at `15ffdb39a28ea0b9e254f68a76443fa399886a54`:** GitHub
[run 40994737233](https://github.com/Debrato2005/cryptalis/actions/runs/40994737233)
passes both Source / PostgreSQL 16 and Reproducible artifacts / installed recovery.
The [retained CI boundary](_reset/github-shared-host-boundary-20261030.json)
contains verified GitHub archive digests and the actual source/installed receipts.

The complete default source run passes 3,122 test calls and eighteen subtests.
Twelve call skips, 63 setup skips and sixteen collection skips remain explicit;
all 3,197 selected items complete. All 280 Python hashes match the local checkout,
and source/imported-runtime stability passes. The original source-role fixture
failure at `2d53867` remains fixed; no skipped cell is treated as qualified.

The installed wheel passes 63 ORM/init/Doctor controls, 69 real OpenBao/provider
checks, one export and one genuine fresh PostgreSQL recovery. Local and GitHub
wheel/sdist hashes are identical. Repeat archives, SBOM, installed-file inspection
and dependency consistency pass. The frozen audit reports 26 packages, zero known
vulnerabilities and zero adverse statuses; this is not proof of absence of unknown
vulnerabilities or independent review. Earlier CI is retained in [history](history/implementation-2026-10.md#complete-ci-at-dd5ac01-2026-10-30).

Documentation consolidation is `26e882b`; the shared-host implementation is
`15ffdb3`. The final requirements/routing/evidence follow-up changes documentation
only and preserves the tested executable hashes.

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

## Shared initialization and Doctor context

**VERIFIED locally, current source and installed wheel:** one key-free
`InitializationContext` now serves both `init` and `doctor --initialization-context`.
Optional SELECT samples are structurally admitted without execution. Doctor writes
no artifact; init refuses publication for a failed sample. Invalid/conflicting
inputs, unsafe engines, inspection failure, cleanup and output failure stay visible.

The [retained boundary](_reset/shared-host-boundary-20261030.json) binds 160 focused
source checks, 63 installed ORM/init/Doctor checks, 69 real OpenBao/provider checks,
and one genuine PostgreSQL export plus one fresh-target recovery. Repeat archives,
SBOM, installed files and dependency consistency pass. The first source attempt's
new test assertion failure is retained with the correction. The complete GitHub
source run above additionally verifies this implementation. No production gate changes.

## Capability summary

| Area | Implemented boundary | Contract / instructions |
|---|---|---|
| Manifest | Bounded JSON declaration, mapping/schema validation, generated locks and semantic diff | [Manifest](manifest.md) |
| Crypto | CF1 AES-256-GCM-SIV, random nonces, HKDF, independent HMAC search roots and authenticated context | [Security](security.md) |
| ORM/search | Bounded sync/async SQLAlchemy and optional SQLModel; exact/IN/uniqueness and explicitly admitted forms | [Compatibility matrix](compatibility.md#full-capability-matrix) |
| Lifecycle | Maintenance and bounded initial online protection, resumable verification, three rotations, current-data reverse/removal, fresh restore/adoption | [Lifecycle](lifecycle.md), [operator walkthrough](walkthrough-migration.md) |
| Providers | Development custody, optional AWS SDK adapter, actual local OpenBao TLS/outage/revocation/snapshot evidence | [OpenBao](openbao.md); no production custody qualification |
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

- [Latest complete CI receipt](_reset/github-shared-host-boundary-20261030.json): exact source and installed bindings, counts, skips and artifact digests.
- [Implementation history](history/implementation-2026-10.md): earlier bounded capabilities, failures and measurements.
- [Decision history](history/decisions-2026-10.md): rationale and superseded choices.
- [Research index](research/README.md): external sources and historical review material.
- [Build plan](build-guide.md): next implementation priority and verification order.

Update the current boundary in place. Keep detailed machine receipts in `_reset`
and revision-specific narrative in history; do not prepend another chronological
log to this page or repeat it in the objective ledger.
