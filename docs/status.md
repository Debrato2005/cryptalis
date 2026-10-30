# Current implementation status

Cryptalis implements a bounded research prototype. **No production release or compatibility cell is qualified.**
This page owns current verification and release gates; the [34-objective ledger](BUILD_CHECKLIST.md) owns remaining work.
Use the [documentation map](README.md) to find contracts and procedures.

## Current complete CI qualification

**VERIFIED at `dd5ac01467712b2a2e451706b188bd53417eabb7`:** GitHub
[run 40955279799](https://github.com/Debrato2005/cryptalis/actions/runs/40955279799)
completed successfully on 2026-10-29 UTC. Both Source / PostgreSQL 16 and
Reproducible artifacts / installed recovery passed. Historical checkpoints are in the [evidence history](history/implementation-2026-10.md).

The complete default source run passes 3,103 test calls and eighteen subtests.
Twelve call skips, 63 setup skips and sixteen collection skips remain explicit;
all 3,178 selected items complete. All six source-role wrapper checks pass,
resolving the three fixture failures in run 40947951794 at `2d53867`.
Three role probes, all 280 current Python hashes, source stability and imported
runtime stability pass. The [retained CI boundary](_reset/github-current-boundary-20261030.json)
includes the actual source and installed receipts, with archive digests verified
against GitHub artifact metadata. No skipped cell is treated as qualified.

The installed wheel passes 69 OpenBao/provider/Doctor checks, 29 ORM controls,
one export and one genuine fresh PostgreSQL recovery. Both the local environment
and GitHub runner produce identical wheel and sdist hashes. Selected-extra SBOM,
installed file/CLI inspection and dependency consistency pass. The frozen audit
reports 26 packages, no known vulnerabilities and no adverse statuses. This
does not establish absence of unknown vulnerabilities or independent review.

The credentials fixture fix is `fa5045a`; OpenBao, operational qualification,
cold-provider Doctor and independent snapshot recovery are committed and pushed.
The final evidence update changes documentation only, with all tested executable
hashes preserved. Earlier interrupted/cancelled runs remain incomplete evidence.

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

- [Latest complete CI receipt](_reset/github-current-boundary-20261030.json): exact source and installed bindings, counts, skips and artifact digests.
- [Implementation history](history/implementation-2026-10.md): earlier bounded capabilities, failures and measurements.
- [Decision history](history/decisions-2026-10.md): rationale and superseded choices.
- [Research index](research/README.md): external sources and historical review material.
- [Build plan](build-guide.md): next implementation priority and verification order.

Update the current boundary in place. Keep detailed machine receipts in `_reset`
and revision-specific narrative in history; do not prepend another chronological
log to this page or repeat it in the objective ledger.
