# Product build checklist

This file is the product engineering ledger. It tracks the 34 product objectives
against the actual product source, tests, and evidence.
[Status](status.md) owns current capability claims. [Architecture](architecture/README.md),
[security](security.md), [lifecycle](lifecycle.md), and [compatibility](compatibility.md)
own their contracts. This file does not replace those owners.

## Status vocabulary

| Term | Meaning |
|---|---|
| SPECIFIED | The final product requires the behavior; it is not implemented. |
| IMPLEMENTED | Product source exists. Verification may be incomplete. |
| VERIFIED | Executed evidence supports the named behavior at the recorded revision and cell. |
| UNKNOWN | Required evidence is absent. This is not a pass. |
| BLOCKED | An external resource, decision, or approval is required. |

The first public release targets the full SRS and all 34 objectives with production qualification.
Internal development checkpoints preserve partial progress without reducing that scope.
Use the [competitive capability matrix](research/capability-matrix.md) and the
[release direction](decisions.md#comprehensive-first-public-release-2026-10-23) to choose complete E2E work.
Completed capabilities and real application journeys measure progress.
No objective is complete until its acceptance evidence and applicable gate pass.

## Current boundary

- Boolean storage has typed CF1 descriptors and native sync/async controls.
  Both unchanged SQLModel profiles preserve defaults and latest False values.
  Mixed rotations and a fresh-cluster restore/removal journey pass.
  The first full run exposed outdated test clock names. All 43 affected
  lease controls pass after correction. The final full run passes 2,361 tests
  plus 18 subtests. The actual installed wheel passes 41 controls. See the [Boolean checkpoint](status.md#boolean-storage-checkpoint-2026-10-23).

- The combined search/Doctor checkpoint passes 2,322 primary tests plus 18
  subtests, with 174 stable Python hashes. Installed-wheel checks pass the
  searchable app, 27 CLI controls and both local SDK application journeys.
  The fixture-lifetime failure and its deterministic correction remain recorded.
  All seven production gates stay UNKNOWN. See the
  [installed integration](status.md#installed-searchable-application-integration-2026-10-23).

- The unchanged SQLModel application now exercises fixture-scoped encrypted email
  equality/IN/uniqueness and latest-value exit. Deterministic implicit default
  collation has bounded native admission. The pre-adoption CLI shares Python
  preflight and keeps host-code effects UNKNOWN. Separate local SDK evidence
  covers asynchronous Smolink. See [current status](status.md).

- Smolink now completes manifest preflight, committed-process interruption/resume,
  root rewrap, payload rotation, genuine fresh-cluster recovery and latest-value
  package-free exit. The SQLModel template also completes the pre-adoption Doctor
  journey. Source and actual installed-wheel runs verify these bounded
  storage-only application profiles. See the
  [recovery checkpoint](status.md#manifest-first-application-recovery-checkpoint-2026-10-23).

- Optional SQLModel 0.0.48 has bounded synchronous PostgreSQL bridge/template
  evidence. The SQLModel-absent full primary run passes 2,282 tests and 18
  subtests. The actual installed optional cell passes 14 controls. A current
  performance failure and unchanged-source follow-up remain separate, with cause
  UNKNOWN. See the
  [SQLModel checkpoint](status.md#optional-sqlmodel-template-checkpoint-2026-10-23).

- Native VARCHAR mapped dictionary UPDATE preserves the tested native assignment,
  error and zero-match behavior through a private per-group carrier. The combined
  primary regression passes 2,281 tests and 18 subtests. Current release and
  installed-wheel Python 3.13 application checks pass separately. See the
  [VARCHAR UPDATE checkpoint](status.md#native-varchar-mapped-update-checkpoint-2026-10-23).

- The installed wheel passes the pinned Smolink URL lifecycle on Python 3.13.12
  with exact runtime pins and binary psycopg. Product/runtime imports use the
  new disposable site. App/test dependencies use a read-only fallback. See the
  [installed Python 3.13 checkpoint](status.md#installed-wheel-python-313-checkpoint-2026-10-23).

- The local fork regression holds the keyring mutex while sync/async preparation
  refuses inherited keys. Fresh child and retained parent keys still work.
  Product crypto stays unchanged. See the
  [fork checkpoint](status.md#keyring-held-mutex-fork-checkpoint-2026-10-23).

- Wheel Python/dependency metadata now matches project declarations through standard
  packaging parsers, with duplicate-sensitive dependency comparison. The final
  suite passes 14 tests and 60 subtests. See the
  [metadata checkpoint](status.md#artifact-dependency-metadata-checkpoint-2026-10-23).

- The combined defensive source passes 2,250 tests and 18 subtests, with four
  skips, 48 existing warnings and 154 stable Python hashes. Current release,
  unchanged Smolink, all six 10k read targets and isolated storage pass separately.
  All seven production gates remain UNKNOWN. See the
  [combined defensive checkpoint](status.md#defensive-projection-and-delete-integration-checkpoint-2026-10-23).

- The earlier post-admission 10k profile at `3a21096` passes all six latency targets
  and 1.52483× isolated storage, with 150 stable Python hashes. This is warm
  synchronous TEXT evidence with public fixture keys. See the
  [earlier 10k checkpoint](status.md#post-admission-10k-profile-checkpoint-2026-10-23).

- Expanded entity/table SELECT admission now applies type, operation and owned-lineage
  rules to selected columns and descendants. Both final affected cells pass 284
  checks. Earlier native frame-exposure and benign mapped-expression failures stay
  recorded. See the
  [expanded SELECT checkpoint](status.md#expanded-select-projection-checkpoint-2026-10-23).

- Finite mapped DELETE preserves native results and transactions under exact
  tenant/record authority. Ordinary flush DELETE also refuses custom AST nodes.
  The scoped integration passes 55 checks. Both final flush bundles pass 65.
  The earlier alternate restart failure and its isolated correction stay separate.
  See the [DELETE checkpoint](status.md#mapped-delete-admission-checkpoint-2026-10-23).

- Historical checkpoint `351789e` reports 2,167 passes and two failures,
  with 18 passed subtests, four skips and 149 stable hashes. Its corrected
  early-refusal and unchanged CLI timeout controls pass in isolation.
  The original timeout cause stays UNKNOWN. The later combined defensive
  checkpoint supplies the full follow-up. See the
  [earlier combined checkpoint](status.md#combined-integration-checkpoint-2026-10-23).

- Scoped TEXT dictionary UPDATE now preserves native groups, NULL/omission,
  repeated IDs, zero matches and transactions under exact tenant/record proofs.
  Shared attachment checks also refuse identity variants before key resolution.
  Both affected cells pass 143 cases. See the
  [bulk UPDATE checkpoint](status.md#scoped-mapped-bulk-update-checkpoint-2026-10-23).

- Payload/search staging and paired-frame verification retry actual expiry
  once per row under both exact policies. Both 83-case cells pass, including
  20 new no-effects/recovery controls. Source-only and final checks retain
  terminal expiry. See the
  [rotation checkpoint](status.md#rotation-row-lease-recovery-checkpoint-2026-10-23).

- Planning rejects dialect-specific record/tenant type variants. Two native
  controls reproduce SQL-transformed UUIDs before the refusal fix. The corrected
  planning regression passes 105 cases. Attachment checks are separate. See the
  [identity checkpoint](status.md#identity-variant-planning-checkpoint-2026-10-23).

- Doctor/status inspection failures retain the public operation UUID and fixed
  remedies for known role/pin refusals. Seven new controls and the 128-case
  affected run pass, with read-only snapshots and private-value redaction.
  See the [diagnostic checkpoint](status.md#actionable-inspection-failures-checkpoint-2026-10-23).

- Restored-frame scans retry actual expiry once with exact retained-policy
  checks. Nine integrated scan/admission checks and ten public restore controls
  on each genuine TEXT/VARCHAR fresh cluster pass. Failed custody remains
  `KeyUnavailable` before effectful probes. See the
  [restore checkpoint](status.md#restored-frame-lease-recovery-checkpoint-2026-10-23).

- An optional AWS KMS SDK bridge pins the full key ARN, response algorithm
  and exact public context. Both protocol/integration runs pass 86 checks;
  the isolated actual-SDK profile and its integration pass 12 cases each.
  The current installed wheel passes one original SQLModel application journey
  with local SDK outage, authentication refusal and recovery controls.
  Live AWS custody and production provider qualification remain UNKNOWN.
  See the [provider checkpoint](status.md#optional-aws-kms-sdk-adapter-checkpoint-2026-10-23).
- Protection and decrypt-back now retry one unfinished row after key lease
  expiry, before SQL, progress or digest effects. Four previous-product controls
  fail; all 16 new controls pass. Existing primary checks pass 111 cases and
  the alternate cell passes 127. Provider failure, changed policy and a second
  expiry still stop the operation. The full primary run passes 2,034 tests
  and 18 subtests, with three skips, 48 existing warnings and 137 stable hashes.
  See the [lease checkpoint](status.md#bounded-row-lease-recovery-checkpoint-2026-10-23).
- A current pinned 10,000-row profile meets local added-p95 targets for point
  scalar, equality tuple and IN-20 tuple reads: 1.6294, 2.0107 and 2.5330 ms.
  Isolated name-column/equality-index storage measures 1.5248× native for
  unique 53-byte names. Both 136-file receipts stay stable. This warm synchronous
  TEXT cell uses public fixture keys and does not qualify entity, million-row,
  remote-provider or deployment performance by itself. The subsequent entity
  extension meets local targets at 1.2622/2.6119/2.8613 ms added p95 for
  point/equality/IN-20. Its separate receipts keep stable 136-file hashes.
  A separate 100k-row run also meets all six targets. Entity added p95 measures
  1.2667/1.7083/2.5670 ms and isolated storage measures 1.5296× native.
  The later prepared million-row run completes the full product transition.
  It meets all six read targets, with entity added p95 at
  2.4646/2.1569/2.5735 ms and isolated storage at 1.4372× native.
  Final 137-file hashes stay stable. Process CPU/elapsed/peak RSS are recorded
  separately from server resources.
  See the
  [current performance checkpoint](status.md#current-pinned-performance-checkpoint-2026-10-23).
- Mapped bulk INSERT now returns one direct protected scalar through native
  Row/scalar results and page handling. Exact prepared-input proofs reject
  changed frames, NULL presence or row context. Current/future page mutation,
  lease use, native error precedence, savepoint recovery and typed identity
  controls pass. The affected primary run passes 100 cases.
  The final alternate cell passes 103 cases, including TEXT/VARCHAR current-value
  removal and unchanged Smolink. Final 135-file hashes stay stable.
  The full primary regression passes 2,018 tests and 18 subtests, with three
  separate-environment skips and 48 existing warnings at that final bundle.
  Reproducible archives and all 36 installed files pass. See the
  [scalar RETURNING checkpoint](status.md#mapped-protected-scalar-returning-checkpoint-2026-10-23).
- The wrapper now records ordinary calls, subtests, setup, teardown and
  failed/skipped collection outcomes separately. Historical counters retain
  their original meaning. The focused reporter/preflight run passes 24 cases.
  The alternate cell also passes 24 cases. The full primary run passes
  1,978 tests and 18 subtests, with three separate-environment skips and
  48 existing warnings. All 132 Python hashes stay stable and match the worktree.
  This full run includes the final shared-driver buffer fix.
  See the [receipt checkpoint](status.md#test-receipt-checkpoint-2026-10-23).
- Implemented scope includes native text/VARCHAR storage, equality/IN,
  tenant uniqueness, sync/async attachment, maintenance protection,
  decrypt-back/removal, and separate root-rewrap, payload and search rotation.
  Payload/search preparation uses sealed activation and shared publication.
  Restore adoption uses the existing host-approved binding. Effective privilege,
  ancestry and metadata checks precede effectful restore probes or key work.
  Read-only Doctor repeats runtime attachment admission in one snapshot and
  reports six unobserved boundaries plus its aggregate result UNKNOWN.
  ACTIVE/PENDING status repeats effective privilege admission.
  CLI status also reads payload/search preparation with its own pin and source
  identity. Every recorded preparation keeps `runtime_metadata_matches: false`, NOT_PERFORMED and
  exit 3. Preparation status repeats effective privilege admission.
  Attached mapped dictionary INSERT now preserves bounded native grouping,
  NULLs, explicit typed context, uniqueness and transaction/savepoint behavior.
  Its final driver guard checks actual payload bytes and row context.
  The shared guard now captures native flush/read and RETURNING-page driver
  values before later cursor callbacks and checks them at final dispatch.
  First/unique effective callback order is required. Cursor observers must
  register on the engine after attachment and retain SQL and values.
  See the [current checkpoint](status.md#shared-driver-event-checkpoint-2026-10-23).
- The shared guard checkpoint passes 1,974 tests and 18 subtests in the broad
  primary run, with three separate-environment skips and 48 existing warnings.
  A subsequent exact-buffer fix passes 227 affected cases and 63 final
  alternate cases including the unchanged Smolink lifecycle. These final runs
  retain stable 131-file hashes. Reproducible archives and all 36 installed
  package files pass. The broad run predates only that narrow buffer fix and
  corrected attachment docstring. Fresh-cluster/full-alternate profiles retain
  their earlier revision boundaries.
- The bulk checkpoint passes the full primary regression: 1,953 tests and
  18 subtests, with three separate-environment skips and 48 existing warnings.
  Stronger final driver controls pass all 44 bulk cases at the final source
  bundle. The alternate Python 3.13 / SQLAlchemy 2.0.51 cell passes those cases
  plus the pinned unchanged Smolink lifecycle, 45 cases. Both final receipts
  retain stable 130-file hashes. Reproducible archives and all 36 installed
  package files pass. The full alternate cell and fresh-cluster profiles were
  not rerun for this route.
- The preparation-status checkpoint passes 369 affected CLI and rotation cases.
  Eight phase/purpose cases pass again with actual runtime credentials.
  Reproducible archives and all 36 installed package files pass, including CLI.
  The earlier Doctor checkpoint passes 88 focused cases plus two final cleanup controls.
  Search TEXT/VARCHAR backups each pass one export and 30 restore cases,
  including Doctor on an adopted runtime. Reproducible archives and all 36
  installed package files pass, including CLI startup and Doctor help.
  Full regression passes 1,887 tests and 18 subtests, with three separate-environment
  skips. Its 125 Python hashes belong to that earlier checkpoint.
  The prior search checkpoint passes 92 focused cases, including independent crypto,
  native search/uniqueness/current-value removal, mixed rotation lineage,
  lost COMMIT replies and SIGKILL recovery. Search TEXT/VARCHAR backups each
  pass one export and 29 restore cases. Older protection, rewrap and payload
  profiles also pass at the same Python hashes. Its earlier full regression passes
  1,869 tests and 18 subtests, with three separate-environment skips.
  Reproducible archives and all 36 installed package files pass, including CLI.
- Current execution uses local PostgreSQL 16 and Python 3.12.3 with SQLAlchemy
  2.1.3. The current bounded alternate/app rerun is recorded above. The earlier
  full alternate and [external adoption evidence](status.md#pinned-smolink-adoption-2026-10-22)
  retain their exact revision boundaries. Private-role probes and Git writes use scoped approved
  execution. Default sandbox restrictions remain in place.
- The import ledger and dated status checkpoints preserve earlier evidence.
  Reproducibility includes wheel RECORD, license metadata and an SBOM.
  Signing, publication identity and independent rebuild remain UNKNOWN.
  Other non-text types, advanced predicates, online migration, adopted-target rotation,
  production custody/retirement, authenticated host authority and independent
  review remain open. All seven qualification gates remain UNKNOWN.


## Objective ledger

Requirement text is abbreviated. The full definitions remain in the research
`CRYPTALIS_BUILD_CHECKLIST.md` and the final blueprint; no requirement is dropped.

| ID | Requirement (abbreviated) | Product status | Implemented mechanism and evidence | Open gap / next action |
|---|---|---|---|---|
| OBJ-SEC-01 | Encrypt before PostgreSQL; prove at SQL/driver boundaries | VERIFIED, bounded | `crypto/cf1.py`, `sqlalchemy.py`; slice 2/3 receipts in `docs/_reset`; real runtime-role tests | Broader writer/auth/provider boundaries; independent review |
| OBJ-SEC-02 | Bind tenant, field, row, generation; reject malformed/swapped frames | VERIFIED, bounded | CF1 AAD, descriptor binding, sync/async tamper tests | Collision assumptions and composition review |
| OBJ-SEC-03 | Authorization, result lineage, tenant isolation, parameterization | PARTIAL | Tenant-scoped sessions, requested-point checks, typed errors; expanded entity/table SELECT type, operation and owned-lineage admission; finite mapped DELETE binds compiled/final parameters to original tenant/record authority | Host authorization is external; audit remaining ORM routes |
| OBJ-SEC-04 | Detect plaintext bypass through ORM, bulk, SQL, COPY, jobs, logs | PARTIAL | Guarded attachment rejects raw SQL/COPY/opaque writes and unsafe engine logging before connect/key access; writer inventory at plan; effective runtime privilege refusal before restore probes/keys, repeated at planning, active admission, Doctor, ACTIVE/PENDING status, shared maintenance and host-phase-selected reverse execution | Complete route inventory; identity variants now refuse during planning; deployment enforcement is unverified |
| OBJ-SEC-05 | Isolate keys and bound nonces, leases and cache lifetime. Preserve fork safety | VERIFIED, bounded | `crypto/keys.py` checks policy, cache expiry and fork refusal. Local outage, revocation and lease drills pass on both SQLAlchemy cells. An actual Linux fork with the mutex held passes sync/async refusal in [main integration](_reset/keyring-held-mutex-fork-integration-20261023.json). Fresh child keys and retained parent keys still work | Remote cancellation, usage limits, production custody |
| OBJ-SEC-06 | Reduce equality/frequency/access leakage with documented trade-offs | SPECIFIED | Equality leakage is declared; no stronger profile admitted | Threat-model and benchmark a lower-leakage profile; six-gate admission |
| OBJ-SEC-07 | Independent red-team, crypto, adapter, provider, supply-chain review | BLOCKED | None | Assign independent reviewers; do not self-certify |
| OBJ-QUERY-01 | Exact equality, `IN`, scoped uniqueness, NULL logic, races | VERIFIED, bounded | `_sqlalchemy_search.py`, slice 4 receipt; native concurrency tests | Keep grammar reconciliation current |
| OBJ-QUERY-02 | Ordinary SQL correctness: NULL predicates, aliases, joins, projections | PARTIAL | Native sync/async controls; textual reference admission and simple negative/NULL predicates; expanded entity/table/descendant admission preserves authenticated outputs and safe public expressions; both final affected cells pass 284 checks | Continue finite native-oracle matrix; general Boolean NOT and protected joins remain unadmitted |
| OBJ-QUERY-03 | Ordering, ranges, prefix/text search, aggregates, other types | PARTIAL | Boolean storage has bounded native, unchanged-application and lifecycle evidence. Advanced operations and other practical types remain unadmitted. Refusal does not complete the objective | Research secure practical profiles, including substring/fuzzy search and structured JSON, then prove independent E2E parity and applicable admission gates |
| OBJ-QUERY-04 | INSERT/UPDATE/DELETE, bulk, RETURNING, triggers, cascades, savepoints | PARTIAL | Scoped tenant-column TEXT/VARCHAR dictionary UPDATE with native plan-sensitive VARCHAR assignment/errors, transaction/group semantics and exact ordered input proofs; ORM flush writes and attached sync/async mapped dictionary INSERT, with optional single protected scalar RETURNING; native NULL/grouping, typed context, errors and savepoints; exact driver/page/input-result checks; finite mapped TEXT/VARCHAR tenant/record DELETE with native results and transactions; custom DELETE AST refusal also covers ordinary flush; 55 scoped integration checks and both 65-case flush bundles pass | Qualify tuple/entity RETURNING, broader DML, used defaults and each trigger/cascade effect separately |
| OBJ-QUERY-05 | Versioned compatibility corpus and read-only scanner | PARTIAL | Native-vs-attached tests and receipts | Build a real pre-adoption scanner; reconcile current revisions |
| OBJ-LIFE-01 | Deterministic plan/apply/verify with diagnostics | VERIFIED, bounded | `migration.py` plan/apply/verify; compiler inspection maps SQLAlchemy and direct psycopg errors to safe SQLSTATE; slice 5 receipts; read-only Doctor/status failure controls preserve operation identity, safe known remedies and UNKNOWN observations | Broader schema and failure boundaries |
| OBJ-LIFE-02 | Resumable, atomic, byte-bounded backfill with verification | VERIFIED, bounded | Journal, advisory lock, chunks, crash/resume tests; one expiry-specific local row retry with policy checks and atomic failure controls in protection/decrypt-back | Exact memory/WAL bounds remain host inputs |
| OBJ-LIFE-03 | Near-zero-downtime migration with capture and catch-up | SPECIFIED | Maintenance pause fallback only | Design, review, and measure an online protocol |
| OBJ-LIFE-04 | Parallel/adaptive migration without lost or duplicate work | SPECIFIED | None | Depends on OBJ-LIFE-03 |
| OBJ-LIFE-05 | Decrypt-back current edits; preserve schema behavior; package-free exit | VERIFIED, bounded | `deprotection.py` implements `cryptalis.reverse/v1`: staged plaintext, verified backfill, transactional switch, recorded constraint/index/collation restoration, guarded activation, approved removal, and terminal-state assertions; seven lifecycle cases pass on both profiles; an independent three-model application completes protect/search/modify/decrypt-back/remove and a package-free restarted process performs native CRUD; the same reverse completes on an adopted restored cluster with the binding; lock v2 captures and restores protected-column comments, statistics targets, storage, compression, options, column grants, constraint/index comments and extended statistics; grants are applied to the ciphertext column at protection; owned sequences remain refused; native catalogs now verify captured metadata through fresh-cluster restore and adopted removal; terminal removal refuses late metadata drift and retains the journal on failed retirement | Broader external application scope, physical column order, owned-sequence restore, retained-native |
| OBJ-LIFE-06 | Rollback, restore, stale pin refusal, RPO/RTO, disaster drills | PARTIAL | Older-snapshot and stale-pin refusals; reverse abort, pin/state ordering, corrupt-frame and disabled-guard refusals; isolated-cluster plaintext and protected restore with frame recovery and loud authority refusal; `cryptalis.restore/v1` adoption issues a binding after approval, frame authentication, schema comparison, and behavioral probes; the adopted cluster then attaches, reverses, and removes; local provider outage/revocation/lease drills keep the committed prefix and fail closed; restored-frame expiry recovery passes exact-policy, no-effects refusal and genuine fresh-cluster TEXT/VARCHAR controls; pinned unchanged Smolink now passes committed-process interruption/resume, root rewrap, payload rotation, genuine fresh-cluster adoption and latest-value package-free exit | Host-authenticated fencing/quarantine, RPO/RTO measurement |
| OBJ-LIFE-07 | Three separate rotation workflows | PARTIAL | Payload/search pure row-step expiry recovery passes 20 new native controls inside both 83-case cells; source-only observations and outer lease checks remain terminal. Root-rewrap successor cutover and shared activation, byte preservation, exact lineage, pending retry/cancellation, process/COMMIT recovery and repeated-rewrap decrypt-back/removal; source-pinned payload planning, durable shadows, source-only cancellation, immutable sealed target proof, atomic cutover/shared publication, mixed custody lineage/current-value removal and native process/COMMIT recovery; fresh-cluster TEXT/VARCHAR payload-backup adoption after later edits, independent selected-generation decoding and old-generation refusal; sealed search reindex, one active namespace with retained readers, native uniqueness/rollback, mixed search/payload/rewrap/search lineage and fresh-cluster search backups | Rotation on adopted restored targets, adopted-restore rewrap/cancellation, external provider/authority qualification |
| OBJ-LIFE-08 | Production KMS with outage/revocation/cost evidence | BLOCKED | Local development provider plus optional exact-context AWS KMS SDK bridge. 86 protocol/CF1 checks and 12 isolated actual-SDK cases. current installed-wheel original SQLModel application passes local SDK outage, authentication refusal and recovery. unchanged asynchronous Smolink also passes local SDK expiry/outage/authentication recovery and latest-value package-free exit; no live AWS qualification | Authorized provider account and independent review |
| OBJ-LIFE-09 | Install, upgrade, decommission, clean uninstall | PARTIAL | Importable package; approved in-database removal retires reverse-owned objects after decrypt-back; a package-free restarted application process performs native CRUD | Versioned upgrade/removal and broader external application evidence |
| OBJ-DX-01 | Minimal model/query changes; one manifest and one attach | IMPLEMENTED | `compile_protection`, `attach`, CLI inspection, bounded ACTIVE Doctor, read-only protection, payload/search preparation and reverse `status` | Unify plan/apply/remove entry points; complete operational status coverage |
| OBJ-DX-02 | Read-only `cryptalis doctor` with explicit UNKNOWN results | PARTIAL | ACTIVE runtime Doctor and shared Python diagnostic use one read-only repeatable snapshot for exact plan/pin/restore, runtime identity, target, lineage, effective privileges and schema; six unobserved boundaries and aggregate UNKNOWN; native refusal, no-key, cleanup and output evidence; Python preflight reuses the read-only compiler for manifest/schema diagnostics with no application rows or keys. Schema PASS leaves aggregate/unobserved checks UNKNOWN; CLI uses an explicit trusted host factory with host-code effects UNKNOWN and 135 native regression cases | Broader query/write route inventory, key/provider diagnostics and operational prerequisites |
| OBJ-DX-03 | Real FastAPI/SQLModel app plus a second independent app | PARTIAL | 38 original Python files stay unchanged. Pinned Smolink 498d24b runs its original FastAPI app without source/model/query edits. HTTP URL creation/refusals, real Redis, ORM CRUD and protect/decrypt-back/remove pass. A fresh import-denied process passes native CRUD. Protection covers only Url.destination. Installed Python 3.13 uses exact runtime pins and binary psycopg, with a read-only app/test fallback. The three-model application retains separate evidence. The optional SQLModel 0.0.48 bridge passes pinned unchanged template 0.10.0 CRUD/protection/removal with User.full_name only. Native exec/AutoString controls and package-free restart pass in the [bounded SQLModel profile](status.md#optional-sqlmodel-template-checkpoint-2026-10-23). The unchanged template additionally exercises fixture-only encrypted User.email equality/IN/global uniqueness in explicit single tenancy, with current-value exit. Both pinned profiles now use manifest preflight in source and current installed-wheel runs. The [Smolink recovery journey](status.md#manifest-first-application-recovery-checkpoint-2026-10-23) adds real interruption/resume, rotations and fresh-cluster latest-value exit | Broader protected fields and application suite, broader SQLModel coverage, second-application HTTP/startup/authentication and deployment |
| OBJ-DX-04 | Normal ORM identity, loading, sessions, pooling, async | PARTIAL | Bounded sync/async adapter and search tests | Broader ORM/framework coverage |
| OBJ-DX-05 | Complete quickstart, threat model, leakage, recovery docs | PARTIAL | README, architecture, security, lifecycle, walkthroughs | Keep docs tied to admitted APIs and evidence |
| OBJ-PERF-01 | Continuous native vs protected latency/resource measurements | PARTIAL | Revision-pinned 10k/100k/1m scalar/tuple and full-entity profiles with matched runtime roles, full migration/ACTIVE attach, raw paired samples, isolated storage and 100k/1m process CPU/RSS; historical million-row receipts retain prior source boundaries | Larger scale, cold/concurrent/tail/WAL/provider measurements |
| OBJ-PERF-02 | Profile-guided optimization without security loss | PARTIAL | Membership projection correction on 2026-10-09 | Continue profiling; no unverified speed claims |
| OBJ-PERF-03 | Multithreading/multiprocessing/async at 1/4/16/saturation | SPECIFIED | Single-worker maintenance path | Define and run isolation/backpressure/cancellation tests |
| OBJ-PERF-04 | Added p95 targets and growth path | PARTIAL | Revision-pinned 10k/100k/1m warm scalar/tuple and full-entity reads meet local 3ms/8ms targets; isolated column plus equality index measures 1.5248x/1.5296x/1.4372x for 53-byte names | Current latency failure and unchanged-source follow-up need causal classification. Larger scale/remote-provider/concurrent qualification and write/pause budgets remain open |
| OBJ-OPS-01 | Reproducible wheel/sdist, SBOM, provenance, reviewers | PARTIAL | `pyproject.toml`, `uv.lock`, `scripts/release_check.py`; [2026-10-21 receipt](_reset/release-check-20261021.json) shows identical repeat-build hashes, verified wheel `RECORD`, license metadata, CycloneDX 1.5 SBOM, and clean-venv import/CLI; the [combined defensive source receipt](_reset/defensive-projection-delete-release-20261023.json) binds 33 wheel modules and 37 installed-file checks to its 38-file source bundle; [dependency metadata controls](_reset/artifact-dependency-metadata-green2-20261023.json) compare wheel Python/dependency declarations with project metadata through standard parsers; the [current recovery release](_reset/doctor-recovery-release-20261023.json) verifies repeat archives, CLI, 36 product modules and 40 installed files against 41 current source hashes | Independent rebuild, signed provenance, vulnerability scan, publication identity, upgrade/uninstall matrix, independent review |
| OBJ-OPS-02 | Recoverable source/evidence and traceability | PARTIAL | Git history and `docs/_reset` receipts | Durable archive and fresh restore |
| OBJ-RESEARCH-01 | Source-backed comparative research with repeatable evidence | ONGOING | Research repository provenance; source-access and fallback rules in `AGENTS.md` | Preserve failed alternatives and provenance links |
| OBJ-RESEARCH-02 | One coherent working candidate that passes all gates | PARTIAL | Implemented scope above | Continue integration; all seven gates UNKNOWN |

## Import ledger

Boolean storage: typed descriptors and lock/v4 reuse CF1 and the common lifecycle.
The [current checkpoint](status.md#boolean-storage-checkpoint-2026-10-23) records
native controls, unchanged SQLModel journeys, mixed rotations, fresh-cluster
recovery and the final full regression. No production gate passes.

| Date | Research reference | Mechanism | Product files | Evidence | Status |
|---|---|---|---|---|---|
| 2026-10-23 | Search rotation and retained readers | Immutable search P/v1 and activation v4, fresh authenticated terms under unchanged payload custody, shared atomic cutover and one query namespace | Rotation planner, common generation engine, search crypto preparation and bound adapter admission | 92 focused cases, real COMMIT/SIGKILL recovery; [native](_reset/search-rotation-native-first-20261023.json); search TEXT/VARCHAR each one export and 29 restore cases; [backup](_reset/fresh-cluster-restore-20261023-11.json); 36 installed files and CLI startup | VERIFIED for listed local controls; [full regression](_reset/search-rotation-full-20261023.json) passes 1,869 plus 18 subtests; production custody/authority/retirement and seven gates remain unqualified or UNKNOWN |
| 2026-10-23 | Reverse runtime boundary | Host-pin-selected effective privileges before staging/publication/retirement, plaintext planning, actual absent-journal REMOVED exception | Shared reverse plan/state admission and native role/grant controls | 19 initial failures, 20 passing controls; [native](_reset/reverse-runtime-first-20261023.json); full 1,809 plus 18 subtests; [full](_reset/reverse-runtime-full-20261023.json); TEXT/VARCHAR each one export and 28 restore cases; [recovery](_reset/fresh-cluster-restore-20261023-9.json); reproducible archives and 35 installed files with CLI startup | VERIFIED for recorded privilege observations and preserved native edits; production credential retirement, host authority and seven full gates remain unqualified or UNKNOWN |
| 2026-10-23 | Payload-backup recovery and runtime admission | Current ACTIVE backup values, exact source/P/A proof and generation, effective native privilege checks before probes/keys | Restore and shared migration admission, native fresh-cluster profiles | TEXT/VARCHAR each one export and 28 restore cases; older rewrap/VARCHAR 26 plus one skip; seven ordinary refusal controls; [recovery](_reset/fresh-cluster-restore-20261023-6.json); full 1,789 plus 18 subtests; [full](_reset/restore-runtime-full-20261023.json); 35 installed files and CLI startup | VERIFIED for recorded local controls; adopted-target rotation, search reindex and all seven gates remain open or UNKNOWN |
| 2026-10-23 | Sealed payload cutover | Deterministic host-pinned A, repeated paired checks, atomic public-frame copy and guard/lineage exchange, target-only retry and shared publication | `rotation.seal_payload_rotation`, `switch_payload_rotation`, migration v3 admission and bounded publication verifier | 37 final native lifecycle/adversarial/recovery cases; [native](_reset/payload-cutover-final-native-20261023.json); independent copy wall/WAL interval observations; full regression 1,782 plus 18 subtests; [full](_reset/payload-cutover-full-20261023.json); 35 installed package files and CLI startup | VERIFIED for named local controls; search reindex, fresh-cluster payload-backup qualification and seven full gates remain open or UNKNOWN |
| 2026-10-23 | Payload staging and cancellation | Immutable P shadows, locked atomic progress, preserved source frames/indexes, authenticated resume and source-only abort | `rotation.apply_payload_rotation`, `status_payload_rotation`, `abort_payload_rotation`, shared maintenance mechanics | 26 native execution/recovery cases, including multi-table/tenant, actual COMMIT reply loss, SIGKILL/fresh restart and rollback after native writes; [recovery](_reset/payload-stage-recovery-20261023.json), full regression 1,745 plus 18 subtests; [full](_reset/payload-stage-full-20261023.json), 34 installed package files and CLI startup | VERIFIED for named controls; sealed A, cutover/publication and seven full gates remain SPECIFIED or UNKNOWN |
| 2026-10-23 | Payload-generation preparation | Source-pinned read-only proposal, exact retained roots/wrappers, one new independent monotonic payload root, unchanged search custody, whole-row logical budget and measured costs | `rotation.plan_payload_rotation`, `PayloadRotationPlan`, shared proposal validation and native controls | 163 focused planner/root-rewrap/crypto controls; full regression 1,719 plus 18 subtests; final matching-preparation-pin refusal; [focused](_reset/payload-plan-focused-20261023.json), [full](_reset/payload-plan-full-20261023.json), [final](_reset/payload-plan-final-admission-20261023.json) | VERIFIED for named read-only controls; staged/sealed payload execution and seven full gates remain SPECIFIED or UNKNOWN |
| 2026-10-23 | Pending root-custody cancellation | Source ACTIVE host authority, exact pending/proposal checks, atomic guard release/source restoration/ABORTED marker, target-outage recovery | `rotation.abort_rewrap`, native cancellation controls and public-fixture worker | 177 expanded lifecycle cases; final 52 cancellation/cutover cases including multi-table tenants, post-DDL rollback, terminal COMMIT loss and independent process retry; [final](_reset/rewrap-abort-final-20261023.json) | VERIFIED for named local controls; adopted-restore cancellation, full rotation and seven gates remain open or UNKNOWN |
| 2026-10-23 | Native root-custody cutover | Immutable transition/v2 successor, shared executor/guards/activation, exact predecessor admission | Migration, rotation, reverse inventory and native recovery worker | 165 focused lifecycle cases; 60 expanded recovery/planner cases including terminal COMMIT-reply loss and fresh-process activation; full regression 1,647 plus 18 subtests; rewrapped text/VARCHAR each pass one export and 15 fresh-cluster restore cases; [full](_reset/rewrap-execution-full-20261023.json), [recovery](_reset/rewrap-execution-recovery-20261023.json), [backup](_reset/fresh-cluster-restore-20261023-2.json) | VERIFIED for named local controls; complete rotation and all seven gates remain incomplete or UNKNOWN |
| 2026-10-23 | Scoped environment recovery and development diagnosis | Existing wrapper diagnoses Git/socket restrictions, private test provenance, tools, PG16 and restricted roles; supported approval supplies the required execution path | `scripts/test_postgres.py`; native diagnostic and source-evidence controls | Full suite: 1,620 tests plus 18 subtests, three skips; after final diagnostic guard: 76 focused checks; [full](_reset/environment-rewrap-full-20261023.json), [final](_reset/development-preflight-final-20261023.json) | VERIFIED in local cell; no service/credential/mount/policy changes; target authorization and all gates UNKNOWN |
| 2026-10-23 | Inactive root-rewrap admission | Read-only snapshot proposal with exact retained-root comparison, frame authentication and digest-only observations | `src/cryptalis/rotation.py`; standalone protocol and native controls | 35 native planner cases within 55 planner/provider checks; later full/focused regression above; five offline protocol groups; [native](_reset/rewrap-plan-native-green-20261023.json) | VERIFIED for named read-only observations; active rotation and all gates remain incomplete or UNKNOWN |
| 2026-10-22 | Typed numeric API admission | Share finite-number and representable-duration checks across protection, reverse and maintenance approval | Migration, reverse and native rate controls | Ten initial raw overflows; 119 focused native tests pass, including fractional rates and full transitions; reproducible artifacts and 32-file installed-wheel check pass; [focused](_reset/numeric-admission-focused-20261022.json) | VERIFIED for public numeric admission and unchanged native effects; earlier full/fresh runs are separate evidence; all gates UNKNOWN |
| 2026-10-22 | Exact restored frame policy | Admit only known PG16 forms of declared CF1 checks; bind older restatements to source fields; compare constraint identities by schema, table and name | Search storage, restore binding and fresh-cluster fixtures | Four initial false acceptances; 172 focused controls pass; text and VARCHAR each pass one export and 15 restore cases, including a same-name incoming FK; pinned Smolink and 1,567 full tests plus 18 subtests pass; [full](_reset/frame-policy-full-sa21-20261022.json), [restore](_reset/fresh-cluster-restore-20261022-27.json) | VERIFIED for named local controls and exact policy forms; general SQL equivalence is not admitted; all gates UNKNOWN |
| 2026-10-22 | Host artifact input admission | Reuse offline compiler lock and catalog structure checks; require safe estimate values and reverse snapshot maps before connection | Compiler, migration, reverse and native plan/CLI controls | 14 initial failures; 138 first focused and 64 final focused tests pass, including 24 admission controls and legacy v1/v2 artifacts; 1,567 full tests and 18 subtests pass; [full](_reset/plan-admission-full-final-sa21-20261022.json), [focused](_reset/plan-admission-final-focused-20261022.json) | VERIFIED for named structural checks and input diagnosis; no host authentication or live semantic claim; all gates UNKNOWN |
| 2026-10-22 | Host-bound staged catalog | Derive protection shadows from the source lock and reverse staging from the host-pinned protected snapshot plus native source types; retain journal continuity | Migration, reverse metadata documentation, native staged-schema controls | 24 initial false acceptances; 175 focused and 1,543 full tests plus 18 subtests pass; pinned Smolink and both fresh-cluster paths pass; [full](_reset/paused-schema-full-sa21-20261022.json) | VERIFIED for recorded catalog facts before paused progress; no freshness or value-verification claim; all gates UNKNOWN |
| 2026-10-22 | Host-bound paused writer fence | Share the host-derived guard check across protection and reverse paused operations and plaintext publication; retain journal continuity checks | Migration, reverse, native guard controls and revised crash/marker fault tests | 18 initial failures; 22 adversarial cases, two native fault controls, and 1,519 full tests plus 18 subtests pass; pinned Smolink and both fresh-cluster paths pass; [full](_reset/paused-guard-full-sa21-20261022.json) | VERIFIED for guard admission before progress; staged catalog admission is a separate later slice; all gates UNKNOWN |
| 2026-10-22 | Host-bound protected catalog | Derive the protected catalog from the source lock; inspect generated frame checks, equality indexes and pending guards; retain explicit restore restatement admission | Compiler, migration, search, reverse and restore modules; native adversarial and fresh-cluster tests | 14 initial false acceptances; 89 lifecycle, 219 expanded and 1,497 full tests plus 18 subtests pass; pinned Smolink passes; each text/VARCHAR fresh cluster passes one export and ten restore cases; [full](_reset/active-contract-full-sa21-20261022.json) | VERIFIED for recorded catalog facts and declared CF1 objects; no key/value or transitive function evidence; all gates UNKNOWN |
| 2026-10-22 | Verification source stability | Capture starting Python hashes and Git revision; compare final bytes; refuse success on changes while retaining the original pytest outcome | `scripts/test_postgres.py`, `tests/test_postgres_evidence.py` | Eight RED controls; 12 source-gate controls, ten real CLI tests, 1,459 full tests plus 18 subtests, pinned Smolink and both fresh-cluster paths pass; [focused](_reset/evidence-stability-final-focused-20261022.json) | VERIFIED for two-observation source admission; no full execution attestation; all gates UNKNOWN |
| 2026-10-22 | Reverse operational status | Read-only snapshot of decrypt-back phases, source identity, counters, native metadata and terminal removal; existing CLI dispatches by artifact format | `deprotection.py`, `migration.py`, `cli.py`; native status/CLI and fresh-cluster tests | 81 focused, 41 adversarial, seven final metadata controls, and 1,447 full tests plus 18 subtests pass; [focused](_reset/reverse-status-green-20261022.json), [adversarial](_reset/reverse-status-adversarial-20261022.json); removed counters remain unavailable | VERIFIED for named local checks; no key/value/provider verification or deployment authority; full gates UNKNOWN |
| 2026-10-22 | Pinned Smolink lifecycle and adoption corrections | Canonical catalog deparsing with restored caller settings and preserved SQLSTATE; invalidate warmed mapper flush caches at attachment | Compiler, adapter, native regressions, and pinned external app/workload tests | RED: native search-path and DML cache controls; initial full run found eight read-only route assertions. GREEN: 154 focused, 1,405 full plus 18 subtests, and the original app lifecycle on two Python 3.13 SQLAlchemy cells; [SA 2.0](_reset/smolink-final-sa20-20261022.json), [SA 2.1](_reset/smolink-final-sa21-20261022.json) | VERIFIED for storage-only Url.destination and the named alternate cells; all full gates UNKNOWN |
| 2026-10-22 | Native VARCHAR type admission | Lock v3 and pg-varchar/v1; native character limits, pending/refresh and failure-state parity; exact query binds; native type restoration; strict reader and transform admission | Compiler, adapter, search and reverse modules; native VARCHAR and fresh-cluster tests | RED: 27 initial cases; reader, rollback-state and hidden-transform controls. GREEN: 179 focused plus 18 subtests, 1,402 full plus 18 subtests, each text/VARCHAR fresh-cluster path passes one export and seven restore cases; [full](_reset/varchar-full-sa21-20261022.json), [VARCHAR restore](_reset/fresh-cluster-restore-20261022-8.json), [release](_reset/varchar-release-20261022.json) | VERIFIED, bounded local cell; external-app adoption remains open; all gates UNKNOWN |
| 2026-10-22 | Fractional measured-rate artifact correction | Share bounded JSON structure checks; admit decimals only at measured throughput paths, including embedded source plans | `src/cryptalis/manifest/parser.py`; `src/cryptalis/migration.py`; `src/cryptalis/deprotection.py`; `tests/test_transition_rates.py` | RED: 3 lifecycle failures. GREEN: 157 focused, 1,363 full tests plus 18 subtests, one export and seven restore cases, repeat release builds and 32 installed-file comparisons; [full](_reset/transition-rates-full-sa21-20261022.json), [restore](_reset/fresh-cluster-restore-20261022-6.json), [release](_reset/transition-rates-release-20261022.json) | VERIFIED, bounded local cell; all gates UNKNOWN |
| 2026-10-22 | Local operational-status slice | Read-only repeatable-read snapshot, committed progress, host pin comparison, safe CLI inputs and diagnostics | `src/cryptalis/migration.py`; `src/cryptalis/cli.py`; status and fresh-cluster tests | RED: missing API/command and malformed plan boundaries. GREEN: 1,351 full tests plus 18 subtests, one export and seven restore cases, eleven release groups and 32 installed-file comparisons; [full](_reset/status-full-sa21-20261022.json), [restore](_reset/fresh-cluster-restore-20261022-5.json), [release](_reset/status-release-20261022.json) | VERIFIED, bounded local cell; no data verification or provider admission; all gates UNKNOWN |
| 2026-10-22 | Native metadata backup/recovery and terminal removal | Lock v2 catalog comparison before journal retirement and during terminal checks; safe missing-journal inspection; native backup metadata assertions | `src/cryptalis/deprotection.py`; `tests/test_deprotection.py`; fresh-cluster qualification modules | RED: 6 drift cases, then 3 terminal retries. GREEN: 22 focused, 1,322 full plus 18 subtests, 1 export and 7 restore; [full](_reset/removal-metadata-full-sa21-20261022.json), [fresh cluster](_reset/fresh-cluster-restore-20261022-4.json), [negative control](_reset/fresh-cluster-metadata-control-20261022.json) | VERIFIED, bounded local cell; all gates UNKNOWN |
| 2026-10-22 | Installed-artifact identity audit | Compare installed bytes with the current wheel, refuse stale package files, isolate bytecode caches, and suppress raw child failure output | `scripts/release_check.py`; `scripts/test_release_check.py` | RED: 4 accepted artifact mutations, stale bytecode execution, and startup diagnostic exposure. GREEN: 11 test groups and actual offline uv install, 32 matched files, isolated CLI; [receipt](_reset/release-install-binding-20261022.json). No dependency or PostgreSQL qualification | VERIFIED, offline local cell; all gates UNKNOWN |
| 2026-10-22 | Local artifact-integrity audit | Complete wheel RECORD coverage and strict wheel/sdist member inspection | `scripts/release_check.py`; `scripts/test_release_check.py` | RED: 25 failures and 4 errors. Review RED: 7 further failures. GREEN: 10 test groups, valid controls, matching offline repeat builds, SBOM; [receipt](_reset/release-integrity-20261022.json). PostgreSQL preflight failed, exit 2; full suite unrun | VERIFIED, offline local cell; all gates UNKNOWN |
| 2026-10-21 | Local release-artifact slice | Reproducible wheel/sdist build, wheel `RECORD` verification, archive-member inspection, MIT license metadata, CycloneDX 1.5 SBOM, clean-venv import and CLI smoke | `pyproject.toml`; `scripts/release_check.py` | GREEN: two builds matched; wheel and sdist hashes recorded; clean venv imported the installed package and started the CLI; [receipt](_reset/release-check-20261021.json) | VERIFIED, local cell; G-RELEASE UNKNOWN |
| 2026-10-19 | `debgh-workspace/cryptalis-research-lab` branch `accel/integration-s20-20261014`, commit `15cf040`; `candidate/src/cryptalis/deprotection.py` (retained-native) | Reverse lifecycle evaluated; product implements an in-place `cryptalis.reverse/v1` variant for the admitted transition format, with journal/pin/approval checks, verified chunked backfill, transactional switch, and approved removal | `src/cryptalis/deprotection.py`; `tests/test_deprotection.py` | GREEN: 7 focused and 1,299 full SA2.1; 7 focused and 1,271 passed + 28 skipped full SA2.0 | VERIFIED, bounded, local cell |
| 2026-10-19 | `debgh-workspace/cryptalis-research-lab` branch `accel/integration-s20-20261014`, commit `15cf040`; `candidate/src/cryptalis/crypto/_payload_rotation.py`; test `test_payload_rotation_preparation.py` (native staging oracle omitted; product uses the in-place layout) | Inactive bounded payload-generation transform with exact source decode, target reseal, identity/header preservation, and lease recheck | `src/cryptalis/crypto/_payload_rotation.py`; `tests/test_payload_rotation_preparation.py` | GREEN: 40 focused SA2.1, 1,292 full SA2.1, 90 focused SA2.0 | VERIFIED, internal, local cell |
| 2026-10-19 | `debgh-workspace/cryptalis-research-lab` branch `accel/integration-s20-20261014`, commit `15cf040`; `candidate/src/cryptalis/manifest/compiler.py` direct-driver catch | Map direct psycopg inspection errors to `InspectionUnavailable` with safe SQLSTATE | `src/cryptalis/manifest/compiler.py` | GREEN: 61 focused each profile; 1,292 full SA2.1; 1,264 passed + 28 skipped full SA2.0 | VERIFIED, local cell |
| 2026-10-19 | `debgh-workspace/cryptalis-research-lab` branch `accel/integration-s20-20261014`, commit `15cf040`; `candidate/src/cryptalis/crypto/_rewrap.py`; test `test_rewrap_preparation.py` | Inactive rewrap candidate over every admitted root with target identity checks and no partial result | `src/cryptalis/crypto/_rewrap.py`; `tests/test_rewrap_preparation.py` | GREEN: 16 focused, 1,252 full SA2.1, 54 focused SA2.0 | VERIFIED, internal, local cell |
| 2026-10-19 | `debgh-workspace/cryptalis-research-lab` branch `accel/integration-s20-20261014`, commit `15cf040`; `candidate/src/cryptalis/_sqlalchemy_search.py` negative-predicate hunks; test `test_sqlalchemy_negative_predicates.py`; updated search grammar test | Simple `!=`, `NOT IN`, and NULL presence with native truth and outer-join tenant-guard preservation | `src/cryptalis/_sqlalchemy_search.py`; `tests/test_sqlalchemy_negative_predicates.py`; `tests/test_sqlalchemy_search.py` | RED: 57 failed, 2 passed. GREEN: 366 focused SA2.1, 1,236 full SA2.1, 202 focused SA2.0 | VERIFIED, local cell |
| 2026-10-19 | `debgh-workspace/cryptalis-research-lab` branch `accel/integration-s20-20261014`, commit `15cf040`; `candidate/src/cryptalis/sqlalchemy.py::UnsafeEngineLogging`; test `test_attachment_engine_preflight.py` | Refuse unsafe query echo or parameter hiding before connection or key access | `src/cryptalis/sqlalchemy.py`; `tests/test_attachment_engine_preflight.py` | RED: 12 unsafe-setting subtests reached `do_connect`. GREEN: 307 focused SA2.1, 1,177 full SA2.1, 143 focused SA2.0 | VERIFIED, local cell |

## Seven gates

| Gate | Status | Required evidence |
|---|---|---|
| G-ADAPTER | UNKNOWN | Complete admitted matrix; unsupported-route coverage; real app; independent review |
| G-CRYPTO | UNKNOWN | Independent composition, nonce, context, and key-lifetime review |
| G-QUERY | UNKNOWN | Semantics and leakage admission for every claimed profile |
| G-LIFECYCLE | UNKNOWN | Fresh-cluster restore, upgrade/rollback, rotation, removal |
| G-PROVIDER | UNKNOWN | Real authorized KMS custody, outage, revocation, and cost evidence |
| G-POLICY | UNKNOWN | Authenticated deployment policy, stale-worker fencing, quarantine |
| G-RELEASE | UNKNOWN | SBOM, provenance, clean build/install, independent reviews |

## Next critical path

1. Run the same lifecycle through a pinned external application, then repeat it on a
   fresh PostgreSQL cluster.
2. Close the remaining reverse-lifecycle metadata and recovery gaps (physical column
   order, retained-native, owned sequences). Lock v2 now captures and restores comments,
   statistics targets, storage, compression, options, column grants, constraint and
   index comments, and extended statistics. Owned sequences remain refused. See the [metadata research note](research/metadata-preservation-and-format-evolution.md)
   and the [lock v2 proposal](research/lock-v2-metadata-proposal.md).
3. Use the competitive matrix to select high-value missing capabilities and complete
   independent application journeys. Preserve native PostgreSQL correctness oracles
   and required focused security checks.
4. Extend the fresh-cluster range with multi-table, fault, and provider-outage drills.
5. Keep every external review and provider item explicitly UNKNOWN; review the
   [lab reconciliation](research/lab-reconciliation-2026-10-19.md) for refused-metadata
   signals, without adopting lab code.
