# Product objective ledger

All **34 objectives** remain required for the first production release. This is
the single work ledger. [Status](status.md) owns executed results and release
gates; [compatibility](compatibility.md) owns the admitted operation matrix.

## Status vocabulary

| Label | Meaning |
|---|---|
| SPECIFIED | Required; implementation is absent. |
| IMPLEMENTED | Product source exists; acceptance is incomplete. |
| PARTIAL | Some of the objective is implemented or verified; listed gaps remain. |
| VERIFIED, bounded | Executed evidence supports only the stated scope and revision. |
| BLOCKED | A named external prerequisite is unavailable. |
| ONGOING | Continuing evidence/research work, not a completed release objective. |
| QUALIFIED | All applicable acceptance criteria and release gates pass; no current objective has this release claim. |
| UNKNOWN | Required evidence is missing; never a pass. |

Do not measure completion by commits or test totals. Preserve failed and skipped
evidence. Update a row when its implementation, proof, gap or next action changes.

## Objective ledger

The [primary SRS](requirements.md) maps all 20 core requirements to these 34
objectives. Earlier research imports retain their provenance in [history](history/README.md);
the current contract owners define acceptance, without dropping any objective.

| ID | Requirement (abbreviated) | Product status | Implemented mechanism and evidence | Open gap / next action |
|---|---|---|---|---|
| OBJ-SEC-01 | Encrypt before PostgreSQL; prove at SQL/driver boundaries | VERIFIED, bounded | `crypto/cf1.py`, `sqlalchemy.py`; slice 2/3 receipts in `docs/_reset`; real runtime-role tests | Broader writer/auth/provider boundaries; independent review |
| OBJ-SEC-02 | Bind tenant, field, row, generation; reject malformed/swapped frames | VERIFIED, bounded | CF1 AAD, descriptor binding, sync/async tamper tests | Collision assumptions and composition review |
| OBJ-SEC-03 | Authorization, result lineage, tenant isolation, parameterization | PARTIAL | Tenant-scoped sessions, requested-point checks, typed errors; expanded entity/table SELECT type, operation and owned-lineage admission; finite mapped DELETE binds compiled/final parameters to original tenant/record authority | Host authorization is external; audit remaining ORM routes |
| OBJ-SEC-04 | Detect plaintext bypass through ORM, bulk, SQL, COPY, jobs, logs | PARTIAL | Writer inventory, guarded SQL/driver boundaries and runtime-privilege checks reject unsafe writes/logging before key access. [Security](security.md) defines the admitted boundary. | Complete route inventory; identity variants now refuse during planning; deployment enforcement is unverified |
| OBJ-SEC-05 | Isolate keys and bound nonces, leases and cache lifetime. Preserve fork safety | VERIFIED, bounded | Policy, cache expiry, fork refusal and fresh-child preparation; real local provider outage/revocation and held-mutex fork controls. See [history](history/implementation-2026-10.md). | Remote cancellation, usage limits, production custody |
| OBJ-SEC-06 | Reduce equality/frequency/access leakage with documented trade-offs | SPECIFIED | Equality leakage is declared; no stronger profile admitted | Threat-model and benchmark a lower-leakage profile; six-gate admission |
| OBJ-SEC-07 | Independent red-team, crypto, adapter, provider, supply-chain review | BLOCKED | None | Assign independent reviewers; do not self-certify |
| OBJ-QUERY-01 | Exact equality, `IN`, scoped uniqueness, NULL logic, races | VERIFIED, bounded | `_sqlalchemy_search.py`, slice 4 receipt; native concurrency tests | Keep grammar reconciliation current |
| OBJ-QUERY-02 | Ordinary SQL correctness: NULL predicates, aliases, joins, projections | PARTIAL | Native sync/async NULL, alias, projection and public-expression controls; bounded protected counts and DISTINCT. Exact grammar: [compatibility](compatibility.md). | Continue finite native-oracle matrix; general Boolean NOT, protected grouping and protected joins remain unadmitted |
| OBJ-QUERY-03 | Ordering, ranges, prefix/text search, aggregates, other types | PARTIAL | Bounded TEXT/VARCHAR, Boolean, signed integer, finite Date and UUID storage; non-NULL/distinct counts and authenticated DISTINCT reuse admitted representations. Current lifecycle/cost receipts retain their exact boundaries | Range/order/pattern profiles, other aggregates and structured JSON remain unadmitted. Refusal does not complete the objective |
| OBJ-QUERY-04 | INSERT/UPDATE/DELETE, bulk, RETURNING, triggers, cascades, savepoints | PARTIAL | ORM flush, bounded mapped dictionary INSERT/UPDATE and finite mapped DELETE; native transaction, identity, savepoint, paging and INSERT RETURNING controls. Exact shapes: [compatibility](compatibility.md). | Qualify UPDATE/DELETE RETURNING, upserts, broader DML/defaults and each trigger/cascade effect separately |
| OBJ-QUERY-05 | Versioned compatibility corpus and read-only scanner | PARTIAL | Native-vs-attached tests and receipts; [supplied SELECT preflight](history/implementation-2026-10.md#installed-application-query-diagnostics-2026-10-24) reuses runtime admission before migration and diagnoses original HTTP query structures without rows or keys | Complete automatic query/write route inventory and reconcile current revisions |
| OBJ-LIFE-01 | Deterministic plan/apply/verify with diagnostics | VERIFIED, bounded | `migration.py` plan/apply/verify; compiler inspection maps SQLAlchemy and direct psycopg errors to safe SQLSTATE; slice 5 receipts; read-only Doctor/status failure controls preserve operation identity, safe known remedies and UNKNOWN observations | Broader schema and failure boundaries |
| OBJ-LIFE-02 | Resumable, atomic, byte-bounded backfill with verification | VERIFIED, bounded | Journal, advisory lock, chunks, crash/resume tests; one expiry-specific local row retry with policy checks and atomic failure controls in protection/decrypt-back | Exact memory/WAL bounds remain host inputs |
| OBJ-LIFE-03 | Near-zero-downtime migration with capture and catch-up | PARTIAL | Row-lock backfill, durable capture/catch-up fence and reversible role transfer; original HTTP and fresh-cluster rotation/recovery journeys. [Lifecycle](lifecycle.md) owns the limits. | Production pause measurement, deployment fencing, future type coverage and independent review |
| OBJ-LIFE-04 | Parallel/adaptive migration without lost or duplicate work | PARTIAL | Bounded parallel crypto with one SQL writer, ordered results and adaptive approved row/byte limits; real worker overlap, failure atomicity and authenticated resume. | Worker-scaling/resource measurements and multiple database executors remain unqualified |
| OBJ-LIFE-05 | Decrypt-back current edits; preserve schema behavior; package-free exit | VERIFIED, bounded | Verified current-value decrypt-back, native metadata/constraint restoration, owned sequences and opt-in public slots; genuine restored-target and original-application package-free exits. [Lifecycle](lifecycle.md) and [history](history/implementation-2026-10.md). | Broader external application/schema coverage, retained-native objects and retained-copy obligations. |
| OBJ-LIFE-06 | Rollback, restore, stale pin refusal, RPO/RTO, disaster drills | PARTIAL | Stale-pin/target refusals, process/COMMIT interruption recovery, genuine fresh-cluster adoption, provider failure controls and latest-value package-free exit. [Restore contract](lifecycle.md). | Host-authenticated fencing/quarantine, RPO/RTO measurement |
| OBJ-LIFE-07 | Three separate rotation workflows | PARTIAL | Distinct root rewrap, payload rotation and search reindex; adoption lineage, source-only cancellation, process/COMMIT recovery, publication and current-value removal controls. [Rotation contract](lifecycle.md). | Combined provider/database rotation and recovery under production authority; retained-wrapper retirement. |
| OBJ-LIFE-08 | Production KMS with outage/revocation/cost evidence | PARTIAL | Optional OpenBao Transit: actual TLS, context binding, token/version revocation, outage, sealed restart and source-fenced Raft snapshot recovery from source/installed wheel. [Provider evidence](openbao.md). | Hardened deployment, workload identity, audit, HA, production backup custody, combined disaster recovery, controlled destruction and independent review. |
| OBJ-LIFE-09 | Install, upgrade, decommission, clean uninstall | PARTIAL | Importable package; approved in-database removal retires reverse-owned objects after decrypt-back; a package-free restarted application process performs native CRUD | Versioned upgrade/removal and broader external application evidence |
| OBJ-DX-01 | Minimal model/query changes; one manifest and one attach | IMPLEMENTED | Manifest compiler, SQLAlchemy/SQLModel attachment, shared key-free application configuration for init/Doctor/planning/attachment and operational plan/apply/resume/status commands; unchanged original application journeys with explicit host authority. [Host inputs](host-contexts.md). | Extend shared configuration into remaining lifecycle workflows and reduce operator glue while keeping authority explicit. |
| OBJ-DX-02 | Read-only `cryptalis doctor` with explicit UNKNOWN results | PARTIAL | Read-only manifest/schema/query preflight through shared application configuration, pre-key planning query admission, ACTIVE database diagnosis and cold-provider checks that preserve caller leases. Explicit UNKNOWN for unobserved boundaries. [Doctor routes](README.md#choose-a-route). | Broader query/write route inventory, provider workload identity/audit and operational prerequisites |
| OBJ-DX-03 | Real FastAPI/SQLModel app plus a second independent app | PARTIAL | Pinned unchanged Smolink and SQLModel template: HTTP/ORM, real Redis/local mail, protect/rotate/fresh restore/current-value removal and import-denied restart. Field/profile limits remain in [history](history/implementation-2026-10.md). | Broader protected fields and application suites, remaining SQLModel paths, browser/deployment operation and external mail |
| OBJ-DX-04 | Normal ORM identity, loading, sessions, pooling, async | PARTIAL | Native identity/loading/error/rollback controls, sync/async separate sessions at 1/4/16, pool reuse and one-connection cross-tenant cancellation. [Compatibility](compatibility.md) defines the admitted subset. | Broader loading, pool invalidation, concurrent workload and framework coverage |
| OBJ-DX-05 | Complete quickstart, threat model, leakage, recovery docs | PARTIAL | [Documentation map](README.md), manifest and host references, contracts, operator walkthroughs, local qualification commands and illustrated guide. | Keep examples and routes aligned with each admitted API and receipt; broader adoption guidance follows implementation. |
| OBJ-PERF-01 | Continuous native vs protected latency/resource measurements | PARTIAL | Revision-pinned 10k/100k/1m scalar/tuple and full-entity profiles with matched runtime roles, full migration/ACTIVE attach, raw paired samples, isolated storage and 100k/1m process CPU/RSS; historical million-row receipts retain prior source boundaries | Larger scale, cold/concurrent/tail/WAL/provider measurements |
| OBJ-PERF-02 | Profile-guided optimization without security loss | PARTIAL | Membership projection correction on 2026-10-09; per-inspection lineage reuse with a paired target/candidate CPU benchmark, native-lineage controls and an explicit early-match cost increase in the [assignment profile](professor-guide.md#query-inspection-optimization) | Continue whole-path profiling; no unverified speed claims |
| OBJ-PERF-03 | Multithreading/multiprocessing/async at 1/4/16/saturation | PARTIAL | Bounded native/protected sync/async profiles at 1/4/16 sessions with cancellation and pool reuse; exact observations remain revision-bound in [history](history/implementation-2026-10.md). | Multiprocessing, saturation, latency/resource budgets and broader workload qualification |
| OBJ-PERF-04 | Added p95 targets and growth path | PARTIAL | Revision-pinned 10k/100k/1m warm scalar/tuple and full-entity reads meet local 3ms/8ms targets; isolated column plus equality index measures 1.5248x/1.5296x/1.4372x for 53-byte names | Current latency failure and unchanged-source follow-up need causal classification. Larger scale/remote-provider/concurrent qualification and write/pause budgets remain open |
| OBJ-OPS-01 | Reproducible wheel/sdist, SBOM, provenance, reviewers | PARTIAL | Current source/installed CI checks repeat-built archives, wheel RECORD, SBOM, dependency metadata, frozen vulnerability audit and installed lifecycle. Exact artifacts: [status](status.md#current-complete-ci-qualification). | Independent rebuild, signed provenance, controlled publication identity, versioned upgrade/uninstall matrix and independent review. |
| OBJ-OPS-02 | Recoverable source/evidence and traceability | PARTIAL | Git history and `docs/_reset` receipts | Durable archive and fresh restore |
| OBJ-RESEARCH-01 | Source-backed comparative research with repeatable evidence | ONGOING | Research repository provenance; source-access and fallback rules in `AGENTS.md` | Preserve failed alternatives and provenance links |
| OBJ-RESEARCH-02 | One coherent working candidate that passes all gates | PARTIAL | Implemented scope above | Continue integration; all seven gates UNKNOWN |


## Next critical path

1. Extend shared application configuration through the remaining lifecycle
   workflows, keeping tenant authentication, provider credentials, publication
   pins and maintenance authorization explicit.
2. Extend Doctor's route inventory and the admitted native ORM/type matrix with
   real application oracles. Advanced search requires its separate leakage and
   security admission; refusal alone is not completion.
3. Complete versioned upgrade/rollback, deployment fencing, retained-copy
   inventory, combined database/provider recovery and controlled retirement.
4. Measure current hot/cold/concurrent provider, write, migration and resource
   costs against approved budgets; do not promote historical measurements.
5. Obtain independent crypto/security/database review and production identity,
   audit, HA, recovery and release-provenance evidence. Live cloud accounts are
   needed only for selected cloud-provider cells.

The [build guide](build-guide.md) owns the execution sequence and verification
commands. [Historical imports](history/imports-2026-10.md) retain provenance.
