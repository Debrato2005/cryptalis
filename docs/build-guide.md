# Implementation handoff

Status: design dependency order. It does not authorize autonomous runtime changes under the manual learning workflow.
Read [README](../README.md), [architecture](architecture/README.md), [security](security.md), [status](status.md),
the relevant subsystem owner and this slice's gate, then inspect source/tests.
Design drives code. Existing APIs, modules, schemas, tests and commands can change during authorized implementation.
Do not recreate eliminated contracts or reinterpret experimental schema-1/F1/W1 bytes as production format 2.
No shipped production data requires those research readers. Retain only separately justified utilities/evidence.
The [reuse/change map](status.md#reuse-and-replacement) is a review input, not a preservation mandate.

## Invalidating feasibility first

Run these bounded experiments before implementing the declaration compiler or full provider/ORM architecture.
They precede S01–S13. Spike labels S1–S4 are separate from those implementation slices.
All 33 blocked decisions have an [invalidating property](decisions.md#hardening-decisions-and-feasibility-triage).
No gate is waived by a local observation. Failure changes the contract/architecture, never the oracle.

| Order | Fatal hypothesis / decision | Required deciding observation | Evidence now |
|---|---|---|---|
| F01 | H3/H4 public ORM (D01,D14,D35) | Dirty B/stored A survives no_autoflush, normal query autoflush is explicit, refresh suppresses autoflush, last-row failure publishes zero, expired identity refresh has no implicit I/O, late flush/await additions reject without resealing, using public APIs | [S1](../spikes/README.md) local subset passes. Full mapping/Result/cascade/default/cancel cell UNKNOWN |
| F02 | H1/H2 ownership and commit (D03,D18,D21–D24,D33–D34) | Suspend/crash/lock-loss at each boundary, stale token checked in authority/DB, outcome retained through later delete, marker absence cannot classify live backend; later flushes have distinct immutable batch IDs and one transaction outcome | S2 1,216 states/3,664 transitions plus local PG marker/fence cases. AWS/termination/failover UNKNOWN |
| F03 | A2/A3 crypto and field semantics (D04–D06,D08,D11,D19) | Native primitive capability, independent exact vectors, context substitutions, fork re-admission, expert composition/bounds review | S4 smoke passes. Descriptor vectors and independent review UNKNOWN |
| F04 | M5/M7 exact query/uniqueness surface (D08,D10–D13,D36,D38) | Real PG differential truth AND error oracle, unsupported branches reject before SQL, concurrent duplicate conflict, index use and hostile-term counterexample | S3 and M5 local subset passes. Complete runtime grammar UNKNOWN |
| F05 | M6/A1/A5/A6 product viability (D15–D17,D23,D25,D31,D37,D40,D42) | Tiny quotas deny oversize/retry/mirror failure, all 15 kill criteria, representative host integration, hot/cold/cost/downtime/removal budgets | Fake capacity checks pass. AWS cost/performance/customer/rollback/removal UNKNOWN |
| F06 | M8/M9 recovery/custody/release (D20,D27–D29,D39) | Every recovery command repeated, wrong identity rejected, output canaries, restore under current denial, native destruction positive controls and clean artifact evidence | Fake resume/abort checks pass. Commands/live custody/release UNKNOWN |

Only after these experiments support the intended profile should the human start S01.
The authorized spikes are disposable feasibility evidence. They are not Cryptalis runtime implementation or verification.

## Dependency sequence

Build a complete useful vertical product with equality and a safe exit before optional breadth.
Production claims wait for every required gate. A runnable development demonstration can precede production admission and must retain its limits.

| Slice / why | Observable behavior / internal component | Dependencies and invariant | Failure cases, tests and definition of done |
|---|---|---|---|
| S01 Declare intent once | Bounded schema-2 declaration -> deterministic lock/diff. `manifest` and typed contracts | Chosen bounded canonical rules and supplied registry facts. Existing helpers require reuse review. No implicit activation or unknown member acceptance | G-MANIFEST: complete fixture schema, exact defaults, duplicate/limit/type/unknown rejection, remove/re-add/rename, total diff and unrelated-field descriptor stability. Two independent canonical implementations agree. No runtime support claim |
| S02 Freeze crypto and semantic bytes | Exact CPD2, descriptor, KDF/AAD/HMAC and scalar/normalizer vectors. `crypto` | S01 and exact library/native pins. No custom cipher, partial decrypt or coercion | G-CRYPTO/G-CROSSKEY/G-BINDING/G-SEMANTICS: known-answer vectors, every header/context substitution, wrong key/generation, fork/RNG faults, budgets, full-width terms and exact Unicode/decimal/NULL cases. Independent expert review accepts composition before real-data use |
| S03 Current custody and authority | Workload-authenticated exact KMS roots, regional current head/tombstones/CAS, quota. `providers/authority` | S01–S02. Current policy separate from DB restore and cached keys | G-AUTHORITY/G-PROVIDER: conditional race/idempotency, S3 exact-version intent order/loss/expiry, large-batch domain/tenant epochs, table replacement/old backup, context/ARN/root pin mismatch, permissions, throttling/outage, eventual state, lost response, authority loss. No fake provider destruction |
| S04 Ordinary attributes and read/write | Attached sync/async session factory, client identity, hidden mapping, buffered logical handoff. `sqlalchemy` | S01–S03. Every supported DML encrypts first. One tenant/session/task | G-ORM/G-ASYNC/G-REVOCATION: real PostgreSQL new/dirty/no_autoflush/delete/refresh/expire/rollback/identity-map/projection-and-predicate Result shapes. Emitted SQL/rows/logs. Async cold-key batch/cancellation/loop-lag. Public instrumentation only, no private-hook fallback |
| S05 Equality/IN/uniqueness vertical slice | Normal select predicates, full terms, atomic companions, race-safe UNIQUE | S02–S04. No silent filtering, changed SQL semantics or unenforced uniqueness | G-SEARCH/G-SEMANTICS: differential logical oracle for every admitted tree/null/IN/LIMIT shape, concurrent duplicate writes, returned term swaps, chosen-input/frequency demonstration. Every unsupported tree rejects before SQL |
| S06 Doctor and physical plan | Manifest/schema/mapping/writer/provider/leakage diagnostics and reviewed DDL/Alembic proposal. `doctor/schema` | S01–S05. Unknown stays UNKNOWN, no startup DDL or generic SAST | G-DOCTOR/G-BYPASS/G-TARGET/G-PLAN: expiry/approval/tampered proposal and actual roles/COPY/Core/bulk/driver/ETL paths, restricted inspection, wrong RDS identity, bad logs, drift/invalid indexes. Known planted issue fails, unseen writer cannot pass, second autogenerate has no Cryptalis diff |
| S07 Shared protect/verify executor | Maintenance shadows, complete backfill, target-bound journal, full verify and switch. `lifecycle` | S01–S06. One overlapping operation, no mixed authority or partial-success activation | G-TRANSITION: crash on each durable effect/ack, two executors, lock loss, source drift, stale checkpoint, prepared/CDC rejection, disk/WAL/index/provider faults. Full source/target equivalence, negative verifier mutants and no unapproved plaintext |
| S08 Rollback and explicit finalization | Current mirror, truthful exposure/deadline, verified reversal, exact cleanup | S07. Reversibility is actual current data plus reader/keys, not an old snapshot | G-ROLLBACK: writes after switch mirror atomically, mirror error aborts, deadline stops writes, rollback before cleanup succeeds, after cleanup refuses, partial cleanup remains visible. Source loss never occurs without exact approval |
| S09 Rewrap/reencrypt/reindex and upgrades | Reader-first admission, one active writer protocol/generation, verified layer-specific transform | S05–S08. Old dependency retirement cannot strand rows/backups | G-ROTATE: adjacent binaries/old jobs, search normalization merge conflicts, invalid unique indexes, crash/resume at every layer. No uniqueness gap or confusion between wrapper and payload changes |
| S10 Restore and disaster admission | Isolated target, current external denial, trusted schema, admissible full verification | S03,S07–S09. No restored old authority, implicit DR or raw root escrow | G-RESTORE: old DB/VM/authority snapshots, RDS replacement/blue-green/failover, hostile schema, tombstoned rows, missing backup reader/wrapper/KEK, lost latest head. Unprovable state stays denied |
| S11 Truthful revocation/destruction | Managed subject denial and separately bounded domain custody destruction | S03,S08–S10. Shared search/backup recovery caveats persist | G-DESTRUCTION/G-REVOCATION: deny/commit/output races, suspend/restart/fork, deletion request/pending/cancel/native completion, cached roots, subject wrapper restored under surviving KEK. Never call recoverable subject data erased |
| S12 Complete deprotect/remove | Authenticate and backfill plaintext with prior approval, verify, package-free app, safe metadata/key retirement | S07–S11. Package last, every retained encrypted backup has reader/key or explicit loss approval | G-REMOVE: no/wrong/expired staging approval, crash after first plaintext write, old encrypted backups, stale jobs, partial retirement. Real host read/write/query tests without package and independent recovery reader exercise |
| S13 Product performance and release | End-to-end costs, safe diagnostics, dependency/artifact provenance, reviewed release | All supported slices. No evidence inflation or protection bypass for speed | G-PERFORMANCE/G-RELEASE: whole-path hot/cold/outage/rotation benchmarks, canary sinks and broken collectors, clean wheel/install/startup/SBOM/attestation checks, independent security/migration review. Every required compatibility cell and recovery workflow passes |

After the invalidating experiments support the chosen profile, the first implementation file is the schema-2 declaration validator under S01, with a behavior-focused failing test for manual typing.
Agree the single file's responsibility, exact input/output, necessary compatibility and failure oracle. Experimental schema-1 behavior is not a mandatory product requirement before the builder types it.
This documentation reset does not supply that implementation or silently begin it.

## Acceptance evidence

Expected states below describe scenario outcomes, not whether the test runner exits successfully.
`PASS` means the stated postcondition holds. `DENIED` means a supported failure prevents the action. `FAIL` means verification detects a violation.
`PENDING` means actual effects need reconciliation. `INCONCLUSIVE` means required observation is unavailable.
Every scenario uses exact dependency/build/manifest/schema/provider identities, synthetic data, positive controls and required negative mutants.
These are unexecuted runtime evidence requirements today. Existing structural tests remain separate.

| Scenario | Expected state and oracle | Gate |
|---|---|---|
| Public source/config plus finalized DB dump | PASS: independent reader without authority cannot recover protected payloads. State explicit term/length/identity leakage | G-CRYPTO |
| Bit tamper, corrupted envelope, truncated/trailing bytes, unknown format or flags | DENIED: no partial logical value. Bounded safe diagnostic and no arbitrary key lookup | G-CRYPTO |
| Relocate field/record/table, wrong requested ID, subject swap or cross-tenant substitution | DENIED: expected context wins even when DB companion metadata is swapped | G-BINDING |
| Old authentic same-context envelope replay | PASS with documented replay limitation: old value can authenticate under still-admitted context, no freshness claim | G-BINDING |
| Wrong/unregistered key or altered wrapper registry digest | DENIED: one exact root lookup, no trial keys or injected provider | G-CROSSKEY |
| Disabled or delete-pending KMS key on cold path | DENIED: no value. Native observation and eventual-consistency limits retained | G-PROVIDER |
| KMS outage/throttling, warm currently admitted cache versus cold/expired cache | PASS warm within bounds / DENIED cold or expiry. No hidden unlimited retry. Count actual calls | G-PROVIDER |
| Authority outage with warm key | DENIED: current state cannot be replaced by cache | G-AUTHORITY |
| Cache expiry, process restart, fork and copied task context | DENIED stale handles, PASS fresh independently admitted incarnation. No memory-destruction inference | G-REVOCATION |
| Stale worker with old generation, old binary, restored queue/job | DENIED before new write/release admission. Current head/fence and exact binary tuple checked | G-ROTATE |
| Suspend after authorization before handoff/COMMIT, concurrent deny | PENDING until known operation drains/reconciles, then DENIED new operations. No instant plaintext recall | G-REVOCATION |
| Invisible VM-memory clone | INCONCLUSIVE/outside supported deployment: do not present TTL or PID as universal snapshot defense | G-REVOCATION |
| Two overlapping migrations, executor death/lock loss | DENIED losing executor. Exactly one owner and no stale commit/switch | G-TRANSITION |
| Crash before/after every row, checkpoint, DDL, CAS, provider and irreversible effect | PENDING after ambiguous boundary; PASS resume only after exact durable reconciliation | G-TRANSITION |
| Resume old checkpoint against new target/head | DENIED. Restored checkpoint cannot grant progress | G-TARGET |
| Count/shape-only verification, omitted scan range or corrupt target value | FAIL: positive defects detected, switch denied despite apparently complete cursor/count | G-TRANSITION |
| Live role/writer drift, prepared transaction, CDC, invalid index, privilege-limited inventory | FAIL for proven violation / INCONCLUSIVE for missing facts. No switch/finalization | G-DOCTOR |
| Rollback after current writes before finalization | PASS: full equivalence and monotonic reversal, no lost current value | G-ROLLBACK |
| Mirror update failure or deadline expiry | DENIED whole write. No stale mirror is advertised as rollback | G-ROLLBACK |
| Rollback after source/key/read-format contraction | DENIED `IrreversibleState`, actual alternate recovery dependencies shown | G-ROLLBACK |
| Restore old DB after tombstone/key/format retirement | DENIED managed resurrection. Remove/quarantine denied rows before verified admission | G-RESTORE |
| Restore old VM/cache or old authority table at reused name | DENIED stale admitted identity. Fresh runtime/current authority required | G-RESTORE |
| Loss of current authority proof or permanent KEK/wrapper loss | DENIED recovery. Explicit unprovable-state/permanent-data-loss boundary | G-RESTORE |
| Reader-first rolling deployment | PASS only if both binaries share current writer protocol and all required readers. Old-only writer DENIED | G-ROTATE |
| Search-key rotation and changed normalization | PASS after complete maintenance reindex, conflict-free valid UNIQUE and verified terms. Conflicts FAIL before switch | G-ROTATE |
| Payload/index mismatch, stale term, false candidate occupying first LIMIT slots | FAIL whole buffer, no earlier publication/refill/scan. Session closed | G-SEARCH |
| Hostile DB omits a true match | INCONCLUSIVE completeness. Query success never asserts anti-omission proof | G-SEARCH |
| Low-entropy Boolean/status/country/diagnosis equality declaration | DENIED. Warning cannot waive the exclusion | G-DOCTOR |
| Chosen-input labeling, auxiliary/frequency/correlation attack | PASS only when leakage demonstration and documented acceptance match construction. No inference-resistance claim | G-SEARCH |
| Unicode combining/non-BMP/Turkish-I/sharp-S/BOM/whitespace and version changes | PASS exact frozen vectors, DENIED undeclared/unassigned normalization changes | G-SEMANTICS |
| Email local/domain case, phone validation, decimal 1.0/1.00/negative zero/type fidelity | PASS admitted fixed-scale mapped equivalence and exact payload. Generic signed-zero/extra-scale forms remain syntax-only. Unsupported mapped forms DENIED | G-SEMANTICS |
| NULL, empty, all-NULL/empty/duplicate IN, Boolean grouping and pagination | PASS SQL three-valued oracle. Nullable NULL substitution demonstrates explicit unauthenticated-presence limit | G-SEMANTICS |
| Concurrent normalized unique insert/update, conflict or HMAC collision | PASS at most one equivalent non-null commit. Conflict redacted, unexplained collision FAIL without data deletion | G-SEARCH |
| Scalar projection/tuple/entity Result, protected predicates absent from projection, dirty no_autoflush identity map, refresh/rollback/expire | PASS exact logical shape/state and same grant checks. Unresolved/lazy/detached value DENIED | G-ORM |
| Async cancellation during queued/running SDK requests, key preparation, DB fetch, flush or ambiguous commit | DENIED/PENDING as actual commit dictates. No partial value, blocking SDK fallback or polluted session reuse | G-ASYNC |
| Bulk/Core/text/raw/COPY through guarded surface | DENIED before SQL on guarded paths. Ordinary unframed physical writes reject by constraints | G-BYPASS |
| Separate driver, ETL, alternate worker or owner migration | FAIL on demonstrated plaintext bypass / INCONCLUSIVE unknown coverage. Doctor never reports unobserved path PASS | G-BYPASS |
| Deliberate forged frame containing a plaintext canary | FAIL full authentication inspection even if shape CHECK accepts. No universal DB prevention claim | G-BYPASS |
| Logging/echo/exception/APM/export configuration and actual canary sinks | FAIL seeded exposure, INCONCLUSIVE broken/unobserved collector. Host-owned export remains outside secrecy claim | G-RELEASE |
| Deprotect without staging approval or after ambiguous approval crash | DENIED before further plaintext persistence. Existing exposure remains recorded | G-REMOVE |
| Uninstall with old encrypted backups or required delayed worker | DENIED unsafe retirement. PASS package-free host plus retained standalone recovery reader/key trial | G-REMOVE |
| Subject revocation then restore old wrapped root under surviving domain KEK | DENIED managed adapter access. PASS research recovery control shows offline recovery survives. Not erased | G-DESTRUCTION |
| Domain deletion requested/pending/cancelable, unknown descendant copy | PENDING/INCONCLUSIVE. Never BOUNDED_DESTRUCTION_VERIFIED before complete scoped evidence | G-DESTRUCTION |
| Tampered wheel, wrong issuer/repository/workflow/hash or unexpected .pth/startup executable | DENIED release/install admission under selected release gate. Correct provenance alone cannot approve malicious code | G-RELEASE |


## Hardening-specific acceptance scenarios

| Scenario | Expected state and oracle | Gate |
|---|---|---|
| H1: pause after fence/admission, terminate backend but keep worker/buffer alive, race denial. Stale owner submits DML/CAS/effect | PENDING until registered worker and mutation drain. DB/authority tokens reject stale effects. AWS dispatcher cannot transfer while unknown | G-AUTHORITY/G-REVOCATION |
| H2: flush B then C in one transaction, lose COMMIT reply, later delete row, retry same/different ordinary attribute or digest, inspect absent marker while original backend runs | Distinct immutable batch markers commit together and survive later delete. Same-type changed-attribute identity changes digest. Live backend absence stays UNKNOWN; original xid8/target lineage required. Delete/mirror and marker atomic | G-TRANSITION |
| H3: stored A, dirty B, entity/scalar no_autoflush, partial refresh, expire/get, last-row corruption with held entity reference | Preserve B, return stored A, partial refresh DENIED, explicit identity inspection, no new logical publication on failure | G-ORM |
| H4: late before_flush/default/cascade addition on commit AND autoflush after cold async preparation | DENIED before late DML. No provider call in event, no callback-order assumption or blocked loop. Retry only after complete reprepare | G-ASYNC/G-BYPASS |
| M5: protected_eq OR division by zero, hidden cast/function, nested protected NOT, ILIKE, join, unused invalid branch | Typed rejection before SQL. Total plain atoms preserve TRUE/FALSE/UNKNOWN and original success/error behavior | G-SEMANTICS |
| M6: target live set exceeds tiny cap, retries burn headroom, old mirror quota zero, disk/WAL/provider exhausted between chunks | Preflight DENIED or explicit finalize-before-writers. Mid-flight PENDING with committed markers/fences, never partial switch | G-TRANSITION/G-ROLLBACK |
| M7: two equivalent insert/update races, soft-delete duplicate, NULL pairs, tenant separation, partial/composite declaration | One non-null equivalent commit per tenant/field. NULLS DISTINCT. Soft-delete conflict. Unsupported scope DENIED, redacted membership oracle stated | G-SEARCH |
| M8: every recovery-catalogue state, repeat reconcile/resume/abort/recover, lost plan and expired initial plan, wrong target/role/digest | No repeated effect or denial clearing. Read-only reconcile. No output plaintext/term canary. Unknown history denies break-glass | G-TRANSITION/G-RESTORE |
| M9: operator reads revoke/destroy command output without lifecycle prose | Distinguishes managed denial, recoverable backup/shared terms and delayed domain custody. No subject ERASED output | G-REVOCATION/G-DESTRUCTION |
| M10/A1: representative small AWS backend follows eligibility and removes package, inject authority/receipt/KMS outages | Fits customer-approved adoption/cost/latency/sustainable-capacity/pause/drain/recovery/exit budgets. An unresolved-worker injection is explicitly ineligible for bounded completion with denial retained. No zero-change/offline/universal-support implication | G-PERFORMANCE/G-REMOVE |

## Evidence admission

Store exact commands, pins, seeds, minimized cases and safe raw outcomes. Collect evidence at the real entry point and highest practical boundary.
End-to-end tests lead, integration tests diagnose component interactions, and unit tests protect unique format/crypto/state-machine properties.
Each test must survive reasonable internal refactoring and identify a meaningful fault. Test count or coverage percentage is not a target.
Samples/emulators/first-party AI/source review cannot supply a live-provider destruction, independent audit or production guarantee.
Safe reports retain required-check inventory, collector health, scope, interval and exclusions.
Use separate monotonic clock/deadline observations. Do not subtract timestamps from independent clocks as though they share a timebase.
Negative exposure conclusions need actual positive canaries, matching before redaction, collector drain/loss accounting and healthy controls.
Unknown or failed collectors cannot manufacture PASS or erase a proven FAIL.
Each oracle declares source, observation point, synthetic value/encoding forms, private marker map, retention, redaction and bounded decoding.
Match declared forms before public redaction. Use opaque public IDs, never production secrets or identities.
Start barriers and terminal drain/lateness checks define the observed interval.
Pagination gaps, dropped events, rotation, reconnect, truncation, sampling or missing privileges block absence claims.
Keep applicability, reached boundary, actual outcome, execution health and controls separate.
A stopped test can prove its blocking assertion. It cannot prove an unexercised confidentiality boundary.
Use explicitly authorized disposable targets, synthetic credentials and declared resource budgets. Loopback/private IP is not ownership.
Cleanup failures remain visible. A fast CI subset cannot replace release evidence or waive an invariant.
Required-check applicability is fixed before evaluation. Valid inapplicability records its proof and remains visible.
No invariant failure is averaged into a security score.
No generic attack harness or rich evidence-bundle platform is required. Use mature tools for host security and artifact provenance.
The [release gate](../ENGINEERING_PLAYBOOK.md#release-gate) controls production wording and distribution.
