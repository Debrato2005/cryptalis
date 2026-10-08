# Implementation status

**IMPLEMENTED:** research prototype. Protection runtime exists only as isolated code under `spikes/revamp`.
The public package contains research utilities, not the SPECIFIED SQLAlchemy protection runtime.
No PostgreSQL/provider/runtime cell, production key provider, independent review, or release is qualified.
VERIFIED below refers only to recorded receipts and their exact revisions. This documentation pass runs no runtime tests.
All other contract and promotion requirements are SPECIFIED. All seven full gates remain UNKNOWN.

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

The current package has structural record decoding/canonicalization, bounded manifest/header inspection, local crypto/search examples, and local transition-admission research.
Those APIs do not provide SQLAlchemy database protection, managed key custody, safe deployment admission, or production lifecycle.
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

The latest DISTINCT fix lacks real PostgreSQL regression. The app-assigned-key plan-time contract and full admitted scope need executable evidence.
Historical service access and local application observations did not qualify a runtime release. Recheck the exact environment before any new runtime claim.
No service, provider, artifact, or project test runs during this documentation pass. Prior receipts remain unchanged.

Independent-process recovery, non-owning runtime enforcement, deployment writer exclusion, retained-backup readers, format upgrades,
real resource-exhaustion faults, production provider custody, authenticated policy publication/restore, and independent review remain required.
[Gate criteria](#missing-evidence-and-promotion-criteria) state the deciding observations without restoring the deleted control plane.
No production provider is designated. The local provider is functional evidence only.
G-PROVIDER, G-POLICY, all review requirements, and the [release gate](../ENGINEERING_PLAYBOOK.md#release-gate) remain UNKNOWN.
