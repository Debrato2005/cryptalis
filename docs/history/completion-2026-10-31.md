# Completion-branch observations: 2026-10-31

Historical revision-bound evidence, before final branch consolidation.

## Partial mutation check of the pruned suite: 2026-10-31

After pruning, each of 26 safety checks was disabled in turn and the suite run in parallel,
stopping at the first failure. **INCOMPLETE:** the system stopped the run for low memory after 19.

Sixteen were caught by a related test, including the read-time term check, tenant checks on read,
write and search, the deployment pin, verification before switch and the schema contract.

Three are not proven: sealed value tenant at the driver, parameter logging refusal and the
one-tenant rule for sorting. Each was stopped about two minutes in by an unrelated rotation test, so
that test may be flaky under load and the sabotage itself may never have been detected.

Seven did not finish: malformed plan refusal, plaintext consent, removal approval, restore
approval, small search domain refusal, state file privacy and invalid session tenant first.
Malformed plan refusal matters most, because `test_plan_admission` was deleted in this pruning.

The kill also left the malformed-plan sabotage in the working tree. It was never committed and was
restored. The script edited the checkout in place, which a hard kill can leave behind; a repeat must
use a separate copy.

## Parallel tests and removal of brittle checks: 2026-10-31

The owner asked to drop brittle tests in favor of end-to-end evidence and to run tests in
parallel. The suite now runs with pytest-xdist, one file per worker, on one database because
tests use unique schemas. Locally, 12 workers finish in about 2 minutes 40 seconds; the serial
hosted run took about 25 minutes.

Removed: tests of the test tooling and their scripts, the old manifest-format command and its
tests, the crypto demo, malformed-artifact shape tests, a fake-clock restore lease suite that
proved timing-sensitive under load, and direct private-function calls in rotation preparation.
Independent rotation vectors stay. Forged-journal, hidden-plaintext and other real-PostgreSQL
attack tests stay even where their names read like unit tests. `cryptalis manifest inspect` now
reads the real manifest and reports accepted leakage.

About 3,530 cases remain from roughly 1,250 functions, most on real PostgreSQL. Test counts are
not the measure of completion.

## Order search on integers and dates: 2026-10-31

**VERIFIED, bounded:** opt-in `order` adds `<`, `<=`, `>`, `>=`, `BETWEEN`, `NOT` and `ORDER BY`
on int2, int4, int8 and date fields. See the [decision](../decisions.md#order-search-2026-10-31).

`tests/test_order_search.py` runs over 300 queries and more than 5,000 result rows on native
PostgreSQL first, then requires identical rows in identical order through Cryptalis. That holds
sync and async, after search and payload rotation, with new edits, and after decrypt and
removal. Further checks cover keyset pagination, index use with sequential scans disabled,
unrelated terms across tenants, tampered-term refusal, adding and removing search on a protected
field, and planning and query refusals. One essential vector recomputes the stored term through
a separate derivation. `fresh_cluster_qualification.py --project` covers order frames after a
real restore. The affected regression passes 1,212 checks with 15 skips on local PostgreSQL 16.2.

The native oracle caught a wrong-result bug before commit: a bare `order_by(column)` reuses the
selected column object, and an identity-based rewrite returned the search term as the value. The
sort list is now rewritten directly. `statement.params()` values were also invisible to search
rewriting, which failed loudly; they are now read.

No published sorting attack was run and no independent review occurred. MIN/MAX refuse.
All seven production gates remain UNKNOWN.

## One session across single-tenant tables: 2026-10-31

**VERIFIED, bounded:** a session could not write two protected single-tenant tables,
because every row was compared to one session tenant while each such table's tenant is
its own UUID. A session now prepares keys per scope, and each column uses its table's
scope. The CF1 format and per-table keys are unchanged. `sessions()` works without a
tenant when single-tenant tables exist, and refuses otherwise.

Behavior change: a session naming tenant T can reach declared single-tenant tables,
which earlier refused. Tenant-column data keeps its checks. Local PostgreSQL 16.2
regressions covering sync/async adapter, search, DML and SQLModel paths pass, including
reads, writes, joins and deletes across two tables and a mixed tenant-column manifest.

## Project front door: 2026-10-31

**VERIFIED, bounded:** `cryptalis.Project` takes a manifest, key provider and state
directory, and drives doctor, protect, online protect, attach, three rotations,
search modification, tenant addition, recovery, decrypt, removal and abort through
the existing executors. It adds no cryptography, SQL or transition logic.

Local PostgreSQL 16.2 checks in `tests/test_project.py` cover the complete journey
through fresh simulated processes, sync and async attachment, stored-frame inspection,
native exit with the latest edit, and refusals. Crash cases fail at every state save
for protect, the three rotations, modify, tenant addition, decrypt and remove, both
before and after the save is durable, and each resumes to correct values. Status is
checked at every recorded step of an unfinished operation, and abort for each operation
before its switch. The online tests need the separate source role, which is unavailable
locally, so they run only in hosted CI.
`fresh_cluster_qualification.py --project` restores a `Project` dump into a separately
initialized PostgreSQL 16 cluster, then runs `recover`, reads, search, an edit, payload
rotation, decrypt and remove, and compares the latest values natively. Hosted CI repeats
it against the built wheel. Development custody and a public fixed-key provider are used,
so real provider restart and production custody are not established here.

Tenant addition no longer requires an online-protection access contract. That limit
blocked onboarding for every maintenance-protected deployment. Adding an empty tenant
changes no grants, and runtime privileges keep their own checks. The successor format
stays v15/v16 and validates against its plain base when no contract exists. Later
payload and wrapping rotation and decrypt on such a deployment pass.

## KISS removal of unused modules: 2026-10-31

Removed code no product entry point reaches, under requirement 16: the `contracts`
package (ActiveState, development authority, transition admission), the F1/W1/scalar
`_candidate_*` parsers, `manifest/descriptor.py`, six unreferenced functions, their
tests and their example fixtures. These were early research structures; CF1, the
lock and the transition engine replaced them. Git history retains them. No admitted
behavior changes. `crypto/_rewrap.py` stays: it builds a rewrap target for hosts.

Evidence: a static import walk from the product entry points now finds only
`_rewrap` outside them, and 344 focused manifest, CLI, rotation, restore, compiler
and runtime-binding checks pass locally on PostgreSQL 16.2. The full suite runs in
hosted CI on the pushed branch.

## Main-history consolidation: 2026-10-31

**VERIFIED, bounded:** integration retains main `f082cf3` (including merged
PRs #1/#2), completion history and the `5ea671d` single-record UPDATE slice.
Reporting, scalar storage, fixed-scope writes, both SQLModel suites, cached
projections, labeled/entity RETURNING proofs and Doctor remain covered.
The [complete source run](../_reset/main-consolidation-full-20261031.json) passes
3,446 tests and eighteen subtests, with 104 explicit skips and 48 existing
warnings. Source and imported-runtime hashes remain unchanged.

The [installed run](../_reset/main-consolidation-installed-20261031.json) passes
312 controls with 28 explicit skips. The [artifact receipt](../_reset/main-consolidation-artifact-20261031.json)
verifies reproducible wheel/sdist, hashed backend inputs, SBOM, CLI and 50
installed files. Source uses Python 3.12.16/PostgreSQL 16.2; the artifact tool
uses Python 3.13.12. No skipped or external cell is qualified. All seven
production gates remain UNKNOWN. Separate unmerged `origin/work` history is
not included in this checkpoint.


## Single-record mapped UPDATE: 2026-10-31

**VERIFIED, bounded:** mapped `.values(...)` UPDATE with explicit tenant/record
equality and `synchronize_session=False` now reuses the existing authenticated
write pipeline. Native sync/async TEXT/VARCHAR cursor row counts, loaded-state
behavior, NULLs, rollback, unique-savepoint recovery, autoflush and PostgreSQL
assignment-error timing pass. Original values and identity are checked again
after provider work; final driver mutations refuse before dispatch. SET targets
must be direct mapped columns with literal values. RETURNING, expressions,
ordered assignments and identity/tenant changes remain unadmitted.

The [258-check source receipt](../_reset/point-update-source-20261031.json) includes
affected bulk-update, scoped-DELETE, Boolean and adapter controls. This records
the branch before integration with newer main history. No new full-suite,
installed-package or production qualification follows. All seven gates remain
UNKNOWN.


## Native OpenBao Transit provider: 2026-10-31

**VERIFIED, bounded:** the optional OpenBao provider implements the existing
wrap/unwrap/async/rewrap protocol through a supplied native hvac Transit client.
It pins the authority, named key and explicit version; the service authenticates
the complete root context as AEAD additional data. Metadata and response checks
fail closed. It performs no credential discovery, key administration or retries.
The [security contract](https://github.com/Debrato2005/cryptalis/blob/19657a6/docs/security.md#optional-openbao-transit-adapter) defines
the exact context encoding, admitted key configuration and host obligations.

The [150-check source receipt](../_reset/openbao-source-20261031.json) includes a
real OpenBao 2.7.2 service and hvac 2.4.0, authenticated context/tag alteration,
randomized wrappers, pinned old-version use after rotation, cross-provider
rewrap, least-privilege token revocation/recovery and canceled late responses.
The PostgreSQL journey protects existing values, searches, preserves a later
edit through decrypt-back, removes Cryptalis objects, and reads all current
values through a fresh native ORM. Existing AWS, CF1, fork and provider-failure
controls also pass. Source hashes remain unchanged during the run.

All [68 installed checks](../_reset/openbao-installed-20261031.json) pass from a
clean wheel environment. The [artifact receipt](../_reset/openbao-artifact-20261031.json)
verifies reproducible wheel/sdist, SBOM, 47 installed files and CLI. The
[service input record](../_reset/openbao-service-inputs-20261031.json) retains
official release identity, download digest and native SDK versions. The failed
initial PostgreSQL probe stopped before collection; the same stopped disposable
cluster was explicitly recovered before a new run. No database was substituted.

This profile uses disposable in-memory OpenBao storage and loopback HTTP.
Production TLS/workload identity, durable custody, native deletion, independent
recovery and independent review remain unqualified. All seven gates remain
UNKNOWN. The previous full-suite checkpoint is still `172f8c7`; this slice has
focused source and installed evidence, not a new full-suite qualification.


## Cached direct alias projections: 2026-10-31

**VERIFIED, bounded:** native ORM and Core alias columns created before
attachment now use the owned authenticated result codec. A native annotation
creates a separate compiler projection; cached caller column types and result
lookup remain unchanged. The stale codec cannot return CF1 bytes as a public
value. Native TEXT/VARCHAR/Boolean comparisons cover aliases, search rewrites,
sync/async results, exact False/True/NULL values and altered-tag authentication
failure.

All [410 affected source checks](../_reset/cached-projections-20261031.json) and
[91 clean installed checks](../_reset/cached-projections-installed-20261031.json)
pass. The [artifact receipt](../_reset/cached-projections-release-20261031.json)
verifies reproducible wheel/sdist, SBOM, CLI and 46 installed files. The full
3,091-test source checkpoint remains at `172f8c7` and predates this localized
correction. These local Python 3.13.12/PostgreSQL 16.2 observations close the
recorded cached-alias codec gap; they promote no production gate or other cell.


## Asynchronous SQLModel and cached projections: 2026-10-31

The [final full source regression](../_reset/sqlmodel-async-full-20261031.json)
passes **3,091 tests and 18 subtests**, with 38 explicit skips and 48 existing
DISTINCT ON deprecation warnings. Source hashes remain unchanged throughout
the run. The [reproducible artifact receipt](../_reset/sqlmodel-async-release-20261031.json)
verifies the wheel/sdist, SBOM, dependency metadata, CLI and 46 installed files.
All [64 installed API/projection checks](../_reset/sqlmodel-async-installed-20261031.json)
pass in a clean optional-SQLModel environment.

At this checkpoint, direct cached alias columns could still retain a native
result codec. The [following correction](#cached-direct-alias-projections-2026-10-31)
adds authenticated decoding for that separate path.

The [initial full run](../_reset/sqlmodel-async-full-initial-20261031.json) stopped
after five label-admission regressions, with 2,554 passes, 36 skips and 18
subtests. Native computed and mapper-generated labels need their own metadata
handling. The correction preserves that behavior while retaining direct-field
codec checks; all [289 affected controls](../_reset/sqlmodel-async-affected-20261031.json)
pass. The initial failed run is not current full-suite qualification.

**VERIFIED, bounded:** SQLModel 0.0.48 asynchronous attachment uses its native
AsyncSession/Session.exec result handling through the existing SQLAlchemy
admission and awaited key-preparation path. Sixteen native API and sync bridge
checks pass: CRUD, scalar/tuple/entity results, labeled bulk RETURNING, scoped
dictionary UPDATE, scoped DELETE, rollback, and actual provider cancellation
before autoflush with successful recovery. The plain installation retains its
typed no-effect missing-dependency control.

The new native comparison exposed cached SELECT labels that returned CF1 bytes
through a stale native codec. Direct labels and transparent parentheses now use
the owned authenticated decoder without changing caller expressions. Forty-eight
TEXT/VARCHAR sync/async comparisons pass across aliases, search rewrites,
original label lookup, grouped ORM labels and Core parenthesized columns.
The cursor guard permits native buffered async soft-close without releasing a
row or protocol handle.

Receipts: [SQLModel API and cancellation](../_reset/sqlmodel-async-20261031.json),
[cached projection comparisons](../_reset/select-transparent-20261031.json), and
[base dependency absence](../_reset/sqlmodel-absence-20261031.json). These are local
Python 3.13.12, SQLAlchemy 2.1.3 and PostgreSQL 16.2 source observations. They do
not qualify an independent asynchronous HTTP deployment, production provider,
other runtime cell or any production gate. All seven gates remain UNKNOWN.


## Native labeled INSERT RETURNING: 2026-10-31

**VERIFIED, bounded:** attached mapped dictionary INSERT supports native direct
column labels, named or anonymous, in scalar/column and entity projections.
Native sync/async TEXT and VARCHAR comparisons preserve values, Row keys,
lookup by the original Label object, paging, requested ordering and transactions.
The compiler changes only the SQL projection codec; caller labels remain
unchanged. Each protected value retains its exact prepared-frame proof. Raw
rows correlate labeled identity/tenant slots before native ORM loading.

Custom label dispatch, names, quote flags, type overrides, result aliases and
stale element caches refuse before effects. Late replacement, including an
equivalent new Label or supplemental-default substitution, refuses before raw
INSERT. Read-only Python/CLI Doctor samples admit the same direct labels and
keep parameters NOT_INSPECTED. The [311-check receipt](../_reset/returning-labels-20261031.json)
records the affected DML/driver/Doctor regression. Computed expressions and
aliased entities remain unadmitted. OBJ-QUERY-04 remains PARTIAL; no production
qualification or gate promotion is implied.


## Packaged RETURNING and Doctor checkpoint: 2026-10-31

**VERIFIED, bounded:** revision `a8a9c30` builds identical wheel and source
archives twice. Archive inspection, wheel RECORD, dependency metadata, license,
CycloneDX SBOM and 46 installed-file comparisons pass. The independent virtual
environment imports the wheel and starts its CLI. All 113 selected PostgreSQL
ORM RETURNING and Python/CLI Doctor checks pass from that installation.

The [artifact receipt](../_reset/release-installed-20261031.json) and
[installed application receipt](../_reset/installed-journey-20261031.json) bind the
exact source and artifact bytes. This is local Python 3.13.12/PostgreSQL 16.2
evidence. Optional SQLModel and production provider cells are not qualified.
Independent rebuild/review, signed provenance and all seven release gates remain
UNKNOWN. No publication occurred.

**IMPLEMENTED:** research prototype with a product manifest compiler, CF1 typed storage primitives, a local development provider,
bounded sync/async SQLAlchemy storage/search, a PostgreSQL maintenance protection transition, an in-place
decrypt-back/removal path for that transition format, and an approved fresh-cluster protected-backup
recovery and adoption path. Root rewrap and payload/search generation rotation
share bounded maintenance and publication mechanics.
Separate runtime-role verification is complete for the local cell.
No PostgreSQL/provider/runtime cell, production key provider, independent review, or release is qualified.
VERIFIED below refers only to the named checks and their exact revisions.
All other contract and promotion requirements are SPECIFIED. All seven full gates remain UNKNOWN.


## Pre-adoption INSERT diagnostics: 2026-10-31

**VERIFIED, bounded local source cell:** Python and CLI pre-adoption Doctor can
inspect ordinary mapped INSERT structures, direct-column RETURNING and the
admitted entity RETURNING forms alongside SELECT samples. The inspection
reuses runtime structural admission. It executes no samples, reads no
application rows, resolves no keys and replaces no mapped types. Core inserts,
embedded values, caller defaults, expressions, aliases and loader-option samples
receive safe structural refusals.

INSERT items explicitly report parameters NOT_INSPECTED. Successful structural
checks leave query-route coverage, provider access, writer exclusion and overall
health UNKNOWN. This is not permission to execute a write. The
[105-check receipt](../_reset/doctor-insert-20261031.json) includes actual CLI
success/refusal, output privacy, unchanged native schema/types and existing
Doctor, initialization and protection CLI controls. No production gate changes.
The preceding internal equality candidate is pushed as `57e58a6`.


## Internal NULL-safe equality candidate: 2026-10-31

**IMPLEMENTED, INTERNAL ONLY:** an internal qualification profile rewrites
`IS DISTINCT FROM` and `IS NOT DISTINCT FROM` through the existing full equality
term and NULL-presence representations. It passes native sync/async truth,
alias, pagination, reversed/late bind, literal/bound NULL, outer-join and tenant
oracles. The affected query selection passes 293 checks with 48 existing
deprecation warnings. The [receipt](../_reset/nullsafe-internal-20261031.json) binds
the exact source and test selection.

Normal attachment still refuses these operators before SQL. An explicit control
checks that boundary. The candidate is not admitted public functionality and
does not complete OBJ-QUERY-02. Six-gate admission, capability leakage acceptance
and measured-cost approval remain required. No new representation or key format
is selected. The preceding entity slice is pushed as `36415ba`.


## ORM entity INSERT RETURNING: 2026-10-31

**VERIFIED, bounded local source cell:** mapped dictionary INSERT can return the
exact attached single-table entity, mixed entity/column results and repeated
entities. Native sync/async TEXT/VARCHAR results, identity reuse, Boolean
`populate_existing`, expiration and rollback pass their native oracles. Deferred
protected fields retain authenticated lazy loading. Aliased, inherited/versioned,
computed and loader-option entity forms remain unadmitted.

The affected selection passes 289 checks. A separate AI source review identified
independent public-identity tampering and a supplemental-RETURNING shape bypass;
both were reproduced against PostgreSQL before repair. Raw cursor fetches now
correlate public ID/tenant slots with each protected carrier before ORM loading.
Input membership also applies when every protected field is deferred. Final
native compilation must retain the requested ORM projection. The
[receipt](../_reset/entity-returning-20261031.json) binds the exact selection and
source hashes. This is local source evidence, not installed-artifact, independent
human review or production qualification.

The [full source regression](../_reset/entity-returning-full-20261031.json) passes
2,856 tests and 18 subtests in 563.19 pytest seconds. Pytest reports 38 skips
across collection/setup/call boundaries and 48 existing DISTINCT-ON deprecation
warnings. Both private-role probes pass. Source hashes remain unchanged during
the run. Skipped external, optional and ICU cells remain unqualified.

The preceding lifecycle verification repair is pushed as `ce8da05`. The standard
`.venv` now contains the locked Python 3.13.12 environment. Its broken Python 3.12
predecessor is preserved under ignored `.research-tools`. Existing PostgreSQL 16
tools are discoverable through user-local launcher links. All 34 objectives and
all seven UNKNOWN production gates are retained.


## Unix-socket lifecycle fault verification: 2026-10-31

**VERIFIED, bounded local source cell:** the existing real PostgreSQL fault proxy
now forwards to the same configured Unix socket as well as TCP targets. It keeps
the actual SCRAM handshake and terminal COMMIT/DDL reply-loss checks. The focused
migration, pause and collation selection passes 68 checks with one explicit ICU
skip. A recovered ICU catalog entry no longer counts as binary capability; only
the exact native `0A000` no-ICU refusal skips that fixture. Other setup failures
still fail. The [receipt](../_reset/socket-faults-20261031.json) binds the source and
test selection. ICU refusal qualification remains unavailable in this cell.

The preceding RETURNING slice is pushed as `da62695` on
`codex/product-completion-20261031`. Full regression must be repeated after this
verification repair. All seven production gates remain UNKNOWN.


## Direct-column INSERT RETURNING: 2026-10-31

**VERIFIED, bounded local source cell:** mapped dictionary INSERT accepts direct
public and protected column tuples, including repeated columns. Native result
keys, Row/scalar values, grouping, paging and parameter-order requests are retained.
Each protected field requires its own exact prepared-input frame proof. Literal
columns, altered projections, custom column dispatch and unadmitted expressions
refuse before driver execution. Entity RETURNING remains unfinished.

The reviewed slice passes 242 PostgreSQL checks across INSERT, returned-frame
tampering, sync/async TEXT/VARCHAR, multiple protected fields, signed bigint
identities, the adapter, search and driver boundaries. The literal-column review
finding was reproduced before repair. The [receipt](../_reset/returning-columns-20261031.json)
records source hashes and the exact selection. Python 3.13.12, SQLAlchemy 2.1.3,
psycopg 3.3.6 and the recovered PostgreSQL 16.2 cell are the evidence boundary.
No installed-wheel or production qualification follows.

The [full regression](../_reset/returning-columns-full-20261031.json) stops after
five failures: the unavailable native ICU case and four TCP-only lost-reply proxy
cases on the Unix-socket target. It records 1,252 passes, 21 skips and 18 subtests.
The full suite is not green. A preceding run exhausted the recovered cluster's
20 connection slots (1,250 failures, 65 setup errors, 1,494 passes); the local
limit was restored to PostgreSQL's default 100 before this diagnostic run.

Development resumed under the user's autonomous completion instruction. The
working branch is `codex/product-completion-20261031`. The initial restored development
environment was `/tmp/cryptalis-goal-venv`; the standard `.venv` was subsequently
restored from the same lock, with its broken predecessor preserved. The preserved test database now uses its documented
private Unix socket. Database, roles and passwords were retained. Original test
locators have private backups outside the repository. The recovered PostgreSQL
binary was built `--without-icu`; its nondeterministic-collation test cannot
establish refusal evidence in this cell. All 34 objectives remain in scope and
all seven production gates remain UNKNOWN.
