# Implementation status

**IMPLEMENTED:** research prototype with a product manifest compiler, CF1 typed storage primitives, a local development provider,
bounded sync/async SQLAlchemy storage/search, a PostgreSQL maintenance protection transition, an in-place
decrypt-back/removal path for that transition format, and an approved fresh-cluster protected-backup
recovery and adoption path. Root rewrap and payload/search generation rotation
share bounded maintenance and publication mechanics.
Separate runtime-role verification is complete for the local cell.
No PostgreSQL/provider/runtime cell, production key provider, independent review, or release is qualified.
VERIFIED below refers only to the named checks and their exact revisions.
All other contract and promotion requirements are SPECIFIED. All seven full gates remain UNKNOWN.

## PostgreSQL identifier admission correction: 2026-10-28

**VERIFIED, bounded source and installed cells:** protected physical columns
whose names are PostgreSQL type/function keywords now pass activation and
search validation. The old validator expected SQLAlchemy's unquoted `integer`
while PostgreSQL deparsed the same identifier as `"integer"`.
Known framing forms now include the native preparer's exact quoted spelling.
The live CHECK must depend on exactly the declared column, retain its complete
bounds/header/generation expression, be validated and permit inheritance.
Ordinary admission remains nested-only; restored flattened expressions still
require the exact separately inspected restatement. Search-index spelling comes
from bound `pg_catalog.quote_ident` in the existing catalog query, with no extra
round trip. No CF1, manifest grammar or cryptographic construction changes.

The integrated matrix passes 173 checks, with two missing-reader skips and one
fresh-fixture collection skip. After combining the catalog lookup, all 16 native
identifier cases and 75 search controls pass. The final installed wheel passes
the same 16 identifier cases, reproducible builds, 48 installed-file checks and
CLI inspection. Its SHA-256 is
`b560cb8aa830448a7f3d56fecd0c51f71e5e3a6d684d660bd301c98cdc9db7af`.
Both layouts cover keyword, ordinary, mixed-case and embedded-quote names,
equality/IN, latest edits and native removal. Changed bounds and additional
column dependencies refuse before provider access. Native reparse controls
retain the distinction between original and explicitly admitted restore forms.
Independent agent review found no actionable defect in this scope.

The [boundary](_reset/frame-identifier-boundary-20261028.json) retains exact
receipts and source/runtime identities, including the initial collection-path
error. These checks do not qualify a production compatibility cell, performance
budget or independent human review. All seven production gates remain UNKNOWN.

## Maintenance tenant-policy provisioning: 2026-10-28

**VERIFIED, bounded source and installed cells:** `cryptalis.tenancy` adds one
explicitly host-approved empty tenant through the existing maintenance and
publication lifecycle. Old policy digests, lock, access contract, schema and
ciphertext bytes remain exact. Planning authenticates current frames; apply
rechecks empty membership under locks and atomically records source SUPERSEDED
and successor PENDING with durable guards. Strict successors v15/v16 require
external retention/publication and the actual ACTIVATING pin. Inspected retry
and cancellation preserve source authority and data. Physical older readers
refuse the new formats before execution.

The original HTTP account authenticates but receives 409 before approval, then
creates its first protected Item after explicit administrator-approved
publication. A stale host artifact refuses before factory/key lookup. The
enlarged cohort survives root, payload and search rotation, genuine fresh
adoption, another restored-target addition and latest-value removal. Both
import-denied native children HTTP-read eleven latest Items through ten owners.
All 26 original application files remain unchanged; explicit host integration
still applies.

The integrated source matrix passes 207 checks with one omitted-reader skip;
that physical-reader control passes separately. The isolated tenant-only matrix
passes all 13 controls. Source and actual installed fresh journeys pass with
stable runtime bindings. The reproducible wheel is
`72d4ccde3fefc016cf8e07f5219c7eb0690321884efcd3ac2396e5f26cc4aa19`;
44 modules and installed-file/CLI inspection pass. The
[boundary](_reset/tenant-provision-boundary-20261028.json) retains exact receipts
and release inputs. Independent agent review found no actionable tenant defect.

This Python API performs O(N) frame authentication under a global writer pause.
It does not qualify scalable online signup, arbitrary-process revocation, live
KMS, operational CLI provisioning, production budgets or independent human
review. COUNT candidate code is excluded. Execution resumed after the earlier
quota interruption; the preserved bundle remains historical recovery material.
All 34 objectives remain in scope and all seven gates remain UNKNOWN.

## SDK protocol and early tenant admission checkpoint: 2026-10-28

**VERIFIED, local source and installed cells:** the isolated
[AWS SDK cell](../qualification/aws-sdk/README.md) retains boto3 1.42.89 and
botocore 1.42.97 with exact dependency hashes and service-model identity.
The 129-check protocol bundle passes, including 22 real SDK serializer/model
cases. Source and target Stubber queues verify source decrypt, target encrypt
and target decrypt. Wrong roots, malformed material, wrong key identity and
disabled-target responses refuse while source custody remains usable.
Credential discovery and HTTP transport are explicitly denied. No live AWS
cryptography, IAM, custody, deletion or production-provider qualification follows.

The factory now checks exact UUID type and pinned tenant membership before the
host key resolver. Previously an unapproved UUID reached that callback before
refusal, and a UUID subclass with a changed string identity could pass the
policy comparison. Both native PostgreSQL controls reproduce the old boundary.
The correction passes 149 affected adapter, context, online-tenant and actual-SDK
checks, including ordinary approved-scope access. The known-approved nil UUID
retains its existing online lifecycle coverage.

The current reproducible wheel is
`d809a9b6a9dc2f3a2f306bb97061c98d3d4038d49a1f7cc6a630496b8eaf5054`.
All 50 release inputs, 47 installed files and CLI inspection pass. Its installed
tenant source/fresh-restored journeys both pass with stable source and runtime
identity. The earlier `4af03c…` wheel and its wider DATE/original-HTTP evidence
remain preserved at their own boundary. No package publication occurred.

A matched warm 10k profile over the preceding `d7f2dba` product bytes reports
1.8042 ms added point p95, 3.5577 ms equality and 3.7962 ms IN-20; isolated
column-plus-equality-index storage is 1.4976× native. Equality **misses** its
3 ms target. Other stated targets pass in that one local observation. Profiling
shows repeated traversal at three distinct security admission boundaries.
A per-admission memoization experiment was slower and was reverted. Host
variance remains unresolved; no performance fix or production pass is claimed.

The [boundary](_reset/sdk-admission-boundary-20261028.json) binds archived
receipts, exact inputs, the failed performance observation and the preserved
unfinished branch. SDK-profile agent review accepted; the final small admission
fix has root self-review and executable evidence only. Independent human review
remains required. All seven production gates remain UNKNOWN.

**Execution blocked by account usage limit.** Specialist turns for tenant-policy
provisioning, count reporting and cache architecture were rejected by the account
quota. Their unfinished code is preserved as local branch
`wip/policy-count-unverified-20261028`, commit `7c0dd6b`, and in the
[verified Git bundle](_reset/policy-count-unverified-20261028.bundle). It is not
imported, enabled or qualified on the continuation branch. The runtime UUID guard
was completed separately; broader provisioning and counts remain unfinished.
See the [resume record](superpowers/plans/2026-10-28-policy-query-resume.md).

## Verified continuation checkpoint: 2026-10-28

**VERIFIED, bounded source and installed cells:** the unchanged 26-file original
HTTP application now has an owner-scoped Item journey through original JWT/account
authentication, online capture, administrator pagination, transactional account
cascades, all three rotations, genuinely fresh recovery and latest-data native
exit. The host authenticates before selecting an approved owner, then locks and
rechecks public owner metadata before payload access. Ordinary and administrator
pages match their public count/order/offset/limit oracles. Both package-free
children HTTP-read all nine specific latest Items through eight original owners.

Original application bytes are unchanged; integration is not zero-change.
The fixture replaces the request database dependency, adapts the administrator
list handler and translates the exact account-cascade delete in one transaction.
Global User authentication remains native. This profile protects Item title and
description as storage-only fields. New accounts can authenticate, but new-owner
Item writes refuse with 409 before key lookup. Dynamic tenant-policy provisioning
remains unfinished product work. This is not complete arbitrary-signup SaaS adoption.

The separate [HTTP dependency cell](../qualification/http/README.md) replaces the
earlier Starlette pin and records exact transitive hashes. Python 3.13.5,
FastAPI 0.162.0 and Starlette 1.10.0 pass the named journeys. The current upstream
standard-extra/Sentry conflict is documented. Recorded PyPI fields contain no
advisory entries, but raw retrieval receipts were not retained and OSV returned
403. A complete dependency security audit remains UNKNOWN.

The reproducible wheel has SHA-256
`4af03c2cc3b265249be505c87fcef8d8134ee370414c9caa9c166a44d1439ea3`.
All 50 release inputs match, 47 installed files and CLI inspection pass, and all
43 runtime module bytes match. The actual wheel passes tenant and original HTTP
source/fresh-restored phases, including original email equality/IN and rotations.
It also passes DATE export/restore in both layouts. The TestClient deprecation
warning remains. No public package was published.

The mandatory wrapper now rejects a wrong source checkout or mismatched installed
wheel before pytest. It checks candidate bytes before import, suppresses import
diagnostics, rejects unadmitted loaded module origins, records runtime hashes
and repeats their checks after pytest. Explicit `--installed-wheel` propagates
through both qualification harnesses. All 35 affected wrapper controls pass.
Parallel DATE runs exposed a global receipt-name collision; fresh qualification
now stores receipts in each new private work directory. Both profiles pass together.

The broad source attempt ended with pytest internal exit 3 after 2,218 passing
calls and 18 passing subtests, with stable source and no ordinary failed-call
report. Its final terminal trace was unavailable after executor reattachment;
the cause remains UNKNOWN. The following recovery module passes three checks,
and the remaining tail passes 615 with three call skips and four collection
skips. The separate online matrix passes 18. These are explicit follow-up
matrices; no clean full-suite pass is claimed and the incomplete receipt is retained.

The [qualification boundary](_reset/release-continuation-boundary-20261028.json)
binds exact archived receipts, source/runtime hashes, artifact bytes, dependency
inputs and known failures. Scoped reviews and the final agent code review found
no remaining actionable findings. Agent review does not supply independent human
qualification. Advanced encrypted queries, additional type admission, dynamic
tenant policies, production fencing/budgets, live KMS, independent review and
controlled publication remain open. All 34 objectives remain in scope. All seven
production gates remain UNKNOWN; this is a development checkpoint, not the release.

## DATE storage construction and lifecycle: 2026-10-27

**VERIFIED, bounded local source candidate:** exact native Date/DATE mappings
now use authenticated four-byte days from 2000-01-01 under existing context/v2.
Values are exact Python date or NULL, from 0001-01-01 through 9999-12-31.
Literal client defaults use canonical ISO metadata. Strict lock/v8 requires the
date codec and, only when applicable, default reader tag. Existing v1-v7
selection remains unchanged; a physical installed v7 reader accepts unchanged
integer artifacts and refuses DATE before execution.

Operational planning counts infinity/out-of-domain source dates and refuses.
Expansion repeats that check under table locks before journal or DDL effects.
Custom mappings, variants, coercions and undeclared date search refuse. No date
range/order/arithmetic/search or online type admission is added.

The [source receipt](_reset/date-source-20261027.json) records 31 passing checks
with stable source hashes: independent epoch/authenticated framing controls,
native default/NULL/ORM/dictionary/async state, refusal controls, both layouts,
three rotations alongside searchable text, current edits and package-free exit.
Both genuinely fresh-cluster profiles pass export and restore: default layout
[export](_reset/fresh-cluster-export-20261027-2.json)/[restore](_reset/fresh-cluster-restore-20261027-2.json),
and public slots
[export](_reset/fresh-cluster-export-20261027-3.json)/[restore](_reset/fresh-cluster-restore-20261027-3.json).
Each uses a distinct initialized target, explicit adoption, typed latest values,
corruption refusal and native restart. The initial failed restore receipt stays
preserved; it exposed the missing expected Python date type check, which was fixed.

Scoped independent agent review found no actionable DATE defect. These are
synthetic fixtures with public reconstructible custody. An unchanged external
DATE application, installed artifact/cost qualification and independent human
review remain required. Earlier affected runs with concurrent tenant test edits
retain their invalid wrapper outcomes; they are not stable verification.
All 34 objectives remain in scope and all seven gates remain UNKNOWN.

## Finite native SELECT functions: 2026-10-27

**VERIFIED, isolated local adapter cell:** attached SELECT admission now rejects
unrecognized functions, non-catalog namespaces and custom compiler dispatch
before key resolution or driver execution. The finite
[native function table](../src/cryptalis/_sqlalchemy_functions.py) covers ordinary
public aggregates, string helpers, tested windows and cancellation helpers.
Admitted ordinary calls compile with explicit `pg_catalog` resolution. Native
special expressions such as COALESCE retain their syntax. Protected expression
and search restrictions remain unchanged.

The deciding control reproduced an unknown database-side function reaching
execution through an attached typed SELECT. That route can perform effects
outside prepared ORM writes. It now refuses before keys or driver calls.
A separate positive control first observes a shadowed native function through
the connection's search path, then proves attached calls use the catalog result.
Registered concat/rank/dense-rank classes and native NULL/count/window results
also pass after a scoped review correction.

The [source-bound isolated receipt](_reset/select-functions-source-bound-20261027.json) records 233 passing
adapter, search, textual-clause, mapped-expression and async-cancellation checks
with stable source hashes. Forty-eight existing DISTINCT deprecation warnings
remain. Scoped agent review accepts the final change. Arbitrary application SQL
functions require separate admission; typed SELECT is not general function-call
authority. This evidence does not prove deployment-wide writer exclusion or
independent human security qualification. All seven gates remain UNKNOWN.

The earlier temporary-checkout receipt did not bind imported package location:
the shared interpreter selected the main checkout's editable package. It is
retained as historical evidence and superseded for source identity by the
explicit-PYTHONPATH isolated rerun above. The same correction applies to the
direct-provider receipt below. The build/archive evidence is unaffected.

## Direct provider rewrap recovery proof: 2026-10-27

**VERIFIED, isolated local protocol cell:** both direct AWS SDK-adapter and
development-provider `rewrap` methods now unwrap the replacement under the
original context. They require exactly 32 immutable bytes, compare the original
root in constant time and recheck the pinned target provider identity before
returning success. Ordinary failures remain redacted `KeyUnavailable`;
interruption propagates and the original wrapper remains usable.

Previously, valid wrapper metadata alone could report apparent success even if
the target wrapped a different root. Fourteen source controls reproduced that
failure across both providers. The existing higher-level rotation preparation
already performed its own recovery proof; this change closes the direct API gap.

The [source-bound isolated receipt](_reset/direct-rewrap-source-bound-20261027.json) records 107 passing
provider, CF1 and rewrap-preparation checks with stable source hashes. Controls
cover incorrect or malformed recovered material, target outage, identity drift,
interruption, source retention and healthy retry. Agent review found no remaining
scoped findings. Direct rewrap now requires target decrypt permission and can add
one external provider request. No live AWS, custody retirement, deletion,
independent human review or production-provider qualification was performed.
All seven gates remain UNKNOWN.

## Resumption and frozen build backend: 2026-10-27

**VERIFIED, isolated local build cell:** explicit `Continue Cryptalis` resumes the
audited `5d6ff65` checkpoint. Remote main matched that revision before edits.
The same disposable PostgreSQL 16.15 cluster was stopped on resume. After starting
it, fresh private owner/runtime/source probes and six targeted online tenant and
source-role controls passed. These observations do not qualify a production cell.

Release builds now pin `uv_build==0.12.23` and enforce its standard uv-generated
hash constraints through isolated PEP 517. Explicit build isolation and disabled
configuration discovery prevent ambient configuration from weakening that claim.
The receipt records interpreter, uv, backend requirement and constraint digest.
The runtime dependency lock is unchanged.

An isolated checkout passes all 15 artifact-integrity tests. Wrong backend hashes
refuse without producing a wheel under default settings and conflicting isolation
or hash-verification environment settings. Review identified the isolation override
and an ignored input directory; both are corrected and re-reviewed. The earlier
offline test failure came from its empty-cache assumption, which had depended on
uv's internal fast build path. Offline PEP 517 checks now use the warmed admitted
backend cache and the same constrained invocation.

The [release receipt](_reset/build-backend-20261027.json) records byte-identical
wheel/sdist rebuilds, archive/RECORD checks and SBOM. This is a build-input
checkpoint over the audited product source, isolated from concurrent feature
work. It is not a new production release, signed provenance, refreshed application
dependency qualification, or independent human review. All seven gates remain UNKNOWN.

## Preservation checkpoint and operator pause: 2026-10-24

**Operator pause.** Resume only after the explicit instruction **Continue Cryptalis**. Implementation `8b6bccc` adds approved tenants to online capture. It includes restored adoption, all rotations and current-data native exit. Its [qualification boundary](_reset/online-tenants-boundary-20261024.json) records 452 source checks and 18 installed online checks. The installed original HTTP application also passes export and fresh recovery.

All 47 release inputs still match the reproducible wheel. The push audit removes one trailing blank line from a test. Its Python AST stays identical. Product bytes stay unchanged.

The [pre-push audit](_reset/prepush-security-20261024.json) checks all local Git history, tracked files and local changes. Gitleaks v8.30.1 also checks all 85 archived receipt members. Every match is a file digest or published CF1 test vector. The scan found no real credentials. Git object integrity, private-file ignore rules and 239 Python AST parses pass.

Fresh logging controls pass through the mandatory wrapper with three roles. The installed CLI and compatibility checks for 73 packages also pass. Ruff and Bandit are unavailable. Neither tool ran.

The audit of 20 frozen project packages reports no advisories. The separate cell of 72 packages for application tests reports Starlette 0.46.2 advisory identifiers. Keep that pinned cell isolated. Refresh and requalify its dependencies before production use. All seven gates remain UNKNOWN.

All 49 worktrees remain preserved. Two historical test worktrees retain local changes. This push excludes them. A private bundle contains all Git refs and passes verification. The bundle and copies of those tests remain under `/tmp/cryptalis-prepush-20261024`.

The next application-tenant profile has no implementation. Future work must validate original JWT/account authority before tenant selection. It must preauthorize Item owner metadata. It must handle global administrator and User DELETE cascade routes explicitly. All development agents stopped. The final chat report records the confirmed pushed revision.

## Tenant-scoped online lifecycle: 2026-10-24

**VERIFIED, local source and installed cells:** explicit approved tenant scopes extend online initial protection to tenant-column tables. The v2 preparation artifact binds the complete approved policy set, including empty scopes and fixed table scopes. Planning rejects UUIDs outside the approved policy set before host key lookup. Native membership must also pass the narrower tenant allowlist. Locked expansion rechecks membership before DDL. Native writes reject unknown tenants and preserve the native NULL failure. Backfill uses each row's current tenant and record identity. Scoped uniqueness includes the tenant key. P1 and the v8 activation format remain unchanged.

The local lifecycle check stages real frames, moves a tenant and record identity, invalidates both protected fields in a fixed-scope table, and captures lower-key inserts, deletion/reinsertion and NULL. It then backs up, drops the source schema, restores into an explicitly selected second database, adopts, and rotates root wrapping, payload and search keys. An approved nil-UUID tenant stays empty until its first protected write after all rotations. Current protected edits survive decrypt-back and removal. A child process refuses Cryptalis imports, reads both native tables and commits an ordinary write.

The affected source run passes **452 checks in 250.92 pytest seconds**, including the unchanged original HTTP application and prior single-tenant online controls. All three mandatory role probes pass. The [source receipt](_reset/online-tenants-source-20261024.json) retains all 239 Python hashes unchanged. The first focused attempt failed because the test used a tenant session for a fixed-scope table; the corrected focused run passes both lifecycle and refusal controls. The installed online matrix passes **18 checks in 22.31 pytest seconds**. The same wheel passes the original HTTP source/export control phase (five checks, 12.02 seconds) and genuinely fresh-cluster restore (one workflow, 11.48 seconds). Each wrapper probes all three roles and retains the same 239 Python hashes. The existing Starlette/AnyIO warning remains.

The [final boundary](_reset/online-tenants-boundary-20261024.json) binds exact archived receipts and [repeat-build evidence](_reset/online-tenants-release-20261024.json). Wheel SHA-256 is `6ddd45793f3f0dafa53fd33b5b29f10350b2ff3428c6b90657a908e8bdec9e89`. All 42 installed modules match the committed source; 46 installed files, CLI and SBOM checks pass. A physical earlier installed reader rejects canonical v2 before execution. Run `scripts/online_qualification.py --workdir NEW_DIRECTORY -- tests/test_online_tenants.py -q` for the focused tenant journey, or omit the selection for the complete online matrix.

This is a synthetic SQLAlchemy fixture on a second database in the same local PostgreSQL 16 cluster. Development custody stays in the qualification process. It does not prove fresh-cluster multi-tenant recovery, independent provider recovery, live KMS, production fencing or pause budgets. All seven production gates remain UNKNOWN.

## Original online HTTP fresh recovery: 2026-10-24

**VERIFIED, source and installed cells:** the unchanged 26-file application now
completes online adoption, protected backup, genuinely fresh-cluster restore,
explicit adoption, all three rotations and current-data native exit in one harness.
The source cluster finishes its native exit and stops before the restored cluster
starts. A nonzero `pg_ctl stop` result stops the harness. A focused failure control
proves that failed source shutdown cannot start the restored phase.

Each fresh cluster receives new credentials for the owner, encrypted runtime and
native source roles. Every wrapper reloads and probes all three private files.
The restored plan refuses ordinary admission until the host supplies its explicit
restore binding. Root rewrap, payload generation 2 and search generation 2 retain
the exact access contract through strict v12, v13 and v14 successors.
The original HTTP/JWT, encrypted search, uniqueness races, rollback and local-mail
workload then passes. Latest rows in every mapped table match after decrypt-back.
Native catalog definitions and restored public column slots match after removal.
Both original HTTP child processes refuse Cryptalis imports and use native source access.

The source export/control phase passes five checks in 9.28 pytest seconds.
Its fresh restore passes in 9.40 seconds. The installed phases pass five checks
in 9.45 seconds and the restore workflow in 8.93 seconds. All four retain the same
238 Python hashes. The product's 42 modules still match the earlier reproducible
wheel, so the artifact is reused. The existing Starlette/AnyIO warning remains.
Each complete journey observes sixteen local SMTP messages.

The [final boundary](_reset/online-http-fresh-boundary-20261024.json) binds exact
receipts, application hashes and reused artifact bytes. Run
`scripts/online_qualification.py --workdir NEW_DIRECTORY --http-fresh` with the pinned
`CRYPTALIS_SQLMODEL_HTTP_SOURCE`. This is a local single-tenant fixture with public,
reconstructible test custody. It does not qualify live KMS, production source fencing,
downtime budgets, multi-tenant online migration or independent review.
All 34 objectives remain in scope. All seven production gates remain UNKNOWN.


## Original HTTP application online adoption: 2026-10-24

**VERIFIED, source and installed cells:** the unchanged 26-file FastAPI/SQLModel
application completes initial online protection and current-data native exit.
An original signup request commits while a backfill batch holds a row lock.
The complete original HTTP/JWT and local-mail workload also runs during capture.
Native writes include a lower UUID, NULL and delete/reinsert before catch-up.

The final fence keeps source reads available and refuses source writes. Cutover
revokes source access on existing and fresh connections, then publishes the
host-retained activation artifact. Original target-role HTTP routes, encrypted
email equality/IN, native uniqueness races and rollback pass. Full-name storage
and native Boolean values retain their types. All mapped tables match the
native snapshot after activation and the latest protected snapshot after reverse.
Native catalog definitions and public column slots also match after removal.
A fresh original HTTP child refuses Cryptalis imports and exercises current credentials.

Each run observes ten supplied SELECT structures and twelve loopback SMTP messages
across native, capture and protected phases. The source and installed workflows
pass in 11.29 and 9.57 pytest seconds. Both retain all 237 Python hashes.
The existing Starlette/AnyIO deprecation warning remains recorded.
The [qualification boundary](_reset/online-http-boundary-20261024.json) pins the
raw receipts, unchanged application hashes and reused installed wheel.
All 42 product modules match the earlier qualified artifact. No rebuild is needed.

Use `scripts/online_qualification.py --workdir NEW_DIRECTORY --http` with
`CRYPTALIS_SQLMODEL_HTTP_SOURCE` set to the pinned snapshot. The harness creates
an isolated PostgreSQL 16 cluster and reloads/probes three private role files.
The new profile repeats no backup or rotation workflow. Those existing receipts
retain their separate boundaries. Online fresh-cluster recovery, broader deployment
fencing, pause budgets, live KMS and independent review remain open.
All 34 objectives remain in scope. All seven production gates remain UNKNOWN.


## Bounded online initial protection: 2026-10-24

**VERIFIED, installed cell:** the reproducible wheel passes 103 affected PostgreSQL
checks in 69.42 pytest seconds, including the complete 15-check online matrix.
The source checkpoint is `aa2648f`. Both runs retain all 236 Python hashes.
The installed run repeats concurrent native writes, four committed-process kills,
six rotation successors, actual dump/restore, adopted access authority and current-data
native exit. It uses three freshly probed roles on an isolated PostgreSQL 16 cluster.

The release check proves reproducibility, wheel RECORD, SBOM, CLI and 46 installed
files across 42 product modules. All 72 dependency pins stay unchanged.
Wheel SHA-256 is `4b588f5af8c528257209a39bd6558855a533ba0fb3fdacfa42f0b561b2631982`.
The existing uv/build-backend version warning remains recorded.
The [final boundary](_reset/online-final-boundary-20261024.json) binds the source,
installed receipt, release inputs and documentation. The previous installed reader
refuses the new activation format before database or provider access.

OBJ-LIFE-03 advances from SPECIFIED to PARTIAL. All 34 objectives remain in scope,
and all seven production gates remain UNKNOWN. An unchanged independent application,
a genuine fresh-cluster online restore, live KMS, measured pause budgets and independent
security review remain required. This is bounded product evidence, not release qualification.

**VERIFIED, bounded source cell:** 480 affected checks pass through
`scripts/online_qualification.py` in 238.13 pytest seconds. The wrapper reloads
and probes all three private role URLs. All 236 Python hashes remain stable.
The selection includes 15 online/access/wrapper checks and the affected maintenance,
rotation, restore, Doctor and evidence controls. It proves overlapping native writes,
row-lock ordering, dirty invalidation, NULL, delete/reinsert, lower-key insert,
abort before and after fencing, exact grants, and two tables in one schema.

Four committed-process SIGKILL checkpoints cover two backfill batches, the durable
fence and switched PENDING state. A fresh child activates the retained artifact.
These checks do not simulate a transport-level lost COMMIT reply. Six rotation
successors preserve the contract through root rewrap, payload/search generation 2,
actual dump/restore into another database, explicit adoption and generation 3.
Latest-value decrypt-back restores native source access and revokes encrypted access.
A fresh native child refuses Cryptalis imports and commits an ordinary write.
Restore remains on the same cluster with in-process development custody.

The [source receipt](_reset/online-source-verification-20261024.json) pins the
verified checkout. The [construction history](_reset/online-construction-history-20261024.json)
retains initial fixture and harness failures. No mandatory probe failed.
This source checkpoint preceded the installed qualification above.

**IMPLEMENTED:** `cryptalis.online` permits native application writes during
initial TEXT/VARCHAR backfill on declared single-tenant tables. It records
transactional dirty-row capture, bounded row locks, a durable final writer fence,
full native-versus-decrypted verification and an immutable activation artifact.
The host saves that artifact outside the database before the atomic switch.
An empty backlog alone never permits cutover. Repeatedly changed rows can
prevent convergence. Progress counts transformed row versions, not unique rows.

Three distinct authenticated roles separate the migration owner, native source
and encrypted target. The initial source has direct CRUD grants. The target
has no table access. All column grants must be empty. Cutover atomically revokes
source CRUD and grants target CRUD. This also fences existing source connections.
The exact contract survives root, payload and search successors, restored adoption,
current-data decrypt-back and removal. Native rollback restores source grants
and revokes target grants. Owner and DDL writers remain a host exclusion duty.

Native plaintext remains in PostgreSQL during capture. The capture trigger clears
all staged protected values on each native INSERT or UPDATE. Each backfill batch
locks rows before reading their values and commits frames with its progress marker.
The executor checks row sizes before fetching values. NULL markers remain dirty.
Deletes remove their shadows with the row. New identities below earlier work are
found by dirty-state scans. The terminal fence drains in-flight writers before
catch-up. Full authentication, index DDL, public-slot rewrites where selected,
lock drain and publication still contribute to the final pause.

This bounded implementation does not qualify near-zero downtime, parallel workers,
adaptive scheduling, multi-tenant online migration or production deployment fencing.
The current online checks use synthetic SQLAlchemy fixtures. They do not qualify
an unchanged independent application or external KMS. All seven gates remain UNKNOWN.



## Comprehensive public release direction: 2026-10-23

**SPECIFIED:** the first public release must cover the full SRS and all 34
objectives with production qualification. Current bounded implementations are
internal development checkpoints. They do not establish a restricted beta or
partial public release. Unadmitted SRS capabilities remain required work, and
safe refusal does not complete them. The [approved direction](decisions.md#comprehensive-first-public-release-2026-10-23)
and [competitive capability matrix](research/capability-matrix.md) govern prioritization.
Progress follows complete real-application journeys and resolved production requirements.
All seven production gates remain UNKNOWN.

## Installed application query diagnostics: 2026-10-24

**VERIFIED, bounded installed cell:** the reproducible wheel passes 40 focused
Doctor controls in 20.02 pytest seconds. Python diagnostics and CLI children use the installed package.
Positive samples, known refusal, unavailable inspection, read-only catalog access,
no application-row reads, no key resolution, mapping preservation and redaction pass.
The source checkpoint separately passes 72 affected Doctor/initialization controls.

The unchanged original HTTP application passes genuine installed export and
fresh PostgreSQL 16 recovery. Twelve native SELECT structures captured from
original routes, authentication, local SMTP and search pass structural admission.
A protected ILIKE control refuses before migration without disclosing its value.
The same application completes root, payload and search rotations, latest-value
removal, native schema/public-slot restoration and an import-denied HTTP restart.
Three mail phases each deliver four loopback messages. Both fresh phases pass
the mandatory probes for both roles. All 228 Python hashes remain stable.

The artifact passes repeat-build, 45-input, 40-module, 44-installed-file, RECORD,
SBOM and CLI checks with 72 unchanged dependency pins. Wheel SHA-256 is
`f3fa093c5203ee7344ed4389d2616da0bab385836328b357c5bf582059ab6274`.
The existing uv/build-backend version warning remains recorded. The [final boundary](_reset/query-preflight-final-boundary-20261024.json)
binds current PostgreSQL evidence, exact archived receipts, product bytes and
canonical documents. Construction history retains the earlier expected failures.

This implements supplied-query diagnosis, not a complete route scanner. Successful
samples retain aggregate and query_routes UNKNOWN. Runtime admission still applies.
Public fixture keys, explicit single tenancy, local TestClient and loopback SMTP
limit the application evidence. Live KMS, browser/deployment behavior and independent
review remain open. No cryptographic, key-policy, format or tenant contract changes.
All 34 objective states and seven UNKNOWN production gates remain unchanged.


## Supplied application query preflight: 2026-10-24

**IMPLEMENTED, bounded source verification:** Doctor accepts an optional tuple
of at most 128 SELECT samples before migration. It reuses runtime SELECT
admission against the compiler's inspected mapping and descriptors. It does not
attach the mapping, execute the samples, read application rows or resolve keys.
Known incompatibilities return fixed issue codes, sample indexes and remedies.
SQL text, bound values and exception messages do not enter the report.

All accepted samples produce query_samples PASS and STRUCTURE_ADMITTED items.
Overall status and query_routes stay UNKNOWN because supplied samples do not
prove complete route coverage, bind compatibility, execution or result semantics.
A known unsupported sample sets query_routes and overall status FAIL. Unavailable
inspection stays UNKNOWN. The CLI returns exit 3 for known query incompatibility
and exit 4 for unavailable query inspection. Existing three-member host contexts
retain their behavior. An optional fourth tuple supplies the samples.

Source [verification](_reset/query-preflight-final-source2-20261024.json) passes
72 affected Doctor/initialization controls. The new
HTTP profile captures twelve distinct SELECT structures from the unchanged
original routes, authentication, local SMTP and search workload. Doctor admits
all twelve structures and refuses a protected ILIKE negative control. The same
source application then passes genuine fresh restore, all three rotations,
latest-value removal and a fresh original HTTP process with Cryptalis imports
denied. Both phases pass fresh mandatory probes for both roles. The earlier
three expected missing-operation failures remain in the
[construction history](_reset/query-preflight-construction-history-20261024.json).

The [installed checkpoint](#installed-application-query-diagnostics-2026-10-24) now extends this source evidence. It qualifies the
supplied SELECT structures and the named original application only. No manifest,
ciphertext, key policy, tenant scope or query-operator admission changes. All
34 objective states and seven UNKNOWN production gates remain unchanged.


## Original HTTP application fresh recovery: 2026-10-24

**VERIFIED, installed local cell:** the unchanged 26-file FastAPI template completes
native HTTP/authentication, manifest diagnosis, protection, encrypted search,
protected backup and genuine fresh PostgreSQL 16 adoption. The restored target
completes root rewrap, payload rotation and search rotation. Original routes then
accept retained latest credentials and reject old passwords, invalid tokens,
inactive accounts and unauthorized cross-user operations. Local SMTP delivers
four messages at each of three boundaries, including after restore.

The journey also covers concurrent email uniqueness, rollback, NULL/Unicode
edits, item ownership and cascade deletion. A corrupted email frame refuses
adoption. Root rewrap preserves exact frames. Payload rotation changes every
non-NULL frame. Search rotation preserves storage-only frames and index identity.
Latest edits survive decrypt-back, native catalog and public-slot restoration,
and a fresh original HTTP process with Cryptalis imports denied.

The automated application matrix reuses the existing fresh-cluster harness with
`--sqlmodel-http`. The existing six-file SQLModel public-slot/direct-search row
also passes as an affected control. Four mandatory wrapper runs each pass their
export or restore control with fresh probes for both roles. All 228 Python hashes
stay stable. The [boundary](_reset/http-fresh-installed-boundary-20261024.json) retains exact
receipts and both application reports.

This slice changes tests and the harness only. All 40 product modules match the
qualified ce92 wheel. No artifact rebuild is needed. Doctor still reports
unproven host, query-route, writer-exclusion and custody checks as UNKNOWN.
Public fixture keys, explicit single tenancy, local TestClient and loopback SMTP
limit this evidence. Live KMS, browser/deployment behavior, external mail and
independent security review remain open. All 34 objective states and seven
UNKNOWN production gates remain unchanged.


## Integer storage cost observation: 2026-10-24

**VERIFIED, local observation only:** three matched native/installed 10,000-row
fixtures pass. The [wrapper](_reset/integer-costs-installed-20261024.json) keeps
228 Python hashes stable. All 40 installed product modules match the qualified
ce92 artifact. This slice changes tests only. No new artifact build follows.

| Native width | Added p95 scalar point, ms | Added p95 entity point, ms | Isolated column bytes/native |
|---|---:|---:|---:|
| int2 | 1.2713 | 1.6110 | 22.5× |
| int4 | 2.5815 | 2.0588 | 11.75× |
| int8 | 1.6901 | 1.5266 | 6.375× |

All six point observations meet the local 3 ms target. Each workload uses 100
measured warm pairs after ten warmups, with alternating native/attached order.
Public-ID batches of 20 also match native results. They are not encrypted-value
IN queries, so no encrypted IN target claim follows. Raw samples and exact seed,
cell, storage and process facts appear in the
[boundary](_reset/integer-cost-boundary-20261024.json) and its verified archive.

Column bytes use sum(pg_column_size(name)), including bytea headers. This profile
has no equality index; it does not evaluate the 2× indexed-column target. Whole
heap/relation sizes include retained space after ordinary VACUUM. They do not
prove compact storage or plaintext erasure. Peak RSS is the process-lifetime
high-water mark, including imports and prior cases; it is not incremental app memory.

Protection/publication/attachment takes 0.87–1.02 seconds for these fixtures.
Decrypt-back/removal takes 1.12–1.29 seconds, excluding reverse planning. All
30,000 native values match after removal. No approved write or pause
budget follows. Public local fixture keys, shared-host load and one warm synchronous
cell limit these observations. Remote custody, async, concurrent and larger-scale
costs remain unqualified. Cost approval, all six integer admission gates, all 34
objective states and seven UNKNOWN production gates remain unchanged.

## Integer literal-default installed checkpoint: 2026-10-24

**VERIFIED, internal candidate:** the actual installed artifact passes
[367 affected checks](_reset/integer-defaults-final-installed-20261024.json) in
116.97 pytest seconds. Native default and default-free async writes retain their
loaded attributes after INSERT and UPDATE. Zero and both signed extrema preserve
native pending, NULL/render_nulls, refresh, rollback and savepoint behavior.
Mapping mutation and noncanonical metadata refuse. Both retained readers pass
their exact old-lock/new-reader boundaries. All 227 Python hashes stay stable.

Seven installed fresh-cluster journeys pass fourteen export/restore controls.
Six integer width/layout profiles cover zero or signed extrema, root rewrap,
payload rotation, omitted defaults, explicit NULL edits, tamper refusal before
adoption, latest-value removal and package-free native restart. A Boolean journey
retains the original behavior. Source and installed checks use fresh role probes.
The [final boundary](_reset/integer-defaults-final-boundary-20261024.json) binds
all current receipts, exact archived fresh-run bytes and seven canonical documents.
These are fixture checks; full application and production qualification remain open.

The [artifact check](_reset/integer-defaults-final-release-20261024.json) passes
reproducibility, 45 source inputs, 40 modules, 44 installed files, RECORD, SBOM and
CLI checks with 72 unchanged dependency pins. Wheel SHA-256 is
`ce92ab8e49c19ece07ae70ab3b9225162c5439e07a2a93e77bc58bb4df321bad`.
The existing uv/build-backend version warning remains recorded.

The prior installed expiration failure stays in the immutable construction
history. No ciphertext, context, key policy or canonical-number contract changes.
Default values remain public configuration in lock metadata. Server, callable,
SQL, on-update and generated defaults remain unadmitted. All six integer technical
gates remain unpassed. All 34 objective states and seven UNKNOWN production gates
remain unchanged. Measured workload costs and independent admission evidence
remain required. This is not a public-release qualification.

## Integer defaults and ORM state source checkpoint: 2026-10-24

**IMPLEMENTED, internal candidate:** exact in-range native integer client defaults
now use the existing typed write paths. Optional application_default metadata
uses a canonical signed decimal string and requires pg-integer-default/v1. The
restricted manifest number grammar stays unchanged. Defaults are public
application configuration; the lock contains their decimal values.

**VERIFIED, bounded source cell:** the earlier 190-case check passes default and
integer/compiler/Boolean controls. The [current frozen run](_reset/integer-defaults-final-source-20261024.json)
passes 96 controls for zero/extrema, nullable and non-nullable defaults, native
pending/refresh/rollback, dictionary NULL/render_nulls, async writes, retained
readers and dictionary boundaries. All 227 Python hashes stay stable. An old
integer reader accepts an unchanged default-free v7 plan and refuses new default
metadata before SQL. Mapping-default mutation refuses before key preparation.

The previous installed integer wheel fails three native async-state controls:
its unconditional coercion expression expires valid attributes after flush.
The fix reserves that expression for a known range failure. Valid INSERT and
UPDATE retain native loaded state and avoid implicit async I/O. Overflow, stale
prepared-row and earlier-constraint controls continue to pass. Exact historical
receipts, including that installed failure, remain in the
[construction archive](_reset/integer-defaults-construction-history-20261024.json).

Genuine source [export](_reset/fresh-cluster-export-20261024-67.json) and
[restore](_reset/fresh-cluster-restore-20261024-66.json) each pass one control for
the minimum int64 default with preserved public slots. Default omission, explicit
NULL edits, root rewrap, payload rotation, adoption, latest-value removal and a
fresh child with Cryptalis imports denied pass. Ciphertext bytes stay unchanged
during root rewrap. This is fixture evidence.

The [installed checkpoint](#integer-literal-default-installed-checkpoint-2026-10-24)
now extends this source evidence. Server, callable, SQL, on-update and
generated defaults remain unadmitted. Full type admission and measured workload
costs remain pending. All 34 objective states and seven UNKNOWN production gates
remain unchanged. See the
[decision](decisions.md#literal-integer-application-default-construction-2026-10-24).

## Integer installed lifecycle checkpoint: 2026-10-24

**VERIFIED, internal candidate:** the actual installed wheel passes
[663 affected checks](_reset/integer-installed-regression-20261024.json), including
the 233 source controls and native bulk, adapter/search, migration, restore,
public-slot and removal regressions. Pytest reports 290.09 seconds. All 226 Python
hashes stay stable. Every Cryptalis import comes from the isolated wheel.

The existing fresh-cluster harness passes seven installed journeys: each signed
integer width in both layouts, plus Boolean. All fourteen export/restore runs
pass one control each with fresh probes for both roles. They preserve extrema,
NULL, payload rotation, tamper refusal before adoption, latest edits, native width
and public slots where selected. Every removal ends in a fresh child with
Cryptalis imports denied. These are public fixture journeys, not production
application qualification. The [final boundary](_reset/integer-storage-final-boundary-20261024.json)
binds all current receipts and the exact archived fresh-run bytes.

The [artifact check](_reset/integer-storage-final-release-20261024.json) passes
reproducibility, 45 source inputs, 40 modules, 44 installed files, RECORD, SBOM
and CLI checks with 72 unchanged dependency pins. Wheel SHA-256 is
`13cba8a954426c98d5618a4a24e42e2a3f4723bfbd4f2e6ba2a243f4ba70100f`.
The build still reports the existing uv/build-backend version warning.

This completes a bounded implementation and artifact checkpoint. Integer defaults,
query operators, measured workload costs and independent admission evidence remain
required work. All six integer technical gates remain unpassed. All 34 objective
states and seven UNKNOWN production gates remain unchanged. No full-suite,
original-application integer, live-provider or production-readiness claim follows.

## Integer storage source checkpoint: 2026-10-24

**IMPLEMENTED, internal candidate:** signed native int2/int4/int8 storage uses exact
Python int values or SQL NULL. Typed context/v2 binds fixed signed big-endian
codecs. Lock/v7 names the required codec readers. Existing text and Boolean
formats retain their selectors and bytes. Integer search, order, range,
arithmetic, aggregates, joins and protected defaults remain unadmitted.

**VERIFIED, bounded source cell:** [233 checks](_reset/integer-source-regression-20261024.json)
pass in 83.85 wrapper seconds with all 226 Python hashes stable. They include
independent frame construction, native extrema and prepared-plan controls,
sync/async writes, rollback/savepoints, both layouts, rotations, process recovery,
compiler refusals and the unchanged installed pre-integer reader. Seven actual
SIGKILL/restart controls pass, including six integer width/layout combinations.
The retained reader refuses v7 before SQL in both layouts.

Native custom plans reject an unmatched out-of-width UPDATE with 22003. Generic
plans return zero rows. A stale ORM row produces native StaleDataError under a
generic plan. Public coercion constants preserve these outcomes without private
numeric binds. Ordered entity/dictionary INSERT retains the earlier constraint
error. Typed IntegerRangeExceeded exposes only width and SQLSTATE 22003.

Genuine source [export](_reset/fresh-cluster-export-20261024-68.json) and
[restore](_reset/fresh-cluster-restore-20261024-67.json) pass for int64 with
preserved public slots after payload rotation. Each phase passes one control.
Tampered frames refuse adoption; latest edits survive native-width removal and a
fresh child with Cryptalis imports denied. The Boolean
[export](_reset/fresh-cluster-export-20261024-69.json) and
[restore](_reset/fresh-cluster-restore-20261024-68.json) also pass one control each.
The [construction history](_reset/integer-construction-history-20261024.json)
retains exact intermediate receipts, including failures, in a verified ZIP.
The initial integer restore exposed a text-only result-type assertion; the
corrected verifier requires the pinned native type after authentication.

CF1 frame sizes are 44/46/50 bytes for non-NULL int2/int4/int8 values. These are
frame costs, excluding heap, index, metadata and WAL costs. The [installed checkpoint](#integer-installed-lifecycle-checkpoint-2026-10-24)
now supplies artifact evidence. Full type admission and measured workload costs
remain pending.
All six integer technical gates remain unpassed. All 34 objective states and
seven UNKNOWN production gates remain unchanged. See the
[contract](decisions.md#storage-only-postgresql-integer-contract-2026-10-24).

## Native integer failure oracle: 2026-10-24

**VERIFIED, native PostgreSQL only:** nine width/route controls pass for int2,
int4 and int8 entity flush, dictionary INSERT and scoped UPDATE. Extrema, NULL,
rollback and savepoint recovery pass. Out-of-width values raise server 22003,
including zero-match UPDATE.

Flush deactivates the Session and rolls back the connection to IDLE. Direct
execution leaves an active Session over an INERROR transaction until rollback. See the [run](_reset/integer-native-oracle-initial-20261024.json)
and [observations](_reset/integer-native-observations-20261024.json).

This fixes the native failure oracle before protected integer construction.
No protected integer codec, compiler admission or query support is implemented
by this slice. All six integer admission gates remain unpassed. All 34 objective
states and seven UNKNOWN production gates remain unchanged.

## Public-policy status installed qualification: 2026-10-24

**VERIFIED, current source and installed profiles:** pinned public key-policy
status and invalid native-coroutine SDK cleanup pass the same 168 checks from
[source](_reset/key-policy-final-source-20261024.json) and the
[installed wheel](_reset/key-policy-final-installed-20261024.json), in 65.54 and
72.57 wrapper seconds. All 223 Python hashes remain stable. Both runs include
generation2/removal status, retained obligations, legacy status/Doctor and actual
local SDK controls. No keys are prepared for metadata inspection.

The [reproducible artifact check](_reset/key-policy-final-release-20261024.json)
verifies 45 source inputs, 40 modules and 44 installed files with 72 unchanged
pinned dependencies. Wheel SHA-256 is
`c5cff07217a37bb01f0d8e15d1d400d186cd2ed5f78c507e011612b78e513c1f`.
Genuine installed [export](_reset/fresh-cluster-export-20261024-65.json) and
[direct-generation restore](_reset/fresh-cluster-restore-20261024-64.json) pass one
and 19 controls, respectively, with all 223 hashes stable. Direct v2 planning,
cancellation, process/COMMIT recovery, previous-reader refusal and latest-value
native exit pass. The initial [configuration run](_reset/fresh-cluster-restore-20261024-63.json)
passed 17 and failed two because the required previous-reader interpreter was
omitted. Its probes passed; the corrected run uses the unchanged verified reader.
The [final boundary](_reset/key-policy-final-boundary-20261024.json) binds four
current database receipts, exact artifacts and six documents. All 34 objective
states and seven UNKNOWN gates remain unchanged. No full-suite or live AWS
qualification follows.

## Pinned public key-policy status: 2026-10-24

**VERIFIED, bounded source profile:** optional `status --key-policy-context
MODULE:FACTORY` reports public policy metadata under the exact artifact digest.
The host supplies KeyPolicyStatusContext(operation_id, plan_digest, policies).
Strict native policy/context/wrapper validation and the exact tenant-policy set
precede database access. A pure helper preserves the existing canonical policy
document and digest, including wrapper order. Preparation P refuses before host
loading for this option; its existing status path remains supported.

The report lists selected generations, public provider/root/context identities
and wrapper digests. It emits no sealed bytes. DIGEST_MATCH means local metadata
agreement only. Verification is NOT_PERFORMED; provider availability, material
correctness, completeness and recovery capacity remain UNKNOWN. Both metadata
options can be used after current-value removal without a journal or key work.

The [RED](_reset/key-policy-status-source-red-20261024.json) records one parser
failure. The [initial run](_reset/key-policy-status-source-green-initial-20261024.json)
passes 112 tests and exposes one test-only preparation snapshot error. After that
fixture correction, the [source run](_reset/key-policy-status-source-green-final-20261024.json)
passes all 113 tests in 76.17 seconds, including 25 new controls. All 223 Python
hashes stay stable. Real rewrap, payload2, search2, latest-value reverse/removal,
retained metadata, pre-connect refusals and output failure controls pass.
Current installed verification appears in the
[combined checkpoint](#public-policy-status-installed-qualification-2026-10-24).
All 34 objective states and seven UNKNOWN gates remain unchanged. See the
[contract](architecture/README.md#public-key-policy-status-metadata).

## Invalid KMS coroutine-response cleanup: 2026-10-24

**VERIFIED, bounded source protocol and actual-SDK checks:** a synchronous SDK
callback can still return a native coroutine. The adapter now closes that invalid
return without running its body, then retains its existing redacted KeyUnavailable
failure. The [RED run](_reset/kms-response-cleanup-source-red-20261024.json) reproduces
two warning failures. The [source run](_reset/kms-response-cleanup-source-green-20261024.json)
passes 55 checks in 1.76 seconds, including fresh/already-closed returns, healthy
retry and 12 local actual-SDK Stubber cases. All 221 Python hashes stay stable.
This three-line cleanup change adds no generic awaitable execution or live provider
qualification. Current installed verification appears in the
[combined checkpoint](#public-policy-status-installed-qualification-2026-10-24). All seven gates remain UNKNOWN.

## Integrated defensive hardening: 2026-10-24

**VERIFIED, bounded source and installed profiles at `worktree-6739968d9f52b9dd`:** custom
protected-search dispatch refuses before keys in sync and async execution. Recognized
async SDK methods refuse during client construction. Retained-backup status admits
bounded declarations before database access and never prepares keys.

The [source run](_reset/integrated-hardening-source-20261024.json) passes 74 tests in
89.376 wrapper seconds. The [installed run](_reset/integrated-hardening-installed-20261024.json)
passes 357 tests with one inherited fresh setup skip in 245.754 seconds.
The genuine installed [export](_reset/fresh-cluster-export-20261024-63.json) passes one test.
The separate-cluster [restore](_reset/fresh-cluster-restore-20261024-62.json) passes 24 tests
with one generation-specific setup skip. The [installed SDK run](_reset/integrated-hardening-installed-sdk-20261024.json)
passes 12 local Stubber cases in 2.265 seconds, with credential-discovery and transport tripwires.
All five runs retain 221 stable Python hashes.

The four HTTP reports retain the joined and basic controls:
[source journey](_reset/integrated-hardening-source-application-20261024.json),
[source basic](_reset/integrated-hardening-source-basic-http-20261024.json),
[installed journey](_reset/integrated-hardening-installed-application-20261024.json) and
[installed basic](_reset/integrated-hardening-installed-basic-http-20261024.json).
The [fresh metadata report](_reset/integrated-hardening-fresh-retained-20261024.json)
supplies actual dump/wheel references, with drill None, no journal and zero key preparations.
The command reports host declarations. It does not inspect these files or prove recovery.

The [artifact check](_reset/integrated-hardening-release-20261024.json) covers 44 inputs,
39 modules and 43 installed files. The wheel SHA-256 is
`53e416e8fd17438c460b76cbe258ae511740ddcb4a467928500410aae2a23b3c`.
The [final boundary](_reset/integrated-hardening-final-boundary-20261024.json) binds this evidence.
No current full-suite, live AWS or production qualification follows. All 34 objective
states and seven UNKNOWN gates remain unchanged.

## Synchronous KMS SDK admission: 2026-10-24

**VERIFIED, bounded local protocol checks:** the AWS adapter rejects recognized
coroutine and async-generator methods, including callable objects, during
construction. The unchanged synchronous SDK contract does not dispatch these
methods and leak unawaited-coroutine warnings. The [RED run](_reset/kms-sync-source-red-20261024.json) reproduces three late failures.
The [protocol run](_reset/kms-sync-source-green-20261024.json) passes 39 checks in
0.42 seconds and records the SDK collection skip in that environment. The separate
[actual-SDK run](_reset/kms-sync-sdk-source-green-20261024.json) passes all 12 local
Stubber cases in 2.17 seconds using the preserved isolated SDK target. Credential
discovery and HTTP transport tripwires remain active. All 218 Python hashes stay
stable in both runs at that checkpoint. Current installed verification appears in the
[integrated checkpoint](#integrated-defensive-hardening-2026-10-24).
This fixes client admission only; live AWS custody and production qualification
remain UNKNOWN.

## Exact protected-search expression dispatch: 2026-10-24

**VERIFIED, bounded source native regressions:** protected equality rewriting requires
native SQLAlchemy binary dispatch. Custom subclasses or instance renderers must
fail before key resolution and execution. A benign FALSE renderer reproduced
four attached-query failures while six native and ordinary-query controls passed.

The first fix passed 183 affected tests but exposed two async early-key-resolution
failures. Async SELECT admission now precedes preparation; synchronous execution
rechecks admission. This changes no query capability, crypto or format.
The [initial RED](_reset/search-ast-source-red-20261024.json) and
[first attempted fix](_reset/search-ast-source-green-20261024.json) remain recorded.
The [corrected source run](_reset/search-ast-source-green-final-20261024.json) passes
185 native query, projection, NULL and Boolean controls in 45.77 seconds, with no
skips. All 219 Python hashes stay stable.

Both sync and async custom-dispatch refusals precede keys and driver execution.
Current installed verification appears in the
[integrated checkpoint](#integrated-defensive-hardening-2026-10-24).

## Declared retained-backup status references: 2026-10-24

**VERIFIED, bounded source profile at `worktree-fb4ad19d45ce786b`:** the
[source suite](_reset/retained-status-source-green-20261024.json) passes 131 tests
with one inherited fresh setup skip in 76.37 wrapper seconds (76.09 pytest).
It includes 23 new controls. The [parser RED](_reset/retained-status-source-red-20261024.json)
records one failure in 1.29 seconds. All 220 source/test hashes remain stable
and match this checkpoint.

Legacy output, key-free reporting, journal-free REMOVED ancestor references and output-error
retention pass. References are HOST_DECLARED_DIGEST_REFERENCES. Verification is NOT_PERFORMED.
Completeness, availability and recovery remain UNKNOWN. Current installed and
fresh-cluster verification appears in the
[integrated checkpoint](#integrated-defensive-hardening-2026-10-24).
All 34 objective states and seven UNKNOWN gates remain unchanged. See the
[contract](architecture/README.md#retained-backup-status-metadata).

## Original HTTP operational CLI journey: 2026-10-24

**VERIFIED within the source and installed profiles at `53fd91b`:**
the unchanged 26-file FastAPI HTTP/JWT/local-SMTP application completes initialization,
protection, rewrap, payload2, search2 and latest-value reverse/removal through existing
CLI workflows. Earlier basic HTTP evidence retains its recorded boundary. This is
an application-composition qualification, with no product or helper change.

The [source run](_reset/http-cli-source-20261024.json) and
[installed run](_reset/http-cli-installed-20261024.json) each pass two tests with no
skips. Wrapper elapsed times are 48.88 and 47.20 seconds. Pytest reports 48.54
and 46.44 seconds, with one existing Starlette deprecation warning per run.
The new journey and existing basic HTTP control both pass. Their
[source journey](_reset/http-cli-source-application-20261024.json),
[source basic control](_reset/http-cli-source-basic-http-20261024.json),
[installed journey](_reset/http-cli-installed-application-20261024.json) and
[installed basic control](_reset/http-cli-installed-basic-http-20261024.json)
receipts retain all 26 SHA-256 identities. The profile checks original Git blobs
against the pinned manifest.

Six boundaries repeat original HTTP/auth/password/inactive/Item-cascade controls:
native, protected, rewrapped, payload-published, search-published and plaintext-published.
Each delivers four real loopback SMTP messages, 24 per joined journey. Retained
password, name, email and inactive False checks pass across these boundaries.
Five actual committed-checkpoint SIGKILLs and independent CLI resumes preserve exact
staged/sealed frames, saved P+A, native indexes and public slots. Old-pin refusal
and target-only retry/publication pass. The import-denied original HTTP child verifies
latest native values and excludes SMTP. Only original `get_db` is overridden.
Original authentication, authorization, hashing, queries and routes remain unchanged.

All 218 Python hashes stay stable and match that checkpoint. The 217 prior Python
files remain unchanged. The [reuse attestation](_reset/http-cli-artifact-reuse-20261024.json)
confirms the historical initialization wheel's exact 43 inputs, 38 modules, 42 installed
files and 72 pinned requirements. Its SHA-256 remains
`1d06531b894d117540117544ef251d5cdbe05cf75f0cc93394f4c266cc17ac04`.
No artifact rebuild, install or dependency-environment change occurs. The
[final boundary](_reset/http-cli-final-boundary-20261024.json) binds two current database
receipts, four application receipts, six documents and reused artifact facts.
No product defect or RED is claimed. No current full-suite, fresh-cluster, browser,
deployment, external-mail, live-custody or production qualification follows. All 34 objective
states and seven UNKNOWN gates remain unchanged. See the
[acceptance boundary](architecture/README.md#original-http-operational-qualification),
[security limits](security.md#http-operational-journey-limits) and
[procedure](walkthrough-migration.md#qualify-original-http-across-the-cli-lifecycle).

## Operational CLI initialization: 2026-10-24

**VERIFIED within the bounded source and installed profiles at `85c00b3`:** `init --host-context MODULE:FACTORY --out DECLARATION`
inspects explicit public declaration bytes from a trusted host. A frozen,
repr-disabled `InitializationContext` requires `engine`, `mapping`, `declaration`,
`writers` and `search_reviews`. The existing byte bound and strict parser run
before canonicalization. No models, tenancy, providers or authority are inferred.

Existing key-free Doctor preflight inspects the schema. Only manifest_schema PASS
permits exclusive private publication of the canonical declaration. The report retains
Doctor's pre-adoption format, six unobserved UNKNOWN checks and aggregate UNKNOWN.
Its digest identifies the exact saved canonical bytes. Initialization creates no
operation UUID, transition phase or database progress result.

Compiler inspection effects are NONE. Host-code effects remain UNKNOWN. Output,
fsync or cleanup errors retain known inspection and artifact facts. No key,
provider, deployment pin, runtime role, target ID, measurement, layout or plan
is supplied or created by initialization.

The [parser RED](_reset/init-cli-source-red-20261024.json) records one failure in
0.66 seconds because the old grammar lacks initialization. The
[focused source profile](_reset/init-cli-source-focused-initial-20261024.json) passes
94 tests with four inherited genuine-fresh setup skips in 128.99 seconds: 15
initialization controls and 79 existing operational/application controls. All 217 Python
hashes stay stable and match that checkpoint. Strict-byte policy, key-free inspection,
schema FAIL, unavailable inspection UNKNOWN, durability and failure controls pass.

The [source application](_reset/init-cli-source-application-initial-20261024.json)
retains six pinned files. Initialization supplies the private canonical declaration
consumed by existing planning, replacing the fixture's manual manifest write. Native
schema remains unchanged. The same five actual SIGKILL checkpoints, original CRUD,
search, Boolean values, four observed current IDs and latest-value native exit pass.
Initialization adds no sixth interruption checkpoint.

The [affected-source suite](_reset/init-cli-source-affected-20261024.json) passes
373 tests with no skips in 30.48 seconds. Its ten modules cover CLI, history,
Doctor/preflight, declaration, compiler, public-slot, parser and canonicalization controls.
All 217 Python hashes stay stable and match that checkpoint. The
[artifact check](_reset/init-cli-release-20261024.json) passes reproducible archives,
SBOM, CLI, 38 modules and 42 installed-file checks. All 43 release-source hashes
match that checkpoint. The wheel has SHA-256
`1d06531b894d117540117544ef251d5cdbe05cf75f0cc93394f4c266cc17ac04`.
Only three CLI product modules change. The other 35 modules, including ten crypto
modules, remain unchanged. The
[installed suite](_reset/init-cli-installed-affected-20261024.json) passes 467 tests
with four inherited genuine-fresh setup skips in 157.45 seconds. Its
[application receipt](_reset/init-cli-installed-application-20261024.json) retains
six pinned files, initialization-generated canonical input, the same five actual
SIGKILL checkpoints and latest-value native exit. All 217 Python hashes stay stable
and match that checkpoint. The [final boundary](_reset/init-cli-final-boundary-20261024.json)
binds three current database receipts, two application receipts, six documents and
actual artifact bytes, with the earlier parser RED preserved. Fresh-cluster proofs
retain their older `c612727` boundary. This slice repeats no fresh-cluster or full-suite
qualification. No HTTP or production qualification follows. All 34 objective states
and seven UNKNOWN gates remain unchanged. See the
[architecture contract](architecture/README.md#initialization-cli),
[trust boundary](security.md#initialization-cli-trust-boundary) and
[procedure](walkthrough-migration.md#initialize-an-explicit-declaration-through-the-cli).

## Operational CLI search rotation: 2026-10-24

**VERIFIED within the bounded source and installed profiles at `c612727`:** `keys rotate search` adds `plan`, `apply`,
`status`, `seal`, `switch`, `activate` and `abort` over existing search APIs.
P is search-rotation/v1 or direct-restored v2. Its reserved A uses transition/v4
or adopted v7. Distinct P/A pins bind the exact operation and artifact digest.
Search-specific validation preserves existing protection, reverse and payload exit behavior.

Search rotation retains payload generation, roots and wrappers. It authenticates all
fields, then reseals searchable CF1 with fresh nonces and search terms. Storage-only
CF1 bytes remain exact. Source-only abort, target-only publication and key-free status
retain their existing boundaries. Status reports NOT_PERFORMED verification.

The seven explicit Search contexts mirror the corresponding Payload context fields.
The same authenticated seal, private durable P+A and external-A retention rules apply.
No new core API, artifact format, crypto or host authority is introduced. Doctor
remains unchanged.

The [parser RED](_reset/search-cli-source-red-20261024.json) preserves one failure
in 0.82 seconds because the old command grammar lacks search rotation. The
[focused source profile](_reset/search-cli-source-focused-initial-20261024.json)
passes 79 tests with four genuine-fresh setup skips in 127.80 seconds: nine new
search, 16 payload, 13 rewrap, 19 reverse, 21 protection controls and one original
application journey. All 216 Python hashes stay stable and match that checkpoint.

The [source application](_reset/search-cli-source-application-initial-20261024.json)
retains six pinned files and five actual SIGKILL checkpoints. Its search transition
keeps payload generation 2, selects search generation 2 and changes the searchable
email nonce and term. Both storage-only fields retain exact CF1 bytes. Key-free
status, source-only cancellation, saved-A recovery and target-only retry/publication pass.
Original CRUD, equality/IN, native uniqueness and Boolean controls pass. Reverse
observes four current records before latest-value removal and an import-denied restart.
The [affected-source suite](_reset/search-cli-source-affected-20261024.json)
passes 449 tests with no skips in 231.36 seconds. Its 21 modules cover 260
existing CLI, Doctor and reverse controls, 129 payload controls and 60 search
retained-reader, preparation, lifecycle and recovery controls. The unchanged 103 core
root-rewrap controls retain their `f303a18` boundary. The focused source run includes
13 current operational rewrap controls. All 216 Python hashes stay stable and match
this worktree. The [artifact check](_reset/search-cli-release-20261024.json) passes
reproducible archives, SBOM, CLI, 38 modules and 42 installed-file checks. All 43
release-source hashes match that checkpoint. The wheel has SHA-256
`a103f8c018d07c7942a289577f8caa091fb748825a059f758a596ce74cf57025`.
Only three CLI product modules change. The other 35 modules, including ten crypto
modules, remain byte-exact at `f303a18`. Genuine source
[export](_reset/fresh-cluster-export-20261024-61.json) and
[separate-cluster restore](_reset/fresh-cluster-restore-20261024-60.json) each pass
one test in 0.89 and 1.75 seconds. A wrong restore binding refuses before keys.
The real binding produces search proposal v2 and activation v7. Current search edits
and CLI reverse/removal complete latest-value native exit. Both receipts retain 216
stable/current Python hashes.

The [installed suite](_reset/search-cli-installed-affected-20261024.json) passes
528 tests with four genuine-fresh setup skips in 355.12 seconds. Its
[application receipt](_reset/search-cli-installed-application-20261024.json) retains
six unchanged files, five actual SIGKILL checkpoints and latest-value native exit.
All 216 Python hashes stay stable and match that checkpoint. Actual installed
[export](_reset/fresh-cluster-export-20261024-62.json) and
[separate-cluster restore](_reset/fresh-cluster-restore-20261024-61.json) each pass
one test in 0.82 and 1.24 seconds, with the same 216 stable hashes at that checkpoint.
The [final boundary](_reset/search-cli-final-boundary-20261024.json) binds seven
current database receipts, two application receipts, six documents and actual
artifact bytes. The earlier parser RED retains its historical boundary. No current
full-suite, HTTP or live custody qualification follows. All 34 objective states and
seven UNKNOWN gates remain unchanged. See the
[architecture contract](architecture/README.md#search-rotation-cli),
[admission boundary](security.md#search-cli-admission) and
[procedure](walkthrough-migration.md#rotate-search-generation-through-the-cli).

## Operational CLI payload rotation: 2026-10-24

**VERIFIED within the bounded source and installed profiles at `f303a18`:** `keys rotate payload` adds `plan`, `apply`,
`status`, `seal`, `switch`, `activate` and `abort` over existing APIs. P reserves
A's operation UUID, not its content or digest. Seal authenticates BACKFILLED
shadows to produce A. Seal changes no data, schema or journal phase. Provider
audit and cost effects remain possible.

Retain exact private durable P+A before switch. A lost seal output permits
fresh authenticated resealing while shadows remain. Identical staged bytes and
explicit copy measurements produce identical A. After switch, P is superseded
and shadows are gone. Recovery requires externally retained A. Current APIs cannot
reconstruct its immutable frame proof from P or journal assertions.

P staging and A switch/publication use distinct exact pins. Abort uses source
custody alone. Activation uses target custody alone. Status uses no keys and
reports NOT_PERFORMED verification. File publication is separate from database
progress. Host-code effects remain UNKNOWN. Existing formats, cryptography, core
protocols and Doctor remain unchanged. The CLI creates no root, provider or authority.
Earlier receipts retain their exact failed or incomplete boundaries:

| Receipt | Result and limit |
|---|---|
| [Parser RED](_reset/payload-cli-source-red-20261024.json) | One failure in 0.65 seconds: the old parser lacks payload commands. |
| [First source candidate](_reset/payload-cli-source-focused-initial-20261024.json) | 66 passed, one failed in 68.26 seconds. Lost seal output lacks a remedy. Three fresh setup cases and the application collection are skipped. |
| [Intermediate source run](_reset/payload-cli-source-focused-verified-20261024.json) | 69 passed in 69.35 seconds after the payload-local remedy fix. Application collection remains skipped, so this run supplies no application evidence. |
| [First collected application](_reset/payload-cli-source-focused-complete-20261024.json) | 69 passed, one failed in 87.33 seconds. Its test oracle treats random storage nonces as stable metadata. |
| [Next application control](_reset/payload-cli-source-app-proof-20261024.json) | One failure in 20.69 seconds. Its reverse assertion expects two records after payload CRUD creates a third. |

The corrected [application-only run](_reset/payload-cli-source-app-native-20261024.json)
passes one test in 26.30 seconds. The [final focused profile](_reset/payload-cli-source-focused-final-20261024.json)
passes 70 tests with three genuine-fresh setup skips in 94.73 seconds. All 215
Python hashes stay stable and match that checkpoint. The
[final application receipt](_reset/payload-cli-source-application-final-20261024.json)
retains six pinned files and four actual SIGKILL checkpoints across protection,
rewrap, payload and reverse. It verifies source-only payload cancellation, key-free
status, authenticated identical resealing, independent PENDING recovery and target-only
publication. Current CRUD, search, Boolean values and latest-value native exit pass.
The [affected-source suite](_reset/payload-cli-source-affected-20261024.json)
passes 492 tests with one collection skip in 250.35 seconds. Its 22 selected modules
include 363 existing CLI, Doctor, decrypt-back and rewrap controls plus 129 payload
planning, preparation, execution, cutover and recovery controls. Direct-generation tests
are collection-skipped through a fresh-only import. Their controls do not run here.
All 215 Python hashes stay stable and match that checkpoint. The
[artifact check](_reset/payload-cli-release-20261024.json) passes reproducible archives,
SBOM, CLI, 38 modules and 42 installed-file checks. All 43 release-source hashes
match that checkpoint. The wheel has SHA-256
`df6c287462dec619e79869ca169cb248d5b4800f1bc14fe4ea9b05218df1baba`.
Only three CLI product modules change. The other 35 modules, including ten crypto
modules, remain unchanged. The genuine source
[export](_reset/fresh-cluster-export-20261024-59.json) and
[separate-cluster restore](_reset/fresh-cluster-restore-20261024-58.json) each pass
one test in 0.99 and 1.95 seconds. A wrong binding refuses before custody work.
The real binding produces payload proposal v2 and activation v6. Later edits and
CLI reverse/removal complete latest-value native exit. Both receipts retain 215
stable/current Python hashes.

The [installed suite](_reset/payload-cli-installed-affected-20261024.json) passes
562 tests in 346.20 seconds, with three genuine-fresh setup skips and one
direct-generation collection skip. Its [application receipt](_reset/payload-cli-installed-application-20261024.json)
retains six unchanged files, four actual SIGKILL checkpoints and latest-value native
exit. All 215 Python hashes stay stable and match that checkpoint. Actual installed
[export](_reset/fresh-cluster-export-20261024-60.json) and
[separate-cluster restore](_reset/fresh-cluster-restore-20261024-59.json) each pass
one test in 0.88 and 1.81 seconds, with the same 215 stable hashes at that checkpoint.
The [final boundary](_reset/payload-cli-final-boundary-20261024.json) binds seven
current database receipts, two current application receipts, six documents and
actual artifact bytes. Earlier failed/incomplete runs and the standalone application
proof retain their recorded boundaries. No current full-suite or production qualification follows. Search CLI remains required next. All 34 objective
states and seven UNKNOWN gates remain unchanged. See the
[architecture contract](architecture/README.md#payload-rotation-cli),
[artifact-retention boundary](security.md#payload-cli-artifact-retention) and
[procedure](walkthrough-migration.md#rotate-payload-generation-through-the-cli).

## Operational CLI root rewrap: 2026-10-24

**VERIFIED within the bounded source and installed profiles at `93fb372`:** `keys rotate rewrap` adds `plan`, `apply`,
`activate` and `abort` over existing root-rewrap APIs. Plan saves proposal P.
Apply saves its deterministic activation A before host loading or database work.
Both source and target resolvers remain necessary for apply, including PENDING retry.
Only activation uses target custody alone. Abort uses source custody and the
separate source ACTIVE pin. It creates no target context.

Ordinary output collisions refuse. Explicit `apply --resume OP` checks the saved
operation and exact private regular A before host loading. Symlinks and mismatched
bytes refuse. If A is absent, resume publishes it exclusively. Resume re-syncs
the verified file and parent before API retry. File publication does not establish
any database phase. An unreturned API outcome requires INSPECT_JOURNAL.

Four explicit trusted contexts supply host pins, approvals and keyrings. The CLI
creates no authority, provider or key material. Existing formats, cryptography,
core protocols and Doctor's tuple remain unchanged.

The [initial parser RED](_reset/rewrap-cli-source-red-20261024.json) records one
failure in 0.64 seconds. The [first source candidate](_reset/rewrap-cli-source-focused-initial-20261024.json)
passes 54 tests in 48.11 seconds, with its [initial application](_reset/rewrap-cli-source-application-initial-20261024.json).
Later review reproduces two [compatibility failures](_reset/rewrap-cli-compatibility-red-20261024.json)
in 1.59 seconds: global denial classification changes existing protection/reverse
publication refusals from exit 3 to 2. Rewrap-local classification restores those
contracts. The [corrected source profile](_reset/rewrap-cli-source-focused-verified-20261024.json)
passes 54 tests with two genuine-fresh setup skips in 50.14 seconds, including
both compatibility controls. All 214 Python hashes stay stable and match that checkpoint.

The [verified source application](_reset/rewrap-cli-source-application-verified-20261024.json)
retains six pinned files and actual protection, rewrap and reverse SIGKILL checkpoints.
Source-only cancellation passes during target outage. Terminal retry preserves a later
source edit. A new proposal reaches PENDING, then independent exact-A resume and
target-only activation preserve frames and native index identities. Original search,
latest native values and package-free exit pass.

The [affected-source suite](_reset/rewrap-cli-source-affected-20261024.json)
passes 363 tests in 174.41 seconds: 260 existing CLI, decrypt-back, runtime and
status controls plus 103 root-rewrap planner, preparation, execution and abort controls.
All 214 Python hashes stay stable and match that checkpoint. The
[artifact check](_reset/rewrap-cli-release-20261024.json) passes reproducible archives,
SBOM, CLI, 38 modules and 42 installed-file checks. All 43 release-source hashes
match that checkpoint. The wheel has SHA-256
`b5e84edcf0096adee115dbacb4e1c4f0aebee312d1f21fc111c3ed9f639ba74a`.
The genuine source [export](_reset/fresh-cluster-export-20261024-57.json) and
[separate-cluster restore](_reset/fresh-cluster-restore-20261024-56.json) each pass
one test in 1.15 and 1.79 seconds. A wrong binding refuses before either resolver.
The real binding embeds in proposal v2 and successor v5. Payload frames and native
index identities stay exact through rewrap. Target custody supports a later edit
and existing CLI reverse/removal completes latest-value native exit. Both receipts
retain 214 stable Python hashes at that checkpoint.

The [installed-primary suite](_reset/rewrap-cli-installed-affected-20261024.json)
passes 417 tests with two genuine-fresh setup skips in 225.51 seconds: 363 affected,
13 new native, 19 reverse, 21 protection controls and one original application journey.
Its [application receipt](_reset/rewrap-cli-installed-application-20261024.json) retains
six pinned files and all three actual SIGKILL checkpoints, source-only cancellation,
target-only activation and latest-value native exit. All 214 Python hashes stay
stable and match that checkpoint. Actual installed [export](_reset/fresh-cluster-export-20261024-58.json)
and [separate-cluster restore](_reset/fresh-cluster-restore-20261024-57.json) each
pass one test in 0.64 and 1.45 seconds, with 214 stable Python hashes at that checkpoint.
The [final boundary](_reset/rewrap-cli-final-boundary-20261024.json) binds seven
current database receipts, two current application receipts, six documents and
actual artifact bytes. Three earlier database receipts and the initial application
retain their historical boundaries. No current full-suite, HTTP or live custody
qualification follows. Payload CLI remains required next, then search CLI. All 34
objective states and seven UNKNOWN gates remain unchanged. See the
[architecture contract](architecture/README.md#root-rewrap-cli),
[artifact/authority boundary](security.md#root-rewrap-cli-artifact-and-authority-boundary) and
[procedure](walkthrough-migration.md#rewrap-root-custody-through-the-cli).

## Operational CLI reverse and removal: 2026-10-24

**VERIFIED within the bounded source and installed profiles at `402bdd5`:** `plan` accepts mutually exclusive manifest
or `--reverse SOURCE` inputs. Reverse planning saves the existing immutable
`DeprotectionPlan` before the host reviews it and supplies separate plaintext consent.
`rollback REVERSE` and `apply REVERSE` execute that same saved proposal. They do
not create another proposal or infer authority. This reverses current values,
not an arbitrary historical codec.

Default execution stops at PLAINTEXT_PENDING. The host supplies PLAINTEXT_ACTIVATING
before explicit PLAINTEXT_ACTIVE completion. Resume and abort require the saved
reverse operation UUID before host loading. Abort removes only pre-switch staging.
`remove REVERSE` requires exact host pins, plaintext consent and removal approval.
Terminal retry still needs the REMOVED pin and the same approvals.

Three explicit trusted contexts separate reverse planning, execution and removal.
An optional restore binding enters only through planning and stays in the artifact.
Removal uses no keys. Doctor retains its strict key-free tuple. Host-code effects
remain UNKNOWN. Existing artifact formats, cryptographic and core protocols stay unchanged.

The [focused source profile](_reset/reverse-cli-source-focused-initial-20261024.json)
passes 41 tests with one skipped genuine-fresh case in 24.37 seconds. It combines
19 new native controls, 21 protection controls and one original application journey.
All 213 Python hashes stay stable and match that checkpoint. The
[earlier parser](_reset/reverse-cli-source-red-20261024.json) fails one reverse-planning
control in 0.89 seconds. Its receipt retains the historical 213-file snapshot.

The [source application](_reset/reverse-cli-source-application-initial-20261024.json)
retains six pinned files. Actual SIGKILL follows committed BACKFILLED progress during
protection and reverse. Independent resumes preserve all three fields' staged frames
and completed plaintext. Original native CRUD and latest Boolean false pass after
explicit plaintext publication. Approved CLI removal, REMOVED retry and an
import-denied restart complete the journey.

The [affected-source suite](_reset/reverse-cli-source-affected-20261024.json)
passes 260 tests in 116.94 seconds: 189 existing CLI, history, status and Doctor
controls plus 71 native decrypt-back, runtime and status controls. All 213 Python
hashes stay stable and match that checkpoint.

The genuine source [export](_reset/fresh-cluster-export-20261024-55.json) and
[separate-cluster restore](_reset/fresh-cluster-restore-20261024-54.json) each pass
one test in 1.22 and 1.66 seconds. A wrong valid binding digest refuses before
keys. The real binding embeds in the saved proposal and completes reverse and
latest-value native exit. Both receipts retain the same 213 stable hashes at that checkpoint.
The [artifact check](_reset/reverse-cli-release-20261024.json) passes reproducible
archives, CLI, 38 modules and 42 installed-file checks. All 43 release-source
hashes match that checkpoint. The wheel has SHA-256
`55c3d89de08465febfcf199352ae610ea0c3efef485d6e4b32ea60c4ee2a968a`.
The [installed-primary suite](_reset/reverse-cli-installed-affected-20261024.json)
passes 301 tests with one genuine-fresh setup skip in 136.00 seconds. It combines
260 affected controls, 19 new native controls, 21 protection controls and one
[unchanged application journey](_reset/reverse-cli-installed-application-20261024.json).
All 213 Python hashes stay stable and match that checkpoint. The original six-file
journey now passes on the actual wheel, including both interruption/resume paths,
explicit plaintext publication, native latest values and approved package-free exit.
The actual wheel also passes genuine [export](_reset/fresh-cluster-export-20261024-56.json)
and [separate-cluster restore](_reset/fresh-cluster-restore-20261024-55.json) stages,
one test each in 0.91 and 1.24 seconds. Both receipts retain 213 stable
Python hashes at that checkpoint. The [final boundary](_reset/reverse-cli-final-boundary-20261024.json)
binds seven current database receipts, two application receipts and six documents,
with actual artifact bytes and preserved historical RED evidence. No current
full-suite, HTTP or external custody qualification follows. Root-rewrap CLI remains
required next, followed by payload/search CLI work. All 34 objective states and
seven UNKNOWN gates remain unchanged. See the
[architecture contract](architecture/README.md#reverse-and-removal-cli),
[authority boundary](security.md#reverse-cli-authority) and
[procedure](walkthrough-migration.md#plan-and-execute-current-value-plaintext-reverse-through-the-cli).

## Operational CLI protection workflow: 2026-10-24

**VERIFIED within the source and installed profiles at `4373e5e`:** `plan` and `apply` commands
reuse the existing protection planner and maintenance executor. An explicit
trusted synchronous zero-argument host factory returns a frozen `PlanningContext`
or `ApplyContext`. Planning requires an engine, mapping, writer inventory, search
reviews, keys, runtime role, target ID and four existing measurements. Apply
requires an engine, keys, host pin and maintenance approval. Doctor retains
its separate key-free three-member tuple.

Plan writes the canonical existing protection artifact to a new private path.
Existing paths refuse. Atomic publication and fsync protect the artifact write.
Planning authority is `HOST_SUPPLIED_CONTEXT`, not a published deployment pin.
Apply defaults to PENDING. Resume and abort require the exact saved operation
UUID before host loading. ACTIVE requires an actual ACTIVATING host pin and
maintenance approval. Factory names and requested phases convey no authority.

Each factory supplies a fresh CLI-owned PostgreSQL/psycopg engine with safe logging.
The CLI disposes it after success or failure. Host imports, factory calls and
native effects remain UNKNOWN. CLI reports expose no keys, credentials or host
exception text. Rotation, reverse and removal commands remain outside this slice.
Their later CLI completion remains required for the comprehensive public release.

The [initial source profile](_reset/operational-cli-source-initial-20261024.json)
passes 15 tests in 9.49 seconds: 14 CLI controls and one original SQLModel
application journey. Its 212 Python hashes stay stable within the recorded run.
The [earlier native RED](_reset/operational-cli-source-red-20261024.json) records
one unknown-plan-command failure, exit 2 instead of 0, with 210 stable hashes.

The [source application](_reset/operational-cli-source-application-20261024.json)
retains six pinned files and protects `full_name` VARCHAR, `email` search/uniqueness
and `is_active` Boolean through plan/apply/resume subprocesses. Actual SIGKILL follows
committed BACKFILLED progress. Independent resume preserves all three fields' staged
frames. An explicitly supplied ACTIVATING host pin permits publication. Original
CRUD, search, Boolean values and latest false pass. Python decrypt-back/removal
and an import-denied restart complete the journey. This is source-only evidence.
Expanded failure controls, revised artifacts and installed PostgreSQL verification
were pending at that initial checkpoint. No current full-suite result follows.

The [first expanded source candidate](_reset/operational-cli-source-expanded-initial-20261024.json)
reports 21 passed and one failed in 11.22 seconds. A recognized async callable
key-resolver object passes `ApplyContext` validation instead of receiving
`HostContextInvalid` before command-managed connection. Other controls pass, including
artifact directory durability, output races and cleanup after known progress.
The [expanded source application](_reset/operational-cli-source-expanded-application-20261024.json)
also passes at that candidate's recorded boundary. Initial and expanded receipts
keep separate historical snapshots.

The [revised focused source profile](_reset/operational-cli-source-focused-20261024.json)
passes all 22 tests in 11.39 seconds. All 212 Python hashes remain stable
and match that checkpoint. The recognized async callable resolver now refuses
before command-managed connection. The [verified source application](_reset/operational-cli-source-verified-application-20261024.json)
retains six unchanged files and the actual SIGKILL, independent resume, explicit
host publication and latest-value native exit.

The [affected-source suite](_reset/operational-cli-source-affected-20261024.json)
passes 189 tests in 76.82 seconds. Its 212 Python hashes remain stable and
match that checkpoint. It covers existing CLI, history, status, Doctor and
pre-adoption routes. The [artifact check](_reset/operational-cli-release-20261024.json)
passes reproducible archives, CLI and 42 installed-file checks. All 43 release-source
hashes match that checkpoint and all 38 product modules match the wheel.
The [installed PostgreSQL suite](_reset/operational-cli-installed-affected-20261024.json)
passes 211 tests in 79.34 seconds: 189 existing controls, 21 new native controls
and one [unchanged application journey](_reset/operational-cli-installed-application-20261024.json).
All 212 Python hashes remain stable and match that checkpoint. The installed wheel
has SHA-256 `a133c4717d229ec277db7aed29576f8611c5d9bd131895ddbfedcbaa47d8c10f`.
The [final boundary](_reset/operational-cli-final-boundary-20261024.json) binds
the three current PostgreSQL receipts, two current application receipts, actual
release/install bytes, historical candidates and six documents. Of the 36 prior
product modules, only the CLI changes; all ten crypto modules remain unchanged.
Two new modules supply host contexts and command composition. No current full-suite
result follows. At that checkpoint, rotation, reverse and removal CLI commands remained
unimplemented. The [new reverse workflow](#operational-cli-reverse-and-removal-2026-10-24) records later source evidence.
All 34 objective states and seven UNKNOWN gates remain unchanged. See the
[architecture](architecture/README.md#operational-protection-cli),
[security boundary](security.md#operational-cli-trust-boundary) and
[specified procedure](walkthrough-migration.md#plan-and-apply-protection-through-the-cli).

## Legacy expression-statistics admission: 2026-10-24

**VERIFIED, bounded source and installed profiles at `7f231fc`:** two
[native controls](_reset/legacy-expression-statistics-red-20261024.json) fail because
late expression-only statistics reach a forbidden key resolver. One uses a
planned legacy lock/v2 source. The other plans reverse from ACTIVE. Both
statistics objects have non-null `stxexprs` and no ordinary `stxkeys` entries.
The recorded 208 Python hashes stay stable within that failed baseline run.

The fix extends the existing catalog EXISTS guard to all layouts through
shared source, unrecorded-metadata and protected-contract admission. It inspects
catalog facts without evaluating expressions. Unsupported expression statistics
raise `unsupported_dependency`. Artifact formats, layout selection, tenant and CF1
contracts remain unchanged.

The [first expanded candidate](_reset/legacy-expression-statistics-expanded-initial-20261024.json)
reports 42 passed and one failed in 66.76 seconds. It combines 18 new legacy
controls with 25 public-slot controls. The remaining failure reaches the forbidden
resolver during an EXPANDED reverse retry. Other type/selector and phase controls
pass at that candidate boundary.

The [prepared-reverse control](_reset/legacy-expression-statistics-prepared-reverse-red-20261024.json)
also fails because first reverse expansion does not raise the required refusal.
This separate run reports one failure and 18 deselected cases in 1.05 seconds,
with 208 stable Python hashes. Revised code adds guards in paused reverse
inspection and first reverse expansion before DDL or provider work. Earlier
candidates retain their exact failed boundaries.

The [revised source profile](_reset/legacy-expression-statistics-source-focused-20261024.json)
passes all 44 controls in 65.39 seconds: 19 legacy cases and 25 public-slot cases.
At `7f231fc`, all 208 Python hashes remain stable and match its files. Refusal leaves
snapshots unchanged and reaches no forbidden key resolver. Removing only the
late object lets the same pinned plan complete its native exit. The
[revised artifact check](_reset/legacy-expression-statistics-release-revised-20261024.json)
passes reproducible archives, CLI, 36 product modules and 40 installed files
against 41 release-source hashes recorded at `7f231fc`. The
[earlier artifact candidate](_reset/legacy-expression-statistics-release-20261024.json)
remains historical.
The [affected-source suite](_reset/legacy-expression-statistics-source-affected-20261024.json)
passes 536 tests in 298.87 seconds. Its 208 Python hashes remain stable at
`7f231fc`. This suite covers source, protected and paused admission,
reverse, metadata, restore, rotation, diagnostics and compiler behavior.

The [revised wheel](_reset/legacy-expression-statistics-installed-affected-20261024.json)
passes 583 installed controls in 387.45 seconds, with one known Starlette warning.
Three ordinary application receipts retain
[six public-slot](_reset/legacy-expression-statistics-installed-public-slots-application-20261024.json),
[six default-searchable](_reset/legacy-expression-statistics-installed-searchable-application-20261024.json)
and [26 HTTP/JWT/SMTP](_reset/legacy-expression-statistics-installed-http-application-20261024.json)
source files unchanged.

The original three-field public-slot application also passes installed
[export](_reset/fresh-cluster-export-20261024-53.json) and
[fresh-target](_reset/fresh-cluster-restore-20261024-52.json) stages, one test each
in 1.60 and 3.63 seconds. Its [application receipt](_reset/legacy-expression-statistics-installed-fresh-application-20261024.json)
retains the six original files. The legacy owned-sequence profile passes one
[export](_reset/fresh-cluster-export-20261024-54.json) in 0.93 seconds and
[four target tests](_reset/fresh-cluster-restore-20261024-53.json) in 8.96 seconds.
These seven database receipts retain 208 stable Python hashes at `7f231fc`.
The [final boundary](_reset/legacy-expression-statistics-final-boundary-20261024.json)
binds those receipts, four application receipts and five canonical documents.
The three RED runs and initial artifact remain historical. Only migration and
deprotection product modules change. The earlier full suite retains its recorded
boundary. No current full-suite result is claimed. See the
[all-layout decision](decisions.md#expression-statistics-admission-across-layouts-2026-10-24),
[security contract](security.md#expression-statistics-admission) and
[lifecycle rule](lifecycle.md#late-expression-statistics-admission-2026-10-24).
All seven production gates remain UNKNOWN.

## Original three-field SQLModel fresh adoption: 2026-10-24

**VERIFIED, bounded source and installed journeys at `f72a49d`:** the unchanged six-file SQLModel
application completes genuine fresh-cluster adoption with `full_name` VARCHAR,
`email` search/uniqueness and `is_active` Boolean. Lock/v6 preserves source public
slots through protection. Restore/v3 records target slots, then direct-binding
search rotation publishes v7 without an intermediate rewrap. Recorded target
User/Item OIDs and public slots remain unchanged through original CRUD,
latest-value removal and an import-denied restart. Source and target OIDs have
separate evidence. Storage-only `full_name`/`is_active` frames stay byte-exact through search rotation.
Original email search/uniqueness and Boolean controls pass, with the latest Boolean false after removal.

The source [export](_reset/fresh-cluster-export-20261024-49.json) and
[target](_reset/fresh-cluster-restore-20261024-48.json) stages each pass one test
in 2.15 and 3.62 seconds. Installed [export](_reset/fresh-cluster-export-20261024-50.json)
and [target](_reset/fresh-cluster-restore-20261024-49.json) stages each pass one
in 1.63 and 3.93 seconds. The [source](_reset/sqlmodel-public-slots-source-application-20261024.json)
and [installed](_reset/sqlmodel-public-slots-installed-application-20261024.json)
application receipts retain all six pinned files. All 207 Python hashes remain
stable at `f72a49d`.

The source legacy rewrap-first profile passes one
[export](_reset/fresh-cluster-export-20261024-51.json) in 1.35 seconds and one
[target test](_reset/fresh-cluster-restore-20261024-50.json) in 2.43 seconds.
The installed direct-search legacy profile passes one [export](_reset/fresh-cluster-export-20261024-52.json)
in 1.20 seconds and one [target test](_reset/fresh-cluster-restore-20261024-51.json)
in 2.80 seconds. Their [source](_reset/sqlmodel-public-slots-legacy-source-application-20261024.json)
and [installed](_reset/sqlmodel-public-slots-legacy-installed-application-20261024.json)
application receipts retain the default-layout and restore/v1 boundaries.
The [final boundary](_reset/sqlmodel-public-slots-final-boundary-20261024.json)
binds eight PostgreSQL receipts, four application receipts and three documents.

This test-only slice changes three harness/test files. All 36 product modules,
including ten crypto modules, retain their earlier bytes. It reuses the
[4025210f8957 wheel](_reset/public-slots-release-20261024.json). The prior full suite
remains evidence for its recorded checkpoint. No new full run or artifact build
follows from this application slice. Email admission stays fixture-only with
explicit single tenancy. This journey adds no HTTP, browser, deployment or
provider qualification. All seven production gates remain UNKNOWN.

## Public column slot preservation: 2026-10-24

**VERIFIED, bounded source and installed profiles at `6cb926e`:** explicit `layout="preserve-public-slots/v1"`
selects lock/v6 through `compile_protection()` or `migration.plan()`. None retains
the earlier format selection and DROP/RENAME behavior. A previous lock does
not select the new layout. Invalid values refuse before connections or providers.

The new switch changes original public attributes' types with authenticated
staged values. It rebuilds public CF1 CHECKs and equality indexes before
dropping shadows. Reverse changes the same attributes to native types and
restores captured metadata. Within each target, original public attnums/order
and admitted sequence identity remain pinned. Heap and index storage can change.
DDL rewrites and index costs remain outside host-supplied row-rate/WAL estimates.

Restore/v3 records every public column's complete ordered source-to-target slot
map, plus a mandatory complete sequence map or empty list. Slot values must
be exact integers in 1..32767. Boolean values refuse. Flat lineage composes
current mapped target slots without changing original artifacts or authority.
Legacy metadata comparison stays unchanged. Restore/v1/v2 cannot authorize v6 sources.

The [recorded focused profile](_reset/public-slots-source-focused-20261024.json)
passes 25 controls in 48.20 seconds: nine local, seven compiler and nine recovery
cases. Actual SIGKILL, post-ALTER/index rollback, native counter gaps, lost COMMIT
replies and slot drift despite matching journals pass. Its 206 hashes stay
stable within that run. A later fixture-only serialization fix remains outside
that snapshot. The [initial implementation](_reset/public-slots-source-initial-20261024.json)
passes 14. The [strict opt-in baseline](_reset/public-slots-source-red-20261024.json)
retains one legacy pass and two missing-layout failures. Both
[late expression-statistics failures](_reset/public-slots-late-statistics-red-20261024.json)
precede the v6 guard. Source, ACTIVE, paused, restore and terminal checks now
refuse that dependency before providers or effects.

At `6cb926e`, source TEXT without sequences passes one
[export](_reset/fresh-cluster-export-20261024-42.json) in 1.09 seconds and
[six fresh-target tests](_reset/fresh-cluster-restore-20261024-41.json) in 10.70 seconds.
TEXT with an owned sequence passes one [export](_reset/fresh-cluster-export-20261024-43.json)
in 1.48 seconds and [six target tests](_reset/fresh-cluster-restore-20261024-42.json)
in 12.04 seconds. Both profiles record 206 stable Python hashes at `6cb926e`.
The [artifact check](_reset/public-slots-release-20261024.json)
passes reproducible archives, CLI, 36 product modules and 40 installed files
against 41 current release-source hashes. Source VARCHAR passes one
[export](_reset/fresh-cluster-export-20261024-44.json) in 1.17 seconds and
[six fresh-target tests](_reset/fresh-cluster-restore-20261024-43.json) in 10.32 seconds.
The [actual installed wheel](_reset/public-slots-installed-affected-20261024.json)
passes 294 affected/application controls in 198.49 seconds with one known warning.
Its sequence-bearing v6 [export](_reset/fresh-cluster-export-20261024-45.json)
passes one in 1.22 seconds and its [fresh-target profile](_reset/fresh-cluster-restore-20261024-44.json)
passes six in 11.07 seconds. These runs retain 206 stable Python hashes.

A new [installed profile](_reset/public-slots-installed-batched-application-20261024.json)
passes one original SQLModel application journey in 2.91 seconds with 207 stable
Python hashes. Its [application receipt](_reset/public-slots-installed-batched-original-application-20261024.json)
keeps six pinned files unchanged. One batched conversion protects `full_name`
VARCHAR, `email` search/uniqueness and `is_active` Boolean. Native User/Item table
OIDs and public attnums/order remain intact. Exact staged CF1 bytes reach each
public field at cutover. Original CRUD, search, Boolean values, latest-value
removal, native catalogs and an import-denied restart pass. Email equality/uniqueness
uses opaque fixture identities in explicit single tenancy. Production email-domain
admission remains UNKNOWN. This profile adds
no HTTP or fresh-adoption qualification. The ordinary HTTP regression retains
its separate 26-file/default-layout boundary. Only this profile file is new
after the earlier 206-file snapshots.

The installed v6 profile uses VARCHAR without sequences. Its
[export](_reset/fresh-cluster-export-20261024-46.json) passes one test in 1.01 seconds.
[Six target tests](_reset/fresh-cluster-restore-20261024-45.json) pass in 10.01 seconds.
The legacy lock/v5 and restore/v2 sequence profile passes one
[export](_reset/fresh-cluster-export-20261024-47.json) in 0.91 seconds and
[four target tests](_reset/fresh-cluster-restore-20261024-46.json) in 7.15 seconds.
The original SQLModel application also passes its direct-search journey. Its
[export](_reset/fresh-cluster-export-20261024-48.json) and
[target](_reset/fresh-cluster-restore-20261024-47.json) stages each pass one test
in 1.10 and 2.88 seconds. The [application receipt](_reset/public-slots-installed-legacy-direct-application-20261024.json)
keeps the default legacy layout and restore/v1 scope, with six unchanged files.
All 207 Python hashes remain stable at `6cb926e`.

The [final full source regression](_reset/public-slots-source-full-20261024.json)
passes 2,503 tests and 116 subtests in 851.39 seconds, with 16 skips and
49 known warnings. Two test calls and 14 collection skips account for the skips.
All 207 Python hashes remain stable at `6cb926e`. The installed
294-test and three-field application profiles keep their separate recorded boundaries.
The [final boundary](_reset/public-slots-final-boundary-20261024.json) binds 17 current
receipts, four historical receipts, four application receipts and seven documents.
The original three-field journey remained unverified at that checkpoint. Its
[later application evidence](#original-three-field-sqlmodel-fresh-adoption-2026-10-24)
has a separate test-only boundary.
All seven production gates remain UNKNOWN. See the
[lifecycle contract](lifecycle.md#public-column-slot-layout-2026-10-24) and
[format decision](decisions.md#original-slot-layout-and-restore-authority-2026-10-24).

## Native column identity oracle: 2026-10-24

**VERIFIED, native-only decision support:** one PostgreSQL 16
[profile](_reset/column-identity-native-20261024.json) passes in 0.50 seconds
with 202 stable Python hashes. It uses fixed public CF1-like bytes, without
product encryption or authentication. No product layout changes.

Native ALTER TYPE USING a staged column preserves original public attnums and
column order through both directions, including the existing gap at slot 3.
The relation OID stays unchanged, but heap relfilenodes change. The primary
index retains its OID with a changed relfilenode. Rebuilt native indexes,
constraints and extended statistics retain exact logical definitions with new OIDs.
The sequence retains its OID, ownership attnum, ACL, configuration and native counter behavior.

The profile also passes real post-ALTER rollback, a separate runtime read
refusal with SQLSTATE 55P03, frame CHECK refusal 23514, native uniqueness 23505
and VARCHAR assignment refusal 22001. Comments, statistics target 500, options
and column ACL survive the bytea conversion. Storage EXTERNAL and compression
pglz become EXTENDED and the default compression policy. Reverse restores both explicitly.

The [observations](_reset/column-identity-native-observations-20261024.json) cover
one local three-row table. They qualify no pause, throughput, WAL or production
cost target. Measured forward/reverse ALTER times are 8.003/5.424 milliseconds.
Whole-protocol times are 21.772/15.560 milliseconds. At that checkpoint, product
layout selection and restored-slot authority remained unimplemented. Its later
[product extension](#public-column-slot-preservation-2026-10-24) has a separate
verification boundary. The [layout evaluation](_reset/layout-evaluation-20261019.md#native-original-slot-oracle-2026-10-24)
records this alternative. All seven production gates remain UNKNOWN.
The [boundary](_reset/column-identity-native-final-boundary-20261024.json) binds the
profile, observations, four documents and 36 unchanged product modules.
The [design inputs](decisions.md#column-preserving-conversion-design-inputs-2026-10-24)
describe the proposed explicit layout and restored-slot mapping.

## Owned-sequence preservation and restore: 2026-10-24

**VERIFIED, bounded revised source and installed profiles:** lock/v5 records ordinary persistent
sequences automatically owned by protected columns. Forward and reverse switches
preserve each sequence's OID, owner, configuration, comment and effective ACL,
including grantor and grant option. They detach and reattach ownership inside
the existing transaction. Checks repeat after native ALTER locking and before
column replacement. Counter values remain native, including rollback gaps and
unused cache reservations. Cryptalis never recreates or resets the sequence.

The [focused source receipt](_reset/owned-sequences-source-focused-20261024.json)
passes 81 controls: 18 native sequence cases and 63 compiler cases. At that
checkpoint, all 201 recorded Python hashes stay stable and match its worktree. Exact admitted
`_cryptalis_*` sequences survive removal. Unrecorded objects, changed identities
and unsupported dependencies still refuse. Reverse planning and paused progress
check the current mapped inventory before provider work or new effects.

Sequence-bearing adoption uses restore/v2 with complete source-to-target OID
mapping after exact logical catalog comparison. The [source export](_reset/fresh-cluster-export-20261024-37.json)
passes one test in 1.01 seconds. The [fresh-target profile](_reset/fresh-cluster-restore-20261024-36.json)
passes four in 7.32 seconds with the same 201 stable Python hashes at that checkpoint. It covers
inherited root/payload lineage, current-value native exit, direct payload/search
planning and a second adoption with two restore/v2 maps. The actual previous
installed reader refuses v5 sources and restore/v2 bindings before database access.

The [initial artifact check](_reset/owned-sequences-release-final-20261024.json) passes
reproducible archives, metadata, SBOM, CLI and 40 installed-file checks.
All 41 release-source hashes match its worktree at that checkpoint. Its wheel contains 36 product
modules. Existing artifacts without owned sequences retain their earlier formats
and bytes.

The [first full source run](_reset/owned-sequences-source-full-20261024.json)
reports 19 failed, 2,459 passed, 15 skipped and 116 passed subtests in
845.50 seconds, with 49 warnings. All failures concern read-only statement
assertions: sequence inspection starts with WITH, while these controls require
SELECT or SET. The revised compiler query starts with SELECT and retains the
assertions. The earlier focused,
fresh-cluster and artifact receipts retain their exact source boundary. They
do not qualify the revised query or a new installed wheel.

The [revised source controls](_reset/owned-sequences-source-readonly-recovery-20261024.json)
pass 201 tests in 97.72 seconds. They cover all five failed modules plus the
18 native sequence and 63 compiler cases. The read-only assertions remain
unchanged. At that checkpoint, all 201 Python hashes stay stable and match its worktree.
The [revised artifact check](_reset/owned-sequences-release-revised-20261024.json)
passes reproducible archives, CLI and 40 installed files against its 41 recorded
source hashes and 36 product modules. The initial candidate remains historical.

The revised [source export](_reset/fresh-cluster-export-20261024-38.json) passes
one test in 1.00 second. Its [fresh-target profile](_reset/fresh-cluster-restore-20261024-37.json)
passes four in 9.84 seconds. The revised wheel passes
[269 affected/application controls](_reset/owned-sequences-installed-affected-20261024.json)
in 157.98 seconds with one known warning. The ordinary
[searchable](_reset/owned-sequences-installed-searchable-application-20261024.json)
and [HTTP/JWT/SMTP](_reset/owned-sequences-installed-http-application-20261024.json)
application receipts preserve their separate six-file and 26-file boundaries.
Its installed [export](_reset/fresh-cluster-export-20261024-39.json) passes
one in 1.01 seconds and its [fresh-target profile](_reset/fresh-cluster-restore-20261024-38.json)
passes four in 8.64 seconds. All runs retain the same 201 stable Python hashes.

The original six-file SQLModel application also passes both installed adoption
paths. Direct-generation [export](_reset/fresh-cluster-export-20261024-40.json)
and [target](_reset/fresh-cluster-restore-20261024-39.json) stages pass one each
in 1.29 and 2.34 seconds. Rewrap-first [export](_reset/fresh-cluster-export-20261024-41.json)
and [target](_reset/fresh-cluster-restore-20261024-40.json) stages pass one each
in 1.54 and 3.07 seconds. Their [direct](_reset/owned-sequences-installed-direct-adoption-application-20261024.json)
and [legacy](_reset/owned-sequences-installed-legacy-adoption-application-20261024.json)
application receipts retain original search controls, frame/index identities,
native catalogs and latest-value package-free exit. These are ordinary application
regressions, separate from the sequence-bearing four-case profile.

The [revised full source regression](_reset/owned-sequences-source-full-revised-20261024.json)
passes 2,478 tests and 116 subtests in 824.22 seconds, with 15 skips and
49 known warnings. The skips comprise two test calls and 13 collection skips.
At that checkpoint, all 201 Python hashes remain stable and match its worktree. This source run
includes the pinned original SQLModel CRUD and HTTP profiles. Installed-wheel
evidence retains its separate boundary. The
[final boundary](_reset/owned-sequences-final-boundary-20261024.json) binds current
receipts, artifacts, application evidence and seven canonical documents. It also
retains earlier failed runs and the initial artifact as historical evidence.

Existing generated-key and protected-default
refusals remain unchanged. This checkpoint changes no CF1, tenant, key-policy or
host-authority contract. All seven production gates remain UNKNOWN. See the
[lifecycle contract](lifecycle.md#owned-sequence-preservation-and-restored-identity-2026-10-24)
and [format decision](decisions.md#owned-sequence-metadata-and-restored-identity-2026-10-24).

## Direct restore-binding generation planning: 2026-10-24

**VERIFIED, bounded source and installed-wheel profiles:** payload and search planners now
accept an explicit existing restore binding with the original source and ACTIVE
pin. The exact purpose/v2 proposal embeds that binding. No-binding proposals
remain v1, including sources with inherited lineage. Activation retains v6/v7
formats and appends flat restore lineage. Original source identity and journal
authority remain distinct from the evaluated physical target.

The [expanded source export](_reset/fresh-cluster-export-20261024-31.json) passes
one test in 1.07 seconds. All [19 fresh-target controls](_reset/fresh-cluster-restore-20261024-30.json)
pass in 50.18 seconds. At that checkpoint, 199 stable Python hashes match its files.
Changed restored CHECKs and disabled staged guards refuse before provider
resolution. Source-only cancellation, keyless CLI status, SIGKILL recovery and
a lost actual cutover COMMIT reply pass. A second genuine backup/restore
adoption retains two flat bindings and rotates the other generation.

The [source VARCHAR profile](_reset/fresh-cluster-restore-20261024-31.json)
passes all 19 in 50.57 seconds. The [source affected suite](_reset/direct-generation-source-affected-20261024.json)
passes 606 tests in 271.60 seconds. The [installed affected suite](_reset/direct-generation-installed-affected-20261024.json)
passes 68 in 58.71 seconds with one existing Starlette warning. At that checkpoint,
all 199 Python hashes stay stable and match its files.
The ordinary [searchable SQLModel](_reset/direct-generation-installed-searchable-application-20261024.json)
and [HTTP/JWT/SMTP](_reset/direct-generation-installed-http-application-20261024.json)
receipts preserve six and 26 pinned files. These regressions do not qualify the
new direct-binding application journey.

The [installed TEXT direct-generation profile](_reset/fresh-cluster-restore-20261024-32.json)
passes all 19 in 50.17 seconds after its [source export](_reset/fresh-cluster-export-20261024-33.json).
The original six-file SQLModel application also completes direct restore-binding
search rotation without an intermediate rewrap. Its installed
[export](_reset/fresh-cluster-export-20261024-34.json) and
[fresh-target](_reset/fresh-cluster-restore-20261024-33.json) stages each pass
one test in 1.19 and 2.35 seconds. Its source [export](_reset/fresh-cluster-export-20261024-35.json)
and [fresh-target](_reset/fresh-cluster-restore-20261024-34.json) stages each
pass one in 1.36 and 2.54 seconds. The [direct source](_reset/direct-generation-direct-source-application-20261024.json)
and [direct installed](_reset/direct-generation-direct-installed-application-20261024.json)
application receipts preserve original CRUD, storage frames, index identities,
native catalog restoration and latest-value package-free exit.

A separate installed legacy [export](_reset/fresh-cluster-export-20261024-36.json)
and [fresh-target](_reset/fresh-cluster-restore-20261024-35.json) each pass one
in 1.27 and 2.51 seconds. Its [application receipt](_reset/direct-generation-legacy-installed-application-20261024.json)
retains the original intermediate root rewrap. Email equality/IN/uniqueness
remains fixture-only in explicit single tenancy. The ordinary HTTP/JWT/SMTP
profile keeps its separate boundary. All 199 Python hashes remain stable at that checkpoint.

The first [source export](_reset/fresh-cluster-export-20261024-30.json) passes
one test in 1.12 seconds. Both [native positive cases](_reset/fresh-cluster-restore-20261024-29.json)
pass in 3.97 seconds with 199 stable Python hashes. The
[previous installed wheel](_reset/fresh-cluster-restore-20261024-28.json)
reproduces two missing-restore-keyword failures. This does
not establish a new full regression result.

The [artifact check](_reset/direct-generation-release-final-20261024.json) verifies
reproducible archives, metadata, RECORD, SBOM, 40 installed files and CLI.
The [final boundary](_reset/direct-generation-final-boundary-20261024.json) binds
the runs, application receipts and seven canonical docs recorded at that checkpoint. Production
email populations, browser and deployment qualification remain open or UNKNOWN.
Old readers reject v2 proposals and accept unchanged v6/v7 activation formats.
Crypto, provider, host-authority and retained-key contracts do not change.
All seven production gates remain UNKNOWN.
See the [format decision](decisions.md#direct-restore-binding-generation-planning-2026-10-24).

## Original searchable SQLModel adoption: 2026-10-24

**VERIFIED, bounded source and installed-wheel journey:** the pinned SQLModel
template retains six captured files without model or query edits. After a genuine
PostgreSQL 16 backup restore, the journey adopts the target, publishes root
rewrap v5, then search rotation v7. Original CRUD passes email equality,
IN/empty IN, ignored IN NULL, Unicode, native 23505 rollback and a two-transaction
unique winner. Later email edits survive removal and an import-denied native restart.

User.full_name storage frames and all native index identities remain exact
through search rotation. The final native catalog matches its original state.
An unadopted source and the stale original binding after successor publication
both refuse. The [source application receipt](_reset/searchable-adoption-source-application-20261024.json)
and [installed application receipt](_reset/searchable-adoption-installed-application-20261024.json)
retain the six pinned files.

The final [source export](_reset/fresh-cluster-export-20261024-28.json) and
[fresh-target run](_reset/fresh-cluster-restore-20261024-27.json) each pass one
test in 1.52 and 2.45 seconds. The installed [export](_reset/fresh-cluster-export-20261024-27.json)
and [fresh-target](_reset/fresh-cluster-restore-20261024-26.json) stages each
pass one in 1.37 and 2.11 seconds. At that checkpoint, all 198 Python hashes stayed
stable and matched its source files. The [initial source receipt](_reset/searchable-adoption-initial-source-application-20261024.json)
precedes the explicit SQLModel 0.0.48 fixture guard and remains historical.

At that checkpoint, all 36 product modules and 40 installed files retained the
exact earlier wheel bytes. Earlier full regression and build evidence keep their
recorded boundaries. That test-only slice added no product behavior or full-suite run. The
[final boundary](_reset/searchable-adoption-final-boundary-20261024.json) binds
the tests, unchanged artifact and application receipts recorded at that checkpoint.

The profile accepts fixture-only email equality/uniqueness leakage in explicit
single tenancy. Production email-domain admission and external custody remain
UNKNOWN. The HTTP/JWT/SMTP profile keeps its separate boundary. Browser and
deployment qualification remain open. At this checkpoint, direct restore-binding
generation planning stayed unadmitted. Its later
[extension](#direct-restore-binding-generation-planning-2026-10-24) records the
separate implementation and verification boundary. All seven production gates remain UNKNOWN.

## Search rotation after adopted lineage: 2026-10-24

**VERIFIED, bounded native and installed-wheel profiles:** search rotation now accepts an ACTIVE
lineage-bearing successor. Its unchanged search-rotation/v1 proposal embeds the
source. Transition/v7 retains every v4 search proof and the flat restore lineage.
The genuine fresh-target workflow passes committed-prefix resume,
target-only PENDING retry, equality/IN/NULL, native uniqueness/rollback and a
two-transaction winner. Searchable terms change while storage-only label bytes,
payload selection and native index identities remain unchanged. Later rewrap to
v5, payload rotation to v6 and latest-value package-free exit also pass.

The [expanded source export](_reset/fresh-cluster-export-20261024-21.json) passes
one test in 1.06 seconds. All [11 fresh-target controls](_reset/fresh-cluster-restore-20261024-20.json)
pass in 30.42 seconds with 196 stable Python hashes. They include five fault
controls, native collision rollback, SIGKILL with fresh-process status/resume,
and a lost actual cutover COMMIT reply with target-only retry. Direct v7-to-v6
and v7-to-v5-to-v6 paths pass. Older installed readers refuse before database access.

The [source VARCHAR profile](_reset/fresh-cluster-restore-20261024-21.json) passes
the same 11 controls in 28.59 seconds. The [source affected suite](_reset/adopted-search-source-affected-20261024.json)
passes 496 tests in 268.01 seconds. The [installed affected suite](_reset/adopted-search-installed-affected-20261024.json)
passes 68 in 58.10 seconds with one existing Starlette warning. All 196 Python
hashes stayed stable and matched the source at that checkpoint.
The installed [searchable SQLModel](_reset/adopted-search-installed-searchable-application-20261024.json)
and [original HTTP/JWT/SMTP](_reset/adopted-search-installed-http-application-20261024.json)
receipts preserve six and 26 pinned files respectively. These are ordinary
application regressions; they do not verify search rotation after SQLModel adoption.
The later [original searchable journey](#original-searchable-sqlmodel-adoption-2026-10-24)
supplies that separate bounded application evidence.

The final [installed TEXT search profile](_reset/fresh-cluster-restore-20261024-22.json)
passes all 11 controls in 29.56 seconds after its [source export](_reset/fresh-cluster-export-20261024-23.json).
The same wheel passes [17 adopted root-rewrap controls](_reset/fresh-cluster-restore-20261024-23.json)
in 24.40 seconds. Both retain 196 stable Python hashes.

The same installed wheel repeats the unchanged Smolink journey: its
[source stage](_reset/fresh-cluster-export-20261024-25.json) passes one test in
3.36 seconds and its [fresh-target stage](_reset/fresh-cluster-restore-20261024-24.json)
passes one in 4.02 seconds. The [application receipt](_reset/adopted-search-installed-smolink-application-20261024.json)
preserves all 38 pinned files and verifies adopted root/payload rotation,
ASGI/JWT/ORM and real Redis work, latest-value removal and an import-denied restart.
Url.destination remains storage-only. This repeats root/payload compatibility;
it supplies no adopted-search application evidence.

The [initial source export](_reset/fresh-cluster-export-20261024-20.json) passes
one test in 0.73 seconds; the [fresh-target workflow](_reset/fresh-cluster-restore-20261024-19.json)
passes one in 3.05 seconds. Both retain 196 stable Python hashes.
The [previous installed wheel](_reset/fresh-cluster-restore-20261024-18.json)
reproduces `adopted_generation_rotation_unsupported`. The earlier
[fixture index-assertion failure](_reset/fresh-cluster-restore-20261024-17.json)
remains recorded. The earlier 2,430-test
full regression belongs to the payload checkpoint below.

The [artifact check](_reset/adopted-search-release-final-20261024.json) verifies
repeatable archives, metadata, RECORD, SBOM, clean installed files and CLI.
The [final boundary](_reset/adopted-search-final-boundary-20261024.json) binds
these runs, both installed environments, application sources and seven canonical docs.
It does not establish an installed adopted-application journey. Direct
restore-binding generation planning, external custody and host authority remain
unadmitted or unqualified. All seven production gates remain UNKNOWN. See the
[format decision](decisions.md#adopted-target-search-rotation-2026-10-24).
The later [direct-binding extension](#direct-restore-binding-generation-planning-2026-10-24)
records its separate proposal API and current verification boundary.

## Payload rotation after adopted lineage: 2026-10-24

**VERIFIED, bounded local source and installed-wheel profiles:** payload rotation can now start from
an ACTIVE adopted rewrap successor. The existing payload-rotation/v1 proposal
retains its complete source. A transition/v6 activation keeps the approved flat
restore lineage and every existing payload proof. Ordinary v3 activation and CF1
remain unchanged. A later root rewrap returns to v5 with the same lineage.
Direct and embedded fractional copy-rate artifacts round-trip.

The [source export](_reset/fresh-cluster-export-20261024-12.json) and
[12 fresh-target controls](_reset/fresh-cluster-restore-20261024-11.json) pass;
the latter takes 30.16 seconds. Checks cover one committed chunk and resume,
source-only cancellation, terminal retry after later edits, prior canceled
operations, stale pins/policies, provider outage, changed CHECK/fence, retained
generation frames and resealed targets. SIGKILL and lost actual chunk/abort
COMMIT replies recover through the same artifacts. Actual older installed
readers refuse both proposal and activation before database access.

The [source VARCHAR profile](_reset/fresh-cluster-restore-20261024-13.json)
passes the same 12 controls in 29.77 seconds. The [actual installed TEXT wheel](_reset/fresh-cluster-restore-20261024-14.json)
passes all 12 in 28.48 seconds. The installed wheel also passes the existing
[17 adopted root-rewrap controls](_reset/fresh-cluster-restore-20261024-15.json)
in 24.85 seconds.

The [unchanged Smolink source journey](_reset/fresh-cluster-restore-20261024-12.json)
passes in 4.20 seconds after its [source stage](_reset/fresh-cluster-export-20261024-13.json).
After restore, canceled/new root rewrap and v5 publication, payload rotation
advances generation 2 to 3 in v6. All three original wrapped contexts remain;
one independent payload context is added. Original ASGI/JWT/ORM and real Redis
work, later edits, removal and an import-denied restart pass. Physical index
identities stay unchanged while payload bytes change.

The final installed wheel repeats the original Smolink journey: its
[source stage](_reset/fresh-cluster-export-20261024-17.json) passes one test in
2.62 seconds and its [fresh-target stage](_reset/fresh-cluster-restore-20261024-16.json)
passes one in 3.23 seconds. The [source application receipt](_reset/adopted-payload-smolink-source-application-20261024.json)
and [installed application receipt](_reset/adopted-payload-smolink-installed-application-20261024.json)
retain all 38 pinned application files without model or query changes.

The [previous installed wheel](_reset/fresh-cluster-restore-20261024-8.json)
reproduces the original refusal. The [expanded failed run](_reset/fresh-cluster-restore-20261024-10.json)
retains 11 passes and one fixture recovery failure. Ordinary ENABLE had not
restored the recorded ALWAYS trigger mode. That partial repair now receives an
explicit refusal assertion before exact-mode recovery.

The [full primary regression](_reset/adopted-payload-full-primary-20261024.json)
passes 2,430 tests plus 18 subtests in 730.38 seconds. Twelve skips and 48 existing
deprecation warnings remain. The [actual installed affected suite](_reset/adopted-payload-installed-affected-20261024.json)
passes 126 controls in 86.62 seconds, including ordinary payload, lease,
SQLModel HTTP/SMTP and tenant-pool checks. All 195 Python hashes remain unchanged
across the listed runs.
The [artifact check](_reset/adopted-payload-release-final-20261024.json) verifies
repeatable archives, metadata, RECORD, SBOM, 40 installed files and isolated CLI.
The [final boundary](_reset/adopted-payload-final-boundary-20261024.json) binds
these receipts to the product and installed artifacts recorded at that checkpoint.
Smolink protection remains limited to Url.destination storage under explicit
single tenancy. Browser and server deployment remain unqualified.
At this checkpoint, adopted search rotation remained unadmitted. The later
[search extension](#search-rotation-after-adopted-lineage-2026-10-24) records its
bounded native and installed verification. Direct restore-binding generation planning remains
unadmitted. Host authority, provider qualification and all seven gates remain UNKNOWN.
See the [format decision](decisions.md#adopted-target-payload-rotation-2026-10-24).

## Smolink adopted-target rewrap journey: 2026-10-24

**VERIFIED, bounded installed-wheel journey:** pinned Smolink retains all 38
original application Python files. The source stage completes committed-process
interruption/resume, root rewrap and payload rotation. After a genuine fresh
PostgreSQL 16 restore and adoption, root-rewrap cancellation succeeds without a
target provider. A new rewrap publishes its own transition/v5 successor. The
original [async HTTP/ASGI and ORM workload](../tests/smolink_workload.py) checks
valid/invalid access JWTs, validation, conflicts and Redis rate limits. A later
edit survives decrypt-back, removal and an original application restart with
Cryptalis imports denied.

Cancellation and successful rewrap preserve exact payload bytes and every native
index OID and relfilenode. All three retained contexts and selected payload
generation 2 remain unchanged. The [source export](_reset/fresh-cluster-export-20261024-8.json)
passes one test in 3.61 seconds; the [fresh-target run](_reset/fresh-cluster-restore-20261024-7.json)
passes one in 3.37 seconds. Both retain 194 stable Python hashes. The
[application receipt](_reset/smolink-adopted-journey-application-20261024.json)
records the unchanged sources and complete journey. The
[final boundary](_reset/smolink-adopted-final-boundary-20261024.json) binds both
runs, all 40 installed files and the reused product/build evidence.

This uses the actual installed wheel on Python 3.13.12 without a Cryptalis source
fallback. Product bytes remain unchanged from fcbca39; the earlier full regression
and build retain their recorded boundaries. Protection covers only Url.destination
storage under explicit single tenancy, with public query routes and local fixture
custody. Browser, server deployment, encrypted search and external provider
qualification remain outside this profile. All seven production gates remain UNKNOWN.

## Adopted-target root rewrap: 2026-10-24

**VERIFIED, bounded local PostgreSQL 16 profiles:** root rewrap now accepts the
original ACTIVE plan, pin and explicit restore binding after genuine database
restore and adoption. Rewrap/v2 records that binding. The transition/v5 successor
uses the adopted target and retains flat, ordered restore lineage. Repeated
rewrap preserves that lineage and the existing CF1 frames and search index.
Ordinary rewrap/v1 and transition/v2 artifacts retain their formats.

The [expanded source run](_reset/fresh-cluster-restore-20261024-4.json) passes
17 controls in 25.17 seconds, after the [source export](_reset/fresh-cluster-export-20261024-5.json).
The [native VARCHAR profile](_reset/fresh-cluster-restore-20261024-5.json) passes
the same 17 in 24.59 seconds. The [actual installed wheel](_reset/fresh-cluster-restore-20261024-6.json)
passes all 17 TEXT controls in 25.10 seconds on Python 3.13.12.
Controls cover missing probes, wrong binding/pin/target/custody, wrong roots,
unselected generations, authentication failure, PENDING retries and cancellation.
Failed cancellation after the actual guard drop rolls back its source-state
change and fence removal. SIGKILL and lost actual COMMIT replies recover from
the same disk artifacts. Terminal cancellation retries preserve later edits,
including a source-only fresh process without target custody.

The complete chain performs repeated rewrap, another real pg_dump/restore into
a distinct database, new adoption with inherited CHECK forms, another rewrap,
current-value edits, decrypt-back and removal. A fresh import-denied process
then reads the latest values and performs native search and CRUD.

The [previous installed wheel](_reset/fresh-cluster-restore-20261024.json)
reproduces the missing API in three controls. The [expanded RED](_reset/fresh-cluster-restore-20261024-3.json)
records 15 passes and two failures. One exposes inconsistent custody metadata
that now refuses against the original source policies before provider work.
The other records a test fixture reusing an attached engine; the fixture now
uses a fresh engine. The earlier adapter variable failure is also
[retained](_reset/fresh-cluster-export-20261024-2.json).

The [full primary regression](_reset/adopted-rewrap-full-primary-20261024.json)
passes 2,430 tests plus 18 subtests in 729.16 seconds. Eleven skips and 48 existing
deprecation warnings remain. All 194 Python hashes stay unchanged across the
full run and the final fresh-target runs. The
[actual installed affected suite](_reset/adopted-rewrap-installed-affected-20261024.json)
passes 103 controls in 71.84 seconds, including root-rewrap/restore controls,
tenant pool isolation and the unchanged SQLModel HTTP/JWT/SMTP journey through
current-value removal and an import-denied restart. One existing application
deprecation warning remains. The [final boundary](_reset/adopted-rewrap-final-boundary-20261024.json)
binds these receipts, unchanged cryptographic modules, packaged sources and docs.
The [artifact check](_reset/adopted-rewrap-release-final-20261024.json) verifies
repeatable wheel/sdist builds, metadata, RECORD, SBOM, 40 installed files and
isolated CLI execution. Host custody, fencing, quarantine and publication remain
external assertions. At this root-rewrap checkpoint, payload/search rotation on
adopted lineage refused before database or key effects. The later
[payload extension](#payload-rotation-after-adopted-lineage-2026-10-24) supplies
the separate verified payload path. Search rotation with lineage and all seven
production gates remain open or UNKNOWN. See the
[format decision](decisions.md#adopted-target-root-rewrap-2026-10-24).

## Bounded session pool isolation: 2026-10-24

**VERIFIED, local correctness profile:** independent sync Sessions and async
tasks pass matching native/attached work at 1, 4 and 16 scheduled workers.
They share a four-connection pool. Each worker owns its Sessions and row.
Two tenant policies exist before the real protection plan and ACTIVE transition.
Checks cover typed projections, refresh, explicit opposite-tenant zero matches,
rollback, latest committed values and fresh-session reads. An independent decoder
checks the stored frames against each expected tenant and record.

Both modes record native/attached checkout peaks of 1, 4 and 4 for the three
worker counts. This proves observed overlap up to four connections. It does
not establish 16 simultaneous transactions or system saturation.

A separate one-connection profile observes PostgreSQL PgSleep before canceling
a writer with a flushed, uncommitted row. Another tenant already waits for the
pool. It then commits the same primary key, reads its authenticated value and
releases the connection. Both tenants retain healthy later reads and writes.
This proves rollback and observed pooled recovery in that local cell.

The [source run](_reset/session-isolation-native-first-20261024.json) passes
13 controls in 5.81 seconds. The [actual installed wheel](_reset/session-isolation-installed-20261024.json)
passes the same 13 in 6.05 seconds. Both retain 193 unchanged Python hashes.
JUnit preserves the [source pool measurements](_reset/session-isolation-native-first-20261024.xml)
and [installed measurements](_reset/session-isolation-installed-20261024.xml).
Product bytes remain unchanged from 8a799fe. The [final boundary](_reset/session-isolation-final-boundary-v2-20261024.json)
binds the existing wheel, packaged sources, installed files and new evidence.
The earlier full regression remains evidence for its recorded revision. This
slice runs affected controls only. Multiprocessing, saturation, latency/resource
budgets, shared-Session safety and remote-provider cancellation remain unqualified.
All seven production gates remain UNKNOWN.

## Original SQLModel HTTP journey: 2026-10-24

**IMPLEMENTED, bounded local verification:** the unchanged pinned FastAPI
full-stack template 0.10.0 now passes its original HTTP authentication and
user/item routes with encrypted User.email, full_name and is_active. All
26 captured application, template, license and dependency files retain their
pinned hashes. The fixture accepts email equality/uniqueness leakage for opaque
UUID128 addresses in explicit single tenancy. This does not qualify real email
populations or broader deployment policies.

The first authenticated request exposed UUID text rejection in Session.get.
Expected-context normalization now preserves the original SQL bind and ORM
identity key. Native and attached sync/async checks preserve alternate UUID
spellings, cache hits, malformed-input SQLSTATEs and rollback. Invalid points
cannot authorize authenticated output or outer-join NULLs. A second failure in
the original administrator route exposed refusal of unprotected Item DELETE.
The new finite mapped DELETE path retains native synchronization, row counts
and transactions. It freezes physical metadata and predicates before callbacks
and repeats checks through final driver dispatch. Custom AST and protected-table
aliases still refuse before SQL.

The [120 focused controls](_reset/http-uuid-delete-physical-final-20261024.json)
pass in 24.43 seconds. The [original HTTP journey](_reset/sqlmodel-http-complete-journey-physical-final-20261024.json)
passes in 6.10 seconds. It covers signup, real password/JWT authentication,
account state, ownership and administrator refusals, current-value updates and
item cleanup. Both native and attached phases deliver four real MIME messages
to localhost SMTP. The delivered reset token changes the password through the
original route. Invalid and expired tokens refuse. Deprotection and removal
preserve current credentials and inactive False values. A fresh process runs
the original HTTP journey with Cryptalis imports denied.

A later compiler check reproduced three metadata faults after initial admission.
An annotated column could change its effective name or table while deannotation
still identified the original column. A direct column.table change also escaped
the snapshot. The [native RED](_reset/unprotected-delete-annotated-metadata-red-20261024.json) retains all three failures. The [stopped full run](_reset/sqlmodel-http-full-primary-20261024.json)
records 1,137 passes and 18 passing subtests with exit 2. It is incomplete
verification. Effective annotated metadata and original table ownership now
receive explicit checks before deannotation can establish authority.

The [application receipt](_reset/sqlmodel-http-journey-application-physical-final-20261024.json)
records the source hashes, runtime versions, route controls and removal result.
The [UUID failure](_reset/sqlmodel-http-auth-red-20261023.json) and
[Item DELETE failure](_reset/sqlmodel-http-full-journey-first-20261024.json)
remain evidence. TestClient ASGI and local SMTP do not qualify a browser,
external mail delivery, HTML escaping, application startup or deployment.
All seven production gates remain UNKNOWN.

The [final full primary regression](_reset/sqlmodel-http-full-primary-final-20261024.json)
passes 2,422 tests plus 18 subtests in 727.17 seconds. Ten skips and 48 existing
deprecation warnings remain. All 191 Python hashes stay unchanged. The first
stricter metadata check also refused six existing DELETE controls. The
[retained failure](_reset/http-uuid-delete-annotated-final-20261024.json) led to
native identifier equivalence checks, which pass with the final affected suite.

Repeat wheel/sdist builds, metadata, RECORD, SBOM and installed CLI checks pass.
The [actual installed wheel](_reset/sqlmodel-http-installed-wrapper-20261024.json)
passes 134 controls in 43.80 seconds, including the full original HTTP/local
SMTP journey and existing SQLModel profiles. All 36 product modules match
current source. All 40 installed files match the wheel before and after.
The wheel SHA-256 is
`b76f3d67305af12eb15b65a45d6d1bdb5bb2bf54601544914d30528748f63956`.
The [installed environment](_reset/sqlmodel-http-installed-environment-20261024.json)
uses Python 3.13.12, binary psycopg and exact core pins. The primary source
suite uses Python 3.12.3 and the same exact core dependency pins. The [final boundary](_reset/sqlmodel-http-final-boundary-20261024.json)
binds source, artifacts, receipts and verification limits. All seven production
gates remain UNKNOWN.

## Boolean storage checkpoint: 2026-10-23

**IMPLEMENTED, bounded local verification:** native Boolean storage uses
`cryptalis.context/v2`, `boolean-u8/v1` and lock/v4. False encodes as byte 00.
True encodes as byte 01. SQL NULL stays SQL NULL. The shared CF1 path
authenticates before decoding. Existing text vectors and descriptors stay unchanged.
Boolean search remains unadmitted under the small-domain policy.

The [164 focused controls](_reset/boolean-native-final-boundary-20261023.json)
pass native sync/async values, literal client defaults, pending/refresh state,
NULL failures and rollback, dictionary writes, authenticated projections and
custom-converter refusal. Independent vectors cover both Boolean values,
record codecs and tenant contexts. Invalid Boolean diagnostics redact supplied values.
The unchanged SQLModel template passes [both profiles](_reset/boolean-sqlmodel-wrapper-final-20261023.json):
storage-only and mixed searchable email. Both preserve defaults, latest False edits
and a package-free restart.

A mixed two-table, two-tenant fixture passes root rewrap, payload/search rotation,
checkpoint resume and latest-value removal. Rewrap preserves roots, so retained keys
can still decrypt unchanged frames. Old deployment authority refuses validation.
The [fresh-cluster Boolean profile](_reset/fresh-cluster-restore-20261023-25.json) passes protected-backup recovery after payload
rotation, tampered-frame refusal before adoption, a later False edit, removal and
native reading with Cryptalis imports denied. The first restore attempt exposed
a text-only decoded-type restriction. Restore now checks the descriptor's exact type.

The first full primary run retains 40 failures, 2,321 passes and 18 passing subtests.
All failures came from test clocks that still named the old text-only functions.
The corrected clocks retain real post-AEAD expiry injection. All
[43 affected lease controls](_reset/boolean-lease-hook-final-20261023.json) pass.
The [final full regression](_reset/boolean-full-primary-final-20261023.json) passes
2,361 tests plus 18 subtests in 745.62 seconds, with 9 skips and 48 existing
deprecation warnings. No failed run is counted as a pass.

Repeat wheel/sdist builds, metadata, RECORD, SBOM and installed-package CLI checks
pass. The [installed artifact receipt](_reset/boolean-release-installed-20261023.json)
checks 40 installed files. The [actual installed wheel](_reset/boolean-installed-wrapper-20261023.json)
passes 41 controls in 18.06 seconds, including both original SQLModel profiles.
All 36 product modules match the wheel and current source before/after. The
[final boundary](_reset/boolean-final-boundary-20261023.json) binds the receipts and hashes.
Other practical types, advanced queries and all 34 objectives remain required work.
All seven production gates remain UNKNOWN.

## Local research workflow: 2026-10-23

The user-selected free research workflow now uses built-in source discovery,
direct downloads and isolated local Crawl4AI 0.9.5 extraction. HTTP and browser
retrievals of official PostgreSQL documentation pass status/title/passage checks.
Both cached results work in the restricted sandbox. A local JavaScript fixture
and three cache/Markdown controls pass. Paid services and LLM extraction are off.
This changes development tooling only. Runtime dependencies and all production
gates stay unchanged. See the [research setup](research/README.md#local-research-extraction)
and [recorded evidence](_reset/local-research-extraction-20261023.json).

## Installed searchable application integration: 2026-10-23

**VERIFIED, bounded installed package:** the actual current wheel passes the
unchanged searchable SQLModel application through latest-value removal and a
package-free restart. Its native default-collation email search/uniqueness
profile passes once in 2.93 seconds. The pre-adoption CLI passes all 27 controls
in 19.12 seconds. A recorded fixture adapter keeps child processes outside the
source tree so they load the installed package. Assertions and database targets
stay unchanged.

Both original application SDK profiles pass together in 7.39 seconds: synchronous
SQLModel and asynchronous Smolink. Provider expiry/outage, authentication refusal,
recovery and latest-value exit retain their local Stubber boundary. All 36 product
modules and 40 installed files match before/after. All three wrappers retain 174
stable current Python hashes and pass fresh owner/runtime probes.

A new disposable Python 3.13.12 environment uses exact core runtime pins and
SQLModel 0.0.48. Repeat wheel/sdist archives, metadata, RECORD and SBOM checks pass.
The wheel SHA-256 is
`3f89885a25c11915b0a61d92dd3300a82229c7cfceb5371542b6116889c5067d`.
No source Cryptalis path supplies this package. External AWS custody, broader
application coverage and all seven production gates remain UNKNOWN.

The first combined primary full run records 2,321 passed tests, 18 passed
subtests and one failed cleanup control. A function-local fixture model could be
collected before inspection, so the correct schema report was FAIL rather than
the fixture's expected PASS. Explicit garbage collection reproduces
`model_resolution`. Retaining the model in the host module fixes the fixture;
48 affected Doctor controls pass. Product modules remain byte-identical.
The original full failure and deterministic RED remain evidence. The final
serial primary regression passes 2,322 tests plus 18 subtests in 754.32 seconds.
Seven skips and 48 existing deprecation warnings remain. Both fresh role probes
pass and all 174 Python source hashes stay unchanged. The primary environment
has no SQLModel; its optional application evidence remains separate.
See the [final full receipt](_reset/searchable-doctor-integration-full-final-20261023.json).

Evidence: [installed boundary](_reset/searchable-doctor-wheel-final-boundary-20261023.json),
[installed environment](_reset/searchable-doctor-wheel-py313-install-20261023.json),
[release archives](_reset/searchable-doctor-release-20261023.json),
[original full result](_reset/searchable-doctor-integration-full-20261023.json),
[fixture diagnosis](_reset/doctor-cli-fixture-lifetime-boundary-20261023.json),
and [affected Doctor regression](_reset/doctor-cli-fixture-lifetime-green-20261023.json).

## Pre-adoption CLI checkpoint: 2026-10-23

**IMPLEMENTED, bounded verification:** `doctor --pre-adoption` accepts a manifest,
private connection file and explicit trusted `module:factory`. The factory
returns the registry, writer inventory and search-review tuple. The CLI reuses
Python preflight, owns its engine and preserves the existing ACTIVE command.
Compiler inspection is read-only. Host-code effects remain UNKNOWN.

The focused native CLI bundle passes 135 cases. It covers native schema PASS,
actionable schema refusal, safe SQLSTATE/UNKNOWN failure, cleanup/output failures,
redacted host exceptions, mode/input admission before import and Python stream
suppression. Conninfo normalization preserves literal connection values.
Four separate regular-suite Python preflight controls also pass. No optional
application environment is needed for these controls.

The first default-sandbox wrapper attempt stopped at failed probes before tests
or a wrapper receipt. Its cause remains UNKNOWN. No target was substituted.
After explicit user authorization, the scoped same-target rerun passed both fresh
probes and the 135-case bundle. The original offline parser RED remains separate.
No production gate or deployment-wide route/provider claim follows.

Evidence: [CLI regression](_reset/doctor-pre-adoption-cli-first-20261023.json),
[boundary/refinement](_reset/doctor-pre-adoption-cli-boundary-20261023.json),
[stopped attempt](_reset/doctor-pre-adoption-cli-probe-stop-20261023.json),
[original RED](_reset/doctor-pre-adoption-cli-offline-red-20261023.json),
and [regular Python checks](_reset/doctor-preflight-regular-suite-20261023.json).

## Searchable SQLModel application checkpoint: 2026-10-23

**VERIFIED, bounded source cells:** the unchanged official SQLModel template
now protects both `User.full_name` and `User.email`. Its original
`get_user_by_email` works through the native Session API. The journey compares
native/protected equality, IN, empty IN, Unicode values, duplicate SQLSTATE
`23505`, rollback and two-session uniqueness arbitration. A later email edit
survives decrypt-back, removal and a fresh process that denies Cryptalis imports.
All six pinned application source/license records stay unchanged.

The original email column uses native VARCHAR and implicit default collation.
The compiler now admits exact `pg_catalog.default`, provider `d`, with inspected
determinism and an implicit mapping. It retains the existing exact native C
branch. Index collation must match its source. Named shadow collations,
nondeterministic collations, mismatched mappings/indexes and altered serialized
facts still refuse. Existing readers reject these new default-collation search
locks. CF1 bytes, descriptors and text normalization stay unchanged.

Original SQLModel expressions can retain their pre-attachment AutoString bind.
Search admission now reuses the existing exact pinned AutoString recognizer.
Changed hooks, variants, versions and subclasses retain their refusal boundary.
No new query grammar follows.

The final application journey passes once after the concurrency control reuses
the existing barrier pattern. The earlier 18-case application/bridge bundle
and 83-case SQLModel-absent native/search bundle pass at their recorded source
boundaries. The factored storage-only application also passes once.
The admission RED and intermediate two failures remain recorded separately.
Native oracle scan settings do not establish which physical scan path executed.

Search review covers public opaque UUID fixture identities only. This is an
explicit single-tenant application with a native global unique email index;
it supplies no multi-tenant application qualification or production email-domain
review. This profile does not exercise encrypted search rotation, HTTP startup,
authentication endpoints or fresh-cluster recovery. No new full-suite or
installed-wheel result follows. All seven production gates remain UNKNOWN.

Evidence: [journey boundary](_reset/sqlmodel-search-boundary-20261023.json),
[final application](_reset/sqlmodel-search-final-wrapper-20261023.json),
[native/search regression](_reset/sqlmodel-default-collation-plain-search-20261023.json),
[original storage journey](_reset/sqlmodel-search-storage-regression-wrapper-20261023.json),
[primary-source/native evidence](_reset/sqlmodel-default-collation-primary-evidence-20261023.json),
and [admission RED](_reset/sqlmodel-search-admission-red-20261023.json).

The separate unchanged asynchronous Smolink application also passes a local
AWS SDK journey. Exact-expiry outage refuses before SQL, rollback/retry succeeds,
and wrong-root/tag authentication refusals recover. Five async SDK decrypt
operations execute outside the event-loop thread. Original HTTP/Redis CRUD,
latest-value exit and the import-denied child pass. Its 38 application files and
170 Python source hashes remain stable. This uses deterministic local Stubber
responses and supplies no live AWS, IAM, custody or rotation qualification.
See the [async application receipt](_reset/aws-kms-smolink-wrapper-20261023.json)
and [transport boundary](_reset/aws-kms-smolink-transport-20261023.json).

## Manifest-first application recovery checkpoint: 2026-10-23

**VERIFIED, bounded application journeys:** pinned unchanged Smolink now completes
manifest preflight, protection, real process interruption and fresh-cluster recovery.
The source journey kills its worker after committed BACKFILLED progress, resumes
the same plan, then completes root rewrap and payload rotation. Normal protected
HTTP/ORM CRUD uses real Redis before the current database dump.

A genuine fresh PostgreSQL 16 cluster restores that backup and completes
host-bound adoption and ACTIVE Doctor. The original application makes a later
edit, decrypts the latest values, removes Cryptalis and restarts with Cryptalis
imports denied. All 38 pinned application Python files stay unchanged.
Named column attributes, constraints and indexes retain their recorded semantics.
Physical column order remains a separate gap. The storage-only `Url.destination`
profile supplies no new encrypted equality, uniqueness or search-rotation evidence.

The pinned SQLModel template also completes preflight before protection, normal
CRUD, latest-value decrypt-back, removal and a package-free child. Its six pinned
source/license records stay unchanged. Preflight controls cover compatible schema,
invalid tenancy with actionable remedies and a deterministic database outage
that suppresses private exception details.

`cryptalis.doctor.preflight` reuses read-only `compile_protection`. It reads no
application rows and requests no keys. Compatible schema produces
`manifest_schema: PASS`, while overall status and unobserved checks remain UNKNOWN.
Schema refusals return FAIL with codes, locations and remedies. Database
inspection failures retain UNKNOWN. The existing CLI Doctor remains ACTIVE-only.
This helper does not qualify provider access, application query routes or deployment.

Guard observation uses the compiler's existing canonical catalog path, so
legitimate search-path rendering differences no longer change captured facts.
Actual fence changes still refuse. Older paused journals that captured a
noncanonical definition can still refuse. This slice admits no automatic
upgrade or universal resume behavior for those journals. Cryptographic formats,
readers and deployment pins stay unchanged.

Three integrated application runs share 168 stable current Python hashes and
pass both role probes: source export, fresh-cluster recovery and the SQLModel
Doctor/lifecycle profile each pass once. The separate affected guard regression
passes 77 cases. Earlier export and fixture-order failures remain recorded.
The missing-Doctor-module RED and fixture-environment skip remain separate.
The full primary suite retains its earlier revision boundary.

The actual installed wheel repeats both application journeys in a new Python
3.13 environment with exact runtime pins and SQLModel 0.0.48. Smolink source
export passes once in 3.91 seconds, genuine fresh-cluster recovery in 4.77 seconds,
and the SQLModel Doctor/lifecycle profile in 1.80 seconds. All 168 Python hashes
remain stable. All 36 product modules, 40 installed files and the 38/6 pinned
application records match before and after these runs. No source Cryptalis path
supplies the package. The release check verifies repeat archives, CLI and 41
current source hashes. No new full-suite or production result follows.
Authentication endpoints, external key custody and broader application coverage
remain unqualified. All seven production gates remain UNKNOWN.

Evidence: [integrated source export](_reset/fresh-cluster-export-20261023-22.json),
[integrated genuine recovery](_reset/fresh-cluster-restore-20261023-21.json),
[integrated SQLModel Doctor journey](_reset/doctor-recovery-sqlmodel-integration-20261023.json),
[current release](_reset/doctor-recovery-release-20261023.json),
[installed-wheel environment](_reset/doctor-recovery-wheel-py313-install-20261023.json),
[installed-wheel boundary](_reset/doctor-recovery-wheel-py313-boundary-20261023.json),
[installed Smolink export](_reset/fresh-cluster-export-20261023-23.json),
[installed fresh-cluster recovery](_reset/fresh-cluster-restore-20261023-22.json),
[installed SQLModel wrapper](_reset/doctor-recovery-wheel-py313-sqlmodel-wrapper-20261023.json),
[installed SQLModel application](_reset/doctor-recovery-wheel-py313-sqlmodel-application-20261023.json),
[specialist journey](_reset/smolink-fresh-journey-20261023.json),
[specialist boundary](_reset/smolink-fresh-boundary-20261023.json),
[guard regression](_reset/smolink-guard-context-green-20261023.json),
[original fence failure](_reset/fresh-cluster-export-20261023-19.json),
[intermediate fixture failure](_reset/fresh-cluster-restore-20261023-19.json),
[Doctor RED](_reset/pre-adoption-doctor-app-red-20261023.json), and
[separate environment skip](_reset/pre-adoption-doctor-app-setup-skipped-20261023.json).

## Optional SQLModel template checkpoint: 2026-10-23

**IMPLEMENTED, bounded verification:** `cryptalis.sqlmodel.attach` adds an
optional synchronous PostgreSQL bridge for SQLModel 0.0.48. It reuses native
`Session.exec` through the shared guarded Session. The SQLAlchemy entry point
retains its existing Session behavior. Exact stock AutoString mappings normalize
to their native String implementation. Changed hooks, variants and subclasses
remain unadmitted. Top-level SQLModel absence, unsupported version tags and async
attachment refuse with typed failures before database or key work.

The pinned MIT official `full-stack-fastapi-template` 0.10.0 supplies unchanged
models and CRUD at revision `d40de23896d27d15c17a7bf9649123fd167a0aa8`.
Four original application Python files, upstream project metadata and LICENSE
retain their hashes. Only `User.full_name` receives storage-only protection under
explicit single tenancy. Native/protected create, get, update and delete retain
defaults, NULL, Unicode and native scalar/tuple results. Protection, current-value
decrypt-back, removal and a fresh process that denies Cryptalis imports also pass.

The final specialist source passes **ten controls**, including nine bridge
controls and one template lifecycle. Its Python 3.13.12 cell uses SQLModel
0.0.48, Pydantic 2.14.1, SQLAlchemy 2.1.3 and binary psycopg. A separate
SQLAlchemy 2.0.51 profile without SQLModel passes **54 controls**. Both runs
share 163 stable Python hashes and 35 product modules.

The earlier 209-case ordinary SQLAlchemy run predates the final typed optional
follow-up. Its boundary and the original one-failure AutoString admission RED
remain separate. The version-refusal control changes the reported tag on actual
SQLModel 0.0.48. It does not establish an installed older-SQLModel cell.
Setup failures remain separate from successful verification.

**VERIFIED, local primary cell:** the serial full regression passes **2,282 tests
and 18 subtests** in 861.43 seconds. Six skips comprise one test and five
collection skips. Two collection skips cover the absent SQLModel modules.
The primary environment has no SQLModel. All 164 Python hashes stay unchanged,
and both role probes pass. See the [full receipt](_reset/sqlmodel-integration-full-20261023.json).

The application-tested wheel passes repeat-build archives, exact optional metadata,
35-module source comparison, 39 installed-file checks and CLI startup.
Base and optional dependency SBOMs keep separate inventories. Its SHA-256 is
`c35c9cf25c6db9f69fb8e6d10af07405bae0601485671a1d678f534d592ee57c`.
See the [release receipt](_reset/sqlmodel-integration-release-20261023.json) and
[optional SBOM](_reset/sqlmodel-optional-sbom-20261023.json).

The final README refresh changes only wheel METADATA and RECORD.
The final wheel SHA-256 is
`9011200069060814c678734c2bccf955ec1aff9f9a45cc7bdfa3e963f4e9e5f0`.
All 35 product modules remain byte-identical to the application-tested wheel.
Identity and dependency headers stay unchanged. Repeat builds, all 40 current
release hashes, 39 installed-file checks and isolated CLI startup pass.
See the [final release](_reset/sqlmodel-strategy-release-20261023.json) and
[artifact equivalence](_reset/sqlmodel-strategy-artifact-equivalence-20261023.json).

A separate actual-wheel Python 3.13.12 cell with SQLModel 0.0.48 passes **14
controls** in 127.29 seconds. Ten cover the bridge/template and four cover
ordinary sync/async SQLAlchemy behavior with SQLModel installed. Exact base
runtime pins and binary psycopg come from the new site. Application/test
dependencies use a read-only fallback. All 39 checked wheel files, 35 product
modules and six pinned application sources match before and after. Its wrapper
retains 164 stable Python hashes. See the
[installation](_reset/sqlmodel-wheel-py313-install-20261023.json),
[application](_reset/sqlmodel-wheel-py313-application-20261023.json),
[wrapper](_reset/sqlmodel-wheel-py313-wrapper-20261023.json), and
[exact boundary](_reset/sqlmodel-wheel-py313-boundary-20261023.json).

The current quiet 10k profile initially fails all six latency targets while
isolated storage passes at 1.52483× native. A serial same-host comparison then
passes on prior revision `d3b748e` and the unchanged current source. Both later
runs meet all six latency targets and the storage target. Thresholds and
source stay unchanged. The original failure remains valid evidence.

| Workload | Initial added p95, ms | Unchanged follow-up, ms | Budget, ms |
|---|---:|---:|---:|
| Point scalar | 5.371 | 1.375 | 3 |
| Equality tuple | 8.136 | 2.067 | 3 |
| IN-20 tuple | 8.527 | 3.226 | 8 |
| Point entity | 5.853 | 1.479 | 3 |
| Equality entity | 8.169 | 2.143 | 3 |
| IN-20 entity | 22.948 | 2.953 | 8 |

The failure does not repeat in this sequence. Its cause remains UNKNOWN.
Shared-host variation is a possible explanation, not an established cause.
These warm synchronous TEXT/public-key observations do not qualify production
or optional SQLModel performance. All current runs retain 164 stable hashes.
See the [initial failure](_reset/sqlmodel-integration-performance-20261023.json)
and [wrapper](_reset/sqlmodel-integration-performance-wrapper-20261023.json),
[prior-revision control](_reset/sqlmodel-performance-baseline-d3b748e-20261023.json)
and [wrapper](_reset/sqlmodel-performance-baseline-d3b748e-wrapper-20261023.json), and
[unchanged current follow-up](_reset/sqlmodel-performance-current-after-baseline-20261023.json)
and [wrapper](_reset/sqlmodel-performance-current-after-baseline-wrapper-20261023.json).

This application scope covers synchronous PostgreSQL CRUD modules. HTTP endpoints,
authentication, full application startup, deployment and async SQLModel remain
unqualified. Original configuration/security imports do not qualify those surfaces.
All seven production gates remain UNKNOWN.


Evidence: [final source boundary](_reset/sqlmodel-bridge-boundary-20261023.json),
[pinned source/license](_reset/sqlmodel-pinned-source-20261023.json),
[original RED](_reset/sqlmodel-native-baseline-red-20261023.json),
[final optional profile](_reset/sqlmodel-bridge-primary-final-20261023.json),
[final absent-dependency profile](_reset/sqlmodel-plain-sqlalchemy-alternate-final-20261023.json),
[earlier ordinary regression](_reset/sqlmodel-plain-sqlalchemy-primary-20261023.json),
[template lifecycle](_reset/sqlmodel-template-application-final-20261023.json), and
[setup outcomes](_reset/sqlmodel-environment-setup-20261023.json).

## Native VARCHAR mapped UPDATE checkpoint: 2026-10-23

**IMPLEMENTED, bounded verification:** mapped dictionary UPDATE extends its
existing TEXT route to native VARCHAR. The route still requires `execute()`,
a nonempty list of dictionaries, typed application IDs, one direct tenant-column
equality and `synchronize_session=False`. It retains the existing refusals for
Core, RETURNING, single-tenant mappings and other unsupported options or shapes.

Assignment counts characters and accepts excess ASCII spaces before sealing.
Omitted fields stay omitted. Equality query values retain their exact characters.
A private owned CASE uses public constants for invalid assignments. Each emitted
group preserves the tested native plan-sensitive behavior. Forced custom plans
raise SQLSTATE 22001 for matching, missing and foreign records. Forced generic
and the tested warmed automatic plan raise it for matching records. Missing and
foreign records then produce zero matches without an error.

Only the known owned carrier's DBAPI 22001 becomes its original safe
`VarcharLengthExceeded`, with SQLSTATE `22001`. Other native DBAPI errors stay
native. Protected text never becomes a SQL parameter for the error carrier.
Ordinary flush and INSERT retain their existing length-failure paths.

Sync/async admission captures exact typed requests before provider callbacks.
The immutable ordered ledger binds owned lineage, compiled SQL, bind names,
private constants and final driver bytes. Public expressions and SQL-producing
type hooks gain no admission. Other UPDATE entry points, including scalar and
stream helpers, refuse before key resolution or data SQL. CF1, readers, provider
trust, leakage acceptance and search formats stay unchanged.

Seven native oracle controls and three native CASE probe controls pass.
The initial attached RED records 14 blanket refusals. Intermediate primary runs
retain 58 passes/34 failures and 21 passes/13 failures. The final focused primary
correction passes 13 cases. The final alternate affected run passes 92 cases.
A later multi-field VARCHAR/int64 delta passes once in each cell. Those receipts remain partitioned specialist evidence.

**VERIFIED, local PostgreSQL 16 cell:** the combined serial primary regression
passes **2,281 tests and 18 subtests** in 720.06 seconds. Four skips and 48 existing
SQLAlchemy deprecation warnings remain. All 158 recorded Python hashes stay unchanged.
Both mandatory role probes pass. See the
[full receipt](_reset/varchar-update-integration-full-20261023.json).

Current repeat-build archives, exact dependency metadata, SBOM, 37 installed-file
comparisons and CLI startup pass. All 33 wheel modules match the 38-file source
bundle. The wheel SHA-256 is
`8b57d11ade9364d952764b362478f59fe81e60aedc88b7e2ab53e57a61969191`.
See the [release receipt](_reset/varchar-update-integration-release-20261023.json).

A normal installation uses a disposable Python 3.13.12 environment.
Pinned Smolink `498d24b` passes one URL lifecycle in 3.00 seconds.
Its 38 application files stay unchanged.

Exact runtime pins use cryptography
50.0.2, greenlet 3.5.6, SQLAlchemy 2.1.3 and psycopg/binary 3.3.6. Product/runtime
imports use the new site. App/test dependencies use the read-only Smolink fallback.
All 37 checked wheel members and 33 product modules match before and after.
The check excludes installer-rewritten RECORD. Its wrapper retains 158 stable
Python hashes and passes both role probes.

Real Redis, native/protected HTTP/ORM operations and package-free current-value
removal pass. This application evidence covers the storage-only `Url.destination`
workflow. The dedicated UPDATE controls supply the bulk UPDATE evidence.
Authentication, deployment, SQLModel and a second external app remain unqualified.
All seven production gates remain UNKNOWN. See the
[installation](_reset/varchar-update-wheel-py313-install-20261023.json),
[application](_reset/varchar-update-wheel-py313-application-20261023.json),
[wrapper](_reset/varchar-update-wheel-py313-wrapper-20261023.json), and
[exact boundary](_reset/varchar-update-wheel-py313-boundary-20261023.json).


Evidence: [native plan observations](_reset/varchar-update-native-plan-observations-lifecycle-20261023.json),
[native CASE observations](_reset/varchar-update-case-carrier-observations-lifecycle-20261023.json),
[attached RED](_reset/varchar-update-attached-red-lifecycle-20261023.json),
[first primary failure](_reset/varchar-update-primary-first-lifecycle-20261023.json),
[remaining primary failures](_reset/varchar-update-primary-failed-cases-lifecycle-20261023.json),
[final primary correction](_reset/varchar-update-primary-failed-cases2-lifecycle-20261023.json),
[alternate regression](_reset/varchar-update-alternate-lifecycle-20261023.json),
[primary multi-field delta](_reset/varchar-update-multifield-primary-lifecycle-20261023.json), and
[alternate multi-field delta](_reset/varchar-update-multifield-alternate-lifecycle-20261023.json).

## Installed wheel Python 3.13 checkpoint: 2026-10-23

**VERIFIED, bounded local cell:** a disposable environment uses Python 3.13.12.
A normal wheel installation supplies Cryptalis 0.1.0. Exact runtime pins:
cryptography 50.0.2, greenlet 3.5.6, SQLAlchemy 2.1.3 and psycopg/binary 3.3.6.

The binary driver is active. Product and runtime imports come from the new site.
The read-only Smolink site follows it for application/test dependencies.
Official PyPI supplies dependencies. Only the disposable environment receives nine
distributions. Setup failures remain in the receipt.
The wheel SHA-256 is `75821785bbb1fdab70b56265c1d4b91df1237f979c753076ddf3a182bd4cd1b7`.

Pinned Smolink `498d24b` passes one URL lifecycle in 3.48 seconds. Native/protected operations,
current-value removal and an import-denied child pass with real Redis.
Its 38 application files stay unchanged.
All 33 product modules match source `57e41e8`. All 37 checked wheel members
match before and after the application run. The check excludes installer-rewritten RECORD.

The wrapper retains 155 stable Python hashes. Protection covers only `Url.destination`.
Authentication endpoints, deployed startup, SQLModel and a second external app remain unqualified.
All seven production gates remain UNKNOWN.

Evidence: [installation and setup outcomes](_reset/wheel-py313-exact-install-20261023.json),
[application](_reset/wheel-py313-exact-smolink-application-20261023.json),
[mandatory wrapper](_reset/wheel-py313-exact-smolink-wrapper-20261023.json), and
[exact import and artifact boundary](_reset/wheel-py313-exact-boundary-20261023.json).

## Keyring held-mutex fork checkpoint: 2026-10-23

**VERIFIED, local Linux / Python 3.12.3:** the parent holds the mutex across an actual POSIX fork.
A bounded join limits test duration. In the child, public sync/async
preparation promptly raises `KeyUnavailable` before it locks the inherited mutex.
Fresh keys in the child complete a CF1 roundtrip. Retained and newly prepared
keys in the parent still work after lock release. Failure cleanup kills and reaps a live child.

The specialist regression passes **71 tests**, including CF1 and provider controls.
The integrated fork control passes once. Each run retains 155 stable Python hashes.
Product source and crypto formats stay unchanged. The full suite retains its earlier source boundary.
Production custody, deletion, zeroization and other platforms remain unqualified.
All seven production gates remain UNKNOWN.

Evidence: [specialist regression](_reset/keyring-held-mutex-fork-20261023.json),
[exact boundary](_reset/keyring-held-mutex-fork-boundary-20261023.json), and
[main integration](_reset/keyring-held-mutex-fork-integration-20261023.json).

## Artifact dependency metadata checkpoint: 2026-10-23

**IMPLEMENTED, bounded offline verification:** the release checker compares wheel
`Requires-Python` with the project Python constraint through `packaging.specifiers.SpecifierSet`.
It compares the `Requires-Dist` multiset with project dependencies through
`packaging.requirements.Requirement`. Standard parsing accepts equivalent spelling and ordering.
The multiset retains duplicates. Missing, malformed or changed declarations refuse.
`packaging>=26.3` is an explicit development dependency. The lock refresh changes
no runtime pins. Runtime product source and cryptographic contracts stay unchanged.

The RED records nine failed subtests and one failed test, with two passing tests.
The first GREEN records 13 passes, 54 passed subtests and one installed-check
failure because the development dependency left the lock stale. The final suite
passes **14 tests and 60 subtests** in 3.53 seconds. All four recorded file hashes
stay unchanged during that run.

Current repeat-build archives, SBOM, 37 installed-file comparisons and CLI startup
pass. Wheel metadata declares Python `>=3.12` and the four exact runtime requirements,
including the psycopg binary extra. The wheel hash remains unchanged.
These checks cover artifact metadata and exact installed bytes. Installed dependency
resolution and production qualification remain UNKNOWN. Database suites were not
repeated for this tooling slice. All seven production gates remain UNKNOWN.

Evidence: [RED](_reset/artifact-dependency-metadata-red-20261023.json),
[first GREEN failure](_reset/artifact-dependency-metadata-green-20261023.json),
[final GREEN](_reset/artifact-dependency-metadata-green2-20261023.json), and
[current release](_reset/artifact-dependency-metadata-release-20261023.json).

## Defensive projection and DELETE integration checkpoint: 2026-10-23

**VERIFIED, local combined source:** the serial PostgreSQL 16 primary regression
passes **2,250 tests and 18 subtests**, with four skips and 48 existing deprecation warnings.
The skips comprise one test and three collection skips. The run takes 758.81
seconds. All 154 Python hashes stay unchanged. Both mandatory role probes pass.
This checkpoint combines expanded SELECT descendant admission, authenticated
output regressions, finite mapped DELETE and native-node checks for ordinary
ORM flush DELETE. The receipts bind the combined worktree based on `5b3362b`.

The earlier wrong-password CLI timeout does not recur. Product and test timeouts
stay unchanged. The original timeout's cause remains UNKNOWN. The earlier
`351789e` failed checkpoint remains below, with its original evidence.
See the [full primary receipt](_reset/defensive-projection-delete-full-20261023.json).

The current release check passes repeat-build wheel/sdist hashes, archive
inspection, SBOM, all 37 installed-file comparisons and CLI startup. All 33 wheel
modules match the recorded 38-file source bundle. The wheel SHA-256 is
`75821785bbb1fdab70b56265c1d4b91df1237f979c753076ddf3a182bd4cd1b7`.
See the [release receipt](_reset/defensive-projection-delete-release-20261023.json).

Pinned Smolink revision `498d24b` passes one separate lifecycle check with real
Redis. All 38 application files stay unchanged. Native/protected URL operations,
current-value removal and a package-free child pass. Only `Url.destination` is
protected. Authentication endpoints and deployed startup remain unqualified.
See the [application observations](_reset/defensive-projection-delete-smolink-app-20261023.json)
and [mandatory wrapper](_reset/defensive-projection-delete-smolink-wrapper-20261023.json).

The current 10,000-row native-matched profile passes all six latency targets
and the isolated storage target. Each workload uses 100 paired samples after
ten warmup pairs. Native and attached values match. Other database jobs stop
during sampling. The product completes protection, verification and pinned
ACTIVE attachment.

| Workload | Scalar/tuple added p95, ms | Entity added p95, ms | Budget, ms |
|---|---:|---:|---:|
| Point | 2.2091 | 1.7067 | 3 |
| Equality | 2.3908 | 2.1547 | 3 |
| IN-20 | 2.9629 | 3.2268 | 8 |

Isolated name-column/equality-index storage measures **1.52483× native**.
This warm synchronous TEXT/public-key cell does not qualify larger datasets,
async traffic, concurrent traffic, writes or remote custody. Shared-host load
remains uncontrolled. The application and profile runs retain the same 154-file
source bundle. All seven production gates remain UNKNOWN.
See the [matched profile](_reset/defensive-projection-delete-performance-20261023.json)
and [mandatory wrapper](_reset/defensive-projection-delete-performance-wrapper-20261023.json).

## Expanded SELECT projection checkpoint: 2026-10-23

**IMPLEMENTED, bounded verification:** SELECT admission expands full entity and
table projections before applying existing type, operation and owned-lineage
rules. One shared snapshot includes each selected column and its descendants.
The type check and both general admission checks use that snapshot.

Two native PostgreSQL controls first reproduced a public output hook that
returned CF1 frame hex through an unrelated public attribute. Both attached
entity/table projections now refuse before key resolution or SELECT execution.
A benign mapped `length(protected_field)` control also exposed different admission
for direct and entity projections. Both now refuse. Direct/entity
`length(public_field)` retains the native value.

Ten projection controls cover those refusals, separately constructed table
lineage, ordinary entity/table reads, a public nested SELECT, protected Unicode
and safe Python codecs. The existing authenticated result processor and exact
owned payload exception stay unchanged. No new query grammar or cryptographic
format results from this repair.

The final affected suites each pass **284 checks** with 151 stable Python hashes.
The primary uses Python 3.12.3 / SQLAlchemy 2.1.3. The alternate uses Python 3.13.12 /
SQLAlchemy 2.0.51 with pure psycopg. Both runs reload the private URLs and pass
both mandatory role probes.

Earlier evidence stays visible: the original entity/table RED has two failures.
The first expansion regression has 279 passes and one invalid nested fixture
failure. Its corrected focused control passes once, and its alternate passes
280 checks. The later mapped-expression RED has three passes and one missing
refusal. The final 284-case runs supersede those earlier source boundaries.
The [combined checkpoint](#defensive-projection-and-delete-integration-checkpoint-2026-10-23) passes the full primary regression.
All seven production gates remain UNKNOWN.

Evidence: [entity/table RED](_reset/select-entity-type-hooks-red-20261023.json),
[initial expansion boundary](_reset/select-expanded-columns-boundary-20261023.json),
[mapped-expression RED](_reset/select-expanded-expression-red-20261023.json),
[final primary regression](_reset/select-expanded-expression-primary-20261023.json),
[final alternate regression](_reset/select-expanded-expression-alternate-20261023.json), and
[exact final boundary](_reset/select-expanded-expression-boundary-20261023.json).

## Mapped DELETE admission checkpoint: 2026-10-23

**IMPLEMENTED, bounded verification:** sync/async mapped `execute()` admits one
record DELETE with exact tenant and application-record equalities. It requires
`synchronize_session=False`, no RETURNING and no external parameters. The route
supports tenant-column TEXT/VARCHAR mappings and UUID/int64 application IDs.
Core DELETE, scalar entry points and broader predicates remain unadmitted.

Exact native AST classes and compiler dispatch must pass before key resolution.
Original tenant/record authority stays fixed across provider callbacks, compiled
binds and final driver arguments. Native controls cover row counts, zero matches,
identity-map behavior, autoflush, foreign-key failure, savepoints and rollback.
This route authenticates no stored frame because it returns no protected value.

Ordinary ORM flush DELETE also checks native nodes before its existing early
return. Four benign single/batch TEXT/VARCHAR controls replace a DELETE with an
equivalent subclass that inherits the native compiler. The corrected RED records
four missing refusals. The guard now refuses before DELETE execution and leaves
rows unchanged. Removing the hook restores native flush and rollback behavior.
The guard adds no scoped tenant-predicate requirement to ordinary ORM flush.

The scoped route passes **55 integrated checks**. Its earlier primary affected
run passes 258 existing checks. The final flush-guard bundle passes **65 checks**
in each primary and alternate cell, including scoped/native DELETE and existing
sync/async ORM state controls. All runs keep their recorded source hashes stable.

The earlier alternate affected run records 312 passes and one VARCHAR restart
failure. Its isolated child lacked psycopg. A test-only interpreter option now
permits a disposable Python 3.13 child with psycopg and no Cryptalis. The default
interpreter and `-I` remain unchanged. The single failed control then passes.
This does not replace the original 312-pass/one-failure receipt with a full pass.
The [combined checkpoint](#defensive-projection-and-delete-integration-checkpoint-2026-10-23) passes the full primary regression.
All seven production gates remain UNKNOWN.

Evidence: [native oracle](_reset/scoped-delete-native-lifecycle-20261023.json),
[scoped controls](_reset/scoped-delete-green2-lifecycle-20261023.json),
[scoped integration](_reset/scoped-delete-integration-20261023.json),
[existing primary regression](_reset/scoped-delete-primary-existing-lifecycle-20261023.json),
[earlier alternate failure](_reset/scoped-delete-alternate-lifecycle-20261023.json),
[isolated native child](_reset/scoped-delete-alternate-varchar-child-environment-lifecycle-20261023.json),
[corrected restart control](_reset/scoped-delete-alternate-varchar-restart-lifecycle-20261023.json),
[initial flush RED](_reset/flush-delete-dispatch-red-lifecycle-20261023.json),
[corrected flush RED](_reset/flush-delete-dispatch-red2-lifecycle-20261023.json),
[final primary flush bundle](_reset/flush-delete-dispatch-primary-lifecycle-20261023.json), and
[final alternate flush bundle](_reset/flush-delete-dispatch-alternate-lifecycle-20261023.json).

## Post-admission 10k profile checkpoint: 2026-10-23

**VERIFIED, local profile only:** committed `3a21096` passes the existing
10,000-row native-matched profile after shared identity and SELECT type checks.
All six latency targets and the isolated storage target pass. Each workload
uses 100 paired samples after ten warmup pairs. Native and attached results match.
The product completes protection, verification and pinned ACTIVE attachment.

| Workload | Scalar/tuple added p95, ms | Entity added p95, ms | Budget, ms |
|---|---:|---:|---:|
| Point | 1.5218 | 1.4839 | 3 |
| Equality | 2.2998 | 2.0060 | 3 |
| IN-20 | 3.7486 | 2.9876 | 8 |

Isolated name-column/equality-index storage measures **1.52483× native**.
All 150 recorded Python hashes stay unchanged. The test passes in 4.82 seconds.
Process CPU measures 3.175 seconds, elapsed time 4.608 seconds and lifetime peak
RSS 94,004 KiB. These include fixture work and imports, with no server-resource
or streaming-memory claim. The team holds other database jobs during sampling.
Shared-host load remains uncontrolled. This warm synchronous TEXT/public-key cell
does not qualify larger datasets, async traffic, writes or remote custody.
All seven production gates remain UNKNOWN. Full combined follow-up remains required.

Evidence: [matched observations](_reset/select-type-performance-20261023.json) and
[mandatory wrapper](_reset/select-type-performance-wrapper-20261023.json).

## Finite SELECT type admission checkpoint: 2026-10-23

**IMPLEMENTED, bounded verification:** attached SELECT checks every typed AST
node before generated-node exceptions, including nested statements and compiled
forms. Native controls first exposed public type hooks that returned CF1 hex
or changed a matching predicate. The original RED retains three failures and
one safe-codec pass.

Admission now refuses SQL bind/output hooks, dialect variants, dynamic type
implementations, user-defined SQL type spelling and literal-execution binds.
Current compiler dispatch must be an actual bound method with exact native
function identity and the correct bound type object. Decorator and container
inner types also pass these checks. Only the exact owned physical payload type
may use its internal output hook. That exception waives no other check.
Tested ordinary Python bind/result processors and native Boolean/Enum values
retain their native behavior.

All **12 controls** pass on the final primary integration source. The final
alternate affected run passes **274 checks** on Python 3.13.12 / SQLAlchemy 2.0.51.
Earlier primary evidence records 272 passes and the already corrected assertion
that expected configuration rejection later. Two final primary delta controls
also pass. Earlier receipts stay separate from the final-source evidence.
These checks cover SELECT admission. Public write-type hooks and hostile Python
execution have separate boundaries. Full combined follow-up remains required.
All seven production gates remain UNKNOWN.

Evidence: [initial native RED](_reset/select-type-hooks-red-20261023.json),
[earlier primary controls](_reset/select-type-hooks-green-20261023.json),
[earlier affected failure](_reset/select-type-hooks-affected-20261023.json),
[final primary delta controls](_reset/select-type-hooks-dispatch-mapping-20261023.json),
[final primary integration](_reset/select-type-hooks-integration-20261023.json),
[final alternate regression](_reset/select-type-hooks-sa20-20261023.json), and
[exact admission and evidence boundary](_reset/select-type-hooks-boundary-20261023.json).

## Combined integration checkpoint: 2026-10-23

**IMPLEMENTED, bounded checks:** the full regression is incomplete.
Checkpoint `351789e` combines KMS, restore, diagnostics, native identity admission, rotation
row recovery and scoped bulk UPDATE. Its full primary run reports 2,167 passed,
two failed, four skipped, 48 existing warnings and 18 passed subtests.
All 149 Python hashes stay unchanged during the run.

One failure expects configuration rejection only during execution. The new
pre-key check correctly refuses session creation earlier. The corrected test
accepts refusal at either boundary and retains zero-driver and healthy-restored
mapping checks.

The other failure is a wrong-password search-status CLI process
that exceeds the test's 10-second limit. Both focused controls pass afterward.
The CLI case takes 1.30 seconds. Product and test timeouts stay unchanged.
The original timeout's cause remains UNKNOWN. A full follow-up remains required.

Pinned unchanged Smolink passes its separate lifecycle check with real Redis,
current-value removal and a package-free child that denies Cryptalis imports.
All 38 application files match. This covers storage lifecycle, not authentication
endpoints or deployed startup. Reproducible archives, SBOM, all 37 installed
files and CLI startup pass. The installed wheel SHA-256 is
`fe6856a8a501c6208920a82b2c1e8342435a1f0335dfb6b8aaf867ddfd1beea9`.

These artifacts match the product source. The later assertion correction changes
only test code. A separate SELECT type-hook repair remains outside this checkpoint.
All seven production gates remain UNKNOWN.

Evidence: [full run with two failures](_reset/parallel-integration-full-20261023.json),
[focused failure controls](_reset/parallel-integration-failure-controls-20261023.json),
[unchanged application](_reset/integrated-smolink-app-lifecycle-20261023.json),
[application wrapper](_reset/integrated-smolink-wrapper-lifecycle-20261023.json),
[reproducible archives](_reset/parallel-integration-release-20261023.json), and
[installed wheel](_reset/parallel-integration-installed-20261023.json).

## Scoped mapped bulk UPDATE checkpoint: 2026-10-23

**IMPLEMENTED, bounded verification:** attached sync/async sessions admit mapped
TEXT dictionary UPDATE with one explicit tenant equality and
`synchronize_session=False`. Inputs require a nonempty list of dictionaries
with typed application IDs. Protected fields can be omitted, NULL or exact text.
Public Python bind processors retain native behavior. The route preserves
contiguous groups, repeated IDs, zero matches, autoflush, savepoints, errors,
identity-map behavior and the native empty Result.

The route refuses Core, RETURNING, embedded values, extra predicates, tenant
assignments, version counters, dynamic defaults, read-only mapper properties,
SQL-producing type hooks and type variants. VARCHAR and single-tenant bulk
UPDATE remain unadmitted. It adds no rowcount promise. Exact owned-column
lineage, ordered input proofs, scope/ID binds, sealed bytes and final driver
snapshots bind every emitted group to its prepared inputs.

The later [native VARCHAR UPDATE checkpoint](#native-varchar-mapped-update-checkpoint-2026-10-23)
extends this historical TEXT boundary. Its evidence and limits remain separate.

Attachment also requires exact native row-context types and flags. Repeated
configuration checks refuse changed identities before host key resolution.
Native bulk and flush INSERT controls demonstrate SQL-transformed UUID values
before protection, then refuse the changed mapping under the original valid plan.
These shared checks cover initial attachment and later metadata changes.
A late public type change refuses with rollback and unchanged rows. The same
factory has no recovery promise after native DML type caches capture that change.

The primary and alternate affected runs each pass **143 cases** on the same
141-file source bundle. The primary uses Python 3.12.3 / SQLAlchemy 2.1.3.
the alternate uses Python 3.13.12 / SQLAlchemy 2.0.51 with pure psycopg.
The original 12-case native oracle and intermediate failure receipts remain
separate. Review controls exposed read-only property handling and hidden SQL
type transformations before final admission. All seven full gates remain UNKNOWN.

Evidence: [native oracle](_reset/bulk-update-native-first-20261023.json),
[initial protected RED](_reset/orm-bulk-update-red-20261023.json),
[read-only property RED](_reset/orm-bulk-update-readonly-red-20261023.json),
[SQL hook RED](_reset/orm-bulk-update-sql-hooks-red-20261023.json),
[final primary regression](_reset/orm-bulk-update-ready-primary-20261023.json), and
[final alternate regression](_reset/orm-bulk-update-ready-alternate-20261023.json).

## Rotation row lease recovery checkpoint: 2026-10-23

**IMPLEMENTED, bounded verification:** payload/search staging and paired-frame
verification share one expiry retry per row. The retry checks both exact pinned
policies before fresh preparation and verifies the retained-root relationship.
It retries only a failed pure crypto step. The singleton staging transform also
includes its internal lease checks. No generic provider or policy fault retries.
SQL, progress and digest effects follow complete successful work.

Verification releases source frames before target decoding. The existing
three-frame logical budget remains unchanged. Source-only observations, activation
target observations and outer executor/return lease checks retain terminal expiry.
Their unchanged final behavior has source review, without new expiry-injection evidence.
This checkpoint does not claim automatic recovery throughout every rotation phase.

All 20 new controls pass inside each **83-case** primary and alternate regression.
The cells use Python 3.12.3 / SQLAlchemy 2.1.3 and Python 3.13.12 / SQLAlchemy 2.0.51.
Both receipts match the same 141 Python files. Native controls force actual
post-AEAD source/target expiry, policy drift, provider outage and second expiry.
They check source/shadow/journal rollback and explicit healthy resume. The original
RED run retains 20 failures. All seven production gates remain UNKNOWN.

Evidence: [original RED controls](_reset/rotation-lease-red-lifecycle-20261023.json),
[primary regression](_reset/rotation-lease-green-lifecycle-20261023.json), and
[alternate regression](_reset/rotation-lease-alternate-lifecycle-20261023.json).

## Identity variant planning checkpoint: 2026-10-23

**IMPLEMENTED, planning boundary:** identity codec admission rejects mappings
with dialect-specific type variants. Exact native UUID or bigint types must
represent the record and tenant context declared by the lock.

Two native PostgreSQL controls first insert with a UUID SQL variant. The real
stored record or tenant UUID differs from the supplied UUID. Each transaction
rolls back before planning, and rows stay unchanged. The preceding compiler
accepts both mappings, so both RED controls fail. The corrected compiler and
existing compiler/VARCHAR regression pass **105 cases**.

This checkpoint covers read-only protection planning. Attachment and later
mapping mutation require their separate adapter controls. All seven production
gates remain UNKNOWN.

Evidence: [native RED controls](_reset/context-type-red-20261023.json) and
[planning regression](_reset/context-type-green-20261023.json).

## Actionable inspection failures checkpoint: 2026-10-23

**IMPLEMENTED, bounded verification:** Doctor and status inspection failures
include the selected plan's public operation UUID. Known runtime-role and
external-pin refusals give fixed reasons and bounded remedies. Other codes
retain their generic reason. Cleanup failures also retain the operation UUID.
The CLI omits private connection values and raw exception details.
Existing codes, exit classes and UNKNOWN observations stay unchanged.

Seven new native PostgreSQL controls pass through the lead integration.
The specialist's affected regression passes 128 cases. JSON and text output
retain safe context, and read-only snapshots show no database changes.
The original RED receipt retains seven failures. Two initial expectations used
a different connection-failure code and were corrected to the existing contract.
All seven production gates remain UNKNOWN.

Evidence: [original RED controls](_reset/inspection-diagnostics-red-lifecycle-20261023.json),
[affected regression](_reset/inspection-diagnostics-green-lifecycle-20261023.json), and
[lead integration](_reset/inspection-diagnostics-integration-20261023.json).

## Restored-frame lease recovery checkpoint: 2026-10-23

**IMPLEMENTED, bounded verification:** restored-frame scans retry one unfinished
row after actual key expiry. Fresh admission checks the exact retained policy.
Provider failure, changed policy and repeated expiry remain `KeyUnavailable`.
Authentication and generation faults retain their existing typed failures.
No binding or probe write precedes complete frame authentication.
Host approval, target identity, schema and runtime-role checks retain their order.

The lead integration passes nine scan/admission checks. Separate genuine fresh
PostgreSQL clusters pass ten public restore controls for TEXT and ten for VARCHAR.
Each profile first exports a protected backup through the normal product path.
Controls cover post-AEAD expiry recovery, deployment admission, provider and
policy refusal, repeated expiry, corrupt frames, generations and authority order.
All 139 recorded Python hashes match the integrated files. No durable rows,
journal state or catalogs change on failed adoption.

The original RED receipt retains four failures and three passes. The first
implementation run also failed because fixture bookkeeping passed prepared keys
to a keyring policy helper. The corrected run passes. Both failures remain
separate from successful evidence. All seven production gates remain UNKNOWN.

Evidence: [original RED controls](_reset/restore-lease-red-lifecycle-20261023.json),
[first implementation failure](_reset/restore-lease-green-lifecycle-20261023.json),
[corrected scan checks](_reset/restore-lease-green2-lifecycle-20261023.json),
[lead integration](_reset/restore-lease-integration-20261023.json),
[TEXT export](_reset/fresh-cluster-export-20261023-17.json),
[TEXT restore](_reset/fresh-cluster-restore-20261023-17.json),
[VARCHAR export](_reset/fresh-cluster-export-20261023-18.json), and
[VARCHAR restore](_reset/fresh-cluster-restore-20261023-18.json).

## Optional AWS KMS SDK adapter checkpoint: 2026-10-23

**IMPLEMENTED, bounded verification:** a caller-supplied synchronous KMS client
wraps and unwraps roots under an exact full key ARN and fixed public context.
Aliases, wrong response identity/algorithm, invalid material, inherited providers
and relabeled context refuse. Async cancellation publishes no late cached key.
The host supplies SDK credentials, endpoint, timeout, retry and logging settings.
CF1 and the existing provider/key-policy interfaces stay unchanged.

The specialist and lead integration each pass **86 checks**, including 36 new
SDK-shaped protocol controls and 50 existing CF1/keyring/rewrap cases.
An explicit isolated boto3 1.42.89 / botocore 1.42.97 profile passes **12 cases**.
It verifies actual SDK model acceptance, serialized binary/context requests,
modeled service errors, malformed replies and cancellation. Synthetic credentials
and working transport/discovery tripwires prevent live AWS access.
Its first run retains one serialization-observer ordering error; the corrected
run and lead integration pass. No adapter correction was needed for that error.
Reproducible wheel and source archives, the SBOM, all 37 installed files and
CLI startup pass. The installed wheel SHA-256 is
`876a5e15666387050cd32079dea9410fa6d8db6d19ab7f5b980ab8d18cd136be`.

The current installed 36-module wheel passes one original SQLModel application
journey in **2.28 seconds**, with 169 stable Python files. Python 3.13 uses the
exact runtime pins and SQLModel 0.0.48. Local boto3/botocore Stubber responses
exercise original CRUD. Exact-expiry provider outage refuses before SQL.
Rollback and retry pass. Healthy expiry, wrong-root/tag authentication refusal
and recovery, latest-value decrypt-back/removal and package-free restart pass.
This local application profile supplies no live AWS, IAM, custody or rotation
qualification.

Production custody, IAM, workload identity, live transport/logging, provider
revocation/deletion and all seven full gates remain UNKNOWN.

Evidence: [official references and context](_reset/aws-kms-research-20261023.json),
[specialist protocol checks](_reset/aws-kms-protocol-20261023.json),
[lead protocol integration](_reset/aws-kms-integration-20261023.json),
[isolated SDK versions and limits](_reset/aws-kms-sdk-environment-20261023.json),
[initial SDK observer failure](_reset/aws-kms-sdk-profile-20261023.json),
[corrected SDK profile](_reset/aws-kms-sdk-profile-green-20261023.json), and
[lead SDK integration](_reset/aws-kms-sdk-integration-20261023.json),
[reproducible archives and SBOM](_reset/aws-kms-release-20261023.json), and
[installed wheel](_reset/aws-kms-installed-20261023.json),
[current installed application wrapper](_reset/doctor-recovery-kms-application-wrapper-20261023.json),
[local application transport](_reset/doctor-recovery-kms-application-transport-20261023.json), and
[original application lifecycle](_reset/doctor-recovery-kms-application-lifecycle-20261023.json).

## Bounded row lease recovery checkpoint: 2026-10-23

**IMPLEMENTED, bounded verification:** protection and decrypt-back retry local
row crypto once after actual lease expiry. They check the exact host policy
before fresh admission. Failed row work changes no SQL, progress marker or
verification digest. Provider failure, changed policy and repeated expiry
still stop the operation. Public diagnostics remain `KeyUnavailable`.
The [security contract](security.md#implemented-cf1-primitives-and-local-custody) owns the precise retry boundary.

The initial million-row profile failed during protection. A diagnostic replay
located expiry at the final payload check after real encryption in backfill.
Both failed receipts remain separate from successful performance evidence.
A later run stopped at bounded table-lock admission with SQLSTATE `55P03`.
It produced no performance measurements. The explicit profiler now completes
named-table `VACUUM (ANALYZE)` after seeding each disposable fixture, before
product planning. Its separate 120-second statement limit is restored afterward.
Product lease durations and lock limits stay unchanged.

Four new success controls fail against the immutable preceding product source.
The fix passes all 16 new PostgreSQL controls across protection/decrypt-back
and backfill/verification. They force expiry after the real AEAD call, using
an isolated key clock. They verify fresh admission, native rows, independent
frame decoding and verification digests. Failed refresh, repeated expiry and
policy changes retain exact rows and journal state before explicit healthy resume.
The existing primary crypto/provider/lifecycle run passes 111 checks.
The alternate Python 3.13.12 / SQLAlchemy 2.0.51 cell passes all 127 checks.
One extra check passes for pinned unchanged Smolink, including real Redis and
current-value removal with Cryptalis imports denied in a fresh process.
All 38 app source hashes match, with no model/query changes.
This storage/lifecycle boundary excludes authentication endpoint qualification.
Reproducible archives, SBOM, all 36 installed files and CLI startup pass.
The prepared million-row profile completes the product transition and all six
native-matched read targets. The full primary regression passes **2,034 tests
and 18 subtests**, with three separate-environment skips and 48 existing warnings.
The wrapper records 594.06 seconds. Its 137 Python hashes stay stable and
match the final worktree, as do the million-row and app wrapper hashes.
The earlier focused receipts differ only at the later profiler fixture revision.
Later restore and rotation checkpoints extend their stated scan/staging boundaries.
All seven full gates remain UNKNOWN.


Evidence: [initial million-row failure](_reset/performance-million-current-wrapper-20261023.json),
[diagnostic replay](_reset/performance-million-trace-wrapper-20261023.json),
[safe failure origin and diagnostic source](_reset/performance-million-lease-origin-20261023.json),
[bounded lock refusal](_reset/performance-million-row-lease-wrapper-20261023.json),
[previous-product RED control](_reset/row-lease-red-20261023.json),
[control product hashes](_reset/row-lease-red-product-source-20261023.json),
[new lease controls](_reset/row-lease-green-20261023.json),
[existing primary checks](_reset/row-lease-existing-20261023.json),
[alternate cell](_reset/row-lease-sa20-20261023.json),
[unchanged app wrapper](_reset/row-lease-smolink-20261023.json),
[app source and lifecycle evidence](_reset/row-lease-smolink-app-20261023.json),
[reproducible archives](_reset/row-lease-release-20261023.json),
[installed wheel](_reset/row-lease-installed-20261023.json), and
[full primary regression](_reset/row-lease-full-20261023.json).

## Current pinned performance checkpoint: 2026-10-23

**VERIFIED, bounded local measurement:** an explicit wrapper-run profile compares
two identical 10,000-row applications with unique 53-byte names.
Both seed and query through the separate runtime role. The protected path
replans seeded data, completes the product protection/ACTIVE publication path,
and attaches with its deployment pin. Timings retain every product guard and
include native execution plus complete scalar/tuple materialization.
The primary cell is Python 3.12.3 / SQLAlchemy 2.1.3 / psycopg 3.3.6 /
cryptography 50.0.2 / PostgreSQL 16.15 on the recorded local WSL2 host.

Each workload discards ten warmup pairs, then measures 100 pairs with alternating
native/attached order. Added p95 means attached p95 minus native p95.
Raw samples retain exact values. The following table records the initial projection run.

| Workload | Native p95 ms | Protected p95 ms | Added p95 ms | Local target |
|---|---:|---:|---:|---|
| Point name scalar | 0.3841 | 2.0135 | 1.6294 | PASS, at most 3 ms |
| Equality `(id, name)` | 0.3319 | 2.3426 | 2.0107 | PASS, at most 3 ms |
| IN-20 `(id, name)`, native ID order | 0.5291 | 3.0620 | 2.5330 | PASS, at most 8 ms |

The isolated name column plus equality index measures **1.5248× native**,
within the 2× target for this distribution. Whole relation sizes remain context
in the receipt. They are outside that isolated denominator.
The wrapper passes one explicit profile case. Both receipts retain stable
136-file Python hashes. Product bytes match the preceding full regression and wheel.

A subsequent profile extends the same fixture and predicates to full ORM
entities with all four attributes materialized. It retains no identity-map objects
between samples. All six workloads pass exact native-result checks.
Added entity p95 measures **1.2622 ms point**, **2.6119 ms equality**, and
**2.8613 ms IN-20**, within the respective 3/3/8 ms local targets.
Both subsequent receipts retain stable 136-file hashes at the extended profiler.
Their raw projection measurements remain separate from the initial table.

A bounded row-count option now admits 10,000, 100,000 or 1,000,000 rows.
The **100,000-row** run passes all six workload targets and exact result checks.
Added entity p95 measures **1.2667 ms point**, **1.7083 ms equality**, and
**2.5670 ms IN-20**. Isolated storage measures **1.5296× native**.
The process uses 11.96 CPU seconds over 18.03 elapsed seconds, including setup
and cleanup. Its lifetime peak RSS is 182.5 MiB, including pytest imports.
These resource observations exclude PostgreSQL server CPU and memory.
Both 136-file receipts stay stable at the configurable profiler revision.

The subsequent **1,000,000-row** run completes the full product protection,
verification and ACTIVE attachment path. Both receipts retain stable 137-file
hashes. All six read workloads match native results and meet local targets.
This profiler revision includes the bounded row lease fix and explicit fixture
maintenance before planning. It keeps the original product lease and lock limits.

| Workload | Projection added p95 ms | Entity added p95 ms | Local maximum ms |
|---|---:|---:|---:|
| Point | 1.8239 | 2.4646 | 3 |
| Equality | 1.8742 | 2.1569 | 3 |
| IN-20 | 0.9442 | 2.5735 | 8 |

Isolated storage measures **1.4372× native**. The process uses 110.78 CPU seconds
over 172.69 elapsed seconds, including fixture maintenance and cleanup.
Its lifetime peak RSS is 1,064.9 MiB, including pytest imports.
This peak also includes the full generated input list, temporary identity/name
sets and seed serialization. It does not bound streaming backfill or adapter memory.
These observations exclude database-server CPU and memory.
The earlier lease failures and lock refusal remain separate evidence.

These are warm synchronous TEXT observations with in-process public fixture keys.
Shared-host load remains uncontrolled. Remote/cold providers, async/VARCHAR,
concurrent load, throughput and maintenance pauses remain unmeasured here.
The historical million-row receipts keep their earlier source and query-shape boundaries.
All seven full gates remain UNKNOWN.

Evidence: [raw samples, cell, lifecycle and storage](_reset/performance-current-20261023.json)
and [mandatory wrapper receipt](_reset/performance-current-wrapper-20261023.json),
then [full-entity samples](_reset/performance-entities-20261023.json)
and [full-entity wrapper receipt](_reset/performance-entities-wrapper-20261023.json),
then [100,000-row samples and resources](_reset/performance-100k-20261023.json)
and [100,000-row wrapper receipt](_reset/performance-100k-wrapper-20261023.json),
then [million-row samples and resources](_reset/performance-million-prepared-20261023.json)
and [million-row wrapper receipt](_reset/performance-million-prepared-wrapper-20261023.json).
The [fixture smoke samples](_reset/performance-row-lease-smoke-20261023.json)
and [smoke wrapper](_reset/performance-row-lease-smoke-wrapper-20261023.json)
retain the preceding small-fixture check.

## Mapped protected scalar RETURNING checkpoint: 2026-10-23

**IMPLEMENTED, bounded native verification:** attached sync/async mapped bulk
INSERT admits exactly one direct protected mapped column in `returning()`.
Native one-column Rows/scalars keep mapped keys, Python types, NULL/grouping,
paging, explicit parameter-order requests and an empty identity map.
Caller dictionaries stay unchanged. The driver observer sees the public
Unicode marker before protection. The same observer sees no plaintext marker afterward.

Tuple/entity results, labels, expressions, aliases, loader options and caller
`return_defaults()` remain refused. No format or provider contract changes.

Each returned scalar must match its input tenant, real record identity and
exact prepared ciphertext or NULL. Immutable expectations come from each native
group and survive operation cleanup. Native supplemental RETURNING authenticates
during `execute()` in the exercised cells. Lease expiry before that use refuses.
Later iteration retains plaintext that already passed authentication without
new provider work. Outstanding Results survive later session operations.
SELECT outer-join NULL behavior remains separate.

The native insertmanyvalues generator retains SQL construction, parameter
association, fetches and sentinel ordering. The guard validates full processed
input, then compares every page's rows with the original frozen slice.
It binds exact generated SQL/parameters to one cursor/context and dispatch.
Current-page and future-page mutation controls refuse before the altered page
reaches raw psycopg. The shared first-capture/completion checks remain active.

**VERIFIED:** the initial eight native baselines pass, then protected execution
fails at the original RETURNING refusal. Intermediate receipts retain admission
failures and fixture errors. Ordinary ORM annotations retain native types even
in fresh mappings. Owned column lineage now drives admission, as for SELECT.
Both native derived defaults forms pass. Test reads now use admitted explicit
primary-key IN, and refusal counters exclude the factory's tenant-policy check.
The first combined run passes 91 cases with one obsolete RETURNING refusal
expectation. That control now checks an unadmitted public-ID result instead.
The next run passes **100 cases**. The wrapper records 33.55 seconds.
Controls include current/future page tampering, returned-frame/identity/NULL substitution, leases, duplicate-ID
precedence, savepoint recovery and renamed/signed single-tenant fields.

The final alternate Python 3.13.12 / SQLAlchemy 2.0.51 / psycopg-Python cell
passes **103 cases**. The wrapper records 34.72 seconds.
It adds TEXT/VARCHAR current-value removal
after RETURNING insertion and a later ORM edit, plus unchanged pinned Smolink.
All 38 app source hashes match with no model/query changes. Its real Redis,
runtime application and import-denied package-free removal checks pass.
All final 135 Python hashes stay stable and match the worktree.
The full primary regression passes **2,018 tests and 18 subtests**.
The wrapper records 624.76 seconds, with three separate-environment skips and
48 existing DISTINCT warnings.
Its 135 Python hashes also stay stable and match the final worktree.
Reproducible offline archives, SBOM and all 36 installed package files pass,
including CLI startup. Fresh-cluster/full-alternate profiles retain their prior
revision boundaries. All seven full gates remain UNKNOWN.

Evidence: [initial native controls](_reset/bulk-returning-red-20261023.json),
[first integration](_reset/bulk-returning-green-20261023.json),
[native annotation admission](_reset/bulk-returning-native-green-20261023.json),
[derived-form admission](_reset/bulk-returning-lineage-green-20261023.json),
[native read fixtures](_reset/bulk-returning-derived-green-20261023.json),
[driver/result controls](_reset/bulk-returning-boundary-20261023.json),
[native recovery and identity controls](_reset/bulk-returning-recovery-20261023.json),
[full primary regression](_reset/bulk-returning-full-20261023.json),
[final alternate regression](_reset/bulk-returning-sa20-20261023.json),
[final app evidence](_reset/bulk-returning-smolink-app-20261023.json),
[reproducible archives](_reset/bulk-returning-release-20261023.json), and
[installed wheel](_reset/bulk-returning-installed-20261023.json).

## Test receipt checkpoint: 2026-10-23

**IMPLEMENTED, bounded verification:** the PostgreSQL wrapper adds
`pytest_report_counts` without changing historical `counts` or `modules`.
It separates final ordinary calls, subtest calls, setup, teardown and
failed/skipped collection reports. It also records selected item count.
The wrapper retains report references until session finish because pytest can
change a parent outcome after a failed subtest. No product or crypto behavior changes.
The [build guide](build-guide.md#receipt-outcome-fields) owns each field's meaning.

**VERIFIED:** real isolated pytest subprocesses cover ordinary tests and
pytest/unittest subtests. They also cover skips, phase errors, collection
failure, expected failures and non-strict unexpected passes.
The initial repository control fails all three cases on the missing field.
The corrected focused wrapper run passes **24 cases** in 2.69 seconds,
including source-stability and development-preflight regressions.
A mistaken test path produced no tests and exit 4. Its receipt remains separate.
The alternate Python 3.13 cell passes the same 24 cases in 3.08 seconds.

The full primary regression passes **1,978 tests and 18 subtests** in
552.20 seconds, with three separate-environment skips and 48 existing DISTINCT warnings.
The new receipt separates 1,978 passed/one skipped ordinary call, 18 passed
subtests and two collection skips. It records 1,979 selected items.
All 132 Python source hashes stay unchanged and match the worktree.
This full run also covers the shared driver's final exact-buffer fix below.

Other pytest versions and external report plugins remain unverified.
These counters do not qualify a production gate. Product package bytes retain
the preceding reproducible archive evidence. No new wheel build was needed.

Evidence: [initial missing-field failures](_reset/report-counts-red-20261023.json),
[invalid test path](_reset/report-counts-green-20261023.json),
[focused reporter/preflight regression](_reset/report-counts-focused-20261023.json),
[alternate reporter/preflight regression](_reset/report-counts-sa20-20261023.json), and
[full primary regression](_reset/report-counts-full-20261023.json).

## Shared driver event checkpoint: 2026-10-23

**IMPLEMENTED, bounded native verification:** the shared guard captures each
native processed statement/parameter set at the first cursor event, then checks
the actual values at dialect dispatch. It freezes native SQL, binary bytes,
containers and typed primitive/identity values. It retains unknown unprotected
driver adapters by object identity, without freezing their mutable internals.
Capture consumption covers ordinary flush/read paths, sync/async dispatch and
each native insertmanyvalues RETURNING page. The bulk route retains its
independent sealed-batch checks. No crypto format, key authority or DML scope
changes.

Capture must be first and unique in effective Connection dispatch. Preattachment
engine listeners refuse before connection. Effective Connection listeners
refuse before the first catalog query. Later class/connection cursor hooks also
refuse before data dispatch. Register unchanged engine-instance observers after
attachment. Native `insert=True` does not reorder these Connection events.
Changed SQL/values, unsafe order, missing capture and SQL string subclasses
raise `UnsafeDriverEvent`. Named-key comparison freezes native text and type
identity, without calling supplied equality overrides. No callback receives a
driver permit. Independent clients, host authorization, earlier expression
admission and custom adapter internals keep their separate trust limits.
An after-cursor check requires actual guarded dispatch completion before native
result/UOW success. A dialect callback cannot return `True` to silently skip
an INSERT, including a class callback installed during a later cursor callback.
Each page resets and consumes its own markers. Deliberate removal of Cryptalis
callbacks is trusted-host guard tampering, outside this boundary.

**VERIFIED:** the initial run retains 13 failures. Eleven expose cursor
changes that reached the real driver or changed observable read behavior.
Two reveal RETURNING fixture errors: the existing mapper cached default metadata
before the test changed it. Fresh imperative mappings with eager defaults now
establish the native five-row, three-page baseline without private cache edits.
The first corrected primary run passes **59 cases** in 22.53 seconds, including
all 44 bulk cases. Controls cover in-place plaintext/valid-frame substitution,
identity and tenant mutation, ordinary UPDATE, point/equality query changes,
SQL and spoofed-string replacement, connection-local hooks, preattachment
refusal before connection/key work, native observer results, RETURNING page
tampering, async failure/rollback and clean retry. Raw psycopg call collectors
remain empty during each refused injection.

The alternate Python 3.13.12 / SQLAlchemy 2.0.51 / psycopg-Python cell passes
those cases plus the pinned unchanged Smolink lifecycle: **60 cases** in
18.67 seconds. All 38 app source hashes match, with no model/query changes.
Its import-denied current-value removal child also passes. The full primary
regression was interrupted to add the completion control after source review.
Its receipt retains 975 passed tests, 18 passed subtests, two collection skips
and one real reattachment exception-class failure before interruption.
`UnsafeDriverEvent` now retains the existing unsupported-operation category.
The completion, reattachment, deprotection and bulk run passes **80 cases** in
35.90 seconds. The final alternate cell passes **62 cases** in 28.53 seconds,
including both dialect-skip controls and the unchanged Smolink lifecycle.
The subsequent broad primary run passes **1,974 tests and 18 subtests** in
586.08 seconds, with three separate-environment skips and 48 existing DISTINCT
warnings. This run precedes the following narrow buffer-admission fix.

A real PostgreSQL negative control then exposes a custom Binary buffer bypass:
a bytearray subclass reports the original frame through `__bytes__`, while
psycopg sends its different native buffer. The inserted row reached the driver
without the required typed refusal. The guard now requires exact native buffer
types and reads them through `memoryview`, without custom byte conversion.
The final affected primary run passes **227 cases** in 58.70 seconds across
the event, bulk, deprotection, adapter, search and runtime boundaries.
The final alternate cell passes **63 cases** in 28.38 seconds, including the
buffer control and unchanged Smolink lifecycle. Both final 131-file Python
bundles match the current worktree. The broad run above remains bounded to its
recorded pre-buffer-fix source. Fresh-cluster profiles and the full alternate
cell were not rerun for this guard.
Completed runs retain stable 131-file Python hashes. Reproducible final offline
archives, SBOM and all 36 installed package files pass, including CLI startup.
All seven full gates remain UNKNOWN.

Evidence: [initial failures](_reset/driver-event-red-20261023.json),
[primary guard and bulk regression](_reset/driver-event-green-20261023.json),
[interrupted broad run](_reset/driver-event-full-20261023.json),
[completion and deprotection controls](_reset/driver-event-completion-20261023.json),
[broad primary run](_reset/driver-event-full-final-20261023.json),
[native masked-buffer failure](_reset/driver-event-buffer-red-20261023.json),
[final affected primary regression](_reset/driver-event-buffer-green-20261023.json),
[alternate guard and app](_reset/driver-event-sa20-20261023.json),
[app evidence](_reset/driver-event-smolink-app-20261023.json),
[final alternate guard and app](_reset/driver-event-sa20-final-20261023.json),
[final app evidence](_reset/driver-event-smolink-app-final-20261023.json),
[final buffer/app alternate run](_reset/driver-event-sa20-buffer-20261023.json),
[final buffer/app evidence](_reset/driver-event-smolink-app-buffer-20261023.json),
[final reproducible archives](_reset/driver-event-release-buffer-20261023.json), and
[final installed wheel](_reset/driver-event-installed-buffer-20261023.json).

## Mapped bulk INSERT checkpoint: 2026-10-23

**IMPLEMENTED, bounded native verification:** attached sync/async sessions admit
`Session.execute(insert(Model), list[dict])` without RETURNING. Each row supplies
its stable typed identity and declared tenant. Single-tenant mappings use their
declared table UUID. The route copies caller dictionaries, prepares distinct
row/field-bound CF1 frames, and delegates grouping, dispatch and constraints to
the native ORM. It adds no crypto format, representation or provider authority.

Native checks cover heterogeneous rows, omitted/explicit NULL, `render_nulls`,
exact Unicode and VARCHAR space truncation, uniqueness, empty identity maps,
closed no-row Results, rollback and nested savepoint recovery. An earlier native
row constraint retains precedence over a later VARCHAR length error. Failed
pending ORM autoflush also retains precedence. A known bulk length failure
uses public constants in PostgreSQL assignment coercion, then returns the typed
failure with native Session activity and aborted-transaction behavior. Protected
text never becomes an error-carrier parameter.

The final bulk driver guard checks actual SQL, row identity, tenant and payload
bytes against the admitted batch after cursor listeners. Compiled parameters
alone cannot waive that check. Late context and payload replacements refuse
before the real psycopg INSERT methods. This strengthened processed-value check
is scoped to this bulk route. Exact stock savepoint-control clauses separately
require native SQL, empty parameters and unchanged attachment configuration.
They grant no data permit and retain native transaction objects and cleanup.

RETURNING, Core INSERT, upserts, statement-embedded values, INSERT SELECT,
SQL row expressions, legacy bulk methods and used callable/context/SQL/server
defaults remain unadmitted. Explicit values can bypass unused defaults.
Missing/cross-tenant context and unavailable/expired keys refuse without a
partial prefix. Async preparation cancellation reaches no data SQL and permits
a fresh retry. TEXT/VARCHAR single-tenant mappings with renamed attributes pass
bulk insertion, latest ORM edit, decrypt-back and native current-value removal.
Separate independent-process package-free evidence retains its earlier scope.

**VERIFIED:** the first 26-case run retains 15 admission failures and
11 passing controls. An intermediate implementation run retains 15 failures,
including invalid test read shapes and the missing native savepoint route.
After correcting those helpers and the guard, all 26 pass in 8.41 seconds.
The expanded driver, cancellation, autoflush and removal run passes 38 cases
in 14.82 seconds. Two subsequent multi-field UUID/signed-int64 cases pass in
0.58 seconds, including nil UUID, zero and signed limits.

The Python 3.12.3 / SQLAlchemy 2.1.3 full regression passes **1,953 tests and
18 subtests** in 611.83 seconds, with three separate-environment skips and
48 existing DISTINCT deprecation warnings. These are pytest terminal counts.
The receipt's call-report aggregate includes subtests and excludes two
collection skips. All 130 Python files remain stable during that run.
The subsequent test-only change strengthens final-driver injection controls.
All **44 bulk cases** pass in 13.26 seconds at the final 130-file bundle.
They cover valid CF1 in same-type Binary substitution, in-place Binary mutation,
coherent compiled/driver row substitution, actual SQL replacement, and a
savepoint replacement that must not grant a data-write permit.

The alternate Python 3.13.12 / SQLAlchemy 2.0.51 cell passes these 44 cases
and the pinned unchanged Smolink lifecycle, **45 cases** in 22.91 seconds.
It uses existing read-only installed dependency paths and psycopg 3.3.6's
Python implementation. The initial bare interpreter lacked psycopg and stopped
before database probes. No package was installed into Smolink. Its 38 original
Python source hashes match. The HTTP/repository/ORM lifecycle, real disposable
Redis, current-value removal and import-denied child pass at the recorded
single protected `Url.destination` scope. The full alternate cell, complete
external application suite and fresh-cluster backup profiles were not rerun.
All product bytes match the full regression and release receipts. Both final
cell receipts have stable 130-file hashes that match the final worktree.

Reproducible offline wheel/sdist builds, SBOM inspection and all 36 installed
package files pass, including CLI startup. Provider custody, independent review,
other event-mutation routes and the seven full production gates remain UNKNOWN.

Evidence: [native oracle](_reset/bulk-insert-native-oracle-20261023.json),
[initial admission failures](_reset/bulk-insert-red-20261023.json),
[intermediate failures](_reset/bulk-insert-first-20261023.json),
[guarded native behavior](_reset/bulk-insert-guard-20261023.json),
[adversarial and removal cases](_reset/bulk-insert-boundary-20261023.json),
[multi-field context](_reset/bulk-insert-context-20261023.json),
[full regression](_reset/bulk-insert-full-20261023.json),
[final primary matrix](_reset/bulk-insert-final-20261023.json),
[alternate matrix and application](_reset/bulk-insert-sa20-20261023.json),
[pinned app evidence](_reset/bulk-insert-smolink-app-20261023.json),
[reproducible archives](_reset/bulk-insert-release-20261023.json), and
[installed wheel](_reset/bulk-insert-installed-20261023.json).

The later [shared guard checkpoint](#shared-driver-event-checkpoint-2026-10-23)
extends cursor-event mutation checks to flush/read routes. Exact receipt count
reporting remains open. Broader DML/RETURNING, used defaults,
online lifecycle and external qualification remain separate product gaps.

## Rotation preparation status checkpoint: 2026-10-23

**IMPLEMENTED, bounded native verification:** `cryptalis status` now reads
payload and search preparation artifacts through their existing typed public
status APIs. It reports PREPARED, EXPANDED, BACKFILLED or ABORTED progress,
the source operation and its own operation, and the supplied preparation pin.
The scopes are `payload_rotation_preparation` and `search_rotation_preparation`.
Every preparation result keeps `runtime_metadata_matches: false`,
`verification: NOT_PERFORMED`, `effects: NONE` and exit 3. Recorded preparation
does not authorize an active application deployment.

Both Python and CLI preparation status repeat effective runtime privilege
admission before observing progress. Inspection uses a read-only repeatable
snapshot, without provider work or maintenance locks. An invalid preparation
pin fails before connection. A supplied restore binding is refused before its
file is read. Doctor continues to refuse preparation artifacts. This change
adds no adopted-target rotation support or publication authority.

Search planning now admits source types before reading source fields. Invalid
sources raise `external_policy_mismatch`, without connection or key work.
Missing search preparation and activation rows now use `missing_search_operation`
and `missing_search_activation`. Existing payload error codes remain unchanged.
Refusals retain source values, staged ciphertext, progress and native catalogs.

**VERIFIED:** the initial native run retains 23 failures and three passing
payload controls. The affected CLI, manifest inspection, Doctor, source/pin
admission, runtime privilege and generation workflows pass **369 cases** in
178.30 seconds. New cases cover both purposes and all four recorded phases,
exact public-API counters, unsafe grants and recovery after REVOKE, invalid
authority before connection, missing forward-pinned operations, no-key and
read-only paths, wrong credentials, typed invalid source and missing activation.

The eight phase/purpose cases pass again in 7.59 seconds with actual runtime
credentials after strengthening that single test function. The final run's
127 Python source/test/script hashes match at start, end and final inspection.
All product bytes still match the 369-case regression and release receipts.
The wheel and sdist build reproducibly offline. All 36 installed files match the wheel, and
installed CLI startup plus rotation-status help pass.
The previous full regression and fresh-cluster profiles below remain
revision-bound. They were not rerun for this interface and diagnostic change.
Provider custody, host authority, frame freshness and the complete operational
status contract remain unqualified. All seven full gates remain UNKNOWN.

At this checkpoint, next work targeted ordinary ORM bulk inserts. The later
[bulk checkpoint](#mapped-bulk-insert-checkpoint-2026-10-23) records that bounded
admission. Broader DML and RETURNING remain product gaps.

Evidence: [initial native failures](_reset/rotation-status-red-20261023.json),
[affected regression](_reset/rotation-status-regression-20261023.json),
[actual runtime credentials](_reset/rotation-status-runtime-20261023.json),
[final reproducible archives](_reset/rotation-status-release-final-20261023.json), and
[final installed wheel](_reset/rotation-status-installed-final-20261023.json).

## Doctor and runtime status checkpoint: 2026-10-23

**IMPLEMENTED, bounded native verification:** `cryptalis doctor` inspects an
existing ACTIVE deployment through its actual declared runtime connection.
`migration.diagnose_deployment` admits the immutable plan, exact ACTIVE pin,
and optional matching restore binding before connection. It repeats shared
attachment admission in one read-only, repeatable-read catalog snapshot.
The check covers runtime identity, target, lineage, effective privileges and
schema. It requests no keys, authenticates no frames, takes no maintenance
locks and changes no rows, journal or schema.

Doctor reports `runtime_deployment: PASS` only after inspection and connection
cleanup succeed. Provider keys, frame authentication, query routes, writer
exclusion, host authority and recovery capacity remain UNKNOWN. The aggregate
result also remains UNKNOWN. Exit 0 means the scoped observed check passed.
Typed observed refusals report FAIL. Unavailable inspection, cleanup and output
failures report UNKNOWN. Diagnostics retain safe primary and cleanup codes
without raw connection or exception details.

Ordinary ACTIVE/PENDING `migration.status` now repeats shared runtime privilege
admission before reporting matching metadata. Previously it could return
success after unsafe schema CREATE or journal-column UPDATE grants. Restored
status already used the shared check. All status remains keyless and reports
`verification: NOT_PERFORMED`.

**VERIFIED:** the initial Doctor controls retain 12 failures. Two separate
native controls directly expose the unsafe ACTIVE status success. The corrected
focused run passes 88 cases in 39.50 seconds. They include real runtime and
owner connections, unsafe ACTIVE/PENDING grants, same-artifact recovery after
REVOKE, malformed/unpublished authority before connection, wrong credentials,
native transaction settings, forbidden provider work, unchanged native
snapshots, lost output and actual post-close failures. Doctor accepts later
ACTIVE edits after search rotation and refuses a changed predecessor chain.
Two final cleanup controls pass in 0.68 seconds after adding sanitized close
stage evidence alongside the primary refusal.

Search TEXT and VARCHAR fresh-cluster profiles each pass one export and
30 restore cases in the approved isolated-cluster harness. Doctor accepts
the adopted binding through the actual runtime role. A source-incompatible
binding fails before connection. The same profiles still complete latest-value
CRUD, decrypt-back and native removal. The wheel and sdist build reproducibly
offline. All 36 installed files match the wheel, and installed CLI startup and
Doctor help pass. These checks qualify no release or production provider.

**VERIFIED, Python 3.12.3 / SQLAlchemy 2.1.3 local cell:** full regression passes
**1,887 tests and 18 subtests**, with three separate-environment skips and
48 existing DISTINCT ON deprecation warnings, in 519.66 seconds. The wrapper
counts subtests with passed cases. All 125 Python source/test/script hashes
match at run start, run end and final inspection. The fixing fingerprint is
`worktree-c6c36eaa97093f1b`; cleanup, both fresh-cluster profiles and release
checks match the same current product bytes. The SQLAlchemy 2.0.51 cell and
pinned Smolink application were not rerun for this slice. Earlier evidence
below remains revision-bound.
The command does not scan pre-adoption applications, qualify providers,
authenticate host policy, prove freshness or observe all query/write routes.
All seven full gates remain UNKNOWN.

The later [preparation status checkpoint](#rotation-preparation-status-checkpoint-2026-10-23)
adds both preparation formats and purpose-correct search diagnostics.
Pre-adoption application scanning and provider diagnostics remain product gaps.

Evidence: [initial Doctor failures](_reset/doctor-native-red-20261023.json),
[direct status failures](_reset/doctor-status-privilege-red-20261023.json),
[first corrected native controls](_reset/doctor-native-green-20261023.json),
[expanded native controls](_reset/doctor-native-final-20261023.json),
[final cleanup diagnostics](_reset/doctor-cleanup-final-20261023.json),
[TEXT adopted recovery](_reset/fresh-cluster-restore-20261023-15.json),
[VARCHAR adopted recovery](_reset/fresh-cluster-restore-20261023-16.json),
[reproducible archives](_reset/doctor-release-20261023.json),
[installed wheel](_reset/doctor-installed-20261023.json), and
[full regression](_reset/doctor-full-20261023.json).

## Search-key rotation and backup checkpoint: 2026-10-23

**IMPLEMENTED, bounded native verification:** search rotation now has planning,
encrypted staging, status, source-only cancellation, deterministic sealing and
atomic cutover through the shared publication engine. P uses
`cryptalis.search-rotation/v1`. Sealed activation A uses
`cryptalis.transition/v4`, with exact target observations, policy digests,
batch limits and source-to-P-to-A ancestry. Current code retains v1/v2/v3 artifact reading. Older host readers must upgrade
before v4 publication.

The target retains exact source wrappers and root material. Each selected
search policy adds one independent root above every retained search generation.
Payload selection stays unchanged. Searchable frames receive new terms and
fresh authenticated nonces. Storage-only frames and search-less tenant policies
remain exact. The adapter admits retained search readers only under an exact
bound deployment policy and pins one active query namespace. It never queries
multiple generations with OR.

The two generation workflows share encrypted shadows, atomic cursor commits,
guards, paired verification and publication mechanics. Their policy and header
checks remain explicit. Native public UPDATE maintains equality and unique
indexes inside the terminal transaction. A target uniqueness conflict rolls
back the entire switch. Host copy-rate and WAL estimates must include index
maintenance. Bounded preparation does not bound the full-table terminal copy,
memory overhead, storage capacity, pause or WAL.

**VERIFIED:** 92 focused cases pass in 70.64 seconds. They include 32 search
crypto controls with independent frame composition, 13 retained-reader controls,
12 native search lifecycle cases, three actual lost-COMMIT/SIGKILL recovery
cases and 32 existing payload cases. The search cases cover TEXT/VARCHAR,
multiple tables/tenants, exact storage-only bytes, Unicode/NULL, equality/IN,
uniqueness, latest-value removal, target outage cancellation, authentic target
resealing, late proof/counter/ancestor drift, post-UPDATE/guard-drop rollback,
an injected target HMAC collision with native SQLSTATE `23505`, and a
search/payload/rewrap/search chain. A fresh process publishes the same saved
artifacts after SIGKILL. Native conflict and recovery tests preserve committed
source or target bytes and recorded progress.

Search TEXT and VARCHAR fresh-cluster profiles each pass one export and
**29 restore cases**. A protected edit after publication differs from A's sealed
snapshot and survives recovery. A separate KDF/HMAC decoder authenticates the
generation-two search term under the unchanged payload root. The existing
`cryptalis.restore/v1` binding admits the backup, current edits and native removal.
A valid old search-generation frame remains refused despite retained keys.
Original protection and root-rewrap profiles pass 23 and 26 restore cases,
respectively, with one rotation-only skip each. The payload/VARCHAR profile
passes 29 cases. Each also passes its own export on the same product source.

**VERIFIED, Python 3.12.3 / SQLAlchemy 2.1.3 local cell:** full regression passes
**1,869 tests and 18 subtests**, with three separate-environment skips, in
505.01 seconds. The wrapper counts subtests with passed cases. The 48 existing
warnings concern SQLAlchemy DISTINCT ON deprecation. All start/end Python hashes
match. The SQLAlchemy 2.0.51 cell and pinned Smolink application were not rerun
for this slice.

After the full run, one trailing blank line was removed from the recovery test.
Its AST and source locations remain identical. The three native lost-COMMIT
and SIGKILL controls pass again in 20.35 seconds at the final test hashes.
All product bytes still match the full and release receipts.

The wheel and sdist build reproducibly offline. A disposable installed wheel
matches all 36 packaged files and starts its CLI. Initial extraction errors
and a test-clock defect remain in the failed receipts. The corrected focused
run above reruns every affected control.

All three rotation workflows now have bounded local product paths. Rotation
on adopted targets, production custody/retirement, authenticated host authority,
online migration and independent review remain open. All seven full gates
remain UNKNOWN. Search rotation deletes no retained keys and establishes no
unlinkability or cryptographic-erasure guarantee.

The later [Doctor checkpoint](#doctor-and-runtime-status-checkpoint-2026-10-23)
adds bounded diagnosis and aligns ACTIVE/PENDING status with deployment
privilege admission. Status remains a metadata observation and reports
cryptographic verification as `NOT_PERFORMED`.

Evidence: [first extraction failures](_reset/search-foundation-first-20261023.json),
[corrected extraction and clock failures](_reset/search-foundation-corrected-20261023.json),
[native lifecycle and recovery](_reset/search-rotation-native-first-20261023.json),
[full regression](_reset/search-rotation-full-20261023.json),
[test-only normalization](_reset/search-rotation-test-normalization-20261023.json),
[final recovery controls](_reset/search-rotation-final-recovery-20261023.json),
[TEXT search recovery](_reset/fresh-cluster-restore-20261023-10.json),
[VARCHAR search recovery](_reset/fresh-cluster-restore-20261023-11.json),
[older payload recovery](_reset/fresh-cluster-restore-20261023-12.json),
[older rewrap recovery](_reset/fresh-cluster-restore-20261023-13.json),
[original protection recovery](_reset/fresh-cluster-restore-20261023-14.json),
[reproducible archives](_reset/search-rotation-release-20261023.json), and
[installed wheel](_reset/search-rotation-installed-20261023.json).

## Reverse runtime admission checkpoint: 2026-10-23

**IMPLEMENTED, bounded native verification:** decrypt-back rechecks effective
runtime privileges before staging, resume, publication and journal retirement.
Read-only reverse status uses the same admission. Plaintext-role planning now
uses the shared privilege predicate before provider work, while preserving
`unsafe_plaintext_runtime_role` for unsafe plaintext credentials.

The trusted host pin selects the runtime boundary. PREPARED, EXPANDED,
BACKFILLED, VERIFIED and PLAINTEXT_PENDING require the source protected runtime.
PLAINTEXT_ACTIVATING, PLAINTEXT_ACTIVE and REMOVING require the declared plaintext
runtime. A mutable journal phase cannot select a different role. An actually
absent journal with REMOVED skips both role checks and retains native metadata
inspection. The old protected runtime can retire after plaintext publication.
Checks observe effective privileges. They do not freeze later administrative
changes or authenticate publication, writer fencing or credential retirement.

**VERIFIED:** the initial native controls expose **19 failures** and retain one
passing removal retry. After the fix, all **20 cases pass** in 11.34 seconds.
They cover unsafe journal-column and schema grants across every admitted host
phase, initial plaintext planning, forged journal phase selection, unchanged
rows/progress on refusal and preserved native edits after removal. Terminal
retries succeed after the former runtime restrictions change. These tests do
not delete the shared roles or prove a production credential-retirement process.

**VERIFIED, Python 3.12.3 / SQLAlchemy 2.1.3 local cell:** full regression passes
**1,809 tests and 18 subtests**, with three separate-environment skips, in
473.95 seconds. The wrapper counts subtests with passed cases. The 48 existing
warnings concern SQLAlchemy DISTINCT ON deprecation. All start/end Python hashes
match.

TEXT and VARCHAR payload backups each pass one export and **28 restore cases**
on new PostgreSQL 16 clusters at the final Python hashes. The adopted paths
retain independent generation-two decoding, later edits, decrypt-back, native
metadata and package removal under the stricter runtime admission.

The wheel and sdist build reproducibly offline. The installed wheel matches all
35 packaged files and starts its CLI. Search reindex and rotation on adopted
restored targets remain SPECIFIED. Production custody, authenticated authority,
independent review and all seven full gates remain unqualified or UNKNOWN.

At this reverse checkpoint, search rotation remained SPECIFIED. The later
[search checkpoint](#search-key-rotation-and-backup-checkpoint-2026-10-23) above
adds bounded native preparation, publication and backup evidence.

Evidence: [native failures](_reset/reverse-runtime-red-20261023.json),
[phase-aware controls](_reset/reverse-runtime-first-20261023.json),
[full regression](_reset/reverse-runtime-full-20261023.json),
[TEXT recovery](_reset/fresh-cluster-restore-20261023-8.json),
[VARCHAR recovery](_reset/fresh-cluster-restore-20261023-9.json),
[reproducible archives](_reset/reverse-runtime-release-20261023.json), and
[installed wheel](_reset/reverse-runtime-installed-20261023.json).

## Payload-backup recovery and runtime admission checkpoint: 2026-10-23

**IMPLEMENTED, bounded native verification:** the fresh-cluster harness accepts
`--payload-rotation`, with optional `--varchar`. It exports a published activation
plan A, its retained source/preparation ancestry and current protected data.
An attached application edits data after publication and before the dump.
Recovery preserves that edit, even though its frame differs from A's sealed
cutover snapshot. Existing `cryptalis.restore/v1` approval, fencing and binding
remain required. A database journal supplies no external authorization.

Restore admission now checks the host-pinned plan, exact predecessor chain,
strict journal state and inventory before behavioral schema probes or key work.
It also checks effective runtime privileges and protected-column metadata first.
The shared role check rejects owner membership, dangerous role attributes,
database/schema CREATE, protected-table TRIGGER/TRUNCATE and journal writes,
including column grants. Initial protection planning, active admission, adopted
binding admission and the shared maintenance executor use this check.

The initial recovery controls exposed ten failures. After the fixes, TEXT and
VARCHAR payload profiles each pass one export and **28 restore cases** on new
PostgreSQL 16 clusters. A separate decoder derives generation-two fixture keys
and authenticates current CF1 payloads and search terms. A valid generation-one
frame still fails adoption under the selected generation-two policy, even with
retained old keys. Other controls cover altered ancestry/proofs, unsafe grants,
late binding drift, attached search/edits, decrypt-back and native removal.
The older rewrap/VARCHAR profile passes one export and **26 restore cases**.
Its payload-only case is explicitly skipped. Seven ordinary native cases also
refuse unsafe privileges before provider work or database changes.

**VERIFIED, Python 3.12.3 / SQLAlchemy 2.1.3 local cell:** full regression passes
**1,789 tests and 18 subtests**, with three separate-environment skips, in
456.88 seconds. The 48 existing warnings concern SQLAlchemy DISTINCT ON
deprecation. All start/end Python hashes match.

The wheel and sdist build reproducibly without network access. A disposable
installed wheel matches all 35 packaged files and starts its CLI.
Search reindex and rotation on adopted restored targets remain SPECIFIED.
Production custody, authenticated host authority and independent security review
remain unqualified. All seven full gates remain UNKNOWN.

Evidence: [initial failures](_reset/fresh-cluster-restore-20261023-3.json),
[TEXT recovery](_reset/fresh-cluster-restore-20261023-6.json),
[VARCHAR recovery](_reset/fresh-cluster-restore-20261023-5.json),
[older rewrap recovery](_reset/fresh-cluster-restore-20261023-7.json),
[shared role controls](_reset/restore-runtime-focused-20261023.json),
[full regression](_reset/restore-runtime-full-20261023.json),
[reproducible archives](_reset/restore-runtime-release-20261023.json), and
[installed wheel](_reset/restore-runtime-installed-20261023.json).

## Sealed payload cutover checkpoint: 2026-10-23

**IMPLEMENTED, bounded native verification:** `rotation.seal_payload_rotation`
authenticates a complete BACKFILLED preparation P against its original source
and actual target frames. It returns a deterministic immutable transition/v3
activation plan A without changing database data or authority. A pins target
frame/membership observations, target policies, validated scan limits, explicit
copy/WAL estimates and the exact source/preparation ancestor chain. The host must
persist A before `rotation.switch_payload_rotation`.

Cutover repeats source and paired target authentication under maintenance locks.
It compares the target observations to host-pinned A, copies ciphertext into the
existing public columns, removes P's shadows and exchanges its guards for A's.
Source SUPERSEDED to P, P SUPERSEDED to A and A PENDING commit atomically. The
public columns keep their physical identities, constraints, grants and equality
indexes. A bounded post-copy pass authenticates the installed target against A.
A PENDING retry uses target custody and A's exact lineage. It does not replay the
retired original source. Switched preparation cannot resume or cancel.

Shared `migration.apply` admits A only for ACTIVATING/ACTIVE publication. An
ACTIVATING retry repeats target verification even when the journal claims ACTIVE.
A genuine ACTIVE pin permits later application edits. Publication also checks
current owner, metadata, inventory and strict progress shape before provider work.
Native controls preserve current edits through decrypt-back and package removal,
including a payload/rewrap/payload chain with five exact ancestors.

**VERIFIED:** 37 final native cases pass in 51.77 seconds. They cover text/VARCHAR,
multiple tables and tenants, storage-only fields, exact Unicode/NULL values,
equality/IN/uniqueness, deterministic sealing, scope ordering across artifact
reload, authentic target reseal after sealing, forged ACTIVE journals, late ACL
or inventory drift, malformed artifacts and journal counters, missing ancestry,
rollback after native public UPDATE and guard removal, real cutover/publication
COMMIT reply loss, SIGKILL and fresh-process disk-artifact publication. The initial
17 cases and expanded 33-case run also pass after the missing-API red controls.

**VERIFIED, Python 3.12.3 / SQLAlchemy 2.1.3 local cell:** full regression passes
**1,782 tests and 18 subtests**, with three separate-environment skips, in
450.53 seconds. The wrapper counts subtests with passed cases. The 48 existing
warnings concern SQLAlchemy DISTINCT ON deprecation. All start/end Python hashes
match. Fresh-cluster and pinned Smolink harnesses were not rerun for this cutover
slice.

The wheel and sdist build reproducibly without network access. The installed wheel matches all 35 packaged
files and starts its CLI. Dependency installation remains outside that check.

The final server copy is one complete-table write in an atomic terminal
transaction. It has no committed chunk bound. Host estimates include five
verification passes and the copy. A seven-row local observation records 3.70 ms
inside the native copy and 114.09 ms for the whole switch call. The cluster WAL
counter advances 2,056 bytes during the copy interval and 13,640 bytes across the
whole call. These are one synthetic sample and cluster-wide observations, not
isolated operation attribution, throughput, capacity or pause guarantees.

Search reindex and rotation on adopted restored targets remain SPECIFIED.
At this cutover checkpoint, fresh-cluster payload backups remained unqualified.
The later [recovery checkpoint](#payload-backup-recovery-and-runtime-admission-checkpoint-2026-10-23)
adds that bounded evidence. Production provider/authority evidence and independent
security review remain open. All seven full gates remain UNKNOWN.

Evidence: [missing APIs](_reset/payload-cutover-red-20261023.json),
[first native run](_reset/payload-cutover-first-20261023.json),
[expanded recovery](_reset/payload-cutover-expanded-20261023.json),
[final native controls](_reset/payload-cutover-final-native-20261023.json),
[full regression](_reset/payload-cutover-full-20261023.json),
[copy observation](_reset/payload-cutover-copy-observation-20261023.json),
[reproducible archives](_reset/payload-cutover-release-20261023.json), and
[installed wheel](_reset/payload-cutover-installed-wheel-20261023.json).

## Payload staging and cancellation checkpoint: 2026-10-23

**IMPLEMENTED, bounded native verification:** `rotation.apply_payload_rotation`
stages encrypted payloads under the immutable preparation artifact P. The source
public frames, equality indexes and source ACTIVE journal remain intact. The
executor checks source authority, schema, journal inventory, retained custody and
both policies before expansion. Exact P guards and nullable bytea shadows commit
together. Existing source attachments reject the changed maintenance schema.
Keep all application workers stopped during preparation.

Each chunk holds write-excluding table locks across its length probe, reads,
shadow writes and progress marker. Complete rows obey P's aggregate logical byte
budget. Python, driver, database and provider overhead remain outside that budget.
This establishes no RSS or capacity bound. Resume authenticates the committed
prefix and preserves its randomized frames. It rejects copied source-generation
frames, unauthentic target frames, inconsistent cursors and altered guards or schema.
BACKFILLED requires a complete source/target value, NULL, generation and search-header
check. Every BACKFILLED retry repeats authentication. `max_chunks` can stop after
the last data chunk while phase remains EXPANDED. A later call performs the final
verification and records BACKFILLED.

`status_payload_rotation` reads recorded progress without keys. It reports
`NOT_PERFORMED` and no runtime metadata match. It supplies no data-verification or
publication authority. `abort_payload_rotation` requires the external source ACTIVE
pin. It authenticates the source, removes only P's exact shadows and guards, and
records P as ABORTED in one transaction. It needs no target provider. Terminal
retries preserve later source edits and reject a superseded source. Adopted restore
is outside this implementation.

**VERIFIED:** 26 native execution/recovery cases pass in 30.54 seconds. Controls
cover text/VARCHAR, multiple tables and tenants, equality and storage-only fields,
NULL and exact Unicode values, source edits after planning, prior rewrap lineage,
provider outage, invalid authority, tampering, cancellation before expansion and
after full backfill, process death after a committed chunk, and fresh-process
artifact reload. Real proxies discard committed chunk and cancellation replies.
Injected failures after native shadow UPDATE and guard DROP preserve the previous
committed state and writer fence. Resume preserves committed prefix nonces and
source bytes/index identity.

**VERIFIED, Python 3.12.3 / SQLAlchemy 2.1.3 local cell:** full regression passes
**1,745 tests and 18 subtests**, with three separate-environment skips, in
386.13 seconds. The wrapper counts subtests with passed cases. The 48 existing
warnings concern SQLAlchemy DISTINCT ON deprecation. All start/end Python hashes
match. The separate fresh-cluster and pinned Smolink harnesses were not rerun for
this preparation slice.

The wheel and sdist build reproducibly without network access. The installed-wheel check matches all 34
packaged files and starts its CLI under a fresh bytecode cache. Dependency
installation remains outside that check. Receipt source hashes match the worktree.
The initial red run reports the missing execution APIs. The first 13 native
controls pass before the expanded recovery cases. Review found no additional
concrete bypass. That review supplies no independent security qualification.

At this staging checkpoint, sealing A, final cutover and publication remain
SPECIFIED. The later [sealed cutover checkpoint](#sealed-payload-cutover-checkpoint-2026-10-23)
adds these operations. P cannot enter `migration.apply`. The
[two-artifact decision](decisions.md#payload-rotation-preparation-and-activation-2026-10-23)
requires host persistence of A before the destructive switch. A journal marker
cannot replace that authority. Search rotation, restored-target rotation,
production custody and independent review remain open. All seven full gates
remain UNKNOWN.

Evidence: [initial controls](_reset/payload-stage-red-20261023.json),
[first implementation](_reset/payload-stage-first-20261023.json),
[expanded native recovery](_reset/payload-stage-recovery-20261023.json),
[full regression](_reset/payload-stage-full-20261023.json),
[reproducible release](_reset/payload-stage-release-20261023.json), and
[installed wheel](_reset/payload-stage-installed-wheel-20261023.json).

## Payload-rotation planning checkpoint: 2026-10-23

**IMPLEMENTED, bounded native verification:** `plan_payload_rotation` emits an
inactive source-pinned `PayloadRotationPlan`. It checks current deployment,
schema and journal inventory in one read-only repeatable-read snapshot. The
target retains every exact source wrapper/root and adds one independent payload
root above all retained payload generations. Search custody remains unchanged.
Historical readers and tenants with no current rows remain necessary.

The artifact records source frame/membership/schema observations, public contexts,
policy digests, distinct preparation/successor IDs, aggregate batch limits and
host-measured backfill/verification/storage/WAL estimates. It contains no wrapper
bytes, root material or plaintext digest. The length probe uses bigint arithmetic
and admits only the complete-row prefix within the aggregate logical budget
before retrieving frames. Python, driver, database and provider overhead remain
outside that budget. This establishes no capacity or RSS bound.

**VERIFIED:** 163 focused native cases pass in 68.45 seconds across new planning,
root-rewrap planning/execution/cancellation, and the independent payload-batch
controls. They include real multi-field/multi-tenant budgets, historical/deleted
tenant readers, exact retained-wrapper refusal, fresh payload generation,
snapshot stability under a concurrent commit, safe artifact/input admission and
cleanup-time expiry. The shared offline rewrap protocol also passes five groups
with synthetic artifacts. That offline run establishes no PostgreSQL behavior.

**VERIFIED, Python 3.12.3 / SQLAlchemy 2.1.3 local cell:** full regression passes
**1,719 tests and 18 subtests**, with three separate-environment skips, in
367.59 seconds. The wrapper counts subtests with passed cases. The 48 existing
warnings concern SQLAlchemy DISTINCT ON deprecation. All start/end Python hashes
match. This run includes the root-rewrap cancellation API from the preceding
checkpoint as well as the new planner. The separate fresh-cluster and pinned
Smolink harnesses were not rerun for this read-only slice.

Initial controls found the missing API. The first implementation passes 84 cases.
Review then reproduces three boolean estimate-counter acceptances and a lease
expiry mislabeled as a policy change. Explicit supplied-counter validation and
preserved `KeyUnavailable` classification close those defects. Full regression
also covers current-value edits, text/VARCHAR, provider/data/inventory failures,
RNG failure and unrepresentable estimates. Afterward, a test-only strengthening
supplies a matching preparation pin to the application executor. Its native
control passes and refuses preparation as publication authority before connection.
Product source is unchanged from the full run.

The wheel and sdist build reproducibly without network access. The installed-wheel
check matches all 33 packaged files, starts its CLI under a fresh bytecode cache,
and inspects the genesis manifest. Dependency installation remains outside this
check. Current release source hashes match the artifact receipt.

At this planning checkpoint, staged execution, paired sealing, final cutover and
cancellation remain SPECIFIED. The later [staging checkpoint](#payload-staging-and-cancellation-checkpoint-2026-10-23)
adds preparation and cancellation. The preparation cannot enter the application publication executor.
The [two-artifact decision](decisions.md#payload-rotation-preparation-and-activation-2026-10-23)
requires actual verified target observations in a separate immutable activation
artifact before destructive switch. No journal result hash supplies authority.
Search rotation, adopted-restore rotation, production custody and independent
review remain open. All seven production gates remain UNKNOWN.

Evidence: [initial controls](_reset/payload-plan-red-20261023.json),
[first implementation](_reset/payload-plan-first-20261023.json),
[counter review](_reset/payload-plan-review-red-20261023.json),
[lease control](_reset/payload-plan-lease-red-20261023.json),
[focused native run](_reset/payload-plan-focused-20261023.json),
[full regression](_reset/payload-plan-full-20261023.json),
[final publication refusal](_reset/payload-plan-final-admission-20261023.json),
[offline protocol](_reset/payload-plan-offline-20261023.json), and
[installed wheel](_reset/payload-plan-installed-wheel-20261023.json).

## Pending rewrap cancellation checkpoint: 2026-10-23

**IMPLEMENTED, bounded native verification:** `rotation.abort_rewrap` cancels
an exact PENDING successor under the republished source ACTIVE pin. The source
pin supplies host authority. The deterministic successor selects shared executor
locks, target/owner checks and the current verification estimate. Cancellation
does not repeat historical protection work or require target-provider access.

Under maintenance locks, cancellation checks exact source/successor digests and
lineage, original source state, source policy and retained roots, current frames,
membership, schema and guards. Source ACTIVE, guard removal and a retained
ABORTED successor marker commit together. A terminal retry checks current source
authority and leaves later application edits intact. A later operation that
supersedes the source prevents an old retry from reviving it.
Use the source plan and its current pin for read-only status. The canceled
successor cannot activate. Generic protection abort remains a pre-switch operation.

**VERIFIED:** all 18 initial cancellation cases pass. The expanded native run
passes **177 cases** in 118.36 seconds across cancellation, cutover/planning,
protection, reverse/removal and multi-table protection. Controls cover target
outage, source outage, wrong keys/pins/approval, digest/link/guard/schema/frame
and membership tampering, unknown operations, current pause admission, wrong
native target before key access, and transaction rollback after guard removal.
An actual proxy loses the terminal cancellation COMMIT reply. Inspection and
retry retain the committed terminal state. A process dies after committed
cancellation; an independent process reloads disk artifacts and resumes without
target custody. Frame bytes and equality-index identity remain unchanged.
A second rewrap can be canceled after application edits, then decrypt-back and
approved removal recover the latest native values.

After one additional multi-table/multi-tenant control, all **52 cancellation and
cutover cases** pass in 38.39 seconds. The control rejects writes on both paused
tables, then releases their shared guard function atomically. It preserves all
three protected fields and independently decodes their public-fixture frames.
Attached source-policy reads match both tenant datasets after cancellation.
Product source is unchanged from the expanded run. The final receipt retains
matching Python hashes.

Initial controls failed because the API was absent. Review found a conservative
pause refusal against historical protection estimates. Cancellation now uses the
successor estimate after separate source-authority admission. One expanded
invocation named a nonexistent test module and ran no tests. The corrected run
above passes with matching start/end Python hashes.

The updated wheel and sdist build reproducibly without network access. The
installed-wheel check matches all 33 packaged files and starts its CLI under a
fresh bytecode cache. Dependency installation remains outside that check.
The full 1,647-test suite and text/VARCHAR fresh-cluster drills below precede
this additive cancellation API. They were not repeated for this slice.
Adopted-restore rewrap/cancellation, payload rotation, search reindex, production
provider/host authority qualification and independent review remain open.
All seven production gates remain UNKNOWN.

Evidence: [initial controls](_reset/rewrap-abort-red-20261023.json),
[first implementation](_reset/rewrap-abort-first-20261023.json),
[invalid test path](_reset/rewrap-abort-focused-20261023.json),
[expanded native run](_reset/rewrap-abort-focused-corrected-20261023.json),
[final cancellation/cutover run](_reset/rewrap-abort-final-20261023.json), and
[installed wheel](_reset/rewrap-abort-installed-wheel-20261023.json).

## Active root-rewrap checkpoint: 2026-10-23

**IMPLEMENTED, bounded native verification:** a rewrap proposal now derives a
deterministic `cryptalis.transition/v2` successor plan. `apply_rewrap` uses the
existing maintenance executor, locks and writer guards. It rechecks current
source policy, schema, journal and complete source/target frame observations.
One transaction preserves payload/search bytes, creates a successor PENDING row
and marks the old immutable operation SUPERSEDED. No key or wrapper bytes enter
PostgreSQL. Both complete policies remain host-owned recovery artifacts.

The host publishes the successor separately. Existing `migration.apply` with
an ACTIVATING pin authenticates the target and compares host-pinned observations
before dropping guards. An already-ACTIVE journal claim also undergoes that check
on an ACTIVATING retry. True ACTIVE pins allow later ordinary application edits.
Runtime and reverse/removal admit only the exact host-pinned predecessor chain.
Known ancestors are removed only through the existing approved removal path.

**VERIFIED so far:** 165 focused lifecycle cases pass. The expanded native
recovery/planner run passes 60 cases, including unchanged frames, native search
and edits, two custody changes followed by latest-value decrypt-back/removal,
wrong policy/pin/approval, altered source/journal, malformed successor artifacts,
predecessor tampering, and false journal ACTIVE claims. An actual local transport
proxy discards a terminal COMMIT reply. Inspection then resumes the same pending
operation without changing frames. A process is killed after committed pending
progress; an independently started process reloads disk artifacts and public
fixture keys, inspects, resumes and activates. Frame bytes and equality-index
OID/relfilenode remain unchanged in that restart control.

The first execution run found a callable-only test helper. Review controls then
reproduced a journal-claim bypass and raw invalid-input errors. Admission now
precedes dispatch, and publication retry verifies host observations.
The source review found no additional concrete defect in that pass. AI review
supplies no independent security qualification.

**VERIFIED, local Python 3.12.3 / SQLAlchemy 2.1.3 cell:** full regression passes
**1,647 tests and 18 subtests**, with three separate-environment skips, in
300.23 seconds. The wrapper counts subtests with passed cases. The 48 existing
warnings concern SQLAlchemy DISTINCT ON deprecation. All start/end Python hashes match.

After that run, fresh-cluster profile checks gained explicit manifest/successor
admission and a negative original-policy adoption control. Product source did
not change. Each rewrapped source type, text and VARCHAR, then passes one export
and 15 restore cases on a new PostgreSQL 16 cluster. These cover retained-frame
recovery, exact target-policy admission, stale authority refusal, approved adoption,
latest-value decrypt-back/removal, and native metadata. The original public-root
oracle remains independent of the target-policy factory. Profile labels alone
cannot satisfy successor admission. Both runs retain matching Python hashes.
The separate pinned Smolink harness was not rerun for this slice.

The wheel and sdist build reproducibly without network access. The disposable
installed-wheel check matches all 33 packaged files, imports verified source
under a fresh bytecode cache, starts the CLI and inspects the genesis manifest.
Installation used `--no-deps` and does not qualify dependency installation.

At this checkpoint, pre-publication rewrap abort, rewrap on an adopted restored target, payload
rotation, search reindex, production provider qualification and independent
review remained open. The later cancellation checkpoint above closes the bounded
pending-abort gap. Host writer exclusion and publication remain operator
assertions. The rotation build slice is incomplete. All seven gates remain UNKNOWN.

Evidence: [initial acceptance](_reset/rewrap-execution-red-20261023.json),
[first implementation](_reset/rewrap-execution-first-20261023.json),
[review controls](_reset/rewrap-execution-review-red-20261023.json),
[focused lifecycle](_reset/rewrap-execution-focused-20261023.json), and
[process/transport recovery](_reset/rewrap-execution-recovery-20261023.json),
[full regression](_reset/rewrap-execution-full-20261023.json),
[text backup recovery](_reset/fresh-cluster-restore-20261023.json),
[VARCHAR backup recovery](_reset/fresh-cluster-restore-20261023-2.json), and
[installed wheel](_reset/rewrap-execution-installed-wheel-20261023.json).

## Development environment recovery: 2026-10-23

**VERIFIED:** the default sandbox denies IPv4 socket creation with errno 1 and
mounts `.git` read-only. Both private test files are present, parse correctly,
and have mode `0600`. The user authorized environment repair and supported
scoped execution approval. That path passes a temporary Git write/read/delete
check and both private-role PostgreSQL probes. No credential, service, database,
ownership, mount, or sandbox-policy change was needed. The failed operation
was not repeated under the unchanged execution boundary.

`scripts/test_postgres.py --development-preflight` now diagnoses Git writes,
dependencies, tools, private test-file provenance, socket creation, PostgreSQL
16, same-target role separation, and observed privileges. It uses read-only
database transactions, runs no pytest test, and never prints connection values
or raw exceptions. Runtime must lack database CREATE, cannot assume the owner,
and cannot own application schemas or relations. PostgreSQL tool discovery checks
actual major versions. Missing separate-harness tools remain UNKNOWN.
Target authorization remains UNKNOWN: file provenance and successful probes
cannot establish that an operator authorized a database as disposable.

**VERIFIED:** the [default-sandbox diagnostic](_reset/development-preflight-sandbox-final-20261023.json)
reports Git and socket failures as `authorized_alternative`, before database access.
The [approved diagnostic](_reset/development-preflight-approved-final-20261023.json)
reports all observed prerequisites PASS. Other diagnostics classify automatically
repairable tool discovery, external prerequisites, and implementation defects.
The [engineering procedure](../ENGINEERING_PLAYBOOK.md#development-environment-checks)
states the invocation and approval boundary.

Initial controls found the missing diagnostic mode. A first combined run then
found that in-process CLI tests cleared the outer runner's admitted URLs.
The tests now restore those environment values. A later controlled CREATE
observation exposed a false acceptance. The final gate rejects it without any
native grant change. Failed controls remain separate from successful evidence.

**VERIFIED, local Python 3.12.3 / SQLAlchemy 2.1.3 cell:** the full suite passes
**1,620 tests and 18 subtests**, with three separate-environment skips, in
314.88 seconds. Its wrapper count includes the 18 subtests. The 48 existing
warnings concern SQLAlchemy DISTINCT ON deprecation. After the final
diagnostic-only CREATE guard and tool-discovery classification, **76 focused
checks pass** in 17.24 seconds, including native rewrap/provider and source-evidence
regression. Both runs retain matching start/end Python hashes.
The full suite was not repeated after that final diagnostic-only change.
Fresh-cluster and pinned Smolink harnesses were not rerun in this step.

Git integrity checks pass. Existing dangling objects were left untouched.
The planner and offline-test files retain their original checkpoint hashes.
The native planner tests changed only to use the documented `KeyUnavailable`
diagnostic. The original branch, HEAD ancestry, prior commits and receipts remain
preserved. Ordinary reads still use the default sandbox. Required Git writes
and PostgreSQL verification use the scoped approved execution path.
All seven production gates remain UNKNOWN.

Evidence: [initial mode controls](_reset/development-preflight-red-20261023.json),
[test-isolation failure](_reset/development-preflight-focused-20261023.json),
[runtime CREATE control](_reset/development-runtime-create-red-20261023.json),
[full suite](_reset/environment-rewrap-full-20261023.json), and
[final focused run](_reset/development-preflight-final-20261023.json).

## Inactive rewrap planning checkpoint: 2026-10-23

**IMPLEMENTED, VERIFIED in the named local cell:** `cryptalis.rotation.plan_rewrap`
creates an inactive `RewrapPlan` for an ACTIVE protection plan. It inspects the
host pin, native target, journal and protected schema in one read-only
repeatable-read transaction. It compares exact source and target roots,
including historical readers and tenants with no remaining rows, then
authenticates current frames under both policies. The artifact contains policy,
membership, frame and schema digests, public contexts, required readers and a
host-measured verification estimate. It contains no root or wrapper bytes.

Planning changes neither database state nor current publication authority.
Current writers can continue. Observations describe one snapshot and cannot
authorize a later switch. Execution must recheck current data and host policy
under maintenance. Structural artifact validation does not authenticate host
inputs or reconstruct root identities from an opaque source-policy digest.

**VERIFIED:** all 35 native planner cases pass within the 55-case planner/provider
run and the later full and focused suites above. Cases cover ordinary application
edits, concurrent commits during the snapshot, retained roots, deleted tenants,
missing/wrong roots, pin/journal/schema/frame mutations, malformed artifacts,
invalid rates, cleanup-time expiry and random-ID failure. Refusals preserve
native source state and suppress private provider/error markers.
The first native run found seven diagnostic-spelling mismatches in the tests.
The tests now expect the existing security-contract code `KeyUnavailable`.

Five standalone offline protocol groups also pass. The local wheel installs
without network access into a disposable Python environment, matches all 33
installed files against the archive, starts the CLI with a fresh bytecode cache,
and inspects the supplied genesis manifest. Repeat builds match.
Installation used `--no-deps` and does not qualify dependency installation.

Earlier default-sandbox probes stopped before pytest. Their blocker is resolved
through the approved path above. The original collection-only and offline
receipts remain historical evidence. This checkpoint covered inactive planning.
The [later execution checkpoint](#active-root-rewrap-checkpoint-2026-10-23)
adds successor cutover and shared activation. Payload rotation and search reindex
remain unimplemented.
The rotation build slice remains incomplete. All seven full gates remain UNKNOWN.

Evidence: [first native run](_reset/rewrap-plan-native-first-20261023.json),
[planner/provider run](_reset/rewrap-plan-native-green-20261023.json),
[offline checkpoint](_reset/rewrap-plan-offline-final-20261023.json), and
[installed artifact](_reset/rewrap-plan-installed-wheel-20261023.json).

## Numeric API admission: 2026-10-22

**IMPLEMENTED:** protection and reverse planners share safe numeric input and
duration checks. Integers that overflow float conversion fail as invalid measured
rates or invalid maintenance approval. A positive finite rate that produces an
infinite or unrepresentable duration fails with `unrepresentable_pause_estimate`.
Estimated seconds must fit the canonical integer range before artifact creation.

The change preserves fractional rates and separate backfill, verification, and
combined pause estimates. It adds no rate floor or substitute estimate.
An invalid maintenance approval fails before a transition starts.

**VERIFIED, initial controls:** ten native public API cases reproduced raw
`OverflowError`. They cover both rate fields in both planners, minimum positive
float rates, huge integer rates, and huge maintenance pauses in both executors.
Catalog facts, rows, journal inventory, schema relations, and function definitions
stay unchanged during these failures. Twelve existing rate controls pass.

**VERIFIED, corrected controls:** all 119 focused native tests pass in 63.15 seconds.
They include the ten refusals, fractional-rate artifact reload and both complete
transitions, artifact admission, crash/resume, protection, and reverse controls.
All 97 Python files retain their start/end hashes. The wheel and sdist build
reproducibly; the installed-wheel check matches 32 files and starts the CLI.

The full suite and fresh-cluster checks were not repeated for this input-only
change. Their evidence in the next section belongs to the preceding restore-policy
revision.
All seven production gates remain UNKNOWN.

Evidence: [initial controls](_reset/numeric-admission-red-20261022.json),
[corrected controls](_reset/numeric-admission-focused-20261022.json), and
[installed wheel](_reset/numeric-admission-release-installed-20261022.json).

## Restore frame policy admission: 2026-10-22

**IMPLEMENTED:** restore adoption accepts two exact PostgreSQL 16 forms of the
declared CF1 frame check. Both forms use the same length bounds, header bytes,
generation rules, and quoted column. The shared storage check refuses any other
admitted expression. Malformed-frame probes remain additional evidence.
They cannot establish general SQL equivalence.

Binding identity checks also compare every recorded restatement with its source
field and known forms. This applies when a reverse plan embeds a restore binding.
An older binding with weaker bounds cannot supply policy authority.
Constraint comparison uses schema, table, and name so an incoming foreign key
cannot hide a declared frame CHECK with the same name.

**VERIFIED, initial fault reproduction:** the native isolated-cluster run passes
ten existing controls and reproduces four false acceptances. Lowering the minimum
frame length by one or raising the maximum by one still passed the finite probes.
Adoption issued a binding, and a matching older binding passed deployment checks.
The source journal and retained values stayed unchanged in these controls.
The same run records the exact flattened PostgreSQL expression used by the fix.

Evidence: [initial export](_reset/fresh-cluster-export-20261022-26.json) and
[initial restore controls](_reset/fresh-cluster-restore-20261022-26.json).

**VERIFIED, corrected local controls:** 172 native storage and lifecycle tests pass.
Both text and VARCHAR fresh-cluster paths pass one export and 15 restore cases.
These include the four refusals, the valid same-name foreign key, and the full
adopted attach/search/edit/decrypt-back/removal path. The native restored expression
matches the known flattened form exactly. Journal and row snapshots stay unchanged
on refusal. The pinned Smolink lifecycle also passes in its existing alternate
Python 3.13 / SQLAlchemy 2.0.51 cell.

The wheel and sdist build reproducibly. The installed-wheel check matches 32 files
and starts the CLI. No new dependency, artifact format, provider, or publication
authority is introduced.

The [full native suite](_reset/frame-policy-full-sa21-20261022.json) passes
**1,567 tests and 18 subtests**, with three separate-environment skips and
48 existing SQLAlchemy warnings. All 97 Python files retain their start/end
hashes. The wrapper records 279.31 seconds in the unchanged local dependency cell.
All seven production gates remain UNKNOWN.

Evidence: [focused controls](_reset/frame-policy-focused-20261022.json),
[text restore](_reset/fresh-cluster-restore-20261022-27.json),
[VARCHAR restore](_reset/fresh-cluster-restore-20261022-28.json),
[Smolink](_reset/frame-policy-smolink-sa20-20261022.json), and
[installed wheel](_reset/frame-policy-release-installed-20261022.json).

## Host plan input admission: 2026-10-22

**IMPLEMENTED:** protection artifacts now pass compiler lock admission before
use. This check uses PostgreSQL identifier quoting without opening a connection.
Compiler root, model, and field members use explicit canonical sets.
Required row and pause estimates must be nonnegative integers; booleans are refused.
Display limits must be nonempty text. Measured rates, when present, must form
a complete positive finite pair. Historical protection artifacts may omit both rates.

Reverse artifacts require a mapping of table IDs to catalog snapshots.
They reuse the compiler's catalog structure checks for relation, columns,
constraints, indexes, and dependencies. Recorded column names must match the
source model. Estimate checks also run before reverse maintenance admission.
Live catalog and host-policy checks remain separate.

**VERIFIED:** the initial run reproduced 14 failures and passed two controls.
The first corrected run passes 138 tests. The final focused run passes 64,
including 24 plan-admission controls. Empty compiler locks and model inventories,
malformed catalog containers and scalar types, missing estimates, unknown compiler
members, and invalid pause values now fail during artifact construction.
Valid v1/v2 artifacts with no measured rates retain their bytes, legacy display,
and public PREPARED status. Ordinary valid protection and reverse reloads also pass.

The first full run passed 1,564 tests and 18 subtests, with three failures in
VARCHAR controls that expected rejection during apply. They now expect constructor
rejection and retain their original native PREPARED-state check.
That correction changes tests only. All 64 VARCHAR and admission checks pass.

The [final full native suite](_reset/plan-admission-full-final-sa21-20261022.json)
passes **1,567 tests and 18 subtests**, with three separate-environment skips
and 48 existing SQLAlchemy warnings. All 97 Python files retain their start/end
hashes. The wrapper records 319.37 seconds in the unchanged local dependency cell.

An initial native control demonstrated vacuous ACTIVE metadata acceptance with
an empty model inventory, a matching changed host pin, and a changed journal digest.
This required coordinated malformed host input; it was not a database-only bypass.
The constructor now rejects that artifact before the journal can change.
CLI controls use an unreachable database address and receive exit 2,
`InvalidInput`, at the input stage. No private marker or traceback appears.
Previously those calls attempted connection and returned operational exit 4.

The final pinned Smolink lifecycle passes in its existing alternate Python 3.13 /
SQLAlchemy 2.0.51 cell. Both final fresh-cluster paths pass one export and ten
restore cases. The reproducible wheel and sdist retain the current product bytes;
the installed-wheel check matches 32 files and starts the CLI.

This admission check validates artifact structure and selected compiler invariants.
It does not authenticate the host, validate values, qualify providers, or establish
writer exclusion. All seven production gates remain UNKNOWN.

Evidence: [initial controls](_reset/plan-admission-red-20261022.json),
[first focused run](_reset/plan-admission-focused-20261022.json), and
[final controls](_reset/plan-admission-final-focused-20261022.json).
Further evidence: [VARCHAR controls](_reset/plan-admission-varchar-final-20261022.json),
[Smolink](_reset/plan-admission-final-smolink-sa20-20261022.json),
[VARCHAR restore](_reset/fresh-cluster-restore-20261022-24.json),
[text restore](_reset/fresh-cluster-restore-20261022-25.json), and
[installed wheel](_reset/plan-admission-release-installed-20261022.json).

## Host-bound staged schema: 2026-10-22

**IMPLEMENTED:** paused protection and reverse operations now compare staged
catalog facts with host artifacts as well as their journal snapshots.
The validated plan kind selects the transformation. No new artifact format,
publication authority, key policy, or plaintext fallback is introduced.

Protection retains the native columns, constraints, indexes, and dependencies
from the source lock. It adds the declared nullable bytea shadows and checks
their CF1 frame constraints and equality indexes against the physical shadow names.
Reverse inspection uses the protected catalog snapshot in the host-pinned
reverse plan, captured after source admission. It adds only the declared nullable
plaintext staging columns, with native type limits and collation from the source lock.
Logical comparison permits different physical column slots.

**VERIFIED:** 24 initial native controls reproduced false acceptance.
The correction passes 175 focused tests. The attacks cover extra columns,
native type and constraint changes, missing indexes, shadow and staging defaults,
nullability and type changes, weaker frame checks, changed equality expressions,
index ordering and uniqueness, and a reverse VARCHAR(64) stage changed to VARCHAR(63).
The valid writer fence remains unchanged while each test forges the matching
journal schema. Status, backfill, verification, and abort refuse the change.
Journal state, counters, catalog, guard, and row values remain unchanged on refusal.

The [full native suite](_reset/paused-schema-full-sa21-20261022.json) passes
**1,543 tests and 18 subtests**, with three separate-environment skips and
48 existing SQLAlchemy warnings. All 96 Python files retain their start/end
hashes. The wrapper records 278.15 seconds; the local dependency cell is unchanged.
Both fresh-cluster paths pass one export and ten restore cases. The pinned
Smolink lifecycle passes in its existing alternate Python 3.13 / SQLAlchemy 2.0.51 cell.
The wheel and sdist build reproducibly. The installed-wheel check matches 32 files
against the wheel and starts the CLI.

The reverse baseline is a host-pinned snapshot, not database authority.
The later [input admission slice](#host-plan-input-admission-2026-10-22) adds
shared catalog structure checks. Structural validity does not establish live semantics.
The check covers recorded catalog facts. It does not establish value verification,
unchanged external function bodies, freshness, or host writer exclusion.
All seven production gates remain UNKNOWN.

Evidence: [initial controls](_reset/paused-schema-red-20261022.json),
[focused checks](_reset/paused-schema-focused-20261022.json),
[Smolink](_reset/paused-schema-smolink-sa20-20261022.json),
[VARCHAR restore](_reset/fresh-cluster-restore-20261022-20.json),
[text restore](_reset/fresh-cluster-restore-20261022-21.json), and
[installed wheel](_reset/paused-schema-release-installed-20261022.json).

## Host-bound paused writer fence: 2026-10-22

**IMPLEMENTED:** every paused protection and reverse inspection now checks the
writer fence against the host plan. The shared check also runs before plaintext
publication. It requires the operation's expected function body, invoker security,
owner, search path, enabled statement trigger, and absence of extra user triggers.
The journal's guard snapshot remains an additional continuity check.
It cannot authorize a different function or trigger inventory.

**VERIFIED:** 18 initial controls reproduced false acceptance. Two protection
resumes committed PENDING before the previous final check detected the change.
The correction moves admission before backfill, verification, switch, abort,
status, and plaintext publication. All 22 adversarial cases now pass.
Each case first observes SQLSTATE `55000` from the restricted runtime login.
It then replaces the guard body or enables `SECURITY DEFINER` and forges the
matching journal snapshot. The damaged guard admits an actual UPDATE.
The probe write rolls back. The refused operation preserves journal state,
counters, catalog, guard, and row values, including staging columns.

Two revised fault controls also pass. A native row lock stops the second chunk
after its first update; the test kills the worker and checks rollback before
an independent process resumes. A journal trigger suppresses the marker update;
the typed `journal_marker_write_failed` failure leaves zero committed rows,
chunks, and frames. These controls replace application-trigger injections that
the stricter fence admission now refuses.

The pinned Smolink lifecycle passes in its existing alternate Python 3.13 /
SQLAlchemy 2.0.51 cell. Both fresh-cluster paths pass one export and ten restore
cases. The wheel and sdist build reproducibly; the installed-wheel check matches
32 files against the wheel and starts the CLI.

The [full native suite](_reset/paused-guard-full-sa21-20261022.json) passes
**1,519 tests and 18 subtests**, with three separate-environment skips and
48 existing SQLAlchemy warnings. The wrapper records 255.69 seconds.
All 95 Python files retain their start/end hashes. The local dependency cell
is unchanged. Independent release and provider qualification remain UNKNOWN.

This check does not establish host writer exclusion or protect against an
authorized owner changing the database after inspection. Staged schema admission
is separate; the later [staged schema slice](#host-bound-staged-schema-2026-10-22)
adds that host check. All seven production gates remain UNKNOWN.

Evidence: [initial controls](_reset/paused-guard-red-20261022.json),
[first integration run](_reset/paused-guard-focused-20261022.json), and
[24 final controls](_reset/paused-guard-final-focused-20261022.json).
Further evidence: [Smolink](_reset/paused-guard-smolink-sa20-20261022.json),
[VARCHAR restore](_reset/fresh-cluster-restore-20261022-18.json),
[text restore](_reset/fresh-cluster-restore-20261022-19.json), and
[installed wheel](_reset/paused-guard-release-installed-20261022.json).

## Host-bound protected schema: 2026-10-22

**IMPLEMENTED:** protection status, deployment checks, attachment, activation,
and reverse planning now check the live protected catalog against the host's
source lock and the declared CF1 transformation. A database journal can no
longer redefine that contract by recording the same unauthorized schema change.
No new authority artifact or format is introduced.

The shared check retains unchanged native columns, constraints, indexes,
and dependencies from the lock. It verifies protected bytea columns, validated
frame checks for storage and search, and the declared equality index expression,
uniqueness, flags, opclasses, collation, and sort options.
PENDING also requires the host-derived pause function, enabled trigger,
and absence of extra user triggers. Native constraints with equal names on
different tables remain distinct. Logical column slots may change on restore.

Restore adoption uses the same host check. A changed live frame check that
matches a forged journal receives no automatic exception. Existing explicit
CHECK restatements still require the adoption probes and exact binding match.
Catalog deparsing uses a shared temporary search path and restores the caller's
setting. A SQL failure retains its original error for caller rollback.

**VERIFIED:** the initial 14 native controls reproduced false acceptance.
The corrected lifecycle run passes 89 tests. The expanded run passes 219 tests,
including 38 host-contract controls for altered native metadata, weakened frame
checks, changed equality expressions, ordering and uniqueness, rewritten or
disabled pause functions, and additional triggers. Each attack changes the
catalog and its journal snapshot together.

The pinned Smolink lifecycle also passes in its existing alternate Python 3.13 /
SQLAlchemy 2.0.51 cell. Both fresh-cluster paths pass one export and ten restore
cases, including three new pre-adoption forgery controls. Existing retained-frame
reads, admitted CHECK restatements, decrypt-back, metadata restoration, removal,
and native writes pass on each new cluster.

The [full native suite](_reset/active-contract-full-sa21-20261022.json) passes
**1,497 tests and 18 subtests**, with three separate-environment skips and
48 existing SQLAlchemy warnings. All 94 Python files retain their start/end
hashes; the wrapper records 248.70 seconds. The local dependency cell is unchanged.
The wheel and sdist build reproducibly. The installed-wheel check verifies
32 files against the wheel and starts the CLI. These are local release checks;
signing, publication, and independent rebuild remain UNKNOWN.

This check binds the catalog properties recorded by the source lock and the
declared CF1 storage objects. It does not prove unchanged bodies of external
functions, domain definitions, or collation implementations. Generated index
tablespaces and storage options are outside this check. Status still performs
no key or value verification. Writer exclusion, freshness, provider qualification,
and independent review remain separate requirements. All seven gates remain UNKNOWN.

Evidence: [initial controls](_reset/active-contract-red-20261022.json),
[focused checks](_reset/active-contract-adversarial-20261022.json),
[Smolink](_reset/active-contract-smolink-sa20-20261022.json),
[VARCHAR restore](_reset/fresh-cluster-restore-20261022-16.json),
[text restore](_reset/fresh-cluster-restore-20261022-17.json), and
[installed wheel](_reset/active-contract-release-installed-20261022.json).

## Verification source stability: 2026-10-22

**IMPLEMENTED:** the PostgreSQL test wrapper now captures Python source hashes
before pytest and compares them with a second snapshot after pytest.
It resolves the checkout from its own file and runs pytest in that checkout.
The starting revision and source hashes identify the input bundle.
Previously, the receipt recorded only the final files.
A source edit during tests could therefore describe bytes that the run did not load.

Different start/end bytes, added files, or removed files force wrapper exit 4.
This check also applies when no receipt is requested.
The receipt retains the original `pytest_exit_code`, the wrapper `exit_code`,
starting `source_test_sha256`, and a `source_stability` result with changed paths.
`source_after_sha256` records only changed paths. A removed file has a null hash.
Unchanged sources preserve the original pytest exit code.
Unreadable source produces an explicit failure without raw filesystem diagnostics.
Both private credential files still reload and both database roles still probe first.
No failed database probe is retried.

**VERIFIED:** eight initial controls failed. The corrected focused run passes
12 wrapper controls and ten real reverse-status CLI tests.
The wrapper controls use disposable source trees and controlled inner pytest results.
They check successful and failed pytest outcomes, no-receipt runs, additions,
removals, and equal-size edits that retain the original modification time.
These controlled outcomes do not establish application correctness.
The following real CLI cases also pass, which checks fixture environment cleanup.

The snapshot covers Python files under `src/cryptalis`, `tests`, and `scripts`.
It compares two observations. It does not detect an edit that is restored between them.
Keep the checkout stable during verification. Dependencies, interpreter state,
configuration, and human review remain separate evidence boundaries.
Historical receipts remain immutable and predate this stability check.
All seven production gates remain UNKNOWN.

Evidence: [RED controls](_reset/evidence-stability-red-20261022.json) and [focused verification](_reset/evidence-stability-final-focused-20261022.json).

The [pinned Smolink rerun](_reset/evidence-stability-smolink-sa20-20261022.json)
also passes after the shared plaintext-metadata correction. It retains the
alternate Python 3.13 / SQLAlchemy 2.0.51 scope and the unchanged 38-file app snapshot.
Both [VARCHAR](_reset/fresh-cluster-restore-20261022-14.json) and
[text](_reset/fresh-cluster-restore-20261022-15.json) fresh-cluster paths pass
one export and seven restore cases. Each new receipt records unchanged start/end
source hashes. The existing product release bytes remain unchanged by this
wrapper-only slice. No dependency or provider qualification is added.

The [full native run](_reset/evidence-stability-full-sa21-20261022.json) passes
**1,459 tests and 18 subtests**, with three separate-environment skips and
48 existing SQLAlchemy warnings. The wrapper records 238.73 seconds.
Its receipt reports identical start/end hashes for all 93 Python files,
`pytest_exit_code: 0`, and `exit_code: 0`. The exact local dependency cell
remains Python 3.12.3, SQLAlchemy 2.1.3, psycopg 3.3.6, and cryptography 50.0.2.

## Read-only reverse status: 2026-10-22

**IMPLEMENTED:** `cryptalis status` now accepts a `cryptalis.reverse/v1` plan.
The Python API is `cryptalis.deprotection.status(plan, engine, pin=pin)`.
The existing protection status behavior remains available.
Reverse output uses `scope: reverse_transition` and includes the source operation ID.

The API reads one PostgreSQL read-only, repeatable-read snapshot.
It checks the target, supplied reverse pin, source journal identity, operation
inventory, phase, committed counters, schema, and writer fence.
Before the plaintext switch, it checks the protected source or paused schema.
After that switch, it checks native plaintext metadata and captured column metadata.
The restored-target path uses the binding already embedded in the reverse plan.
An additional CLI binding must match that embedded binding exactly.

The output retains `verification: NOT_PERFORMED`, `authority: HOST_SUPPLIED_PIN`,
and `effects: NONE`. No key resolver or maintenance consent is required.
Status neither decrypts data nor changes publication policy.
Exit 0 requires metadata that matches the supplied `PLAINTEXT_ACTIVE` or `REMOVED` pin.
Other phases remain incomplete. Existing input, uncertainty, and operational exit
classes remain 2, 3, and 4.

After removal, the journal is absent. Status reports null counters in JSON
and UNKNOWN counters in text. It does not substitute zero or a plan estimate.
It checks the native schema and captured metadata before reporting REMOVED.
A missing journal under an earlier pin remains an explicit failure.
A false removed pin over protected tables also fails.

**VERIFIED, local PostgreSQL 16:** the focused status, CLI, protection, and reverse
run passes 81 tests. The additional adversarial run passes 41 tests.
The native controls cover all reverse phases, aborted work, terminal removal,
concurrent commits, malformed progress, source/pin mismatch, schema and comment
drift, disabled guards, and safe connection, cleanup, and output failures.
A real write attempt receives SQLSTATE 25006 in the status transaction.
The snapshot test sees the old committed prefix while another executor advances.
The next status call sees the new committed prefix.

The RED controls first showed the missing API and CLI rejection of reverse plans.
An initial test listener intercepted executor setup. The corrected listener
isolates the status transaction. Missing evidence never becomes a successful status.
A later negative control changed both the plaintext schema and its journal copy.
It first produced a false match. Shared plaintext inspection now compares the
native schema with the original host lock, checks the exact enabled guard,
and checks captured metadata. Status, activation, and removal use that same check.
Three removal regressions exposed a changed error code. The correction preserves
`metadata_not_restored:source_metadata` and the existing journal-retention behavior.
No fresh value verification, retained-backup disposition, key/provider qualification,
or deployment-wide writer exclusion follows from metadata inspection.
All seven full gates remain UNKNOWN.

Evidence: [focused](_reset/reverse-status-green-20261022.json), [adversarial](_reset/reverse-status-adversarial-20261022.json), and [CLI RED](_reset/reverse-status-cli-red-20261022.json).
The [final metadata controls](_reset/reverse-status-metadata-final-20261022.json) pass seven cases,
including the [forged-journal negative control](_reset/reverse-status-journal-red-20261022.json).
Fresh PostgreSQL 16 clusters each pass one export and seven restore cases:
[VARCHAR](_reset/fresh-cluster-restore-20261022-12.json) and
[historical text](_reset/fresh-cluster-restore-20261022-13.json).
Those runs observe reverse PREPARED, PLAINTEXT_PENDING, PLAINTEXT_ACTIVE, and
REMOVED through the embedded adoption binding.
The [final release check](_reset/reverse-status-release-installed-final-20261022.json)
passes repeat-build identity, archive and SBOM checks, 32 installed-file comparisons,
and isolated CLI startup. Installation uses `--no-deps`; runtime dependency
qualification remains separate.


The [final full suite](_reset/reverse-status-full-sa21-20261022-2.json) passes
**1,447 tests and 18 subtests**, with three separate-environment skips and
48 existing SQLAlchemy warnings. The wrapper records 244.89 seconds.
All 92 source/test hashes match the final worktree. The exact local cell uses
Python 3.12.3, SQLAlchemy 2.1.3, psycopg 3.3.6, and cryptography 50.0.2.
The skipped external-app and fresh-cluster modules retain their separate evidence.
The external Smolink suite was not rerun for this status slice.
No production provider, host publication system, or independent review is qualified.

## Pinned Smolink adoption: 2026-10-22

**VERIFIED, bounded:** Smolink revision `498d24bae999ed53ad85e1c1f1a09ea7fa151aa4`
completes a native, protected, and post-removal workload on PostgreSQL 16.
The test extracts 38 Python files with local Git. It checks their hashes and
import origins. It changes no application source, model declaration, or query.
The original FastAPI app supplies the URL endpoint, authentication dependency,
service, repositories, Snowflake IDs, and response validation.
HTTP checks cover URL creation, duplicates, invalid authentication, invalid
aliases, expired URLs, invalid input, and real Redis rate-limit refusal.
Repository and ORM calls cover reads, current-value updates, deletion, and refresh.

Only `Url.destination` is protected. The profile uses storage-only VARCHAR(2048)
and an explicit single-tenant declaration. `owner_id` remains application data.
The test does not infer authorization or tenant scope from that foreign key.
Protected cursor parameters contain no destination marker. Native database
reads find CF1 frames. Decrypt-back retains the latest destination and restores
the native character limit. A fresh process runs the original app again with
all Cryptalis imports denied.

Adoption requires a manifest, key resolver, writer inventory, maintenance
approval, deployment pins, and a replacement session dependency.
The test also uses a private schema through connection settings, public test
settings, a seeded verified user, and disposable Redis through a Unix socket.
No external key custody or deployment-wide writer exclusion is established.
Email search, password-hash protection, other endpoints, the complete application
suite, a second external app, and packaged Python 3.13 installation remain open.

The run exposed two product defects. Catalog definition digests depended on
the caller's search path. Catalog reads now use the compiler's canonical
`pg_catalog` path and restore the caller's setting. Database failures retain
their primary SQLSTATE and require rollback. A real division-by-zero control
checks the original error and the restored path after rollback.
Attachment also clears each protected mapper's flush cache. The engine cache
alone did not remove INSERT and UPDATE processors compiled before attachment.
Both native and external controls first failed, then passed after this change.
The first full run found eight read-only route assertions. Canonical reads now
use SELECT-based setting functions, so those strict assertions remain unchanged.
The mapper cache is a private SQLAlchemy dependency. Keep its regression when
upgrading SQLAlchemy.

Two external cells pass: Python 3.13.12 with FastAPI 0.139.0 and SQLAlchemy
2.0.51 or 2.1.3. Both use greenlet 3.5.3, psycopg 3.3.6 in Python mode, and
cryptography 50.0.2. SQLAlchemy 2.1.3 uses its Python implementation.
The tests reuse existing packages and compatible cached modules without installation.
These cells differ from the pinned release dependencies. It is compatibility
evidence, not release qualification. All seven full gates remain UNKNOWN.

The [focused correction run](_reset/smolink-readonly-green-20261022.json) passes 154 tests.
The pinned app passes separately with [SQLAlchemy 2.0.51](_reset/smolink-final-sa20-20261022.json)
and [SQLAlchemy 2.1.3](_reset/smolink-final-sa21-20261022.json).
The source and cost records are [SA 2.0](_reset/smolink-application-final-sa20-20261022.json)
and [SA 2.1](_reset/smolink-application-final-sa21-20261022.json).
These receipts include all 38 source hashes and exact runtime versions.

The [full pinned-dependency run](_reset/smolink-full-sa21-20261022-3.json) passes
**1,405 tests and 18 subtests**, with three skips and 48 existing SQLAlchemy warnings.
The final wrapper receipt records 208.23 seconds. The skips cover the two fresh-cluster modules and
the external app, which has its own interpreter and receipts above.
The [release check](_reset/smolink-release-installed-20261022.json) passes matching
repeat builds, archive and SBOM checks, 32 installed-file comparisons, and isolated
CLI startup. Installation uses `--no-deps`; it does not qualify runtime dependencies.
The first build attempt could not write the default uv cache. The existing cache
under `/tmp` permits an offline run without a permission change.

Each source type also passes one export and seven restore/adoption/removal tests
on a new PostgreSQL 16 cluster: [VARCHAR](_reset/fresh-cluster-restore-20261022-10.json)
and [historical text](_reset/fresh-cluster-restore-20261022-11.json).
The [normalization record](_reset/smolink-evidence-binding-20261022.json) binds these
runs to the final helper file. The only later difference removes one trailing
blank line. Its Python syntax tree is identical, and all other 89 source/test
hashes match. The historical receipts remain unchanged.
A sandbox approval-review timeout prevented the first command from starting.
The permitted retry passed both private-role probes and completed the harness.
No failed database probe was retried, and no host permission policy changed.

## Native VARCHAR support: 2026-10-22

**IMPLEMENTED:** the text family now includes native PostgreSQL `varchar(n)` and
unbounded `varchar`, with matching standard SQLAlchemy `String` or `VARCHAR` mappings.
Native `text` keeps its existing `Text` mapping contract.
The compiler rejects mismatched lengths, custom types, domains, and dialect variants.

Plans with a protected VARCHAR field emit `cryptalis.lock/v3` and require
`pg-varchar/v1`. Text-only plans still emit v2. Readers retain v1/v2 support.
The source schema records the native typmod. No field-source member or CF1 byte
format changes. Attachment now validates the full compiler lock before connection,
including standalone targets without a transition journal.

Protected writes preserve PostgreSQL character counts and excess-ASCII-space rules.
They encrypt the exact stored value after assignment coercion.
Pending ORM attributes retain their assigned value until refresh or expiration.
Equality query values receive no assignment coercion.
An overlength non-space value raises `VarcharLengthExceeded`, with SQLSTATE `22001`.
The error occurs during binding, before cursor execution. The failed session requires
rollback, as the native PostgreSQL flush does. Diagnostics omit the supplied value.
Authenticated plaintext beyond the declared character limit raises `RepresentationMismatch`.

Reverse staging uses the captured native type and typmod. Removal checks native
schema and metadata after journal retirement. The test restarts an isolated process
that imports no Cryptalis module, then completes native insert, update, read, and delete.
A fresh-cluster mode repeats backup, adoption, status, decrypt-back, and removal
with a VARCHAR source. The default mode retains historical text coverage.

The native oracle covers Unicode, composed/decomposed text, NULL, empty values,
ASCII and non-ASCII whitespace, trailing-space uniqueness conflicts, pending state,
refresh, exact typed query binds, async writes, and post-removal length enforcement.
Adversarial controls reject reader downgrades, missing reader dependencies, invalid
typmods, transformed mappings, transformed query binds, and overlength authenticated frames.
SQL parameter capture contains no protected input marker.

The [focused run](_reset/varchar-final-focused-20261022.json) passes 179 tests and 18 subtests.
This is local type and lifecycle evidence. It does not prove Smolink adoption,
a production provider, host writer exclusion, or independent security review.
All seven full gates remain UNKNOWN.

The [full suite](_reset/varchar-full-sa21-20261022.json) passes **1,402 tests and 18 subtests**, with two fresh-cluster
modules skipped and 48 existing SQLAlchemy warnings. The run took 186.02 seconds.
The local cell uses Python 3.12.3, SQLAlchemy 2.1.3, psycopg 3.3.6, and
cryptography 50.0.2. No SQLAlchemy 2.0.51 rerun occurred.

The separate orchestrator passes one export and seven restore tests for each
source type: [historical text](_reset/fresh-cluster-restore-20261022-9.json)
and [native VARCHAR(64)](_reset/fresh-cluster-restore-20261022-8.json).
Both paths preserve captured metadata through approved adoption and removal.
The VARCHAR path also checks the restored native character limit.
The [repeat release builds](_reset/varchar-release-20261022.json) match. Archive checks, SBOM export, isolated CLI startup,
and all 32 installed-file comparisons pass. Installation uses `--no-deps`.

Review exposed three admission gaps: standalone reader fences, failed-flush state,
and hidden dialect transformations. Negative controls first reproduced each gap.
The corrected tests pass. Earlier intermediate failures also included test-fixture
errors: a non-admitted index shape, an extraneous storage-only review, a duplicate
native restart value, and incorrect context-manager use for prepared keys.
The logging control now rejects its incomplete lock before connecting.
These changes strengthen admission. Valid connection paths retain real PostgreSQL coverage.

This slice removes the native VARCHAR type blocker. A pinned external application
still needs its own lifecycle and deployment evidence.
All seven full gates remain UNKNOWN.

## Source retrieval workflow: 2026-10-22

The repository instructions now define the reusable retrieval fallback.
Use local Git and files for product source, Firecrawl for external research,
and Playwright only when ordinary HTTP cannot retrieve the required rendered content.
Every Firecrawl scrape supplies its required `objective` with the URL.
A failed valid call switches retrieval method without an unchanged retry.

**VERIFIED:** the corrected call retrieved the official PostgreSQL 16 character-type
page with status 200, the expected final URL and title, and relevant body passages.
The earlier missing-objective response remains a failed retrieval.
This workflow change does not establish a product runtime capability.
No database suite ran for this documentation-only checkpoint.
New prose lint scores 0.66 per 100 words.

## Fractional measured rates: 2026-10-22

**IMPLEMENTED:** protection and reverse plans now reload their own decimal rate
observations. Previously, both planners accepted finite floating-point inputs,
but their artifact reader rejected every decimal JSON number.
Even a measured rate of `1000.0` could not pass that reader.

The transition reader shares the existing structural JSON limits.
It admits positive finite decimals only in `estimates.backfill_rows_per_second`
and `estimates.verify_rows_per_second`. A reverse artifact also admits those
same paths inside its embedded `source_plan`. Counters, target facts, locks,
and cryptographic policy keep their integer-only number contract.
Manifest inspection also keeps its integer-only contract.
The fix preserves the bytes and formats that the planners already emit.
It does not introduce a new rate encoding or change cryptographic formats.

**VERIFIED, local PostgreSQL 16 cell:** three lifecycle regressions first failed
([negative control](_reset/transition-rates-red-20261022.json)).
The corrected cases reload integer, integral-float, and fractional protection
plans, then protect and decrypt-back through a fractional reverse plan.
Independent native reads retain all seven current values in each case.
Negative controls refuse floating counters, target ports, lock facts, zero and
negative rates, NaN, infinity, and an overflowing exponent.
The [focused parser, status CLI, and transition run](_reset/transition-rates-green-20261022-2.json) passes 157 tests.

Throughput rates remain host observations. Pause estimates exclude drain, DDL,
index builds, publication delays, and capacity guarantees.
No production provider, authenticated deployment authority, or independent review
is qualified. All seven full gates remain UNKNOWN.

The full current-revision suite passes **1,363 tests and 18 subtests**, with two
fresh-cluster modules skipped and 48 existing SQLAlchemy warnings.

The [full receipt](_reset/transition-rates-full-sa21-20261022.json) records current source and test hashes.
The run took 178.81 seconds on Python 3.12.3, SQLAlchemy 2.1.3, psycopg 3.3.6,
and cryptography 50.0.2. No SQLAlchemy 2.0.51 rerun occurred.

One [export](_reset/fresh-cluster-export-20261022-6.json) and seven
[restore cases](_reset/fresh-cluster-restore-20261022-6.json) pass separately on a new PostgreSQL 16 cluster.
These cases retain the historical integer-rate artifact path through restore adoption,
status, decrypt-back, and package-free removal.

The [repeat release builds](_reset/transition-rates-release-20261022.json) match. Archive checks, SBOM export, isolated CLI startup,
and all 32 installed-file comparisons pass. Installation uses `--no-deps`.
This evidence does not qualify runtime dependencies or a production deployment.

## Read-only protection status: 2026-10-22

**IMPLEMENTED:** `cryptalis status PLAN --pin PIN --database-url-file PRIVATE_FILE`
reports one committed protection-transition snapshot. The Python API is
`cryptalis.migration.status(plan, engine, pin=pin, restore=binding)`.
The optional restore binding refers to an approved adopted backup.

The command checks the planned target, supplied external pin, journal identity,
and phase-specific schema or maintenance fence. It reports the committed phase,
row and chunk counts, external phase, metadata match, and a safe next action.
It uses a PostgreSQL read-only repeatable-read transaction. It needs no keys,
maintenance approval, or executor advisory lock. Concurrent executor progress
appears on the next request, rather than partway through the current snapshot.

`verification: NOT_PERFORMED` means that this request does not authenticate data,
check providers, or qualify host writer exclusion. An ACTIVE metadata match is
not production admission. Pin provenance remains the host's responsibility.
This command covers protection transitions. Reverse transitions, rotation,
retained-key obligations, and the full Doctor remain open.

Plan admission rejects missing or unknown top-level members, invalid identities,
and malformed basic containers before connection. Private inputs use bounded
regular-file reads. Diagnostics omit connection details and input values.

**VERIFIED, local PostgreSQL 16 cell:** the full suite passes **1,351 tests and
18 subtests**, with two fresh-cluster modules skipped and 48 existing SQLAlchemy
warnings. The [full receipt](_reset/status-full-sa21-20261022.json) records source and test hashes.
The run took 191.19 seconds. The current cell uses Python 3.12.3,
SQLAlchemy 2.1.3, psycopg 3.3.6, and cryptography 50.0.2.
No SQLAlchemy 2.0.51 rerun occurred.

The regressions cover all seven protection phases, one stable snapshot during
another executor's commit, enforced read-only writes, and inspection without the
executor lock. CLI tests cover private malformed inputs, wrong credentials,
text and JSON results, and actual output failure.
The [plan-shape negative control](_reset/status-plan-shape-red-20261022-2.json) recorded five failures and two passing refusals.
An earlier draft used an incorrect expected diagnostic code. Its separate RED
[receipt](_reset/status-plan-shape-red-20261022.json) remains historical test-development evidence.

One [export](_reset/fresh-cluster-export-20261022-5.json) and seven
[restore cases](_reset/fresh-cluster-restore-20261022-5.json) pass on a new PostgreSQL 16 cluster.
The adopted protected backup reports ACTIVE metadata through the new status API
before its native metadata checks, decrypt-back, and removal.
The standalone release suite passes eleven test groups. Repeat builds match,
[archive inspection and SBOM export](_reset/status-release-20261022.json) pass, and the installed wheel matches all
32 checked files. Installation uses `--no-deps`. Isolated CLI help passes.
Without runtime dependencies, the installed status command reports
`DependenciesUnavailable` with exit 4 and no traceback.
No production provider, authenticated host fencing, independent security review,
or release qualification is complete. All seven full gates remain UNKNOWN.

## Removal metadata and restored backups: 2026-10-22

**IMPLEMENTED:** removal now compares the current native catalog with lock v2
`source_metadata`, as well as the structural schema. A changed captured comment,
statistics target, or column grant raises `metadata_not_restored:source_metadata`.
The failed removal transaction retains the journal and its `PLAINTEXT_ACTIVE` state.
`check_removed` and repeated terminal removal requests use the same comparison.
A terminal retry first checks whether the retired journal exists, then checks the
actual package-free state. It does not query a deleted table or recreate a journal.
Lock v1 retains its existing boundary because it carries no `source_metadata`.

**VERIFIED, local PostgreSQL 16 cell:** six regressions first failed because drift
passed silently. The first correction exposed three terminal retries that queried the
missing journal. After both corrections, all 22 focused lifecycle, independent
application, and restore cases pass ([receipt](_reset/removal-metadata-green-20261022-2.json)). Native reads retain every current value.

The fresh-cluster scenario now seeds comments, a column grant with grant option,
statistics target, storage, compression, column options, index options, and extended
statistics. Native catalog assertions check both plaintext backup restoration and
adopted protected-backup recovery through decrypt-back and removal.
One export and seven restore cases pass on a new isolated cluster
([export](_reset/fresh-cluster-export-20261022-4.json),
[restore](_reset/fresh-cluster-restore-20261022-4.json)).

The full current-revision suite reports **1,322 passed, 2 skipped, 18 subtests passed**
in 175.32 seconds, with 48 existing SQLAlchemy deprecation warnings
([receipt](_reset/removal-metadata-full-sa21-20261022.json)). The skipped fresh-cluster
modules pass separately through the orchestrator above. The local runtime uses
Python 3.12.3, SQLAlchemy 2.1.3, psycopg 3.3.6, and cryptography 50.0.2.
No SQLAlchemy 2.0.51 rerun occurred.
The standalone release suite passes eleven test groups. The
[rebuilt artifact receipt](_reset/removal-metadata-release-20261022.json) records
matching repeat builds, archive inspection, SBOM export, and 32 installed-file
comparisons with isolated CLI startup. Installation still uses `--no-deps`.

A temporary pytest mutation removed the protected-column comment after restoration.
Before the fix, removal reported success and the native assertion found the missing
comment. That [expected failure](_reset/fresh-cluster-metadata-control-20261022.json) remains
recorded separately from positive evidence.
The mutation changed no product file. Qualification uses public synthetic roots.
No external provider, authenticated host fencing, or independent review is qualified.
All seven full gates remain UNKNOWN.

## Sandbox access recovery: 2026-10-22

The user authorized repair of the execution blockers and resumption of engineering.
Read-only inspection found correct filesystem ownership and readable credential files.
The sandbox mounted `.git` read-only and denied TCP socket creation with errno 1.
These observations identify execution restrictions, not a PostgreSQL authentication failure.

**VERIFIED:** approved execution outside the sandbox creates and removes a temporary
file in `.git`. The required `scripts/test_postgres.py --preflight-only` then passes
both fresh private-role probes. Credentials, database configuration, host permissions,
and sandbox policy remain unchanged. Ordinary repository reads still use the sandbox.
Required database tests and Git writes use scoped approved execution.

**VERIFIED, Python 3.12.3, SQLAlchemy 2.1.3, psycopg 3.3.6, cryptography 50.0.2:**
the full wrapper run reports **1,316 passed, 2 skipped, 18 subtests passed** in
188.95 seconds. The 48 warnings concern deprecated SQLAlchemy DISTINCT ON syntax.
The two skipped modules require the separate fresh-cluster orchestrator.
The [receipt](_reset/resumed-full-sa21-20261022.json) records current source hashes.
The standalone release suite also passes all eleven test groups.

The earlier failure receipts remain immutable historical evidence. Their blocked status
does not describe the successful approved execution path. Production provider selection,
deployment authority, and independent reviews remain external prerequisites.
All seven full gates remain UNKNOWN.

## Installed artifact identity: 2026-10-22

**IMPLEMENTED:** `scripts/release_check.py --python PATH` compares installed file bytes
with the wheel from the current build. It checks every original wheel file except installer-rewritten `RECORD`.
It rejects extra package files and requires the selected virtual environment.
It also checks the imported package origin. Isolated Python subprocesses use
a fresh bytecode cache, so preexisting unchecked bytecode cannot replace verified source.
The [receipt](_reset/release-install-binding-20261022.json) records the wheel hash and the number of compared files.

**VERIFIED, offline local cell:** the standalone release suite passes eleven test groups.
Four mutations previously passed incorrectly: changed module bytes, metadata, license,
and an extra package module. The corrected checker refuses all four.
A review probe showed that unchecked stale bytecode could execute despite matching
source. The corrected checker ignores that bytecode and executes the verified source.
An actual offline uv installation uses a new Python 3.13.12 environment.
It passes all 32 file comparisons and the isolated CLI help check. Installation used `--no-deps`.
This verifies package identity and the standard-library CLI, not runtime dependencies.

A startup-hook negative control exposed raw child diagnostics on failure.
Failures now report `Release.CommandFailed`, the tool name, and its exit status.
The injected private marker stays absent from the checker output.
Two builds also match, and archive inspection and SBOM export pass.

**Limits:** this check trusts the interpreter, installer, and host filesystem.
It does not sandbox Python startup hooks or prove dependency safety.
No production runtime, independent rebuild, or publication authority is qualified.
This checkpoint originally lacked PostgreSQL and Git access.
The sandbox recovery above supplies the later full-suite evidence and Git write path.
All seven full gates remain UNKNOWN.

## Release archive integrity correction: 2026-10-22

**IMPLEMENTED:** the release checker requires each wheel file exactly once in `RECORD`.
Every file except `RECORD` requires its SHA-256 hash and exact size.
Duplicate archive members, noncanonical paths, links, and special files are refused.
Wheel metadata must match the project name and version in `pyproject.toml`.
Directory entries must be empty and agree with their declared type.
The sdist checker applies exclusions below its single root directory and requires
project metadata at that root. These checks inspect archives without extraction.
The checker targets Cryptalis's unsigned artifacts, not every permitted wheel variant.

**VERIFIED, offline local cell:** the standalone command
`.venv/bin/python scripts/test_release_check.py` passes ten test groups.
Before the correction, the same tests reported 25 failing cases and four errors.
Review exposed seven further failures for directory payloads and distribution metadata.
The valid archive controls pass, including an empty wheel directory.
Two offline builds produce identical wheel and sdist hashes, and both archives pass
the corrected inspector. The SBOM export also passes. The [receipt](_reset/release-integrity-20261022.json) records source
and test hashes, artifact hashes, commands, and verification limits.

**BLOCKED:** `.venv/bin/python scripts/test_postgres.py --preflight-only` returns
`OperationalError`, exit 2. The run does not retry or substitute a database.
The full pytest suite remains unrun because its admission hook requires that preflight.
No database-dependent implementation changes or capability claims follow.
At this checkpoint, the optional clean-install probe lacked installed-artifact identity.
The installed-artifact correction above closes that gap with its own evidence.
Independent rebuild, publication, provider qualification, and human review remain open.
All seven full gates remain UNKNOWN.

## Lock v2 metadata capture and restore: 2026-10-21

**IMPLEMENTED:** new protection plans emit `cryptalis.lock/v2`. Each model records
`source_metadata` for protected columns: comment, statistics target, storage,
compression, options, and column grants; constraint and index comments; and extended
statistics with kind letters, sorted columns, statistics target, comment, and a
definition digest. Grants use `GRANTEE|PRIVILEGES|GRANTABLE` with canonical privilege
letters and `PUBLIC` as a valid grantee. The protection switch applies captured grants
to the ciphertext column. A catalog change after planning raises
`source_metadata_changed`; the reverse switch refuses changed grants and late metadata
on the ciphertext column, then restores the captured facts. A missing role raises
`acl_role_missing`. The restore compares the resulting catalog with `source_metadata`
and raises `metadata_restore_mismatch` on any difference. Extended statistics with
expressions and sequences owned by a protected column remain refused.

The reader accepts `cryptalis.lock/v1` and `cryptalis.lock/v2`. A v1 lock restores no
metadata because it carries none.

**VERIFIED, local PostgreSQL 16.15 cell:** capture, grant forwarding at `PENDING`,
drift, reverse refusal, and exact catalog restore pass in
`tests/test_protection_compiler.py`, `tests/test_deprotection.py`, and
`tests/test_migration.py`. The full suite reports **1,316 passed, 2 skipped** on
SQLAlchemy 2.1.3 ([receipt](_reset/lock-v2-full-sa21-20261021-3.json)).

**UNKNOWN:** the SQLAlchemy 2.0.51 cell was not rerun because its local virtual
environment is absent. The missing-role path is implemented but has no executable test
because the least-privilege owner cannot create or drop roles. Owned sequences remain
refused. Tablespace moves remain UNKNOWN (the local cell has no additional tablespace
and the least-privilege owner cannot create one). Physical column order still changes.

## Release artifacts and SBOM: 2026-10-21

**IMPLEMENTED:** `scripts/release_check.py` builds the wheel and sdist twice, compares
SHA-256 hashes, verifies every wheel `RECORD` digest and size, rejects forbidden archive
members, requires project metadata and the license file, scans runtime source for
network or telemetry import terms, and exports a CycloneDX 1.5 SBOM from the locked
runtime dependency set. Package metadata declares the MIT license and includes the
license file.

**VERIFIED, local Python 3.12.3 and uv 0.12.12 cell:** two consecutive builds produced
identical wheel and sdist hashes. The wheel has 39 members; its `RECORD` hashes and sizes
match. The sdist has 39 members. The SBOM contains `cryptalis`, `cryptography`,
`psycopg`, `sqlalchemy`, and their locked transitive components. A wheel installed into
a new virtual environment imports from that environment and starts `cryptalis --help`.
The runtime source scan found no network or telemetry import terms.
`uv lock --check` passes. The [receipt](_reset/release-check-20261021.json) records
source hashes, artifact hashes, and the clean-install path. G-RELEASE remains UNKNOWN.

**Limits:** reproducibility is same-host and same-uv only. There is no independent
rebuild, signed provenance or attestation, Trusted Publishing, vulnerability scan,
old-reader compatibility, upgrade/uninstall matrix, or controlled release identity.
The clean install resolved dependencies from the network; it did not use an offline,
hash-verified install. Independent review and publication remain external blockers.

## Independent application adoption and package-free restart: 2026-10-19

**IMPLEMENTED:** `tests/independent_app.py` is an ordinary three-model application
(accounts, customers with a real foreign key, notes) that imports no Cryptalis component
and refuses such imports when `CRYPTALIS_FORBIDDEN` is set.
`tests/test_independent_application.py` runs the complete host workflow against it:
schema creation and seeding through application code, manifest planning, protection to
`ACTIVE`, ORM reads and exact search under attachment, edits and inserts during
protection, decrypt-back, approved removal, metadata comparison, and a fresh package-free
process that edits, inserts, deletes, and reads through the application's own code.

**VERIFIED, local PostgreSQL 16.15 cell:** the lifecycle case passes on SQLAlchemy 2.1.3
and 2.0.51, including a zero-row protected table, two tenants, Unicode, empty and
trailing text, a deleted row, and a real foreign key. The package-free child process
reports `cryptalis` in no output and matches the expected native values. Full suites
report **1,300 passed, 2 skipped** on 2.1.3
([receipt](_reset/independent-app-full-sa21-20261019.json)) and **1,272 passed, 30 skipped**
on 2.0.51 ([receipt](_reset/independent-app-full-sa20-20261019.json)).

**Limits:** the application is an in-repo fixture, not a pinned external application; the
package-free restart does not exercise a web framework, connection-pool warm-up, or a
second independent codebase. G-LIFECYCLE remains UNKNOWN.

## Fresh-cluster protected-backup recovery and adoption: 2026-10-19

**IMPLEMENTED:** `scripts/fresh_cluster_qualification.py` initializes a new PostgreSQL 16
cluster, creates same-named roles and databases, and runs the recovery suite through the
mandatory credential wrapper with a temporary HOME. `tests/test_fresh_cluster_export.py`
writes a plaintext pre-protection dump, a protected dump after attached edits, and a
manifest of expected values and retained artifacts. `tests/test_fresh_cluster_restore.py`
runs only against the new cluster. `cryptalis.restore/v1` (`restore.py`) issues a
`RestoreBinding` after a read-only adoption scan; `migration.check_deployment(...,
restore=binding)`, `attach((plan, pin, binding))`, and `deprotection.plan(..., restore=
binding)` evaluate the binding.

**VERIFIED, isolated PostgreSQL 16.15 cluster:** the plaintext dump restores natively and
matches the pre-protection rows. The protected dump restores with the same roles; the
payload column is `bytea`; the runtime role reads ciphertext only; the retained key policy
and descriptor recover every exact value (NULL, empty, Unicode, trailing space, edited,
added) through both the product decoder and the independent decoder oracle. Without a
binding, the restored journal cannot become current authority: `check_deployment` and
reverse planning refuse with `deployment_not_current`, and `attach` refuses with
`PolicyMismatch`. With an approved binding, the restored schema attaches, serves exact
search, accepts edits and deletes, reverses to plaintext, and removes the package objects
with matching native values and schema facts. Refusals are typed:
`restore_approval_required`, `restore_source_is_current`, `invalid_restore_binding`,
`restored_frame_verification_failed`, `restored_state_changed`, `restore_target_mismatch`,
`restore_binding_mismatch`, `restored_schema_mismatch`, `restored_schema_changed`,
and `restored_constraint_probe_failed`. Post-adoption drills also refuse structural
schema drift, definition-only drift, and journal-state drift on the restored copy.
[Export](_reset/fresh-cluster-export-20261019-3.json) and
[adoption](_reset/fresh-cluster-restore-20261019-3.json) receipts record the wrapper runs.
The full suites remain green with the qualification modules skipped outside the
orchestrator: **1,302 passed, 2 skipped** on SQLAlchemy 2.1.3
([receipt](_reset/restore-full-sa21-20261019.json)) and **1,274 passed, 30 skipped**
on 2.0.51 ([receipt](_reset/restore-full-sa20-20261019.json)).

**Limits:** the host asserts source fencing and quarantine; the package does not
authenticate either and has no cryptographic evidence of source isolation. Adoption
refuses a restated frame constraint with no retained frame
row, and it qualifies the restated text behaviorally, not textually. A pinned external
application, physical column order, and the owned-sequence limit remain. G-LIFECYCLE
remains UNKNOWN.

## In-place decrypt-back and removal: 2026-10-19

**IMPLEMENTED:** `cryptalis.deprotection` adds `cryptalis.reverse/v1` for an admitted
`cryptalis.transition/v1` source. Reverse state shares the source journal and advisory
lock; the source row remains `ACTIVE`. Expand stages native plaintext columns and fences
inventoried schemas, backfill decrypts current frames, verification re-authenticates every
value, and switch replaces the ciphertext column without `CASCADE`, restoring recorded
constraints, indexes, and collation. Pre-switch abort removes reverse-owned objects.
Removal requires a literal `RemovalApproval`, matching external pins, an empty metadata
diff against the recorded source schema, and no remaining `_cryptalis` relations or
functions in inventoried schemas.

**VERIFIED, local PostgreSQL 16.15 cell:** seven lifecycle cases pass on SQLAlchemy 2.1.3
and 2.0.51. The [full 2.1.3 run](_reset/reverse-full-sa21-20261019.json) reports
**1,299 passed**; the [full 2.0.51 run](_reset/reverse-full-sa20-20261019.json) reports
**1,271 passed, 28 skipped**. The cases cover edits and deletes during protection, a row
added while protected, wrong custody, corrupt frames, disabled guards, lost COMMIT replies,
abort, repeated terminal requests, metadata restoration, and unsafe plan/removal refusals.
These counts are not gate evidence.

**Limits:** in-place reverse cannot restore physical column order (`attnum`). The compiler
lock records no comments, statistics targets, storage, or compression settings, so those
remain UNKNOWN. Fresh-cluster restore, a real package-free application run, retained-backup
reader proof, and production pause budgets remain open. The
[layout evaluation](_reset/layout-evaluation-20261019.md) records why retained-native is
not promoted. All seven gates remain **UNKNOWN**.


## Direct driver inspection failures: 2026-10-19

**IMPLEMENTED:** compiler inspection maps both SQLAlchemy and direct psycopg errors
to `InspectionUnavailable`. SQLSTATE is read from the driver error, whether it is
wrapped by SQLAlchemy or raised directly by an event listener. Raw driver text and
SQL binds remain outside the public failure.
Before this change, a direct psycopg error from a `before_cursor_execute` listener
escaped on SQLAlchemy 2.0.51 while the same case was mapped on 2.1.3.

**VERIFIED, local PostgreSQL 16.15 cell:** focused compiler and diagnostics suites
report **61 passed** on each profile.
[Full SQLAlchemy 2.1.3](_reset/inspection-errors-full-sa21-20261019.json) reports
**1,292 passed** and [full SQLAlchemy 2.0.51](_reset/full-sa20-20261019.json) reports
**1,264 passed, 28 skipped**. These counts are not gate evidence; all seven gates
remain UNKNOWN.

## Inactive payload-rotation batches: 2026-10-19

**IMPLEMENTED, internal only:** `cryptalis.crypto._payload_rotation.prepare_payload_rotation_batch`
decodes current frames under the exact source payload generation and reseals the same
exact text under the target generation. It preserves record identity and the source
search-header bytes, and returns a complete immutable tuple or raises.
It admits one field and tenant, distinct source/target payload roots, an unchanged
search generation, bounded rows/bytes, and unique records. The source and target
leases are rechecked after transformation, so an expired lease cannot yield an earlier
successful batch. No SQL, provider, policy, schema, or publication effect occurs.
The function does not implement a rotation executor or active-policy switch.

**VERIFIED, local cell:** the focused wrapper run reports **40 passed** for
[SQLAlchemy 2.1.3](_reset/payload-rotation-focused-sa21-20261019.json) and the
[full SQLAlchemy 2.1.3 suite](_reset/payload-rotation-full-sa21-20261019.json) reports
**1,292 passed**. Focused SQLAlchemy 2.0.51
([receipt](_reset/payload-rotation-focused-sa20-20261019.json)) reports **90 passed**.
The tests use frozen CF1 vectors, an independent framing/AEAD oracle, source/target
root separation, record and header preservation, bounded-batch refusals, and lease
faults. These counts are not gate evidence; all seven gates remain UNKNOWN.

## Internal rewrap candidate preparation: 2026-10-19

**IMPLEMENTED, internal only:** `cryptalis.crypto._rewrap.prepare_rewrap(source, target)`
prepares an inactive replacement policy. It resolves every admitted source root under
the existing lease, wraps each root with the target provider, unwraps and compares the
exact bytes and context, and returns the same contexts and generations under the target
provider identity. The source policy and cache stay unchanged.
Invalid target identity, provider faults, wrong roots/contexts/providers, identity
drift, and source expiry return `KeyUnavailable` without a partial candidate.
Interruption propagates. No rotation executor, active-policy publication, persistent
custody, payload rotation, search reindex, or retained-artifact update exists.

**VERIFIED, local cell:** the focused wrapper run reports **16 passed** for
[SQLAlchemy 2.1.3](_reset/rewrap-preparation-focused-sa21-20261019.json) and **54 passed**
for [SQLAlchemy 2.0.51](_reset/rewrap-preparation-focused-sa20-20261019.json).
The [full SQLAlchemy 2.1.3 suite](_reset/rewrap-preparation-full-sa21-20261019.json)
reports **1,252 passed**. The tests use an independent
development provider, old-frame reads, and bad-provider oracles. These counts are not
gate evidence; all seven gates remain UNKNOWN.

## Local provider outage, revocation and lease drills: 2026-10-19

**VERIFIED, local cell:** `tests/test_provider_failures.py` drives `Keyring` and both the
migration and attachment executors against a real PostgreSQL 16 cluster with a synthetic
local provider. The drill reports **4 passed** for
[SQLAlchemy 2.1.3](_reset/provider-failures-focused-sa21-20261019.json) and
[SQLAlchemy 2.0.51](_reset/provider-failures-focused-sa20-20261019.json).

The drills prove these behaviors:
- A second-chunk provider outage returns typed `KeyUnavailable` through
  `TransitionFailure`, rolls back the failing chunk, keeps the committed prefix
  (2 journal rows, 1 chunk), and a healthy retry resumes to `PENDING`.
- Revoked provider identity and malformed short material refuse before any backfill
  write (0 journal rows, 0 ciphertext rows), and a healthy retry completes.
- An attached sync commit with an expired lease and an offline provider fails closed
  with no committed row; a healthy retry commits.
- An attached async commit with an expired lease and an offline provider fails closed
  with no committed row; a healthy retry commits.

Wrong-root material, cancellation and replay remain covered by the CF1 and adapter
oracles in `tests/test_cf1.py` and `tests/test_sqlalchemy_adapter.py`.

The [full SQLAlchemy 2.1.3 suite](_reset/provider-failures-full-sa21-20261019.json)
reports **1,306 passed, 2 skipped** and the
[full SQLAlchemy 2.0.51 suite](_reset/provider-failures-full-sa20-20261019.json)
reports **1,278 passed, 30 skipped**. These counts are not gate evidence; all seven
gates remain UNKNOWN.

## Negative predicate boundaries: 2026-10-19

**IMPLEMENTED:** protected text admits simple `!=`, `NOT IN`, `IS NULL`, and
`IS NOT NULL` predicates in sync and async statements. Value predicates reuse the
declared authenticated equality term. NULL presence uses the SQL NULL check, so a
storage-only field needs no equality capability.
For NULL and `NOT IN` predicates, the tenant guard is the declared scope OR the
record key is NULL. This preserves SQL three-valued truth for NULL-extended
outer-join rows. The record key resolves by lineage and must match exactly once;
otherwise the attachment refuses.
General Boolean NOT around a compound expression remains refused because it could
invert the embedded tenant guard. No new leakage class is admitted; the existing
equality enumeration and frequency limits remain.
Before this change the same shapes were refused. A naive negation port would have
dropped absent outer-join rows, so the guard change is part of the admission.

**VERIFIED, local PostgreSQL 16.15 cell:**
[focused SQLAlchemy 2.1.3](_reset/negative-predicates-focused-sa21-20261019.json)
reports **366 passed** and [full SQLAlchemy 2.1.3](_reset/negative-predicates-full-sa21-20261019.json)
reports **1,236 passed**. Focused SQLAlchemy 2.0.51
([receipt](_reset/negative-predicates-focused-sa20-20261019.json)) reports **202 passed**.
The native-oracle matrix covers typed, reversed, late, and mixed NULL binds,
empty lists, aliases, pagination, OR composition, and outer joins. The RED run
before the change reported 57 failures and 2 passes. These counts are not gate
evidence; all seven gates remain UNKNOWN.

## Engine logging preflight: 2026-10-19

**IMPLEMENTED:** `attach` refuses an engine with `echo` enabled or `hide_parameters`
disabled before it opens a connection or resolves a key. The refusal is a typed
`UnsafeEngineLogging` failure with stage `engine logging admission` and a concrete
remedy. The earlier check ran during post-connect validation, so an unsafe engine
could reach the driver and key access before refusal.
No manifest, crypto, storage, or query-plan capability changed.

**VERIFIED, local PostgreSQL 16.15 cell:**
[focused SQLAlchemy 2.1.3](_reset/engine-preflight-focused-sa21-20261019.json) and
[full SQLAlchemy 2.1.3](_reset/engine-preflight-full-sa21-20261019.json) report
**307 passed** and **1,177 passed**. Focused SQLAlchemy 2.0.51
([receipt](_reset/engine-preflight-focused-sa20-20261019.json)) reports **143 passed**.
The deterministic preflight tests use a `do_connect` sentinel and key sentinel. They
assert that no connection or key access occurs and that no URL credential appears in
the failure. These counts are not gate evidence; all seven gates remain UNKNOWN.

## Textual reference admission correction: 2026-10-19

**IMPLEMENTED:** protected textual names in `ORDER BY`, `GROUP BY`, `DISTINCT ON`,
window ordering/partitioning, and `WITHIN GROUP`/aggregate ordering resolve against
the native SQL name spaces. The attachment refuses before the driver when any
resolved candidate is a protected column. Public output labels and FROM names that
shadow protected names retain native resolution.
Without this check, PostgreSQL can sort or group by randomized ciphertext and
silently change results. The earlier check inspected only selected output keys. It
missed unprojected FROM names, aliases, table-qualified names, window clauses, and
ordered aggregates.
The attachment resolves names with an empty native compilation state. It does not
render protected columns, capture keys, or add SQL. No manifest, crypto, storage, or
query-plan capability changed.

**VERIFIED, local PostgreSQL 16.15 cell:**
[focused SQLAlchemy 2.1.3](_reset/textual-admission-focused-sa21-20261019.json) reports
**303 passed**, including 164 textual-boundary cases and the existing adapter/search suites.
[Full SQLAlchemy 2.1.3](_reset/textual-admission-full-sa21-20261019.json) reports
**1,173 passed**, with 48 upstream `distinct_on` deprecation warnings.
[focused SQLAlchemy 2.0.51](_reset/textual-admission-focused-sa20-20261019.json) reports
**275 passed and 28 native-version skips**.
The native execution path is the oracle in every case. Both sync and async paths run.
The RED reproduction failed four attached unprojected `GROUP BY` cases before the change.
Admission adds one name-resolution pass per SELECT that contains textual references.
Performance was not separately measured because admitted SQL, plans, and crypto bytes are unchanged.
All seven full gates remain **UNKNOWN**.

## Membership performance correction: 2026-10-09

**IMPLEMENTED:** membership scans select row/tenant identities without protected source values.
Backfill and complete source/frame verification keep their original projections. Ordered digest bytes, cursors, journal, locks and public API are unchanged.
The user approved this bounded correction before Slice 6; no online or parallel protocol was authorized.
**VERIFIED:** [full current suite](_reset/audit-verification-31ac368e2bbf3bd3.json): **1,009 passed** in 102.12 s at `worktree-31ac368e2bbf3bd3`, based on Git `7edd164`.
[Regression proof](_reset/membership-regressions-31ac368e2bbf3bd3.json): committed source fails four native column-permission cases; fixed source passes all five tests.
The independent oracles check exact journal membership, UUID/bigint boundaries, both tenancy forms, multiple fields/tenants, pagination and all 1,007 decoded application values.
Projection, tenant-binding and pagination removals each fail/restoration passes. [Twenty prior safety removals](_reset/slice5-regressions-audit-d6a6b23daa40d329.json) retain their failure/restoration evidence.
Existing corruption, atomic commit, process interruption, lost reply, fence, lock queue, generation and external-pin tests still pass.
Graphify was refreshed; source confirms `_scope` serves expansion/verification, while backfill and value verification retain their value projections. Graph `scope()` test fixtures are unrelated.

[Same-connection wide-text control](_reset/membership-paired-32768-a81d3cf873c3edd8.json): median membership time **302.48→16.92 ms** for 5,000 rows with two 32 KiB fields.
[Separate-process before](_reset/membership-profile-32768-a94d3d18190b80fb.json)/[after](_reset/membership-profile-32768-a81d3cf873c3edd8.json): traced Python peak **131.84→0.59 MB**, process RSS **286.7→98.4 MiB**.
For two 32-byte fields, the [paired median](_reset/membership-paired-32-a81d3cf873c3edd8.json) was 32.54→30.33 ms. These are warm synthetic scan measurements, not backfill memory bounds.
A matched 30,000-row transition observed pause 3.741→2.813 s and expansion reader latency 0.224→0.113 s.
Unchanged backfill also ran faster; cache/scheduling variation prevents attributing the whole-pause difference to this patch. Verification membership was slower in that pair.
The [research assessment](research/performance-checkpoint.md) owns exact phase/CPU/WAL conditions, primary sources, ranked opportunities, byte-budget analysis and an unimplemented online proposal.
[Clock control](_reset/performance-clock-control-7edd164.json) observes raw/CPU versus monotonic rate discrepancy; cause and historical timing effects remain UNKNOWN.
No new million-row measurement, crypto/cache redesign, index-timing change, Slice 6 or concurrency protocol. The historical million-row pause remains 116.291 s.
All seven full gates remain **UNKNOWN**. No production provider or independent review exists.

## Step A corrective checkpoint: 2026-10-09

**IMPLEMENTED:** same-schema tables share the existing operation guard function, with a separate trigger on each table.
Expand creates the function once per schema. Activation/abort inspect every fence, drop every operation trigger, then drop each function without CASCADE in the same transaction.
An existing function is never replaced or adopted; `guard_function_conflict` reports native `42723`. Names, artifacts, pins and journal state are unchanged.
Frozen field descriptors are validated once per backfill chunk and once per model verification pass. No descriptor, tenant key or row context is retained across operations.
AEAD, field/tenant/row binding, fresh nonces, key expiry/generation checks, full verification and bounded lock retries remain unchanged.

**VERIFIED:** [final checkpoint](_reset/step-a-corrective-final-030b935c0581cb72.json) at content revision `worktree-030b935c0581cb72`;
[full suite](_reset/step-a-corrective-final-verification-030b935c0581cb72.json): **1,004 passed**, including 18 same-schema E2E/attack cases.
The tests assert exact NULL/empty/Unicode values across two tables, three fields and two tenants; both write fences; five process-kill/resume phases;
idempotent pre-switch abort; atomic failure during second-table expansion/retirement; conflict preservation; fence-drift refusal; and rejection of valid wrong-field/tenant/row frames before switch.
[Corrective proofs](_reset/step-a-corrective-regressions-030b935c0581cb72.json): original engine fails the native two-table application test, fixed engine passes;
six isolated removals fail/restoration passes, and all five old single-table checkpoint phases resume through the new engine.
[Twenty prior safety removals](_reset/slice5-regressions-audit-729b0f0ba9f8fea6.json) and [five bounded-lock removals](_reset/step-a-lock-regressions-0fadd110317d7e85.json) still fail/restoration passes.
Graphify was refreshed; source confirms guard creation/retirement and descriptor call paths. All database commands used the fresh-credential wrapper.

| Instrumented one-million-row measurement | Recorded baseline | Corrected engine |
|---|---:|---:|
| Backfill / throughput | 98.126 s / 10,191 rows/s | 67.804 s / 14,748 rows/s |
| Backfill main CPU / descriptor CPU | 64.588 s / 17.739 s | 35.658 s / 0.030 s |
| Verification / descriptor CPU | 65.404 s / 16.214 s | 42.214 s / 0.000062 s |
| Writer pause / observed expansion reader wait | 169.145 s / 5.496 s | 116.291 s / 6.106 s |

The [paired 20,000-row control](_reset/step-a-corrective-summary-c64053e2b5558c3f.json) measured backfill 2.065→1.128 s and verification 1.579→1.131 s before the single new million-row run.
[New measurement](_reset/step-a-optimized-million-1000000-a94d3d18190b80fb.json) reuses the baseline data, chunks and instrumentation: 500 UPDATE batches, 5,027 inspection/marker calls and 500 pipeline sync points remain unchanged.
Backfill SQL-call wall time was 37.560 s, including 29.340 s combined server/network/scheduling time; commits took 2.887 s. Exact database execution/wait time is unavailable.
Cluster-wide backfill WAL was 1,189,163,448 bytes; equality-index growth was 88,588,288 bytes. Physical per-index writes are UNKNOWN; no database/WAL optimization is claimed.
WSL still exposed 20 CPUs, 7.47 GiB RAM and 2 GiB swap with no overrides. Starting load was 0.864/0.682/0.467, versus 0.154/0.352/0.353;
available memory was 3.94 versus 6.12 GiB. New process peak RSS was 98.31 MiB. Cache/checkpoint/load differences and instrumentation limit causal claims.
The observed writer-pause reduction is 31.2%; the paired CPU/descriptor evidence supports a real reduction in Python work. Remaining sealing/verification work and expansion locking still cost time.
The engine verified all million values; an independent decoder checked eight representative rows, and the smaller E2E cases independently decoded every field.
The small-run receipt label was overwritten by an instrumentation-loop variable; source hashes identify baseline/fixed runs. The label was corrected before the million-row run; timing/workload logic was unchanged.
No Slice 6, parallelism, dual writes, public configuration or security-contract change. All seven gates remain **UNKNOWN**; no production provider or independent review exists.

## Step A protection measurement and lock checkpoint: 2026-10-09

**VERIFIED, instrumented one-million-row PostgreSQL run at Git `0383cec`:** [measurement](_reset/step-a-protection-0383cec.json).
The user confirmed that unrelated programs were closed. WSL exposed 20 logical CPUs (20 reported cores, one thread per core), 7.47 GiB RAM and 2 GiB swap;
no `.wslconfig` overrides or narrower cgroup CPU/memory limits were found. Load averages changed from 0.154/0.352/0.353 to 1.133/0.791/0.532.

| Phase | Wall time | Main client CPU |
|---|---:|---:|
| Expand | 5.521 s | 4.711 s |
| Backfill, 500 chunks of 2,000 rows | 98.126 s; 10,191 rows/s | 64.588 s |
| One final verification and switch | 65.433 s; verification 65.404 s | 63.865 s |
| Local ACTIVE acknowledgement | 0.023 s | 0.009 s |

Writer pause was **169.145 s**, excluding seed/plan/drain and real publication delay. Expansion index creation took 0.229 s over NULL shadows.
DDL SQL calls took 0.062 s at expansion and 0.0013 s at switch; these overlap phase times.
Lock-request calls took 0.114/0.252/0.143 ms at expansion/verification/activation. No executor lock wait was sampled; exact server wait time is unavailable.
The plain reader waited 5.496 s during expansion. Client-observed ACCESS EXCLUSIVE intervals were 5.512/0.018/0.016 s at expansion/switch/activation.
Backfill/verification reads continued; their maximum observed latencies were 156/37 ms, with no sampled reader lock wait in those phases.
Backfill CPU: seal 32.371 s, repeated descriptor preparation 17.739 s, key preparation 0.025 s. Client CPU dominates this workload with public test roots.
There were 500 UPDATE batches, 5,027 inspection/marker calls, 500 pipeline sync points and 504 driver commits; exact wire round trips are unavailable.
SQL-call wall time was 40.831 s, including 8.854 s client CPU and 31.977 s non-CPU time. The latter includes server/network/scheduling, not isolated database wait.
Sampled database waits included 73 WALSync, 22 WALWrite and 79 DataFileWrite observations; variable sampling intervals do not establish wait seconds.
Backfill cluster-wide WAL advanced 1,269,621,872 bytes. Equality-index size grew 76,800,000 bytes; per-index physical writes and table-attributed WAL remain UNKNOWN.
Instrumentation adds overhead and its component timers overlap. A [failed observer run](_reset/step-a-failed-instrumentation-0383cec.json) is retained as failed evidence;
restricted-role activity fields were NULL. Corrected instrumentation passed a [1,000-row control](_reset/step-a-smoke-1000-0383cec.json) before the million-row run.

**IMPLEMENTED local fix:** the executor keeps a 5 s session lock timeout. ACCESS EXCLUSIVE acquisition now uses three 100 ms attempts, with 50 ms gaps and savepoint rollback.
Cutover explicitly upgrades before DDL; rollback releases partial upgrades but retains EXCLUSIVE verification locks. Exhaustion reports `table_lock_busy_retry`/`55P03` without switching.
These limits bound individual acquisition attempts, not time spent holding a granted lock or an entire multi-table operation.
[Regression proof](_reset/step-a-lock-regressions-e137d3240bd453e9.json): `0383cec` gives three failures/one native-control pass; fixed code gives four passes. Five safety removals fail and restoration passes.
[Full verification](_reset/step-a-lock-verification-e137d3240bd453e9.json): **986 passed** at content revision `worktree-e137d3240bd453e9`.
[Twenty prior safety removals](_reset/slice5-regressions-audit-0e01c8924bb16893.json) still fail their tests and restoration passes. All database work used the fresh-credential wrapper.
Graphify was refreshed and findings were checked in source. A [same-schema two-table control](_reset/step-a-guard-reproduction-e137d3240bd453e9.json) reproduced duplicate guard-function creation (`42723`) with atomic rollback. The corrective checkpoint above fixes it; this control remains historical evidence.
Parallel workers are **not recommended before slice 7** on this evidence. First evaluate preparing the immutable descriptor once, then repeat a controlled profile.
Disjoint workers would need atomic per-range coverage, stable context/key generations, crash reconciliation, terminal original transactions, serialized cutover, and mandatory global verification; the current single cursor does not supply that protocol.
The historical 508.7/197.0 s variation is still UNKNOWN: source, instrumentation, load, chunking and cache conditions were not controlled across those runs.
Slice 6/7, decrypt-back measurements and package-free removal remain unimplemented. No dual writes or parallelism were added. All seven gates remain **UNKNOWN**.

## Step 0 protection-pause checkpoint: 2026-10-09

**IMPLEMENTED:** uninterrupted apply verifies and switches in one transaction, with one full verification pass.
Saved VERIFIED checkpoints still require fresh verification and an unchanged frame digest before switch.
Verification uses PostgreSQL EXCLUSIVE locks: plain reads continue, while writes and locking reads wait.
DDL still acquires ACCESS EXCLUSIVE. A reader that delays DDL past the lock timeout leaves source data and the BACKFILLED marker unchanged.
`print(plan_result)` reports native row count, supplied measured rates, and the estimated uninterrupted writer pause.
Extra verification checkpoints/retries, drain, DDL, index construction, and publication delay are excluded; this is not a pause bound.
**VERIFIED, bounded PostgreSQL 16 cell:** content revision `worktree-c72bb439d7e13334`, based on Git `9f335c6`.
[Full verification](_reset/step0-verification-c72bb439d7e13334.json): **982 passed**, including seven new native lock/SQL and independent-decoder cases.
[Step 0 proofs](_reset/step0-regressions-c72bb439d7e13334.json): committed engine gives six failures and one pass; fixed copy gives seven passes.
Seven isolated Step 0 mutations and [20 existing safety removals](_reset/slice5-regressions-audit-72f0a976a1fe9d8f.json) fail their behavioral checks; restoration passes.
The authentication attack now flips a tag bit instead of assigning a byte that could already have that value.
No new million-row pause was measured. The historical 508.7 s receipt and unexplained timing variation remain historical evidence.
No protocol change, dual writes, slice 6/7, production provider or independent review is added. All seven gates remain **UNKNOWN**.

## Corrective audit checkpoint: 2026-10-09

**VERIFIED, bounded PostgreSQL 16 cell:** source/test revision `audit-a07004dfcda8cd05`, based on `fe2b061`.
This is a content-bound worktree revision, not a Git commit. [Full receipt](_reset/audit-verification-a07004dfcda8cd05.json): **975 passed**.
[Slice 3](_reset/slice3-audit-a07004dfcda8cd05.json): 64 cases; [slice 4](_reset/slice4-audit-a07004dfcda8cd05.json): 75;
[slice 5](_reset/slice5-audit-a07004dfcda8cd05.json): 53 existing plus 40 audit cases. Old receipts remain unchanged.
Earlier slice 3 and 4 row-isolation claims did **not** cover grouped or callable primary-key binds.
The fix captures grouped AND/scalar-IN identities, normalizes explicit bind values and rejects ambiguous forms before SQL.
Protected primary-key lookups in HAVING or JOIN ON also reject. Plain projections retain native primary-key grammar.
All maintenance entries require approval before connection or locks. Read-only plan/deployment/attachment checks are exempt.
Acquisition, phase and cleanup failures retain safe diagnostics, operation identity and both primary/cleanup outcomes.
The credential wrapper reloads both private files and probes both roles; three real authentication-failure controls verify suite redaction.
[Audit regressions](_reset/audit-regressions-a07004dfcda8cd05.json) compare original and fixed code in isolated copies;
[20 existing safety removals](_reset/slice5-regressions-audit-1407433d842664f6.json) fail without their mechanism and pass after restoration.
No slice 6 work, production provider or independent review is added. All seven gates remain **UNKNOWN**.

## Slice 5 checkpoint: 2026-10-09

**IMPLEMENTED:** `cryptalis.migration.plan`, `apply`, `verify`, and pre-switch `abort`.
One phase loop uses a PostgreSQL journal, cooperating session advisory lock, transactional DDL, and bounded atomic chunks.
Plans bind the native schema, compiler lock, target, runtime role, inventoried tenant key policies, writer assertions, and host cost estimates.
Expand drains table access and installs an owner-controlled statement trigger that rejects restricted-runtime writes across chunk commits and process crashes.
Resume preserves committed ciphertext. Full verification checks membership, native value/type/NULL parity, authentication, terms, generations, constraints/indexes, and trigger inventory.
At that recorded revision, switch repeated verification under exclusive table locks and retired the original SQL column without CASCADE.
Database switch remains PENDING until the host supplies the exact externally published ACTIVATING pin.
After acknowledgement, startup requires the externally current ACTIVE pin, target/schema agreement, planned runtime role, and matching tenant key policies.

**VERIFIED, local PostgreSQL 16.15:** **53 migration cases** within **917 passing full-suite cases**.
The original native application supplies plaintext/type/NULL oracles; a separate stdlib HKDF/HMAC and AEAD decoder checks migrated frames against those values.
Independent child processes are killed at durable phase boundaries and during a partly completed backfill, then resume without replacing committed frames.
A real PostgreSQL transport fault discards an already-terminal COMMIT reply. Resume inspects the committed marker and retains the first chunk's bytes.
Connection faults during expand, verify, and transactional switch preserve the original representation and prevent false completion.
Concurrent runtime writes committed before fencing are included; writes during maintenance reject with `55000`, and an attached retry works after publication.
The runtime can read progress but cannot mutate the journal, disable the fence, alter its schema, or acquire ownership.
Real corruption, missing rows, changed source/index/trigger metadata, missing markers, and wrong active generations refuse switch.
A real own-schema `pg_dump`/`psql` older-snapshot restore cannot advance under the current external ACTIVE pin.
Missing publication, stale pins, altered keys, owner attachment, and competing executors refuse.
**Twenty isolated safety removals** fail their behavioral oracles; restoring each copied source restores a passing result.

[Verification](_reset/slice5-verification.json), [regression proofs](_reset/slice5-regressions.json), and
[performance](_reset/slice5-performance.json) retain commands, hashes, scope, and costs.
The final isolated million-row run backfilled **3,942 rows/s** in 253.7 s; the measured write pause was **508.7 s**.
Expand took 5.3 s, verify 148.6 s, and repeated verification plus database switch 100.9 s.
The pause ends at local ACTIVE acknowledgement; actual host publication delay adds to it.
Runtime write attempts in all four paused phases returned `55000`; an attached post-switch edit/read succeeded.
The observed phase maximum for the customer heap and indexes was 600,793,088 bytes; cluster-wide WAL increased about 1.396 GB.
These do not prove secure erasure, attributed WAL, storage bounds, or a production pause budget.
The earlier source measured 11,559 rows/s and 197.0 s pause. The cause of the run-to-run difference remains **UNKNOWN**.
An underestimated fixed WAL multiplier was replaced with required host staging cost inputs; no multiplier is presented as a bound.
The [60-line walkthrough](walkthrough-migration.md) explains plaintext retention and deployment responsibilities.

**Limits:** protection is a maintenance operation. It does not admit online plaintext writes during backfill.
Owner/DDL writers must be excluded by the host. The tests do not qualify a deployment's worker termination, credential control, policy provenance, or restore quarantine.
A supplied pin is a host assertion, not authentication implemented by this package. A restored journal never selects current authority.
Same-context row replay, hostile result omission, nullable substitution, and writers that bypass attachment remain outside the claimed boundary.
Only inventoried tenant policies are admitted. One protection operation per schema is currently admitted; an aborted journal remains for inspection.
Decrypt-back, package-free removal, rotation, finalization, retained-backup recovery, and production provider integration are not implemented by this slice.
No source mirror survives SQL switch, but dropped-column bytes can remain in heap tuples, WAL, snapshots, and backups. No erasure claim follows.
Storage/WAL and rate estimates require host staging observations; they are not bounds. Real exhaustion and production pause budgets remain UNKNOWN/D.
No production provider or independent review exists. All seven gates remain **UNKNOWN**. No commit or push occurred.

## Slice 4 checkpoint: 2026-10-08

**IMPLEMENTED:** declared exact-text equality/IN, mapped aliases, AND/OR and native tenant-scoped uniqueness.
The attachment hashes ordinary text query values with the existing independent search-root composition.
PostgreSQL uses a B-tree over the full term inside the CF1 frame, with tenant first when declared. No extension or companion column is needed.
One bytea write updates payload and term together. Native constraints arbitrate races and preserve distinct NULLs.
Attachment validates exact index/check definitions, keys, operator classes, uniqueness and valid/ready/live state.
Catalog deparsing uses `pg_catalog` resolution to reject function shadowing. Search key changes within an attachment refuse.
Protected predicates/projections compile per operation; plain projections keep native compilation caching.

**VERIFIED, local PostgreSQL 16.15:** **75 search cases**, **four independent frozen-term vector cases**, and **864 full-suite cases**.
The application path uses the separate non-owning runtime role; owner setup grants only schema USAGE and customer CRUD in disposable schemas.
Native sync/async controls compare text membership, SQL NULL/empty-IN truth, aliases, typed/reverse/late/shared binds and two protected fields.
Concurrent same-tenant insert races produce one commit and one native `23505`; cross-tenant duplicates and distinct NULLs commit.
Uniqueness failures roll back payload/term updates; later writes and queries recover. Duplicate backfill blocks unique-index creation.
Wrong-tenant queries expose no protected value. Known small domains, absent review/leakage acceptance and malformed physical contracts reject.
Listed unsupported grammar, forged/wrapped aliases, protected JOIN/derived tables, codecs, callables and ambiguous bind names refuse before SQL.
Real elapsed key-lease expiry leaves PostgreSQL unchanged; fresh sync/async sessions recover.
Independent writers can still hide search membership or install structurally plausible invalid AEAD. Point reads reject changed frames.
Returned-row authentication supplies no freshness, presence, result completeness or adversarial global-uniqueness guarantee.

[Verification receipt](_reset/slice4-verification.json) records exact source/test hashes, test intent and isolated regression removals.
[Performance receipt](_reset/slice4-performance.json) records the million-row runtime ORM measurements and their limits.
The earlier page-query source includes a protected entity projection; its former plaintext-only label is retired.
Its historical timing and causal explanation remain historical/UNKNOWN. Current profiling separates plain projections from protected entities with plaintext filters.
Empty-schema fixture conversion is not product migration. Fresh-deployment policy binding, writer exclusion, lifecycle and key rotation remain unqualified.
No production provider or independent human review exists. All seven full gates remain **UNKNOWN**. No commit or push occurred.
See the [60-line search walkthrough](walkthrough-search.md). This run stops at slice 4.

## Slice 3 checkpoint: 2026-10-08

**IMPLEMENTED:** `cryptalis.sqlalchemy.attach` returns a tenant-scoped Session factory.
Async attachment is awaited. The target must already store protected fields as `bytea`.
The host supplies a trusted compiler lock and exact tenant keyrings. Attachment does not migrate data or authenticate deployment authority.
Only ordinary ORM flush writes and admitted SELECTs are implemented. Search rewriting belongs to slice 4.
Prepared CF1 frames replace driver binds while mapped attributes remain ordinary text or NULL.
Read projections carry payload, record identity, and declared tenant context. Authentication precedes each value's release.
Protected SELECTs disable compilation caching so operation-specific result processors cannot retain another tenant, point, or key set.
Unprotected SELECTs retain native compilation caching. Public raw-driver, COPY, opaque SQL, and unprepared-write routes reject.

**VERIFIED, earlier restricted fixture-owner run:** the adapter suite returned **41 passed in 8.01 s**; the full suite returned **777 passed in 18.41 s**.
Commands: `.venv/bin/python -m pytest -q tests/test_sqlalchemy_adapter.py --tb=short`
and `.venv/bin/python -m pytest -q --tb=short`.
The cell uses Linux/WSL, Python 3.12.3, SQLAlchemy 2.1.3, psycopg 3.3.6, cryptography 50.0.2, and PostgreSQL 16.15.
The URL stayed private. Tests created and dropped only their own schemas under the restricted fixture owner.
Native and attached controls exercise exact text/NULLs, state/history, autoflush, merge, refresh/expiry, rollback,
entities/scalars/labels, aliases, outer joins, relationships, batches, streaming, and interleaved tenants.
Async controls exercise concurrent tenant tasks and cancellation observed through PostgreSQL's `PgSleep` wait event.
Cancellation during awaited key preparation leaves the database unchanged and permits a later write.
Sync and async updates/deletes work after commit expires context attributes.
Single-tenant bigint outer joins retain native NULLs. Same-named tables in separate schemas retain distinct values.
Cancellation is propagated; rollback removes the pending row; a later tenant session recovers.
Defensive checks verify driver-bind privacy with a visible unprotected control, valid-frame wrong-tenant refusal,
wrong returned point, relocated/changed ciphertext, unsupported grammar before driver execution, mapping mutation, failed-flush cleanup, and guarded reconnects.
Ambiguous columns and alternate protected mappings reject. Attachment refuses existing checked-out connections.
Target translation, changed primary-key mappings, and catalog nullability/default mismatches reject.

**VERIFIED regression sensitivity:** the main thread used an isolated copy of the current source and tests.
Only the copy lost the protected SELECT cache-disable call. All four native sync/async entity/scalar controls passed.
All four attached cases failed with `AuthenticationFailed`. Restoring the copy gave eight passes.
The original source remained unchanged during this proof. No assertion was weakened.
The withheld output was unavailable in the main-thread context. Its findings supplied no relied-upon evidence.
[Verification receipt](_reset/slice3-verification.json) binds these observations to source/test hashes.

**VERIFIED bounded cost:** 5,000 synthetic rows, 40 paired samples, warm local keys, fully consumed results.
Point p50/p95: native 0.435/0.618 ms and attached 1.715/2.903 ms. The p95 difference was 2.285 ms.
Plaintext page p50/p95: native 1.428/1.906 ms and attached 2.238/2.810 ms. Both paths recorded 60 cache hits.
[Compatibility](compatibility.md#slice-3-local-profile-2026-10-08) owns profiling details and limits.

### Restricted runtime-role completion: 2026-10-08

**VERIFIED, local slice 3 cell:** the adapter suite returned **49 passed in 9.00 s**.
The full suite returned **785 passed in 20.27 s**, with no failures, errors, or skips.
Commands: `.venv/bin/python -m pytest tests/test_sqlalchemy_adapter.py -q --tb=line`
and `.venv/bin/python -m pytest -q --tb=line` (the full run also wrote a temporary JUnit receipt).
Each database shell command loaded both URLs fresh from the private files before a psycopg `SELECT 1` check.
The SHA-256 prefixes were `0f63934e` for the fixture owner and `4e551e31` for the runtime login.
Both roles are restricted, use the same PostgreSQL 16.15 target, and have distinct identities.
The runtime login cannot inherit or `SET ROLE` to the fixture owner.

Only owned fixture objects received grants: schema `USAGE`, customer `SELECT/INSERT/UPDATE/DELETE`, and article `SELECT`.
The article read is required by native SQLAlchemy relationship lookup during customer deletion.
The first run without it failed equally in native and attached sync/async cases; the corrected grant passed.
Effective privilege checks reject schema `CREATE`, ownership, grant options, `TRUNCATE`, `REFERENCES`, and `TRIGGER`.
Sync/async native and attached controls verify exact NULL/empty/Unicode values, CRUD, refresh, and flushed-update rollback.
An independent connection observes committed protected bytes. A bind collector sees an unprotected marker and no supplied protected insert markers.
Opaque DDL rejects through the attachment before driver execution.

Independent sync and async psycopg connections receive SQLSTATE `42501` for nine operations:
create table, add column, create index, truncate, drop table, change table owner, change schema owner, drop schema, and switch to the fixture-owner role.
Each refusal rolls back; later queries succeed; inspected ownership and schema remain unchanged.
These denials concern the owned persistent schema. The runtime login retains database `TEMP` privilege; no universal DDL-denial claim follows.

A separate runtime writer can reconnect and commit data changes without the attachment.
Fresh connections observe its changed ciphertext, replayed historical frame after a legitimate application update, NULL substitution, and deletion.
Sync/async attached reads reject changed ciphertext but accept the older authenticated value, nullable NULL, and row absence.
This proves the tested schema privilege separation and read-time tamper refusal. It does not prove writer exclusion, freshness, presence, completeness, or host authorization.
Deployment enforcement, lifecycle-metadata permissions, provider custody, and independent review remain UNKNOWN.
The [runtime verification receipt](_reset/slice3-runtime-verification.json) records hashes, cases, grants, and limits.
Product source, all existing tests, both earlier receipts, and `spikes/revamp` remain unchanged.
All fixture schemas were removed. No roles or global grants changed. Slice 4 was not started.
All seven full gates remain **UNKNOWN**. This run stops at the local slice 3 checkpoint.

### Earlier prerequisite failures (historical)

The completion above supersedes these connection and role-availability blockers. The records remain preserved.

**BLOCKED advancement:** separate non-owning runtime credentials are unavailable. `cryptalis_runtime` is absent;
the only additional membership reported is the built-in non-login role `pg_database_owner`. No roles or permissions were added.
The fixture owner cannot prove runtime privilege isolation or deployment writer exclusion.
Finish this slice with provisioned restricted runtime access, native CRUD controls, and DDL/ownership refusal evidence before slice 4.

**Latest connection recheck, 2026-10-08 19:40 UTC:** this agent process has `CRYPTALIS_TEST_DATABASE_URL` set,
but psycopg reports `FATAL: password authentication failed for user "cryptalis_migrator"`.
Neither `CRYPTALIS_TEST_RUNTIME_DATABASE_URL` nor `CRYPTALIS_RUNTIME_DATABASE_URL` is set in this process.
The runtime connection could not be attempted. No fixture, privilege, or runtime test ran during this recheck.
The earlier role-catalog observation above is historical; this attempt does not establish whether the runtime role now exists.
Resume in a process that receives both working connection variables. Do not put credentials in repository files or diagnostics.

**Connection recheck, 2026-10-08 20:04 UTC:** both `CRYPTALIS_TEST_DATABASE_URL` and
`CRYPTALIS_TEST_RUNTIME_DATABASE_URL` are present in this agent executor.
One psycopg connection attempt per role returned `SELECT 1 = 1` for the runtime connection.
The migration connection failed with `FATAL: password authentication failed for user "cryptalis_migrator"`.
The required two-connection prerequisite did not pass. No database objects changed and no runtime tests ran.
Authorized CRUD, DDL/ownership denial, and sync/async attachment under separate runtime credentials remain unverified.
This recheck supersedes the earlier missing-runtime-credentials observation; it does not establish role privileges.
Supply working migration credentials privately, then recheck both connections before fixture work.
The [connection receipt](_reset/slice3-runtime-recheck-20261008T200458Z.json) records the exact failure and preservation snapshot.

The historical million-row anomaly remains UNKNOWN. No production provider, independent review, deployment admission,
transition executor, search rewriting, rotation, or release qualification follows from this checkpoint.
All seven full gates remain **UNKNOWN**. See the [walkthrough](walkthrough-sqlalchemy.md).

## Slice 2 checkpoint: 2026-10-08

**IMPLEMENTED:** `cryptalis.crypto` seals and authenticates bounded text with trusted compiler descriptors and prepared keys.
It uses library AES-256-GCM-SIV, HKDF-SHA-256, and full HMAC-SHA-256.
Strict UTF-8 preserves exact text. SQL NULL remains SQL NULL. The encoded text limit is 16 MiB.
The product implements storage-only and packed equality frames, UUID/bigint records, and both declared tenancy codecs.
It rejects unknown flags, companion representations, malformed frames, missing generations, and invalid text.

`Keyring` pins a finite policy and exact provider identities. Frame headers cannot select provider authority.
Sync and async preparation publish keys only after all roots pass checks.
The cache has fixed expiry, with a 60-second default and 300-second maximum. Access does not extend it.
Inherited providers and keys refuse use after fork. A child can create and prepare fresh local material.
The ephemeral development provider wraps, unwraps, and rewraps roots in memory.
[Security](security.md#implemented-cf1-primitives-and-local-custody) owns these operational limits and APIs.

**VERIFIED:** the focused CF1 suite returned **30 passed**, including **eight real PostgreSQL persistence cases**.
The full suite returned **736 passed** with `.venv/bin/python -m pytest -q --tb=short`.
The environment uses PostgreSQL 16.15, Python 3.12.3, cryptography 50.0.2, SQLAlchemy 2.1.3, and psycopg 3.3.6.
Those cases compare recovered values with native text under actual compiled descriptors.
They cover both frame formats, both record codecs, and both tenant codecs, including nil UUIDs and bigint endpoints.
Eight frozen CF1 vectors use a separate RFC 8452 reference with OpenSSL AES blocks and separate HKDF/HMAC code.
Published RFC 8452, RFC 5869, and RFC 4231 vectors check that reference and the installed primitives.
The fixture reproduction command is `.venv/bin/python tests/reference_cf1_vectors.py`.

Attack and failure cases cover byte changes, relocation, wrong roots, retirement, expiry, failed/canceled preparation, and fork.
Local rewrap preserves existing frames. Failure diagnostics exclude supplied secrets and raw provider errors, including during RNG failure.
AI review found and corrected nil-UUID refusal and writable-policy retention of old cache entries.
AI review does not replace independent human security review.

**Limits at slice 2:** SQLAlchemy attachment, query rewriting, database transitions, and deployment rotations remained pending.
The slice 3 checkpoint above records the later bounded attachment evidence.
The local provider cannot recover after process loss. No production provider exists.
SQL NULL substitution and same-context replay remain accepted scope limits.
Remote cancellation, custody, independent recovery, usage bounds, collision assumptions, and independent review remain unqualified.
All seven full release gates remain **UNKNOWN**.

## Slice 1 checkpoint: 2026-10-08

**IMPLEMENTED:** `cryptalis.manifest.compiler.compile_protection` parses field intent, resolves a supplied registry,
and inspects PostgreSQL catalogs. A fresh read-only transaction holds a repeatable schema snapshot.
Unqualified mappings resolve through the original PostgreSQL search path.
The result contains canonical lock bytes, a digest, and semantic changes. Compilation creates no database effects and reads no application values.

**VERIFIED:** `.venv/bin/python -m pytest -q --tb=short` returned **706 passed**, including **58 compiler cases**.
The compiler tests use PostgreSQL **16.15**, Python **3.12.3**, SQLAlchemy **2.1.3**, and psycopg **3.3.6** under the restricted disposable role.
They compare native schema and data before and after planning. They execute proposed additive DDL only in test-owned schemas.
A real INSERT injection fails with SQLSTATE `25006`, including through an AUTOCOMMIT engine.

This compiler admits native text, application-assigned UUID or bigint keys, explicit UUID tenancy or a single-tenant declaration,
and qualified native uniqueness. Storage-only fields need no search review or search collation.
Searchable fields require `pg_catalog.C` equivalence, matching leakage acceptance, and an explicit host review of the value domain.
Small or unknown domains block search. The host declares complete writer coverage and excluded routes. These records remain host assertions.

Known unsafe schemas and inconsistent prior locks raise typed errors.
The lock includes original admitted constraints, additive DDL, immutable context descriptors, and reader requirements.
A tenant change requires resealing. A SQL rename preserves the descriptor.
Missing or changed stable identities cannot silently replace existing identities.
[Architecture](architecture/README.md#implemented-compiler-syntax) owns the exact syntax.

**Slice 1 limits:** this checkpoint did not implement attachment, encryption, a provider, transitions, or runtime query rewriting.
Other ID codecs, protected varchar/custom types, non-UUID tenant columns, protected defaults, unsupported dependencies, and schema translation reject.
A new unique request needs a qualified native source constraint first.
The additive DDL does not qualify CF1 framing or authorize a switch.
External writer exclusion and domain assertions remain unverified. All seven full gates remain **UNKNOWN**.

## Approved scope and build order

The [comprehensive release direction](decisions.md#comprehensive-first-public-release-2026-10-23) retains the full SRS and all 34 objectives.
The earlier [baseline decisions](decisions.md#approved-scope-decisions-2026-10-08) do not supply implementation evidence.
Python 3.12+, SQLAlchemy 2.x, psycopg 3 sync/async, PostgreSQL 16 are the selected stack.
SUPPORTED design scope: text storage, equality, IN, and tenant-scoped uniqueness.
Each protected table declares a tenant column or declares itself single-tenant. Primary keys must be application-generated.
Plan rejects serial, identity, and database-default-generated keys, unsupported types, small-domain searchable fields, missing tenancy, and unsupported writers.
Other full-SRS types/operators remain CURRENTLY UNADMITTED and unfinished. Internal research helpers remain INTERNAL ONLY.

Baseline dependencies follow compiler → crypto/provider → SQLAlchemy → equality/search → protection → removal → rotation.
Independent workstreams can proceed with real PostgreSQL evidence before dependent integration.
New capabilities retain [six-gate admission](compatibility.md#capability-admission) and leakage opt-in.
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
| G-QUERY | UNKNOWN | Complete admitted PostgreSQL 16 semantics, leakage evidence, read/storage target measurements and anomaly profiling remain pending. Write-throughput remains D; advanced queries remain CURRENTLY UNADMITTED pending secure admission |
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

The current package has the product compiler, CF1 primitives, and bounded SQLAlchemy attachment above, structural record decoding/canonicalization, bounded manifest/header inspection,
local crypto/search examples, and local transition-admission research.
The slice 3/4 attachment supplies stated storage and search behavior only within the tested boundaries above.
These APIs do not qualify managed key custody, safe deployment admission, or production lifecycle.
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

Slices 1–5 have bounded product evidence for app-assigned-key planning, storage/search admission and protection transitions.
Earlier receipts omit grouped and callable primary-key binds; their row-isolation claims do not cover those forms.
The [corrective checkpoint](#corrective-audit-checkpoint-2026-10-09) records their repair. No runtime release is qualified.

Full independent recovery, deployment writer exclusion, retained-backup readers, format upgrades,
real resource-exhaustion faults, production provider custody, authenticated policy publication/restore, and independent review remain required.
[Gate criteria](#missing-evidence-and-promotion-criteria) state the deciding observations without restoring the deleted control plane.
No production provider is designated. The local provider is functional evidence only.
G-PROVIDER, G-POLICY, all review requirements, and the [release gate](../ENGINEERING_PLAYBOOK.md#release-gate) remain UNKNOWN.
