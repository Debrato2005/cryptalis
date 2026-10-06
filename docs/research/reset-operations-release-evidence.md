# Operations and release evidence for the architecture reset

Access date for every external source below: **2026-10-06**.

This document records research and recommendations. It is not a normative architecture or executable capability evidence.
No migration, provider call, release workflow, artifact verification, or adversarial fixture ran in this research lane.
Source dates establish publication or event timing. They do not establish that a package version or deployment remains safe today.

Final selection: the [lifecycle owner](../lifecycle.md#rollback-and-finalization) chooses a 24-hour default rollback window, with an absolute seven-day maximum.
The seven-day default recommendation below is a rejected research input. Online transitions are excluded.

## Findings that constrain the design

### Migration, rollback, and removal

PostgreSQL updates retain old row versions until vacuum can reclaim them. Normal vacuum makes space reusable within the relation [O01].
WAL archives and base backups can restore earlier database states [O02].
Consequently, replacing current plaintext with ciphertext does not prove historical plaintext destruction.
A report must distinguish current protected rows from historical copies and unknown external copies.

Many ALTER TABLE operations acquire ACCESS EXCLUSIVE locks. Some changes rewrite tables, and NOT VALID plus later validation has operation-specific limits [O03].
Concurrent index construction takes several transactions and can leave an invalid index after failure [O04].
An invalid unique index can still enforce uniqueness. Its presence alone cannot prove cutover readiness.

These facts support bounded chunks, operation-specific DDL journals, catalog reconciliation, and explicit storage/WAL/lock budgets.
They do not prove Cryptalis can execute those mechanisms safely.

The existing repository already separates shadow targets from read authority and requires full terminal verification.
Retain those invariants when the parent reset consolidates the lifecycle contract.
Remove arbitrary observation intervals that pretend elapsed time proves writer exclusion or rollback readiness.

### Logging and memory

SQLAlchemy `hide_parameters=True` hides parameters in INFO logs and StatementError text. DEBUG can record result rows [O05].
PostgreSQL can log bind values, and truncation still reveals the retained prefix [O06].
Neither control stops the host application from logging decrypted values, SQL literals, serialized entities, or request bodies.

The LiteLLM team described secret headers that reached spend logs and OpenTelemetry through guardrail metadata on March 18, 2026 [O07].
That incident supports a bounded diagnostic schema. It does not establish a Cryptalis defect.
OWASP recommends excluding primary secrets and sensitive data from logs and testing logging failures [O08].

Key caches reduce provider calls but increase the interval during which key material remains usable locally [O09].
OWASP identifies memory dumps, garbage collection, audit integrity, and secrets-service outage as separate concerns [O10].
Dropping a Python reference or expiring a cache is not proof that every memory copy disappeared.
Do not advertise process memory protection, instantaneous revocation of copied keys, or complete Python zeroization.

### Supply chain in 2026

The PyPA advisory for `dydx-v4-client` names a malicious `1.1.5.post1` upload after account compromise [O11].
The advisory publication timestamp is January 28, 2026. It does not give the upload timestamp.
Use that date as an advisory date, not an inferred incident date.

LiteLLM published its initial incident notice on March 24, 2026. Its March 27 update gives the first malicious upload at 10:39 UTC [O12, O13].
The affected versions were `1.82.7` and `1.82.8`. The latter included an executable `.pth` file.
The maintainer account attributes the incident to an unpinned scanner in a shared CI environment with static release credentials.
The report expresses uncertainty about parts of the attribution. Preserve that qualifier.
Python documents that executable `.pth` lines run during interpreter startup, even when the associated package is not imported [O14].
Thus, a source review or ordinary import test alone cannot establish wheel safety.

TanStack's May 11, 2026 postmortem records 84 malicious releases across 42 packages between 19:20 and 19:26 UTC [O15].
It describes an untrusted pull request, shared cache poisoning, and extraction of an OIDC token from runner memory.
Its May 15 revision corrects timeline details. The evidence uses that revised account.
OIDC removes reusable publication credentials. It does not prevent attacker code in a trusted publication context.

These are a dated incident sample, not an exhaustive census of 2026 PyPI/npm malware.
No download totals, affected-organization estimates, or claims about all attack campaigns follow from these sources.

## Recommended lifecycle decisions

These recommendations use source constraints and repository invariants. The canonical reset owners must record the final choices.

| Decision | Recommendation | Reason and residual limit | Required acceptance evidence |
|---|---|---|---|
| Shared transition engine | Use one engine for protect, payload rotation, reindex, deprotect, and remove. Hide internal phases behind ordinary CLI progress | Reuse durable journals and verification. This does not require a generic workflow framework | Crash and resume at every durable boundary for each transition kind |
| Default migration strategy | Use a maintenance fence with shadow target columns and bounded row chunks | This avoids mixed-writer correctness machinery. It costs write availability during transformation | Rejected raw/COPY/worker writes under restricted roles, drained transactions, repeatable resume |
| Online migration | Admit only a defined atomic coexistence protocol. Otherwise reject the request and offer maintenance migration | All writers must update source, ciphertext, terms, and durable logical revision in one transaction. A heartbeat is not a fence | Old writer exclusion, concurrent writes/backfill, delete/recreate, cancellation, terminal fenced sweep |
| Backfill concurrency | Allow one operation per overlapping scope. Claim chunks and use expected logical revisions | SKIP LOCKED or a cursor is work allocation, not coverage proof. Do not use xmin as permanent logical identity | Two executors, lock loss, stale revision, skipped ranges, partial chunk, crash after row commit before checkpoint |
| Cutover | Require full row authentication, decode equivalence, term recomputation, valid indexes, and a final writer fence | Sampling cannot prove complete migration. Index existence cannot prove index readiness | Every required row scanned, corrupt row blocks switch, invalid unique index blocks switch, drift invalidates receipt |
| Unique reindex | Keep writes fenced until the new generation owns complete uniqueness enforcement | OR across two generations does not prove uniqueness between them. This favors maintenance over clever mixed-index locking | Equivalent concurrent insert/update attempts across every reindex boundary |
| Rollback representation | Keep a current rollback representation until explicit finalization. If writers resume, maintain it atomically | An unchanged pre-cutover snapshot becomes stale after new writes. A plaintext mirror preserves exposure | Protected writes update mirror or fail atomically, rollback after changed rows, corruption blocks rollback |
| Rollback window | Put an exact deadline and explicit finalization action in the plan. Recommend seven days as a product default, subject to canonical approval | Seven days is a policy choice, not a scientific safety bound. Expiry must not silently drop the mirror or keys | Expiry reports required action. Extension is explicit. Finalization records the lost recovery route |
| Residual plaintext | Report current-row coverage separately from WAL, dead tuples, TOAST, replicas, snapshots, backups, exports, and unknown copies | Current-row encryption does not sanitize previous physical or external copies | Real backup/PITR recovery shows the stated residual boundary. Unknown inventory cannot become PASS |
| Deprotect | Obtain downgrade authorization before the first plaintext staging write, then verify every required value | Staging already creates plaintext WAL and backup exposure. Approval only at cutover is too late | Missing/wrong-target approval denies staging, partial exposure remains reported after crash |
| Removal | Deprotect, verify, switch, run the application without Cryptalis, settle backup reader/key obligations, retire objects, remove package last | Encrypted backups can outlive the package. Removing keys too early destroys recoverability | Package-absent E2E plus archived-backup recovery or explicit approved loss of recovery |

Online operation adds product value for large deployments, but also adds a substantial implementation and audit burden.
It cannot be a fallback when writer inventory is incomplete.
If the final architecture excludes online transitions, mark them UNSUPPORTED BY DESIGN and retain the maintenance procedure as the chosen solution.
Do not leave the design as a roadmap promise.

An operator can finalize the rollback representation before seven days through the explicit contraction action.
That action ends cheap old-binary rollback and records all retained copies.
A deadline reminder must not become automatic destructive approval.

## Recommended operational boundary

### Offline inspection

Offline inspection reads bounded local manifest and source files only. It must not import the backend or execute manifest-supplied code.
It must not discover plugins, read ambient credentials, contact providers, open databases, or execute subprocess hooks.
Live doctor checks require an explicit target and declared access scope.
An offline result must report live schema, external writers, provider health, backups, and deployment state as UNKNOWN.

Test the offline CLI with network access denied, fake credentials, and a backend module that raises if imported.
Test malformed and oversized inputs. Missing live evidence must not become PASS.
These are proposed acceptance tests, not current runtime claims.

### Key cache and outage behavior

Use a process-local bounded cache only for approved payload or search material. Never cache raw root authority in the application.
The cache key must include provider identity, protection domain, tenant/subject scope, purpose, generation, and policy revision.
A cache entry supplies material, not permission. Require current external policy admission for each protected operation.
Provider outage must never select plaintext. Policy-authority outage must deny new operations, including operations with warm material.

Choose explicit maximum entries, bytes, lifetime, and operation/byte usage budgets in the approved profile.
Measure cold, warm, throttled, and unavailable-provider cases before claiming acceptable ordinary workload latency.
For async support, use an explicit awaited preparation boundary and an async adapter. Reject synchronous SDK fallback.
Fork, process restart, and restored VM/cache require new admission and invalidate inherited cache authority.

Revocation prevents admitted use after the defined fence. It cannot recall keys or plaintext already copied by a compromised application.
Record this limit beside shredding claims. Separate provider audit records from cache-hit operation records.

### Audit and diagnostics

Use a small structured event allowlist: operation ID, phase, outcome, target digest, format/generation, policy revision, safe counts, and typed error code.
Do not emit plaintext, key bytes, search terms, SQL binds, raw entity repr, connection strings, or exception-local dumps.
Treat stable row/subject identifiers as potentially sensitive. Use access controls and pseudonymous correlation where possible.
Bound event size and cardinality. Reject newline/control-character injection in human-readable fields.

Keep the durable lifecycle journal separate from best-effort debug logs.
If a required authority/journal write fails, deny transition activation or destructive finalization.
For ordinary diagnostic sink failure, preserve the primary operation error and emit bounded health information through the declared failure channel.
Never drop security events silently or describe failed collection as complete coverage.

Doctor can detect known logging settings and demonstrated sinks. It cannot certify absence of arbitrary host logging.
Canary tests must cover success, errors, DEBUG settings, serializers, traces, provider failures, and migration diagnostics.
Report the exact observed sinks and exclusions.

## Proportionate release policy

Trusted Publishing guidance came from the current PyPI docs index, then its security-model page [O16].
It recommends a dedicated publication environment, job-scoped permissions, and a separate build job.
Attestation guidance explicitly separates artifact origin from trust in its source or builder [O17].
Sigstore identity verification and SLSA provenance give mature mechanisms [O18, O19].
Use them with a narrow verifier policy instead of building a new signing service.

| Control | Recommended requirement | Limit |
|---|---|---|
| Maintainer identity | Hardware-backed authentication for repository and PyPI accounts, recovery methods, reviewed membership and publisher inventory | PyPI requires 2FA, but Cryptalis hardware-token policy is a project choice [O20] |
| Release approval | Protected environment and reviewed release tag. Two maintainers approve security-sensitive releases when two exist | A solo project must report the missing second reviewer. AI review is not independent review |
| Build isolation | Fresh release runner. No untrusted PR code or cache shares the release trust context. No application/provider secrets | Trusted Publishing still trusts the workflow and runner |
| Publication | PyPI OIDC publisher bound to repository, workflow, and environment. Only the publication job gets token authority | Do not describe short-lived credentials as impossible to steal |
| Dependency scope | Minimal runtime dependencies. Separate optional provider/CLI/development extras. Review every dependency addition | A dependency can access plaintext in process |
| Reproducible inputs | Pin and hash all build/test/release dependencies and actions. Use reviewed complete locks and approved artifact hashes | A correct hash can identify a malicious approved artifact [O21] |
| Wheel inspection | Compare release contents to reviewed source. Reject executable .pth, sitecustomize, unexpected entry points, bundled secrets, and unrelated generated files | Legitimate native dependency wheels require separate inventory and review |
| Startup behavior | No network, telemetry, credential reads, database access, shell execution, or provider initialization at import/startup | Verify an installed wheel in a quarantined process. Source intent does not establish artifact behavior |
| Inventory | Generate an artifact-bound SBOM with maintained tooling. Record direct, transitive, bundled native components and omissions | CycloneDX supports dependency/completeness metadata. An SBOM does not establish code safety [O22] |
| Provenance | Bind artifact digest to reviewed source revision and build identity. Verify expected issuer, identity, workflow, and source | A signature from an unexpected identity fails. Valid origin does not prove a safe build |
| Rebuild comparison | Rebuild wheel and sdist in an independent clean environment with pinned inputs. Compare bytes or report exact variance | Claim reproducibility only for artifacts that match under the recorded procedure [O23] |
| Disclosure | Publish a private reporting channel, response ownership, and advisory process. Keep security reports outside diagnostic dumps | Do not invent an unsupported response-time guarantee |
| Critical format flaw | Freeze affected write support, preserve recovery readers, disclose affected formats, and supply a tested bounded migration | Never silently downgrade crypto or delete old read compatibility to force upgrades |

The runtime library must not depend on SBOM generators, scanners, signing tools, or a release service.
Release tooling remains development infrastructure.
No SLSA level, audited status, compliance claim, or Cryptalis-reproduced supply-chain guarantee follows from this policy document.

## Community pain signals and limits

| Signal | What it adds | Authoritative constraint |
|---|---|---|
| Reddit discussion about pgroll [O24] | Developers object to a separate migration language and warn that application/infrastructure rollback can diverge | PostgreSQL lock/rewrite/index behavior remains authoritative [O03, O04]. Cryptalis should keep one manifest and concrete rollback prerequisites |
| Reddit response to LiteLLM [O25] | Developers struggle to distinguish upstream source, package artifacts, credential theft, and installed-host exposure | Maintainer reports and Python .pth semantics establish the relevant facts [O12–O14] |
| SQLAlchemy issue #13439 [O26] | A report describes silent RETURNING result-order errors under concurrent cached statements | The issue is closed and includes an AI-involvement label. No current defect or fix-version claim follows without reproduction |
| pgroll repository [O27] | Existing migration tooling demonstrates the appeal of shadow versions, backfill, and reversibility | Its broad no-lock/instant-rollback language is a vendor claim. It does not establish encrypted backfill or Cryptalis equivalence |

## Opened source ledger

All rows use access date **2026-10-06**. Rolling documentation has no inferred publication date.
Index pages were navigation only. The actual supporting pages follow.

| ID | Actual opened source | Date or edition | What this established |
|---|---|---|---|
| O01 | [PostgreSQL routine vacuuming](https://www.postgresql.org/docs/current/routine-vacuuming.html) | PostgreSQL 18 current docs | UPDATE/DELETE retain row versions. Ordinary vacuum reuses relation space |
| O02 | [PostgreSQL continuous archiving/PITR](https://www.postgresql.org/docs/current/continuous-archiving.html) | PostgreSQL 18 | Base backup plus WAL can restore an earlier cluster state |
| O03 | [PostgreSQL ALTER TABLE](https://www.postgresql.org/docs/current/sql-altertable.html) | PostgreSQL 18 | Lock, rewrite, and constraint-validation behavior depends on the operation |
| O04 | [PostgreSQL CREATE INDEX](https://www.postgresql.org/docs/current/sql-createindex.html) | PostgreSQL 18 | Concurrent build failure leaves invalid indexes and can retain unique enforcement |
| O05 | [SQLAlchemy engine configuration](https://docs.sqlalchemy.org/en/20/core/engines.html) | SQLAlchemy 2.0 docs generated October 5, 2026 | Parameter hiding has specific limits. DEBUG records result rows |
| O06 | [PostgreSQL error reporting/logging](https://www.postgresql.org/docs/current/runtime-config-logging.html) | PostgreSQL 18 | Bind log controls separate non-error and error cases. Truncation is not exclusion |
| O07 | [LiteLLM guardrail logging incident](https://docs.litellm.ai/blog/guardrail-logging-secret-exposure-incident) | Published/event March 18, 2026. Duration unknown | Returned internal request metadata exposed secret headers in logs/traces |
| O08 | [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) | Rolling guidance | Sensitive data exclusion, safe event encoding, and logging-failure tests |
| O09 | [AWS data key caching](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/data-key-caching.html) | Rolling vendor documentation | Cached cryptographic material reduces calls/cost. This is not a Cryptalis benchmark |
| O10 | [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) | Rolling guidance | Memory handling, audit, quotas, outage and backup/restore need explicit treatment |
| O11 | [PyPA advisory via OSV PYSEC-2026-1](https://osv.dev/vulnerability/PYSEC-2026-1) | Published January 28, 2026 at 21:09:02 UTC. Modified February 6 | A compromised account published malicious dydx-v4-client 1.1.5.post1. Upload date absent |
| O12 | [LiteLLM initial security update](https://docs.litellm.ai/blog/security-update-march-2026) | Published March 24, 2026. Page includes March 30 update | Affected PyPI versions, malicious .pth, direct upload, bounded attribution uncertainty |
| O13 | [LiteLLM security townhall](https://docs.litellm.ai/blog/security-townhall-updates) | Published March 27, 2026 | March 24 upload timing and shared CI/static credential/unpinned scanner account |
| O14 | [Python site module](https://docs.python.org/3/library/site.html) | Python 3.14.8 current docs | Executable .pth lines run at interpreter startup regardless of later module use |
| O15 | [TanStack incident postmortem](https://tanstack.com/blog/npm-supply-chain-compromise-postmortem?trk=public_post_comment-text) | Published/event May 11, 2026. Timeline revised May 15 | Cache poisoning and OIDC token extraction enabled malicious npm publication |
| O16 | [PyPI Trusted Publisher security model](https://docs.pypi.org/trusted-publishers/security-model/) | Rolling docs. Reached from PyPI docs index | Trust rests on workflow/IdP integrity. Dedicated environments and job separation narrow exposure |
| O17 | [PyPI attestation security model](https://docs.pypi.org/attestations/security-model/) | Rolling docs. Reached from PyPI docs index | A valid signature proves origin/integrity under trust assumptions, not source/build safety |
| O18 | [Sigstore Python client](https://docs.sigstore.dev/language_clients/python/) | Rolling docs. Reached from Sigstore docs index | Verification can constrain certificate identity and OIDC issuer |
| O19 | [SLSA build provenance](https://slsa.dev/spec/v1.2/build-provenance) | Version 1.2 specification | Provenance includes build definition, dependencies, builder and run details. No inferred project level |
| O20 | [PyPI account help](https://pypi.org/help/) | Rolling docs | PyPI requires 2FA and recommends recovery methods and Trusted Publishing |
| O21 | [pip secure installs](https://pip.pypa.io/en/stable/topics/secure-installs/) | pip 26.2.1 docs. Reached from pip index | --require-hashes requires complete pinned dependencies. --only-binary excludes source distributions |
| O22 | [CycloneDX specification overview](https://cyclonedx.org/specification/overview/) | 1.7 released October 21, 2025. Page lists ECMA publication December 10, 2025 | Direct/transitive dependency and composition completeness metadata exist |
| O23 | [Reproducible Builds definitions](https://reproducible-builds.org/docs/definition/) | Rolling project documentation | A reproducibility claim requires identical specified artifacts from recorded inputs/environment/instructions |
| O24 | [Reddit pgroll discussion](https://www.reddit.com/r/programming/comments/1b1h8q8/introducing_pgroll_zerodowntime_reversible_schema/) | Historical discussion. Search metadata gives February 2024 context | UX and rollback pain signal only. No current capability claim |
| O25 | [Reddit LiteLLM discussion](https://www.reddit.com/r/Python/comments/1s2c1gy/litellm_1827_and_1828_on_pypi_are_compromised_do/) | March 24, 2026 discussion | Conflicting artifact/source/credential explanations justify clear incident guidance |
| O26 | [SQLAlchemy issue #13439](https://github.com/sqlalchemy/sqlalchemy/issues/13439) | Opened July 17, 2026. Closed at access. Fix version not established | Proposed regression scenario for concurrent cached RETURNING. User report, not local evidence |
| O27 | [pgroll repository](https://github.com/xataio/pgroll) | Rolling main README. No release pinned | Multiple schema versions, automatic backfill and rollback are documented product features, not reproduced guarantees |

CycloneDX's generic documentation link failed retrieval. The overview page resolved and supplies only the bounded facts in O22.
No failed retrieval counts as capability evidence.
