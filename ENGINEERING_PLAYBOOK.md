# Engineering playbook

This document owns implementation workflow, evidence discipline and release policy.
The [architecture map](docs/architecture/README.md#documentation-ownership) names technical contract owners.
The [build guide](docs/build-guide.md) orders implementation. The [status](docs/status.md) owns current capability claims.
Read README/architecture, security/lifecycle, compatibility/status, approved decisions/build guide, then this playbook.
Use the [repository reading path](AGENTS.md#deterministic-reading-path) before implementation.
Use SPECIFIED / IMPLEMENTED / VERIFIED with exact evidence scope. Do not describe spike code as product code.

## Manual workflow

The human builder normally types each executable file.
AI may review code, explain contracts, propose a bounded slice and edit documentation.
The user can explicitly authorize direct implementation. Do not infer this from a documentation task.
Implement one [ordered build slice](docs/build-guide.md#ordered-build-slices) per run.
Each slice needs real PostgreSQL 16 tests before the next slice starts.
Advanced range/order/prefix/text work requires all seven slices, then six-gate admission with leakage opt-in.
Slice test success does not promote a full gate.

1. Select one observable behavior and its canonical contract.
2. Explain its purpose, exact file path, code and failure conditions.
3. Supply one meaningful RED test file and one command.
4. Wait for the actual output.
5. Supply one implementation file and explain each important line.
6. Wait for GREEN evidence before the next slice.

Do not supply several executable files at once.
Keep the slice small enough to understand, but complete enough to protect its stated behavior.
An isolated learning experiment can compare alternatives without entering production code or claiming capability.
Record its exact limitations. Never connect unsafe lab authority to production data.

## Fail loudly and explicitly

Nothing important may fail silently.
Use typed failures or explicit command outcomes at every security boundary.
Reject unsupported formats, queries, mappings, provider states and ambiguous authority.
Never return plaintext fallback, unauthenticated bytes, incomplete filtered results or false migration success.

Diagnostics give a stable family/code, operation, stage, safe cause, retry classification and remedy.
Do not echo plaintext, keys, ciphertext bodies, search terms, credentials, SQL/bind values or raw provider exceptions.
Preserve the primary failure when cleanup, collector or error-output handling also fails.
Do not catch an error merely to continue normal work.
Exceptions and command exits must remain observable when their output channel fails.
Short writes, flush errors, broken pipes and closed descriptors are operational failures.
Successful stream delivery does not prove durable storage.

A partial operation records its durable effects and reconciliation state.
Retry only after current inspection proves the action idempotent or identifies the original operation.
An ambiguous commit is not proof of rollback.
Audit/output failure that prevents required evidence blocks the dependent security claim.
The [security failure contract](docs/security.md#public-failure-contract) owns designed codes and exits.
Existing commands remain unchanged in a documentation-only pass. Authorized implementation may replace or remove research-only APIs and commands.

## Test layers

Choose the highest real boundary that exposes the property.

| Layer | Use |
|---|---|
| End-to-end | Public commands or real application/ORM/provider/database behavior, lifecycle and package-free operation |
| Integration | Adapter/driver, external authority, database constraints, provider failure or output/collector interactions |
| Focused unit | Independent crypto vectors, bounded decoders, canonicalization, exact normalization, state-machine edges and deterministic algorithms |

Use end-to-end evidence first, integration next, then selective units.
Do not test each function, private layout, getters, imports or constants merely to increase coverage.
A test must survive reasonable internal refactors and protect a meaningful property or regression.
Use real PostgreSQL and exact provider semantics where the claim depends on them.
Fakes can force local failures. They cannot prove provider custody, IAM, concurrency, restore identity or destruction.
Record which boundary each substitute bypasses.

Test negative cases alongside positive cases.
For output/privacy evidence, prove the collector observes a known injected exposure before trusting absence.
For destruction evidence, prove the recovery route works before asserting it no longer recovers.
Preserve crash, race, stale-worker, format and semantics regressions.
Use deliberate generators/seeds and meaningful bounds, not arbitrary case-count targets.
Tests passing once and high coverage do not establish production safety.

Run focused checks that exercise the changed contract.
Broaden checks when failures, new changes or unresolved risks justify them.
Record commands, versions, environment, outcomes, scope and limits.
Do not label an unrun or unavailable check successful.

## Review and evidence

Every change has one contract owner, implementation delta and meaningful validation.
A pull request explains the concrete trigger, resulting behavior, important constraints and actual checks.
Link the relevant design decision and named production gate.
Preserve source evidence and provenance. Distinguish documented, exercised, independently observed, operator-attested and independently reviewed facts.
A signature authenticates bytes and issuer within its trust assumptions. It does not establish measurement truth.

Before deleting or merging documentation, map each normative requirement to its new owner or an explicit dropped reason.
Do not retain duplicate contracts simply to preserve old filenames.
Use source history for historical working notes.
One failed required check cannot disappear from the selected inventory to make a result green.
Skipped/inapplicable checks retain their reason and evidence. UNKNOWN never becomes PASS.

Use installed secure-default and threat-model skills where relevant.
Human cryptographic review remains mandatory for the [expert review list](docs/decisions.md#independent-expert-review).
No AI review or vendor document supplies an audit.
Do not invent primitives, committing wrappers, KMS, SQL parsers, scanners or package-signing tooling.

## Release gate

The selected runtime remains blocked until every applicable [build gate](docs/build-guide.md) passes in a released compatibility cell.
No production claim follows from this documentation reset or the current test count.
A release requires these independently reviewable artifacts:

1. Exact interpreter, OS, driver, crypto wheel/native backend, selected provider SDK, database build and service/workload identities.
2. Complete approved adversarial behavior evidence, lifecycle exercises and package-free removal/backup-reader tests.
3. Independent cryptographic/security review, resolved material findings and an explicit residual-risk statement.
4. Whole-backend hot/cold/outage and lifecycle benchmarks against the same unprotected backend.
5. Reviewed manifest/format compatibility, immutable old-reader dependencies and tested critical-flaw response.
6. Dependency inventory, locked hashes, SBOM, inspected built artifacts, provenance and a verified publication identity.

The release process uses mature PyPA, Sigstore, CycloneDX and provenance tools.
Maintainers use phishing-resistant authentication where available, protected recovery methods and separate release identities.
Use PyPI Trusted Publishing with an exact repository/workflow and protected release environment.
Build in an isolated job without publication authority or production credentials.
Publish only reviewed, already built artifacts from a dedicated job.
Pin actions and tools by immutable revision. Treat caches, untrusted pull requests and third-party scanners as untrusted inputs.
Short-lived OIDC credentials reduce static-secret exposure. Compromised runners can still steal them.
No provenance or valid signature proves the package contains safe code.

Lock direct and transitive dependencies to exact versions and hashes.
Deployment uses pip `--require-hashes` and wheels admitted for the selected platform. Record native wheel provenance.
Minimize runtime dependencies. Maintain a CycloneDX SBOM with dependency/composition completeness limits.
Inspect wheel and sdist contents, startup/import behavior, executable `.pth` files, entry points and dependency changes.
Reject unapproved network, subprocess, credential or telemetry behavior during installation/import.
Rebuild independently from recorded inputs where practical. Claim reproducibility only for artifacts whose equality was actually demonstrated.
Investigate and record any reproducibility difference before release.

The [2026 incident ledger](docs/research/reset-operations-release-evidence.md) includes PyPI account theft, malicious startup files and npm runner/token compromise.
It is a dated sample, not a complete incident census.
Those incidents require artifact and runner controls even when repository source appears clean.
Use standard private security-advisory reporting with published contact and response ownership before a public release.
Until that channel exists, production support is blocked. Do not invent a reachable security email.

For a critical key/format/release flaw, stop new admission and publish bounded affected-version guidance.
Preserve required old readers in an isolated recovery path.
Plan verified re-encryption/reindex or package replacement. Rewrap alone does not cure an exposed data key.
Do not destroy old recovery keys before the corrected route passes full verification.
State already disclosed data and irreversible loss boundaries explicitly.

## Documentation-only work

In a documentation-only pass, preserve source, tests, fixtures, dependencies, build/CI files and existing user changes.
That write boundary does not make current abstractions permanent.
During authorized implementation, review every reuse against the final architecture and replace unjustified code/tests/contracts.
Inspect links, code examples, ownership, meaning, internal versions, claim status and traceability.
Search the entire tracked tree for obsolete contracts. Historical source names do not become new runtime claims.
Do not run the project test suite unless a non-documentation file changed.
Inspect the final Git diff and verify that only authorized documentation changed.
Report document checks separately from runtime gates that were not executed.
