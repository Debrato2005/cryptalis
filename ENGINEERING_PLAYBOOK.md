# Engineering Playbook

This file owns contribution, explicit failure policy, verification, migration review, and release processes.
[README.md](README.md) owns product scope. The [architecture blueprint](docs/architecture/README.md)
owns design. The [backend checklist](docs/backend-build-checklist.md) owns implementation state.
[Prior art](docs/prior-art.md) owns competitive claims. The
[learning-first philosophy](docs/learning-first-research-philosophy.md) governs research scope and
decisions to build or integrate components.

## Working agreement

- Do not describe planned behavior as implemented or implemented behavior as verified.
  Do not describe a vendor statement as a Cryptalis measurement.
- For every security change, state the protected threat, plaintext boundary, leakage from each capability, and failure behavior.
- Apply the [explicit failure policy](#fail-loudly-and-explicitly) at every runtime and tooling boundary.
- Treat tenant and subject context as an authenticated authorization grant.
  An identifier from a request, model, `ContextVar`, session, or pooled connection does not establish authority.
- Never expand a search capability merely to make a test pass.
  Capability changes require a review of leakage and migration consequences.
- Generated schema and migrations are proposals that require review. They do not authorize production changes.
- Preserve the documentation map with one owner per contract. Link to decisions instead of copying them.
- Reject scope that cannot pass a falsifiable prototype or benchmark gate.
- Do not reject work merely because a competitor already implements it.
  Record its learning value, reference systems, correctness oracle, maintenance cost, and production or educational classification.
- Keep educational implementations of known constructions separate from components approved for production.
  Show that separation in packages, configuration, reports, and public claims.
- Treat every documented Cryptalis subsystem as active program scope.
  Dependencies and evidence gates limit integration and claims.
  They do not impose a semester ceiling or prohibit parallel research and isolated experiments.

### Settled architecture review rules

The [blueprint](docs/architecture/README.md#load-bearing-decisions) owns these decisions.
Treat this list as review prompts, not a second technical specification.

- Check desired versus active authority and target-bound plan reinspection at every mutation boundary.
- Block real ciphertext until domain/representation/descriptor/suite/exact-key composition freezes with reviewed evidence.
- Keep trusted identity at the normal Session boundary. Reject low-level public crypto or bypass controls.
- Use the one offline transition engine first. Keep online, search, async, fleet, and broad assurance behind separate gates.
- Check explicit approval for plaintext publication and each irreversible cleanup, with truthful recovery and copy residue.
- Quarantine restored targets. Admit only through current external authority and reviewed executable-object inventory.
- Reject unsupported DB-profile cells and incompatible writers before protected work. Use one active writer version initially.
- Require artifact provenance separately from evidence signing before public release.

The [P0 documentation register](docs/architecture/README.md#p0-documentation-review-register) records each pending review.
The [unresolved register](docs/architecture/README.md#unresolved-research-questions) keeps Q1–Q5 open.
Do not implement dependent runtime crypto, ORM, migration, KMS, restore, or decommission behavior before researched closure and P0 documentation review.
Documentation reconciliation alone does not supply independent review or permission to cross those gates.
Follow [C33–C40](docs/backend-build-checklist.md#ordered-foundation-slices) in behavior-first slices.
Reject a PR that silently broadens support, claims absent evidence, or crosses an unapproved irreversible boundary.

## Fail loudly and explicitly

**Nothing important may fail silently.**

This section owns the failure policy for application code, adapters, CLI commands, background work, tests, build tools, and automation.
Prefer explicit state and contracts, deterministic behavior, strong validation, narrow interfaces, actionable errors, and observable failures.
Do not rely on implicit assumptions, silent recovery, or undefined "best effort" behavior.

- Propagate every failure through a typed error, exception, non-zero exit status, or explicit failure value that callers check.
  Never swallow exceptions with `except: pass`, empty handlers, or equivalent patterns.
  Never ignore subprocess exit codes or failed I/O, parsing, validation, database operations, cryptographic operations, or external calls.
- Validate inputs and check invariants at trust boundaries and important state transitions.
  Reject malformed, ambiguous, unsupported, or unsafe input early.
  Fail fast when continuation could produce incorrect state. Security-sensitive behavior must fail closed.
  Reject impossible states explicitly.
- Identify what failed, where it failed, and relevant safe context in errors and diagnostic logs.
  Preserve the original cause when wrapping errors.
  Use specific failures internally. Generic public errors require a documented need at an API boundary and a safe diagnostic channel.
  Never expose passwords, keys, tokens, plaintext secrets, sensitive cryptographic material, or unredacted exception payloads.
- CLI failures must return meaningful non-zero exit codes. APIs must return explicit, stable error responses.
  Use the [error and CLI contract](docs/architecture/manifest-context-api.md#errors-and-observability) for categories, safe fields, and exit mappings.
- Make file and state mutations atomic where practical.
  Otherwise, define interruption, rollback, and recovery behavior that prevents unexplained partial state.
  Surface cleanup or rollback failures without hiding the primary failure.
  Never report success until all required postconditions pass.
- Never substitute defaults that hide corruption, incompatibility, missing configuration, security failure, or programmer error.
  Intentional fallback must have an explicit, documented contract, an observable result, and failure-path tests.
  Recovery must have a defined reason, trigger, and outcome. Defensive code must not hide bugs.
  Bound retries by attempts and deadlines under the operation's idempotency contract.
  Expose exhausted retries as a terminal failure. Retries must not hide persistent failures.
- Await promises and asynchronous tasks, or assign an owner that observes their completion and failure.
  Background work must surface failures through a defined, observable error channel.
  Cancellation must reach callers and obey the cleanup contract.
- Keep warnings separate from errors. Never downgrade correctness or security failures to warnings.

The [failure-path test requirements](#failure-path-evidence) define the evidence required for this policy.

## Solo manual-typing workflow

Cryptalis has one human builder. In the default learning workflow, artificial intelligence (AI)
assistance directly updates documentation only. It supplies source, tests, migrations, build
configuration, containers, and continuous integration (CI) files for manual typing.
An explicit user instruction can authorize direct implementation for a named scope.
After that scope is complete, resume the manual workflow unless the user extends authorization.

Prerequisite: The builder understands the previous file's result before the assistant supplies the next file.

The assistant supplies implementation help in conversation, one file at a time:

1. Explain the file's responsibility, interface, invariant, and dependencies.
2. Select the highest realistic test boundary for the behavior and failure.
   Reuse an existing scenario when it already protects the invariant.
   If new evidence is necessary, supply one complete test file or revision for manual typing.
3. Give the exact command and expected result. New behavior starts with a failing test where practical.
4. Diagnose the builder's actual output.
5. Supply one complete implementation file for manual typing.
6. Run the narrow tests.
7. Run the applicable broader tests.
8. Inspect SQL, rows, logs, or other evidence.
9. Update documentation and checklist state before the next file.

The assistant withholds the next file until the builder understands the previous result.
Within the manual workflow, bulk source dumps and autonomous scaffolding violate the learning goal.
See the [complete build guide](docs/cryptalis-build-guide.md).

## Change workflow

Prerequisite: Identify the blueprint section and checklist gate that the change affects.

1. Read the affected blueprint section and checklist gate.
2. Write the invariant, supported operation, and expected failure.
3. Add or extend a failing behavior test at the highest practical boundary.
   Include positive and negative controls for the affected security property.
4. Implement the smallest behavior that the manifest defines and the controls accept.
5. Run the targeted tests.
6. Run the full applicable boundary and compatibility suite.
7. Inspect emitted SQL, database rows, logs, errors, traces, audit data, and artifacts for sensitive data.
   Sensitive data includes seeded plaintext, key material, raw search tokens, and credentials.
8. Update the compatibility matrix, benchmark evidence, checklist, and owning documentation.
9. Commit one reviewable security outcome.

## Pull-request requirements

Every pull request states:

- Changes to logical and physical behavior
- Affected manifest, schema, query, and key versions
- Threat and leakage consequences
- Supported and rejected synchronous, asynchronous, object-relational mapping (ORM), and Core paths
- Each path's classification as transparent, reject, detect, or unobservable, with exact context provenance
- Migration, rollback, rotation, and shredding impact
- Exact commands and evidence
- Remaining unknowns or implications for stop gates

Reviewers block a change when:

- The change violates the [explicit failure policy](#fail-loudly-and-explicitly), including its fallback, diagnostic, or postcondition requirements.
- Plaintext can enter protected storage through a supported path.
- A known unsupported query silently executes with changed semantics.
- The system guesses a tenant, subject, record, field, normalization, or index domain.
- Remote key management service (KMS) or Transit input/output (I/O) lacks an explicitly selected and tested profile.
  The profile must specify warm-up, a greenlet bridge, or deferred access, with visible failure and cancellation behavior.
- A cache can outlive its declared fence, lease, or time-to-live (TTL) model.
- A shredding claim omits shared search-index residue.
- An autogenerated migration hides locks, data motion, coexistence, or irreversible contraction.
- A claim says transparent access prevents application logging.
- Audit or receipt claims exceed their signer and witness model.
- Superiority, performance, compatibility, or compliance claims lack reproducible evidence.

## Test layers

This section owns repository testing policy. Subsystem contracts own exact properties and admission gates.
Local pytest checks cover the implemented manifest, candidate-envelope, and terminal-inspection boundaries.
CI and full protection workflow tests remain pending.
The layers below guide test selection as implementation proceeds.

Test important behavior at the highest realistic boundary.
Add lower-level tests only when higher-level checks cannot detect the failure efficiently or precisely.
The default confidence order is:

1. End-to-end (E2E) tests
2. Integration or subsystem tests
3. Contract or boundary tests
4. Selective unit tests with unique fault-detection value

### Observable behavior and boundary selection

E2E tests are the primary confidence layer when the workflow is executable.
Use the real entry point and implementations in a disposable synthetic environment.
For Cryptalis, a workflow can start at a registered ORM session, public API, or CLI.
A host-service request test applies when that adapter exists. A user interface (UI) test applies only to an implemented UI.

| Boundary | Required behavior or useful failure case |
|---|---|
| E2E | Authenticated grant -> key preparation -> encrypt -> PostgreSQL commit -> fresh-session retrieve -> authenticate -> decrypt. Inspect SQL and rows for plaintext. Exercise equality results and authorization denial |
| E2E | CLI invocation -> reviewed proposal or redacted evidence artifact -> exit code. Migration interruption -> restart -> resume. Key creation/use -> rotation/revocation -> supported restore denial |
| Integration/subsystem | ORM/crypto/persistence round trips, query/SQL semantics, provider/cache fencing, concurrent uniqueness, migration recovery, and collector health. Use when E2E is costly or insufficiently diagnostic |
| Contract/boundary | Public formats, typed errors, provider protocols, version rejection, import/build quarantine, and evidence interoperability |
| Selective unit | Cryptographic wrappers, nonce/initialization vector (IV) rules, key derivation function (KDF) and key-format validation, authentication tags, encoding/canonicalization/normalization, parsers, deterministic algorithms, protocol framing, policy evaluation, and lifecycle state machines, including bounded shredding transitions. Target difficult or security-critical edge cases |

Before the complete workflow exists, use the highest executable subsystem or contract boundary.
Record the missing dependencies and pending E2E evidence. Passing a lower layer does not pass a workflow gate.
Test ordinary ORM state, rejected query paths, schema constraints, migration phases, and lifecycle faults under their canonical gates.

Test important failures as well as successful operations.
Include malformed input, corrupted ciphertext or tags, wrong/missing/revoked keys, and permission denial.
Exercise partial writes, database failures, network interruption, provider timeouts, and unexpected responses.
Include restart during an operation, concurrency, resource exhaustion, and invalid state transitions.
Assert the defined safe outcome, transaction state, and absence of unauthorized plaintext release.

### Failure-path evidence

Apply the [failure policy](#fail-loudly-and-explicitly) at the highest practical test boundary.
Assert the error category, safe operation/stage context, propagation, and meaningful exit status or stable API response where applicable.
Check that failed operations emit no success result and leave only the state permitted by their recovery contract.
Exercise bounded retries, explicit fallback, asynchronous failures, cancellation, and failed cleanup where those behaviors exist.
Check diagnostic redaction and cause preservation without exposing sensitive fixtures.
Successful cases must establish the required postconditions.

### Real dependencies and selective substitutes

Prefer real implementations, then local/containerized instances, then protocol-compatible test servers, then boundary fakes, then mocks.
Use synthetic values and local test keys. Never place production data, credentials, or key material in fixtures.
Use mocks for rare fault injection, costly external APIs, nondeterminism, or specific protocol errors.
Keep substitutes at explicit boundaries. Record which real dependency behavior remains unverified.
An emulator cannot establish a cloud provider's actual deletion, restore, or outage semantics.

Do not assert internal call chains, private class structure, constant substrings, trivial getters, or wrappers merely to exercise code.
Avoid tests that repeat the implementation or mock nearly every dependency.
Preserve useful existing tests, including unit tests. Do not remove a test solely because of its layer.

### Test selection, agents, and regression history

Before adding a test, name the real regression or important security, correctness, or reliability property it detects.
Check whether a higher boundary already detects that failure.
Explain any unique value from a lower-level test. The assertion must survive a valid internal refactor.
Do not mechanically generate tests for each new function or add tests merely to increase coverage.
A new implementation file does not automatically require a new test file.

For a real defect:

1. Reproduce the observable failure.
2. Add the smallest useful regression case at the highest practical boundary.
3. Confirm the case fails before the fix where practical.
4. Fix the defect.
5. Confirm the case passes after the fix.

Run the affected broader workflows. Keep feasible user-reported failures as permanent regression cases.
Record any limit that prevents reproduction or the expected failing run.

### Security evidence and diagnostics

Correctness tests, including E2E tests, do not establish cryptographic security.
Keep published known-answer vectors and composed protocol checks under the crypto owner's gates.
Test security-sensitive logic below E2E when vectors or deterministic edge cases require precision.
Constant-time-sensitive behavior needs appropriate analysis. An ordinary timing assertion cannot prove constant-time execution.
Likewise, interface denial tests cannot prove key-byte destruction or universal erasure.

Derive negative and authorization tests from the threat model and invariant IDs.
Use property tests and fuzzing for parsers, untrusted formats, serializers, query IR, and state transitions where useful.
Check exact payload and codec round trips, authentication rejection, and unauthorized alternate paths.
Revocation and destruction properties must match the declared managed boundary and recovery limits.
Record seeds and minimized synthetic counterexamples.
Dependency scanning, static analysis, secret scanning, protocol conformance, and adversarial trials supply separate evidence where applicable.

Security evidence requires positive and negative controls. Share controls across scenarios when their scope permits it.
Missing observation is `INCONCLUSIVE`. The assurance contract owns collector and mutant requirements.
Retain reproducible commands, versions, seeds, redacted results, and useful SQL/request traces or CLI output.
Include screenshots or UI traces only where UI behavior matters. Avoid artifact collections without diagnostic value.
Apply the assurance contract's privacy, integrity, retention, and cleanup rules to test artifacts.

### Coverage and CI confidence

Line coverage is diagnostic data that can reveal untested areas. It is not a quality target.
Do not use test count, function coverage, or a repository-wide coverage percentage as a completion gate.
Report critical workflows exercised, security properties checked, failure modes and boundary interactions exercised, and regressions caught.
Keep exact behavioral corpus, compatibility, and control thresholds in subsystem gates.
Those thresholds are distinct from line coverage and do not permit arbitrary test inflation.

Schedule fast deterministic checks first, then focused integration/security checks, then critical E2E workflows.
Run extended fuzz, chaos, or adversarial suites in the applicable isolated lane.
Execution order controls feedback cost. It does not change the confidence hierarchy above.
Required workflow failures, missing evidence, and unresolved security controls block their capability gates.
A fast subset cannot establish release confidence alone. Do not skip a required E2E gate merely to meet a time budget.
The [assurance CI contract](docs/architecture/assurance-evidence.md#11-ci-reference-lab-and-regression) owns lane safety and result handling.
Optimize regression-detection value per developer and CI cost, rather than the number of tests.

## Crypto and key-management rules

- Production profiles use established libraries and reviewed constructions.
  No project-designed cipher or insufficiently reviewed order-revealing encryption (ORE), order-preserving encryption (OPE), or text-search construction qualifies as production secure.
  Isolated research profiles can contain independent implementations of known constructions.
- Freeze an algorithm suite only with versioned envelope and index formats and test vectors.
- Generate nonces and salts with the chosen library's required strategy.
  Bind canonical context as additional authenticated data (AAD).
- Use separate key domains for encryption, equality, join, migration, audit, and receipt operations.
- Cloud KMS or Vault wraps tenant branch material. Normal field crypto is local.
- Review provider preparation at the visible Session boundaries in the [normal API](docs/architecture/manifest-context-api.md#public-python-surface).
  Keep key preparation internal. Normal callers supply trusted identity once.
  Greenlet and deferred alternatives require their measured profile. Do not permit undeclared remote I/O.
- Provider adapters expose actual version, deletion delay, restore, export, outage, and audit semantics.
  They must not present providers as interchangeable.
- Keys, plaintext, raw search tokens, request bodies, and ciphertext bodies never appear in logs, metrics labels, traces, audit events, or receipts.

Changes to a primitive, envelope, AAD, key hierarchy, normalization, index domain, or access mode require architecture review.
Changes to a provider, cache, rotation, revocation, or shredding also require that review.

The [crypto owner](docs/architecture/crypto-search-lifecycle.md#key-operation-contract) distinguishes nine key operations and initial cache authority.
Review rotation claims against actual wrapper, payload, search, provider, and recovery effects.
Do not infer key commitment from exact-key syntax or nonce-misuse resistance.
The existing schema-1 descriptor and private F1/W1/scalar parsers establish structural boundaries only.

## SQLAlchemy rules

- The public logical attribute and hidden physical attributes remain separate.
- Scalar types do not guess row, tenant, or subject authority. Default scalar crypto is local.
  An explicit experiment with bridged or deferred access obeys its named compatibility contract.
- The protected-session context establishes validated tenant and key state before local ORM work.
- Ordinary sessions keep one immutable authenticated tenant authority.
  Cross-tenant administration, workers, migrations, and restores use explicit grants with separate scopes.
- Comparators explicitly map only declared operators. Every other encrypted operation raises an error.
- Classify every path as transparent, reject, detect, or unobservable.
  Name each path in the compatibility matrix with exact dependency versions.
- Direct drivers and external extract, transform, and load (ETL) processes are outside ORM enforcement.
  They require a separately reviewed path.
- Database domains and checks add defense in depth. They do not prove authentic Cryptalis output.
- Design database checks for malformed envelopes only after envelope, index, and coexistence bytes freeze.

## Migration rules

Use the [ORM transition owner](docs/architecture/orm-schema-migration.md#migration-state-machine-and-concurrency) for exact phases and recovery semantics.
Initial work uses offline writer quiescence, idempotent row/chunk revisions, terminal full verification, and authenticated CAS activation.
Review target/precondition reinspection, overlap locks, interrupted DDL/provider effects, and abandoned finalizers.
Coexistence, dual writes, distributed leases, and online verification remain future strategy review topics.

Generated revisions must show:

- Physical additions/removals, exact schema and format versions, and reviewed Alembic heads
- Writer exclusions, lock classes/timeouts, scan/rewrite behavior, and disk/WAL/provider budgets with uncertainty
- Retry, cancellation, resume, invalid-index reconciliation, source/target row coverage, and commit/CAS ambiguity
- Exact retained rollback data/keys/readers, expiry, restore prerequisites, and irreversible approval actions
- Deprotect plaintext exposure, decommission inventory, and copy exclusions

Autogeneration never applies migrations. Declaration removal never drops data.
Incomplete or inconclusive evidence blocks SWITCH and FINALIZE.
Review protect/reconfigure/deprotect workflows and hostile restore/exit behavior before support.
Every approval belongs to the exact irreversible boundary, not each reversible phase.

## Search-capability review

Search is disabled in the initial runtime target.
Later equality/IN/uniqueness uses offline reindex before any online dual-generation profile.
The [crypto owner](docs/architecture/crypto-search-lifecycle.md) owns leakage, normalization, nulls, and term retirement.

An enabled capability requires:

1. Actual application query semantics
2. A reviewed construction or library
3. A leakage statement for the field
4. Physical representation and storage budget
5. Normalization and null semantics
6. Offline reindex and retirement. Dual-index migration only for a later online profile
7. Subject-shredding treatment
8. Tests for unsupported operations
9. A benchmark against the no-search baseline

Optional analysis can recommend capabilities. The shared transition planner cannot activate a recommendation or rewrite desired policy.
Equijoin, range/order, text, fuzzy, and JSON capabilities remain unavailable until their individual gates pass.

## Verification safety

Scanners, payloads, deliberately vulnerable fixtures, test credentials, and destructive scenarios stay outside production packages and built wheels.
Verification targets are loopback or a named disposable network.
They use synthetic data, exact authorization, and strict rate, time, and request limits.

The harness reports exploit success, database access, protected extraction, plaintext exposure, and Cryptalis control outcomes separately.
It is not a web application firewall (WAF) or proof of universal security.
Active research can implement generic scanner concepts internally.
The product claim remains limited to measured findings and correlation with protected data.
Public-target scanning, denial of service, credential attacks, stealth, and persistence are outside scope.

## Release gate

A release candidate remains blocked until all of these conditions hold:

- The supported compatibility matrix passes from a clean checkout.
- Schema exercises and migration recovery and restore exercises pass.
- Algorithm and provider vectors pass, and reviewers examined dependencies and licenses.
- Evidence for key caches, rotation, revocation, and shredding matches documented bounds.
- Positive and negative controls establish that the verification harness works.
- Scans for seeded plaintext and secrets pass across the database, logs, traces, audit, receipts, reports, and artifacts.
- Benchmarks are reproducible and labeled as measurements.
- An independent reviewer examined cryptographic use and destructive migration behavior.
- Prior-art and demand research are current.
- Release notes state limitations, failed experiments, leakage, and incompatible changes.

Before a public release, also require artifact-bound product provenance:

- Locked dependencies and exact runtime/native crypto artifacts with source, license, and supported-version review
- Minimal wheel and separate experimental/lab distributions, with forbidden-import and secret-bearing-artifact checks
- SBOM, protected build/publishing environment, PyPI Trusted Publishing, and verified artifact-bound attestations
- Source-to-wheel contents and reproducibility checks where feasible, with explicit limits
- Wrong issuer/workflow/repository/artifact, tampered wheel, dependency/lock drift, and emergency dependency-response evidence

The [primary tool ledger](docs/research/assurance-tool-evidence.md#product-artifact-provenance) owns external provenance facts.
Evidence signing cannot vouch for a substituted wheel. Provenance establishes origin and bytes within its trust chain, not source correctness.
Required profile tests and independent review remain separate release gates.
Use a deliberately noncompliant plan/API/release review fixture to check these rules and the canonical-owner links.

A release cannot use “production-ready,” “better,” “more secure,” “zero leakage,” or compliance claims without a definition and evidence set.
The definition and evidence set must support separate review.

## Documentation-only finalization and evidence admission

Reviewed 2026-09-30. Obey the [canonical ownership map](docs/architecture/README.md#documentation-ownership).
The technical requirements above are review prompts.
Their linked architecture owners define precise algorithms, state machines, limits, and operator semantics.
A process summary must not create an alternative technical decision.
Maturity is [per capability](docs/backend-build-checklist.md).

A documentation-only pass can run read-only or ad hoc validation.
It can record exact commands and output in a Markdown audit.
It does not create application code, tests, migrations, build or CI configuration, or fake checker scripts.
A working audit log is not committed executable evidence.
Human review, scripted checks, first-party AI challenge, independent expert review, and executable capability evidence are distinct provenance classes.
No checked capability rests on prose alone.

Before a stronger public or production claim, independent checkpoints examine cryptographic use and leakage, authenticated identity provenance, and destructive migration and recovery.
They also examine distributed fencing and restore assumptions, collector and oracle methodology, and the claim and release process.
Record reviewer identity, competence, conflicts, exact artifact scope, findings, and resolution.
AI subagents in this pass supply first-party adversarial review. They do not supply external independence.

Documentation checks on a snapshot must examine relative file links, generated heading anchors, case, and fences.
They must also examine claim, maturity, and status consistency, canonical ownership, terms and versions, evidence checkboxes, and W-1..W-5.
Checks for deleted references and the boundary that permits documentation writes only are also necessary.
Store command text, raw results, and snapshot hashes.

A future maintainer can convert the documented check into a manually typed checker under the learning contract.
A missing or unexecuted check is explicitly unverified.
Markdown checks imply no build, package test, or production-security conclusion.
