# Assurance, Analysis, and Evidence Contracts

Status: Accepted design contract. Unimplemented and unmeasured

Reviewed: 2026-10-01

This is the canonical owner of Doctor analysis, minimum-leakage planning, ProtectionGraph, writer
provenance, Verify, Pentest, collectors, result schemas, evidence integrity and assurance gates.
The [architecture hub](README.md) owns cross-system invariants. The
[manifest/context/API contract](manifest-context-api.md), [ORM/schema/migration contract](orm-schema-migration.md)
and [crypto/search/lifecycle contract](crypto-search-lifecycle.md) own their respective controls.
The [assurance research](../security-assurance-suite-research.md) retains research rationale,
learning tracks and product falsifiers. The [tool evidence ledger](../research/assurance-tool-evidence.md)
owns dated external capability statements. The [backend checklist](../backend-build-checklist.md)
alone records implementation progress.

All interfaces below are proposed specifications. No APIs are available. Every numeric threshold is a proposed gate declared before measurement.
These thresholds are not benchmark results or assurance probabilities. This document asserts no experiment, independent assessment, signed receipt or production support.

## 1. Responsibility and trust

Doctor is the static analyzer. It reconciles declarations with observations and reports bounded hypotheses from static analysis or runtime evidence.
Plan proposes a reviewable capability or migration change. It cannot edit declarations or authorize deployment.
Verify runs deterministic verification of protection assertions.

Pentest is the authorized lab scenario engine. It exercises lab attacks and imports findings from mature engines.
Evidence serializes these distinct observations.
A generic vulnerability can be confirmed while a specific Cryptalis confidentiality assertion holds.

The runtime protection package does not import scanner engines, attack payloads, lab secrets,
packet-capture tools or Doctor's semantic engine. Assurance uses explicit adapters to read immutable Protection Manifest and compiled-plan snapshots, the compatibility catalogue and redacted runtime events.
It cannot modify authoritative policy, release or destroy a key, apply a migration or grant tenant
authority by reporting a finding. Only an explicitly authorized disposable scenario can mutate a provider through the lifecycle API. Ordinary Doctor and Verify collectors cannot mutate providers.

First-party signatures establish a producer and exact bytes under a verification policy.
They do not establish independent assessment, honest instrumentation or global absence of copies.
A compromised application may forge its own events. Evidence states that trust limitation.

## 2. Typed interfaces and version boundary

These are language-neutral record contracts. Fields named `*_id` are typed identifiers, not
interchangeable strings. Digests name algorithm and lowercase hex. Root records contain `schema_version`, `producer_version` and `created_at`. They record UTC time precision and the clock source.
Enforced durations use monotonic time.

These records use the shared restricted JCS
profile. The following field conventions do not relax it:

- `created_at` and wall-clock interval endpoints are UTC RFC 3339 strings with `Z`, exactly nine
  fractional digits, and a separate nonzero `clock_resolution_ns` decimal-string field. Padding
  unavailable subsecond precision with zeroes does not imply nanosecond measurement accuracy.
  Record clock identity, synchronization uncertainty and discontinuities. Wall time never enforces a lease.
- Counts, byte lengths, line and column offsets and bounded ordinals are JSON integers in 0..2^53-1.
  Larger integer domains use explicitly typed decimal strings. No float, exponent notation, NaN
  or infinity enters canonical producer JSON, including tool-derived metrics and extensions.
- Every duration, monotonic offset, clock resolution and lateness budget is an unsigned decimal
  string of **nanoseconds**, named `*_ns`, matching `0|[1-9][0-9]*`. No sign, leading zeroes or
  fractional text. Monotonic endpoints also bind the same clock and boot incarnation. Values
  from distinct monotonic clocks cannot be subtracted without an evidenced conversion.
- Fractional measurements and ratios use a schema-declared rational record of decimal-string numerator
  and positive denominator plus an ASCII unit. Signed numerator uses `0|-?[1-9][0-9]*`. A rational is reduced with a positive denominator. Approximate source floats retain their exact raw artifact and a documented descriptor for conversion and rounding.
  This descriptor prevents a silent claim of exact measurement.
  Unknown, absent and not-measured remain distinct declared states, never zero or null by accident.
- A schema may prescribe integer units for a particular field. The field name and version bind
  that unit. Producer, model and tool versions and accepted enum sets come from pinned catalogues.

| Interface | Required input | Required output and refusal |
|---|---|---|
| `DoctorInput` | manifest/compiled plan. Model inventory. Source revision/dirty digest. Stages. Framework lane. Policy. Budgets | `DoctorReport`: findings, coverage, unknowns, graph observations. Mismatched plan/manifest refused |
| `AnalysisWorkspace` | source digests, parser/IR/model-pack versions, exclusions and limits | syntax/semantic/query IR, symbols, CFG/call/data-flow edges and unknowns. Static mode never imports arbitrary app modules |
| `PlanInput` | manifest, requirements/constraints, query observations, classification/leakage policy | `PlanProposal`: alternatives, changes, unknowns, leakage/lifecycle/storage and migration obligations. Never applies |
| `GraphObservation` | typed subject/object, relation, evidence, basis, target/run/version/interval | immutable validated observation and conflict/unresolved state. Dangling evidence/scope mismatch refused |
| `ScenarioSpec` | ID/version, invariants, preconditions, actions/oracle, collectors, controls, cleanup, budgets | `ScenarioResult`. Unsafe target/unsupported version or privilege refused before action |
| `CollectorSpec` | ID/version, source/point, classes, watermarks, transforms, limits, health/control methods | `CollectorReceipt`: coverage, cursors, loss, redaction stage, health and artifacts. Inaccessible source unavailable |
| `ToolAdapter` | tool/edition/image/config/rules digests, supported schema, scope and caps | source findings plus execution state and redacted artifact hash. Malformed/partial output never clean |
| `EvidenceBundle` | result, graph, receipts, artifacts and replay descriptors | canonical manifest plus detached wrapper. Missing required member refused |

Schema majors are incompatible. Readers reject an unknown major or unknown required security fields before they evaluate a gate. Optional namespaced `extensions` are preserved but cannot strengthen conclusions. Rule and scenario meanings cannot change in place. Change their version. Alternatively, assign a new ID and `supersedes`.

IR, graph, result, scenario, pack, collector and tool-output schemas version independently. An
adapter version cannot imply newer tool support.

Compare results or create a baseline only when these properties match:

- Target role
- Invariant and check version
- Asset identity
- Manifest and format compatibility
- Collector requirements
- Policy

Otherwise, emit `reclassified` or `not_comparable`. Upconverters preserve original bytes, their digest and the conversion artifact. They cannot manufacture missing health, context or controls.
They cannot turn incomplete old results into `PASS`.
Unsupported tool editions remain `NOT_RUN`.

Comparison is an internal evidence operation with the compatibility preconditions above.
`evidence validate` checks schema, inventory, bytes, trust policy and required controls. It cannot turn a failed protection assertion into success. `evidence export` renders selected canonical results after privacy and integrity checks. It has no implicit upload.
Signing or attestation is an optional bundle-production adapter, separately authorized by a signing policy. Proposed
`evidence compare` or `evidence attest` CLI extensions remain research-only until the shared API
owner approves their names, configuration, failure and exit contracts. No second public CLI is
specified here.

## 3. Doctor pipeline and semantic workspace

Doctor executes a dependency graph of explicitly selected stages. `StageReceipt` binds stage
ID/version, required predecessor receipts/input digests, privilege, selected/not-selected state,
completion, output hashes, budget use and diagnostics. A stage failure preserves earlier observations
and blocks only dependent affirmative conclusions. A skipped optional stage is `NOT_RUN`, not
healthy coverage. It does not block unrelated offline source analysis.

| Stage | Required inputs / dependency | Output / privilege |
|---|---|---|
| D0 validate | supplied manifest/compiled plan/catalogue/policy | compatible immutable inputs or refusal. Offline |
| D1 ingest/parse | D0. Selected source roots and digests | source/syntax IR, exclusions and parse errors. Bounded local read, no app import |
| D2 mapping | D0. Supplied pinned inventory OR explicit sandbox import | logical/physical map and contradiction receipts. Import side effects named |
| D3 schema | D0/D2 expected map. Selected catalogue connection | compile expectation/reconcile snapshot. Reflection connection read-only, not implicit |
| D4 migration | D0. Selected revision graph and schema binding, D3 for live agreement assertion | ancestry/binding/checkpoint observations. Revision source is data, arbitrary app migration code not run |
| D5 semantics/rules | D0/D1. Declared framework models. D2/D3 only for rules requiring their facts | symbols -> semantic/query IR -> selected CFG/call/def-use/taint -> findings/unknowns. Offline native analysis |
| D6 provider/deployment | D0. Explicit scoped read-only adapters | point-in-time capability/config facts, not crypto proof |
| D7 runtime | D0. Selected authenticated redacted event artifacts/receipts | observed paths/writers with loss/interval/identity. No active attack |
| D8 graph/report | D0 and completed selected compatible receipts | provenance-preserving merge, coverage and bounded conclusions. No policy mutation |

Default selection is D0/D1/D5/D8. D2 may use a supplied inventory without imports.
Live D3/D6 and runtime D7 require explicit configuration and authority. The selected-rule policy declares which missing stage makes a rule inapplicable, not-run or inconclusive.
Source-only work cannot produce a PASS for a schema, provider or runtime assertion. Global and stage budgets are part of DoctorInput and the receipt.

Mapper inspection may execute application initialization. This sandboxed stage requires explicit selection and has no production credentials.
Its receipts record import side effects. Offline source analysis never imports to resolve
types. Catalog, provider and deployment access is read-only, limited and point-in-time. Parameters are
discarded before telemetry export.

### 3.1 Syntax and semantic IR

Use a pinned CPython parser. Do not create a new Python grammar. `SyntaxNode` binds file digest, UTF-8 byte span, line and column span, parser version, node kind and children. A parse failure remains a diagnostic for excluded coverage. Identity binds digest, span and kind, not mutable line number alone.

`Symbol` records scope, qualified name, import origin, binding kind, candidate types, resolution
basis and alternatives. Annotations supply evidence. They do not establish runtime guarantees. Imports and reexports,
aliases and star imports, closures, decorators and descriptors and dependency injection require models or
`Unknown`. Dynamic `getattr`, imports, code generation, `exec`, monkey patching and unresolved
dispatch never yield invented exact symbols.

`SemanticNode` records syntax reference, operation, typed operands, possible results and effects.
It also records exception and cancellation edges and manifest asset bindings. Model assignment, attribute and collection reads and writes, calls, returns, branches, comparisons and raises.
Also model await, yield and context entry and exit. Separate
query IR records SQLAlchemy column identity, binds and literals, comparators, predicates,
joins, groups, order and aggregates, functions and casts, projections and DML targets. Unmodeled SQL becomes
`UnknownQuery`, not a supported operator.

### 3.2 CFG, calls and data flow

Each function has entry, normal, exceptional and cancellation exits. Preserve `try/except/else/finally`,
short-circuit branches, loops, backedges, break and continue, context managers, returns and async suspension.
A `finally` edge cannot disappear because a return or exception was modeled earlier. Unsupported
generator or exception constructs mark the function incomplete.

Local reaching definitions and definition and use relations distinguish value-preserving data flow from transformation
based taint. Alias and points-to sets are bounded and may-valued. Unresolved alias is not separation.
Function summaries bind receiver, argument, return and heap effects, exceptions, labels and model versions.
Calls list possible targets and their resolution basis. Recursion uses a worklist, fixed point and widening. Context, depth,
node, path, time and memory caps are explicit. Exhaustion emits unknown frontiers and dependent
`INCONCLUSIVE`, never no path.

Interprocedural analysis is progressive research, not whole-program soundness. Path feasibility is modeled or unknown. Static reachability does not establish observed execution. Pyright types, CodeQL paths and
Semgrep imports retain edition and model provenance. Their clean output does not resolve local unknowns.

### 3.3 Multi-label taint and sink-specific transformations

Track independent labels `ProtectedPlaintext(asset)`, `SensitivePlaintext(classification)`,
`UntrustedInput`, `Secret`, `KeyMaterial`,
`Ciphertext(context,suite,generation)`, `SearchMetadata(domain,version)`, `TenantIdentifier`,
`SubjectIdentifier`, `AuthenticatedGrant(issuer,scope)`, `SQLCode`, `SensitiveMetadata` and
`RedactedEvidence(policy)`. Joins take the union of possible labels. An ambiguous identity stays ambiguous.

Normalization and encoding retain sensitivity. SQL parameterization removes modeled SQL-code influence
at a SQL sink, not log sensitivity. Only a successful modeled, approved encryption call yields context-bound ciphertext. Preserve its failure edges. Preserve the original plaintext variable's label.

Decryption restores plaintext. A blind index is metadata, never anonymity. A tenant string is not
a grant. Redaction is specific to the sink and policy, never authorization for storage, key release or migration.
Unknown calls retain possible sensitivity.

| Flow class | Sources | Sinks / allowed transform |
|---|---|---|
| protected/general sensitive plaintext | manifest-bound getters, authenticated reveal/decode, classified host inputs | only declared protected persistence or authorized logical output. Logs/traces/metrics/errors/files/reports are sinks requiring their own policy |
| secret/key material | trusted provider/credential/private fixture handles | approved cryptographic operation in its domain. No serialization/telemetry/export |
| untrusted request/SQL fragment | request body/path/query/header, external message/file, raw SQL construction | modeled authorization/validation per boundary. Parameterization is SQL-code-only barrier |
| ciphertext | successful approved encrypt with format/context/generation evidence | allowed physical persistence. Decode restores plaintext only after authentication/context checks |
| equality/search metadata | approved token/term operation with domain/normalizer version | declared companion storage/query use. Disclose equality/frequency/membership under the search policy |
| tenant/subject identifiers | request/model/database/job identity inputs | must be reconciled through trusted grant/resource mapping before key/SQL/reveal. Conversion is not authentication |

Propagators model assignment, arguments and returns, aliases, container mutation, serialization and
concatenation. A sink-specific barrier records the exact label or property removed, preconditions and exception edges. It does not erase other labels. Missing framework model means possible flow plus
unknown coverage. A runtime observation confirms one executed flow. Its absence cannot resolve an unresolved static path.

### 3.4 Rule engine and coverage

`RuleSpec` binds ID and version, invariants, stages, and AST or query predicates or sources, sinks, propagators and barriers.
It also binds lane, applicability, context, expected failure, remediation and labeled fixtures. Pack processing validates each pack, hashes all its contents and signs it when distribution requires a signature.
Packs have declared privileges and require allowlisting.
Rule data never executes arbitrary embedded shell or Python.

Default rule authoring is a typed, trusted native API in the pinned assurance package. A restricted
declarative DSL is an active alternative for portable reviewable data packs, not a new programming
language. Its candidate grammar admits catalogue-bound predicates for sources, sinks, propagators and barriers.
It also admits `all`/`any`/`not`, typed equality and membership, and bounded AST and query selectors. It admits no imports, network or file access, reflection, dynamic evaluation or user-supplied regex engine.

The maximum rule expression depth is 16. Each rule permits at most 1,000 predicate nodes.
Evaluation permits at most 100 ms per rule/function pair and remains subject to the workspace's global budget.
Exhaustion creates an explicit unknown frontier.

Native framework models
are executable trusted extensions installed through the shared extension policy, never loaded from
an untrusted data pack. G-A10 compares identical typed-native, restricted-DSL and imported-rule
cases. Unsupported lowering preserves uncertainty. DSL failure retains typed-native authoring and
isolated learning, and blocks claims of portable rule equivalence.

Rule families cover these cases:

- Plaintext in logs, traces, metrics, exceptions, serialization, messages and files
- ORM, Core, raw, bulk, COPY and external writes
- Companion tampering
- Reveal and context
- Migration, AAD, normalization and version
- Provider export, audit and cache
- Deployment credentials, network and evidence-store

Distinguish structural matches, modeled paths, observed execution and confirmed exposure. Preserve source-tool severity.

Coverage lists roots, files, functions, exclusions, parse failures, unsupported syntax, unresolved calls and aliases.
It also lists model coverage, T/R/D/U writers, inspected schema and provider sources, and executed paths.
Unknown denominators stay unknown. No application-wide percentage from sampled paths. A complete static inspection assertion may `PASS`. That result does not pass dynamic confidentiality.

## 4. Minimum-leakage planner

Combine explicit requirements and constraints, query IR and opt-in redacted runtime observations.
Classify operators as declared/supported, declared-unobserved, observed-undeclared,
unsupported/fail-loud or unknown. Preserve disagreements. Runtime samples cannot prove an existing
capability unnecessary.

Propose the least disclosed alternative satisfying explicit requirements, with uncertainty. A new
field with no query requirement proposes no search. Equality/`IN`/uniqueness need normalization,
domain, null and tenant semantics. Join, group, range, order, text, fuzzy and JSON invoke capability research and review,
never automatic enablement. Removing existing capability requires review and migration.

`PlanProposal` records evidence paths, unmet operations and unknowns. It records frequency, order, token, query, access and cross-column leakage.
It also records low-entropy inference, subject-deletion residue, rotation, coexistence, storage and write amplification, compatibility, and required decisions. Unknown requirements produce
alternatives, not a numerical optimum or security score.

## 5. ProtectionGraph and writer provenance

### 5.1 Identity and relationships

The Protection Manifest is the normative immutable policy. The Protection Graph contains derived observations and evidence.
It cannot establish policy or authorization. `ProtectionGraph` names its proposed record contract.

| Node | Identity binding |
|---|---|
| logical field and tenant/subject/key/index domain | stable manifest IDs plus manifest digest. Exported tenant/subject identities pseudonymous |
| physical column/index/table/schema | deployment/database identity, catalog identity, schema fingerprint/epoch. OID alone insufficient across restore |
| code/query/writer | repository/content digest, path/symbol/span or declared workload ID. Runtime incarnation distinct |
| migration/checkpoint | migration ID, revision/checkpoint digest, phase and epoch |
| provider key/cache/worker | provider-qualified generation, cache scope/epoch, worker incarnation/lease. Never key bytes |
| scenario/tool/collector/artifact/finding | run/scenario, pinned versions, source identity, immutable artifact hash and stable finding ID |

The node-kind catalogue also includes `search_representation`, `normalizer`, `route`,
`reader`, `provider` and `deployment`. A representation or normalizer binds stable manifest ID and
catalogue and version. Route binds method and path-template plus application content digest. Reader binds symbol or workload plus incarnation.

Provider binds namespace, key reference and capability snapshot. Deployment binds environment and image digest plus rollout incarnation. Sensitive paths and identifiers
are redacted under export policy without merging identities.

Relations include `maps_to`, `persists_to`, `indexed_by`, `uses_domain`, `normalized_by`,
`encrypted_under`, `read_by`, `written_by`, `flows_to`, `reachable_from`, `migrated_by`, `cached_by`,
`exercised_by`, `observed_by`, `supports`, `contradicts`, `supersedes`. `maps_to` relates logical and
physical identity. `persists_to` records modeled or observed storage. `flows_to` records a labeled data
flow. `reachable_from` records modeled or exercised control reachability. Neither `flows_to` nor `reachable_from` implies a confirmed exposure. Edge schemas restrict endpoint kinds and basis. Unknown kinds and relationships are rejected or retained as opaque extensions. They do not contribute to protection assertions.

Each immutable observation records evidence, basis, exactness, collector, interval, watermarks, target, run and scenario.
It also records manifest, schema and application versions, scope, limitations, and active, superseded or conflicted state. Observation ID hashes canonical scoped content. Imports never silently upgrade exactness.

Exact joins require compatible named run, target, scenario, manifest asset, request, trace, transaction, marker and artifact identifiers. Time proximity creates a hypothesis. A contradiction preserves both sources. Reconciliation appends a decision. Unknown nodes and ambiguous edges remain.

Negative exposure binds marker forms, collectors and interval. No timeless `not_exposed` edge is permitted. Preserve restore and deployment epochs. Reused IDs do not merge automatically.

### 5.2 Writer ledger

Inventory declared deployment, job and migration writers, observed ORM and engine events, DB roles and connections
and version-qualified statement fingerprints. Per asset classify registered-observed,
registered-unobserved, unregistered-observed, ambiguous or unknown. Bind incarnation, authenticated
DB role, database, pool, connection and transaction, release and manifest, target columns, observation point
and evidence.

PostgreSQL `application_name` and client trace IDs are spoofable hints. Shared role credentials do
not identify a process. Fingerprints group statement shapes. They prove neither identity nor parameter confidentiality or equivalence across DB versions.

Logging loss, pool or proxy remapping, triggers and ETL are gaps. Export no plaintext parameters or credentials. An unobserved writer is not necessarily safe. No observed writer does not establish that no writers exist. Stronger attribution needs workload-bound credentials and collector provenance,
and still describes observed executions only.

## 6. Verify scenarios and results

`ScenarioSpec` binds hub invariant IDs, fixture and target versions, synthetic principals, tenants and subjects,
preconditions, actions and oracle, required collectors, controls, cleanup, timeout and replay. Verify
works without DAST. CI selects disposable deterministic fixtures. Live access must be selected.

Core scenarios cover these cases:

- Supported and rejected writes and queries
- DB credential extraction
- Cross-tenant and cross-subject substitution
- Envelope tamper, truncation, version and relocation
- Index, ciphertext and normalization mismatch
- Provider outage, throttle and wrong-key cases
- Cache expiry, stale workers, epochs and fencing of in-flight outputs
- Rotation
- Migration interruption, version skew and CAS
- Shred, fresh and stale cases, restore and reimport
- Audit mutation
- Markers in DB, HTTP, errors, logs, traces, reports and exports

Each supported cell links exact scenarios.

### 6.1 Orthogonal dimensions

| Dimension | Values |
|---|---|
| execution | not_started, started, completed, aborted |
| applicability | applicable, not_applicable, unknown |
| exploit/database authority/column extraction/candidate decode/exact plaintext | yes, no, not_applicable, not_executed, inconclusive. Each separate evidence |
| exposure classes | none_observed, ciphertext, envelope_metadata, search_metadata, plaintext, key_material, unknown. Multiple classes permitted |
| control outcome | held, bypassed, degraded, not_exercised, inconclusive |
| basis | declared, static_modeled, schema_observed, provider_reported, runtime_observed, actively_exercised, exposure_confirmed |
| scope | exact asset/path, table, service, deployment, unknown |
| reproducibility | deterministic, seeded_replay, flaky, unreproduced |

Each assertion has exactly one `PASS`, `FAIL`, `WARNING`, `INCONCLUSIVE`, `NOT_APPLICABLE` or `NOT_RUN`.

`PASS` requires completed applicable execution, intended boundary exercised, expected outcome,
required evidence and successful controls. `FAIL` requires demonstrated contradiction. `WARNING` reports risk without that proof. Insufficient evidence is `INCONCLUSIVE`. Applicable work that was not attempted is `NOT_RUN`.


`NOT_APPLICABLE` requires a validated reason.

An attack that never reaches the boundary cannot pass its confidentiality assertion. It may pass a separate attack-blocking assertion. A confirmed violation remains `FAIL` if another collector
failed, with incomplete coverage attached. Missing evidence prevents absence but cannot erase a
positive violation. Run summaries list results and the gate decision. They never average security.

Findings bind schema, rule, scenario and invariant versions, run, target, manifest, policy and assets.
They also bind source, tool, edition, rules, point, interval, redacted references and dimensions.
Other fields bind severity, impact, limitations, remediation and baseline. Attack severity and asset impact differ. Report metadata disclosure even
when plaintext protection holds.

## 7. Exposure oracle and collectors

Generate >=128 bits of cryptographic randomness per synthetic marker. Bind the private mapping to field, tenant, subject, run and scenario. Markers are fake data. Public bundles contain opaque marker IDs
and match metadata. Private value mappings/seeds remain disposable lab secrets. Replay recreates
local synthetic fixtures, or generates a fresh shareable fixture without exposing the old mapping.

`CollectorSpec` declares source, point, coverage, artifact classes, watermark type, clock and lateness.
It also declares exact and derived marker forms, bounded decoding, health, control insertion and readback, retention, caps, and redaction stage. Reference collectors are physical PostgreSQL cells and companions, HTTP responses and errors,
app logs and generated evidence and report outputs. Traces, metrics, queues, exports, backups and packets are
additional named sources, never implied.

Protocol:

1. Authenticate the target and collector.
2. Isolate the namespace.
3. Where safe, drain stale fixtures.
4. Record the start cursor or watermark with an acknowledged barrier.
5. Insert a distinct positive control at each required observation point.
6. Prove readback at each point.
7. Test an absent negative marker for false matching.
8. Execute the normal scenario with unique markers.
9. Where required, collect continuously during execution.
10. Close the interval.
11. Flush or drain to an acknowledged end watermark.
12. Honor bounded lateness.
13. Record counts, loss and incomplete sources.
14. Decode allowlisted bounded transforms.
15. Match registered forms.
16. Deduplicate by marker and artifact location.
17. Separate control, scenario, stale and out-of-window hits.
18. Never delete inconvenient stale hits.
19. Run the relevant semantic mutant in an isolated reset fixture.
20. Require the intended violation and its evidence.
21. Restore normal protection.
22. Repeat the corresponding check.
23. Search generated artifacts before export.
24. Redact the content.
25. Retain control and coverage receipts.

A timestamp without asynchronous drain acknowledgement is insufficient. DB scans bind consistent
snapshot and committed visibility and paged cursor and table scope. Rotation and reconnect gaps, sampling,
compression and encoding, partial responses, truncation, drops and permissions are losses. Hits prove the observed form and location. Absence concerns only registered forms, sources and the observation interval.

Redaction before matching that destroys visibility makes absence inconclusive. Redaction after private synthetic matching is required. It may preserve the decision through marker ID, transform, cursor or location, counters and digest.
The result remains first-party.

Lossless supported decoding can preserve visibility. Unmodeled hashing, transformation or partial redaction cannot preserve visibility. A positive control
at a different layer cannot substitute for the actual observation point.

Each required collector must find its positive control. It must reject the negative control. It must detect the corresponding mutant.
It must pass the restored normal case.

Minimum mutants are plaintext persistence, disabled context or relocation binding, stale-cache acceptance and index mismatch. Only a relevant mutant supports an assertion. Lifecycle and search extensions add matching mutants. Failed control, watermark, loss, timeout or access denial
prevents absence-pass. Confirmed policy violations still fail.

## 8. Pentest architecture and safety

Internal learning can build endpoint, role and state graphs, bounded crawler and authentication, mutations,
payloads and oracles, minimization and replay. Integrate ZAP generic detection by default, optional
commercial Burp DAST, explicit Nuclei packs and destructive synthetic sqlmap extraction. Preserve
source-tool semantics.

### 8.1 Internal engine contract and adapter boundary

The proposed initial integrated DAST default is a pinned mature adapter. The internal engine is a quarantined
research implementation of the same scenario/result interfaces. G-A11 controls promotion.
Authorization and an independent traffic broker precede every component below, including retries.

1. Import an allowlisted bounded OpenAPI or route inventory as untrusted input.
   Disable external references unless individually authorized. Unresolved or dynamic routes remain coverage gaps.
   `Endpoint` identifies method, path template, parameter and body schema, and deployment revision.
2. Build an endpoint, role and state graph.
   `AuthState` binds synthetic principal, role, token expiry, login and refresh recipe, and private secret handle.
   `StateTransition` binds prerequisites, action, expected state and cleanup.
   Keep tokens and cookies outside the public graph and results.
   Check authentication health before a chain. Check it after the chain.
   Login success does not prove the intended principal.
3. Normalize a `RequestCase` with endpoint, role, state, typed parameters and content type.
   Include secret handles for body and headers, run, scenario and marker IDs, and required authorization scope.
   Preserve exact private request bytes and their digest for replay under lab retention.
   Redact the public form.
4. A bounded crawler proposes inventory additions.
   A mutation planner selects a versioned payload family and one semantic change per case.
   CSRF, session, IDOR, authorization, injection, serialization and protection-boundary cases require distinct preconditions and oracles.
   Never execute unknown endpoint semantics as an automatic destructive probe.
5. Immediately before dispatch, the broker checks target, image, current scope, time, caps, pinned destination and allowed method.
   The executor records counts for offered, sent, completed, retried and cancelled requests.
   It records authenticated state, timeout, response truncation, and transaction and trace identities.
   Tool errors are execution failures. They do not establish exploit absence.
6. Differential analysis compares matched baseline and protected cases, or matched role, state and control cases.
   Status, length, timing and alert differences remain hypotheses until a scenario oracle confirms the intended control boundary and asset.
   Run synthetic exposure matching through the registered collectors.
7. Minimization can change only declared case dimensions within the same scope and budget.
   Reauthorize every candidate. Preserve the prerequisite chain. Preserve the matching oracle.
   A smaller input that produces an alert without the original exposure is a different finding.
8. Replay resets the disposable target and recreates synthetic secret handles.
   It repeats prerequisites and actions with pinned tool and fixture versions. It compares semantic dimensions.
   Raw nonces, times and run IDs can differ.
   Lost authentication, state or collector coverage makes the result inconclusive.

Planner workers cannot expand their own scope or override broker denial. Third-party engine findings
retain original confidence/severity/IDs alongside Cryptalis assertions. Source alerts may map to an
asset only through an evidenced route/query/trace/schema relationship. Time proximity alone is a
hypothesis. Counterexample budgets and missing roles/routes remain visible in graph and report coverage.

### 8.2 Profiles, interlocks and containment

| Profile | Actions and prerequisites |
|---|---|
| passive (default) | supplied artifacts/captures. No target traffic |
| discovery | scoped route/spec/spider. Disposable target, traffic authorization/budgets |
| active-safe / api | selected authenticated ZAP/Burp rules/synthetic states. Name is not harmlessness |
| boundary | direct-DB/raw/bulk/context/relocation fixture actions |
| sqli-exposure | confirmed injection, exact synthetic columns, additional destructive token |
| lifecycle-chaos | fenced disposable emulator, worker/shred/restore. Cloud lane separately authorized |

Authorization binds owner and purpose, deployment and image, endpoints, IPs and ports, profiles, engines, methods and data,
time window, caps, cleanup owner and target-issued ephemeral lab token. Destructive work needs
sentinel and separate run token. Do not use production data or shared credentials. Do not mutate cloud resources without explicit authorization.
A private IP or localhost does not establish ownership of a disposable target.

Enforce deny-by-default network egress plus request validation. IP pinning covers IPv4/IPv6,
redirects, browser resources, spec URLs, proxy, WebSocket and secondary hosts. Deny cloud metadata,
link-local, public OAST/callbacks, arbitrary proxy/Tor, host network, Docker socket and unintended
mounts. Preserve expected Host, SNI and TLS identity. Tooling that cannot obey scope is unavailable. A rebinding, redirect or deployment mismatch aborts execution before the next request.

Reference caps: 5 requests/sec, concurrency 2, 1,000 requests, 1 MiB response, 100 MiB accumulated
capture, 100 extracted synthetic rows, 10 minutes actions, 60 seconds cleanup. Discovery shares the budget. The effective cap is the lower limit from authorization and profile. Larger research caps need new explicit
authorization/policy before starting. A cap-triggered abort records partial coverage and cleanup. Incomplete work cannot pass.

Code, headless, local-file, raw-network and unsigned capabilities default to denied. Allowlist each capability separately. Isolate each allowed capability. A signature proves origin and integrity. It does not prove safety. Hash all pack members including helper
payloads omitted by engine signatures. Internal DSL has no shell/Python. The sqlmap profile forbids general dumps, filesystem or OS actions, arbitrary SQL, broad discovery and unrestricted tamper scripts.
Risk and level flags do not establish containment. Use confirmed synthetic injection/column and disposable DB.

Give every tool process an allowlisted clean environment. Give it a private bounded workspace. Supply ephemeral credentials with minimum privileges. Inherited proxy, callback, cloud credentials, credential-validation, analysis or revocation flags and environment settings and remote-source downloads are denied in passive mode.
For example, the Betterleaks maintainer README documents provider requests that the environment can enable.
A passive secret-scan adapter must explicitly disable these requests. It must prove zero egress under G-A05.
No actual discovered credential is sent to a provider for validation by the default assurance
profile. Separate synthetic lab authorization does not authorize testing real third-party secrets.

The kill switch revokes traffic before it stops engines. It retains redacted partial results and starts cleanup.
Stop APIs can lag. Use an external supervisor and network caps. Cleanup is idempotent. It removes credentials, plaintext fixtures, TLS secrets, dumps and volumes.
Incomplete cleanup is a separate failure that names its owner and resources.

## 9. Network and deployment evidence

Nmap XML describes exposure and services. It does not establish field confidentiality. TShark fields and Zeek flow and protocol logs pin the decoder, scripts, filters, capture point and interface.
They also pin snaplen, drops, clocks and join keys. Imported
PCAP/logs are untrusted bounded-parser input.

Ordinary TLS capture cannot inspect HTTP/PostgreSQL plaintext. Its absence result is `NOT_APPLICABLE`
for plaintext inspection, or `INCONCLUSIVE` if required. Lab key logs or observation inside encryption
can support a named source. Secrets and decrypted captures remain quarantined until destruction. pcapng can embed secrets. Inspect exported captures for secrets and sensitive metadata. Timing and size support declared metadata-leakage research. They do not establish global absence.

Trivy, Grype and Gitleaks imports bind configuration, exclusions, feed and rule freshness, baseline, VEX, ignores and versions. Filtered absence/clean secret scans are not proof of no secrets. Deployment assertions
focus on key release, DB TLS, credentials, evidence integrity, backups and tombstones, clocks and isolation.
Image and configuration fingerprints establish inspected deployment, not every replica.

The network pipeline has these stages:

1. Authorize capture.
2. Establish the observation point, filters and start watermark.
3. Capture or import a bounded immutable artifact.
4. Decode the artifact with a pinned decoder in a sandbox.
5. Normalize flow and session records.
6. Correlate records through evidence.
7. Apply the scenario oracle.
8. Scan for secrets.
9. Export redacted results.
10. Clean up.
Live capture requires a separate disposable-interface capability. Offline decoding gets no privilege for target traffic or network resolution. DNS names, TLS SNI, five-tuples and Zeek UIDs are scoped
observations, not authenticated actor identity. Flow reconstruction records packet loss, truncated segments, retransmissions, out-of-order data and decoder uncertainty.
Incomplete sessions cannot support absence. Nmap host and port evidence joins a deployment only with proof of target identity and interval.
Hostname equality does not establish this join. G-A11 uses synthetic fixture PCAPs for plain, TLS, fragmented, lost, reordered and corrupt cases.
It also uses fixed expected sessions and explicit TLS visibility controls. Size and timing research requires matched workloads, public leakage assumptions and a statistical protocol.
Its results cannot be reclassified as decrypted content.

## 10. Evidence bundle and integrity

Cryptalis JSON retains the full scenario and control model. SARIF 2.1.0 exports source and artifact findings.
JUnit XML exposes CI outcomes. Markdown and HTML explain evidence. Preserve unknowns, coverage,
attribution and semantics. JUnit maps inconclusive and not-run results to explicit skip or error states plus canonical properties. It never maps them to successful tests.
XML disables external entities and remote schemas. HTML escapes untrusted content.

`bundle-manifest.json` binds results, graph and receipts to these records:

- Target and run
- Manifest, compiled plan, model, schema and migration
- Source revision and dirty state
- Image, provider and DB
- Policy and authorization
- Tool, edition, rules and configuration
- Replay
- Clocks, watermarks, loss and redaction
- Cleanup

The complete member inventory records
normalized relative path, media type, length and SHA-256. Hash the exact finalized bytes. Canonical producer JSON uses the shared restricted RFC 8785/JCS profile.
The schema and bytes are versioned.


Plain sorted JSON is not JCS. Do not hash a logical object and then serialize it differently. Detached signatures remain outside the signed inventory. An explicit wrapper relation prevents recursive hashes.

The manifest does not inventory itself. It inventories results, graph, receipts and artifact members.
A trusted expected digest or signature binds the manifest's exact bytes. Detached wrappers are typed transport relations. Independent trust policy requires every mandatory wrapper.
Removing a wrapper cannot downgrade verification to unsigned evidence.

Verification, parsing, rendering and export consume the same bounded immutable content snapshot.
Never verify a file path and then reread replaceable bytes from that path.

Bundle member paths are relative POSIX paths with lower-case ASCII components matching
`[a-z0-9][a-z0-9._-]*`, at most 255 bytes per component and 4,096 bytes total. Reject empty/dot/dot-dot
components, absolute or drive-qualified paths, backslashes, NUL/control bytes, Windows reserved
component stems and paths that collide after a supported filesystem's case/normalization rules.
Do not silently sanitize names into collisions. The producer assigns safe paths to public artifacts with incompatible original names. It supplies an explicit redacted provenance mapping.

Reject duplicate paths/JSON keys, traversal, symlinks/hardlinks/device files, archive bombs, every
unlisted member, changed size/hash, missing artifacts and forbidden reference cycles. Detached wrapper files form a separately enumerated, typed allowlist bound to exactly one inventoried manifest.
Only those wrappers are exempt from its signed inventory. Treat wrapper claims as untrusted until
verification. Import never executes artifacts. It never follows remote references or trusts embedded signer roots. Verify bounds during streaming before allocation or extraction to a private temporary namespace.


Do not turn a partially validated bundle into a report or CI result. The import cap is 100 MiB uncompressed, 10,000 members and JSON depth 64.
Canonical manifest compilation still has separate stricter limits. Larger research artifacts need separate policy. Private quarantined artifacts stay outside the public inventory with opaque local references. Their absence limits external reproduction.

Optional in-toto Statement v1 names bundle manifest digest as subject and a versioned Cryptalis
predicate. DSSE signs the exact payload and type with standard pre-authentication encoding through an established library. Optional Sigstore signs exact manifest bytes. Verification pins trusted keys or the expected OIDC issuer and identity.
It also pins accepted signature and bundle versions, roots, and required inclusion, transparency and time evidence.

Envelope key ID is not trust. Wildcard identity/disabled claim or log
checks cannot yield equivalent assurance. Offline verification records root snapshot, time and
unavailable revocation/freshness.

A hash detects corruption relative to a trusted expected digest. A hash chain without an independently retained checkpoint cannot detect dishonest truncation or replacement. Audit checkpoints require an external witness plus sequence and count continuity.
One bundle cannot prove that omitted runs never existed.

Signatures prove neither truthful collectors, completeness, independence nor plaintext erasure.
Unsigned local evidence remains useful. A required signer that is unavailable blocks its policy gate.

Public bundles contain no raw markers, credentials, tokens, keys, TLS secrets or full dumps.
They contain no ciphertext bodies or unrestricted payload bodies. The oracle checks generated artifacts with synthetic controls before export.
 Retention is explicit for each artifact and its encrypted storage and access policy. Private artifacts default to destruction during cleanup.
Public bundles default to a run-selected expiry. There is no indefinite default.

## 11. CI, reference lab and regression

Proposed command semantics are `doctor`, `plan`, `verify`, separate `pentest`,
`evidence inspect|validate|export` and `check --ci`. Shared API owner owns names/errors. Doctor defaults
to offline manifest/source. Schema, provider and deployment access require explicit selection. `check --ci` runs only selected
fast Doctor/Verify fixtures. It never discovers live targets, launches DAST or grants destructive
authorization.

CI evaluates canonical JSON after control and integrity checks. Exit codes and precedence follow the
[shared CLI contract](manifest-context-api.md#cli-and-configuration). A proven `FAIL` survives an
operational error in canonical results even when the error takes exit-code precedence. Warnings and
required-not-run follow explicit policy. Exceptions bind owner, reason, scope, expiry and approval. They may waive a gate. They never relabel a result `PASS`.


The reference lab uses identical application revisions, routes, fixtures and identities for baseline and protected configurations.
It contains synthetic PostgreSQL, a local provider emulator, engines, collectors and a builder. Only documented protection and schema differ. Separate attacker, application, DB-provider and evidence networks. Deny host and external egress. Pin digests.
Reset between normal, mutant and baseline configurations. Evidence records health, tokens and cleanup.

Cloud, managed backup, multi-cluster and network chaos are separate lanes with dependency, cost and authorization limits.

Pytest associates executed request, SQL and synthetic-collector paths. Coverage describes executed tests only.
Stateful/property/fuzz tests cover envelope, query, context, migration, lifecycle and cache and evidence
parsers. Record seeds and minimized counterexamples without secrets. Baselines show new, resolved, unchanged, regressed and reclassified results without suppressing failures. Dependency, manifest, model, rule or collector changes invalidate incompatible baselines.
Rerun affected compatibility, mutant and serialization fixtures.

## Research gates

These stable IDs extend existing P0-P10 obligations without renaming them. All gates are pending.
Fixture minima prevent promotion from one demo. They do not establish statistical assurance. Any critical
counterexample fails regardless of aggregate metrics.

| Gate | Evidence and exact initial acceptance criterion | Failure response |
|---|---|---|
| G-A01 semantic IR/CFG | pinned lane. >=2 fixtures per modeled construct including exceptional/async. 100% expected spans/bindings/edges. Every unmodeled/budget case unknown | remove affected supported construct. No whole-program claim |
| G-A02 rule accuracy | per promoted family >=30 unsafe, 30 safe, 10 ambiguous. Held-out labels separate from tuning. Precision >=95%, recall >=90% with counts/uncertainty. 100% critical context/plaintext cases found. 100% ambiguous/unsupported retain uncertainty | research-only/narrow lane. Never silent safe |
| G-A03 graph/writer attribution | >=30 labeled chains plus 10 timestamp/alias/restore/spoof/conflict cases. 100% exact joins correct, zero false exact. 100% conflicts/unknown writers retained | demote links to hypotheses/block dependent claims |
| G-A04 Verify/oracle | every promoted scenario: healthy positive/negative at each required point, relevant mutant killed, normal restored. 100% controls pass. 100% missing/lost/truncated/early-redacted cases prevent absence-pass. Zero false exposure/absence corpus decisions | inconclusive/research-only. Observed violations still fail |
| G-A05 containment | IPv4/IPv6 redirects, rebinding, proxy, metadata, callback, spec, hostile pack/volume, budget/kill. 100% unauthorized denied/caps enforced. Cleanup <=60s in reference lane | active profile unavailable. Cleanup failure visible |
| G-A06 replay/versioning | 10 independent resets/replays per deterministic scenario give identical semantic results/relations excluding run/time IDs. 100% unsupported schema/pack/tool refused. Old conversion fixtures preserve dimensions/unknowns | flaky classification/gate invalidation. Old bytes/conversion retained |
| G-A07 benchmarks | >=5 measured independent runs/variant. >=60s warm-up and >=180s measurement for steady workloads. Random order, raw distributions/95% intervals, no control/correctness failure. Throughput CV <=10% or instability reported without comparative claim | no performance claim. Future budgets redeclared before rerun |
| G-A08 integrity/privacy | >=100 fixtures per inventory/path/version/signer/replay attack family. 100% modified/missing/unlisted/path/duplicate/unknown-version/wrong-signer/issuer/replay-target rejected. Two independent-language encoders agree on >=10,000 canonical numeric/time/ratio vectors and reject all float/unit/clock-invalid fixtures. 100% seeded marker/key/token/TLS artifacts excluded or safely redacted | block publication/CI integrity. Redacted failure retained |
| G-A09 differentiated value | >=30 labeled baseline/protected/mutant/missing-collector chains paired with ZAP/manual. Zero false definitive asset conclusions. >=10 percentage-point impact accuracy gain OR >=20% median explanation-time reduction without accuracy loss. Setup/maintenance/intervals reported | remove graph marketing thesis. Retain integration/learning |
| G-A10 restricted rule DSL | >=1,000 held-out safe/unsafe/ambiguous fixtures per promoted family against equivalent typed-native rules. 100% result/path/unknown equivalence. Zero pack escape. >=100 depth/node/time exhaustion fixtures remain unknown. Median CPU <=2x native and peak RSS <=125% native on same corpus | retain typed-native default. DSL research-only. Block equivalence/portability claim |
| G-A11 internal DAST/network | >=30 labeled authenticated role/state chains plus >=100 containment/capture-loss/redirect/replay faults. Compare same action traces against adapter/manual oracle. Zero unauthorized request, false definitive exposure or hidden skipped boundary. 10 reset replays reproduce semantic classification | narrow engine/lane. Fallback pinned adapter. Preserve explicit gaps |

### Explicit choices behind the pending gates

The table below supplies the question, rationale, preferred default, serious alternatives,
required future evidence and blocked claims for each gate. The experiments and exact pass/fail criteria remain in the table above.
A change requires a new recorded gate version before measurement. No artifact named here exists. Safe independent work may implement the isolated fixture, adapter or educational candidate.
Integration or promotion depends on the named gate.

| Gate / question and why it matters | Preferred default and alternatives to test | Required future artifact / blocked claim / safe work |
|---|---|---|
| G-A01: Can semantic IR preserve exceptional/dynamic Python semantics? Missing edges can invent safe paths. | pinned CPython AST plus bounded explicit IR. Alternatives: narrower syntax-only rules, imported CodeQL/Pyright models, selected native framework models | `semantic-corpus` labeled source/span/symbol/CFG golden records and unknown frontier receipts. Block promoted construct/whole-program certainty on failure. Safe parser/IR study |
| G-A02: Are protection rules useful without hiding uncertainty? False negatives conceal exposure and noise erodes use. | precise bounded native rules with unknown states. Alternatives: narrow family/lane, mature-tool import, richer model after evidence | held-out `rule-evaluation` labels/confusion counts/intervals and minimized misses. Block usefulness/absence claims. Safe fixture/model authoring |
| G-A03: Are graph/writer joins exact? Spoofing, pools and restores can falsely attribute actor or asset. | compatible content/run/workload identities with declared exactness. Alternatives: authenticated workload credentials, weaker hypotheses, manual correlation | `graph-attribution` expected/observed nodes/edges, spoof/restore counterexamples and collector bindings. Block exact actor/path conclusions. Safe graph visualization/ledger ingest |
| G-A04: Does the oracle detect exposure and missing visibility? A failed collector can make a false clean result. | point-specific positive/negative/mutant/restored controls with drained interval. Alternatives: richer collectors, explicit narrower source scope, inconclusive result | `oracle-controls` artifact/cursor/loss/match receipts for normal/mutant/missing-source runs. Block bounded absence PASS until healthy. Safe synthetic marker/collector work |
| G-A05: Is active tooling containable? Config-only scope cannot stop redirect/helper/environment escapes. | independent deny-default egress broker and clean isolated process. Alternatives: offline imported evidence, adapter incapable of active use, stricter single-target lane | `containment` requested/denied/observed network/filesystem/process actions, cap/kill/cleanup receipts. Block active profile on any escape. Safe offline adapter work |
| G-A06: Is semantic replay/version conversion faithful? New schemas can erase old uncertainty or incomparable scope. | reset pinned lane, explicit compatibility rejection and original-byte retention. Alternatives: reclassified baseline, narrow deterministic subset, no upconversion | `replay-compatibility` ten-run semantic diffs and old/unknown-major conversion corpus. Block deterministic/comparable claims. Safe importer/version-schema study |
| G-A07: Are cost comparisons stable and equivalent? Fast paths may conceal failure or unequal security semantics. | paired controlled multi-run baseline/protected protocols. Alternatives: narrower workload, publish instability, redeclare budget before fresh trial | `assurance-benchmark` commands/environment/raw offered/completed/error distributions and uncertainty. Block performance claims. Safe measurement-harness design |
| G-A08: Are evidence bytes trustworthy and safe to publish? Serialization, archive or secret-handling errors corrupt meaning. | immutable snapshot, restricted JCS/complete inventory and external signer policy. Alternatives: unsigned local-only evidence, DSSE/in-toto/Sigstore adapter under distinct trust policy | `bundle-integrity` cross-language vectors/hostile archive/signer/replay/privacy corpus and raw verdicts. Block publication/CI integrity where unmet. Safe synthetic serialization/rendering |
| G-A09: Does asset correlation add useful information? A scanner wrapper alone does not justify the product thesis. | evidence graph plus bounded result dimensions. Alternatives: ZAP/manual workflow, diagnostics-only tooling, learning-only engine | `value-study` blinded/labeled decisions and explanation times, setup burden/uncertainty. Block differentiated assurance positioning on failure. Safe integration/learning |
| G-A10: Is the DSL portable without becoming unsafe or costly? Convenience cannot change native rule meaning. | trusted typed-native rule API. Alternatives: restricted declarative predicates, imported mature rules, no DSL promotion | `dsl-differential` paired rule/corpus versions, path/unknown equality and CPU/RSS/budget/escape receipts. Block DSL equivalence/portability. Safe isolated grammar/lowering study |
| G-A11: Can internal DAST/network reconstruction reach intended boundaries safely and reproducibly? Role/state/loss gaps distort exposure. | pinned mature DAST adapter and explicit decoder visibility. Alternatives: narrow internal executor, manual oracle, offline PCAP-only lane | `dast-network` role/state/action/control/replay trace and labeled corrupt/lost/TLS fixture sessions. Block promoted internal coverage/exposure conclusions on failure. Safe crawler/mutator/decoder research |

An unresolved corpus/oracle is a dependency, not permission to pick easy fixtures after seeing a
result. Declare labels and held-out partitions before tuning. Record adjudication provenance.
Review requirements in the crypto, context and ORM owners remain dependencies of scenarios that exercise those controls.
Assurance success cannot promote an unvalidated protection mechanism.

Gate artifacts bind gate version, corpus digest, source, manifest, policy and tools.
They also bind environment, hardware, command, raw output, controls and limitations. G-A09 is a predeclared program decision heuristic,
not market fact. Builder corpus labels and review remain first-party. Independent review requires a named external artifact. AI agreement does not establish independent review.

Separate these benchmark families:

- Crypto sizes: 0/8/32/256/4096 bytes
- Single and batch ORM operations, synchronous and asynchronous
- Warm, cold, stampede and outage cases
- Equality, uniqueness and dual rotation
- Migration, CAS, WAL, locks, replica and recovery
- Doctor time, RSS and unknowns
- Collector and graph overhead

Measure offered and completed load, errors, retries and cancellations. Record p50, p95, p99 and distributions.
Measure CPU, RSS, event-loop lag, provider calls, ciphertext, TOAST, table and index costs.
Also measure WAL, locks, replicas and rows/sec. Histograms cannot silently exclude timeouts or errors.

Fast CI budget <=5 minutes and <=2 GiB peak assurance-worker RSS on a corpus pinned before execution.
Exceeding is profile/performance failure, not cryptographic failure. Declare scenario latency, storage and provider-call budgets before measurement. No universal encryption overhead is assumed.
Exclude comparisons with unequal security, deployment, access or query semantics. Vendor data remains vendor evidence.

## 13. Failure matrix and stop conditions

| Fault | Outcome |
|---|---|
| parse/dynamic call/budget exhaustion | explicit coverage gap. Dependent inconclusive |
| manifest/model/schema/migration contradiction | preserve sources. Matching assertion fail |
| exit 0 but missing jobs/auth/output | incomplete execution. No protection pass |
| exploit does not reach boundary | exploit no. Boundary not exercised |
| marker hit plus collector down | fail with coverage gap |
| loss/truncation/stale cursor/early redaction | no absence-pass. Source inconclusive |
| provider pending/restorable/exportable | exact fact. No stronger destruction |
| stale/suspended worker cannot prove fence | revocation/shred pending/inconclusive |
| restore epoch changed/tombstone authority absent | stop dependent trial. Retain resurrection evidence |
| graph conflict/fingerprint collision | no exact attribution. Preserve alternatives |
| valid pack signature but missing helper/unsafe capability | refuse complete digest/privilege validation |
| altered bundle/untrusted signer/schema downgrade | integrity gate fail |
| expired token/scope/cap change | revoke traffic, abort, evidence cleanup/incomplete work |
| cleanup/private evidence deletion incomplete | quarantine, failure, named owner |

A capability leaves research only after its own protection, compatibility, lifecycle, uncertainty,
benchmark and required review gates. Failure bounds that capability, not unrelated research.
Never derive all-SQLAlchemy protection, no plaintext anywhere, independence, SQL-injection
prevention, legal erasure or compliance certification from this evidence.
