# Cryptalis Security Assurance Suite: Adversarial Architecture Research

Status: Research decision. No implementation exists

Last reviewed: 2026-10-01

Scope: `doctor`, `plan`, `verify`, the quarantined pentesting harness and evidence/reporting.
This document owns research questions, comparison rationale, educational engine tracks and product
falsifiers. Normative analysis, graph, scenario, safety, collector, evidence and gate contracts live
in [Assurance/evidence architecture](architecture/assurance-evidence.md). Shared declarations and
invariants live in the [architecture hub](architecture/README.md). The dated
[tool evidence ledger](research/assurance-tool-evidence.md) owns current external capabilities.
[Prior art](prior-art.md) owns protection-product comparisons. The
[backend checklist](backend-build-checklist.md) owns implementation state.

All proposed pipelines remain unimplemented. This research does not authorize active scanning of any real target.

## Executive decision

**SECURITY ASSURANCE SHOULD BE A MAJOR SECONDARY CRYPTALIS SELLING POINT — conditionally.**

The position survives only if Cryptalis owns the semantic correlation layer. This layer must connect each declared protected field to its model mapping.
It must also connect physical columns and indexes, migration history, write paths, and key and cache lifecycle.
The remaining links connect the exercised attack path, observed artifacts and final exposure.
This defines a narrower, more defensible product than “security scanner for encrypted apps.”

This product-positioning conclusion is separate from the learning decision. Cryptalis may still build substantial SAST, DAST, template, SQL-policy and network-analysis subsystems.
This work requires high educational value and a credible correctness benchmark. Generic breadth does not establish a competitive advantage.
But competitor overlap no longer excludes the work. The governing evaluation model
is in the [learning-first research philosophy](learning-first-research-philosophy.md).

The broad claim does not survive scrutiny:

- Acra documents data protection with a SQL firewall, anomaly reactions, honeytokens,
  security logging, cryptographically protected exported audit logs, key inventory, and SIEM integration.
- CipherStash now documents planning, implementation, validation, status, phased encryption, and
  drift-oriented workflows in addition to searchable encryption and a proxy.
- Thales, Fortanix, and Imperva document estate-wide discovery, posture, activity
  monitoring, centralized key inventory, and compliance operations.
- ZAP, Burp Suite, Nuclei, sqlmap, CodeQL, Semgrep, Trivy, Gitleaks, Grype, Nmap, TShark, and Zeek
  document established generic detection engines and formats.
- A scanner operated by the same product that supplies the protection control is not independent
  assurance. Its evidence can be reproducible and tamper-evident, but it remains first-party.

These qualitative comparisons describe documented capabilities under the dated ledgers. They are not measured rankings.
They do not establish that competitors cannot supply equivalent correlation. Research must compare
actual pinned products and editions under matching scope before claiming a gap.

Thus, Cryptalis earns the secondary selling point only if it shows added value for this application-specific question:

> A specific attack or operational fault reaches this SQLAlchemy application's protected-data boundary.
> Which declared assets become plaintext, ciphertext, search metadata, key material, or nothing at all?
> What evidence supports that conclusion?

If the suite becomes only a wrapper around ZAP plus generic lint rules, demote its product claim to developer tooling.
An independently built learning engine must still show measurable depth.
If `doctor` cannot distinguish facts from heuristics, or `verify` treats missing collectors as a
pass, remove assurance from positioning entirely.

## 1. The claim under test

The strongest credible product statement is:

> Cryptalis helps teams design, exercise and audit the application-specific boundary around protected SQLAlchemy fields.
> It does not prevent application vulnerabilities. It tests whether declared protection still limits exposure during vulnerabilities, bypasses, lifecycle faults and deployment mistakes.

This is deliberately not “continuous pentesting,” “DSPM,” “breach prevention,” or “proof of
security.” SQL injection may succeed while Cryptalis protection holds. A clean generic DAST scan does not establish protection for other paths.
These include raw SQL, bulk writes, migrations, logging, cache staleness and restore paths.

### 1.1 Conditions that would disprove the product position

The major-secondary thesis fails if any of these remain true after a serious prototype:

1. Most Doctor findings cannot identify an exact protected field and concrete violating path.
2. Runtime observation covers only a curated demo while the UI implies application-wide coverage.
3. The harness cannot show that its collectors detect deliberately seeded plaintext and
   deliberately disabled controls.
4. Protected-versus-baseline trials are too nondeterministic to reproduce.
5. SQLAlchemy version churn makes bypass coverage unaffordable.
6. The evidence bundle cannot prove which target, manifest, migration, scanner image, configuration,
   and collectors produced a result.
7. Active tests cannot be safely constrained to disposable authorized environments.
8. CipherStash or Acra adds equivalent SQLAlchemy/Alembic semantic correlation before Cryptalis
   establishes it.
9. Real teams prefer independent assessor evidence and will not use first-party controls as CI
   gates.
10. The suite consumes enough solo-builder capacity that the encryption, migration, and key-lifecycle
    control it evaluates remains shallow.

## 2. Competitive and tooling landscape

### 2.1 Direct and adjacent products

The [prior-art owner](prior-art.md) holds current product capabilities, editions, dates and comparative claims.
It covers CipherStash, Acra, MongoDB, Rails and Python libraries, enterprise data-security platforms, and cloud key managers. Assurance uses that research to test one hypothesis. Does correlation from field to path to exposure improve decisions over established protection products?
Does it improve decisions over scanner and manual-inspection workflows? Competitor overlap is a comparison obligation, not evidence
of novelty or a reason to prohibit an educational prototype.

### 2.2 Mature security tools

Gitleaks maintenance and the Betterleaks research alternative are recorded in the tool ledger.
Betterleaks development documentation includes provider credential validation and analysis. These features are outside passive imports and require separate synthetic authorization.

This table summarizes research roles. The [dated tool ledger](research/assurance-tool-evidence.md) owns exact documented capabilities, editions, versions and current limitations. No integration is run.

| Tool | What it already does well | Cryptalis use | Boundary and learning decision |
|---|---|---|---|
| OWASP ZAP | Scriptable DAST plans, authentication, OpenAPI import, ordered jobs, assertions, exit status, reports and SARIF | Default open DAST adapter and reference benchmark | Build selected crawler/mutator/oracle concepts independently. Never translate alert absence into protection success |
| Burp Suite DAST | Strong crawl/audit engine, authenticated and API scanning, enterprise CI/API control | Optional commercial adapter and evidence import | Do not require a commercial engine for the open reference harness or misattribute imported findings |
| Nuclei | Signed templates, workflows, broad protocols, rate limits, JSONL/SARIF | Imported checks and template-engine reference | A narrower protection-aware DSL is educationally valid. Never automatically trust unsigned/code templates |
| sqlmap | Deep SQL injection exploitation and extraction, REST interface and reports | Explicit, destructive lab profile for synthetic marker extraction | Never run by default, use non-disposable data, or treat low risk settings as a containment guarantee |
| CodeQL | Cross-file Python data flow, path queries and custom models | Deep-analysis adapter and reference corpus | Build analogous CFG/data-flow/path concepts for learning without making CodeQL a runtime dependency |
| Semgrep | Fast structural and taint rules, broad developer adoption | Rule export and differential benchmark | Build a compatible conceptual source/sink/propagator model. Do not embed restricted rule content |
| Ruff/Bandit | Selected security lint rules and AST-based Python checks | Imported baseline and rule-design reference | Generic findings are not differentiation, but implementing selected analyzers can teach useful internals |
| Trivy/Grype/Gitleaks | Dependencies, images, IaC, secrets, VEX and standard reports | Import evidence relevant to the protection boundary | Do not duplicate vulnerability feeds or generic scanners without a bounded protection-specific research question |
| Nmap | Stable XML exposure/service inventory | Optional deployment evidence | Never treat an open port as proof of data exposure |
| TShark/Zeek | Protocol/flow evidence and machine-readable logs | Optional network collector | Never infer TLS plaintext visibility without an evidenced observation point or controlled session secrets |

ZAP itself warns that automated active scanning will not reliably find logical flaws such as broken
access control. It offers orchestration and repeatability. It does not establish semantic completeness. Use
[ZAP Automation Framework](https://www.zaproxy.org/docs/desktop/addons/automation-framework/),
[authentication](https://www.zaproxy.org/docs/desktop/addons/automation-framework/authentication/),
[OpenAPI support](https://www.zaproxy.org/docs/desktop/addons/openapi-support/automation/), and
[Automation tests](https://www.zaproxy.org/docs/desktop/addons/automation-framework/tests/) rather
than starting without a reference. Cryptalis may progressively build selected internal crawler, state, mutation and oracle layers. It may benchmark these layers against ZAP.

## 3. Product boundary and learning build-versus-integrate decision

### 3.1 Cryptalis must own

1. **Protection graph.** A versioned graph from logical field to physical storage, indexes,
   normalizers, key domains, caches, readers, writers, migrations, scenarios, collectors, and
   evidence.
2. **Manifest/model/schema/migration reconciliation.** Four-way drift detection with provenance for
   every conclusion.
3. **Doctor semantic workspace.** Cryptalis-specific source rules first, then versioned AST/symbol,
   CFG, call-graph, data-flow and taint layers tied to protected assets.
4. **Runtime boundary traces.** Opt-in observation of executed SQLAlchemy paths and emitted SQL,
   clearly bounded to the test run.
5. **Deterministic protection scenarios.** Raw/bulk bypass, relocation, cross-tenant access,
   malformed envelopes, migration windows, provider outage, stale caches, shred/restore, and
   exposure-marker trials.
6. **Exposure oracle.** Search synthetic markers across explicitly registered database, response,
   error, log, trace, report, and export collectors.
7. **Common result/evidence model.** Correlate external findings without collapsing their semantics.
8. **Harness self-test.** Positive controls, negative controls, control mutants, collector health,
   and reproducibility checks.
9. **Provider-specific lifecycle verification.** Preserve AWS, GCP, Vault, and local differences.
10. **Safety interlocks.** Authorization, target identity, scope pinning, destructive profiles,
    resource budgets, and artifact hygiene.

### 3.2 Integrate behind adapters

- ZAP as the default generic DAST engine.
- Burp Suite as an optional enterprise adapter.
- sqlmap only for a explicitly destructive, disposable-lab extraction profile.
- CodeQL and Semgrep as generated rule/model packs or imported results.
- Trivy, Grype, and Gitleaks as optional supply-chain/configuration evidence.
- Nmap for exposure inventory.
- TShark directly for packet/field export. Zeek for flow/TLS metadata when useful.
- SARIF, JUnit XML, and CycloneDX/VEX inputs as interchange formats, not the canonical model.
- in-toto Statement/DSSE or Sigstore bundles as optional evidence-integrity wrappers.

These integrations are also reference implementations. The same labeled fixtures should compare Cryptalis analyzers with CodeQL and Semgrep.
They should also compare its crawler, mutators and oracles with ZAP, Burp and sqlmap.
Building and integration are complementary research methods.

### 3.3 Active internal research workstreams

- Writer provenance using PostgreSQL statement telemetry and workload identity.
- Stateful/model-based lifecycle tests and distributed fault injection.
- Restore-resurrection drills across managed backup providers.
- Differential protected/baseline execution at scale.
- Leakage quantification for search indexes.
- Admission/deployment policy generated from the manifest.
- A stable Python semantic IR, CFG, call graph, local/interprocedural data flow and taint analysis.
- An internal crawler, endpoint/state graph, mutator, payload, oracle and replay engine.
- Declarative signed scenario/rule packs with restricted execution.
- SQL firewall, anomaly and honeytoken experiments inspired by Acra.
- PCAP/flow/protocol analysis above TShark/Zeek decoders.

### 3.4 Still reject or isolate

- A custom CVE, secret-pattern, SBOM or vulnerability-feed business with little protection-specific
  learning value.
- A generic compliance dashboard or enterprise DSPM/SIEM clone without a bounded research question.
- Public-internet scanning and autonomous exploitation.
- A universal SQL proxy accidentally replacing the ORM-first product. Isolated parser/rewriter
  experiments remain acceptable.
- An arbitrary-code YAML attack language before a typed internal scenario API works.
- A single security score, “percent secure,” or unsupported attack-coverage percentage.
- Automated remediation that modifies models, schema, keys, or production configuration.
- Novel or insufficiently reviewed range/text/fuzzy cryptography in a production profile. Known
  constructions may be independently implemented in isolated research profiles.

## 4. Architecture research hypothesis

The proposed pipeline connects Protection Manifest, model, Alembic, schema and provider snapshots to a derived Protection Graph.
It then combines Doctor observations, deterministic Verify trials and imported attack findings into a field-specific exposure explanation. The
[canonical graph and interfaces](architecture/assurance-evidence.md#5-protectiongraph-and-writer-provenance)
own the identity, edge and evidence rules. The graph is useful only if it improves decisions beyond source tools plus manual inspection.
Copying scanner rows into a graph database is not a contribution.

Compare three workflows on the same pinned fixtures:

1. ZAP with human DB and log inspection
2. Generic scanner and SIEM correlation
3. Cryptalis scenario and graph correlation Study impact-classification
accuracy, explanation time, false exact links, uncertainty, setup and maintenance. Preserve cases where an injection extracts ciphertext or search metadata while plaintext stays protected.
Also preserve cases where DAST reports no alert but raw or bulk persistence leaks. The graph must distinguish those uncomfortable cases
before it earns a marketing claim. Exact pending thresholds are at
[research gates](architecture/assurance-evidence.md#research-gates).

## 5. Result and evidence research

Study whether developers and reviewers understand the separate dimensions of a result.
These dimensions are execution, applicability, exploit, DB authority, column extraction, decoding, exact plaintext exposure and control outcome.
A single confidence or severity number obscures too much. Generic CVSS remains tool evidence.
Cryptalis impact depends on asset sensitivity, scope, recoverability and lifecycle effects.

The [result contract](architecture/assurance-evidence.md#6-verify-scenarios-and-results) owns states,
required fields and missing-evidence behavior. Research should deliberately include partial execution, unhealthy collectors and successful exploitation with protected storage.
It should also include metadata exposure without plaintext and an observed violation with other missing evidence. Ask which narrative and
machine-readable views preserve uncertainty rather than imply a clean application.

SARIF is useful for source and artifact paths and baselines. JUnit is useful for CI.
Neither format contains the full scenario and control model. Study renderer fidelity, external reviewer usability and replay cost against
canonical JSON. Signing adds integrity. It does not establish independent assessment or truth. The first-party trust
conflict is a central experiment design limitation, not a problem fixed by a logo or certificate.

## 6. Doctor and minimum-leakage research

The proposed Doctor starts with precise reconciliation of the Protection Manifest, model, schema and migration.
At the same time, the educational track builds a substantial semantic analyzer. The [canonical Doctor pipeline](architecture/assurance-evidence.md#3-doctor-pipeline-and-semantic-workspace)
owns AST/IR/symbol/CFG/taint interfaces. The [planner](architecture/assurance-evidence.md#4-minimum-leakage-planner)
owns recommendation behavior. These tracks remain active even where competitors have mature engines.

### 6.1 Compiler and reconciliation study

Compare declarative mapping inspection, source discovery and runtime metadata across inheritance,
composites, hybrids, synonyms, descriptors, events, sync/async sessions and dynamic query builders.
Measure where static, mapper, catalog and migration facts disagree. Study what information makes an unknown useful.
Mapper inspection executes initialization. Offline source analysis has a different trust mode.
Schema snapshots do not establish historical or backup correctness. Provider responses do not prove that exports, copies in memory or restored copies are absent.

SQLAlchemy has several execution planes. Study ordinary flush, `Session.execute`, bulk operations and upsert. Also study Core, text SQL, direct drivers, COPY, ETL, migrations and external writers.
Use the T/R/D/U compatibility classifications in the [ORM contract](architecture/orm-schema-migration.md). Public events are not
universal interception. Alembic autogeneration is reviewed intent, not deployability proof.
The complete revision path and each release's manifest binding matter more than comparing one
migration file to today's manifest.

### 6.2 AST, semantic IR and CFG learning

Use CPython parsing. Independently construct stable IR, scope and import models, definition and use relations, control flow and framework models. Compare local flow first. Then compare summaries, recursion and fixed-point computation, interprocedural dispatch, aliasing and typed taint. Relevant fixtures include exceptional `finally`, context managers, async cancellation and task context copying.
They also include generators, decorator wrappers, FastAPI dependencies and declarative descriptors. Unknown paths are results. Do not hide them as parser failures.

Differentially compare the same labeled paths against CodeQL, Semgrep, Pyright-informed types,
Ruff/Bandit and human labels. Do not treat editions as equivalent when comparing CE single-function detection with a commercial cross-file configuration. Measure each family's precision, recall, unknown rate, path explanations, analysis time and RSS.
This research does not claim sound analysis of a whole Python program. A short pattern rule may be more useful than an expensive model without precise asset binding.

### 6.3 Sink-specific taint research

Study independent labels for plaintext, input, secrets, keys, ciphertext and search metadata.
Also study independent tenant, subject, grant, SQL-code and evidence labels. Parameterization can stop SQL injection without stopping password logging. Normalization retains plaintext. Encryption leaves the original local variable.
A blind index is metadata. A tenant string is not authorization. These differences supply concrete lessons beyond a generic safe or unsafe bit.

Labeled families should span logs, traces, metrics, exceptions, serializers, files, messages and subprocesses.
They should also span reveal and decrypt operations, raw, Core and bulk writes, and companion columns.
Other families cover migration, AAD and format changes, provider export, cache bounds and deployment mistakes. Fixtures include safe, unsafe, ambiguous and narrowly mutated variants across local, cross-function and cross-module calls. Evaluate sensitivity-preserving unknown
models without accepting an unusable false-positive flood.

### 6.4 Query requirements and leakage planning

Study declared and observed equality, IN and uniqueness requirements. Also study joins, groups, range, order, aggregates, text, fuzzy and JSON paths.
Include casts, functions, collations and raw predicates. A no-search default for a new field differs from removal of an existing capability.
Samples with no queries cannot prove that removal is safe.
Recommendations should explain frequency, dictionary inference, and access, order, token and cross-column leakage.
They should also explain migration, storage and subject-deletion residue. Compare decision quality against manual manifest review and current CipherStash planning and status UX.
A numerical leakage score is not the comparison target.

Classification adds declared sensitivity, scope, retention and allowed exposures, but column names
do not establish regulatory obligations. Narrow policy-as-code can select checks, collectors, versions, exceptions and evidence retention.
These selections do not establish authorization or make the policy a WAF or enterprise DSPM.

### 6.5 Writer provenance research

Compare deployment registration, ORM traces, DB roles, `application_name`, query fingerprints,
connection/transaction and workload credentials for attribution. Clients can spoof hints. A shared role or pool identity can merge several actors. Include external ETL/triggers and missing
telemetry in the labeled corpus. The [writer ledger](architecture/assurance-evidence.md#52-writer-ledger)
research asks whether explicit unknown writers are more operationally valuable than more lint rules.

## 7. Pentest and internal DAST research

The hybrid approach integrates generic engines and independently builds an endpoint and state graph.
It also builds crawler, authentication, mutation, payload, oracle, minimization and replay concepts. Study authenticated
crawl coverage, role transitions, tenant/subject substitution, IDOR, response/timing differentials,
OpenAPI paths and state-reset determinism. Compare ZAP and Burp detection with equivalent editions and configurations. Compare Cryptalis field impact separately. Broad generic alerts can have educational value. They do not establish a competitive advantage for protection.

The [scenario/profile and safety contracts](architecture/assurance-evidence.md#8-pentest-architecture-and-safety)
own all privileges for execution, budgets and authorizations. `active-safe` is a profile name, not a
harmlessness guarantee. sqlmap remains an explicitly destructive synthetic extraction track. Low risk and level flags do not isolate damage. Nuclei is a template/workflow reference. Research a smaller typed declarative compiler. Include pack, schema, signature, version and privilege validation, helper-file integrity, and constrained execution.
Never silently extend YAML to execute arbitrary shell or Python.

The complete scenario research spans injection/DB credentials, raw/Core/bulk/COPY/ETL,
cross-context and ciphertext relocation, envelope malformed/version/key states, index tamper and
low-entropy inference, provider outage/throttle/permission/wrong-region, cache expiry/partitions,
migration coexistence/backfill/cutover/contract, shred/restore/reimport, artifact exposure and
audit mutation. Many scenarios are state-machine trials. They supply stronger, more reproducible trials than a generic exploit.

## 8. Verify, exposure and network research

Verify is a deterministic layer that remains useful without DAST. The
[canonical oracle protocol](architecture/assurance-evidence.md#7-exposure-oracle-and-collectors)
owns synthetic markers, forms, watermarks, redaction, controls and absence semantics.

Study whether collector start and end barriers and lateness bounds remain reliable under async logs.
Include rotation, sampling, truncation, compression, DB snapshots and pagination, response caps, and worker failure.
Seed positive markers at the actual observation point. A healthy test at the wrong layer gives no evidence about downstream loss. Distinguish stale/control/scenario hits. Early irreversible redaction can prevent matching. Safe redaction after a private synthetic decision can preserve bounded evidence.

Detector mutation has high learning value. Study plaintext persistence, disabled relocation or context binding, stale-cache acceptance, index mismatch and new capability-specific mutants. Study whether mutants represent the intended fault and cause precisely the intended failure.
A breakage that the detector trivially detects does not establish this property. Missing collectors, unsuccessful attacks and a real
observed violation with other missing collectors are distinct cases.

Research with PCAP, TShark and Zeek studies correlation among flows, endpoints, TLS, timing and size. It also studies overhead. Ordinary
TLS cannot supply plaintext evidence. Lab session secrets or a named capture point inside the boundary change visibility and evidence sensitivity.
pcapng can embed secrets. Nmap supports deployment
exposure, not field confidentiality. Mature decoders supply references. Selected correlation and traffic-analysis concepts remain valid research without new packet parsers as the default.

## 9. Lifecycle and resurrection research

Use the [crypto/lifecycle owner](architecture/crypto-search-lifecycle.md) for provider/control state,
and [Verify results](architecture/assurance-evidence.md#6-verify-scenarios-and-results) for evidence.
Compare AWS retained historical and imported material with Google Cloud destruction and restoration windows.
Also compare Vault rotation, export, deletion and storage backups. Treat these as different state machines. No portable API turns
pending deletion into cryptographic destruction.

Measure fresh and stale-process decryption, worker leases/acknowledgements, in-flight commits/output,
wrapped-key inventory, tombstones outside snapshot authority, supported restore denial and offline
recovery from surviving branch plus wrapped subject keys. Search-index residue and unmanaged copies
are separate effects. Managed access denial and cryptographic destruction of recovery paths need different evidence.
Even the stronger result does not prove erasure from memory, logs or exports, or legal erasure.

## 10. Migration and deployment research

The [ORM/migration owner](architecture/orm-schema-migration.md) owns state/checkpoint/concurrency
contracts. Compare interrupted stages, retries, two workers, concurrent CAS writes, mixed releases,
normalization/index/key changes, uniqueness races, invalid concurrent indexes, WAL/locks/replica lag
and old-phase restore. Study recovery cost and the observations needed before irreversible contraction. Rows verified and rows never attempted must remain distinguishable.

Import generic Trivy/Grype/Gitleaks findings while studying their causal relevance to key release,
DB transport, shared credentials, mutable tools/evidence, backup/tombstone and isolated lab paths.
Scanner filters/VEX/feeds and recognized IaC files are part of comparison, not universal posture.
Current Gitleaks documentation describes maintenance for security patches only. Evaluate whether adapters can be replaced.
Do not assume that a generic engine remains maintained indefinitely.

## 11. Correlation and impact research

A representative chain is injection confirmed -> request/subject -> DB protected-column selection ->
extraction artifact -> marker absence in named healthy collectors -> bounded DB-confidentiality held,
with envelope/search metadata still disclosed. The application vulnerability remains confirmed.
The inverse chain is a clean DAST result beside deterministic plaintext persistence failure.

The [graph owner](architecture/assurance-evidence.md#51-identity-and-relationships) owns exact joins.
Research should include unrelated requests close in time, reused restore IDs, shared pools and forged traces.
Also include unknown writers and conflicting source and runtime claims. Scoring explanations should penalize false
exact attribution more heavily than a correct visible unknown. Do not average attacker success and
control outcome into a product score.

## 12. Safety research

Study whether network enforcement plus request-time scope, deployment tokens and disposal sentinels
can constrain every selected engine. Include IPv4/IPv6, DNS rebinding, redirect chains, proxy/spec
URLs, browser resources, callbacks, metadata services, malicious pack helpers and stop-API delay.
Authorization, a private IP or a small request rate alone does not establish containment. The
[safety owner](architecture/assurance-evidence.md#8-pentest-architecture-and-safety) contains the
normative interlocks. Failure blocks the active profile but permits passive learning.

## 13. Integrity, provenance and reviewer workflow research

The [bundle owner](architecture/assurance-evidence.md#10-evidence-bundle-and-integrity) specifies
canonical bytes, complete inventory, parser limits, attestations and trust policy. Study alternative DSSE, in-toto and Sigstore wrappers.
Use corrupted members, wrong targets, signers and issuers, truncation, checkpoint replacement, schema downgrade, and loss of the witness. Source integrity and
collector truth remain separate even after signing.

Developer views need exact field, source and DB paths, plus remediation.
Reviewers need attack, control, exposure, provenance and unknowns. Operators need manifest, release, provider, migration and baseline information. Measure which results a reviewer can independently recompute from redacted public artifacts.
Measure which results need new local synthetic reproduction. Evidence generation must not create a plaintext, token, TLS-secret or
key repository. Report rendering is itself an exposure scenario.

## 14. CI, pytest and stateful learning

The [CI owner](architecture/assurance-evidence.md#11-ci-reference-lab-and-regression) specifies safe
profiles. The [shared CLI](architecture/manifest-context-api.md#cli-and-configuration) owns exits.
Study narrow pytest hooks for request/SQL identity and marker controls without invasive instrumentation.
Coverage describes executed tests. It does not establish universal application behavior.

Stateful Hypothesis research fits parser/normalization/query rewriting, generations/epochs,
migration transitions and lifecycle faults. Record seeds and minimized synthetic counterexamples.
Regression comparison studies new, resolved, unchanged, regressed and reclassified outcomes as manifest, tool, collector and model versions change.
Baselines are observations. They cannot serve as hidden allowlists for failures.
Fast offline CI, isolated DAST and authorized cloud chaos have different dependencies and failure modes.

## 15. Benchmarks and evaluation

The [research gates](architecture/assurance-evidence.md#research-gates) own exact pending minima and
acceptance thresholds. Corpus work remains a major research task, not a demo checklist.

Static research labels safe, unsafe and ambiguous paths for each rule and compatibility style.
It measures precision, recall, unknowns, explanations and version stability. Dynamic research compares a plaintext baseline, normal protection, one relevant control mutant, and missing or unhealthy collectors. The
scientific outcome is accurate classification of exposure under the same attack, not fewer alerts.

Separate crypto microbenchmarks from ORM, query and uniqueness costs. Also separate migration concurrency and recovery, provider and cache, analyzer, collector and graph costs. Pin versions, hardware, data, tenant cardinality, cache state and load.
Use multiple runs, randomized order, raw distributions, failures, retries and uncertainty. Correctness
and exposure controls must run beside performance. Short fields and variable-cardinality indexes
can have high amplification even where CPU is small. Compare products only under equivalent security, query, access and deployment conditions. Otherwise, retain qualitative lessons.
## 16. Academic integration and complete assurance scope

The historical IS-Lab project context proposed a quarantined reference environment for web
pentesting demonstrations and data-protection impact measurement. Course payloads and intentionally
vulnerable code never enter the production package. Earlier notes assumed ZAP would satisfy an open-tool requirement. No current course rubric was supplied or verified in this pass. This is
historical context, not a current compliance finding. sqlmap, PCAP, TShark, Zeek, Nmap, internal DAST and other integrations remain active Cryptalis workstreams.
They do not depend on a future course rubric.

The course-specific question is whether an actual dated rubric accepts the proposed demonstration.
Wrong assumptions would produce a failed submission. The default is to withhold the course-sufficiency claim. Alternatives are a ZAP-led demonstration or another explicitly accepted open-tool demonstration.
The minimum experiment has these steps:

1. Get the authentic course and rubric version.
2. Map every mandatory item to a pinned demonstration.
3. Execute the required scenarios.
4. Collect the artifacts required by the instructor.

Evidence is that rubric plus
the complete mapping/run artifacts and any instructor clarification. Pass requires satisfaction of every mandatory item. Missing or ambiguous items fail or remain open.
Course-compliance wording is blocked until then. Isolated synthetic lab and engine work may proceed safely.

### 16.1 Reference Docker lab

The [canonical lab and regression contract](architecture/assurance-evidence.md#11-ci-reference-lab-and-regression)
owns services, networks, reset, identity, collectors and cleanup. Research compares baseline,
protected, mutant and incomplete-evidence environments while retaining the same app/attack semantics.
The course demonstration is a local learning artifact, not evidence of complete pentesting coverage.
### 16.2 Complete active assurance workstreams

1. Protection-graph schema and canonical evidence/result model.
2. Doctor checks for manifest/model/schema/Alembic drift plus AST, semantic IR, symbols, CFG, local
   and interprocedural data flow, typed taint and framework-aware rule research.
3. Runtime tracing for one documented SQLAlchemy ORM path and explicit gaps for raw/Core/bulk paths.
4. Verify scenarios for DB-credential extraction, raw/bulk bypass, relocation, cross-tenant access,
   tamper, provider outage, stale cache, shred/restore, migration interruption, and seeded leakage.
5. ZAP Automation Framework adapter with authenticated OpenAPI scanning.
6. Synthetic exposure oracle for PostgreSQL, HTTP results, application logs, and evidence artifacts.
7. Positive/negative collector controls and at least four semantic control mutants.
8. Canonical JSON plus SARIF/JUnit/Markdown renderers and a hashed reproducibility bundle.
9. Strict lab authorization/isolation and CI-safe profile separation.
10. Labeled evaluation corpus and protected/baseline comparison.
11. Burp, Nuclei, sqlmap, CodeQL, Semgrep, Trivy, Nmap, TShark and Zeek adapters or comparison
    harnesses with source-tool semantics preserved.
12. Internal endpoint discovery, crawler and authentication/state modeling, mutation, payload, oracle,
    minimization and replay engines.
13. Provider-cloud chaos, signed attestations, writer provenance, managed-backup and cross-cluster
    restore drills, and attack/protection graph planning.

### 16.3 Solo flat assurance program

One person owns every assurance workstream. Doctor, Pentest, Verify and the Protection Graph may advance concurrently with exposure collectors and tool adapters.
Internal SAST and DAST, networking and lifecycle-chaos research may also advance concurrently. Scenario IDs, evidence schema, test vectors, marker policy and safety contracts are versioned.
Thus, workstreams with different maturity can interoperate while preserving their separate evidence levels. Manual implementation remains one file and one explainable invariant at a time.

## 17. Assurance research themes

These themes organize assurance research questions, not implementation workstream IDs or state.
The [build guide](cryptalis-build-guide.md) owns the dependency-aware file sequence and the
[checklist](backend-build-checklist.md) owns progress. Every experiment records evidence maturity
and dependencies. Research can start before integration is justified.

### Theme A — Falsify the premise

Define the graph and result schemas. Label a fixture corpus. Run baseline and protected scenarios.
Verify that correlation adds information unavailable from source tools. Interview maintainers and
security reviewers about whether first-party evidence is useful while engine experiments proceed.

### Theme B — Core developer assurance

Manifest/model/schema/migration Doctor. Exactness labels. Precise AST rules plus advanced semantic
analysis research. PostgreSQL/HTTP/log exposure collectors. Deterministic Verify. Controls/mutants.
JSON/JUnit/Markdown. CI fast path.

### Theme C — Quarantined attack harness

ZAP authenticated/OpenAPI adapter, attack-to-asset correlation, reference vulnerable app, strict
authorization, pinned images, resource budgets and cleanup evidence.

### Theme D — Lifecycle and operations depth

Provider-specific facts, cache fencing, stale workers, shred/restore, migration interruption,
deployment findings, writer provenance and signed evidence bundles.

### Theme E — Internal SAST/DAST and network depth

Stable syntax/semantic IR, symbols, CFG, local data flow, rule engine, endpoint/state graph, request
mutators, response/exposure oracles, deterministic replay, PCAP/flow correlation and differential
comparison with CodeQL/Semgrep/ZAP/Burp.

### Theme F — Advanced research ecosystem

Interprocedural taint and framework summaries. Signed rule/scenario packs. Acra-like SQL
policy/honeytoken experiments. Managed-backup drills. Nuclei/sqlmap/Trivy/Nmap/TShark/Zeek depth. And broader attack-graph planning.

Every workstream requires thresholds for precision, recall, determinism, mutation-kill, evidence completeness and safety.
Define these thresholds before results support stronger claims. Feature count is not a
maturity criterion.

## 18. Falsifiable research questions

All are pending first-party experiments. Gate definitions are in the [canonical assurance owner](architecture/assurance-evidence.md#research-gates).
A hypothesis or budget change requires a new recorded experiment version before measurement.

| Question / hypothesis | Comparison or failure injection | Acceptance / redesign |
|---|---|---|
| Graph identity survives mapper/migration/restore change | rename/revision/restore fixtures with reused names/OIDs | G-A03/G-A06: no false exact joins. Preserve epochs or redesign IDs |
| Raw/Core/bulk paths can be meaningfully rejected | T/R/D/U cell trials with parameter/bypass variants | ORM P2: zero silent plaintext on admitted T/R. Otherwise narrow profile |
| Correlation needs tolerable instrumentation | same labeled chains with trace adapter vs manual inspection | G-A03/G-A09 plus predeclared overhead/setup budget. Demote if no value |
| Non-Python/background identity can be authenticated | shared-role, forged application_name, pool and ETL trials | G-A03: unknown attribution visible. Exact actor claims require proved identity |
| A named collector set supports bounded absence | missing, truncated, sampled, late, redacted and rotated sources | G-A04: all controls/intervals valid, no false absence. Otherwise inconclusive |
| Metadata leakage ranking changes useful decisions | low-entropy/search-domain fixtures and reviewer explanations | predeclare domain leakage acceptance. Reject search when inferred exposure exceeds it |
| Provider restore tests preserve provider meaning | emulator then authorized AWS/GCP/Vault restore/reimport lanes | lifecycle gates plus G-A04: no state collapse. Stronger claim withheld if recovery survives |
| First-party public artifacts are useful externally | reviewer recomputes hashes/relationships, reruns fresh synthetic fixtures | G-A08/G-A09 plus explicit external artifact before independence claim |
| Mutants represent the intended control fault | one-fault mutants vs normal/missing-collector configurations | G-A04/G-A06: expected violation/replay, no unrelated failure counted as kill |
| Protected-value sink rules are usable | held-out safe/unsafe/ambiguous cross-function/module corpus | G-A02 plus predeclared triage-time budget. Narrow rule when exceeded |
| Reference app predicts compatibility work | vary loaders/mapping/raw/jobs/serializer patterns | per-cell ORM gates. Missing cells unsupported. No app-wide extrapolation |
| Registration burden is acceptable | >=5 maintainers walk through writer/collector/backup setup | record completion/time/rejection. Predeclare <=1 hour local setup hypothesis. Failure demotes adoption thesis, not a market estimate |
## 19. Fatal risks and stop rules

- **Trust conflict:** Cryptalis grades Cryptalis. Mitigation uses transparent artifacts, controls, replay and optional signatures. These controls do not establish independence.
- **Coverage illusion:** a polished dashboard may conceal unobserved writers or collectors. Results must explicitly represent unknowns. Relevant unknowns must block pass results.
- **Scanner maintenance:** generic engines and templates change rapidly. Adapters must be thin,
  version-pinned, and replaceable.
- **Framework churn:** SQLAlchemy/Alembic internals may invalidate rules. Support matrices and fixture
  corpora are release gates.
- **Dangerous automation:** exploitation, key destruction, and restore testing can damage systems.
  The default stays passive and local.
- **Privacy of evidence:** security artifacts can become a new plaintext repository. Synthetic data,
  redaction, least retention, encryption, and access controls are mandatory.
- **Scope starvation:** assurance work can consume the capacity needed to make the protected boundary
  correct. Core protection and migrations remain the primary product.

Compare protected-asset impact classification against ZAP and source-tool output plus human database inspection.
If the correlation-premise experiment cannot show a material improvement, stop or demote the product claim.

### 19.1 Risk register by ownership

| Class | Top risks |
|---|---|
| Technical | SQLAlchemy visibility gaps. Source/runtime correlation ambiguity. Provider/restore non-portability. Flaky active scans. Evidence-schema evolution |
| Security | Destructive execution escapes scope. Evidence stores plaintext/secrets. Stale keys survive claimed shredding. Malicious templates/tools. The suite's own control is trusted circularly |
| Maintenance | Scanner/template churn. SQLAlchemy/Alembic compatibility matrix. Provider API changes. Duplicated generic-tool logic. Long-lived scenario corpus and fixtures |
| Adoption | False positives. Setup/collector burden. Fear of active testing. First-party evidence rejected by assessors. A field-encryption library is good enough |

There are substantive reasons not to build. The same effort invested in migration safety may be more useful.
ZAP plus a human database check may suffice for target users. They may prefer independent pentesters.
Acra or CipherStash may close the semantic gap.

One maintainer may not sustain protection, lifecycle, compatibility, static analysis, pentesting and assurance at the same time.

## 20. Positioning discipline

Acceptable:

> Cryptalis combines SQLAlchemy-native protection diagnostics with controlled attack-impact and
> data-exposure verification. It imports mature scanner findings and correlates them with declared
> protected fields, schema, migrations, keys, caches, and observed artifacts.

Not acceptable:

- “Built-in pentesting proves your application is secure.”
- “No plaintext leaked” without naming collectors, interval and controls.
- “Complete SAST/DAST,” “continuous pentest,” or “enterprise DSPM.”
- “Independent proof,” “breach-proof,” “zero leakage,” or “compliance certified.”
- “Crypto-shredding verified” based only on a successful provider API call.
- “All SQLAlchemy paths protected” without a pinned compatibility catalogue.

The strongest demo exposes difficult results. Show the same exploitable application in plaintext, protected and mutated configurations.
Let the attack succeed. Then show precisely what changed in the database and evidence stores.
Show which controls held, which metadata still leaked and what the suite could not observe.

### 20.1 Value outside the university and research contribution

A developer would use the suite to detect concrete retrofit failures before deployment.
The suite would help the developer decide whether a searchable representation is justified.
It would also help reproduce a protection regression in pytest or CI and give a reviewer a bounded evidence bundle. An operator would use it to reconcile manifest, schema, migration, provider and cache state. A security reviewer would use it to distinguish a
successful exploit from the protected-data impact of that exploit. Those workflows exist outside
the course only if setup is materially cheaper than an ad hoc review.

The plausible research contribution is not a new attack or cryptographic primitive. It is an evaluated model that correlates ORM, schema and key-lifecycle semantics with attack and exposure evidence from multiple sources.
The model includes explicit unknowns and detector mutants. The contribution requires a labeled corpus, protected, baseline and mutant experiments, precision, recall, reproducibility, and published limitations.

## 21. Primary source index

Additional primary references used in this decision:

- [Burp Scanner](https://portswigger.net/burp/documentation/scanner) and
  [CI-driven scans](https://portswigger.net/burp/documentation/dast/user-guide/ci-cd/ci-driven-scans/getting-started)
- [ZAP API warning on logical vulnerabilities](https://www.zaproxy.org/docs/api/) and
  [SARIF reporting](https://www.zaproxy.org/docs/desktop/addons/report-generation/report-sarif-json/)
- [Nuclei execution/output](https://docs.projectdiscovery.io/opensource/nuclei/running)
- [Nmap XML output](https://nmap.org/book/output-formats-xml-output.html)
- [AWS CloudTrail KMS logging](https://docs.aws.amazon.com/kms/latest/developerguide/logging-using-cloudtrail.html)
- [Google Cloud KMS audit logging](https://docs.cloud.google.com/kms/docs/audit-logging)
- [CipherTrust Data Security Platform](https://cpl.thalesgroup.com/encryption/data-security-platform)
  and [data discovery/classification](https://cpl.thalesgroup.com/encryption/data-discovery-and-classification)
- [Imperva unified data-security visibility](https://www.imperva.com/products/data-security/unified-visibility/)
- [Fortanix platform](https://www.fortanix.com/platform)

All vendor claims describe documented capability. They do not establish independently reproduced performance. Re-run this
review before public positioning because product and tool behavior changes quickly.

## Appendix A. Required deliverable coverage

This map preserves the original 62-part research brief. Rows identify research discussions.
The linked architecture documents own normative contracts. No row implies implementation.

| # | Required topic | Research discussion |
|---:|---|---|
| 1 | Executive verdict | Executive decision |
| 2 | Competitor security-tooling landscape | 2 |
| 3 | Features competitors already have | 2.1–2.2 |
| 4 | Features worth adopting | 3.1–3.2 |
| 5 | Features not to replicate | 3.4 |
| 6 | Unique semantic advantages | 3.1, 4 |
| 7 | Final Security Assurance thesis | 1, 20 |
| 8 | Doctor architecture | 6 |
| 9 | SQLAlchemy Doctor | 6.1–6.3 |
| 10 | Query/Search Doctor | 6.4 |
| 11 | Minimum-leakage analysis | 6.4 |
| 12 | Schema/Alembic Doctor | 6.1, 10 |
| 13 | Key/KMS Doctor | 6.1, 9 |
| 14 | Shredding Doctor | 9 |
| 15 | Application-security Doctor | 6.3–6.4 |
| 16 | Secret/logging analysis | 6.3–6.4 |
| 17 | Deployment Doctor | 10 |
| 18 | Dependency/security-tool integration | 2.2, 3.2, 10 |
| 19 | Pentesting architecture | 7 |
| 20 | Web attack suite | 7 |
| 21 | Database compromise tests | 7 |
| 22 | ORM/raw SQL bypass tests | 6.1, 7 |
| 23 | Ciphertext tampering tests | 7, 8 |
| 24 | Searchable-encryption adversarial tests | 6.4, 7, 9 |
| 25 | Key lifecycle tests | 9 |
| 26 | Shredding adversarial tests | 9 |
| 27 | Migration security tests | 10 |
| 28 | Plaintext leakage tests | 8 |
| 29 | PyShark/traffic analysis | 8 |
| 30 | PCAP analysis | 8 |
| 31 | Nmap integration | 2.2, 3.2 |
| 32 | ZAP/Burp/sqlmap/Nuclei integration | 2.2, 3.2, 7 |
| 33 | Template-driven testing | 7 |
| 34 | Doctor-to-Pentest correlation | 4, 11 |
| 35 | Evidence/confidence model | 5 |
| 36 | Security invariants | [Hub invariants](architecture/README.md#23-canonical-security-invariants) |
| 37 | Fuzzing/property tests | 14 |
| 38 | Unified reporting | 5, 13 |
| 39 | Severity model | 5 |
| 40 | CI/CD integration | 14 |
| 41 | Pytest integration | 14 |
| 42 | Security regression workflow | 14 |
| 43 | Safe execution model | 12 |
| 44 | Reference Docker lab | 16.1 |
| 45 | IS-Lab historical context. Rubric unverified | 16 |
| 46 | Competitor comparison | 2 and prior-art document |
| 47 | Usefulness outside university | 20.1 |
| 48 | Developer value | 20.1 |
| 49 | Complete architecture | 4, 17 |
| 50 | Active assurance workstreams | 16.2 |
| 51 | Solo work division and flat coordination | 16.3 |
| 52 | Research contribution | 20.1 |
| 53 | Benchmark methodology | 15 |
| 54 | Features to reject | 3.4 |
| 55 | Top technical risks | 19.1 |
| 56 | Top security risks | 19.1 |
| 57 | Top maintenance risks | 19.1 |
| 58 | Top adoption risks | 19.1 |
| 59 | Reasons not to build | 1.1, 19–19.1 |
| 60 | Final CLI/API | 14 and [shared CLI](architecture/manifest-context-api.md#cli-and-configuration) |
| 61 | Final architecture diagram | [Architecture hub](architecture/README.md) |
| 62 | Final positioning statement | 20 |
