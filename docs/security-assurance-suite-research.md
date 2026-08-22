# Cryptalis Security Assurance Suite: Adversarial Architecture Research

Status: Research decision; no implementation exists

Last reviewed: 2026-08-22

Scope: `doctor`, `plan`, `verify`, the quarantined pentesting harness, evidence/reporting, and the
interfaces between them. This document does not authorize active scanning of any real target.

## Executive decision

**SECURITY ASSURANCE SHOULD BE A MAJOR SECONDARY CRYPTALIS SELLING POINT — conditionally.**

The position survives only if Cryptalis owns the semantic correlation layer: it must connect a
declared protected field to its model mapping, physical columns and indexes, migration history,
write paths, key/cache lifecycle, exercised attack path, observed artifacts, and final exposure.
That is a narrower and more defensible product than “security scanner for encrypted apps.”

This product-positioning conclusion is separate from the learning decision. Cryptalis may still
build substantial SAST, DAST, template, SQL-policy and network-analysis subsystems when construction
offers high educational value and a credible correctness benchmark. Generic breadth does not become
the product moat, but competitor overlap no longer vetoes the work. The governing evaluation model
is in the [learning-first research philosophy](learning-first-research-philosophy.md).

The broad claim does not survive scrutiny:

- Acra already combines data protection with a SQL firewall, anomaly reactions, honeytokens,
  security logging, signed audit logs, key inventory, and SIEM integration.
- CipherStash now documents planning, implementation, validation, status, phased encryption, and
  drift-oriented workflows in addition to searchable encryption and a proxy.
- Thales, Fortanix, and Imperva are much stronger at estate-wide discovery, posture, activity
  monitoring, centralized key inventory, and compliance operations.
- ZAP, Burp Suite, Nuclei, sqlmap, CodeQL, Semgrep, Trivy, Gitleaks, Grype, Nmap, TShark, and Zeek
  already own mature generic detection engines and formats.
- A scanner operated by the same product that supplies the protection control is not independent
  assurance. Its evidence can be reproducible and tamper-evident, but it remains first-party.

Therefore Cryptalis earns the secondary selling point only by answering a question those tools do
not answer together:

> When a specific attack or operational fault reaches this SQLAlchemy application's protected-data
> boundary, which declared assets become plaintext, ciphertext, search metadata, key material, or
> nothing at all—and what evidence supports that conclusion?

If the suite becomes only a wrapper around ZAP plus generic lint rules, demote its product claim to
developer tooling; an independently built learning engine must still demonstrate measurable depth.
If `doctor` cannot distinguish facts from heuristics, or `verify` treats missing collectors as a
pass, remove assurance from positioning entirely.

## 1. The claim under test

The strongest credible product statement is:

> Cryptalis helps teams design, exercise, and audit the application-specific boundary around
> protected SQLAlchemy fields. It does not prevent application vulnerabilities; it tests whether
> declared protection still limits data exposure when vulnerabilities, bypasses, lifecycle faults,
> and deployment mistakes occur.

This is deliberately not “continuous pentesting,” “DSPM,” “breach prevention,” or “proof of
security.” SQL injection may succeed while Cryptalis protection holds. Conversely, a clean generic
DAST scan does not show that raw SQL, bulk writes, migrations, logging, cache staleness, or restore
paths preserve protection.

### 1.1 Conditions that would disprove the product position

The major-secondary thesis fails if any of these remain true after a serious prototype:

1. Most Doctor findings cannot identify an exact protected field and concrete violating path.
2. Runtime observation covers only a curated demo while the UI implies application-wide coverage.
3. The harness cannot demonstrate that its collectors detect deliberately seeded plaintext and
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

| Product class | Existing strength that weakens Cryptalis's claim | Remaining opening | Decision |
|---|---|---|---|
| CipherStash | Searchable encryption, proxy/SDK, key service, metrics, and current `init`/`plan`/`impl`/`status`/validation workflows | SQLAlchemy model/query semantics, Alembic graph analysis, field-to-attack exposure correlation, subject-lifecycle evidence | Benchmark aggressively; do not claim planning, status, or migration as unique |
| Acra | Encryption/search plus SQL firewall, IDS-style reactions, honeytokens, signed audit logs, SIEM, key inventory | ORM-aware declaration/schema/migration reasoning and controlled comparative attack experiments | Treat as the closest counterexample to the assurance narrative |
| MongoDB Queryable Encryption | Deep driver/database integration, randomized searchable encryption, explicit supported-operation catalogue | Python/SQLAlchemy retrofit and cross-provider subject lifecycle | Copy fail-loud discipline; do not imitate protocols |
| Rails Active Record Encryption / Python field libraries | Mature transparent field ergonomics, deterministic lookup or blind indexes, mixed-scheme migration patterns | Unified manifest, physical schema compiler, bypass analysis, distributed lifecycle and evidence | Compete only on systems integration |
| Thales CipherTrust / Fortanix / Imperva | Discovery, classification, posture, key inventory, monitoring, policy, reports across estates | Developer-local, framework-specific causal evidence | Integrate/export where useful; reject enterprise-platform imitation |
| Cloud KMS / Vault | Managed root custody, audit events, rotation/deletion APIs, IAM | Application semantics, cache fencing, migration and exposure tests | Use as sources of provider-attested facts, never flatten semantics |

The current CipherStash workflow deserves special attention. Its CLI documentation now describes a
progression from initialization through planning and implementation, while status/validation expose
per-column encryption phases, progress, and drift. Those capabilities erase a substantial portion
of an earlier Cryptalis differentiation claim. The remaining wedge must be source-aware analysis and
empirical protection-boundary verification, not merely “a plan command for encryption.” See
[CipherStash CLI](https://cipherstash.com/docs/stack/cipherstash/cli),
[plan](https://cipherstash.com/docs/stack/cipherstash/cli/plan),
[implementation](https://cipherstash.com/docs/stack/cipherstash/cli/impl), and
[status](https://cipherstash.com/docs/stack/cipherstash/cli/status).

Acra invalidates the claim that database-protection products only report “encrypted.” Its published
controls include searchable encryption, an SQL firewall, anomaly responses, honeytokens, SIEM-ready
security events, cryptographically signed audit logs, and key inventory. Cryptalis may still offer a
better SQLAlchemy developer workflow, but it is not inventing protection-aware operations. See
[Acra security controls](https://docs.cossacklabs.com/acra/security-controls/),
[SQL firewall](https://docs.cossacklabs.com/acra/security-controls/sql-firewall/), and
[security logging and events](https://docs.cossacklabs.com/acra/security-controls/security-logging-and-events/).

### 2.2 Mature security tools

| Tool | What it already does well | Cryptalis use | Boundary and learning decision |
|---|---|---|---|
| OWASP ZAP | Scriptable DAST plans, authentication, OpenAPI import, ordered jobs, assertions, exit status, reports and SARIF | Default open DAST adapter and reference benchmark | Build selected crawler/mutator/oracle concepts independently; never translate alert absence into protection success |
| Burp Suite DAST | Strong crawl/audit engine, authenticated and API scanning, enterprise CI/API control | Optional commercial adapter and evidence import | Require it for the open reference harness or repackage findings |
| Nuclei | Signed templates, workflows, broad protocols, rate limits, JSONL/SARIF | Imported checks and template-engine reference | A narrower protection-aware DSL is educationally valid; never automatically trust unsigned/code templates |
| sqlmap | Deep SQL injection exploitation and extraction, REST interface and reports | Explicit, destructive lab profile for synthetic marker extraction | Run by default, use against non-disposable data, or claim it is safe at high risk levels |
| CodeQL | Cross-file Python data flow, path queries and custom models | Deep-analysis adapter and reference corpus | Build analogous CFG/data-flow/path concepts for learning without making CodeQL a runtime dependency |
| Semgrep | Fast structural and taint rules, broad developer adoption | Rule export and differential benchmark | Build a compatible conceptual source/sink/propagator model; do not embed restricted rule content |
| Ruff/Bandit | Fast generic Python security lint | Imported baseline and rule-design reference | Generic findings are not differentiation, but implementing selected analyzers can teach useful internals |
| Trivy/Grype/Gitleaks | Dependencies, images, IaC, secrets, VEX and standard reports | Import evidence relevant to the protection boundary | Build another CVE, secret, SBOM, or IaC scanner |
| Nmap | Stable XML exposure/service inventory | Optional deployment evidence | Treat an open port as proof of data exposure |
| TShark/Zeek | Protocol/flow evidence and machine-readable logs | Optional network collector | Promise TLS plaintext visibility without controlled session secrets |

ZAP itself warns that automated active scanning will not reliably find logical flaws such as broken
access control. Its strength is orchestration and repeatability, not semantic completeness. Use
[ZAP Automation Framework](https://www.zaproxy.org/docs/desktop/addons/automation-framework/),
[authentication](https://www.zaproxy.org/docs/desktop/addons/automation-framework/authentication/),
[OpenAPI support](https://www.zaproxy.org/docs/desktop/addons/openapi-support/automation/), and
[Automation tests](https://www.zaproxy.org/docs/desktop/addons/automation-framework/tests/) rather
than starting without a reference. Cryptalis may progressively build selected internal crawler,
state, mutation and oracle layers and benchmark them against ZAP.

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
- sqlmap only for a conspicuously destructive, disposable-lab extraction profile.
- CodeQL and Semgrep as generated rule/model packs or imported results.
- Trivy, Grype, and Gitleaks as optional supply-chain/configuration evidence.
- Nmap for exposure inventory.
- TShark directly for packet/field export; Zeek for flow/TLS metadata when useful.
- SARIF, JUnit XML, and CycloneDX/VEX inputs as interchange formats, not the canonical model.
- in-toto Statement/DSSE or Sigstore bundles as optional evidence-integrity wrappers.

These integrations are also reference implementations. The same labeled fixtures should compare
Cryptalis analyzers with CodeQL/Semgrep and its crawler/mutators/oracles with ZAP/Burp/sqlmap. Build
and integrate are complementary research methods.

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
- A universal SQL proxy accidentally replacing the ORM-first product; isolated parser/rewriter
  experiments remain acceptable.
- An arbitrary-code YAML attack language before a typed internal scenario API works.
- A single security score, “percent secure,” or unsupported attack-coverage percentage.
- Automated remediation that modifies models, schema, keys, or production configuration.
- Novel or insufficiently reviewed range/text/fuzzy cryptography in a production profile. Known
  constructions may be independently implemented in isolated research profiles.

## 4. Architecture

```text
protection declarations + manifest + model metadata + Alembic graph
                 |                   |
                 v                   v
          Protection Graph <--- schema/provider/deployment snapshots
             /      |       \
            v       v        v
        Doctor     Verify   Pentest adapters
       static +   controlled  ZAP/Burp/sqlmap/
       observed    scenarios  Nuclei imports
            \       |        /
             v      v       v
             Common observation model
                       |
          correlation + exposure oracle
                       |
            versioned evidence bundle
        JSON / SARIF / JUnit / HTML / attestation
```

The protection graph is the conceptual moat. A node is an asset or boundary: logical field,
physical column, search index, key generation, cache lease, write path, migration phase, service,
scenario, or collector. An edge states a typed relationship such as `persists_to`, `indexed_by`,
`written_by`, `encrypted_under`, `observed_by`, or `exercised_by`. Every edge records provenance and
confidence. An unknown writer is an explicit coverage gap, not an implicit safe path.

The graph must remain a derived analysis artifact. The Protection Manifest remains the normative
declaration; observed code, schema, and runtime facts may contradict it but must not silently rewrite
it.

## 5. Common result and evidence semantics

### 5.1 Result states

Every check or scenario ends in exactly one of:

- `PASS`: the expected control held, required collectors ran, and relevant positive/negative
  controls behaved correctly.
- `FAIL`: observed evidence contradicts the declared control or exposure policy.
- `WARNING`: a material risk exists, but available evidence does not establish a violation.
- `INCONCLUSIVE`: execution or evidence was insufficient to decide.
- `NOT_APPLICABLE`: the check does not apply and records why.
- `NOT_RUN`: applicable work was not attempted.

Missing, unhealthy, redacted, timed-out, or access-denied collectors can never produce `PASS`.

### 5.2 Separate dimensions

Do not overload one “confidence” or “severity” field. Record independently:

| Dimension | Example values |
|---|---|
| Execution | not started, started, completed, aborted |
| Applicability | applicable, not applicable, unknown |
| Attack result | no foothold, vulnerability confirmed, boundary reached, extraction succeeded |
| Exposure | none observed, ciphertext, index/search metadata, envelope metadata, plaintext, key material |
| Control outcome | held, bypassed, degraded, not exercised, inconclusive |
| Evidence basis | declared, static, schema snapshot, provider-attested, runtime-observed, actively exercised, exposure-confirmed |
| Scope | exact field/path, table, service, deployment, unknown |
| Reproducibility | deterministic, replayable with seed, flaky, unreproduced |

Generic vulnerability severity remains the source tool's CVSS or rating. Cryptalis adds an impact
classification based on protected asset class, reachability, exposure type, tenant/subject scope,
recoverability, and lifecycle consequences. It should not convert these into a pseudo-precise score.

### 5.3 Canonical finding fields

Each finding needs: schema version; stable rule/scenario ID; run and correlation IDs; target and
manifest digests; subject asset(s); stage; applicability; observation point; tool and rule versions;
source location or artifact URI; exact evidence references; redaction status; execution, attack,
exposure, control and result states; severity; limitations; remediation guidance; and baseline
relationship.

Cryptalis JSON is canonical because SARIF cannot naturally express the full scenario/control model.
Export source/artifact findings to SARIF 2.1.0, scenarios to JUnit XML for CI, and a human narrative
to Markdown/HTML. SARIF provides artifact locations, baseline state, correlation identifiers, and
property bags; use them without pretending every dynamic observation is a static-analysis result.
See the [SARIF 2.1.0 standard](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html).

## 6. Doctor architecture

Doctor begins as a compiler/reconciler and may evolve into a substantial Python SAST research
engine. The immediate product value is Cryptalis-specific precision; the complete learning value
includes parser/semantic IR, symbols, CFG, call graph, data flow, taint analysis and a rule engine.
Its staged architecture is defined in the
[learning-first philosophy](learning-first-research-philosophy.md#11-doctor-complete-architecture).

### 6.1 Phases

1. Load and schema-validate the manifest; compute its digest and compiler version.
2. Resolve SQLAlchemy mappings, inheritance, composites, hybrids, synonyms, events, types, sessions,
   engines, sync/async variants, and protected field paths.
3. Compile the expected physical schema, constraints, index domains, envelope versions, and key
   domains.
4. Snapshot the actual database catalog and compare expected versus observed state.
5. Inventory and analyze the Alembic revision graph and generated operations.
6. Parse configured source roots into a pinned CPython AST plus a stable Cryptalis syntax IR.
7. Build scopes/symbols/qualified names, then progressively CFG, call, data-flow and taint layers.
8. Evaluate structural, semantic, query and source-to-sink rules with path explanations.
9. Merge opt-in runtime traces from representative tests.
10. Query provider and deployment adapters for point-in-time operational facts.
11. Build the protection graph and enumerate unsupported, unobserved, or conflicting paths.
12. Emit findings, a coverage statement, and a machine-readable evidence bundle.

### 6.2 Truth taxonomy

Doctor must label how each conclusion was obtained:

| Source | What can be said exactly | What cannot be claimed |
|---|---|---|
| Manifest compiler | Declaration validity and deterministic expected output for a pinned compiler | That applications obey the declaration |
| SQLAlchemy mapper inspection | Registered mapping structure at inspection time | Every dynamic mapping or future execution path |
| PostgreSQL catalog snapshot | Observed physical schema and selected metadata at one time | Historical correctness or unobserved replicas/backups |
| Alembic graph | Included revisions, ancestry, operations that can be parsed, manifest bindings | Safe deployability; Alembic itself says autogenerate requires manual review |
| AST analysis | A syntactic or modeled flow in scanned source | Runtime reachability, reflective code, generated code, unknown libraries |
| Runtime trace | Exact behavior observed for executed tests | Safety of unexecuted paths |
| Provider API | Provider-reported state at a timestamp | Absence of exported copies, erased RAM, or stronger guarantees than provider semantics |
| Deployment collector | Observed config/image/network state | The state of omitted clusters, hosts, or control planes |

SQLAlchemy's `do_orm_execute` intercepts ORM statements through `Session.execute`, while flush
validation belongs in `before_flush`; Core connections, direct drivers, bulk paths, nested execution,
and external writers create different visibility. Doctor must maintain an explicit compatibility
catalogue rather than say “all SQLAlchemy writes.” See
[SQLAlchemy session events](https://docs.sqlalchemy.org/en/20/orm/session_events.html) and
[ORM bulk DML](https://docs.sqlalchemy.org/en/20/orm/queryguide/dml.html).

Alembic's plugin API supports custom operations, implementations, comparators, and autogenerate
extensions, but its documentation explicitly says autogenerated migrations are not perfect and need
manual review. Doctor can validate intent and graph consistency; it cannot certify a production
migration as safe. See [Alembic plugins](https://alembic.sqlalchemy.org/en/latest/api/plugins.html)
and [autogeneration](https://alembic.sqlalchemy.org/en/latest/autogenerate.html).

### 6.3 Cryptalis-specific static rule families

- Protected logical values reaching logging, tracing, metrics labels, exception, serialization,
  file, clipboard, analytics, message, or subprocess sinks.
- Raw SQL, `text()`, direct-driver calls, bulk mappings, Core DML, copy/import, ETL, and maintenance
  jobs touching protected logical or physical columns.
- Direct writes to ciphertext, blind-index, subject, generation, tombstone, or manifest-binding
  columns.
- Reads that expose physical protected columns or envelopes through APIs and admin tools.
- Missing protected-session context, uncontrolled reveal/decrypt calls, disabled strict guards, or
  broad exception fallback to plaintext.
- Migration operations that copy protected columns to plaintext, omit companion indexes, change AAD
  identity, drop evidence prematurely, or allow unsafe downgrade.
- Key/provider configuration that enables export/plaintext backup, omits audit, expands IAM, uses
  weak cache bounds, or conflates disable, schedule-destroy, destroy, and shred.
- Deployment manifests that place production credentials or networks in the pentest profile.

Cryptalis should first implement narrow syntax and local semantic rules it can explain, then use the
same fixture corpus to learn CFG, function-summary, interprocedural and taint analysis. It should
also emit CodeQL model/query packs and Semgrep rules and import their results for differential
comparison.
CodeQL supports Python path queries and custom library models; Semgrep Community Edition's ordinary
taint analysis is not equivalent to its proprietary cross-file analysis, and its maintained-rule
licensing/output history creates product risk. See
[CodeQL Python data flow](https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-python/),
[custom models](https://codeql.github.com/docs/codeql-language-guides/customizing-library-models-for-python/),
and [Semgrep rule glossary](https://semgrep.dev/docs/writing-rules/glossary).

### 6.4 Doctor checks beyond source

**Schema and migration:** nullability, constraints, plaintext remnants, shadow columns, index
domains, old envelope versions, orphaned companions, revision binding, expand/backfill/cutover state,
resume cursor, rollback feasibility, downgrade consequences, mixed-version readers/writers, and
manifest drift.

**Keys and providers:** provider identity and region, key purpose and algorithm, enabled/disabled
state, version/rotation history, pending destruction and restoration window, grants/IAM, audit
coverage, exportability, plaintext backup allowance, cache TTL/capacity/epoch, stale worker leases,
wrapped-key inventory, tombstones, and dependency health.

**Application behavior:** startup validation, strict-mode enforcement, sync/async parity, serializer
and admin interfaces, exception redaction, audit completeness, raw/bulk registration, background
workers, restore tooling, and controlled-access identity.

**Deployment:** image digest and provenance, dependency/container findings imported from mature
tools, secret mounts, database TLS, service accounts, network exposure, pentest-profile isolation,
backups/replicas/exports, clock synchronization, audit sinks, and collector reachability.

### 6.5 Writer provenance as an active differentiator

Static inspection cannot enumerate every writer. A stronger design inventories writer identities
from deployment declarations, migration jobs, SQLAlchemy runtime traces, PostgreSQL
`application_name`, connection identities, and query fingerprints. The output is not “all writers
are safe”; it is a ledger of registered, observed, unregistered, and unknown writers per protected
physical asset. This may become more valuable than adding more syntax rules.

### 6.6 Query/Search Doctor and minimum-leakage planner

For every protected field, Doctor should compare declared capabilities with statically observed and
runtime-observed operations: equality, `IN`, uniqueness, joins, grouping, ordering, range, prefix,
substring, fuzzy search, aggregates, pattern matching, JSON paths, casts, functions, collation, and
raw predicates. It then reports one of: supported as declared; declared but unobserved; observed but
undeclared; unsupported and fail-loud; or unknown because the expression escaped modeling.

The minimum-leakage planner proposes the smallest representation that satisfies evidenced query
needs. It never edits the manifest. No observed query means randomized ciphertext only. Equality
needs may justify a domain-separated blind index; scoped uniqueness needs an explicit tenant/domain
decision. Range, text, fuzzy, JSON, joins, grouping, and cross-field indexes trigger research or
external-primitive gates rather than automatic enablement. Recommendations include frequency,
access-pattern, ordering, token, cross-column, subject-deletion, migration, storage, and inference
consequences. Low-entropy domains receive a prominent dictionary-attack warning even when HMAC keys
remain secret.

Static observations are hypotheses; runtime observations are bounded samples. Conflicts are shown
to the developer, not silently resolved by choosing the more permissive representation.

### 6.7 Data classification and policy-as-code boundary

Classification gives impact context: sensitivity, tenant/subject scope, retention, regulated-data
tags, allowed exposure classes, required collectors, and lifecycle policy. It must not become an
enterprise discovery engine. Cryptalis accepts explicit manifest classifications and may import
classifications from external catalogs; it does not infer regulatory status from column names.

Policy-as-code is likewise narrow. Versioned assurance policy may define required Doctor checks,
allowed unknowns, supported tool/profile versions, collector requirements, result gates, evidence
retention/redaction, and environment-specific exceptions with owner and expiry. It cannot define
general application authorization, WAF behavior, or provider IAM. Policy evaluation never converts
`INCONCLUSIVE` to `PASS`, and exceptions remain visible in reports.

## 7. Pentesting harness

The harness answers whether an attacker can reach and expose protected assets, not whether the app
has no vulnerabilities. It uses a hybrid architecture: mature engines remain quarantined adapters,
while an internal endpoint graph, crawler, authentication/state model, mutator, payload/oracle and
replay engine may grow progressively inside the lab/research boundary.

### 7.1 Profiles

| Profile | Default | Engines/actions | Safety |
|---|---|---|---|
| `passive` | Yes | ZAP passive/baseline, manifest-aware response checks | No state-changing scanner actions |
| `active-safe` | No | Authenticated ZAP active rules selected for the reference app | Disposable target, budgets, pinned scope |
| `api` | No | ZAP/Burp OpenAPI-driven scanning and deterministic API misuse | Synthetic identities and data only |
| `sqli-exposure` | No | Selected ZAP/Burp finding followed by constrained sqlmap marker extraction | Destructive token, disposable DB, exact columns, low risk/level |
| `boundary` | No | Cryptalis scenarios for raw/bulk/direct DB/cross-tenant/relocation | Reference harness only |
| `lifecycle-chaos` | No | Provider outage, stale cache, worker partition, revocation/shred/restore | Local/provider emulator unless explicitly authorized |

sqlmap's risk levels can enable heavy time-based and OR-based payloads; the latter can update many
rows in some contexts. It must never be a routine CI step. Use its API/reporting only after a
specific confirmed injection, limit extraction to uniquely seeded marker columns, and destroy the
environment afterward. See [sqlmap usage](https://github.com/sqlmapproject/sqlmap/wiki/usage) and
[REST API schema](https://github.com/sqlmapproject/sqlmap/blob/master/sqlmapapi.yaml).

### 7.2 Scenario catalogue

The minimum serious catalogue is:

- SQL injection reaches the application database and attempts protected and unprotected extraction.
- Stolen database credentials query tables, companion indexes, key metadata, backups, and views.
- Raw SQL, Core DML, bulk mappings, direct driver, COPY/ETL, maintenance script, and migration paths
  attempt plaintext persistence.
- Cross-tenant subject/key/index confusion and authorization-context substitution.
- Ciphertext relocation across row, column, table, tenant, and subject AAD domains.
- Envelope truncation, version confusion, tag corruption, unknown key, revoked generation, and
  rollback to older ciphertext.
- Equality-index tampering, ciphertext/index mismatch, normalization disagreement, low-entropy
  dictionary inference, and stale-index migration.
- Provider unavailable, throttled, permission-revoked, wrong-region, wrong-key, or audit-disabled.
- Cache expiry, cache epoch fencing, stale worker, process partition, retry storm, and restart.
- Expand/backfill/dual-read/dual-write/cutover/contract failures with retries and mixed app versions.
- Shred initiated, key disabled, destruction pending, destruction restored, wrapped-key restore,
  backup restore, stale cache use, and tombstone enforcement.
- Plaintext canaries passed through response, error, log, trace, metrics, job queue, report, export,
  crash dump, temporary file, and database collector paths.
- Audit record mutation, truncation, reordering, checkpoint substitution, and missing sink.

Do not turn every scenario into an exploit. Many are deterministic state-machine tests with stronger
causal evidence than a generic scanner alert.

### 7.3 Template-driven testing

Use a typed, versioned internal scenario interface while actively researching a declarative format
that expresses only bounded data actions, assertions, collector requirements, cleanup, and resource
budgets. It
must not embed arbitrary shell or Python. Third-party packs need schema/version compatibility,
content digests, signatures, declared privileges, and an allowlist. Nuclei remains the comparison
and import ecosystem; independently implementing a narrower protection-aware template compiler is
a valid learning track. See
[Nuclei templates](https://docs.projectdiscovery.io/templates/introduction) and
[template signing](https://docs.projectdiscovery.io/templates/reference/template-signing).

## 8. Verify and the exposure oracle

`verify` is the Cryptalis-owned deterministic layer. It should run without a generic DAST engine and
must be useful during ordinary development.

### 8.1 What Verify checks

- Manifest, model, schema, envelope, and migration bindings agree.
- Protected writes produce valid envelopes and required companion indexes.
- Reads, query rewrites, normalization, tenant/subject scoping, and fail-loud paths behave as
  declared.
- Known unsupported ORM/Core/raw/bulk operations are rejected or explicitly registered.
- Tamper, relocation, cross-context and stale-generation attempts fail as designed.
- Rotation and rewrap preserve decryptability for intended generations.
- Revocation/cache fencing stops newly unauthorized work within the declared bound.
- Shredding state, provider state, tombstone behavior, cache leases, restore behavior, and data-path
  failures are reported independently.
- Synthetic plaintext markers do not appear in required collectors after each scenario.
- The harness can detect seeded leakage and intentionally weakened controls.

### 8.2 Exposure is an observation, not a global fact

The exposure oracle generates unique high-entropy synthetic values with field, tenant, subject, run,
and scenario identity. It searches only registered evidence stores. “No plaintext observed” means
the marker was absent from healthy covered collectors during a bounded interval. It never means the
plaintext existed nowhere.

Direct database and artifact inspection is stronger than packet inference. For encrypted traffic,
passive PCAP reveals endpoints, timing, sizes, TLS metadata, and sometimes DNS—not HTTP or database
plaintext. TShark can emit stable JSON/EK/field output; Zeek offers useful TLS/flow logs. TLS session
secrets may be used only inside a controlled lab, kept outside the evidence bundle, and destroyed
after derivation of redacted observations. Avoid PyShark as a core dependency because it is a thin
wrapper around TShark with constrained maintenance capacity. See
[TShark](https://www.wireshark.org/docs/man-pages/tshark),
[Wireshark TLS](https://wiki.wireshark.org/TLS), and
[Zeek SSL/TLS logs](https://docs.zeek.org/en/current/reference/logs/ssl.html).

### 8.3 Positive, negative, and mutant controls

A passing run requires:

1. A positive collector control: a seeded marker in each collector is found.
2. A negative control: an absent marker is not falsely reported.
3. A protection mutant: a narrow intentionally weakened control causes the expected scenario to
   fail, for example plaintext persistence, disabled relocation binding, stale-cache acceptance, or
   index mismatch.
4. A restored control: the normal protected configuration passes under the same workload.

This “assurance of the assurance suite” is a high-value missed capability. General mutation tools
such as mutmut can measure test quality, but Cryptalis should own only a small catalog of semantic
control mutants. A detector that cannot kill its corresponding mutant is not ready to support a
security claim.

### 8.4 Security invariants

The suite should name stable invariants independently of individual tools:

- A registered protected value is never persisted as plaintext through a supported write path.
- Unsupported write/query paths fail loudly or remain an explicit uncovered path.
- Envelopes authenticate their declared tenant, subject, table, field, record and version context.
- Search representations exist only for declared capabilities and use separate key/domain material.
- Key/provider calls do not occur in synchronous scalar ORM processors or hidden attribute access.
- Revoked or shredded generations cannot be newly loaded after the declared fencing deadline.
- Tombstones prevent restored wrapped keys or ciphertext from silently resurrecting access.
- Migration phases preserve a documented reader/writer compatibility window and never claim
  completion while plaintext or inconsistent companion artifacts remain.
- Required audit/evidence records are redacted, attributable, ordered and integrity-checkable.
- A pass requires healthy collectors and a working positive, negative and mutant control.

Each invariant has prevention checks, one or more adversarial scenarios, required collectors, and a
defined inconclusive state. Scanner rule counts are not invariants.

## 9. Key lifecycle and crypto-shredding verification

Provider differences are facts, not adapter noise:

- AWS KMS automatic rotation retains old key material for decryption; imported material can be
  deleted and, if a copy still exists, reimported. Hierarchical keyrings add branch-key cache TTL
  and capacity semantics. See [rotation](https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html),
  [imported material deletion](https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys-delete-key-material.html),
  and [hierarchical keyrings](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/use-hierarchical-keyring.html).
- Google Cloud KMS schedules destruction with a restoration window by default and warns that
  destruction cannot guarantee a version is unused. See
  [destroy and restore](https://docs.cloud.google.com/kms/docs/destroy-restore).
- Vault Transit supports derived/convergent keys, rotation, and deletion, but exportability and
  plaintext backup are irreversible configuration choices once enabled; deletion requires an
  explicit setting. Vault audit devices are disabled by default and need resilient configuration.
  See [Transit](https://developer.hashicorp.com/vault/docs/secrets/transit) and
  [audit best practices](https://developer.hashicorp.com/vault/docs/audit/best-practices).

A shredding verification report must keep these observations separate:

1. Cryptalis lifecycle state and tombstone.
2. Wrapped-key inventory and deletion state.
3. Provider-reported key/material state and timestamp.
4. Active cache leases and worker acknowledgements.
5. Decrypt attempts from fresh and deliberately stale processes.
6. Restore/reimport/resurrection trial results.
7. Search-index and derived-artifact treatment.
8. Unmanaged backup/export/log caveats.

Only the combination supports a bounded technical erasure claim. No provider API proves that no
exported copy or process-memory copy exists.

## 10. Migration, deployment, and configuration verification

### 10.1 Migration stages

For expand/backfill/verify/cutover/contract, evidence should include the manifest and revision
digests, source/target schemas, row counts, cursors, retry identities, batch failures, plaintext
residue, envelope/index consistency, app version compatibility, lock/time budgets, rollback plan,
and downgrade consequences. Inject interruption at every stage. Resume must be idempotent and
evidence must distinguish rows never attempted from rows verified.

Comparing a migration file to the current manifest is insufficient. Doctor must compare the whole
revision path, the manifest version expected by each app release, and the actual database phase.

### 10.2 Deployment checks

Cryptalis should define manifest-aware deployment assertions and import generic evidence from mature
tools. Trivy covers vulnerabilities, secrets, licenses, and many IaC formats, but Docker Compose
coverage is not complete; Grype provides vulnerability/VEX workflows; Gitleaks provides secret
finding, baselines, redaction, and SARIF. Use these limits explicitly. See
[Trivy misconfiguration scanning](https://www.trivy.dev/docs/latest/guide/scanner/misconfiguration/),
[Trivy reporting](https://www.trivy.dev/docs/latest/configuration/reporting/),
[Grype](https://oss.anchore.com/docs/guides/vulnerability/getting-started/), and
[Gitleaks](https://github.com/gitleaks/gitleaks/blob/master/README.md).

Deployment-specific Doctor findings should focus on causal threats to Cryptalis: KMS permissions,
audit absence, provider egress, unencrypted DB transport, exposed DB/metrics/admin ports, shared
pentest credentials, writable evidence stores, mutable scanner tags, backup locations, missing
tombstone replication, and unsynchronized clocks. Generic image CVEs remain imported findings unless
they create a concrete path to a protected boundary.

## 11. Correlation and attack-impact proof

Correlation is conservative. Join observations only with explicit identifiers: run, target,
scenario, synthetic marker, manifest digest, asset ID, request/trace ID, database transaction, and
artifact hash. Time proximity alone may suggest a relationship but cannot establish it.

Example outcome:

```text
ZAP: SQL injection confirmed
  -> request/trace ID and seeded subject
  -> PostgreSQL audit/query observation: protected physical columns selected
  -> extraction artifact: envelope bytes and equality terms present
  -> exposure oracle: no plaintext marker in DB/response/log collectors
  -> Cryptalis control: held for DB-compromise boundary
  -> application control: failed; confidentiality still degraded by metadata/index disclosure
```

The inverse is equally important: a scanner may find nothing while a deterministic raw/bulk writer
persists plaintext. The report must show “DAST found no issue” beside “Cryptalis invariant failed,”
not average them into a score.

## 12. Safety architecture

Localhost or RFC1918 addressing is not sufficient; redirects, proxies, DNS rebinding, port forwards,
and shared networks can escape intent. Active profiles require all of:

- An authorization manifest naming owner, purpose, permitted target identities, time window,
  engines, profiles, data class, request/time/resource budgets, and cleanup owner.
- A target-issued ephemeral lab token and deployment/image digest.
- DNS resolution and IP pinning at start, with redirect and secondary-host denial outside scope.
- A disposable-environment sentinel for destructive profiles.
- Synthetic marker namespaces; no copied production data.
- Dedicated low-privilege credentials and egress-denied network isolation.
- Rate, concurrency, request, response-size, database-row and total-time caps.
- Pinned scanner images by digest and recorded tool/template/rule versions.
- A kill switch, cleanup phase, and explicit incomplete-cleanup result.
- Production package/import boundaries that exclude scanners, payloads, TLS secrets, and lab
  credentials.

The CLI must require an additional destructive authorization token for sqlmap extraction,
shred/restore chaos, and write-capable scenarios. CI defaults to passive Doctor/Verify work only.

## 13. Evidence integrity, reporting, and reproducibility

An evidence bundle contains:

- canonical result JSON and schema version;
- manifest, model inventory, compiled schema and migration graph digests;
- source revision and dirty-state declaration;
- target identity, image digests, database/provider/deployment fingerprints;
- authorization manifest and safety budgets;
- tool images, versions, rules/templates, configs, seeds and command descriptors;
- collector inventory, health checks, clocks, redactions and limitations;
- immutable artifact hashes and relationships;
- cleanup outcome; and
- generated SARIF, JUnit, Markdown/HTML and comparison views.

Wrap the bundle manifest in an in-toto Statement/DSSE envelope or a Sigstore blob-signing bundle
when provenance matters. This proves the identified producer signed a particular bundle and may
provide transparency-log evidence; it does not prove the collectors were truthful or the target was
independent. See [in-toto Statement](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md),
[DSSE envelope](https://github.com/in-toto/attestation/blob/main/spec/v1/envelope.md), and
[Sigstore blob signing](https://docs.sigstore.dev/cosign/signing/signing_with_blobs/).

Reports need three views:

1. **Developer:** exact field/path, source/schema location, reproduction, and remediation.
2. **Security reviewer:** attack chain, control outcome, exposure class, evidence provenance,
   coverage gaps, and limitations.
3. **Operator/auditor:** manifest/release/target identity, lifecycle/provider state, migration phase,
   signed bundle, and comparison against an approved baseline.

Never emit raw plaintext markers, credentials, key material, TLS session secrets, complete database
dumps, or unrestricted scanner payloads into the evidence bundle. Redaction itself is recorded.

## 14. CI, pytest, fuzzing, and stateful testing

Recommended command surface:

```text
cryptalis doctor [--static | --schema | --provider | --deployment]
cryptalis plan
cryptalis verify [--profile PROFILE]
cryptalis pentest --profile PROFILE --authorization FILE
cryptalis evidence inspect|compare|attest
cryptalis check --ci
```

Keep `pentest` conspicuously separate because it is dangerous. `check --ci` should run a fast
manifest/model/schema Doctor subset and deterministic Verify scenarios; it must not silently launch
active DAST. Avoid a large `security scan/report/policy/baseline` namespace that hides which engine
and risk profile is operating.

A pytest plugin can register markers/fixtures, collect runtime paths, associate requests and SQL,
seed exposure markers, require collectors, and attach evidence. Pytest's plugin/hook model is mature,
but coverage claims remain limited to executed tests. See
[pytest plugin guidance](https://docs.pytest.org/en/latest/how-to/writing_plugins.html).

Hypothesis state machines are well suited to envelope parsing, normalization, query rewriting,
migration phases, key generations, cache epochs, and lifecycle fault sequences. Seeds and minimized
counterexamples belong in the bundle. See
[Hypothesis stateful testing](https://hypothesis.readthedocs.io/en/latest/stateful.html) and
[failure replay](https://hypothesis.readthedocs.io/en/latest/tutorial/replaying-failures.html).

### 14.1 Continuous security regression

Pin manifest, compiler, app revision, database schema, tool images, rules/templates and scenario
seeds. Compare results by stable identity and show new, resolved, unchanged, regressed, and
reclassified findings. A baseline is an accepted observation set, not an allowlist that hides
failures. Exceptions require owner, reason and expiry; changed evidence requirements invalidate the
old baseline. Fast pull-request gates run Doctor and deterministic Verify subsets. Scheduled local
or isolated jobs may run active DAST and lifecycle chaos. Release gates require the full supported
compatibility corpus and evidence-schema migration checks.

## 15. Benchmarks and evaluation

The suite needs a labeled corpus, not a demo narrative.

### 15.1 Static/Doctor corpus

Create safe and unsafe fixtures for every rule family across supported SQLAlchemy styles, sync/async,
inheritance, Core/raw/bulk paths, migration operations, serializers, background jobs, and provider
configuration. Measure precision and recall per rule family, unknown-rate, analysis time, and
version-to-version stability. Publish unsupported constructs.

### 15.2 Dynamic corpus

For each scenario measure execution determinism, mutation kill rate, collector health, evidence
completeness, false exposure/absence decisions, runtime overhead, and replay success. Compare:

1. Baseline app with plaintext storage.
2. Protected app with normal controls.
3. Protected app with one known control mutant.
4. Protected app with missing/unhealthy collector.

The benchmark win is not “fewer vulnerabilities.” It is accurate classification of what the same
successful attack exposed in each configuration.

### 15.3 Tool comparisons

- Compare Cryptalis local rules with CodeQL/Semgrep only on the same labeled semantic paths.
- Compare ZAP and Burp on generic detection and authenticated crawl coverage, not on Cryptalis
  protection semantics.
- Compare Nmap/TShark/Zeek on observation fidelity and overhead, not a synthetic “security score.”
- Compare Doctor status/migration UX against current CipherStash workflows.
- Compare Acra operational controls honestly; document where Cryptalis has no equivalent.

## 16. Academic integration and complete assurance scope

The IS-Lab requirement is satisfied by a quarantined reference environment that demonstrates web
pentesting techniques and then measures data-protection impact. Course payloads and intentionally
vulnerable code never enter the production package. ZAP is sufficient to satisfy the mandatory
open-tool requirement. sqlmap, PCAP/TShark/Zeek, Nmap,
internal DAST and other integrations remain active Cryptalis workstreams even when the course rubric
does not require every one of them.

### 16.1 Reference Docker lab

The reference lab should contain pinned, isolated services for the baseline and protected app, a
synthetic PostgreSQL database, local key-provider emulator, ZAP, optional attack tools, collectors,
and an evidence builder. Baseline and protected deployments use the same application revision,
routes, fixtures, identities and attack seeds; only the protection configuration/schema differ.
Networks separate attacker, application, database/provider and evidence roles, with egress denied.
Volumes are disposable except the redacted result bundle. Health checks prove target and collector
identity before a run, and cleanup is itself an evidenced phase.

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
12. Internal endpoint discovery, crawler/authentication/state modeling, mutation, payload, oracle,
    minimization and replay engines.
13. Provider-cloud chaos, signed attestations, writer provenance, managed-backup and cross-cluster
    restore drills, and attack/protection graph planning.

### 16.3 Solo flat assurance program

One person owns every assurance workstream. Doctor, Pentest, Verify, the protection graph, exposure
collectors, tool adapters, internal SAST/DAST, networking and lifecycle-chaos research may advance
concurrently. Scenario IDs, evidence schema, test vectors, marker policy and safety contracts are
versioned so partially mature workstreams can interoperate without pretending to share the same
evidence level. Manual implementation remains one file and one explainable invariant at a time.

## 17. Flat workstream map

Every workstream below is active. The labels group responsibilities; they are not sequential phases
or permission gates. Each result records its own evidence maturity and dependencies.

### Workstream A — Falsify the premise

Define the graph/result schemas, label a fixture corpus, run baseline and protected scenarios, and
verify that correlation adds information unavailable from source tools. Interview maintainers and
security reviewers about whether first-party evidence is useful while engine experiments proceed.

### Workstream B — Core developer assurance

Manifest/model/schema/migration Doctor; exactness labels; precise AST rules plus advanced semantic
analysis research; PostgreSQL/HTTP/log exposure collectors; deterministic Verify; controls/mutants;
JSON/JUnit/Markdown; CI fast path.

### Workstream C — Quarantined attack harness

ZAP authenticated/OpenAPI adapter, attack-to-asset correlation, reference vulnerable app, strict
authorization, pinned images, resource budgets and cleanup evidence.

### Workstream D — Lifecycle and operations depth

Provider-specific facts, cache fencing, stale workers, shred/restore, migration interruption,
deployment findings, writer provenance and signed evidence bundles.

### Workstream E — Internal SAST/DAST and network depth

Stable syntax/semantic IR, symbols, CFG, local data flow, rule engine, endpoint/state graph, request
mutators, response/exposure oracles, deterministic replay, PCAP/flow correlation and differential
comparison with CodeQL/Semgrep/ZAP/Burp.

### Workstream F — Advanced research ecosystem

Interprocedural taint and framework summaries; signed rule/scenario packs; Acra-like SQL
policy/honeytoken experiments; managed-backup drills; Nuclei/sqlmap/Trivy/Nmap/TShark/Zeek depth;
and broader attack-graph planning.

Every workstream requires precision/recall, determinism, mutation-kill, evidence-completeness and
safety thresholds defined before its results support stronger claims. Feature count is not a
maturity criterion.

## 18. Open research questions

1. Can a protection graph remain stable across SQLAlchemy mapper and Alembic revisions?
2. Which raw/Core/bulk paths can be rejected reliably, and which must remain declared gaps?
3. Can source-to-runtime-to-database correlation work without invasive application instrumentation?
4. How can background jobs and non-Python writers authenticate provenance?
5. What exact collector set is sufficient for a bounded “no plaintext observed” result?
6. How should search-index metadata exposure be ranked for low-entropy fields?
7. Can restore/resurrection tests be portable without erasing provider-specific meaning?
8. What independently verifiable part of first-party evidence is valuable to an assessor?
9. Can control mutants remain safe, deterministic, and representative rather than theatrical?
10. What false-positive rate will developers tolerate for protected-value sink analysis?
11. Does the reference app exercise enough SQLAlchemy behavior to predict real adoption cost?
12. Are teams willing to register external writers, evidence stores, backups, and collectors?

## 19. Fatal risks and stop rules

- **Trust conflict:** Cryptalis grades Cryptalis. Mitigation is transparent artifacts, controls,
  replay, and optional signatures—not a claim of independence.
- **Coverage illusion:** a polished dashboard may conceal unobserved writers or collectors. Unknowns
  must be first-class and must block pass results where relevant.
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

Stop or demote the product claim if the correlation-premise experiment cannot show materially better protected-asset
impact classification than ZAP/source-tool output plus a human database inspection.

### 19.1 Risk register by ownership

| Class | Top risks |
|---|---|
| Technical | SQLAlchemy visibility gaps; source/runtime correlation ambiguity; provider/restore non-portability; flaky active scans; evidence-schema evolution |
| Security | Destructive execution escapes scope; evidence stores plaintext/secrets; stale keys survive claimed shredding; malicious templates/tools; the suite's own control is trusted circularly |
| Maintenance | Scanner/template churn; SQLAlchemy/Alembic compatibility matrix; provider API changes; duplicated generic-tool logic; long-lived scenario corpus and fixtures |
| Adoption | False positives; setup/collector burden; fear of active testing; first-party evidence rejected by assessors; a field-encryption library is good enough |

Reasons not to build remain substantive: the suite may be less useful than investing the same effort
in migration safety; ZAP plus a human database check may suffice for the target users; independent
pentesters may be preferred; Acra/CipherStash may close the semantic gap; and one maintainer may not
sustain protection, lifecycle, compatibility, static analysis, pentesting and assurance
simultaneously.

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

The strongest demo is intentionally uncomfortable: show the same exploitable application in
plaintext, protected, and mutated configurations; let the attack succeed; then show precisely what
changed in the database and evidence stores, which controls held, which metadata still leaked, and
what the suite could not observe.

### 20.1 Value outside the university and research contribution

A developer would use the suite to catch concrete retrofit failures before deployment, decide
whether a searchable representation is justified, reproduce a protection regression in pytest/CI,
and hand a reviewer a bounded evidence bundle. An operator would use it to reconcile manifest,
schema, migration, provider and cache state. A security reviewer would use it to distinguish a
successful exploit from the protected-data impact of that exploit. Those workflows exist outside
the course only if setup is materially cheaper than an ad hoc review.

The plausible research contribution is not a new attack or cryptographic primitive. It is an
evaluated model for correlating ORM/schema/key-lifecycle semantics with multi-source attack and
exposure evidence, including explicit unknowns and detector mutants. The contribution must be
supported by a labeled corpus, protected/baseline/mutant experiments, precision/recall,
reproducibility, and published limitations.

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

All vendor claims are documented capability, not independently reproduced performance. Re-run this
review before public positioning because product and tool behavior changes quickly.

## Appendix A. Required deliverable coverage

This map makes the original 62-part brief auditable. A row points to the section that owns the
decision; it does not imply that a feature has been implemented.

| # | Required topic | Owning section |
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
| 10 | Query/Search Doctor | 6.6 |
| 11 | Minimum-leakage analysis | 6.6 |
| 12 | Schema/Alembic Doctor | 6.2, 6.4, 10 |
| 13 | Key/KMS Doctor | 6.4, 9 |
| 14 | Shredding Doctor | 6.4, 9 |
| 15 | Application-security Doctor | 6.3–6.4 |
| 16 | Secret/logging analysis | 6.3–6.4 |
| 17 | Deployment Doctor | 6.4, 10.2 |
| 18 | Dependency/security-tool integration | 2.2, 3.2, 10.2 |
| 19 | Pentesting architecture | 7 |
| 20 | Web attack suite | 7.1–7.2 |
| 21 | Database compromise tests | 7.2 |
| 22 | ORM/raw SQL bypass tests | 6.3, 7.2 |
| 23 | Ciphertext tampering tests | 7.2, 8.1 |
| 24 | Searchable-encryption adversarial tests | 6.6, 7.2 |
| 25 | Key lifecycle tests | 7.2, 9 |
| 26 | Shredding adversarial tests | 7.2, 9 |
| 27 | Migration security tests | 7.2, 10.1 |
| 28 | Plaintext leakage tests | 7.2, 8.2 |
| 29 | PyShark/traffic analysis | 8.2 |
| 30 | PCAP analysis | 8.2 |
| 31 | Nmap integration | 2.2, 3.2 |
| 32 | ZAP/Burp/sqlmap/Nuclei integration | 2.2, 3.2, 7.1–7.3 |
| 33 | Template-driven testing | 7.3 |
| 34 | Doctor-to-Pentest correlation | 4, 11 |
| 35 | Evidence/confidence model | 5 |
| 36 | Security invariants | 8.4 |
| 37 | Fuzzing/property tests | 14 |
| 38 | Unified reporting | 5, 13 |
| 39 | Severity model | 5.2 |
| 40 | CI/CD integration | 14 |
| 41 | Pytest integration | 14 |
| 42 | Security regression workflow | 14.1 |
| 43 | Safe execution model | 12 |
| 44 | Reference Docker lab | 16.1 |
| 45 | IS-Lab compliance | 16 |
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
| 60 | Final CLI/API | 14 |
| 61 | Final architecture diagram | 4 |
| 62 | Final positioning statement | 20 |
