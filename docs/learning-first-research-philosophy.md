# Cryptalis Learning-First Research Philosophy and Complete Architecture

Status: Governing research direction; documentation only

Last reviewed: 2026-08-22

This document changes how Cryptalis evaluates scope. The project remains technically rigorous and
security-critical, but competitor overlap is no longer a veto. Cryptalis is both a serious
data-security system and a complete vehicle for learning cryptography, databases, ORM internals,
compilers, static analysis, pentesting, networking, distributed systems, and production security
engineering.

## 1. Revised Cryptalis philosophy

The primary decision question is:

> Will building this capability teach deep, useful, technically challenging, and transferable
> security or systems knowledge, and can its correctness and limitations be evaluated honestly?

Novelty and market differentiation remain useful evidence, but they are secondary. A competitor
already implementing a feature may validate its technical value and provide a reference system. It
is acceptable for Cryptalis to reproduce a known architecture independently, integrate it, or do
both in different phases.

Every major capability is evaluated on:

1. learning value;
2. fit with the coherent Cryptalis system;
3. security and correctness risk;
4. testability;
5. achievable depth;
6. solo feasibility and workstream dependencies;
7. sustained maintenance interest;
8. production usefulness; and
9. prior art and claim discipline.

The goal is comprehension through construction, not artificial novelty. The project should be
explainable down to its algorithms, trust boundaries, failure modes, evidence, and tradeoffs.

## 2. What changes from previous research

Previous research correctly emphasized scope, safety, mature tools, and falsifiable claims, but it
overweighted whether an existing product already solved a problem. The revised position is:

- Competitor parity may be a valid learning target.
- Reimplementation may be worthwhile even when integration is easier.
- Doctor may grow from bounded Cryptalis linting into a substantial Python SAST research engine.
- Pentest may grow from orchestration into an internally understood DAST/adversarial framework.
- Search may extend beyond equality into joins, grouping, range/order, text, and structured data
  after construction-specific research gates.
- Network analysis may become a first-class learning track rather than only corroborating evidence.
- The full architecture is multi-year and remains the active scope from the beginning. Course dates
  may define evidence checkpoints, but they do not remove or defer entire capability families.

What does not change:

- no unsupported production-security claims;
- no casual invention of cryptographic primitives;
- explicit threat models and leakage analysis;
- known vectors, differential tests, benchmarks, and independent comparison;
- production and educational implementations are labeled and isolated;
- destructive testing requires authorization and containment; and
- incoherent, untestable, low-learning-value features can still be rejected.

## 3. Features previously rejected mainly because competitors had them

The following deserve reconsideration rather than automatic exclusion:

- broad searchable-encryption capabilities similar to CipherStash;
- proxy-like query rewriting experiments;
- driver-style fail-loud query compatibility inspired by MongoDB;
- SQL firewall, query anomaly, and honeytoken concepts inspired by Acra;
- a general static-analysis intermediate representation, CFG, call graph, data-flow and taint engine;
- a declarative security-rule language;
- crawler, endpoint graph, request mutation, payload generation, replay, and response analysis;
- a signed declarative attack-template ecosystem;
- packet/flow ingestion and protocol-aware traffic analysis;
- broader posture and deployment correlations; and
- a general attack graph derived from code, deployment, runtime and protection evidence.

These are now research candidates. They are not promises and do not all belong in one release.

## 4. Features to reconsider

| Capability | New classification | Reason to explore | Required gate |
|---|---|---|---|
| Equijoins/grouping | Research-heavy | Key-domain design, relational semantics, leakage | Threat model, lifecycle design, known-reference comparison |
| Range/order/MIN/MAX | Research-heavy | Order-revealing constructions and query planning | Published construction, external cryptographic review before production use |
| Encrypted text search | Experimental | Tokenization, Bloom/trigram structures, false positives, storage | Leakage and adversarial corpus |
| Searchable JSON | Experimental | Path semantics, schema evolution, structured indexes | Restricted query model and migration plan |
| Doctor CFG/data flow | Active research | Compiler analysis, explainable security paths | Labeled corpus and precision/recall |
| Interprocedural taint | Research-heavy | Call graphs, summaries, async/framework modeling | Soundness strategy and explicit unknowns |
| Internal DAST crawler | Active research | HTTP/session/browser modeling | Differential benchmark against ZAP/Burp |
| Payload engine | Active research | Offensive methodology and mutation design | Disposable lab and safety budgets |
| SQL firewall experiment | Experimental | SQL parsing, policy and database boundary | Must not silently become the production protection boundary |
| Honeytokens | Active research | Detection/evidence correlation | Synthetic-data lifecycle and false-alert study |
| PCAP/protocol engine | Active research | Networking and protocol understanding | TLS limitations and artifact hygiene |

## 5. CipherStash features worth independently implementing or adapting

- Randomized authenticated ciphertext plus separate capability-specific search representations.
- Equality search, `IN`, scoped uniqueness, normalization, domain separation, and rotation windows.
- Equijoin and grouping domains where cross-column equality is explicitly authorized.
- Range/order and aggregate support as isolated research tracks using published constructions.
- Text/prefix/substring search structures with measured leakage, false positives, and amplification.
- Structured/JSON query representations with an intentionally constrained operator model.
- Keysets, tenant isolation, identity-aware key release, cache-aware initialization, and bulk paths.
- Schema validation, encryption migration phases, status/progress, operational metrics, and drift.
- Encrypted query rewriting experiments, including an optional non-production proxy study.

Cryptalis must study the documented construction and threat model, implement independently, compare
behavior and benchmarks, and attribute the prior art. Similarity is acceptable; copying source or
claiming invention is not. Current reference material includes
[CipherStash cryptography](https://cipherstash.com/docs/security/cryptography),
[searchable encryption](https://cipherstash.com/docs/concepts/searchable-encryption), and
[CLI workflows](https://cipherstash.com/docs/stack/cipherstash/cli).

## 6. Acra features worth implementing or studying

- SQL allow/deny firewall semantics and query-shape policy.
- Query anomaly reactions and explicit response policy.
- Honeytokens tied to protected assets and evidence correlation.
- Cryptographically integrity-protected audit records and external witnesses.
- Key inventory, rotation visibility, security events, and SIEM export.
- Search and protection deployed at a database-adjacent boundary as a comparison architecture.

The strongest educational approach is not to clone Acra as a product. Build narrow experiments that
teach SQL parsing, anomaly detection, deception, response orchestration, and evidence integrity,
then compare them with Acra's documented controls. See
[Acra security controls](https://docs.cossacklabs.com/acra/security-controls/) and
[SQL firewall](https://docs.cossacklabs.com/acra/security-controls/sql-firewall/).

## 7. MongoDB Queryable Encryption lessons

- Randomized encrypted payloads can coexist with supported query capabilities.
- Queryability requires driver/database protocol cooperation and an explicit operator catalogue.
- Unsupported expressions should fail loudly rather than degrade to plaintext or client-side scans.
- Equality, range, string preview features, index maintenance, schema validation, and migration are
  separate capabilities with separate limitations.
- Compatibility behavior and diagnostic redaction are part of the security design.

Cryptalis should learn from MongoDB's driver-level modeling and test discipline without pretending
that SQLAlchemy offers the same enforcement boundary. See
[Queryable Encryption](https://www.mongodb.com/docs/manual/core/queryable-encryption/) and its
[supported operations](https://www.mongodb.com/docs/v8.0/core/queryable-encryption/reference/supported-operations/).

## 8. SAST concepts worth building ourselves

The Doctor research engine may implement:

- source ingestion and syntax-tree normalization;
- scopes, symbols, imports, qualified-name and limited type resolution;
- control-flow graphs with branch, loop, exception, context-manager, generator and async edges;
- call graph construction with confidence-ranked dynamic-dispatch targets;
- local and global data-flow analysis;
- taint sources, sinks, sanitizers, propagators and path explanations;
- function summaries and bounded interprocedural fixed-point analysis;
- SQL and SQLAlchemy expression discovery;
- manifest/model/schema/key/migration semantic overlays;
- security-rule compilation and evaluation;
- baseline, suppression, provenance, correlation and SARIF output; and
- a labeled benchmark corpus with mutation-based detector validation.

Use CPython's parser/`ast` and `symtable` first rather than writing a Python grammar. Writing a small
parser for the rule language or selected SQL subset has better educational return than maintaining a
complete Python parser. CPython notes that AST shape can change between Python releases; versioned
front ends are required. See [Python `ast`](https://docs.python.org/3/library/ast.html) and
[`symtable`](https://docs.python.org/3/library/symtable.html).

## 9. Pentesting concepts worth building ourselves

- HTTP request/response model and reproducible session store.
- OpenAPI and framework-route import plus same-origin crawling.
- Authentication/session workflows and multi-user role matrices.
- Endpoint and parameter graph, state prerequisites, sequence/replay and cleanup.
- Type-aware mutation, boundary values, encoding, duplicate-parameter and content-type variants.
- SQL injection experiments, error leakage, parameter tampering, IDOR/access control and sensitive
  data exposure.
- Payload families, response-differential oracles, timing controls and confidence calibration.
- Attack planning from templates, preconditions, extracted values and prior observations.
- Evidence capture, minimization, deterministic replay, baseline/protected comparison and
  protection-graph correlation.

Build these incrementally in the reference lab while keeping ZAP/Burp/sqlmap comparisons. An
internal engine is successful when it teaches and produces explainable results, not when its rule
count approaches mature scanners.

## 10. Features better integrated from external tools

Even under a learning-first philosophy, some work is more valuable as integration:

- CodeQL as a reference for mature interprocedural/path-query results.
- Semgrep as a structural/taint rule comparison target.
- ZAP and Burp as DAST/crawler benchmarks and complementary engines.
- sqlmap as the extraction reference after an injection is already confirmed.
- Nuclei as the broad community-template and multi-protocol reference.
- Trivy, Grype, Gitleaks and mature package ecosystems for vulnerability/secrets/SBOM databases.
- Nmap for authoritative service-discovery comparison.
- TShark/Wireshark and Zeek for packet decoding and flow/protocol logs.
- Cloud KMS and Vault for production root custody rather than custom HSM/KMS infrastructure.
- SARIF, JUnit, in-toto/DSSE and Sigstore for interchange and evidence provenance.

Integration and independent construction are not mutually exclusive. Cryptalis can import a CodeQL
path while also using the same fixture to evaluate its own taint engine.

## 11. Doctor complete architecture

```text
source + configs + manifests + models + schema + migrations + traces
                              |
                              v
                      versioned front ends
                              |
                              v
                  semantic analysis workspace
       symbols + types + CFG + calls + data flow + SQL/ORM IR
                              |
                              v
                 Cryptalis semantic overlays
       protected assets + storage + indexes + keys + lifecycle
                              |
                              v
                 rules + path queries + correlation
                              |
                              v
          findings + explanations + coverage + evidence
```

Doctor begins as a manifest/model/schema compiler and grows in replaceable layers. Each finding
records the analyzer version, model assumptions, source-to-sink path, protected asset, confidence,
unknown edges and evidence basis. A syntactic match, static path and observed runtime path remain
distinct.

## 12. AST/parser architecture

1. Parse with the pinned CPython AST front end.
2. Preserve source spans, comments/suppressions through tokens or an optional concrete-syntax layer.
3. Generate a stable Cryptalis syntax IR so Python-version changes do not infect every rule.
4. Build module/import indexes and CPython symbol tables.
5. Resolve qualified names using imports, assignments, annotations and framework models.
6. Lower SQLAlchemy expressions and selected SQL strings into a separate query IR.
7. Cache content-addressed modules and invalidate dependents after interface-summary changes.
8. Emit parse/resolve gaps as first-class diagnostics.

A custom Python parser is a poor default: it duplicates a changing language grammar and teaches
less relevant security analysis than building the semantic layers above it. A parser experiment may
remain educational and isolated.

## 13. CFG and data-flow architecture

Build a per-function CFG with entry/exit, basic blocks and typed edges for normal flow, branches,
loops, `break`/`continue`, returns, raises, exception handlers, `finally`, `with`, yields, awaits and
comprehensions. Convert expressions into explicit definition/use operations. Run a worklist
fixed-point analysis over an abstract state with def-use sets, constants, aliases, symbolic
qualified names and taint labels.

Interprocedural analysis uses function summaries: parameters read, returns derived from parameters,
global/object mutations, calls, exceptions, sources, sinks, sanitizers and propagators. Call targets
are confidence-ranked; unresolved dynamic calls add unknown edges. Context sensitivity begins with
call-site-limited summaries rather than unbounded object sensitivity.

The design should prefer explainability and measured precision to fictional soundness. Python
reflection, monkey-patching, dynamic imports, descriptors, metaclasses, generated code and native
extensions prevent a complete static model.

## 14. Taint-analysis architecture

Taint is typed, not Boolean. Example labels include protected plaintext, secret, key material,
ciphertext, search token, subject identifier, untrusted request input and SQL fragment. Sources may
come from manifest-backed model attributes, decrypt/reveal operations, FastAPI inputs, environment
secrets and provider APIs. Sinks include logs, traces, metrics, errors, serialization, HTTP, files,
queues, subprocesses, raw SQL and protected physical columns.

Rules define propagators, transformations and sanitizers. Encryption transforms protected plaintext
into ciphertext; it is not a sanitizer for every sink. Parameterized SQL sanitizes the SQL-code
injection label but does not make protected plaintext safe to persist. Redaction may sanitize a log
sink while preserving other labels.

Start intraprocedurally, add manually modeled framework summaries, then bounded interprocedural
analysis. Compare results with Semgrep and CodeQL path queries. Semgrep's model explicitly separates
sources, sinks, propagators and sanitizers, while CodeQL path queries compute explainable flow paths;
both are useful references rather than reasons not to learn the machinery. See
[Semgrep terminology](https://semgrep.dev/docs/writing-rules/glossary) and
[CodeQL path queries](https://codeql.github.com/docs/writing-codeql-queries/creating-path-queries/).

## 15. Security-rule engine

A versioned rule contains:

- stable ID, title, taxonomy, severity and learning/assurance category;
- supported language/framework versions;
- structural predicate over syntax/semantic/query/protection IR;
- optional source, sink, propagator and sanitizer definitions;
- required analysis precision and behavior when information is unknown;
- applicability and protected-asset conditions;
- path/explanation template, references and remediation;
- safe/unsafe fixtures, counterexamples and expected limitations; and
- version/migration metadata.

Develop a typed Python API or restricted declarative IR alongside an active custom-query-language
research track. Real rules supply the semantics that determine which language features can graduate
into interoperable use. The language must not permit arbitrary code in untrusted rule packs. Rule
packs are signed/pinned, and generic results remain separable from Cryptalis protection findings.

## 16. Pentesting engine architecture

```text
specs/routes/crawl/seed traffic
              |
              v
        endpoint graph
              |
       auth + state model
              |
              v
        attack planner
              |
     templates + payload/mutators
              |
              v
      bounded request executor
              |
              v
     response/exposure oracles
              |
              v
  replay + evidence + correlation
```

The internal engine and external adapters share target authorization, endpoint, observation,
finding and evidence models. They do not need identical execution APIs. Safety budgets, synthetic
data, target pinning and cleanup are enforced below every engine.

## 17. Crawler and discovery architecture

Combine declared and observed discovery:

- OpenAPI, GraphQL and framework route inventory;
- browserless HTML/link/form crawling;
- optional browser/AJAX crawl through an external engine;
- recorded proxy traffic and test-client traces;
- redirects, content types, WebSocket/API endpoints and method/options discovery;
- authentication state and role-specific visibility; and
- route/parameter deduplication with canonical request shapes.

The endpoint graph records how a state or extracted value enables later requests. Respect robots is
not an authorization control; the lab authorization manifest remains authoritative. Benchmark crawl
coverage and state handling against ZAP/Burp. ZAP's Automation Framework already supports ordered,
pluggable jobs and authentication, providing a strong reference design. See
[ZAP Automation Framework](https://www.zaproxy.org/docs/desktop/addons/automation-framework/).

## 18. Payload and fuzzing architecture

Separate payload intent from encoding. A payload family describes the vulnerability hypothesis,
preconditions, parameter types, mutation positions, expected signals, risk and cleanup. Encoders
produce URL, JSON, form, multipart, header, cookie and nested variants. Mutators cover deletion,
duplication, boundary values, type changes, traversal, quoting, boolean/time/error SQL probes,
identifier substitution, tenant/subject substitution and sequence changes.

Oracles use status/body/header/schema differences, error fingerprints, stable timing statistics,
out-of-band callbacks, database observations and exposure markers. Reduce a successful case to the
smallest replayable request sequence. Never interpret response difference alone as exploitation.

## 19. Verify engine

Verify owns deterministic security-invariant and state-machine tests:

- manifest/model/schema/envelope/index consistency;
- query compatibility and fail-loud behavior;
- tamper, relocation, tenant/subject confusion and rollback;
- key rotation, revocation, cache fencing and provider outage;
- shredding, tombstones, backup restore and resurrection;
- migration interruption and mixed-version behavior;
- collector health, seeded exposure, negative controls and semantic mutants; and
- differential baseline/protected/mutated comparisons.

Pentest explores; Verify asserts known properties. A discovered attack can be minimized and promoted
into a deterministic Verify regression.

## 20. Protection graph

The graph unifies logical fields, classifications, physical columns, indexes, normalizers, query
capabilities, writers/readers, routes, keys, caches, migrations, deployments, attacks, collectors
and evidence. Typed edges include `persists_to`, `flows_to`, `indexed_by`, `queried_by`,
`encrypted_under`, `reachable_from`, `exercised_by`, `observed_by` and `contradicts`.

Static, runtime, database, network and scanner facts preserve their provenance. Unknown writers,
unresolved calls and missing collectors are nodes/gaps, not silent omissions. The graph is derived;
it never silently rewrites the manifest.

## 21. Doctor to Pentest to Verify correlation

```text
Doctor: request input may reach raw SQL
   + Pentest: injection reproduced with minimized request
   + Verify: seeded users table data extracted
   + Protection graph: email/phone protected; display_name unprotected
   = exploit confirmed, ciphertext/index metadata exposed,
     protected plaintext not observed in covered collectors,
     unprotected display_name exposed, control outcome bounded
```

Correlation uses explicit run, request, trace, transaction, asset, marker and artifact identifiers.
Time proximity is suggestive only. A Pentest result promoted to Verify becomes a durable regression;
a Doctor path that cannot be exercised remains a static risk, not a confirmed exploit.

## 22. Searchable-encryption architecture

The complete physical representation may legitimately resemble established systems:

```text
logical plaintext
   +-- randomized authenticated ciphertext
   +-- equality/IN/unique term
   +-- optional equijoin/group domain term
   +-- optional range/order structure
   +-- optional text/prefix structure
   +-- optional structured/JSON index terms
```

Each capability is independently declared, domain-separated, versioned, migrated, rotated,
shredding-aware and leakage-documented. Equality remains the first production candidate. Range,
order, text and structured search begin as isolated research implementations of published work and
cannot enter a production profile without review, vectors and adversarial evaluation.

## 23. Automatic schema and query architecture

The Protection Manifest compiles into model adapters, physical column families, constraints,
indexes, domains, query comparators, normalization functions, compatibility rules and Alembic
operations. Query discovery feeds the minimum-leakage planner; declarations remain authoritative.

SQLAlchemy expressions lower into a capability-aware query IR before physical rewriting. The
compiler checks tenant/index domains, nulls, casts, joins, aliases, subqueries, bulk/Core/raw paths,
sync/async behavior and version compatibility. Unsupported or ambiguous shapes fail loudly. A
proxy/query-rewriter experiment may reuse the same IR without replacing the ORM-first architecture.

## 24. Key lifecycle and shredding

Continue the tenant branch-key and subject-generation architecture, with provider-specific root
custody, bounded caches, epochs, leases, revocation, rotation, rewrap, tombstones, receipts and
restore/resurrection tests. Active research also includes identity-aware release, split authority,
keysets, query-capability keys, multi-region fencing and signed lifecycle evidence.

Provider status, Cryptalis state, wrapped-key deletion, active cache leases, fresh/stale process
behavior and backup restoration remain separate observations. Learning-first scope does not weaken
the claim boundary: no API call proves every plaintext or exported key copy is gone.

## 25. Network and PCAP analysis

The network track may grow from optional evidence into a learning subsystem:

- controlled capture orchestration and artifact metadata;
- direct TShark field/JSON extraction and optional PyShark experiments;
- Zeek connection, DNS, TLS and protocol logs;
- flow/session reconstruction and request/trace correlation;
- protocol metadata, size/timing leakage and plaintext-marker detection where observable;
- Nmap exposure/service correlation; and
- reproducible PCAP fixtures and dissector comparisons.

Do not write packet decoders merely to duplicate Wireshark coverage without a defined learning
target. TLS plaintext requires a controlled endpoint/capture boundary or ephemeral session secrets;
those secrets never enter normal evidence bundles.

## 26. DevSecOps and CI architecture

Fast pull-request gates run manifest/model/schema checks, bounded SAST and deterministic Verify
tests. Deeper interprocedural analysis, active DAST, lifecycle chaos, PCAP and dependency/container
scans run in isolated scheduled or release workflows. Findings share stable identities and preserve
source-tool semantics. SARIF serves code/artifact findings; JUnit serves scenarios; canonical JSON
and signed evidence bundles preserve the full correlation model.

Import Trivy/Grype/Gitleaks/CodeQL/Semgrep/ZAP/Nuclei results, while separately exercising internal
engines. Baselines show new, resolved, unchanged, reclassified and expired-exception states; they do
not turn failures or missing evidence into passes.

## 27. Property testing and fuzzing

Use Hypothesis/state machines for envelope parsing, normalization, query rewriting, schema
compilation, migration phases, key generations, cache epochs, taint propagation and endpoint state.
Use grammar/property fuzzing for manifests, rule DSL, SQL/query IR, attack templates, report schemas
and evidence ingestion. Differentially compare internal analyzers with CPython, CodeQL/Semgrep,
ZAP/Burp, TShark/Zeek and established cryptographic implementations where semantics overlap.

Every major control needs positive, negative and semantic-mutant fixtures. Mutation kill rate,
precision/recall, minimized counterexamples and replay success are first-class metrics.

## 28. Learning-value matrix

Scores are directional research priorities, not promises.

| Capability | Learning value (1–10) | Strongest disciplines |
|---|---:|---|
| Equality/search schema compiler | 9 | Cryptography, databases, ORM, migrations |
| Range/text/JSON research | 10 | Searchable encryption, inference, indexing |
| Doctor AST/symbols/CFG | 10 | Compilers, Python internals, SAST |
| Doctor taint/data flow | 10 | Program analysis, security modeling |
| Internal crawler/request engine | 8 | HTTP, state machines, DAST |
| Payload/oracle engine | 9 | Offensive security, statistics, testing |
| Protection/evidence graph | 9 | Security architecture, graph modeling |
| Key/cache/shredding lifecycle | 10 | Cryptography, distributed systems, operations |
| Migration fault testing | 9 | Databases, reliability, data engineering |
| PCAP/flow analysis | 8 | Networking, protocols, evidence |
| Generic CVE database | 3 | Feed maintenance rather than core learning |
| Generic compliance dashboard | 3 | Mapping/reporting with weak technical depth |

## 29. Complexity matrix

| Capability | Complexity | Correctness risk | Feasibility |
|---|---|---|---|
| Manifest/model/schema lint | Medium | Medium | Feasible now |
| Local AST rules | Medium | Medium | Feasible now |
| CFG/local data flow | High | High | Active research |
| Interprocedural taint | Very high | Very high | Research-heavy |
| Equality/IN/uniqueness | High | High | Active production-candidate workstream |
| Equijoin/grouping | Very high | Very high | Research-heavy |
| Range/text/JSON | Extreme | Extreme | Experimental |
| Internal crawler/mutator | High | High | Active research |
| Browser-grade crawling | Extreme | High | Integrate first |
| Key/cache/shred lifecycle | Very high | Very high | Core progressive track |
| Packet decoding | Extreme | High | Integrate decoder; study analysis layer |

## 30. Build-versus-integrate matrix

| Area | Build ourselves | Integrate | Recommended sequence |
|---|---|---|---|
| Python SAST | Cryptalis IR, CFG, taint, rules, protection overlay | CodeQL, Semgrep, Ruff/Bandit results | Integrate baseline; build progressively; differential benchmark |
| Web DAST | Endpoint graph, mutators, oracles, replay | ZAP/Burp/sqlmap | Integrate first; build lab engine by subsystem |
| Templates | Restricted Cryptalis scenario DSL | Nuclei workflows/templates | Import first; build only protection-aware semantics |
| Search crypto | Known constructions and SQLAlchemy integration | Reviewed libraries where available | Implement educational prototype; production selects reviewed path |
| Key custody | Cache/lifecycle/provider adapters | AWS/GCP/Vault/HSM | Never build root custody; build orchestration |
| Network | Flow/correlation/learning analyzers | Nmap/TShark/Zeek/Wireshark | Integrate decoders; build bounded analyses |
| Supply chain | Correlation with protected boundary | Trivy/Grype/Gitleaks/SBOM | Integrate; do not own feeds |
| Evidence | Canonical model/correlation/rendering | SARIF/JUnit/in-toto/Sigstore | Build semantics; integrate standards |

Decision records for a build candidate include learning value, benchmark/reference, smallest useful
slice, safety, correctness oracle, maintenance owner, and exit condition.

## 31. Flat ambitious program

All major capability families are active program scope:

1. Protection Manifest, randomized ciphertext, equality/`IN`/scoped uniqueness.
2. One documented SQLAlchemy sync/async path and explicit raw/Core/bulk gaps.
3. Schema/Alembic compiler for one resumable existing-data migration.
4. Tenant/subject keys, one local plus one production provider adapter, rotation/revocation/cache
   fencing and bounded shredding evidence.
5. Doctor manifest/model/schema checks and a small AST lint catalogue.
6. Verify tamper, bypass, migration, lifecycle and exposure scenarios.
7. ZAP integration and a small internal request-mutation learning prototype.
8. Canonical evidence, positive/negative/mutant controls and reproducible benchmarks.
9. Stable Doctor syntax/semantic IR, symbols, CFG, local and interprocedural data flow, typed taint,
   framework summaries and a versioned rule engine.
10. Internal endpoint/state graph, crawling, authentication workflows, request mutation, payload
    families, response/exposure oracles, minimization and deterministic replay.
11. Writer provenance, distributed failure injection, PCAP/TShark/Zeek flow correlation,
    protection-aware DevSecOps ingestion and signed evidence ecosystems.
12. Controlled-access authority, equijoin/grouping, range/order, text/fuzzy and structured/JSON
    encrypted-search research, each with its own production gate.

This is one ambitious solo program. Workstreams may overlap in research and implementation; no
three-person ownership or artificial semester ceiling is assumed. The builder still manually types
implementation code one file at a time under the workflow in the
[complete build guide](cryptalis-build-guide.md). Evidence maturity is tracked per capability, so
progress in one area never implies that another area is safe or complete.

## 32. Flat workstream roadmap

The stages below describe increasing evidence maturity, not permission to start. Every workstream
may begin immediately with research, fixtures, interfaces, or experiments. A capability advances
through the stages independently.

### Stage 0 — foundations and falsification

Threat model, manifest/protection graph, evidence schema, reference app, benchmark corpus, known
vectors, compatibility matrix and build-vs-integrate experiments.

### Stage 1 — protected SQLAlchemy vertical slice

Randomized encryption, equality/`IN`/uniqueness, schema/Alembic, tenant/subject keys, lifecycle,
Doctor linting, deterministic Verify and ZAP-backed lab.

### Stage 2 — real Doctor and assurance platform

Stable syntax/semantic IR, symbols, qualified names, SQLAlchemy/query IR, CFG, local data flow, rule
engine, internal endpoint graph/mutators, correlation and CI baselines.

### Stage 3 — interprocedural and distributed depth

Call graph/function summaries, interprocedural taint, async/FastAPI models, writer provenance,
multi-worker cache chaos, restore/resurrection, signed evidence and PCAP/flow correlation.

### Stage 4 — advanced searchable encryption and DAST

Equijoin/grouping, isolated range/order and text/JSON research, broader crawler/auth/state engine,
payload/oracle library, declarative scenario packs and attack-graph planning.

### Stage 5 — production hardening and ecosystem

External cryptographic review, long compatibility/upgrade testing, provider and deployment depth,
plugin APIs, independent assessment, operational evidence, documentation and reproducible research
results.

## 33. What still should not be built

- Novel production cryptographic primitives without credible research and review.
- Custom cloud KMS/HSM root custody.
- A CVE, malware, secret-pattern or package-vulnerability feed with no Cryptalis-specific learning.
- A generic compliance dashboard that substitutes checklists for technical evidence.
- Public or autonomous exploitation without explicit authorization.
- Production inclusion of educationally broken cryptography, payloads or lab credentials.
- A full Python parser when CPython provides the correct front end, unless explicitly isolated as a
  parser-learning experiment.
- Arbitrary-code rule/template execution from untrusted packs.
- Features with no correctness oracle, benchmark, maintainer interest or coherent connection to
  data protection and assurance.
- Claims of novelty, completeness, soundness, legal compliance or independent proof that the
  evidence does not support.

## 34. Final complete architecture

```text
                         CRYPTALIS LEARNING SYSTEM

 declarations + source + schema + migrations + deployment + runtime traffic
                                  |
             +--------------------+--------------------+
             |                    |                    |
             v                    v                    v
     Core data protection     Doctor / SAST       Pentest / DAST
   crypto + search + ORM    AST/symbols/CFG/      crawl/auth/state/
   schema + keys + lifecycle dataflow/taint/rules mutators/oracles/replay
             |                    |                    |
             +--------------------+--------------------+
                                  v
                         Protection Graph
             fields/storage/indexes/keys/paths/attacks/evidence
                                  |
             +--------------------+--------------------+
             |                    |                    |
             v                    v                    v
           Verify            Network analysis      DevSecOps
      invariants/state/       PCAP/flows/TLS/       CI/SARIF/SBOM/
      differential/mutants    protocol evidence     provenance
             |                    |                    |
             +--------------------+--------------------+
                                  v
                   reproducible evidence + benchmarks
```

The architecture stays coherent because every subsystem either protects data, analyzes how data and
attacks move, exercises the boundary, or explains evidence about the outcome.

## 35. Final verdict

**BUILD CRYPTALIS AS AN AMBITIOUS, LEARNING-FIRST DATA-SECURITY SYSTEM WHOSE COMPLETE MULTI-YEAR
ARCHITECTURE IS ACTIVE FROM THE BEGINNING.**

It is acceptable for components to resemble CipherStash, Acra, MongoDB Queryable Encryption,
Semgrep, CodeQL, ZAP, Burp, Nuclei, Wireshark or Zeek. Competitor overlap is a source of prior art,
test vectors and comparison—not a decisive negative.

The hard constraints are coherence, safety, attribution, testability, honest production boundaries,
and sustained learning value. Cryptalis should be judged by whether its builders can deeply explain
and evaluate modern encryption, database integration, static analysis, pentesting, key lifecycle and
security evidence—not by whether every feature is unprecedented.
