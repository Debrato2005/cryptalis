# Learning-first research philosophy

Status: governing evaluation criteria and research scope. No implementation evidence.
Reviewed 2026-09-30.
[Architecture owners](architecture/README.md) own technical contracts.
The [checklist](backend-build-checklist.md) owns state.
The [guide](cryptalis-build-guide.md) owns file order.

## Why build

Cryptalis is a coherent multi-year program for understanding cryptography, databases, object-relational mapping (ORM) internals, compilers, migrations, and distributed authority.
It also examines static and taint analysis, dynamic application security testing (DAST), networking, and evidence.
Its central question is whether construction teaches transferable systems and security knowledge.
The builder must be able to evaluate correctness and limits honestly.
Novelty and market differentiation are secondary.
Prior art supplies attribution, reference behavior, and difficult counterexamples.

Every track must protect data, describe or compile protection, manage lifecycle, analyze bypass paths, exercise the boundary, measure exposure, or produce reproducible evidence.
Reject a track that fits none of these purposes, or keep it outside Cryptalis.
Ambition does not justify incoherence. Dependencies govern integration and claims, not permission to start research.
There is no semester, minimum viable product (MVP), or feature ceiling.
Isolated analysis, search, lifecycle, and network experiments do not require a finished runtime.

One maintainer controls the workload through one explainable invariant per manual coding cycle.

## Evaluation and build versus integrate

Record learning value, system fit, security and correctness risk, oracle quality, depth, dependencies, maintenance interest, production utility, and prior art.
Evidence maturity belongs to each capability.
Integration with a mature tool does not prove Cryptalis's own property.
An educational implementation can remain valuable even when reviewers reject it for production.
New primitives do not silently qualify as safe for production.

The comparison below uses intermediate representation (IR) and control-flow graph (CFG) for analysis structures.
Authenticated encryption with associated data (AEAD) and HKDF, an HMAC-based key derivation function, are established crypto components.
Static application security testing (SAST) analyzes source. DAST exercises running targets.

| Area | Build for understanding | Integrate / differential oracle | Production/research distinction |
|---|---|---|---|
| Crypto/search | Envelope, domains, normalizer, and ORM integration. Attributed known constructions | Established AEAD/HKDF. CipherSweet/CipherStash/MongoDB, provisional Fieldseal vectors | No bespoke primitives. Review each construction for advanced representations |
| ORM/schema/migration | Manifest compiler, query IR, and recovery | Public SQLAlchemy/Alembic APIs, maintained examples | Enumerated compatibility and complete migration evidence |
| Root custody | Cache, lifecycle, and provider-state orchestration | AWS/GCP/Vault. OpenBao comparison | No custom key management service (KMS) or hardware security module (HSM) root system |
| Doctor | Stable IR, CFG, def-use, summaries, taint, and protection overlay | CPython AST/symtable, CodeQL/Semgrep/Pyright comparison | No claim of whole-program soundness across Python dynamism |
| Pentest | State and role graph, mutators, oracles, and replay | ZAP/Burp/Nuclei/sqlmap in an authorized lab | Generic breadth is educational. Causal impact evidence supports product claims |
| Network | Flow, capture, scenario, and size/timing correlation | TShark/Zeek/Nmap decoders/inventory | Passive transport layer security (TLS) cannot prove payload absence |
| Supply chain | Import and correlation that respect boundaries | Trivy/Grype/Gitleaks/SBOM feeds | Do not maintain a generic CVE or secret database |
| Evidence | Scoped result, graph, control, and receipt semantics | SARIF/JUnit/in-toto/DSSE/Sigstore | A signature proves attributed bytes, not independent truthful measurements |

Research selection scores are directional. They do not establish support.
Manifest/equality/compiler scores 9/10, advanced search 10/10, Doctor CFG/taint 10/10, and lifecycle 10/10.
Migration chaos scores 9/10, Pentest state/oracles 9/10, graph/evidence 9/10, and network analysis 8/10.
Generic feeds and compliance dashboards score 3/10.
Their maintenance dominates learning and does not establish a protection invariant.

## Deep research questions

Doctor research examines syntax IR, imports, scopes, qualified names, and CFG edges for exceptions and asynchronous operations.
It also examines local fixed-point dataflow, call targets, function summaries, typed taint, framework models, and restricted rule IR.
The goal is to explain exact flows of protected values and unknown alternatives.

[Assurance research](security-assurance-suite-research.md) preserves the details.
[Assurance contracts](architecture/assurance-evidence.md) freeze normative interfaces and gates.

Pentest research examines endpoint discovery, authentication, roles, state prerequisites, and typed mutation.
It separates payload intent from encoding and examines differential and timing oracles, minimization, and replay.
Networking examines provenance and size/timing leakage above established decoders.
Search research examines leakage from equality, joins, grouping, range, order, extrema, prefix, substring, text, fuzzy, and structured queries.
It also examines auxiliary and chosen-query attacks, storage, and lifecycle.

Crypto and ORM owners determine production integration. This philosophy does not create alternative capability or key-state tables.

Correctness oracles precede implementation.
They include vectors, mathematical or reference behavior, a labeled corpus, baseline/protected/one-mutant fixtures, or a known state-machine outcome.
Unknown or dynamic behavior is a visible result. It does not conveniently mean safety.
Record failed experiments and redesigns instead of expanding a claim to match a demo.

Internal research can examine generic algorithms even when mature tools supply broader production functionality.
Evidence about maintenance and learning determines integration.

## Broader research gates

These tracks remain active beyond the initial target.
Each empirical question names its reason, oracle, default, alternative, experiment, threshold, dependency, and blocked claim.
The thresholds below are proposed acceptance criteria for the design. They remain unmeasured.
Workloads and raw results are predeclared.
Rejection from supported integration does not prohibit educational study.

The [blueprint-linked contracts](architecture/README.md#fatal-risks-and-resolution-gates) own core P0-P10 and construction gates.

| ID / question and value | Default / alternative / smallest experiment and oracle | Pass / reject. Integration dependency and blocked claim |
|---|---|---|
| R-DJANGO: does an ORM-neutral manifest work with Django? | Reuse domain contracts versus framework-specific IR. Protect two models on Django sync/async with 20 fixtures for writes, reads, queries, and bypasses | 100% critical invariants with no guessed context. Otherwise, keep separate adapter research. Depends on manifest, format, and provenance. Django support blocked |
| R-DB: can another DB preserve physical and migration semantics? | PostgreSQL-specific compiler versus SQLite/MySQL adapter. Port one table with equality, null, and unique behavior, plus 20 crash and DDL fixtures | 100% semantic and recovery cases, 0 unsafe implicit downgrades. Otherwise, retain DB-specific contracts. Depends on schema, query, and lifecycle. Cross-DB support blocked |
| R-LANG: is SDK interoperability across languages worth the maintenance? | Shared vectors versus foreign-envelope import only. Python and TypeScript read and write 10,000 generated values. Include vectors for malformed inputs, AAD, and normalization | 100% byte and semantic agreement, 0 accepted malformed inputs or relocations. Otherwise, no shared support. Depends on frozen suite and manifest. Multi-language claim blocked |
| R-UI: does an inspection UI help reviewers? | Read-only explain/graph UI versus CLI and static report. Five users interpret ten cases for policy, drift, and unknowns | >=4/5 correctly explain >=9/10, with 0 unknown cases confused as safe. Otherwise, keep reports. Depends on result and graph DTO. Operational benefit claim blocked |
| R-RELEASE: does independent controlled authority narrow host compromise? | Purpose/end-user-authorized remote release versus local wrapper. Steal workload credentials and attempt ten unauthorized variants for release, purpose, and replay | 0 unauthorized releases, 100% authorized batch correctness. Budget comes from the crypto controlled gate. Otherwise, accident guard only. Depends on grant/provider fences. Stronger compromise boundary blocked |
| R-POLICY: does a SQL policy guard add useful coverage? | Advisory protected-table policy versus proxy firewall. Run 100 labeled raw, Core, and direct queries, with evasion variants against the role/ORM baseline | 100% critical seeded bypasses detected, >=95% precision, no implicit plaintext pass. Otherwise, research only. Depends on query and writer evidence. Universal SQL prevention blocked |
| R-HONEY: can honeytokens add causal evidence? | Synthetic field-aware token versus generic canary. Ten normal and ten leak scenarios, five repetitions | All seeded leaks attributable, 0 normal false hits, 100% cleanup. Otherwise, disable integration. Depends on oracle and provenance. Alert effectiveness blocked |
| R-ANOMALY: can query anomaly ranking aid review? | Advisory only versus no anomaly layer. Labeled 1,000 benign and 100 malicious traces with a drift split | >=90% precision and >=80% recall on the held-out split. Automatic revocation blocks the experiment. Failure keeps generic imports. Depends on writer and graph data. Detection/response claim blocked |
| R-ATTACKGRAPH: do graph paths improve scenario selection? | Explicit evidence path versus timestamp/ML heuristic. 20 labeled reachable, unreachable, and unknown lab paths | 100% critical reachable classification, 0 unknowns treated as impossible. >=20% median explanation-time benefit versus manual baseline or 10-point accuracy improvement. Depends on safety and graph. Causal product claim blocked |
| R-REGION: can lifecycle authority survive region partitions? | Single authoritative linearizable ledger versus quorum/multiregion release. Three regions, 100 sequences for partitions, leaders, restores, and suspension | 0 stale grants past the bound, 100% tombstone monotonicity, pending on quorum loss. Otherwise, no multiregion support. Depends on local fence, clock, and provider tests. Bounded region-wide revoke blocked |
| R-FAULTS: do distributed failure sequences reveal novel bugs? | Stateful model with injected faults versus scripted chaos. 10,000 seeded lifecycle and migration operations, minimized replay | Every state invariant checked and every seeded fault and mutant detected. No nondeterministic contraction. Depends on state DTO and fixtures. Resilience claim blocked |
| R-PACKS: is a rule/scenario ecosystem maintainable? | Restricted typed IR packs versus native trusted internal APIs. Two independent pack implementations, ten rules/scenarios each. Whether ten means combined entries or ten of each kind remains unspecified. 100 cases for malformed input, privileges, and signatures | 100% semantic agreement and refusal of privilege violations. <=10% maintenance cost increase on two upgrade exercises. Otherwise, keep internal seam. Depends on safety, version, and parser gates. Extension compatibility blocked |

These tracks add real learning without making Cryptalis a generic security information and event management (SIEM) system or enterprise data-security posture management (DSPM) system.
They do not make it a CVE feed, malware scanner, arbitrary offensive toolkit, custom custody infrastructure, or unbounded marketplace.

## Production, research and maintenance

Production primitives use maintained, reviewed libraries.
Educational known constructions include attribution, vectors, differential attack analysis, and quarantine in packages, configuration, and reports.
Advanced crypto requires a published primary construction, but publication alone does not establish approval.
Provider, DB, and framework versions are exact test inputs. Rolling documentation supplies documented-only sources.
The [prior-art ledger](prior-art.md) owns comparisons of capabilities, editions, and access dates, with limits on novelty claims.

Maintain one canonical contract per family, a small ergonomic interface, explicit errors, and provenance.
Keep separate planes for trusted runtime, lifecycle, schema and migration, analysis, lab work, and evidence.
Maturity can increase on independent tracks.
Release integration still requires its dependencies and external review.
The manual learning contract remains one file and invariant at a time.

## Rejection and contribution discipline

Reject integration when its oracle is unreliable, its security choice is opaque, or its authority is unbounded.
Also reject unsafe active tests, unreviewed crypto, unreadable migration, useless precision, sensitive evidence, or a boundary the maintainer cannot explain.
Redesign the affected profile, integrate a mature implementation, or preserve the experiment as educational.
An upstream contribution is a valid outcome.

Breadth does not support claims of 'first/only/novel', complete SAST/DAST, zero leakage, production readiness, compliance, or legal erasure.
Learning value, product differentiation, and research contribution are three separate axes.
The proposed contribution evaluates correlation between ORM, schema, lifecycle, and controlled attack and exposure evidence, with explicit unknowns.
Literature search cannot prove that an equivalent does not exist.
Publication requires a fresh independent related-work review and a measured corpus.
