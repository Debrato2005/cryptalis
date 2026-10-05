# Documentation claims and requirement audit

Status: first-party documentation audit. This record is advisory. It does not define
architecture or implementation status. Audit/reconciliation date: 2026-10-01 (Asia/Calcutta).
External source access dates remain per ledger.

The 2026-10-01 sections below are historical. The [later failure-policy audit](#fail-explicit-policy-and-implementation-audit) records current source findings.
Use the [checklist](backend-build-checklist.md) for current capability evidence.

## Verdict and scope

The canonical contracts specify the proposed system and the experiments required to admit each
capability. No package, runtime, tests, provider adapter, migration plugin, scanner integration,
benchmark, independently reviewed construction, or supported compatibility cell exists.

The documentation supports manual prototyping and implementation against gates. It does not pass
those gates. The [checklist](backend-build-checklist.md) records maturity. This audit records
inspection and working-tree checks. It is separate from committed executable evidence and
external independent assessment.

For the 2026-10-01 pass, the local working tree was the editing authority. That pass preserved
and integrated eight modified tracked Markdown files and two untracked audit and hardening
documents. Historical ADRs removed in cc54ee8 remain in Git history. The pass had no
authorization to create source, tests, configuration, scaffolding, commits, or pushes. It
created none.

The [pause handoff](SESSION_HANDOFF.md) is an archival session record. It does not own remaining
design decisions. The user later resumed the work. This audit supersedes the handoff's
unresolved list.

## Prior audit closure

These are documentation closures. Runtime properties remain pending at the linked gates.

| Finding | Exact correction and owner | Evidence limit |
|---|---|---|
| W-1 Circular self-review | Checklist C00 is `[~]`; every runtime row unchecked. Playbook separates human/script/first-party AI/independent review/executable evidence. Ad hoc check text/output below; independent crypto, provenance, migration, fencing and assurance/process checkpoints required | Working log is uncommitted; no `[x]` rests on prose or AI agreement |
| W-2 Greenlet counterexample | ORM explicitly compares local warm, adapted remote hooks and deferred batches; pinned pydantic-encryption await_/await_only/MissingGreenlet source; G-ORM-4/5 delays/tasks/cancellation/availability budgets | Source-inspected, not executed; permanent rejection requires real comparison |
| W-3 Framing dependency | Hub/build DAG and C03->C10 require frozen envelope/index/parser/null/coexistence predicates before DB CHECK. ORM separates well-shaped bytes from authentication | F1/W1 are candidates, no database constraint implemented |
| W-4 Ownership drift | Hub maps four contract owners, three dated source ledgers and audience/scope exclusions. README/guide/philosophy/tracker/prior-art/research link to contracts; historical dossier marked superseded | Short review prompts do not create competing algorithms/status tables |
| W-5 Context provenance | Shared host-issued immutable grants, principal authorization, subject creation/ownership, requested-resource binding independent of mutable DB metadata, task/pool/job/migration/service/test paths. I07/P0/G-CONTEXT deterministic substitution gate | No trusted identity adapter or isolation test has executed |

## Challenge closure

First-party agents reviewed cryptography and distributed systems, SQLAlchemy and Alembic,
databases, application security, product maintenance, and documentation. The coordinating agent
reconciled findings across owners. This was adversarial AI-assisted review. It does not
establish the REVIEWED maturity level or an independent expert audit.

| Material challenge | Disposition / canonical owner |
|---|---|
| Precommit epoch check races COMMIT; lease check races suspended output | Crypto acknowledged operation/sink drain plus ORM transaction FOR SHARE/FOR UPDATE fence, external deny first; expiry-only AUTHORITY_EXPIRED cannot mean physical COMPLETE_MANAGED |
| Original policy digest underdefined | Shared exact immutable descriptor/JCS/domain hash and historical compatibility mapping; crypto candidate tuple tags/widths/codec entry fixed for vectors |
| Authentic wrong-predicate row from swapped term | ORM buffered authenticated predicate/term verification, whole-result IndexInconsistent failure, no silent LIMIT refill/filter/scan |
| U-only writes can stale V after verification | Crypto+ORM dual-writer fence before target backfill; U authoritative until complete V coverage/enforcement and cutover |
| Verification sampling mistaken for full consistency | ORM full streaming authentication/source/term pass plus separate stratified sample; counts/shapes/sample alone cannot certify cutover |
| OBSERVE conflicts with rollback mirror | Zero legacy-authoritative reads/writes; declared atomic mirror counted separately, leakage/retention/rollback-loss explicit |
| Entity/cache publication boundary | ORM complete decoded entity handoff releases all transparent fields; subsequent host plaintext reuse is outside recall; new load/refresh/reveal requires preparation, cache checks never hide RPC |
| Deterministic physical naming | ORM naming v1 exact ASCII patterns, separate payload/term/coherence constraint roles and nonrecycled declared slot ordinals; compiler validates parent history and complete schema collisions |
| Query error timing and narrow wire bounds | Shared separates pre-SQL planning rejection from post-fetch IndexInconsistent; explicit no partial release/transaction reuse, selected F1 catalogue narrows generic manifest ID ranges |
| Public signatures differ from helper APIs | Shared public signatures and ORM DTO alias/internal helper distinction |
| Cold reads need keys unknown before SQL | Authorized bounded hidden ciphertext read then explicit warm; no logical publication before validation, cold writes fail before DML |
| Full metadata swap at same requested PK | Shared trusted ResourceBinding expected UUID/locator plus ORM identity-map/point-load fixtures; broad-query membership/completeness limits explicit |
| Codec/IN/null/BOM limits diverge | One 1MiB encoded limit, five-byte overhead, 1000 logical IN/2000 dual binds, leading U+FEFF preserved, SQL-NULL substitution unauthenticated |
| Distributed counters contradict local hooks | Explicit pre-reserved durable quota, one-way local consumption, no refill in scalar hooks; online-consumption alternative and undetectable RAM-clone limitation gated |
| Tool signatures/inventory do not cover all files | Assurance every-member hashes including Nuclei helpers; reject unlisted members and unsafe capabilities; detached wrapper relation/self-exclusion explicit |
| Signature trust/TOCTOU/secret scanner egress | Assurance immutable same-byte verification-to-render, mandatory wrapper policy, clean environment/zero-egress adapters; Betterleaks active validation disabled |
| DSL/internal DAST lacked a concrete falsifier | Assurance G-A10 typed-native/DSL equivalence and G-A11 state/role/network/loss/replay gates; no broad scanner claim |
| Shell-escaped inline-code corruption | Whole-tree inline-code/control-byte check exposed five damaged assurance identifiers; exact-byte repair and broadened checker verified, rather than relying on link success |
| New release/page drift | Python 3.14.8 comparison, dated GCP footer, recovered CipherStash CLI, contradictory retrieval caches recorded; no runtime equivalence inferred |

## Claim classification

| Claim class | Current classification / evidence owner |
|---|---|
| Upstream versions/API feasibility | Current as of each dated observation; documented or selected source-inspected; ORM ledger |
| Primitive/search/provider/erasure guidance | Documented or bounded paper-inspected, not reproduced; crypto ledger |
| Tool/edition/output/attestation capabilities | Documented-only with exact scope and unresolved binary/edition pins; tool ledger |
| New/adjacent competitor differentiation | Bounded discovery and qualitative comparison, no feature-absence/market/novelty proof; prior art |
| Cryptalis behavior/security/performance/support | Specified or researched requirements; no executed or measured claims |
| Documentation commands | Executed working-tree checks below, first-party and uncommitted |
| Independent review / production / legal erasure / compliance | Unsupported and explicitly not asserted |
| August audit absolute verification verdict/versions | Superseded historical observations, not current assurance |

Version observations are dated inputs. They do not guarantee the latest release after the access
date. No runtime claim is labeled reproduced, benchmarked, or independently reviewed. Future
experiment bundles require exact tool binary pins, service deployment settings, and external
reviews.

## Subsystem readiness cross-check

The following matrix locates all seventeen required design dimensions from directive section 85.
Each linked contract supplies purpose/owner, input/output DTOs, state and trust; public seams
and module dependencies; typed failure/retry/idempotency; independent versions and redacted
observability; correctness/adversarial oracles; risks, performance/migration obligations and
empirical gates.

| Subsystem | Contract locations / state | Tests, risk and dependency evidence |
|---|---|---|
| Manifest/context/API | Shared ManifestDocument/ProtectionGrant/ResourceBinding, canonical bytes, immutable history, public/CLI/config/errors/module/compatibility sections | G-MANIFEST/G-CONTEXT/G-API/G-BOUNDARY; no authority from raw IDs |
| Crypto/search | Crypto suite/F1/W1/codec/E/AAD/KDF/normalization/leakage/continuous uniqueness | G-CRYPTO/G-CROSSKEY/G-AAD/G-EQUALITY/G-UNIQUE/G-SEARCH/G-BUDGET; construction freeze before schema |
| Provider/cache/lifecycle/controlled | Crypto registry/hierarchy/native adapter, quota/lease/permit/drain/tombstone/receipt/reveal states | G-PROVIDER/G-LIFECYCLE/G-RESTORE/G-CONTROLLED; quorum/outage/copy/restore limitations |
| ORM/query/types | MappingPlan/QueryIR/QueryPlan, histories/loaders/path matrix/async comparison/null/limits | G-ORM-1..5; private APIs/unknown traversal/dynamic loaders remain gated |
| Schema/Alembic/migration | SchemaPlan alias/internal helpers, snapshots/operations, phase/chunk/DDL journal/serialized fence | G-ORM-6..10; full verification and per-destructive-step approval |
| Doctor/planner/graph/writers | Assurance workspace/IR/CFG/taint/rules/proposals/typed graph/conflicts and provenance | G-A01..03/G-A09/G-A10; bounded Python analysis, observations never widen policy |
| Verify/Pentest/network | Scenario/collector/control/result schemas, target broker/state/replay/capture | G-A04..07/G-A11; missing/lost evidence inconclusive, synthetic controlled lab only |
| Evidence/CI/integrations | Exact bytes/member inventory/trust/export/baseline/lab/CI contract | G-A06/G-A08 and G-BOUNDARY; signatures do not establish truth/independence |
| Broader coherent tracks | Research philosophy twelve R-* questions/defaults/alternatives/minimum/exit/dependencies | No unbounded toolkit, arbitrary pack code or accidental core proxy pivot |

## Original directive coverage

Every numbered section of the original directive is mapped below. `Design inspected` means the
documentation supplies a required contract, gate, or policy. It does not mean an executable gate
passed. The working record supports scope, process, and final-check rows. The table retains
sections 0..98 instead of reducing them to a shorter MVP list.

| Section | Authoritative evidence locator | Verified requirement / limit |
|---:|---|---|
| 0. NON-NEGOTIABLE EXECUTION MODE | [Playbook](../ENGINEERING_PLAYBOOK.md) | Docs-only scope; no source/tests/config, commit or push |
| 1. PROTECT THE USER'S WORKTREE | [Playbook](../ENGINEERING_PLAYBOOK.md) | Current main/HEAD/origin compared; initial local edits preserved |
| 2. SKILLS / PLUGINS / MCPs — USE THEM PROACTIVELY | [Prior art](prior-art.md) | Relevant skills/MCPs used; inspected alternatives, no appearance-only installation |
| 3. TOKEN-EFFICIENT WORKING METHOD | [Blueprint](architecture/README.md) | Inventory/owner map; disjoint research agents and final integration |
| 4. READ THE ENTIRE AUTHORITATIVE DOCUMENT SET FIRST | [Blueprint](architecture/README.md) | Entire original authoritative set, local audit/dossier/history and new owners read |
| 5. CURRENT CRYPTALIS CENTER OF GRAVITY | [Blueprint](architecture/README.md) | ORM/manifest center; every plane and broad research retained |
| 6. DO NOT CONFUSE AMBITION WITH FALSE CERTAINTY | [Blueprint](architecture/README.md); [Manifest/context/API](architecture/manifest-context-api.md) | DECIDED/DEFAULT/OPEN vocabulary and falsifiable gates |
| 7. MANDATORY EXISTING AUDIT FINDINGS — RESOLVE ALL FIVE | [prior audit closure](#prior-audit-closure) | W-1..W-5 documentation corrections, runtime evidence still pending |
| 8. EXTERNAL RESEARCH — REVERIFY EVERYTHING IMPORTANT | [Prior art](prior-art.md); source ledgers | Current primary versions/editions/access dates and evidence class |
| 9. SEARCH FOR NEW PRIOR ART | [Prior art](prior-art.md) | New Fieldseal/Arca/blind_index/Django/OpenBao/OpenFGA discovery; novelty narrowed |
| 10. DEFINE CRYPTALIS WITH EXTREME PRECISION | [Blueprint](architecture/README.md); [Manifest/context/API](architecture/manifest-context-api.md) | Users, target, threats, protected/transparent/controlled/profile/coverage terms |
| 11. ADD A CLEAR CAPABILITY-MATURITY MODEL | [Manifest/context/API](architecture/manifest-context-api.md); [Checklist](backend-build-checklist.md) | Per-capability cumulative maturity and exact evidence admission |
| 12. FINALIZE THE PROTECTION MANIFEST | [Manifest/context/API](architecture/manifest-context-api.md) | Required/conditional/optional semantic field matrix, canonical bytes/hash/version/migration |
| 13. EXACT DATA-PLANE ARCHITECTURE | [Blueprint](architecture/README.md); [ORM/schema/migration](architecture/orm-schema-migration.md); [Crypto/search/lifecycle](architecture/crypto-search-lifecycle.md) | Write/read sequencing and typed refusals; no unauthenticated output |
| 14. FINALIZE THE TRUST / THREAT MODEL | [Blueprint](architecture/README.md) | Assets/attacker/assumptions/control/residue/tests per threat |
| 15. TENANT / SUBJECT / RECORD IDENTITY MODEL | [Manifest/context/API](architecture/manifest-context-api.md) | Principal/scope/tenant/subject/record/request/job/workload/provider authority; binding substitution |
| 16. CRYPTOGRAPHIC ARCHITECTURE | [Crypto/search/lifecycle](architecture/crypto-search-lifecycle.md) | Established library candidates, KDF/domain/nonces/AAD/memory/key commitment gates |
| 17. ENVELOPE FORMAT | [Crypto/search/lifecycle](architecture/crypto-search-lifecycle.md) | F1/W1 candidate bytes, parser bounds/errors, recognition versus authenticity |
| 18. SEARCHABLE ENCRYPTION — COMPLETE CAPABILITY ARCHITECTURE | [Crypto/search/lifecycle](architecture/crypto-search-lifecycle.md) | Every search family: operators/construction/leakage/cost/null/domain/rotation/cleanup/gates |
| 19. SEARCH DOMAIN VS SUBJECT SHREDDING | [Crypto/search/lifecycle](architecture/crypto-search-lifecycle.md) | Shared-search residue versus strict-shred/no-search/subject-scoped profiles |
| 20. SQLALCHEMY ARCHITECTURE | [ORM/schema/migration](architecture/orm-schema-migration.md) | Instrumentation/state/history and T/R/D/U execution/loader cells |
| 21. SYNC / ASYNC / PROVIDER I/O | [ORM/schema/migration](architecture/orm-schema-migration.md) | Real warm/greenlet/deferred comparison with delay/cancel/outage/N+1 budgets |
| 22. QUERY IR AND FAIL-LOUD BEHAVIOR | [ORM/schema/migration](architecture/orm-schema-migration.md) | Query IR, complete statement validation and bounded predicate verification |
| 23. PHYSICAL POSTGRESQL MODEL | [ORM/schema/migration](architecture/orm-schema-migration.md) | BYTEA/companions/domain/index/null/naming and relational-ID limits |
| 24. SCHEMA COMPILER | [ORM/schema/migration](architecture/orm-schema-migration.md) | Manifest+metadata+snapshot+catalogue inputs; deterministic plan-only output |
| 25. ALEMBIC ARCHITECTURE | [ORM/schema/migration](architecture/orm-schema-migration.md) | Public Alembic operations/renderers/comparators, Plugin floor and reviewed revisions |
| 26. MIGRATION STATE MACHINE | [ORM/schema/migration](architecture/orm-schema-migration.md) | Nine migration phases, dual writer fence, CAS/checkpoints/rollback/irreversible approvals |
| 27. KEY HIERARCHY | [Crypto/search/lifecycle](architecture/crypto-search-lifecycle.md) | Root/branch/random wrapped subject/index hierarchy, independent secrets and recovery copies |
| 28. PROVIDER CONTRACT | [Crypto/search/lifecycle](architecture/crypto-search-lifecycle.md) | Native provider state/IAM/version/import/export/restore/outage distinctions |
| 29. CACHE MODEL | [Crypto/search/lifecycle](architecture/crypto-search-lifecycle.md) | Scoped material versus leased operation authority, quota/cache/outage/resume/fork |
| 30. ROTATION / REVOCATION / SHREDDING | [Crypto/search/lifecycle](architecture/crypto-search-lifecycle.md) | Separate rotation/revoke/shred states; drain versus expiry and provider pending |
| 31. RESTORE-RESISTANT TOMBSTONES | [Crypto/search/lifecycle](architecture/crypto-search-lifecycle.md) | External monotonic tombstones independent of application snapshots; deny on unknown latest state |
| 32. CONTROLLED ACCESS | [Crypto/search/lifecycle](architecture/crypto-search-lifecycle.md); [Manifest/context/API](architecture/manifest-context-api.md) | Controlled purpose/principal release authority versus local accident guard |
| 33. DOCTOR — COMPLETE LONG-TERM ARCHITECTURE | [Assurance/evidence](architecture/assurance-evidence.md) | AST/symbol/semantic IR/CFG/def-use/summaries/calls/taint/model/unknown contracts |
| 34. TYPED TAINT MODEL | [Assurance/evidence](architecture/assurance-evidence.md) | Multi-label transformations and sink-specific sanitizers; unknown sensitivity preserved |
| 35. RULE ENGINE / RULE PACKS | [Assurance/evidence](architecture/assurance-evidence.md) | Versioned RuleSpec, restricted DSL versus typed-native G-A10, no arbitrary pack code |
| 36. MINIMUM-LEAKAGE PLANNER | [Assurance/evidence](architecture/assurance-evidence.md) | Minimum-leakage recommendation provenance/cost/lifecycle, never auto-mutate policy |
| 37. PROTECTION GRAPH | [Assurance/evidence](architecture/assurance-evidence.md) | Typed graph nodes/edges/identity/basis/conflicts; derived, never manifest authority |
| 38. VERIFY ENGINE | [Assurance/evidence](architecture/assurance-evidence.md) | Deterministic scenarios plus positive/negative/mutant/restored controls and health |
| 39. RESULT / EVIDENCE TAXONOMY | [Assurance/evidence](architecture/assurance-evidence.md) | Nine independent dimensions and six exact assertion states, FAIL preserved with gaps |
| 40. EXPOSURE ORACLE | [Assurance/evidence](architecture/assurance-evidence.md) | Synthetic private marker mapping, registered forms/collectors/watermarks and bounded absence |
| 41. PENTEST / DAST ARCHITECTURE | [Assurance/evidence](architecture/assurance-evidence.md); [Assurance research](security-assurance-suite-research.md) | Internal DAST role/state/mutation/oracle/minimization/replay plus mature-tool adapters |
| 42. ACTIVE TEST SAFETY | [Assurance/evidence](architecture/assurance-evidence.md) | Disposable authorization/sentinel/IP/redirect/egress/budget/kill/cleanup interlocks |
| 43. EXTERNAL SECURITY TOOL INTEGRATION | [Assurance/evidence](architecture/assurance-evidence.md); tool ledger | Tool stronger areas/imports/research/nonclaims; editions/native semantics preserved |
| 44. NETWORK / PCAP ARCHITECTURE | [Assurance/evidence](architecture/assurance-evidence.md); [Assurance research](security-assurance-suite-research.md) | Nmap/TShark/Zeek/capture identity/session/flow research, TLS visibility and secret hygiene |
| 45. EVIDENCE BUNDLE | [Assurance/evidence](architecture/assurance-evidence.md) | Complete versioned result/graph/receipt/replay/member inventory and multi-format exports |
| 46. EVIDENCE INTEGRITY | [Assurance/evidence](architecture/assurance-evidence.md) | JCS exact bytes, DSSE/in-toto/Sigstore trust policy, integrity distinct from truth |
| 47. WRITER PROVENANCE | [Assurance/evidence](architecture/assurance-evidence.md) | Configured/observed/unknown/unregistered writers; fingerprints/application_name not identity |
| 48. DEVSECOPS / CI ARCHITECTURE | [Assurance/evidence](architecture/assurance-evidence.md); [Playbook](../ENGINEERING_PLAYBOOK.md) | Offline fast checks, deeper isolated lab and release evidence; no CI scaffolding |
| 49. PROPERTY / FUZZ / STATEFUL TESTING | [Manifest/context/API](architecture/manifest-context-api.md); [ORM/schema/migration](architecture/orm-schema-migration.md); [Crypto/search/lifecycle](architecture/crypto-search-lifecycle.md); [Assurance/evidence](architecture/assurance-evidence.md) | Parser/property/stateful/differential oracles assigned by invariant and gate |
| 50. REFERENCE APPLICATION / LAB | [Assurance/evidence](architecture/assurance-evidence.md) | Identical baseline/protected/one-mutant synthetic app, separate networks and reset |
| 51. BENCHMARK ARCHITECTURE | [Assurance/evidence](architecture/assurance-evidence.md) | Pinned randomized multi-run measurements, raw failures/distributions/uncertainty/fair baselines |
| 52. PERFORMANCE MODEL | [Crypto/search/lifecycle](architecture/crypto-search-lifecycle.md); [ORM/schema/migration](architecture/orm-schema-migration.md); [Assurance/evidence](architecture/assurance-evidence.md) | Cost hypotheses measured separately; budgets predeclared, no performance results |
| 53. PACKAGE / MODULE ARCHITECTURE | [Manifest/context/API](architecture/manifest-context-api.md) | Module responsibility/seam/deps/forbidden directions/invariant/errors/tests |
| 54. DEPENDENCY DIRECTION | [Manifest/context/API](architecture/manifest-context-api.md) | Dependency arrows and table; DTOs below adapters, CLI composition above |
| 55. CONTROL PLANE VS DATA PLANE VS ANALYSIS PLANE | [Blueprint](architecture/README.md) | Runtime/control/schema/analysis/lab/evidence plane flows and mutation authority |
| 56. PUBLIC PYTHON API | [Manifest/context/API](architecture/manifest-context-api.md) | Public input/output/lifetime/sync/async/authority/errors; explicit admission and warm |
| 57. CLI | [Manifest/context/API](architecture/manifest-context-api.md) | Named commands, safe defaults/network/destruction/authorization/artifacts and exits |
| 58. ERROR TAXONOMY | [Manifest/context/API](architecture/manifest-context-api.md) | Redacted typed families and retry semantics; no plaintext fallback |
| 59. CONFIGURATION MODEL | [Manifest/context/API](architecture/manifest-context-api.md) | Presentation precedence versus intersection of immutable security restrictions |
| 60. OBSERVABILITY | [Manifest/context/API](architecture/manifest-context-api.md); subsystem owners | Allowed timings/counts/digests and forbidden plaintext/tokens/keys/bodies |
| 61. COMPATIBILITY MATRIX | [ORM/schema/migration](architecture/orm-schema-migration.md); ORM ledger | Exact candidate cells and comparison versions; no supported matrix exists |
| 62. EXTENSION / PLUGIN ARCHITECTURE | [Manifest/context/API](architecture/manifest-context-api.md); [Assurance/evidence](architecture/assurance-evidence.md) | Narrow provider/collector/tool/report seams, native rules until measured DSL justification |
| 63. BROADER AMBITIOUS RESEARCH | [Research philosophy](learning-first-research-philosophy.md) | Twelve broader track gates: purpose/oracle/default/alternative/minimum/exit/dependencies |
| 64. PRODUCT POSITIONING | [Prior art](prior-art.md) | Correlation wedge hypothesis; honest reasons to prefer alternatives |
| 65. RESEARCH CONTRIBUTION | [Prior art](prior-art.md); [Research philosophy](learning-first-research-philosophy.md) | Research contribution separated from learning/product; no novelty assertion |
| 66. ADOPTION / USABILITY | [Manifest/context/API](architecture/manifest-context-api.md); [Prior art](prior-art.md) | Nine adoption flows and G-API five-maintainer task study |
| 67. FAILURE MODE ANALYSIS | [Blueprint](architecture/README.md); all four contracts | Failure/closedness/retry/idempotency/evidence/loss per plane; matrix below |
| 68. CONCURRENCY / DISTRIBUTED SEMANTICS | [ORM/schema/migration](architecture/orm-schema-migration.md); [Crypto/search/lifecycle](architecture/crypto-search-lifecycle.md) | Lock order, row/phase CAS, worker incarnation, epochs, permits, duplicate requests |
| 69. VERSIONING | [Manifest/context/API](architecture/manifest-context-api.md); all four contracts | Independent schema/instance/compiler/crypto/index/migration/rule/scenario/evidence versions |
| 70. DATA TYPES / EDGE CASES | [ORM/schema/migration](architecture/orm-schema-migration.md); [Crypto/search/lifecycle](architecture/crypto-search-lifecycle.md) | Exact str/bytes plus gated scalar/structured codecs and coercion/size/decode boundaries |
| 71. NULL / NORMALIZATION / COLLATION | [ORM/schema/migration](architecture/orm-schema-migration.md); [Crypto/search/lifecycle](architecture/crypto-search-lifecycle.md) | SQL-null integrity limit, encrypted-null, normalization/collation and index migration |
| 72. SECURITY INVARIANTS | [Blueprint](architecture/README.md) | I01..I12 stable mechanisms/owners/tests/adversaries/evidence/failure states |
| 73. STOP CONDITIONS | [Blueprint](architecture/README.md); research gates | Stop affected claims on fatal counterexamples; unrelated research remains active |
| 74. CLAIM DISCIPLINE | [Blueprint](architecture/README.md); [Playbook](../ENGINEERING_PLAYBOOK.md); [Prior art](prior-art.md) | No unqualified security/novelty/compliance/erasure superiority claims |
| 75. DOCUMENTATION ARCHITECTURE | [Blueprint](architecture/README.md) | One canonical decision-family owner; audience/owns/does-not-own matrix |
| 76. ADRs | [Blueprint](architecture/README.md) | D01..D10 ADR-equivalent context/alternatives/consequences/status/supersession |
| 77. GLOSSARY | [Manifest/context/API](architecture/manifest-context-api.md) | Canonical terminology table; subsystem-specific DTOs refer back |
| 78. CHECKLIST REDESIGN | [Checklist](backend-build-checklist.md) | C00..C32 ID/state/dependency/artifact/exit tracker; no checked runtime capability |
| 79. BUILD GUIDE REDESIGN | [Build guide](cryptalis-build-guide.md) | Dependency DAG plus 16 first-file/concept/outcome construction threads |
| 80. LEARNING-FIRST PHILOSOPHY REDESIGN | [Research philosophy](learning-first-research-philosophy.md) | Learning criteria/build-integrate/multi-year scope, no copied runtime algorithms |
| 81. PRIOR ART REDESIGN | [Prior art](prior-art.md) | Strength/limit/lesson/response/source/date comparisons and attribution |
| 82. SECURITY ASSURANCE RESEARCH DOCUMENT | [Assurance research](security-assurance-suite-research.md); [Assurance/evidence](architecture/assurance-evidence.md) | Deep research separated from normative assurance and core owners |
| 83. README | [README](../README.md) | High-level promise/boundary/status/map/next gates |
| 84. ENGINEERING PLAYBOOK | [Playbook](../ENGINEERING_PLAYBOOK.md) | Operational manual-typing/verification/review/release/claim process |
| 85. MAKE THE ARCHITECTURE IMPLEMENTATION-READY | [subsystem readiness cross-check](#subsystem-readiness-cross-check) | All requested interface/state/trust/failure/version/test/risk/performance/migration/gate dimensions |
| 86. AMBIGUITY HUNT | Validation record below | Dedicated ambiguity scan; material words resolved or tied to precise scoped contract |
| 87. CONTRADICTION HUNT | [challenge closure](#challenge-closure) | Cross-owner contradiction reconciliation, not just grep absence |
| 88. LINK / REFERENCE VALIDATION | Validation checker below | Local Markdown targets/generated anchors/exact path case/fences and deleted references |
| 89. CLAIMS AUDIT — RUN AGAIN AT THE END | This audit and source ledgers | Fresh externally verifiable claim classes; no unsupported runtime assertion |
| 90. SECOND-PASS ADVERSARIAL REVIEW | [challenge closure](#challenge-closure) | Seven first-party perspectives; findings reconciled, external independence not asserted |
| 91. OPEN QUESTIONS MUST BE HIGH QUALITY | All gate owners | Per-gate question/why/default/alternatives/evidence/experiment/pass/fail/blocked/safe-work |
| 92. DO NOT OPTIMIZE FOR DOCUMENT LENGTH | [Blueprint](architecture/README.md) | Four detail owners and three source ledgers; duplicate algorithms replaced with links |
| 93. DO NOT DUMB THE SYSTEM DOWN | [Research philosophy](learning-first-research-philosophy.md); [Checklist](backend-build-checklist.md) | All crypto/DB/ORM/compiler/lifecycle/analysis/DAST/network/evidence tracks remain active |
| 94. BUT DO NOT TURN CRYPTALIS INTO RANDOM SECURITY TOOLING | [Research philosophy](learning-first-research-philosophy.md); [Assurance research](security-assurance-suite-research.md) | Unrelated commodity feeds/custody/SIEM/toolkit excluded or integrated under bounded gates |
| 95. FINAL REPOSITORY STATE SHOULD ANSWER "WHAT EXACTLY DO I BUILD?" | [Blueprint](architecture/README.md); [Build guide](cryptalis-build-guide.md); [Checklist](backend-build-checklist.md) | Entry map answers what to build, current truth and next falsifiers without tribal context |
| 96. REQUIRED FINAL VALIDATION | Validation record below | Tree/status/diff/link/terms/ownership/versions/checkboxes/claims/provenance checks |
| 97. DEFINITION OF DONE | This coverage and validation record | Documentation-only completion; no experimental proof fabricated |
| 98. FINAL RESPONSE FORMAT | Final completion report | Nine requested report sections after reconciliation and final checks |

## Historical audit disposition

The preexisting 2026-08-22 audit claimed external comprehensive verification and no fatal flaws.
Its August 23 addendum superseded that verdict with additional fatal-risk hypotheses. The
2026-10-01 pass could not establish the earlier review's independence or reproduce its checks.
It retained the dates and W-1..W-5 findings as historical inputs, not external approval.

Dated primary ledgers correct older SQLAlchemy-beta and Alembic version lanes and blanket claims
about Plugin introduction. Historical self-review does not establish that current runtime gates
passed.

## Validation working record

This section records validation from the 2026-10-01 documentation pass. Later prose edits change
the snapshot. The dated results below do not validate those later edits.

That pass ran no package installation, runtime test, cloud mutation, or target scan. The checker
below is an ad hoc command recorded in Markdown. It is not a repository source or test script.
It checks UTF-8 decoding, unexpected control bytes, balanced inline code and fences, local
Markdown targets, exact path casing, and GitHub-style heading anchors.

The checker excludes links inside fenced examples. It does not establish external URL
availability, rendered layout, Mermaid rendering, semantic correctness, or production
protection. Reviewers separately read and challenged semantic claims, ownership, and gates.

<!-- DOC_CHECKER_BEGIN -->
```python
from pathlib import Path
import collections, hashlib, re, urllib.parse
root = Path.cwd()
files = sorted(p for p in root.rglob('*.md') if '.git' not in p.parts)
clean, anchors, faults = {}, {}, []
for p in files:
    lines, fence = [], None
    text = p.read_text(encoding='utf-8-sig')
    if any(line.rstrip(' \t') != line for line in text.splitlines()):
        faults.append(f'{p.relative_to(root)}: trailing whitespace')
    if any(ord(c) < 32 and c not in '\n\r\t' for c in text):
        faults.append(f'{p.relative_to(root)}: unexpected control byte')
    for number, line in enumerate(text.splitlines(), 1):
        m = re.match(r'^\s*(`{3,}|~{3,})', line)
        if m:
            if fence is None:
                fence = (m[1][0], len(m[1]))
            elif m[1][0] == fence[0] and len(m[1]) >= fence[1]:
                fence = None
            continue
        if fence is None:
            lines.append(line)
            if line.count('`') % 2:
                faults.append(f'{p.relative_to(root)}:{number}: unmatched inline code')
    if fence:
        faults.append(f'{p.relative_to(root)}: unclosed fence')
    clean[p] = '\n'.join(lines)
    counts, ids = collections.Counter(), set()
    for line in lines:
        m = re.match(r'^#{1,6}\s+(.+?)\s*#*$', line)
        if m:
            slug = re.sub(r'[^\w\- ]', '', m[1].lower()).replace(' ', '-')
            n = counts[slug]
            counts[slug] += 1
            ids.add(slug + (f'-{n}' if n else ''))
    anchors[p] = ids
links = 0
for p, s in clean.items():
    targets = [m[1].strip('<>') for m in re.finditer(
        r'\[[^\]\n]*\]\((<[^>]+>|[^\s)]+)(?:\s+[^)]*)?\)', s)]
    targets += [m[1].strip('<>') for m in re.finditer(
        r'^\s*\[[^\]]+\]:\s*(<[^>]+>|\S+)', s, re.M)]
    for target in targets:
        u = urllib.parse.urlsplit(target)
        if u.scheme or u.netloc or target.startswith('\\\\'):
            continue
        q = (p.parent / urllib.parse.unquote(u.path)).resolve() if u.path else p
        links += 1
        if not q.exists() or not q.is_relative_to(root):
            faults.append(f'{p.relative_to(root)}: missing/outside {target}')
            continue
        exact = root
        for part in q.relative_to(root).parts:
            if part not in [x.name for x in exact.iterdir()]:
                faults.append(f'{p.relative_to(root)}: case {target}')
                break
            exact = exact / part
        if u.fragment and q in anchors and urllib.parse.unquote(u.fragment) not in anchors[q]:
            faults.append(f'{p.relative_to(root)}: anchor {target}')
record = []
for p in files:
    if p.relative_to(root).as_posix() != 'docs/documentation-claims-audit.md':
        record.append(p.relative_to(root).as_posix() + ':' + hashlib.sha256(p.read_bytes()).hexdigest())
print(f'Markdown files={len(files)}; local links={links}; faults={len(faults)}')
print('Snapshot SHA256 (audit self excluded)=' + hashlib.sha256('\n'.join(record).encode()).hexdigest())
for fault in faults:
    print(fault)
raise SystemExit(bool(faults))
```
<!-- DOC_CHECKER_END -->

Prerequisites: Python 3 and the repository root as the working directory.

1. Extract the single checker block between `DOC_CHECKER_BEGIN` and `DOC_CHECKER_END`.
2. Execute that block with Python 3 through standard input.
3. Record results only after the checker runs on reconciled files.

This procedure creates no repository source. Snapshot hashing excludes this audit to prevent a
recursive digest. Git status and content inspection cover the audit separately.

### Executed final results — 2026-10-01

| Check actually run | Result and practical limit |
|---|---|
| WSL pwd / git rev-parse --show-toplevel / branch / HEAD / origin/main / ls-files / find docs | Correct current repository; main; HEAD and local origin/main cc54ee894e1cdfb66245ddc69cc9286e3d6eea60; complete tree inspected |
| git ls-remote origin refs/heads/main | Live public main equals the same commit; read-only, no fetch/reset/checkout over user edits |
| Recorded checker extracted and executed by Python3 through WSL stdin | 18 Markdown files; 329 local links; zero missing targets, anchors, case, fence, inline-code, unexpected-control or trailing-whitespace faults |
| git diff --check | Initial exit 1 exposed four trailing carriage returns from earlier writes; normalized those Markdown files to LF; final exit 0 with no output |
| git diff --stat / git diff --name-only / git status --porcelain --untracked-files=all | Eight tracked Markdown modifications; ten untracked Markdown files including initial two user documents; no non-documentation modification, staged commit or source/config scaffolding |
| Scoped rg ambiguity scan and Python full term inventory | No substantive TBD/TODO/maybe/potentially/eventually/perhaps/suitable/some-mechanism/future-work placeholder in current contracts. Remaining appropriate is a bounded paraphrase of NIST guidance; likely concerns learning-cycle mistakes; future/later refer to explicit artifacts/gates or already released plaintext. Generic/support/complete/all/any checked in their declared scope |
| Scoped rg gateway/proxy/reveal/strong-claim/checkbox scan plus manual cross-owner review | Historical dossier/ADR references and explicit alternatives remain labeled; transparent access does not mandate reveal; no active gateway-first, universal protection/erasure or unsupported production claim |
| Per-capability and original directive table assertions | C00..C32: 33 unique rows, zero completed runtime checkbox rows; sections 0..98: 99 unique requirement mappings |
| Candidate framing/name arithmetic | F1 header 108; W1 header 96; maximum F1 1,048,724; emitted role examples distinct and <=59 ASCII bytes (default PostgreSQL limit 63). Documentation arithmetic only, not executed codec/schema evidence |
| First-party full reads and adversarial integration | Seven requested perspectives supplied; material findings above reconciled. Human independent expert review remains C29, not implied by AI agreement |

Final content snapshot SHA-256 (sorted path:file-byte-SHA256 lines, excluding this audit
itself): `6e8b8019410c571d876158c08b51cea8b12b55631f237d643418781ff4db7a11`. This digest records
the checked working files. It is not a signature or commit. An edit to an included file changes
the digest. The checker source above defines the exact digest bytes.

The actual PowerShell invocation piped a single-quoted Python here-string into
`wsl -d Ubuntu --cd /home/debrato/Projects/cryptalis python3 -`. Its structural-check payload was:

```python
from pathlib import Path
s = Path('docs/documentation-claims-audit.md').read_text(encoding='utf-8')
code = s.split('<!-- DOC_CHECKER_BEGIN -->', 1)[1].split('```python\n', 1)[1].split('\n```', 1)[0]
exec(compile(code, 'audit-documentation-check', 'exec'))
```

The 2026-10-01 pass ran no runtime or package tests, crypto vectors, migrations, provider state
trials, or live scans. It did not independently replay capability evidence or check rendered
Mermaid diagrams or UI output. Documentation checks give no runtime assurance. Future artifacts
and gates remain pending.

This working record cannot satisfy a committed-evidence `[x]` or external review checkpoint. The
pass deleted no documentation and reset no unrelated initial edits. It made no commit or push.

## Fail-explicit policy and implementation audit

Audit date: 2026-10-04 UTC. Source baseline: `1b7eb66edeb413c9a35507954e6e224233165cdb`.
The working tree was clean before this documentation change.
The [playbook](../ENGINEERING_PLAYBOOK.md#fail-loudly-and-explicitly) now owns the strict policy.
Repository instructions, the build guide, architecture decisions, error contracts, review rules, and testing guidance refer to that owner.

The audit inspected all maintained Python source, exception handlers, entry points, subprocess calls, and relevant failure tests.
Eight read-only probes confirmed the findings below, including in-memory injection of an `EIO` filesystem failure.
No implementation, tests, configuration, dependency files, or fixtures were edited.
Medium means a material reliability, diagnostic, or automation contract gap. These findings do not establish a cryptographic compromise.
All three findings were open at this audit snapshot. The [follow-up](#cli-failure-corrections) records their subsequent correction.
No high or critical violation was confirmed in this bounded audit.

| ID / severity | File / location | Current behavior | Why it is dangerous | Recommended correction |
|---|---|---|---|---|
| F01 / Medium | [cli.py](../src/cryptalis/cli.py), `_read_manifest` lines 65–84, `_write_manifest_error` lines 120–142, `_inspect_command` lines 145–154 | Missing child/parent files, malformed JSON, invalid parent links, and operational I/O failures become the same `Manifest.Invalid`, exit 2, non-retryable record. The caught error supplies no safe stage, input role, or cause category | Users cannot locate the failed boundary. Automation cannot distinguish invalid data from operational unavailability. A fresh correlation ID has no associated diagnostic channel here | Retain typed cause categories internally. Emit safe operation, stage, and input role. Map operational unavailability to exit 4 and validation to exit 2. Preserve redaction of raw paths, values, and exception payloads |
| F02 / Medium | [cli.py](../src/cryptalis/cli.py), `_ArgumentParser.error` lines 22–29, JSON option lines 55–60, `main` line 162 | Argument errors print usage and a generic text error even with `--json`. A missing value after `--parent` exits 2 with non-JSON stderr | Machine consumers lose the stable error protocol at the argument boundary and need an undocumented text fallback | Route argument failures through the stable machine error envelope when JSON mode is requested. Supply a safe argument-stage category without echoing user values. Test malformed command arguments through the real CLI |
| F03 / Medium | [cli.py](../src/cryptalis/cli.py), parent option lines 50–54, `main` line 162 | Repeated `--parent` uses argparse's last value silently. A missing first parent followed by a valid second parent returns exit 0 and `manifest_parent_link`. Reversing their order returns exit 2 | The earlier requested input is ignored. Success hides an ambiguous validation request, and scripts can check a different parent than intended | Reject duplicate parent selectors before opening files. Keep the single-parent contract explicit. Add CLI regression cases for both orders and confirm no success output on rejection |

### Reproduction evidence

The probes used `.venv/bin/python -m cryptalis manifest inspect` against synthetic repository examples and a nonexistent temporary path.
The imported CLI resolved to `src/cryptalis/cli.py` in this checkout.
Every subprocess had a ten-second timeout and an explicitly checked return code.
Correlation IDs were excluded only from comparison. Actual error records still contain them.

| Probe | Observed result |
|---|---|
| Missing child, duplicate-key JSON, missing parent, invalid parent link | Four cases: exit 2, empty stdout, identical error fields apart from correlation ID |
| Injected `OSError(errno.EIO, "synthetic I/O failure")` at `cryptalis.cli.os.open` | Exit 2, empty stdout, the same invalid-input record |
| Genesis example with `--json --parent` and no parent value | Exit 2, empty stdout, usage and generic text on stderr |
| Successor example with missing then valid `--parent` values | Exit 0, `scope: manifest_parent_link`, empty stderr |
| Successor example with valid then missing `--parent` values | Exit 2, empty stdout, generic invalid-input record |

Manifest and candidate-envelope parsers already reject many malformed inputs with explicit exceptions.
The audit found no swallowed exception handler or ignored subprocess status in maintained source and tests.
The CLI tests use `subprocess.run(check=False)` and assert return codes. That pattern does not ignore failure.
Likewise, `raise ... from None` suppresses traceback display but does not delete Python's exception context.
Raw decoder exceptions can contain input bytes. Public redaction is valid, but safe cause and stage diagnostics remain necessary.
Database, provider, encryption/decryption, and background adapters are not implemented. Their new policy requirements remain future evidence gates.
This audit does not prove repository-wide production or security readiness.

### Documentation validation

The checks below ran on the documentation change. The runtime suite was not rerun.
Read-only failure probes establish these findings, not corrected behavior.

| Check | Observed result |
|---|---|
| `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python /tmp/cryptalis-fail-explicit-reproduce.py` | Eight asserted reproduction cases passed. The script was temporary and changed no repository implementation |
| Existing `DOC_CHECKER_BEGIN` block extracted and executed with `.venv/bin/python` | 20 Markdown files, 370 local links, zero link, anchor, case, fence, inline-code, control-byte, or whitespace faults |
| `git diff --check` | Exit 0, no output |
| SHA-256 comparison with the pre-edit snapshot | All 25 tracked non-Markdown files unchanged. Six changed paths, all Markdown |
| ASD-STE100 lint on the policy and audit draft | 1.25 findings per 100 words, below the 2.5 gate |

Checked Markdown snapshot, audit self excluded: `30a6437ecdcb9a7ca55875f1d5700a9f3307ff19af4592ef04bf740dbb1a29e1`.
This digest records file contents. It is not runtime or independent security evidence.

## CLI failure corrections

Follow-up date: 2026-10-04 UTC. The user explicitly authorized source and test edits for F01–F03.
The changes preserve the earlier documentation work and use source baseline `1b7eb66edeb413c9a35507954e6e224233165cdb`.
The old findings and probe results above describe the pre-fix snapshot.
Only [cli.py](../src/cryptalis/cli.py) and [test_cli.py](../tests/test_cli.py) changed outside Markdown.

| Finding | Current outcome | Regression evidence |
|---|---|---|
| F01 corrected | Safe operation, stage, input role, and cause fields distinguish argument, input, validation, link, and operational failures. Wrappers retain internal exception causes. Cleanup diagnostics retain a primary failure in both output modes | Missing child, invalid child/parent, rejected links, injected open/stat/read/close failures, and combined read/close failures. Permission denial after open returns 2. Operational failure returns 4. No failure result exposes seeded secrets |
| F02 corrected | Argument failures use the stable JSON error envelope when `--json` occurs before `--`. The terminator prevents path values from selecting JSON mode | Missing parent value before/after `--json`, unknown arguments/commands, and a literal option-shaped path after `--` |
| F03 corrected | Duplicate parent options reject before reading either input, including identical values and equals forms. Full option names are required | Both missing/valid parent orders, both option forms, and repeated identical parents |

The CLI suite first produced 21 expected failures and 17 passes against the old implementation.
A first-party review then identified two edge cases in the initial fix.
Stream cleanup could hide a read failure, and permission denial after open used the operational exit category.
New regressions reproduced both cases before their corrections. The final read-only review found no remaining important issue within this scope.
AI review is first-party. It does not satisfy independent security review.

| Verification actually run | Result |
|---|---|
| `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest tests/test_cli.py -q --tb=short` | 46 passed |
| `UV_CACHE_DIR=/tmp/cryptalis-uv-cache PYTHONDONTWRITEBYTECODE=1 uv run --locked pytest -q` | 246 passed |
| `UV_CACHE_DIR=/tmp/cryptalis-uv-cache uv build --offline --out-dir /tmp/cryptalis-cli-fix-dist` | Wheel and source archive built |
| `UV_CACHE_DIR=/tmp/cryptalis-uv-cache PYTHONDONTWRITEBYTECODE=1 .venv/bin/python /tmp/cryptalis-cli-fix-wheel-smoke.py` | Six console smoke cases passed in a clean temporary environment. Imports resolved to the installed wheel outside the checkout |

These corrections do not establish full semantic manifest validity, ancestry authentication, C25 completion, or production readiness.
Fault injection does not establish every real filesystem's outage or permission behavior.
No dependency, fixture, build configuration, CI, commit, or push changed.
The previous Ruff and mypy availability limits remain. This slice did not rerun those unavailable tools.

Final documentation checks covered 20 Markdown files and 375 local links, with zero faults.
`git diff --check` passed. Only `src/cryptalis/cli.py` and `tests/test_cli.py` changed outside Markdown.
The other 23 protected non-Markdown files match the pre-edit snapshot.
Neither Ruff nor mypy is present on PATH or in the project environment.
The documentation draft scored 1.39 findings per 100 words. The strict error-text draft scored 1.37.

Current source SHA-256:

- `src/cryptalis/cli.py`: `81025b8319426b2382db4a57812050b77305396c8b7660479cdd8827de8d8b00`
- `tests/test_cli.py`: `d120e9de85ecc0a268d6b842c68b40b1c29a15ebb4e5ad888fe936f0cc271d6a`

Current checked Markdown snapshot, audit self excluded: `909cdbb88cd214ea59a4842c6a6ccb8205753bdabab7abe514ac30d44e366413`.
These hashes identify the working files. They are not signatures or independent security evidence.

## Candidate W1 structural parsing

Slice date: 2026-10-04 UTC. Source baseline: `f9ac025092205bb7cd164759866a5e6d83fb7c7a`.
The user authorized one engineering slice with `next` under the production controller.
This slice adds the [private W1 parser](../src/cryptalis/crypto/_candidate_wrap.py),
[boundary tests](../tests/test_candidate_wrap.py), and [synthetic vector](../examples/envelopes/w1-structural.hex).
The [crypto owner](architecture/crypto-search-lifecycle.md#35-local-secret-wrapping-candidate-w1) retains the wire contract.

The parser checks the 96-byte header and exact 156/168-byte frame before it returns immutable fields.
It rejects unsupported selectors, invalid lengths, zero generations, truncation, and trailing bytes.
Physical input above 168 bytes rejects before header parsing. Errors identify W1 and the failed field without input bytes.
All byte fields stay outside `repr`. F1's candidate suite registry and typed error hierarchy remain shared and unchanged.

No authentication, ownership, freshness, key lookup, cryptographic operation, or secret release follows from successful parsing.

The first boundary run produced 41 expected failures because W1 parsing did not exist.
Three later diagnostic regressions failed before version, suite, and flags received separate safe messages.
A read-only first-party review found no important issue. Its separate offset oracle agreed on 46,232 adversarial inputs.
AI review does not satisfy independent security review or admission gates.

| Verification actually run | Result |
|---|---|
| `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest tests/test_candidate_wrap.py -q --tb=short` | 44 passed |
| `UV_CACHE_DIR=/tmp/cryptalis-uv-cache PYTHONDONTWRITEBYTECODE=1 uv run --locked pytest -q` | 290 passed |
| `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python /tmp/cryptalis-w1-differential.py` | Python and a separate Node offset parser agreed on 13,541 unique inputs, including 1,672 accepted structures. Seed `20261004`. Every accepted field matched |
| `UV_CACHE_DIR=/tmp/cryptalis-uv-cache uv build --offline --out-dir /tmp/cryptalis-w1-dist` | Wheel and source archive built |
| `UV_CACHE_DIR=/tmp/cryptalis-uv-cache PYTHONDONTWRITEBYTECODE=1 .venv/bin/python /tmp/cryptalis-w1-wheel-smoke.py` | Clean installed wheel passed two W1 frames, four typed rejection cases, and the existing parent-link console command outside the checkout |

The first installed smoke run passed W1 checks, then failed because the scratch script expected an absent CLI success field.
The corrected script checks the documented scope, revision, and parent digest. The complete installed run then passed.
The differential corpus and package smoke scripts are temporary local checks, not admitted cross-language conformance artifacts.
Differential corpus SHA-256: `df7d5daf7726af12f4fdbba4f7cb90d8065df1712b15f30bb9dd8859509e6355`.

All 25 pre-existing tracked non-Markdown files match the pre-edit snapshot.
Only the three linked additions change the tracked non-Markdown tree. Existing source, tests, dependencies, build configuration, and CI stay unchanged.
No commit or push occurred. Ruff and mypy remain absent from PATH and the project environment, so these checks did not run.

Authentication, authorized registry selection, format freeze, and G-CRYPTO/G-CROSSKEY/G-PROVIDER remain pending. C03 remains incomplete.

Documentation checks covered 20 Markdown files and 389 local links, with zero faults.
`git diff --check` passed. The documentation draft scored 1.53 findings per 100 words.
The final strict error-text draft scored 0.00.

Source and vector SHA-256 for this slice:

- `examples/envelopes/w1-structural.hex`: `d7eda7903401ce52bc67cbc01c3bd3bd02ac05b78d1ffaef66743c4eb04440c9`
- `src/cryptalis/crypto/_candidate_wrap.py`: `18cd89777178a5938848c51d47b48603dab902f57e83a6b330a8643f92748dc4`
- `tests/test_candidate_wrap.py`: `85aa66f3e2ed625e20f13eedc1a41b38049c0ef4b9815928c878f9b943ba8457`

Checked Markdown snapshot, audit self excluded: `c708aeb51b835fe59663860625e46aa416312782de15e6f878a0aaa68993b7b7`.
These hashes identify local working files. They are not signatures or independent security evidence.

## Candidate scalar syntax decoding

Slice date: 2026-10-04 UTC. Starting committed baseline: `f9ac025092205bb7cd164759866a5e6d83fb7c7a`.

W1 commit `9afeb0dde1878ac23d67db78f1fef3021b81cbc2` became visible during this slice.
The starting tree contained the uncommitted W1 slice. Its parser, tests, and vector remain byte-identical to that starting tree.
The user authorized one new slice with `next`. This slice adds the [private scalar decoder](../src/cryptalis/crypto/_candidate_scalar.py),
[boundary tests](../tests/test_candidate_scalar.py), and [synthetic vectors](../examples/scalars/candidate-vectors.json).
The [crypto owner](architecture/crypto-search-lifecycle.md#implemented-scalar-syntax-boundary) retains the syntax contract.

The decoder admits exactly four implemented selectors, including for null. It checks exact framing and size limits before typed conversion.
Integer digit arithmetic avoids ambient string-conversion limits. Decimal tuple construction preserves sign, exponent, and trailing zeros without context rounding.

Malformed input returns typed, redacted failures. UTF-8 wrapping retains the original cause.
Host diagnostics must not serialize exception attributes or local values because the cause retains input bytes.

The first boundary run produced 75 expected failures because scalar decoding did not exist.
Read-only first-party review found no important issue and passed 75 focused tests plus 12,003 additional adversarial checks.
Two maintenance observations led to explicit decimal dispatch and a decoder-local selector allowlist.
Those changes prevent future registry growth from admitting unimplemented value or null syntax.
AI review does not satisfy independent security review or admission gates.

| Verification actually run | Result |
|---|---|
| `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest tests/test_candidate_scalar.py -q --tb=short` | 75 passed |
| `UV_CACHE_DIR=/tmp/cryptalis-uv-cache PYTHONDONTWRITEBYTECODE=1 uv run --locked pytest -q` | 365 passed after final source changes |
| `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python /tmp/cryptalis-scalar-differential.py` | Python and an independent Node decoder agreed on 38,483 unique inputs, including 3,426 accepted values. Seed `20261004`. Types and complete representations matched |
| `UV_CACHE_DIR=/tmp/cryptalis-uv-cache uv build --offline --out-dir /tmp/cryptalis-scalar-dist` | Wheel and source archive built |
| `UV_CACHE_DIR=/tmp/cryptalis-uv-cache PYTHONDONTWRITEBYTECODE=1 .venv/bin/python /tmp/cryptalis-scalar-wheel-smoke.py` | Clean installed wheel passed 15 fixed vectors, six typed rejection cases, and the existing parent-link console command outside the checkout |

The initial Node comparison failed because JavaScript negation produced exponent `-0` from integer scale zero.
The scratch oracle now represents that integer exponent as `0`. Decimal value sign remains a separate preserved field.
No repository decoder change addressed that comparison failure. The complete comparison then passed.
The corpus and package smoke scripts are temporary local checks, not admitted conformance artifacts.

Corpus SHA-256: `16111335bf4f5171ce42f9143faca032b354b3aecd5f92acd97f4063bb705ba2`.

All 28 pre-existing non-Markdown files match the starting snapshot, including the three W1 files.
Only three new files extend the non-Markdown tree. Existing dependencies, build configuration, CI, and implementation files remain unchanged.
This assistant did not commit or push. Ruff and mypy remain absent from PATH and the project environment, so these checks did not run.

Encoding, catalogue admission, descriptor matching, field-specific constraints, authentication, and release authority remain pending.
No public API, CLI command, format freeze, or production claim follows. C03 and G-CRYPTO remain incomplete.
Documentation checks covered 20 Markdown files and 403 local links, with zero faults. `git diff --check` passed.
The documentation draft scored 0.99 findings per 100 words. The strict error-text draft scored 0.00.

Source and vector SHA-256 for this slice:

- `examples/scalars/candidate-vectors.json`: `8028c66f120118c3bf0de9f93aeeca23da5c5893624b44c5a16a52e74ca33be9`
- `src/cryptalis/crypto/_candidate_scalar.py`: `e45a720969fab7abcd4df70ac005eeb8336e23fcd05e94b45330eb85b7f6e831`
- `tests/test_candidate_scalar.py`: `7abb934f9ce8241a1f273d4ee742c74a00002ccfc82ad78b177794791f0f4bb7`

Checked Markdown snapshot, audit self excluded: `a007735aa6a43ff99313a3cee8a71a298c475e9fa2b045a9a42ca8e510171bf0`.
These hashes identify local working files. They are not signatures or independent security evidence.

## Authoritative handoff reconciliation — 2026-10-05

Scope: the supplied 2026-10-05 architecture handoff and its ordered file-by-file patch plan, documentation only.
Fourteen planned documents already contained local edits at entry. This pass preserved them and refined nine documents in plan order.
The historical `SESSION_HANDOFF.md` remains byte-identical. This audit records observations and supplies no normative runtime contract.

The [P0 register](architecture/README.md#p0-documentation-review-register) links each reconciled blocker to its canonical owner.
Every P0 review remains pending. [Q1–Q10](architecture/README.md#unresolved-research-questions) remain open.
No researcher, provider, suite, target-identity source, ORM strategy, or retention default was selected.
No documentation or runtime gate was promoted to reviewed, closed, or supported.

Refinements clarify internal crypto visibility, planned-effect reconciliation, irreversible-only approval, and future lifecycle substates.
CI exceptions cannot bypass the P0/Q1–Q5 blockers. Summaries link to canonical owners.
The checklist and build guide retain the C33–C40 order. Online, search, fleet, and broad assurance remain later gates.

| Check actually run | Result and limit |
|---|---|
| Existing `DOC_CHECKER_BEGIN` block extracted and executed with `python3` | PASS. Local paths, case, heading anchors, fences, inline code, control bytes, and whitespace checked. Final raw totals appear below |
| `git diff --check` | Exit 0, no output |
| SHA-256 comparison against the entry snapshot | Only nine planned Markdown files changed before this audit append. Source, tests, fixtures, packaging, locks, build/CI configuration, and other files remained unchanged |
| Exact comparison with entry copies | README implementation-status prose, checklist implementation passages, C00–C32 rows, existing fenced examples, and historical handoff remained byte-identical |
| ASD-STE100 lint on added prose, before repository writes | Exit 0. 653 words, 9 findings, 1.38 per 100 words. Existing checklist prose scored 3.79. Preserved evidence rows were not rewritten |
| Selected official-page rechecks | Documented-only. Session event scope, restore code-execution warning, AEAD commitment distinctions, artifact attestations, and SLSA provenance. No executable support evidence |
| Runtime tests, build, provider trials, migration/restore/decommission execution | Not run. This documentation pass supplies no new runtime or independent security evidence |

Official rechecks used [SQLAlchemy Session events](https://docs.sqlalchemy.org/en/20/orm/session_events.html) and [PostgreSQL 18 pg_restore](https://www.postgresql.org/docs/18/app-pgrestore.html).
Composition/provenance rechecks used [Tink AEAD](https://developers.google.com/tink/aead), [PyPA index-hosted attestations](https://packaging.python.org/en/latest/specifications/index-hosted-attestations/), and [SLSA provenance v1.2](https://slsa.dev/spec/v1.2/provenance).
The attempted PyPA `/specifications/digital-attestations/` path returned a tool retrieval error. It supplied no evidence.
The existing ledgers retain broader dated research provenance. These rechecks do not redate their other observations or answer Q1–Q5.

Final documentation snapshot SHA-256, audit self excluded: `606511cfca4957f95d68c302fa9487f2732449d2eedbfeec98badd02c6ac3ddb`.

Final raw documentation-check output:

```text
Markdown files=20; local links=488; faults=0
Snapshot SHA256 (audit self excluded)=606511cfca4957f95d68c302fa9487f2732449d2eedbfeec98badd02c6ac3ddb
```

Final hash-boundary result: ten Markdown files changed relative to entry, including this audit append.
All recorded non-documentation hashes remained unchanged. The historical handoff and implemented-status comparisons passed.
Seven P0 documentation reviews remain pending. Q1–Q10 remain open.

## Full documentation review and plaintext approval correction — 2026-10-05

Scope: all 19 maintained Markdown files, with parallel first-party reviews of independent documentation owners.
The entry snapshot contained 15 modified Markdown files. Existing work and historical verification records remain intact.
This pass changes the shared approval contract, ORM execution contract, and this audit only.
No runtime implementation or external-source verification occurred.

### Findings and disposition

Locations below refer to the entry snapshot. These are proposed-contract gaps, not demonstrated runtime vulnerabilities.

| ID / severity | File / location | Current behavior | Danger | Recommended correction / disposition |
|---|---|---|---|---|
| DR01 / P1 | [Shared approval](architecture/manifest-context-api.md#plan-record-approval-and-receipt-schema), lines 168–169. [ORM phases](architecture/orm-schema-migration.md#migration-state-machine-and-concurrency), lines 578–580. [Deprotect](architecture/orm-schema-migration.md#deprotect-decommission-and-finalization), lines 619–622 | Approval centers on SWITCH. Temporary plaintext needs prior approval only if it broadens access | Unchanged application grants can disguise new plaintext exposure through staging, WAL, replicas, or backups | Require approval before first persistence. Bind exposure paths and SWITCH scope. Corrected in the canonical contracts. Runtime evidence remains pending |
| DR02 / P2 | [Assurance interfaces](architecture/assurance-evidence.md#2-typed-interfaces-and-version-boundary), line 105. Bundle inventory, lines 587 and 606 | Bundle inputs and inventory assume a graph despite graph-free initial evidence | An exporter can reintroduce advanced Graph as a prerequisite for the first transition | Define bundle profiles and explicit optional graph disposition. Preserve mandatory receipts and artifacts. OPEN |
| DR03 / P2 | [Assurance evidence](architecture/assurance-evidence.md), lines 67 and 376 | Collector prose names documented and operator-attested bases. The assertion enum omits both | A producer can reject required attestations or mislabel them as observed evidence | Define provenance layers or versioned basis entries with attestor, scope, interval, and limits. OPEN |
| DR04 / P2 | [ORM reproduction queue](research/orm-platform-evidence.md#reproduction-queue), lines 180 and 185–187 | The queue starts with C33–C40 but then instructs every G-ORM-1 through G-ORM-10 | Later search, async, and online gates can obscure the first offline no-search sequence | Separate applicable initial-profile gates from later comparison experiments. OPEN |

### Contract acceptance cases

These are paper-review cases for DR01. They define required future failure-path evidence, not executed runtime tests.

| Case | Required contract result |
|---|---|
| No approval, unchanged application grants, plaintext shadow in TRANSFORM | Explicit refusal before the first plaintext write |
| Approval missing, expired, wrong-target, or missing staging scope | No further plaintext persistence or publication |
| Valid approval names staging and SWITCH | Both actions stay within the exact scope. No approval prompt per chunk |
| Approval covers staging only | SWITCH refuses application publication until exact publication approval exists |
| Crash after first plaintext commit or ambiguous approval disposition | Preserve exposure obligations. Reconcile durable effects before resume. Unknown disposition cannot authorize work |

Q1–Q10 remain OPEN. All seven P0 review dispositions remain pending.
This first-party correction selects no authority backend, suite, provider, ORM strategy, or target-identity source.
Future runtime admission still requires researched Q1–Q5 closure and the P0 review gate.

### Verification actually run

| Check | Result and limit |
|---|---|
| Existing `DOC_CHECKER_BEGIN` block with `python3` | Exit 0. 20 Markdown files including the generated pytest-cache README, 495 local links, zero faults |
| `git diff --check` | Exit 0, no output |
| Entry SHA-256 comparison | Exactly three Markdown files changed. No new maintained files. All other 47 entry files remained byte-identical. Historical audit text remains an exact prefix |
| `UV_CACHE_DIR=/tmp/cryptalis-uv-cache PYTHONDONTWRITEBYTECODE=1 uv run --locked pytest -q` | Exit 0. 365 passed in 1.98 seconds. Existing runtime regression evidence only. No transition engine exists to test these approval cases |
| Added prose lint before writes | STE-flavored: 805 words, 8 findings, 0.99 per 100 words |
| Whole-draft strict lint | Exit 1 at the 1.5 target. Score 1.99, including eight dash markers in dates, location ranges, and question IDs. Preserve those references |
| Safety-contract strict lint | Exit 0. 351 words, zero findings, 0.00 per 100 words. This scoped draft excludes the audit's historical references |

Documentation snapshot SHA-256, audit self excluded: `6305959a32b5cf0088ff95f0dec950c6b01931face9e4b659c7ad634a43278b3`.
These checks do not test plaintext persistence, approval consumption, or transition recovery.
No commit or push occurred.

A separate first-party AI reviewer compared the correction against entry copies and the canonical owners.
The reviewer found no substantive issue in approval timing, action scope, retry reconciliation, or preserved exposure obligations.
DR02–DR04 remain fair unresolved findings. This review supplies no independent security admission or runtime evidence.

## Graph-optional bundle contract correction — 2026-10-05

Entry: clean tree at `b26b72b`. Scope: DR02, documentation only.
The [canonical bundle contract](architecture/assurance-evidence.md#bundle-profiles-and-graph-disposition) now declares versioned profiles and explicit graph disposition.
The transition profile uses scoped evidence without Graph. The graph profile requires its graph artifact and construction receipts.
Consumer policy prevents profile downgrade. Export preserves failed, inconclusive, and unselected outcomes.
Missing required evidence produces an explicit failure. Integrity validation never establishes protection success.

DR02 is corrected at the contract level. Implementation and G-A08 evidence remain pending.
DR03 and DR04 remain OPEN. Historical audit dispositions retain their original scope.
All seven P0 reviews remain pending. Q1–Q10 remain OPEN.
No runtime source, test, configuration, dependency, or build file changes belong to this slice.

### Contract acceptance cases

These are paper-review cases. No bundle implementation exists to execute them.

| Case | Required contract result |
|---|---|
| `transition` bundle with all required evidence and graph `not_selected` | Graph is NOT_RUN. Validate scoped evidence without invoking Graph. No graph-based conclusion |
| Graph-required consumer receives a valid `transition` bundle | Explicit policy refusal despite valid hashes or signatures |
| `graph` bundle omits its required artifact or construction receipt | Explicit member failure. Preserve diagnostics. No complete bundle or successful CI interpretation |
| Selected graph construction fails | Preserve actual failure and dependent INCONCLUSIVE/FAIL. Never substitute `not_selected`, a clean graph, or PASS |
| Profile/version absent, unknown, or selection contradictory | Explicit validation refusal. No default profile |
| Export attempts to remove graph requirements or change profile | Refuse the downgrade. Preserve canonical selection, coverage, and outcomes |

### Verification actually run

| Check | Result and limit |
|---|---|
| Existing `DOC_CHECKER_BEGIN` block with `python3` | Exit 0. 20 Markdown files including the generated pytest-cache README, 497 local links, zero faults |
| `git diff --check` | Initial exit 2 identified an extra blank line at EOF. The correction removed it. Final exit 0, no output |
| Entry SHA-256 comparison | Exactly two Markdown files changed. All other 48 maintained files remained byte-identical. No new maintained files. Historical audit text remains an exact prefix |
| Added prose lint before writes | STE-flavored: 611 words, 5 findings, 0.82 per 100 words |
| Profile-contract strict lint before writes | Exit 0. 266 words, 1 finding, 0.38 per 100 words |
| Runtime tests, bundle production/import/export, external research | Not run. This documentation-only slice changes no executable behavior. Paper cases are not runtime evidence |

Documentation snapshot SHA-256, audit self excluded: `08bd78ff1d53c69d1539863cd6a4cd567cd92e05be933b9ae4862a06ce79f8a6`.
These checks do not complete G-A08 or admit EvidenceBundle support.
No commit or push occurred.

A separate first-party AI reviewer checked the exact diff, StageReceipt outcomes, required coverage, inventories, and signature policy.
The reviewer found no substantive issue. This review supplies no independent security admission or executable support evidence.

## CLI output delivery correction — 2026-10-05

Entry: `b26b72b`, with the graph-profile assurance owner and audit edits still uncommitted.
This code slice preserves those edits and fixes existing CLI output delivery only.
It does not depend on an unresolved crypto, database, provider, or transition selection.

The entry CLI did not check final output flush or write counts.
Real full devices and closed pipes returned Python shutdown exit 120 instead of the operational code.
Missing stdout could silently discard results. Closed streams exposed uncaught exceptions.

The [inspector](../src/cryptalis/cli.py) now checks writes and flushes for result, help, and diagnostic output.
Safe failures identify the output channel, boundary, and symbolic cause under `CLI.OutputUnavailable`.
Unavailable stderr leaves exit 4 as the observable channel.
Native shutdown cleanup has a defined disposal contract and preserves failure.
Native close can attempt another flush.
The [canonical CLI owner](architecture/manifest-context-api.md#cli-and-configuration) documents partial output and terminal-descriptor side effects.

The [failure tests](../tests/test_cli.py) exercise real full devices and closed pipes, plus missing/closed streams and short writes.
A reviewer found descriptor reuse during cleanup. A failing subprocess regression reproduced that defect before correction.
The replacement descriptor now stays stream-owned when opening the null sink reuses the target.
Injected null-open and descriptor-duplication failures retain the original output diagnostic and still return an operational failure.

Primary reference: [Python's SIGPIPE guidance](https://docs.python.org/3/library/signal.html#note-on-sigpipe), accessed 2026-10-05.
It recommends explicit flush and null-sink redirection to prevent a second shutdown failure.
Cryptalis applies its own exit 4 and safe-diagnostic contract. This source does not prove Cryptalis behavior.

### Boundaries and remaining work

The 20 new tests protect output failures. They do not establish destination receipt or filesystem durability.
Full-device fixtures require `/dev/full`. The recorded run used Linux and CPython 3.12.3.
Arbitrary custom-stream finalizers and other operating systems lack this executable evidence.
No new public command, semantic manifest validation, authenticated authority, cryptography, ORM, or transition behavior was added.
C25 and release admission remain incomplete. Q1–Q10 and all seven P0 reviews remain open or pending.
DR03 and DR04 remain OPEN. The preceding graph-profile correction retains its existing scope.

### Verification actually run

| Check | Result and limit |
|---|---|
| Initial output regressions before implementation | 10 failures. Real full devices and closed pipes returned exit 120. Both failed diagnostic cases also returned 120 |
| Missing-stream cases before correction | Two failures with AttributeError. The short-write regression also failed against the entry source, which returned 0 |
| Closed-stream cases against the entry source | Two failures with uncaught ValueError |
| Review-driven descriptor and cleanup cases | Three failing cases before correction. Descriptor reuse and failed duplication could restore exit 120. Final implementation preserves descriptor ownership and closes failed native buffers |
| Text cleanup-chain regression | Two failures before correction. Original output stage and cause were absent from text. Both modes now retain them |
| `UV_CACHE_DIR=/tmp/cryptalis-uv-cache PYTHONDONTWRITEBYTECODE=1 uv run --locked pytest -q` | Exit 0. 385 passed in 2.38 seconds. Current Linux/CPython evidence only |
| `UV_CACHE_DIR=/tmp/cryptalis-uv-cache uv build --offline --out-dir /tmp/cryptalis-cli-output-dist` | Exit 0. Wheel and source archive built. Temporary artifacts are local validation, not admitted release evidence |
| Clean temporary environment and offline wheel installation | Installed the rebuilt wheel. Console and installed-module checks passed 13 cases from `/tmp`, outside the checkout. Success, full device, closed pipe, failed stderr, descriptor reuse, and injected null-open/duplication failures checked |
| Existing documentation checker | Exit 0. 20 Markdown files including the pytest-cache README, 502 local links, zero faults |
| `git diff --check` and entry hashes | Exit 0. Six intended files changed. All other 44 maintained files remained byte-identical. The existing assurance-owner edit and historical audit prefix remain intact |
| Added documentation lint before writes | STE-flavored: 744 words, 3 findings, 0.40 per 100 words. Strict output contract: 179 words, 1 finding, 0.56 per 100 words |
| Disposal wording refinement | Initial strict score 3.57 failed the 1.5 target. Corrected wording scored 0.00. Native close-time flush remains explicit |
| Ruff and mypy | Unavailable on PATH. These checks did not run |

Separate first-party AI review found descriptor ownership and disposal wording issues.
The correction adds descriptor and text-chain regressions and narrows the disposal claim.
Review supplies no independent security admission. Source tests and local installed-wheel smoke checks establish only this bounded CLI behavior.
The assistant did not commit or push.
HEAD advanced to `b43c857`, which records the preceding graph-profile correction. Those entry contents remain intact.

## Candidate scalar syntax encoding — 2026-10-05

Entry: `799203e`, with a clean worktree. The user supplied the production engineering controller and requested continuation from the current state.
That request authorized one direct implementation slice. No commit or push occurred.

The [private scalar codec](../src/cryptalis/crypto/_candidate_scalar.py) now encodes the four existing candidate entries.
The [crypto owner](architecture/crypto-search-lifecycle.md#implemented-scalar-syntax-boundary) defines the boundary.
The encoder closes the decoder-only syntax gap while Q1–Q5 and P0 runtime reviews remain open.
It adds no encryption, field-policy admission, new catalogue entry, public API, or command.
Existing wire vectors and decoding behavior remain unchanged.

### Invariants and adversarial review

Selectors reject before null encoding. Exact types prevent bool, subclasses, mutable buffers, and accidental coercion.
State and length framing preserve null versus empty values. Unicode content, leading U+FEFF, integer signs, and decimal representation remain exact.
Encoded output contains unprotected values and grants no authorization.

Bounds precede integer digit extraction and decimal digit-tuple extraction.
Decimal validation quantizes to the input's own exponent under a private explicit precision and exponent context.
It never rounds to a different exponent. The scale check still rejects representations outside the candidate range.
The context admits the largest valid adjusted exponent and preserves negative zero and trailing zeros.
Ambient precision, traps, flags, clamping, and integer conversion limits do not select the wire bytes.

Manual first-party adversarial review checked coercion, null bypass, byte versus character limits, coefficient overflow, signed zero, and ambient context changes.
A 100,000-digit coefficient with a canceling exponent rejected before large digit-tuple conversion.
The local `tracemalloc` trial measured a 1,344-byte peak after caller-owned input construction.
This observation does not measure native allocations or establish a general performance bound.

Safe exception messages exclude supplied values. Unicode wrapping retains its original cause under the existing failure contract.
Exception attributes, traceback locals, and returned plaintext bytes still require host diagnostic controls.
No independent security review or supported runtime claim follows.

Primary references, accessed 2026-10-05: [Python Decimal quantize](https://docs.python.org/3.12/library/decimal.html#decimal.Decimal.quantize)
and [integer string-conversion limits](https://docs.python.org/3.12/library/stdtypes.html#integer-string-conversion-length-limitation).
These sources explain the dependency behavior. They do not prove Cryptalis behavior.

### Verification actually run

| Check | Result and limit |
|---|---|
| Entry `uv run --locked pytest -q` | Exit 0. 385 passed |
| Encoder regressions before implementation | 69 expected failures because the encoder was absent. The 75 existing scalar tests passed |
| `.venv/bin/python -m pytest tests/test_candidate_scalar.py -q --tb=short` | Exit 0. 144 passed. Fifteen fixed vectors, type rejection, exact limits, ambient context, and 800 seeded typed round trips |
| `.venv/bin/python -m pytest -q` | Exit 0. 454 passed on Linux/CPython 3.12.3 |
| `.venv/bin/python /tmp/cryptalis-encode-differential.py` | Independent Node encoder matched 2,065 cases, including 2,028 accepted values. Seed `20261005`. Exact bytes and rejection classes matched |
| `UV_CACHE_DIR=/tmp/cryptalis-uv-cache uv build --offline --out-dir /tmp/cryptalis-scalar-encode-dist` | Exit 0. Wheel and source archive built |
| `.venv/bin/python /tmp/cryptalis-encode-wheel-smoke.py` | Clean offline wheel installation outside the checkout passed 15 encode/decode vectors, ten typed rejections, two ambient-context checks, and the parent-link console command |
| Documentation checks and `git diff --check` | Local links, anchors, fences, whitespace, and the final diff checked. No faults |
| Added documentation prose lint before writes | STE-flavored score 0.76 per 100 words. Audit prose checked separately |
| Ruff, mypy, Hypothesis | Absent from PATH or the project environment. Ruff and mypy did not run. No Hypothesis claim follows from the finite seeded corpus |

One later uv invocation failed because its default cache was read-only.
Verification then used the existing Python environment and a writable temporary uv cache.
No dependency, build configuration, migration, or CI file changed.

The independent byte implementation is an ad hoc first-party Node script, not an externally reviewed implementation.
Corpus SHA-256: `65b108838e96e3a76e570f37517d0bb28a5111b9773aca4aa58b51b2f604b3a2`.
Scripts and artifacts under `/tmp` are temporary checks. Fixed vectors and behavioral regressions remain in repository tests.
This evidence does not close G-CRYPTO, C03, C34, full cross-language fuzzing, or the release gate.

## Bounded manifest ancestry-chain validation - 2026-10-05

Entry: `94b0f19`, with a clean worktree. The production engineering controller authorized one direct implementation slice. No commit or push occurred.

The internal `validate_manifest_history` helper checks one complete genesis-to-head sequence. It requires a nonempty tuple of immutable byte strings. The first document must be revision 0. Each later document must keep the manifest ID, increase the revision, and name the canonical digest of the preceding document. Revision gaps remain valid under the current contract.

The validator checks the 4,096-document and 16 MiB aggregate limits before it parses any member. It then uses the existing bounded header decoder and domain-separated digest helper. It returns only the validated head header. Failure raises `ManifestInvalid` with a fixed diagnostic that does not contain supplied content.

This helper detects a missing genesis document, a missing intermediate document, reordering, mixed identities, decreasing revisions, and content substitution. Exact tuple and byte requirements prevent mutation of the supplied container or members during validation. A strict revision increase also prevents a linked cycle within one accepted sequence.

The helper supplies structural consistency only. It does not validate the complete semantic schema, authenticate a chain, select the current authorized head, or detect an omitted later revision. An attacker can construct a different internally consistent history. Q1 and G-ACTIVE still own the authority backend, trusted head, rollback protection, and recovery evidence. The change does not activate policy or add cryptography, database I/O, ORM behavior, or a CLI command.

### Verification actually run

| Check | Result and limit |
|---|---|
| Focused RED test before implementation | Collection failed because `validate_manifest_history` did not exist |
| `.venv/bin/python -m pytest tests/test_manifest_header.py -q --tb=short` | Exit 0. 31 tests passed after implementation |
| `UV_CACHE_DIR=/tmp/cryptalis-uv-cache PYTHONDONTWRITEBYTECODE=1 uv run --locked pytest -q` | Exit 0. 467 tests passed in 3.21 seconds on Linux and CPython 3.12.3 |
| Final repeat of the complete suite | Exit 0. 467 tests passed in 2.56 seconds |
| `UV_CACHE_DIR=/tmp/cryptalis-uv-cache uv build --offline` | Exit 0. The source archive and wheel built in a temporary directory |
| Clean temporary environment and offline wheel installation | The installed wheel accepted a two-document chain with a skipped revision number |
| Existing documentation checker | Exit 0. 20 Markdown files, 506 local links, and zero faults |
| Added documentation prose lint | STE-flavored score 1.17 per 100 words. The audit draft scored 0.80 |
| `git diff --check` and final diff review | Exit 0 after the final audit update. Ten intended files changed, with no unrelated file |
| Ruff and mypy | Not installed on PATH or in the project environment. These checks did not run |

First-party adversarial review checked mutation, empty and truncated histories, revision gaps, chain substitution, limit ordering, cycles, and diagnostic leakage. It found no unresolved issue within this structural scope. This review is not independent security review and does not complete G-MANIFEST, G-ACTIVE, C01, C33, or the release gate.

## Structural ActiveState kernel - 2026-10-05

Entry: `ed19c1f`, with a clean worktree. The user replied `next` and authorized one C33 slice. No commit or push occurred.

The private `cryptalis.contracts.active_state` module adds an immutable structural header, a domain-separated content digest, one-link checks, and bounded complete-history checks. The header binds the protection domain, authority revision, active manifest identity, active manifest revision and digest, schema generation, and current operation ID.

The parser requires immutable bytes and canonical UUID and digest forms. Authority revision 0 is genesis. Later authority revisions require a parent digest. Successors keep the protection domain and manifest ID. Authority revisions increase. Active manifest revisions and schema generations never decrease. A fixed manifest revision has one digest, and different manifest revisions cannot reuse one digest.

The history validator requires an immutable nonempty tuple. It checks the 4,096-document and 16 MiB aggregate limits before parsing. Fixed diagnostics do not include supplied values. The underlying parser cause remains available for local debugging. Traceback-local redaction remains a host diagnostic responsibility.

The synthetic examples define a genesis state and one authorization-only successor. Node and Python produced the same genesis digest: `24ec34f029d1939dd354bf5df28a2ac1e5f0a39cebae0ce161798bff9ab3512d`.

This kernel does not authenticate state, select the current head, implement compare-and-swap, supply durable idempotency, activate policy, access files, or mutate a database. A database snapshot or attacker can hold another internally consistent chain. Q1 and G-ACTIVE remain open. C33 remains incomplete.

### Verification actually run

| Check | Result and limit |
|---|---|
| Focused RED run | 42 expected failures because `cryptalis.contracts` did not exist |
| `.venv/bin/python -m pytest tests/test_active_state.py -q --tb=short` | Exit 0. 51 focused tests passed |
| `UV_CACHE_DIR=/tmp/cryptalis-uv-cache PYTHONDONTWRITEBYTECODE=1 uv run --locked pytest -q` | Exit 0. 518 tests passed in 2.96 seconds on Linux and CPython 3.12.3 |
| Independent Node digest check | The fixed genesis digest matched the Python result |
| `UV_CACHE_DIR=/tmp/cryptalis-uv-cache uv build --offline` | Exit 0. The wheel and source archive built in a temporary directory |
| Clean temporary environment and offline wheel installation | The installed wheel accepted a valid history and rejected a cross-domain successor |
| Ruff and mypy | Not installed on PATH or in the project environment. These checks did not run |

First-party adversarial review checked domain substitution, manifest substitution, authority rollback, schema rollback, inconsistent revision/digest pairs, content substitution, mutable input, size/count exhaustion, cycle prevention, and diagnostic leakage. It found no unresolved issue within this structural scope. This review is not independent security review or production authority evidence.

The final review corrected the rollback fixture so its valid baseline uses a new digest with a new manifest revision.
The complete suite then passed 518 tests in 3.00 seconds.
The documentation checker reported 20 Markdown files, 512 local links, and zero faults before this final clarification.
Added contract prose scored 0.82 findings per 100 words. The audit draft scored 1.36.
Complete ActiveState semantics remain pending, including readable formats, the write tuple, lifecycle epochs, and operation transitions.

## Process-local development authority - 2026-10-05

Entry: `2c7e5ed`, with a clean worktree. The user replied `continue` and authorized one C33 slice.
No commit or push occurred.

The private `cryptalis.contracts.development_authority` module loads only a structurally valid,
bounded ActiveState history. It returns frozen snapshots and immutable history. Its
compare-and-swap operation holds one process-local lock through expected-head comparison,
successor validation, bounded history validation, and publication.

Validation failure leaves the head unchanged. One exact retry after a lost success response
returns the current snapshot without appending a duplicate entry. A different successor from the
same old head fails as stale. Two threads that race with different successors cannot both win.
An unrelated stale expectation fails before proposal parsing. Fixed diagnostics exclude supplied
bytes and digest values.

The RED run collected 11 failures because the module did not exist. After implementation, 62
focused ActiveState and development-authority tests passed. The complete suite passed 529 tests
in 2.90 seconds on Linux and CPython 3.12.3.

`uv build --offline` produced the source archive and wheel. A clean temporary environment
installed the wheel. From outside the checkout, it loaded the fixed genesis vector, applied the
fixed successor, retried the same request, and confirmed one successor entry. The installed
snapshot reported authority revision 1 and digest
`ca395dddc1950be3c73f0562f7517f7570d9051fa4b8212f9a813ebddc7671e3`.

The documentation checker reported 20 Markdown files, 514 local links, and zero faults.
The added development-authority prose scored 0.58 findings per 100 words in STE-flavored lint.

First-party security review checked invalid initial state, mutable input rejection through the
structural kernel, failure atomicity, stale-before-parse ordering, diagnostic redaction, competing
writers, exact retry, and package installation. It found no unresolved defect within the stated
process-local scope. This is not independent security review.

The adapter does not authenticate writers or state. It does not persist state or idempotency,
coordinate processes, survive restart or restore, detect an omitted later head, resist host
rollback, activate policy, execute transitions, access a database, or add a public command. Q1,
G-ACTIVE, C33, and the release gate remain open.

## Private transition-plan admission - 2026-10-05

Entry: `2c7e5ed`, with the preceding development-authority slice still uncommitted. The user
replied `continue` and authorized one more C33 slice. No commit or push occurred.

The private `cryptalis.contracts.transition` module adds frozen in-memory plan and observation
records. The plan binds IDs, a declared kind, the offline strategy, a UTC validity window, the
protection domain, the source ActiveState revision and digest, the desired manifest digest, and
an opaque target identity. The target bytes stay out of record representations.

The admission check validates every record field before it compares current facts. It rejects
unknown kinds, a non-offline strategy, an invalid validity window, unsafe counters, mutable or
oversize target identity, hostile time-zone objects, expiry, a pre-creation observation, wrong
domain or target, and a stale ActiveState head. Fixed diagnostics do not include supplied values.

The first RED run produced 40 expected import failures because the module did not exist. The
first GREEN run passed 102 focused checks. Adversarial review then added four failing cases for a
hostile time-zone object, a pre-creation observation, and unsafe plan and observation counters.
After the fix, 106 focused ActiveState, development-authority, and transition checks passed.

The complete suite passed 573 tests in 4.06 seconds on Linux and CPython 3.12.3.
`uv build --offline` produced the source archive and wheel. A clean temporary environment installed the
wheel and admitted a matching synthetic offline plan from outside the checkout.

The documentation checker reported 20 Markdown files, 516 local links, and zero faults.
`uv lock --check` and `git diff --check` returned exit 0. Ruff and mypy were not installed, so
those checks did not run.

The added transition prose scored 0.88 findings per 100 words in STE-flavored lint.

First-party adversarial review checked time handling, exclusive expiry, target replacement,
cross-domain use, stale authority, mutable input, bounded identity bytes, unsupported strategy,
safe counters, immutable records, and diagnostic redaction. It found no unresolved defect within
this private contract scope. This review is not independent security review.

The opaque target identity has no implemented resolver or production trust source. The module
does not serialize or authenticate a plan, compute its digest, validate the complete schema,
acquire a lock, execute a phase, record approval or receipt, access a database, or mutate state.
Q5, G-PLAN, C33, and the release gate remain open.

## Terminal manifest-history inspection - 2026-10-05

Entry: `2c7e5ed`. Development-authority and transition-plan files and their documentation were
already uncommitted. This slice preserves those files. No commit or push occurred.

The user authorized direct implementation of one coherent slice with a terminal demonstration.
The selected slice exposes the existing structural history validator through a read-only command.
Dependent cryptography and database work still require the unresolved research and review gates.

Acceptance requires genesis first, one manifest identity, increasing revisions, canonical parent
digest links, bounded regular-file input, redacted failures, and complete output delivery.
Revision gaps remain valid. Success must state `scope: manifest_history` and `authenticated: false`.
The [CLI owner](architecture/manifest-context-api.md#cli-and-configuration) defines the complete command contract.

The [implementation](../src/cryptalis/cli.py) calls the existing history validator after bounded reads.
It rejects more than 4,096 paths before file access. The reader limits each read to the remaining
aggregate budget plus one overflow byte. It retains the existing file cleanup and output failure
channels. The [tests](../tests/test_cli_history.py) check real command results and file preservation.
Small stream substitutes measure read sizes and inject operational failures.

The [demonstration](../examples/demo_manifest_history.py) checks six subprocess outcomes with
synthetic temporary files. It accepts a valid chain and presentation changes. It rejects a
changed ancestor, a missing middle ancestor, and reversed order. A consistent replacement chain
also passes with `authenticated: false`. This control prevents a structural result from becoming
an authentication claim.

| Check | Result |
|---|---|
| Baseline: `uv run --locked --offline pytest -q` | 573 passed |
| RED: new history CLI tests before implementation | 23 expected failures, 2 argument-rejection cases passed |
| Focused CLI and header/history tests before the demonstration test | 122 passed |
| Final new history and demonstration tests | 26 passed |
| Final complete suite: `uv run --locked --offline pytest -q` | 599 passed in 5.73 seconds on Linux and CPython 3.12.3 |
| Ruff 0.16.3: `check --no-cache` on the three changed Python files | Passed |
| Ruff: `format --check` on the two new Python files | Passed. Existing CLI formatting was preserved |
| Mypy on the CLI and demonstration, Python target 3.12 | Failed with three existing CLI diagnostics. The unchanged baseline produced the same diagnostics |
| `uv build --offline` | Wheel and source archive built |
| Clean temporary environment, offline wheel install, execution outside the checkout | Six demonstration outcomes passed. The installed console script inspected a two-file history |
| Markdown path and heading check | 19 tracked Markdown files, 538 local links, zero faults before this audit addition |
| `git diff --check` | Passed |
| Added documentation prose lint | 0.35 findings per 100 words |

Mypy reports two incompatible `ArgumentParser` method overrides and one nullable errno lookup.
These diagnostics also occur in the unchanged baseline. This slice adds no diagnostic, but the
type gate remains incomplete. No checker rule or security assertion was disabled.

First-party adversarial review checked resource bounds, stale byte links, identity substitution,
partial ancestry, complete replacement, unsupported versions, nonregular files, cleanup, output
delivery, and diagnostic leakage. It found no unresolved defect within the stated structural
scope. This review is not independent security review.

This slice adds no dependency, encryption, database access, policy activation, or authority
authentication. It does not detect an omitted later revision or supply an atomic filesystem
snapshot. C01, C25, C33, G-MANIFEST, G-ACTIVE, and the release gate remain incomplete.

## Synthetic Smolink AEAD trial - 2026-10-05

Entry: `5c15a93`, with a clean worktree. The user requested a tangible terminal demonstration
with synthetic data and Smolink as the reference. The user selected the more impressive result
when offered a primitive trial or structural contract checks. No commit or push occurred.

The [example](../examples/demo_smolink_crypto.py) uses fixed fake `users.email` and
`urls.destination` values from two users and three URLs. One URL has null ownership.
The reference files were Smolink's `backend/app/models/user.py` and `backend/app/models/url.py`.
Their latest relevant commit was `d617363`. No Smolink source or data changed.

The slice uses the existing leading AES-256-GCM-SIV candidate as a library-native research trial.
It does not turn F1, W1, or a descriptor into an encryption format. The
[crypto owner](architecture/crypto-search-lifecycle.md#synthetic-smolink-primitive-trial) defines
the exact scope. The [library API](https://cryptography.io/en/stable/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCMSIV)
and [release notes](https://cryptography.io/en/stable/changelog/) supplied the current primary references.

Acceptance requires exact recovery of five values, a randomized rewrite, eleven authentication
rejections, and visible acceptance of same-context replay. A permissive decrypt substitute must
fail the evaluator. Generated keys must stay out of stdout, stderr, and the saved snapshot.
External input is rejected. Optional output uses exclusive creation and mode `0600` on Linux.
File and terminal failures must return a redacted nonzero result. Success follows all checks.

The first RED run produced seven expected failures because the example and its dependency were
absent. The first GREEN run passed seven checks. Adversarial review added RNG, key-leakage,
cleanup, and output-delivery checks. It then exposed two diagnostic defects: an embedded null
in an output path raised an unstructured exception, and an I/O error without an errno had the
wrong cause category. Both defects first failed focused regression checks and then received fixes.

The final focused set has 13 passing checks. The complete suite has 612 passing tests.
Ruff 0.16.3 lint and formatting pass for both new files. Mypy reports only the same three
existing CLI diagnostics recorded in the preceding slice. The type gate remains incomplete.
No checker rule, property range, security control, or meaningful assertion was weakened.

`cryptography==50.0.2` is a development dependency. Its locked dependencies are `cffi==2.1.1`
and `pycparser==3.0`. Existing dependency records remain unchanged. The new lock records have
130 SHA-256-pinned source and wheel artifacts from `files.pythonhosted.org`.
Runtime package metadata still has no dependencies. No package module imports this example.

The source archive and wheel built offline. A clean temporary environment installed the wheel
and then the pinned lab dependency. Outside the checkout, JSON and human presentation passed.
Five fields recovered exactly, eleven misuse cases rejected, and the private snapshot had mode
`0600`. The tested backend reported `cryptography 50.0.2` and `OpenSSL 4.0.3 29 Sep 2026`.
The initial offline lab-dependency install could not resolve a cached registry entry. An
approved network install completed that check. No production credential was supplied.

The documentation path and heading check found 19 Markdown files, 552 local links, and zero
faults before this audit addition. `git diff --check` passed. The added main documentation prose
scored 1.19 findings per 100 words under STE-flavored lint.

First-party review checked authenticated context, exact-key use, no fallback, nonce repetition,
key and plaintext exclusion from the snapshot, immutable public metadata, guest ownership,
output preservation, diagnostic redaction, cleanup failures, and the replay limit.
It found no remaining defect within the stated trial scope. This is not independent review.

The trial prints only fixed synthetic plaintext and recovery values for teaching. It does not
save keys, guarantee zeroization, supply recoverable storage after process exit, authenticate
production identity, implement Smolink email queries or redirects, access PostgreSQL, or supply
a public Cryptalis encryption API. Q1-Q5, C03, C34, G-CRYPTO, G-CROSSKEY, and the release gate
remain open. The README gives reproducible presentation and ciphertext inspection commands.
