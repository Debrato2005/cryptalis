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
