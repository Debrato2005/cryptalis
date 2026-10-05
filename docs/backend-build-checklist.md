# Backend build and evidence checklist

Current state as of 2026-10-05: documentation plus bounded manifest JSON, content digests,
identity-header validation, parent-link and bounded ancestry-chain validation, structural
field-format digests, offline terminal inspection, private candidate F1/W1 framing, and private
scalar syntax encoding and decoding. Private structural ActiveState header, digest, and history
validation, a process-local development authority, and private transition-plan admission also
exist.
This file is the authority for capability implementation state.
[Manifest contracts](architecture/manifest-context-api.md#terms-and-maturity)
define terms and maturity.
[Architecture owners](architecture/README.md#documentation-ownership) define rationale. The
[build guide](cryptalis-build-guide.md) defines learning order. Every workstream remains active
program scope.

The markers mean:

| Marker | Meaning |
|---|---|
| `[ ]` | No required gate evidence admitted |
| `[~]` | Documented or partially specified |
| `[x]` | Implemented, with required reproducible executable evidence linked and reviewed |
| `[-]` | Rejected for a named profile, with a reason |

No capability is marked complete. A successful documentation command does not establish runtime
maturity. Human and AI review within the project is first-party. Independent review requires a
named external reviewer and disclosed independence.

## State and next artifacts

Each row has an ID, maturity and status, dependencies, owner and gate, required artifact, and
exit rule. Rows group related properties. They do not limit the number of features.

Handoff reconciliation: 2026-10-05. Existing implementation passages and C00–C32 rows remain unchanged.
They describe the bounded current slice and broader inventory, not the new implementation order.
[C33–C40](#ordered-foundation-slices) now govern dependent runtime work.
Online/search/fleet/Graph/DAST breadth remains later unchecked scope and is not a first-transition dependency.
No P0 contract or research question is marked reviewed/closed by this pass.
The [P0 review register](architecture/README.md#p0-documentation-review-register) links each reconciled blocker to its owner and pending disposition.

On 2026-10-04, the manifest components, [terminal inspector](../src/cryptalis/cli.py), private framing parsers,
and scalar decoder had 365 passing tests under `uv run --locked pytest -q` on 2026-10-04.
Normal Python imports work, and `uv build` produces a wheel and source archive.
These local checks do not complete C01, C25, or C26. Complete semantic
validation, trusted history authority, signature authentication, the remaining CLI contract, and
cross-language evidence remain pending.

Parent-link checks validate one supplied pair. Tests cover content tampering, identity
substitution with a matching digest, equal or decreasing revisions, unusable parent files,
and redacted CLI failures. Revisions can skip counter values. Both files can come from an
attacker. Pair consistency does not authenticate policy or establish complete ancestry.

The internal [history validator](../src/cryptalis/manifest/header.py) checks a complete supplied
genesis-to-head chain. It requires immutable sequence inputs, enforces 4,096-document and 16 MiB
aggregate limits before parsing, preserves valid revision gaps, and checks each identity and
digest link. Its boundary tests cover valid chains, genesis truncation, reordering, substitution,
mixed identities, mutable inputs, and both aggregate limits. An internally consistent attacker
chain still passes. The helper does not authenticate history, select the authorized head, or
complete C01 or C33. The CLI also accepts a complete supplied history through `manifest inspect-history`.

On 2026-10-05, 31 focused header/history tests and the complete 467-test suite passed on
Linux and CPython 3.12.3. A source archive and wheel built offline. A clean temporary environment
installed the wheel and validated a two-document chain with a skipped revision number. These
checks supply structural evidence only. They do not complete G-MANIFEST, G-ACTIVE, C01, or C33.

The terminal inspector also checks an explicit complete supplied history through
`manifest inspect-history`. It reuses the structural history validator and bounded regular-file
reader. It rejects excessive file counts before access and excessive aggregate bytes during reads.
The result states its scope and `authenticated: false`. Existing single-file and parent-link
inspection retain their output contracts.

The [history CLI tests](../tests/test_cli_history.py) cover valid revision gaps, canonical presentation changes, tampering,
missing or reordered ancestors, duplicate entries, identity substitution, unsupported versions,
nonregular files, count and byte limits, redacted I/O failures, and failed output delivery.
An internally consistent replacement chain supplies a positive control for the authentication limit.
The [terminal demonstration](../examples/demo_manifest_history.py) checks six real subprocess outcomes and removes temporary files.
This evidence does not complete C01, C25, C33, G-MANIFEST, or G-ACTIVE.

The private [ActiveState kernel](../src/cryptalis/contracts/active_state.py) decodes immutable
authority headers, computes a separate domain digest, checks monotonic parent links, and validates
one bounded complete history. Its 51 focused tests cover fixed vectors, canonical IDs and digests,
required fields, domain and manifest substitution, rollback, digest/revision inconsistency,
aggregate limits, and redacted failures. The synthetic [example history](../examples/active-state)
contains no signature or authority proof. Node and Python agree on its genesis digest.

The complete suite contained 518 passing tests after the structural ActiveState slice. This
evidence does not complete C33 or G-ACTIVE. It adds no production authority, durable idempotency,
transition execution, cryptography, database behavior, or CLI command.

The private [development authority](../src/cryptalis/contracts/development_authority.py) loads a
valid bounded history and serializes compare-and-swap inside one Python process. It publishes
immutable snapshots only after successor and full-history validation. An exact retry of the
current successor does not add a duplicate entry. Different competing successors from one head
cannot both succeed. An unrelated stale digest fails before proposal parsing.

Its 11 focused behavior tests include invalid initialization, immutable snapshots, valid update,
lost-response retry, malformed input with no state change, stale-request redaction, and a
two-thread race. The complete suite passed 529 tests on Linux and CPython 3.12.3. An offline
source archive and wheel build succeeded. A clean temporary environment installed the wheel and
applied and retried the synthetic successor without a duplicate history entry.

This adapter loses its state on process exit. It has no writer authentication, persistence,
cross-process coordination, durable idempotency, independent recovery, or rollback resistance.
It supplies no public command, transition execution, policy activation, cryptography, or database
behavior. C33 and G-ACTIVE remain incomplete.

The private [transition contract](../src/cryptalis/contracts/transition.py) defines immutable
in-memory plan and observation records. Its admission check validates the offline strategy, UTC
validity window, protection domain, opaque target identity, and exact source ActiveState revision
and digest. It returns no mutation authority and has no external effects.

Its 44 focused cases cover all nine transition kinds, exclusive expiry, pre-creation
observations, wrong-domain and wrong-target substitution, stale revision and digest, unsupported
strategy, immutable target bytes, resource bounds, hostile time-zone objects, and fixed redacted
diagnostics. The focused ActiveState, development-authority, and transition set passed 106 tests.
The complete suite passed 573 tests on Linux and CPython 3.12.3. An offline source archive and
wheel build succeeded. A clean temporary environment installed the wheel and admitted a matching
synthetic offline plan.

The opaque target identity has no implemented resolver or production trust source. No hostname,
database name, database object identifier, or editable claim establishes target authority alone.
There is no serialized plan schema, plan digest, authentication, durable record, approval,
receipt, executor, database access, or policy activation. C33 and G-PLAN remain incomplete.

The [CLI failure tests](../tests/test_cli.py) now cover safe diagnostic stages and input roles,
invalid arguments in JSON mode, duplicate parent options, option termination, and dependency failures.
Injected open, metadata, read, and cleanup failures check exit mapping, redaction, and preservation of primary diagnostics.
Permission denial remains exit 2 after file open. Operational I/O and cleanup failures return exit 4.
The [failure audit](documentation-claims-audit.md#cli-failure-corrections) records F01–F03 corrections.
During the CLI slice, a clean temporary environment installed the wheel and passed six console smoke cases outside the checkout.
This evidence does not complete the broader C25 or release gates.

On 2026-10-05, output-delivery corrections brought the full suite to 385 passing tests.
The 66 CLI tests include full-device and closed-pipe results/help, failed stderr, missing/closed streams, and short writes.
They also cover descriptor reuse and failed null-sink cleanup with preserved diagnostics.
Writes and flushes must complete before success. Failed stderr leaves an explicit non-zero exit channel.
The [output audit](documentation-claims-audit.md#cli-output-delivery-correction--2026-10-05) records scope and installed-wheel verification.
This correction adds no command or runtime crypto, ORM, provider, or transition support.

The [field-format helpers](../src/cryptalis/manifest/descriptor.py) check descriptor structure
and compute canonical bytes and a separate content digest.
The [boundary tests](../tests/test_manifest_canonical.py) cover exact bytes, a fixed digest vector,
changed format members, missing or extra members, and malformed representations.
They also cover numeric boundaries, ambiguous JSON, and Unicode preservation.
The fixed digest was independently checked with `sha256sum`.
Node canonicalization and hashing agree on the parameterless and Unicode-parameter vectors.
These two local checks do not complete the cross-language and fuzz corpus required by G-MANIFEST.
Catalogue admission, full manifest compilation, payload authentication, and encryption remain pending.

The [private F1 parser](../src/cryptalis/crypto/_candidate_envelope.py) implements structural
checks under the [crypto owner](architecture/crypto-search-lifecycle.md#32-parser-and-resource-limits).
Its [boundary tests](../tests/test_candidate_envelope.py) cover fixed bytes, all candidate suites,
scalar selectors, length and generation boundaries, truncation, unsupported headers, and redacted errors.
Tests also check immutable inputs/results and ciphertext exclusion from `repr`.
Forged well-shaped tags and digests remain structurally parseable. No authentication claim follows.
Python and an independent Node offset parser agree on 5,143 inputs with seed `20261005`.
The local check includes 1,941 accepted structures and compares every returned field.
This limited first-party trial does not complete G-CRYPTO or admit C03.

The [private W1 parser](../src/cryptalis/crypto/_candidate_wrap.py) implements only the
[local wrapping-record structure](architecture/crypto-search-lifecycle.md#35-local-secret-wrapping-candidate-w1).
Its [44 boundary tests](../tests/test_candidate_wrap.py) cover all suite/kind pairs, every frame truncation,
exact lengths, selectors, generation bounds, redaction, and immutable inputs/results.
Well-shaped forged identities, seeds, nonces, and tags remain parseable. No ownership, freshness, or authentication claim follows.
Python and an independent Node offset parser agree on 13,541 inputs with seed `20261004`.
The check includes 1,672 accepted structures and compares every returned field.
This bounded first-party trial does not complete G-CRYPTO, G-CROSSKEY, or G-PROVIDER and does not admit C03.

The W1 slice built a wheel and source archive with a temporary writable uv cache.
A clean temporary environment installed that wheel outside the checkout. It passed two W1 frame checks,
four typed rejection cases, and the existing parent-link command.
Earlier slices checked the installed F1 parser and descriptor helpers.

The [private scalar decoder](../src/cryptalis/crypto/_candidate_scalar.py) implements only the
[candidate syntax boundary](architecture/crypto-search-lifecycle.md#implemented-scalar-syntax-boundary).
The decoder slice added [75 boundary tests](../tests/test_candidate_scalar.py) for fixed typed vectors, exact framing, null/empty distinctions,
malformed UTF-8, canonical numeric syntax, digit/scale/size limits, and dependency context changes.
It preserves decimal representation and Unicode content. That decoder-only slice added no encoding, field-policy approval, or authentication.
Python and an independent Node decoder agree on 38,483 unique inputs with seed `20261004`.
The trial includes 3,426 accepted values and compares their types and complete representations.
This bounded first-party trial does not complete G-CRYPTO or admit C03.

On 2026-10-05, the private encoder added 69 tests and brought the full suite to 454 passing tests.
The 144 scalar tests cover both directions. The encoder matches all 15 existing vectors without changing their bytes.
It rejects type coercion and subclasses, nonfinite decimals, invalid Unicode, and resource overflow.
Bounds precede integer digit extraction and decimal digit-tuple allocation.
Tests preserve exact decimal representation under restrictive ambient contexts and integers under the 640-digit string limit.
A seeded round-trip corpus covers 800 typed values.
An independent Node encoder agrees on 2,065 cases, including 2,028 accepted values, with seed `20261005`.
This bounded first-party check does not freeze the format, authenticate values, or admit C03/C34.
The [encoding audit](documentation-claims-audit.md#candidate-scalar-syntax-encoding--2026-10-05) records validation and limits.

The current wheel and source archive build offline. A clean temporary environment installs the wheel outside the checkout.
The encoder wheel trial passes 15 bidirectional vectors, ten typed rejections, two ambient-context checks, and the parent-link console command.
Ruff and mypy remain unavailable on PATH and in the project environment. These checks did not run.
Earlier offline resolution found no cached tools, and sandbox DNS blocked their downloads.

SPECIFIED means a contract and gate exist. It does not mean the
gate passed. For the rows marked RESEARCHED here, construction selection remains open. A failed
gate demotes only dependent claims.

| ID / capability | Maturity / status | Dependency | Owner / required evidence / exit |
|---|---|---|---|
| C00 Documentation architecture | SPECIFIED `[~]` | Current tree + primary ledgers | [Claims audit](documentation-claims-audit.md): actual local checks and first-party review, independent review pending; no runtime promotion |
| C01 Manifest schema/canonical compiler | SPECIFIED `[ ]` | Stable IDs/catalogue | [G-MANIFEST](architecture/manifest-context-api.md#version-compatibility-and-research-gates): two-language vectors, malformed corpus, deterministic diff results; 100% agreement/0 ambiguity |
| C02 Tenant/subject provenance P0 | SPECIFIED `[ ]` | Host authn/authz adapter | [G-CONTEXT](architecture/manifest-context-api.md#version-compatibility-and-research-gates): all request/task/pool/job/restore substitutions; 0 unauthorized load/SQL/release |
| C03 Suite/envelope freeze P10 | SPECIFIED `[ ]` | C01/C02 + exact crypto build | [Crypto gates](architecture/crypto-search-lifecycle.md#research-gates): vectors/tamper/RNG/fork/platform/size/independent review; chosen suite/framing accepted before DB checks |
| C04 ORM logical/physical coherence P1 | SPECIFIED `[ ]` | C01..C03 + local keys | [ORM gates](architecture/orm-schema-migration.md#research-gates): sync/async history/flush/rollback/expire/loader cells; no stale physical state or plaintext SQL |
| C05 Query IR / bypass classification P2 | SPECIFIED `[ ]` | C04 + context | [ORM gates](architecture/orm-schema-migration.md#research-gates): operator/alias/raw/bulk/Core/direct-driver matrix; T/R paths match declared behavior, D/U gaps visible |
| C06 Warm/greenlet/deferred comparison P3 | SPECIFIED `[ ]` | C02..C04 + provider fixture | [ORM gates](architecture/orm-schema-migration.md#research-gates): real adapted remote alternative, latency/loop-lag/cancellation/N+1/outage; no strawman blocking-only comparison |
| C07 Stable AAD / legitimate moves P4 | SPECIFIED `[ ]` | C03/C04 | [Crypto](architecture/crypto-search-lifecycle.md) + [ORM](architecture/orm-schema-migration.md): rename/table split/record/tenant transfer crash vectors; raw relocation fails, approved move resumes |
| C08 Equality/IN/no-search | SPECIFIED `[ ]` | C01..C05 + leakage policy | [Crypto gates](architecture/crypto-search-lifecycle.md#research-gates): normalization/domain/null vectors, query correctness, attacks/cost; no undeclared capability |
| C09 Scoped uniqueness / rotation P5 | SPECIFIED `[ ]` | C08 + DB protocol | [ORM](architecture/orm-schema-migration.md) + [crypto](architecture/crypto-search-lifecycle.md): concurrent normalized duplicates/nulls/old-new writer fence/dual terms; exactly one logical uniqueness domain |
| C10 Physical schema/compiler | SPECIFIED `[ ]` | C03 frozen bytes/parser -> null model -> CHECK | [ORM gates](architecture/orm-schema-migration.md#research-gates): clean/drift/collision/constraints/live-schema fixtures; plans only, shape not authenticity |
| C11 Alembic operation/render/comparator | SPECIFIED `[ ]` | C10 + exact API lane | [ORM gates](architecture/orm-schema-migration.md#research-gates): generated/replayed revisions and manifest bindings; immutable reviewable proposals, no auto-apply |
| C12 Migration recovery P6 | SPECIFIED `[ ]` | C04/C09..C11 + writer grants | [ORM gates](architecture/orm-schema-migration.md#research-gates): phase/crash/two-worker/CAS/mixed-app/replica/invalid-index/restore corpus; complete row/index coverage, no unapproved contract |
| C13 Provider hierarchy/adapters | SPECIFIED `[ ]` | C02/C03 + custody registry | [Crypto gates](architecture/crypto-search-lifecycle.md#research-gates): exact AWS/GCP/Vault states/outage/audit/restore/import vectors; no fictional common destroy guarantee |
| C14 Cache/epochs/leases/fence P7 | SPECIFIED `[ ]` | C13 + external control state | [Crypto gates](architecture/crypto-search-lifecycle.md#research-gates): partition/suspend/resume/clock/commit/restart faults; enforced declared bound, pending on uncertainty |
| C15 Rotation/revocation | SPECIFIED `[ ]` | C12..C14 | [Crypto gates](architecture/crypto-search-lifecycle.md#research-gates): duplicate/concurrent request state tests; old read generation declared, new denied access fenced |
| C16 Bounded shred/restore receipts | SPECIFIED `[ ]` | C14/C15 + independent tombstones | [Crypto gates](architecture/crypto-search-lifecycle.md#research-gates): fresh/stale/DB/provider/VM restore; distinguish managed denial from recoverable offline keys, residue listed |
| C17 Controlled access | SPECIFIED `[ ]` | C02/C13..C16 + separate release authority | [Crypto gates](architecture/crypto-search-lifecycle.md#research-gates): purpose/end-user/workload/cancellation/serialize denial; local wrapper never stronger boundary alone |
| C18 Doctor AST/IR/symbol/CFG/taint P9 | SPECIFIED `[ ]` | C01 + labeled corpus | [Assurance gates](architecture/assurance-evidence.md#research-gates): safe/unsafe/ambiguous/mutant precision/recall and cost per rule; G-A10 compares restricted DSL and typed native authoring; unknown Python dynamism visible |
| C19 Minimum-leakage planner | SPECIFIED `[ ]` | C05/C18 + scoped runtime facts | [Assurance](architecture/assurance-evidence.md): recommendation corpus/leakage/migration attribution; never alters policy or infers unobserved absence |
| C20 Graph/writer provenance P8 | SPECIFIED `[ ]` | C01/C10/C13/C18 + evidence DTOs | [Assurance gates](architecture/assurance-evidence.md#research-gates): explicit IDs/contradictions/registered-observed-unknown writers + mature-tool baseline; material explanation/impact value |
| C21 Verify / exposure oracle P8 | SPECIFIED `[ ]` | Canonical result DTO + collectors + selected invariant | [Assurance gates](architecture/assurance-evidence.md#research-gates): health/watermarks/positive-negative-mutant-restored controls; missing evidence INCONCLUSIVE |
| C22 Pentest/DAST and replay | SPECIFIED `[ ]` | C21 + safety broker + synthetic lab | [Assurance gates](architecture/assurance-evidence.md#research-gates): baseline/protected/one-mutant attacks, containment escapes/cleanup budgets and G-A11 role/state/replay; exploitation and exposure separate |
| C23 Network/PCAP | SPECIFIED `[ ]` | C22 scoped runs + capture permission | [Assurance gates](architecture/assurance-evidence.md#research-gates): TShark/Zeek/Nmap fixture correlation and G-A11 loss/decoder trials; TLS observation limits and session-secret hygiene |
| C24 Evidence/bundles/integrity | SPECIFIED `[ ]` | C01 + result schema | [Assurance gates](architecture/assurance-evidence.md#research-gates): redaction/parser/signature/replay/compatibility mutants; signatures != independent truth |
| C25 CLI/config/errors/observability | SPECIFIED `[ ]` | Canonical public contracts + implemented slice | [API/config](architecture/manifest-context-api.md): exit/result mapping and safe default fixtures; no concealed network/destructive action |
| C26 Lab/CI/import quarantine | SPECIFIED `[ ]` | C21/C22/C24 + package build | [G-BOUNDARY](architecture/manifest-context-api.md#version-compatibility-and-research-gates), [assurance](architecture/assurance-evidence.md): seeded forbidden imports/credential/payload wheel checks; no CI configuration exists |
| C27 Compatibility/support | SPECIFIED `[ ]` | C04..C17 + exact versions | [ORM](architecture/orm-schema-migration.md): every admitted matrix cell from clean checkout; no version supported before release evidence |
| C28 Performance/storage hypotheses | SPECIFIED `[ ]` | Correct slice + equivalent baselines | [Assurance](architecture/assurance-evidence.md): pinned raw load/error/latency/cache/storage/migration samples; no cherry-picked/single-run claim |
| C29 Independent production review | RESEARCHED `[ ]` | Required C rows + external reviewer | [Playbook](../ENGINEERING_PLAYBOOK.md): cryptography/provenance/migration/distributed-control/process/evidence review; reviewer identity/findings/resolution published |
| C30 Adoption/usability | SPECIFIED `[ ]` | Prototype APIs/workflows | [G-API](architecture/manifest-context-api.md#version-compatibility-and-research-gates): five-maintainer task study, evidence of usability (not population demand) |
| C31 Advanced search | RESEARCHED `[ ]` | Published constructions/independent oracles | [Crypto gates](architecture/crypto-search-lifecycle.md#research-gates): join/group/range/order/extrema/prefix/substring/text/fuzzy/JSON individually; no blanket search approval |
| C32 Broader systems tracks | RESEARCHED `[ ]` | Core interfaces only for integration | [Research gates](learning-first-research-philosophy.md#broader-research-gates): Django/DB/languages/UI/policy/honeytokens/anomaly/attack graph/multiregion/packs; each threshold met before supported integration |

## Ordered foundation slices

These unchecked rows replace the build order, not historical evidence or capability IDs.
The [canonical unresolved register](architecture/README.md#unresolved-research-questions) owns Q1–Q10.
Q1–Q5 require researched closure and P0 documentation review before dependent runtime behavior.
Safe independent work includes documentation, primary research, and synthetic contract/vector designs that supply no runtime protection claim.

| ID / capability | Maturity / status | Dependency | Owner / required evidence / exit |
|---|---|---|---|
| C33 Active-state/transition contracts | SPECIFIED `[ ]` | P0 review + Q1/Q5 closure for dependent runtime | [Shared authority/plan gates](architecture/manifest-context-api.md#version-compatibility-and-research-gates): immutable DTOs, authenticated history/head, CAS/idempotency, target/preconditions, approval/receipt/errors, local development authority. Future canonical/ancestry/stale/wrong-target/redaction artifacts with pins, replay and reviewer. No crypto or DB mutation |
| C34 Domain/representation/descriptor/suite freeze | SPECIFIED `[ ]` | C33 + Q2 closure | [Crypto gates](architecture/crypto-search-lifecycle.md#research-gates): successor descriptor/binding/catalogue, sole established composition, exact key dispatch, local test provider. Future two-language/external vectors, tamper/clone/RNG/nonce/fuzz and independent review. Structural schema 1/F1/W1 trials do not close it |
| C35 Minimal field/Session API and coverage | SPECIFIED `[ ]` | C33/C34 + Q3 closure | [ORM gates](architecture/orm-schema-migration.md#research-gates): explicit no-search scalar path first, trusted identity, no generic crypto. Then one exact public sync Session cell or repository fallback. Future insert/read/update/delete/load/expiry/rollback/denial/logging and rejected Core/bulk/COPY artifacts. Async later |
| C36 PostgreSQL profile/preflight/schema plan | SPECIFIED `[ ]` | C35 + Q5 closure | [DB profile](architecture/orm-schema-migration.md#initial-postgresql-profile-and-live-preflight): future target/drift/roles/owners/search_path/RLS/code/2PC/CDC/session/index/logging/capacity fixtures and reviewed Alembic plan. Limited visibility refuses. Generate DDL only |
| C37 Offline protect/reconfigure/deprotect | SPECIFIED `[ ]` | C33..C36 + scoped Q6/Q8 limits | [Offline gate](architecture/orm-schema-migration.md#research-gates): PROTECT and compatible RECONFIGURE_PAYLOAD, then DEPROTECT in one engine. Future crash/cancel/two-executor/checkpoint/full-coverage/CAS/approval E2E artifacts. No online journals or dual writers required |
| C38 Restore/recovery and one-provider key operations | SPECIFIED `[ ]` | C37 + Q1/Q4/Q5 closure and explicit Q7/Q9 limits | [Provider/restore gates](architecture/crypto-search-lifecycle.md#research-gates): one live cell, native states, separate rewrap/new-write/re-encryption, bounded cache, recovery manifest and quarantined restore admission. Future emulator/live faults, hostile-schema/PITR/current-denial and offline-recovery trials |
| C39 Upgrade/decommission | SPECIFIED `[ ]` | C37 for local exit prototype; C38 for provider/restore-dependent release | [Compatibility/exit](architecture/orm-schema-migration.md#one-writer-upgrade-admission): aggregate remove after DEPROTECT, old binaries/jobs/copies/reader inventory, package-absent behavior. Future adjacent-version/startup/retired-format/restore/approval artifacts. No mixed writer release |
| C40 Telemetry and product release | SPECIFIED `[ ]` | C33..C39 + required independent review | [Release gate](../ENGINEERING_PLAYBOOK.md#release-gate): future canary sink/redacted-diagnostics artifacts, lock/SBOM/provenance/Trusted Publishing/source-to-wheel/lab-quarantine evidence and reviewed exact cell. Signing does not imply correctness |

Within these groups, use this behavior-first sequence:

1. Contract/active-state kernel, then identity/descriptor/suite freeze. No crypto or DB mutation in the kernel.
2. One explicit field path, then a pinned public synchronous Session cell, then read-only DB preflight and reviewed DDL.
3. Offline PROTECT/compatible RECONFIGURE_PAYLOAD, then DEPROTECT and local aggregate remove.
4. One real provider/key-operation cell, recovery manifest/quarantined restore, then upgrade/downgrade and full exit admission.
5. Safe telemetry, product provenance and release review. Only then consider advanced integration tracks.

Later tracks, each unchecked with separate evidence: equality/uniqueness and offline REINDEX, async Session, multi-process provider/cache, online migration/mixed writers, CDC, multi-provider/region, and broad assurance.
Existing C08/C09/C12/C14/C18–C23/C31/C32 gates apply only to their admitted scope.
No failed or missing dependency can be bypassed by a passing broader tool suite.
Every artifact entry names an actual stable path, exact pins, reproduction command/result, limitations, and reviewer before completion.
No future path in this table is presented as existing evidence.

## Evidence admission

Select tests under the [playbook policy](../ENGINEERING_PLAYBOOK.md#test-layers).
Use the highest realistic behavior boundary. Record pending E2E evidence for incomplete workflows.
Corpus sizes and zero-failure thresholds in subsystem gates remain property-specific admission criteria, not line-coverage targets.

A future evidence entry must include:

- Capability, invariant, and gate IDs
- Exact source revision and digest of the dirty working snapshot
- Manifest, schema, target, and tool versions
- Command, raw machine results, and controls
- Protected behavior or regression, test boundary, substitute dependencies, and missing workflow evidence
- Limitations and reviewer
- Artifact hashes and stable repository location

An absent path is not an artifact. Failed and inconclusive results remain visible. `[x]`
requires a committed reproducible artifact and an independently replayable command under the
applicable contract. Prose and signatures alone do not satisfy this requirement.

Documentation check outputs in the claims audit record commands from the dated documentation
pass. They are an uncommitted working record, not committed capability evidence or independent
review.

The documentation pass created no application source, tests, migrations, build configuration, or
CI configuration. Runtime and empirical rows remain unchecked after design consolidation. Do not
invent executable scripts to close a documentation checkbox.
