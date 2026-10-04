# Backend build and evidence checklist

Current state as of 2026-10-04: documentation plus bounded manifest JSON, content digests,
identity-header validation, parent-link validation, structural field-format digests,
offline terminal inspection, and private candidate F1 envelope parsing.
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

The current manifest components, [terminal inspector](../src/cryptalis/cli.py), and private F1
parser have 246 passing tests under `uv run --locked pytest -q` on 2026-10-04.
Normal Python imports work, and `uv build` produces a wheel and source archive.
These local checks do not complete C01, C25, or C26. Complete semantic
validation, trusted revision history, signature authentication, the remaining CLI contract, and
cross-language evidence remain pending.

Parent-link checks validate one supplied pair. Tests cover content tampering, identity
substitution with a matching digest, equal or decreasing revisions, unusable parent files,
and redacted CLI failures. Revisions can skip counter values. Both files can come from an
attacker. Pair consistency does not authenticate policy or establish complete ancestry.

The [CLI failure tests](../tests/test_cli.py) now cover safe diagnostic stages and input roles,
invalid arguments in JSON mode, duplicate parent options, option termination, and dependency failures.
Injected open, metadata, read, and cleanup failures check exit mapping, redaction, and preservation of primary diagnostics.
Permission denial remains exit 2 after file open. Operational I/O and cleanup failures return exit 4.
The [failure audit](documentation-claims-audit.md#cli-failure-corrections) records F01–F03 corrections.
A clean temporary environment installs the current wheel and passes six console-command smoke cases outside the checkout.
This evidence does not complete the broader C25 or release gates.

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

The wheel and source archive build with a temporary writable uv cache.
A clean temporary environment installs the wheel and passes the F1 vector, truncated/trailing-input
checks, and the existing parent-link command. The previous slice also checked the installed descriptor helpers.
Ruff and mypy checks did not run for this slice. Offline tool resolution confirms that neither
tool is cached. Their downloads failed because of sandbox DNS during the previous slice.

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
