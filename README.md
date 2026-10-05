# Cryptalis

Cryptalis is a planned data-protection system for Python and SQLAlchemy.
The future normal workflow is a field declaration, trusted Session identity, `cryptalis check`, and `cryptalis migrate`.
Generated policy history expresses desired behavior. Authenticated external active state controls runtime behavior after a verified transition.
The initial runtime target is one no-search synchronous PostgreSQL cell with offline maintenance transitions.
Broader security-assurance and search work remains separately gated research.

**Status as of 2026-10-05: bounded manifest JSON, domain-separated content digests,
identity-header validation, parent-link and bounded ancestry-chain validation, structural
field-format digests, offline terminal inspection, private candidate F1/W1 framing, and private
scalar encoding and decoding. Private structural ActiveState header, digest, and history
validation also exist.**

The repository has an installable Python package with a [bounded JSON decoder](src/cryptalis/manifest/parser.py), [restricted RFC
8785 canonicalizer and SHA-256 digest helper](src/cryptalis/manifest/canonical.py), [typed header
decoder](src/cryptalis/manifest/header.py), [field-format helpers](src/cryptalis/manifest/descriptor.py),
and read-only [manifest inspector](src/cryptalis/cli.py).
The private [F1 envelope parser](src/cryptalis/crypto/_candidate_envelope.py) and
[W1 wrapping-record parser](src/cryptalis/crypto/_candidate_wrap.py) check structure and return
unauthenticated bytes. They perform no key lookup or decryption.
The [private scalar codec](src/cryptalis/crypto/_candidate_scalar.py) encodes and decodes candidate
text, bytes, integer, and decimal syntax. It preserves exact types and decimal representation.
Encoded bytes contain unprotected values. The codec does not authenticate values or approve field policy.
The private [ActiveState module](src/cryptalis/contracts/active_state.py) checks structural
identity, monotonic revisions, rollback, parent links, and bounded complete histories. It performs
no authentication, compare-and-swap, policy activation, file I/O, or database mutation.
Behavior tests cover these boundaries. Complete semantic schema validation,
trusted history authority, and signature authentication remain pending.
Cryptography, ORM integration, migrations, providers, and assurance tools also remain pending.
Other Cryptalis APIs and commands are proposed
contracts. The [capability
checklist](docs/backend-build-checklist.md) separates specified design from executable evidence.
No runtime version is supported.

Handoff reconciliation: 2026-10-05, documentation only.
External ActiveState, the transition engine, restore admission, deprotection, and complete uninstall/decommission are not implemented.
The [unresolved questions](docs/architecture/README.md#unresolved-research-questions) remain open.
Dependent runtime behavior waits for researched answers to Q1–Q5 and [P0 documentation review](docs/architecture/README.md#p0-documentation-review-register).
This pass does not change the current structural formats or confer support.

## Run the current slice

Prerequisites: Python 3.12 or later, uv, and the repository root as the working directory.

```bash
uv sync --locked
uv run pytest
uv run cryptalis manifest inspect examples/manifests/genesis.json
uv run cryptalis manifest inspect examples/manifests/genesis.json --json
uv run cryptalis manifest inspect examples/manifests/successor.json --parent examples/manifests/genesis.json --json
```

The inspector prints the validated identity header and content digest in text or JSON form.
Use `--parent PATH` to check the link to one supplied parent. Both files must have valid headers,
the same manifest ID, increasing revisions, and a matching canonical parent digest.
The command reads bounded local regular files. Invalid input returns exit code 2 and a redacted
`Manifest.Invalid` error. The command does not change manifest files or use the network.
Output write or flush failure returns operational exit 4.
When stderr works, it reports a redacted `CLI.OutputUnavailable` error.
Accept output only after exit 0. The [CLI contract](docs/architecture/manifest-context-api.md#cli-and-configuration) defines delivery and cleanup limits.
It does not validate the complete schema, authenticate either document, or establish complete
ancestry or the current authorized policy. The example files contain headers only.
To create a local wheel and source archive, run `uv build`.

The internal `validate_manifest_history` helper validates one complete genesis-to-head sequence.
It requires immutable bytes in an immutable tuple. It permits skipped revision numbers, but each
document must name the previous document by its canonical digest. The sequence is limited to
4,096 documents and 16 MiB in total. This structural check does not authenticate the history,
select the current head, or grant runtime authority. The terminal inspector still accepts only
one optional parent.

The [ActiveState examples](examples/active-state) contain a synthetic genesis state and one
authorization-only successor. They supply fixed structural vectors, not authenticated authority.
The [C33 contract](docs/architecture/manifest-context-api.md#implemented-structural-activestate-header)
defines their fields, digest, monotonic rules, and limits.

The field-format helpers check descriptor structure and compute canonical bytes and a
domain-separated digest. For example:

```python
from pathlib import Path
from cryptalis.manifest.descriptor import digest_field_format_json

raw = Path("examples/field-formats/parameterless.json").read_bytes()
print(digest_field_format_json(raw))
# b96d954389cb35bb7ccd4d59cac9ccf70cb0028a4073fae3fd4057587663417f
```

The [example descriptor](examples/field-formats/parameterless.json) is a synthetic structural
vector. Its numeric IDs do not identify approved production algorithms.
The helpers do not resolve catalogue entries, approve codec parameters, authenticate policy,
or encrypt data. Descriptor bytes are stable format bindings for future additional authenticated
data. They do not supply current authorization.

The private parsers have no public API or CLI command.
The [F1 example](examples/envelopes/f1-structural.hex) and
[W1 example](examples/envelopes/w1-structural.hex) contain synthetic header and ciphertext bytes.
Neither example is a valid authenticated encryption vector.
The crypto owner defines [F1 limits](docs/architecture/crypto-search-lifecycle.md#32-parser-and-resource-limits)
and [W1 limits](docs/architecture/crypto-search-lifecycle.md#35-local-secret-wrapping-candidate-w1).
Authentication, authorized registry selection, and format freeze remain pending.
The [scalar vectors](examples/scalars/candidate-vectors.json) contain synthetic encoded values.
The [scalar boundary](docs/architecture/crypto-search-lifecycle.md#implemented-scalar-syntax-boundary)
defines syntax limits. Field-specific validation, authentication, and format freeze remain pending.

## Purpose and boundary

Application engineers would use Cryptalis to protect selected sensitive model fields. Operators
would manage migrations and key access. Reviewers would interpret evidence within its stated
scope. The first target is a tenant-aware Python service with registered SQLAlchemy sessions,
PostgreSQL, stable record IDs, and host-issued identity and authorization grants. The
application process handles plaintext and is trusted.

The design requires supported paths to encrypt protected values before PostgreSQL receives them.
The intended protection covers database dumps, backup disclosure, direct SQL extraction, and
accidental persistence through supported paths. It does not prevent SQL injection, cross-site
scripting (XSS), business authorization bugs, application-host compromise, or deliberate export
of decrypted values. Search terms, IDs, and lengths reveal declared information.

The initial profile proposes rejection of mediated Core/text/bulk paths and exclusion of raw drivers, COPY, ETL, and separate writers.
External paths remain coverage gaps unless database privileges demonstrably exclude them. A successful exploit and exposure of protected plaintext are separate results.

Transparent fields remain ordinary Python values. Application serializers and logs can receive
these values. Controlled access is a separate profile that requires release bound to purpose and
identity.

A local reveal wrapper alone is not an independent security boundary. Key removal or restore
denial does not prove erasure of backed-up key bytes or unmanaged copies.

## System shape

```text
DeclaredPolicy -> generated PolicyLock + immutable desired history
                        |
                        v
              target-bound offline transition
                        |
                 full verification + CAS
                        |
                        v
       external authenticated ActiveState -> admitted runtime
                        |
          separate irreversible finalization + bounded receipt

      read-only preflight and optional later assurance evidence
```

These names summarize the [shared authority contracts](docs/architecture/manifest-context-api.md#desired-policy-and-active-authority).
The [ORM owner](docs/architecture/orm-schema-migration.md#migration-state-machine-and-concurrency) defines the single internal engine.
Editing a declaration does not activate it. Removing a declaration does not decrypt or drop data.
The future `migrate` flow shows the target, maintenance requirement, storage/time estimates, rollback boundary, and pending irreversible cleanup.
It transforms offline, verifies completely, then changes authenticated active state.
Plaintext publication and loss of recovery require separate explicit approval.

Search is disabled initially. Equality, IN, uniqueness, and advanced query capabilities need individual leakage and correctness gates.
Async, online coexistence, mixed writers, fleet caches, CDC, and multi-provider support remain later cells.
Key preparation stays internal at explicit Session boundaries. The developer supplies trusted identity once and does not choose keys or AAD.
The exact public-hook experiment may select an explicit repository path instead.

The [recovery contract](docs/architecture/crypto-search-lifecycle.md#recovery-manifest-and-restore-admission) treats restored data and schema as untrusted.
Current external policy and denial dominate old snapshots. Deprotection and guided remove retain explicit backup/key/recovery-reader obligations.
Those workflows remain proposed. Uninstall or column drop is not proof of copy erasure.

Doctor, Protection Graph, Verify breadth, Pentest, and network evidence remain valuable research tracks.
They are optional for first-transition value and never activate policy or approve cleanup.
Attribution and differential comparison take priority over novelty claims.

## Start here

| Document | Responsibility |
|---|---|
| [Architecture blueprint](docs/architecture/README.md) | Authoritative ownership map, decisions, threats, invariants, and dependency graph |
| [Manifest/context/API](docs/architecture/manifest-context-api.md) | Semantic schema, identity provenance, public interfaces, modules, errors, and versions |
| [Crypto/search/lifecycle](docs/architecture/crypto-search-lifecycle.md) | Envelope, leakage, provider, cache, fence, restore, and receipt contracts |
| [ORM/schema/migration](docs/architecture/orm-schema-migration.md) | Query paths, async alternatives, physical schema, Alembic, and migration recovery |
| [Assurance/evidence](docs/architecture/assurance-evidence.md) | Doctor, Protection Graph, Verify, Pentest, collectors, network, bundles, and benchmarks |
| [Solo build guide](docs/cryptalis-build-guide.md) | Learning order, first files, and evidence checkpoints |
| [Research philosophy](docs/learning-first-research-philosophy.md) | Learning priorities, build-or-integrate choices, and broader research experiments |
| [Checklist](docs/backend-build-checklist.md) | Current implementation and evidence state |
| [Prior art](docs/prior-art.md) | Dated competitor comparisons and positioning limits |
| [Assurance research](docs/security-assurance-suite-research.md) | Analyzer and adversarial research, including falsification |
| [Engineering playbook](ENGINEERING_PLAYBOOK.md#test-layers) | Behavior-first testing policy, manual implementation, review, and release process |
| [Claims audit](docs/documentation-claims-audit.md) | W-1..W-5 closure, adversarial review, and recorded documentation checks |
| [Historical hardening dossier](docs/adversarial-architecture-hardening.md) | Original hostile-review hypotheses and superseded technical details |

The blueprint links ledgers of primary sources. Documented or source-inspected external
capabilities are separate from reproduced Cryptalis capabilities. Existing encryption, ORM,
search, and assurance systems are strong alternatives. The proposed differentiator is
application-specific correlation. Cryptalis does not claim universal superiority or new
cryptographic primitives.

## Next evidence

Start with [C33–C40](docs/backend-build-checklist.md#ordered-foundation-slices): active authority and target-bound transitions, then domain/representation/suite freeze.
After researched closure and review, build one no-search field/Session path, DB preflight, and resumable offline transition.
Keys, recovery/restore, upgrade, decommission, telemetry, and artifact provenance follow their dependencies.
Online/search/fleet/assurance breadth stays later. Documentation and independent research can proceed while runtime gates remain open.

The default learning workflow has the solo builder type source, tests, migrations, and
configuration, one explained file at a time. Explicit user instructions can authorize direct
AI implementation for a named scope. The [playbook](ENGINEERING_PLAYBOOK.md#solo-manual-typing-workflow)
owns that workflow. Documentation changes confer no production security claim.
