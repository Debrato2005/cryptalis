# Implementation status

Evidence date: 2026-10-07, Asia/Calcutta. Source baseline: `49d34f2`.
This document owns current implementation claims. Design owners define intended behavior, not evidence of execution.

## Maturity

| State | Meaning |
|---|---|
| DESIGNED | A chosen contract and proof gate exist |
| IMPLEMENTED | Executable code exists for the exact stated scope |
| VERIFIED | A named check exercised that scope in a recorded environment |

These states are independent. A verified syntax parser does not verify encrypted field protection.
SPECIFIED is a synonym for DESIGNED, not an extra production state.
SUPPORTED elsewhere selects the final intended design scope.
**Verified production compatibility cells: 0. Independent cryptographic audits: 0.**

## Current capabilities

The package metadata remains `0.1.0`, Python `>=3.12`, no runtime dependency list.
The development dependency includes `cryptography==50.0.2`.
These facts describe the existing research package, not the selected final stack.

| Exact implemented scope | Source and evidence | Limits |
|---|---|---|
| Bounded restricted JSON decoding and canonical output/digest | [parser](../src/cryptalis/manifest/parser.py), [canonicalizer](../src/cryptalis/manifest/canonical.py), [parser tests](../tests/test_manifest_parser.py), [canonical tests](../tests/test_manifest_canonical.py) | No final declaration compiler, authenticated policy or runtime protection |
| Schema-1 manifest identity headers, parent link and bounded genesis-to-head ancestry | [header](../src/cryptalis/manifest/header.py), [header tests](../tests/test_manifest_header.py) | Local internal consistency. Attacker-generated consistent history is not authenticated or current authority |
| Restricted structural field-format canonicalization/digest | [descriptor](../src/cryptalis/manifest/descriptor.py), [canonical tests](../tests/test_manifest_canonical.py) | Digests bind supplied syntax. They do not authenticate data or freeze approved crypto |
| Private F1 payload and W1 wrapper framing decoders | [payload](../src/cryptalis/crypto/_candidate_envelope.py), [wrap](../src/cryptalis/crypto/_candidate_wrap.py), [payload tests](../tests/test_candidate_envelope.py), [wrap tests](../tests/test_candidate_wrap.py) | Structural parsing only. No encryption, provider unwrap, authentication or production reader |
| Private text/bytes/int/Decimal scalar encoding and decoding | [codec](../src/cryptalis/crypto/_candidate_scalar.py), [codec tests](../tests/test_candidate_scalar.py), [vectors](../examples/scalars/candidate-vectors.json) | Candidate exact syntax and bounds, including signed Decimal zero. No final mapped-type/normalizer runtime |
| Private ActiveState headers/digests/links/history | [state](../src/cryptalis/contracts/active_state.py), [state tests](../tests/test_active_state.py) | Structural state, not external authorization, revocation or restore resistance |
| Process-local development authority and compare-and-swap | [authority](../src/cryptalis/contracts/development_authority.py), [authority tests](../tests/test_development_authority.py) | In-memory lifetime, no persistence/workload authentication/production concurrency |
| Offline plan admission | [transition](../src/cryptalis/contracts/transition.py), [transition tests](../tests/test_transition.py) | Caller-supplied expiry/target/head observations. No execution, current provider, fence or activation |
| Offline inspect commands and explicit I/O failures | [CLI](../src/cryptalis/cli.py), [CLI tests](../tests/test_cli.py), [history tests](../tests/test_cli_history.py) | Local bounded inspection. No provider/database connection or activation |
| Synthetic Smolink AEAD demonstration | [example](../examples/demo_smolink_crypto.py), [tests](../tests/test_smolink_crypto_demo.py) | Fixed fake rows, ephemeral in-memory key. Five values recover and eleven misuse cases reject. Same-context replay succeeds |

The synthetic example demonstrates one explicit library construction and misuse controls.
It does not import the Smolink application, query a database, use production keys, implement protected queries or satisfy runtime admission.

## Executable entry points

Run from the repository root with the existing environment:

```bash
.venv/bin/python -m cryptalis manifest inspect examples/manifests/genesis.json --json
.venv/bin/python -m cryptalis manifest inspect examples/manifests/successor.json --parent examples/manifests/genesis.json --json
.venv/bin/python -m cryptalis manifest inspect-history examples/manifests/genesis.json examples/manifests/successor.json --json
.venv/bin/python examples/demo_manifest_history.py
.venv/bin/python examples/demo_smolink_crypto.py --json
.venv/bin/python -m pytest -q
```

Inspect returns bounded structural facts and redacted diagnostics.
It rejects invalid files/JSON/history and reports read/write/flush/broken-output failures explicitly.
Output success does not prove authenticated policy, external freshness or durable artifact retention.
The synthetic example's optional `--output NEW_PATH` creates one new fake ciphertext snapshot and refuses overwrite.
No current command is `init`, `doctor`, `plan`, `apply`, `keys`, `restore`, `revoke`, `destroy`, `reconcile`, `abort`, `recover` or `remove`.
The final `attach` API is not currently importable.

## Verification record

Historical reset: 612 research tests passed before (7.16 s) and after (6.91 s) consolidation, exit 0.
The five listed demonstration/inspect commands returned exit 0. Four JSON outputs parsed.
That documentation-only pass changed no executable file and made no install/commit.
These historical observations do not describe the later authorized hardening task's file/install scope.

Hardening baseline: `.venv/bin/python -m pytest -q`, **612 passed in 7.96 seconds**, exit 0.
Final hardening regression: **612 passed in 6.95 seconds**, exit 0.
Scope/spike receipts are recorded in [the resolution record](research/hardening-resolution.md).
The original 16 production source files are compared by SHA-256 with [the captured baseline](../spikes/results/package-baseline.json).
Original source/tests/fixtures/build/dependency files remain outside the spike write boundary.

## Local feasibility observations

These are executed experiments in top-level `spikes/`, not IMPLEMENTED or VERIFIED Cryptalis runtime capabilities.
Actual local cell: Linux CPython 3.12.3, SQLAlchemy 2.1.3, psycopg 3.3.6, cryptography 50.0.2/OpenSSL 4.0.3,
PostgreSQL 16.2. It is not the selected CPython 3.14.8/RDS PostgreSQL 18.6 production cell.
Exact dependency hashes, hypotheses, commands and raw result files are in [spikes](../spikes/README.md).

| Experiment | Observation | Important limit |
|---|---|---|
| S1 real PostgreSQL sync/async public-API ORM | Dirty entity/scalar separation, identity refresh/expiry/rollback, failed refresh without autoflush, merge/bulk rejection, whole-buffer failure and late flush/autoflush/await rejection pass | One imperative model/field, fake local material, incomplete Result/mapping/query/cancellation coverage |
| S2 bounded exploration and local PG supplement | 1,216 states / 3,664 transitions. Lock-only drain counterexample, stale-owner/capacity/recovery checks, two immutable batch markers commit together and survive later deletion | Two operations, atomic fake authority, discarded application ACK rather than transport cut, no live worker termination/AWS/failover |
| S3 real PostgreSQL search | Concurrent duplicate produces one commit/one conflict, NULL/IN and all-row soft-delete rule, real index plan/storage observed | Synthetic normalizer/data. Hostile unreturned term corruption permits logical duplicate |
| S4 crypto smoke/fork | Native AEAD works. Tamper/relocation/wrong context/key/nonce reject. Inherited PID handle denies | Synthetic descriptor/root and fresh child fixture, no independent vector/composition/RNG/provider proof |
| M5 predicate supplement | PostgreSQL hidden division projection introduces error. Validator rejects 10 unsafe forms. Six three-valued outcomes match | Small grammar subset, not full runtime differential oracle |
| Canonical/request supplement | Two local encoders agree on Unicode/control/order/NULL/integer fixtures; different ordinary attribute IDs change HMAC; duplicate IDs reject | First-party fixtures and one driver type, no full compiler or independent expert vectors |

No AWS service call or production credential was used. No cloud gate passed.
Cold-provider/IAM/authority/latest-history/recovery/destruction evidence remains UNKNOWN.
Whole-backend performance TARGETS remain UNMEASURED. Human security/cryptographic review remains absent.
**Verified production compatibility cells: 0. Independent cryptographic audits: 0.**

## Reuse and replacement

This map judges fit against the final product. Existing code does not choose the architecture.

| Existing item | Reuse judgment | Required change |
|---|---|---|
| Bounded JSON decoding/canonicalization | Candidate utility reuse after exact profile, bounds and independent vectors match | Separate the final declaration/lock schemas from experimental identity headers |
| Redacted CLI I/O/error handling | Candidate behavior reuse | New command/result schema and exact typed runtime failures. Legacy inspect need not remain a product command |
| Structural header/history/ActiveState helpers | Research/evidence only | Replace authority semantics with current DynamoDB admissions and permanent denial. No parser/history chain becomes live trust |
| Process-local CAS/offline admission | Useful local test ideas | Replace persistence, authentication, idempotency, current-state and effect orchestration contracts |
| F1/W1 and candidate scalar codecs | Historical experiments, no required production reader | Replace with CPD2, bare codec 2, direct KMS wrappers and frozen admitted context |
| Synthetic Smolink example | Keep as a scoped demonstration while useful | It cannot become production crypto, search or provider evidence |
| Current tests/fixtures | Fault ideas and historical vectors, each reviewed individually | Replace obsolete assertions. Protect chosen behavior rather than preserve private APIs or counts |
| Current module layout/package dependency surface | No preservation requirement | Build the intended dependency direction. Merge or replace modules when their real responsibilities require it |

No production data in this repository establishes F1/W1/schema-1 read compatibility.
Actual admitted production formats must retain their required readers during later upgrades.
Those two facts are separate. This reset changes no executable files.

## Implementation delta

| Final architecture | Current gap and gate |
|---|---|
| Declaration/lock compilation and downgrade pinning | No compiler or external activation. S01 / G-MANIFEST |
| CPD2 AEAD/context/KDF and full-width equality terms | Only candidate syntax and synthetic encryption. S02 / crypto, context, cross-key and semantics gates |
| Live AWS custody/current authority/journal/fences/cache | Only process-local state. S03 / G-AUTHORITY, G-PROVIDER and G-REVOCATION |
| Transparent ordinary sync/async session read/write | No attachment or mapping adapter. S04 / G-ORM, G-ASYNC and G-BYPASS |
| Supported equality/IN/uniqueness | No encrypted query runtime. S05 / G-SEARCH and G-SEMANTICS |
| Doctor/schema/plan | Offline inspection only. S06 / G-DOCTOR and G-PLAN |
| Verified lifecycle, rollback, rotation, restore, revocation/destruction and package-free removal | Offline plan admission only. S07–S12 / lifecycle-specific gates |
| Whole-backend performance and release | No benchmark or audited release. S13 / G-PERFORMANCE and G-RELEASE |

The [build guide](build-guide.md) gives exact dependency order and behavioral definitions of done.
The [decision ledger](decisions.md) fixes the design defaults and names production blockers.
A failed prototype requires a reviewed decision change. It cannot justify silent fallback or an implementation claim.
