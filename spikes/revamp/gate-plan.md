# Full-gate continuation plan

> Execution: native, one explained file at a time. No install, commit or permission change.

Authority: [architecture](../../docs/architecture/README.md), [security](../../docs/security.md),
[lifecycle](../../docs/lifecycle.md), [gate definitions](../../docs/build-guide.md).
This is an execution/evidence ledger, not another product specification.

## Invariants and smallest redesign

| Blocker | Violated invariant | Resolution and deciding evidence |
|---|---|---|
| COPY/bulk bypass | An admitted write transforms complete row-bound ciphertext or fails before protected plaintext leaves the application | Add a DBAPI method guard inside the adapter. Permit only inspected SQLAlchemy executions; reject COPY, opaque SQL and raw protocol handles. Support complete bulk insert rows and preserve atomic SQL transactions. An independent connection is a writer-inventory blocker, not an intercepted path |
| Generated identity rejection | Ordinary original identities/defaults work, and payloads bind to the final identity before INSERT | Inspect original integer identity/sequence definitions. Reserve from that same sequence before row preparation. Cover relationship dependency assignment, batches, defaults, rollback/savepoints and concurrent allocation. Reject unqualified custom/ALWAYS/default contracts in plan |
| No representative retrofit | Required application behavior and exact native values remain observable; edits are measured | Freeze `plain_app.py` and its 29 assertions. Protect declared email through one attachment/manifest. Keep age/name queries unprotected because this declaration does not protect them. Change only the opaque SQL writer to its equivalent typed update; report that edit. Add protected-path and admission adversarial cases |

No new authority service, SQL parser, network proxy, custom Result or mapper replacement is selected.
Database shape checks cannot certify ciphertext. An arbitrary privileged independent driver remains outside the guarded adapter.
Unknown/unexcluded writers must block transformation. Do not turn this limit into a universal protection claim.

## Work and interfaces

1. **Representative service test first** — `run_gate_retrofit.py` must retain all original assertions,
   demonstrate COPY/raw/DBAPI rejection before wire execution, and exercise generated IDs and admitted bulk operations.
   First run must fail because the new adapter is absent. Receipts contain safe codes/hashes only.
2. **Local crypto boundary** — `integration_crypto.py` implements bounded text CF1 with actual tenant/field/typed-record
   context and independent payload/search roots. Development material remains in memory. No production qualification.
3. **Integration boundary** — `integration_adapter.py` consumes that boundary and the original registry/engine/manifest.
   It prepares identities and rows, rewrites inspected expressions, guards DBAPI execution, and retains native ORM values.
   Run the new representative test and record any failures before redesigning the relevant path.
4. **Lifecycle and fault evidence** — use the same application and representation for protection, interrupted chunks,
   inspected resume, verification mutants, current-data rollback, payload/search rotation and package-free removal.
   A real lost-reply observation is distinct from the existing post-commit process-exit lab.
5. **Async, cost and remaining qualification** — run the new attached application through async/native session paths,
   rejected raw paths and whole-path measurements. Preserve the existing million-row receipt; rerun only a changed representation.

## External requirements supplied by the user

| Gate | Current external requirement |
|---|---|
| G-PROVIDER | UNKNOWN: no production provider selected. Local/dev functional tests cannot qualify mature-provider custody |
| G-POLICY | UNKNOWN: no deployment procedure selected. No invented provider/deployment identifiers |
| G-CRYPTO / G-RELEASE | UNKNOWN: independent human cryptographic/security review is unavailable; external-review-required |
| G-ADAPTER / G-LIFECYCLE | UNKNOWN for non-owning runtime-role enforcement: `cryptalis_runtime` does not exist and the migration login has no role memberships. No role creation or alternate credentials are authorized |

Every full gate remains UNKNOWN or FAIL until its complete required set passes.
Known application/writer failures remain FAIL, even when a new subset succeeds.

## Progress

- Starting work preserved at `/tmp/cryptalis-gates-preserved-uuh2_1w7/` (67 paths, starting patch and copies).
- Existing completed receipts are reused. No completed service suite or research regression suite was rerun.
- Runtime-role prerequisite observed through one new read-only catalog query.

- Final current-code service pass: retrofit 51, boundary 25, async 14, context 48, lifecycle 23, faults 13, current cost 2. All exited 0 and dropped their own schemas.
- Lifecycle includes a fresh package-free original application child with 35 passing outcomes and actual receive EOF before COMMIT outcome classification.
- Actual-CF1 million-row receipt passes 3 checks. Protection/verification took 128.821 s; equality uses a selective expression index. Later admission-only changes use the 10,000-row current-cost run instead of repeating this unchanged scale representation.
- Final validation initially caught a mapped Core UPDATE annotation failure. Assignment inspection now precedes predicate traversal; the unchanged original oracle supplies regression coverage. Only affected new evidence was rerun.
- Additional real gaps fixed: raw info protocol handles, protected ORDER BY inspection, stale compiled types/context, expression assignments, forged internal admission, relationship tenant moves and live schema/type disagreement.
- Original application source/assertions, completed old receipts, production source/tests/configuration and starting deletions are preserved. Owning documents receive additive dated checkpoints.
- All seven complete gates remain UNKNOWN for the exact reasons in [status](../../docs/status.md#current-integrated-checkpoint-2026-10-07). No provider, deployment identity, human review, backup provenance or non-owning role was invented.
