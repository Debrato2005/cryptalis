# Cryptalis LLM Council adversarial review

## Decision

Retain the bounded field-protection product direction. Treat the attached-session integration and distributed completion protocol as provisional until decisive experiments establish feasibility.
Change the contracts below before the full implementation sequence becomes a commitment. Existing source, APIs, tests, modules and experimental formats create no preservation requirement.

This is a read-only architecture review. It changes no repository file and supplies no executable runtime evidence.
The current design remains unimplemented for protected ORM, live authority and lifecycle execution. The recorded research tests are not production qualification.

## Why this won

- Ordinary attributes and equality queries offer useful integration, but public-hook state preservation and async preparation need an early feasibility proof.
- Current authority, independent destructive intent and explicit maintenance keep meaningful safety boundaries. Their admission and outcome mechanisms need precise ordering.
- Quota limits, rollback mirrors and recovery dependencies create operational limits that plans must calculate before effects.
- The documentation states maturity and major threat exclusions honestly. Most findings concern incomplete contracts, rather than concealed implementation claims.

## Findings

Four findings have HIGH priority. Six have MEDIUM priority. These ratings describe architecture work, not demonstrated runtime vulnerabilities.
HIGH means a core security or correctness contract lacks a decisive mechanism or feasibility proof.
MEDIUM means a bounded semantic, availability, recovery-interface or claim problem needs a contract change.
Each failure trace is a review inference. None was reproduced in a runtime experiment during this review.

### R1 — HIGH: Specify fence ordering and ownership after lock loss

Owner: [security.md](/home/debrato/Projects/cryptalis/docs/security.md:119).

A worker observes authority before acquiring its fence or registering ownership, then suspends.
Denial can complete before that worker resumes. The contract requires fences and registration but does not fix their complete ordering.

A fence-first read protocol can solve this interval: acquire the shared fence before observing authority and hold it through authenticated result handoff.
A pre-deny read can finish while denial remains PENDING. The exclusive fence cannot complete meanwhile.
Conditional remote registration is an alternative, not a mandatory transaction for every read.

The remaining risk occurs when DB termination or failover removes the lock while a surviving worker retains a publishable buffer.
Commit reconciliation and required publication acknowledgements can also continue after transaction-lock release.
Define durable ownership for every such interval. Denial must wait until those workers are terminal or reconciled.
A connection snapshot or expired timeout cannot establish safe drain.

The selective dispute round resolved this point. Both technical reviewers accepted fence-first read safety with continuous lock coverage.
Specify the smallest proven protocol, including what happens when that coverage fails.
DynamoDB's own transaction isolation does not supply cross-system publication ordering.
[DynamoDB transaction isolation](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis.html).

### R2 — HIGH: Give ordinary commits durable outcome evidence

Owner: [security.md](/home/debrato/Projects/cryptalis/docs/security.md:388).
Lifecycle already defines atomic chunk markers at [lifecycle.md](/home/debrato/Projects/cryptalis/docs/lifecycle.md:56).

An ordinary mutation commits, but its response disappears and the worker dies. A later mutation changes or deletes the same records.
Current row state no longer distinguishes the original commit from rollback followed by another writer.
The contract says to reconcile by operation and record identity, but specifies no durable ordinary-transaction outcome record.

Commit a unique outcome record atomically with each ordinary mutation, including deletion.
Define its retention, recovery barrier and acknowledgement protocol. Marker absence cannot establish rollback while the original backend can still commit.
Separate DB transaction-lock lifetime from external ownership retained during acknowledgement reconciliation.
This concerns crash recovery under the admitted transaction model. It does not introduce hostile-DB outcome authenticity as a new guarantee.

### R3 — HIGH: Prove dirty-state preservation and atomic publication through public ORM APIs

Owner: [architecture/README.md](/home/debrato/Projects/cryptalis/docs/architecture/README.md:103).

Load stored email A, assign pending email B, then query under no_autoflush.
The entity must keep B, its scalar projection must return authenticated A, and its next flush must persist B.
If another row fails authentication, no newly decoded value may appear through the existing entity reference.

The design correctly separates pending and stored state. It does not yet prove that the selected public extension APIs can implement this combination.
SQLAlchemy's public set_committed_value cancels existing attribute history. A direct publication shortcut can therefore destroy the pending write.
[SQLAlchemy attribute state API](https://docs.sqlalchemy.org/en/21/orm/session_api.html#sqlalchemy.orm.attributes.set_committed_value).

Test this sequence early in sync and async modes, including identity reuse, repeated flush, refresh, expiry, rollback and late buffer corruption.
If public APIs cannot meet it, replace the integration abstraction or explicitly revise the product contract.
Do not preserve attachment merely because the decision ledger already selects it.

### R4 — HIGH: Define when the async protected write set becomes final

Owner: [architecture/README.md](/home/debrato/Projects/cryptalis/docs/architecture/README.md:100).

Awaited preparation loads keys for pending subject A. A host before_flush callback then adds subject B.
B needs a cold root inside a synchronous flush event. The adapter must reject, block the event loop, or find another awaited preparation boundary.
The same issue can recur when commit triggers further flush work.

SQLAlchemy permits before_flush listeners to add objects and change attributes. [SQLAlchemy flush events](https://docs.sqlalchemy.org/en/21/orm/session_events.html#before-flush).

Specify which mutating host callbacks attachment admits. Reject late protected mutations before DML, or prove a bounded protocol that prepares their complete write set.
Extend the callback exclusions beyond protected load callbacks where necessary. Test commit and autoflush separately.
Blocking provider calls inside synchronous async-session events cannot be the fallback.

### R5 — MEDIUM: Predicate safety must include error behavior

Owner: [compatibility.md](/home/debrato/Projects/cryptalis/docs/compatibility.md:58).

Consider protected_eq OR 1 / ordinary_denominator > 0 for a matching protected value and a zero denominator.
The original execution can omit the division. A hidden Boolean projection can force evaluation and introduce an error.
Determinism alone does not rule out division errors, overflow or invalid conversions.

Admit only expressions that safely evaluate over their declared input domain, or prove a guarded rewrite.
The differential oracle must compare success and error outcomes, not only truth tables.
This is a proposed counterexample, not a guaranteed PostgreSQL plan or a reproduced failure.
PostgreSQL does not fix Boolean evaluation order and can omit unnecessary subexpressions.
[PostgreSQL expression evaluation](https://www.postgresql.org/docs/18/sql-expressions.html#SYNTAX-EXPRESS-EVAL).

### R6 — MEDIUM: Preflight target capacity and retained-generation headroom

Owners: [security.md](/home/debrato/Projects/cryptalis/docs/security.md:238), [lifecycle.md](/home/debrato/Projects/cryptalis/docs/lifecycle.md:95).

Two separate traces matter.

A tenant-scoped live set with more than 2**24 non-null protected values cannot fit one fresh target generation.
The 2**40-byte ceiling creates another bound. Retrying rotation does not enlarge one generation's capacity.
Burned reservations further reduce capacity.

An exhausted source generation can rotate a smaller live set successfully. However, resumed writes must also encrypt into its retained rollback mirror.
The old generation has no quota, so those writes fail until finalization. Existing atomic-failure rules correctly prevent silent corruption.

PLAN must calculate target live-set capacity, burned reservations, retry allowance, growth allowance and each retained generation's mirror headroom.
Reject impossible adoption before effects. If a writable observation window is impossible, state that fact and require approved finalization before writer resumption.
Change the root partition contract only through an explicit architecture decision.

### R7 — MEDIUM: Qualify logical uniqueness against hostile term mutation

Owner: [architecture/README.md](/home/debrato/Projects/cryptalis/docs/architecture/README.md:224).

Record A contains value X and term T(X). A DB writer replaces its term with another well-shaped 32-byte value.
An honest insert of record B with X now passes SQL UNIQUE.
A query for X can return authenticated B while the corrupted A remains unreturned.

This follows from the documented omission boundary. It is not a cipher break or evidence that ordinary concurrent UNIQUE enforcement fails.
State explicitly that race-safe logical uniqueness assumes intact existing terms and constraints under admitted writers.
Add the trace as an expected hostile-database counterexample. Returned-buffer authentication cannot establish global index integrity.

### R8 — MEDIUM: Specify operation-ID resumption and failure-specific remedies

Owners: [lifecycle.md](/home/debrato/Projects/cryptalis/docs/lifecycle.md:16), [architecture/README.md](/home/debrato/Projects/cryptalis/docs/architecture/README.md:248), [security.md](/home/debrato/Projects/cryptalis/docs/security.md:387).

An operator loses the terminal and original plan, then returns after initial plan expiry.
The lifecycle requires resumption by durable operation ID, but the public command contract only shows apply PLAN.
The description says apply can resume, yet the exact invocation and retained proposal source remain unspecified.

Define operation-ID resumption within the existing apply command, for example apply --resume OPERATION.
Status and partial failures must show that exact invocation, current prerequisites and the retained immutable operation source.
A separate resume command is also workable. The public recovery behavior matters more than its spelling.

A fresh session is also insufficient as the sole remedy for every read failure.
Corrupt ciphertext or terms require authorized integrity inspection. Denial requires authority reinspection.
Buffer overflow requires a bounded query. Repeated unchanged queries must not masquerade as recovery.

### R9 — MEDIUM: Name subject denial according to its actual effect

Owner: [architecture/README.md](/home/debrato/Projects/cryptalis/docs/architecture/README.md:255).
The correct limit appears at [lifecycle.md](/home/debrato/Projects/cryptalis/docs/lifecycle.md:183).

An operator can run shred --subject and write “subject shredded” in a deletion ticket.
Backup wrappers under a surviving domain KEK remain recoverable, and shared equality terms remain linkable.
The lifecycle explains this correctly, but the command name invites a stronger conclusion.

Prefer revoke --subject or deny --subject for managed denial.
Reserve destruction language for the separately observed domain-custody result.
Test whether operators distinguish access denial, recoverable backup data and bounded destruction from command output alone.

### R10 — MEDIUM: Qualify the opening promise and show adoption eligibility first

Owners: [README.md](/home/debrato/Projects/cryptalis/README.md:4), [README.md](/home/debrato/Projects/cryptalis/README.md:12), [architecture/README.md](/home/debrato/Projects/cryptalis/docs/architecture/README.md:7).

“Encrypt before PostgreSQL receives them” exceeds the full lifecycle contract if read literally.
Protection observation writes a plaintext rollback mirror. Approved deprotection writes plaintext staging columns.
The owners disclose both effects, so this is a headline ambiguity rather than concealed exposure.

“One setup call” also precedes the exact-stack, identity, query/loading, writer and maintenance restrictions.
A backend can fit the syntax example but require substantial adoption work.

Use this bounded opening:
“Cryptalis currently supplies research parsers and synthetic examples.
Its designed runtime targets one reviewed SQLAlchemy/PostgreSQL/AWS stack.
After finalized protection, admitted ordinary writes store selected payloads as ciphertext.
Approved lifecycle operations can retain or create plaintext copies.
Adoption requires compatible mappings, bounded reads, reviewed writers, schema changes and maintenance windows.”

Place a short eligibility check before the setup example. Ordinary syntax must not imply ordinary SQLAlchemy breadth.

## Important dissent

One material remedy dispute emerged: whether every read requires epoch-conditional remote registration.
The chair challenged that requirement with a fence-first alternative. The authority and ORM reviewers both accepted it in a selective second round.
The controlling requirement is continuous ownership through handoff, including surviving workers after backend lock loss.
Remote registration remains necessary where the chosen protocol cannot otherwise establish that ownership.

The UX reviewer proposed a new resume command. The chair prefers an explicit operation-ID mode within apply to keep the public surface smaller.
Either spelling must supply the same durable recovery contract.

Domain-wide maintenance, the rollback deadline, permanent denial after unprovable authority loss and retained recovery obligations are acknowledged choices.
The council does not reclassify them as hidden security defects.
Their acceptability to a representative customer remains untested.

## Claim guardrail

This review is first-party AI design work. It is not an independent human security review, cryptographic audit or production approval.
The documents record zero verified production cells and zero independent cryptographic audits.
The council did not rerun the recorded 612 research tests or execute any proposed runtime experiment.
Missing evidence remains UNKNOWN.

## Implementation direction

Before committing to S01–S13, run one separately authorized feasibility effort with synthetic data and a representative backend.
The current review authorizes no implementation.

1. Prove public-API ORM state and publication behavior, including late flush mutations, in sync and async modes.
2. Prove admission/fence ordering, ownership after lock loss and durable ordinary commit outcomes under suspension and lost acknowledgements.
3. Use small quotas to force live-set rejection and exhausted rollback-mirror behavior before switch.
4. Measure application changes, hot/cold latency, authority/provider cost, domain downtime and interrupted recovery against predeclared budgets.
5. Exercise operation-ID resumption, revocation, restored-backup denial and package-free application exit. Assign retained backup dependencies to an owner.

The controlling observation is whether the useful workflow meets those budgets while preserving every invariant.
If it cannot, revise the architecture before building around its chosen abstractions.
Do not add private ORM hooks, plaintext fallback or stale authority to force a successful result.

## Alternatives rejected

- Treating the selected architecture as settled because its specification is precise: crucial mechanisms still lack feasibility evidence.
- Preserving research formats, existing module boundaries or test counts: none establishes a final-product requirement.
- Replacing the product with a wire proxy now: no review evidence establishes that it solves the identified state, authority and lifecycle problems.
- Weakening buffering, quota, tombstone or recovery rules to improve adoption: that changes the security contract without resolving the stated risks.
- Calling all documented exclusions defects: it obscures the concrete contract gaps and misstates the claim boundary.

## Council record and confidence

The council used [the installed native LLM Council skill](/home/debrato/Projects/oncosyn/.agents/skills/llm-council/SKILL.md).
Seven fresh reviewers received the same frozen packet without parent history or sibling conclusions.

Selected skill roles: Scientific Claim Auditor adapted to software evidence, Product / UX Designer, Skeptical Investor / Grant Reviewer, and Copy + Narrative Reviewer.
Added technical roles: Cryptography and Search, SQLAlchemy and Database Semantics, and Distributed Authority and Lifecycle.
Biotech Brand, Translational Oncology and Data Visualization roles were omitted because this decision has no biological, brand-system or visual-encoding question.

All seven reviews returned. No selected reviewer failed, remained incomplete or was simulated.
This was a native Codex council, not a set of external model-provider calls.
No repository files changed, no packages were installed, and no tests ran during the council review.

Confidence: MEDIUM. Canonical contracts and official documentation support the findings.
The core runtime feasibility, cryptographic composition and operational budgets still lack executable evidence and independent human review.

