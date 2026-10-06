# Second adversarial council record

Date: 2026-10-07, Asia/Calcutta. This is native first-party AI review, not an audit or production qualification.
Seven fresh isolated reviewers read the same [frozen brief](frozen-brief.txt) and role-specific instructions.
The [baseline](review-baseline.json) pins 25 files at contract commit d456c12. Commit 1a77e67 preserves the brief.
All reviewers were read-only. They ran no tests, cloud calls or implementation work and did not see sibling reviews.
The native [LLM Council skill](/home/debrato/Projects/oncosyn/.agents/skills/llm-council/SKILL.md) supplied the workflow.
No external model CLI/API or biotech-specific review role was used.

## Findings and disposition

The raw outputs contain **0 HIGH and 6 MEDIUM findings**. Attribute identity appears in two reviewers' findings.
There are five grouped corrections below. No material disagreement required a dispute round. One further review round was used.
The user allowed at most two. No vote substitutes for deciding evidence.

| Reviewer / raw output | Finding | Chair disposition / deciding evidence |
|---|---|---|
| [Authority](authority.txt) | MEDIUM: ordinary changes omit immutable attribute identity | RESOLVED_DESIGN: exact lock-pinned attribute/type/wire schema, sorting and duplicate rejection in lifecycle. Canonical fixture distinguishes same-type/value attributes. Full inventory/wire emission remains G-ORM/G-TRANSITION |
| [Crypto/search](crypto.txt) | MEDIUM: canonical serialization and ordinary-change bytes underspecified | RESOLVED_DESIGN: restricted RFC8785 algorithm and explicit bytes in architecture. Exact request tuple/key schema in lifecycle. Two local encoders agree on edge fixtures. Full independent construction vectors and composed bound remain blocked |
| [ORM](orm.txt) | No new finding. Requested broader observable adapter evidence | S1 now covers refresh failure without autoflush, query autoflush and await-time late additions. Full Result/declarative/default/cascade/cancellation qualification remains UNKNOWN |
| [Claims](claims.txt) | No new finding. Maturity/counts/hash boundaries retained | No production maturity upgrade. Final source/hash/trace checks are separate executable receipts |
| [UX](ux.txt) | MEDIUM: stronger eligibility exclusions arrive after integration | RESOLVED_DESIGN: README checklist precedes declaration. Nullable integrity, freshness/completeness, uniqueness/mapping limits and pauses decide eligibility first. Representative comprehension test unbuilt |
| [Investor](investor.txt) | Two MEDIUM: fixed-load throughput can falsely pass. Operating burden lacks decisive limits | RESOLVED_DESIGN: separate sustainable-load sweep under common latency/failure limits. Numeric integration/pause/drain/recovery/exit TARGETS. Unresolved worker makes bounded-completion deployment ineligible with denial retained. All targets UNMEASURED |
| [Copy](copy.txt) | MEDIUM: proposal commands can imply completed revocation. LOW: present-tense AWS implementation | RESOLVED_DESIGN: proposals output PROPOSAL_ONLY/NOT_APPLIED and require apply PLAN. Executed plan-kind outcomes are distinct. Provider wording states future unbuilt implementation. Actual command/output comprehension remains UNKNOWN |

## Chair observations and changed evidence

A rerun found a refresh regression after pending-state removal moved behind verification. Refresh now suppresses autoflush and
removes pending state only after verified publication. A new query-autoflush oracle failed because private collection skipped native
ORM autoflush. The adapter now explicitly invokes its guarded flush. Await-time late additions reject against the original seal.
The exact failed outputs remain in [spike evidence](../../../spikes/README.md#failed-observations-retained).

A separate contract trace found that flush B followed by flush C cannot share one fixed batch digest. Lifecycle now assigns an
immutable transaction UUID and fresh operation UUID per preparation/flush batch. All batch markers commit or roll back together.
Original xid8/backend fingerprint and every batch classification govern reconciliation. A multi-batch retry cannot replay an isolated
batch. The local PG supplement observes two markers committed together and retained after later row deletion.
Marker integrity, writer lineage, immutable actual parameters and real transport cuts remain assumptions/proof gates.
An all-NULL protected mutation now explicitly resolves a root for its keyed commitment. Cold cost is disclosed.

These corrections occurred **after** the frozen reviews. Reviewers did not inspect the final corrected bytes or rerun the prototypes.
The final checks and local fixtures supply narrower chair evidence. They do not create an extra council verdict or independent review.
The preserved baseline remains unchanged and its full state is retrievable from the recorded commits.

## Remaining boundary

The review found no new demonstrated fatal defect in the narrowed contract. Product viability remains UNKNOWN.
There are zero verified production cells and zero independent cryptographic audits. Real AWS/IAM/drain/termination/failover,
complete ORM/query composition, independent crypto vectors/bounds, operator studies and whole-backend budgets remain blocked.
The [resolution record](../hardening-resolution.md) retains all original findings, 15 kill criteria and final checks.
