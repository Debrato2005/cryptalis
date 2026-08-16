# Architecture Decision Records

Focused design records for the complex and security-sensitive parts of the system. Each record
states the problem, the constraints that bound it, the design selected, the alternatives rejected
and why, the data flow, the error and security behaviour, the testing strategy, and what is
deliberately deferred.

**Relationship to the README.** [README.md](../../README.md) carries the short form of each decision
as a durable contract (AD-1 … AD-7). These records carry the reasoning. A change that revises a
decision edits **both**, in the same commit — the README so that the contract stays honest, the ADR
so the next person knows what changed and why.

**When to write a new record.** When a decision is hard to reverse: a wire or storage format, a key
scoping choice, a chain construction, a trust boundary, a deployment shape. Reversible decisions
belong in a commit message. See the
[decision-making guidelines](../../ENGINEERING_PLAYBOOK.md#decision-making-guidelines).

## Index

| ID | Title | README contract | Status |
|---|---|---|---|
| [0001](0001-write-time-encryption-boundary.md) | Write-time encryption boundary | AD-1 | Accepted 2026-08-12 |
| [0002](0002-envelope-key-management.md) | Envelope key management, per-subject DEKs, and crypto-shredding | AD-2, AD-3 | Accepted 2026-08-12 |
| [0003](0003-policy-gated-decryption.md) | Policy-gated decryption with deny-by-default | AD-4 | Accepted 2026-08-12 |
| [0004](0004-tamper-evident-audit-log.md) | Tamper-evident audit log | AD-5 | Accepted 2026-08-12 |
| [0005](0005-sdk-integration-and-deployment.md) | SDK integration and deployment topology | AD-6 | Accepted 2026-08-12 |
| [0006](0006-educational-module-quarantine.md) | Educational module quarantine | AD-7 | Accepted 2026-08-12 |
| [0007](0007-orm-integration-layer.md) | ORM integration investigation | — | Deferred pending a deliberate revision of ADR-0005 |
| 0008 | Threat model | — | **Planned** — Milestone 10, see the [checklist](../backend-build-checklist.md#milestone-10--release) |

**Status vocabulary:** *Accepted* — in force. *Superseded by NNNN* — replaced; the record stays for
history. *Planned* — identified as needed, not yet written.

Records 0001–0006 are the accepted pre-code decisions. Record 0007 is retained as a deferred
investigation because it proposes a different integration layer; it is not a current contract.
No application code exists yet to validate the accepted designs.

## Template

```markdown
# ADR-NNNN — Title

**Status:** Accepted | Superseded by NNNN | Planned
**Date:** YYYY-MM-DD
**Contract:** AD-N in README.md (if applicable)

## Problem
## Constraints
## Decision
## Alternatives rejected
## Data flow
## Error and security behaviour
## Testing strategy
## Deferred
```
