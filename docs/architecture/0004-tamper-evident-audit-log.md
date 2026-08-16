# ADR-0004 — Tamper-evident audit log

**Status:** Accepted
**Date:** 2026-08-12
**Contract:** [AD-5](../../README.md#ad-5--append-only-hash-chained-audit-log-with-signed-checkpoints)
**Source:** `capstone-final-decision.md` §4 (hash-chained + Merkle audit log with ECDSA checkpoints)

## Problem

The system makes two claims that are worthless without evidence: "every decryption was authorized"
and "this subject's data was erased on this date." Both are historical claims, and history stored in
a mutable table is only as trustworthy as the person with `UPDATE` on it — who is precisely one of
the adversaries in scope (a rogue administrator).

An ordinary log table gives no way to tell whether a row was altered or removed after the fact.

## Constraints

- The audit write is on the request path. It cannot be slow and it cannot silently fail.
- Detection, not prevention. The gateway cannot stop someone with database write access from editing
  a row; it can make the edit **detectable by anyone**, without trusting the gateway.
- Verification must be runnable by an auditor with read access and a public key — not only by the
  service that wrote the log.
- No external transparency-log infrastructure. Self-contained.
- 14–16 week budget.

## Decision

### Hash chain

Each entry stores `prev_hash` and `entry_hash`, where

```
entry_hash = SHA-256( prev_hash || canonical(entry) )
```

`canonical(entry)` is a **version-stable** serialization of `(seq, ts, actor, action, resource,
decision, reason)`. Canonicalization is the load-bearing detail: if the serialization changes, every
historical hash becomes unverifiable. It is therefore versioned and treated as a storage format, with
the same rules as the ciphertext envelope in
[ADR-0002](0002-envelope-key-management.md).

Any mutation, deletion, or reordering breaks the chain at a computable index. `GET /v1/audit/verify`
recomputes and reports the **first** break by sequence number.

### Signed checkpoints

A chain alone is defeated by an attacker who rewrites an entry *and* re-chains everything after it —
they hold the whole table. So periodically, a checkpoint computes a Merkle root over a sequence range
and signs it with **ECDSA P-256**. The private key is held by the gateway; the public key is
published.

An attacker who rewrites history must now forge a signature to stay consistent, which they cannot do
without the signing key. Checkpoints anchor the chain; the chain provides ordering between anchors.

**Why ECDSA P-256 rather than Ed25519.** `capstone-final-decision.md` specifies ECDSA checkpoints,
and P-256 is directly covered by Lab 4 of the course, which makes the choice explicable in the
project's own terms. Ed25519 would be a defensible alternative — simpler to use safely, smaller
signatures, no nonce-generation hazard — and the honest statement is that this is a *tie broken by
project context*, not a security-driven preference. If ECDSA nonce handling in the chosen library
ever looks doubtful, switching is a checkpoint-format version bump, not a redesign.

### What gets audited

Every encrypt, decrypt, denial, key creation, rotation, revocation, shred, policy load, and audit
verification. A denial is a first-class audited event — denials are the most operationally
interesting entries in the table.

### Failure policy, per operation

The audit write cannot be best-effort, but it also cannot uniformly abort the request:

| Operation | If the audit append fails |
|---|---|
| Shred, rotate, revoke (destructive/state-changing) | **Abort the operation.** The append is in the same transaction as the state change. An unrecorded shred is unacceptable. |
| Decrypt | **Fail the request.** An unlogged decryption defeats the log's purpose. |
| Encrypt | **Fail the request.** Consistent with decrypt; simpler than a partial guarantee. |
| Health, metrics | Not audited. |

`audit_append_failures_total` must be zero; any non-zero value is an alert, per the
[playbook](../../ENGINEERING_PLAYBOOK.md#observability-and-operational-checks).

### Content rules

Audit entries record **references, not values**: `key_id`, action, decision, rule id, hashed subject
reference. Never plaintext, never ciphertext bodies, never key material, never tokens. The audit log
must be safe to hand to an auditor who is not authorized to read the underlying data.

## Alternatives rejected

| Alternative | Why rejected |
|---|---|
| Plain append-only table with database permissions | Relies on the database's access control — the same control the threat model assumes may be compromised. No detection if it fails. |
| Ship logs to an external SIEM | Useful, orthogonal, and requires infrastructure the project does not have. Does not make the local record verifiable. |
| Full Merkle tree per entry | More expensive per write for detection the chain already provides between checkpoints. |
| Blockchain / external anchoring | Solves third-party verifiability, which no current requirement demands. Deferred to P9. |
| Signing every entry | Signature cost on every request in the hot path, for a marginal gain over chain + periodic checkpoints. |
| Best-effort audit writes | Would make the strongest claim in the system conditional on nothing having gone wrong. |

## Data flow

**Append** — the operation completes its core work → build entry → read the current tail's
`entry_hash` → compute the new `entry_hash` → insert with the next `seq`. Appends are serialized so
that two concurrent writers cannot both chain from the same tail; this is a known throughput ceiling
and the benchmark in Milestone 8 must measure it rather than assume it away.

**Checkpoint** — periodically (and on demand): select the range since the last checkpoint → compute
the Merkle root → sign with ECDSA P-256 → insert into `checkpoints`.

**Verify** — `GET /v1/audit/verify`:
recompute every `entry_hash` in order → on mismatch, report the sequence number and stop → verify
each checkpoint signature → verify each checkpoint's Merkle root against the recomputed range →
return `{status, entries_checked, first_break_seq | null, checkpoints_verified}`.

Verification is read-only and can be run by anyone with database read access plus the public key.

## Error and security behaviour

- **Detects:** editing an entry, deleting an entry, reordering entries, inserting an entry into the
  middle, and rewriting a whole range without a valid checkpoint signature.
- **Does not prevent:** any of the above. This is detection, and the distinction is stated plainly
  rather than blurred.
- **Does not detect:** appending truthful-looking entries at the tail using the live gateway's own
  signing key — an attacker who has fully compromised the running gateway can write whatever history
  they like from that moment forward. Consistent with the README's non-goal about a compromised host.
- **Truncation at the tail** past the last checkpoint is detectable only if the expected tail is
  known. Frequent checkpoints shrink this window; the checkpoint interval is therefore a security
  parameter, not a performance knob.
- A verification failure is not an error response — `GET /v1/audit/verify` returns `200` with
  `status: "broken"` and the sequence number. The endpoint working correctly *is* it reporting the
  break.

## Testing strategy

- `tests/integration/test_audit_chain.py` — N entries verify; mutating any single row is detected at
  the correct index; deleting a row is detected; reordering is detected.
- `tests/integration/test_audit_coverage.py` — encrypt, decrypt, denial, key creation, rotation, and
  shred each produce exactly one entry with the documented fields.
- `tests/integration/test_checkpoints.py` — a checkpoint signature verifies; a checkpoint over a
  tampered range fails.
- `tests/integration/test_audit_failure_policy.py` — an append failure produces the documented
  behaviour per operation; a destructive operation does not commit without its audit entry.
- A migration test asserting the chain still verifies across a schema migration that touches
  `audit_log`.
- Release verification includes a manual `UPDATE` against an audit row and confirms `audit/verify`
  reports the correct sequence number.

## Deferred

- **P9 — external anchoring** (publishing checkpoint roots somewhere the gateway does not control),
  which is what would close the compromised-gateway gap.
- Checkpoint signing key held outside the gateway process, ideally in an HSM.
- Log rotation and archival of verified ranges — the chain must remain verifiable across an archive
  boundary, which needs design before any data volume forces it.
- Verification of arbitrary sub-ranges without walking from `seq = 1`, which the Merkle structure
  makes possible but which no current requirement needs.
- A standalone offline verifier binary for auditors.
