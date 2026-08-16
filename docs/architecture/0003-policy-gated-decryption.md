# ADR-0003 — Policy-gated decryption with deny-by-default

**Status:** Accepted
**Date:** 2026-08-12
**Contract:** [AD-4](../../README.md#ad-4--every-decrypt-is-a-policy-decision-and-the-default-is-deny)
**Source:** `capstone-final-decision.md` §4 (ABAC role table, fail-closed default)

## Problem

Encryption alone relocates the trust boundary rather than shrinking it. Once fields are encrypted,
whoever holds a valid gateway credential can read everything the gateway can decrypt — which is a
strictly worse position than before only if that credential is easier to obtain than database
access.

So decryption needs authorization. The design questions:

1. What model — roles, attributes, relationships?
2. What happens to a field nobody remembered to classify?
3. What happens when the authorization component itself is broken or unavailable?

Question 2 is the one that decides whether this system is trustworthy in practice. In every
real deployment, someone adds a column and forgets to register it.

## Constraints

- Not building a general authorization platform. Cerbos, OpenFGA, and Ory Keto exist and are better
  at it. Policy evaluation here exists only to gate decryption. This is a
  [documented non-goal](../../README.md#non-goals).
- Every decrypt is on the hot path, so evaluation must be fast and must not require a network call.
- The decision must be explainable: an auditor asks "why was this allowed?" and the answer must name
  a rule.
- Policy misconfiguration must be discoverable before production, not after a leak.
- 14–16 week budget, one developer.

## Decision

**Deny by default, everywhere, with a pure evaluator.**

### Model

Roles are the baseline; attribute conditions refine them. A policy rule is:

```yaml
- id: allow-billing-read-card
  effect: allow
  principals:  { roles: ["billing-service"] }
  actions:     ["decrypt"]
  resources:   { field_class: "PII", fields: ["card_last4"] }
  conditions:
    env:         ["prod"]
    purpose:     ["payment"]
    time_window: { after: "08:00", before: "20:00", tz: "Asia/Kolkata" }
```

Field classification is an ordered sensitivity ladder — `PUBLIC < INTERNAL < PII < PHI` — and a
principal's clearance must meet or exceed the field's class. This is the Bell-LaPadula "no read up"
idea used where it genuinely fits, rather than imported wholesale.

### Evaluation rules

1. **Deny overrides allow.** A matching deny rule ends evaluation.
2. **No matching allow means deny.** An empty policy set denies everything.
3. **Clearance is checked before conditions**, so a clearance failure is reported as such.
4. **A decision carries a reason**: `Decision(allow: bool, rule_id: str | None, reason: str)`. The
   rule id goes into the audit entry, which is what makes "why was this allowed?" answerable.

### The evaluator is pure

`core/policy/evaluator.py` performs **no I/O**. It takes a request context and a policy set and
returns a decision. Policies are loaded and validated at startup and on explicit reload, not per
request.

This is the decision that makes exhaustive testing cheap: the full decision table is a unit test with
no database, no clock, no network. Time-based conditions receive an injected clock.

### Unregistered fields fail closed at both ends

A field absent from the registry cannot be decrypted **and cannot be encrypted** — `422`, audited.

Rejecting the *encrypt* is the important half. If unregistered fields silently encrypted, the system
would accumulate ciphertext nobody can authorize reading. If they silently passed through as
plaintext, the system would leak while appearing to work. Failing both directions makes forgetting to
classify a column a loud, immediate, testable event.

### Policy unavailability denies

If the policy set fails to load or validate, the service does not fall back to a permissive default
and does not start serving decrypts. A malformed policy document is rejected **at load time**, not at
first request, so the failure appears at deploy rather than in production traffic.

## Alternatives rejected

| Alternative | Why rejected |
|---|---|
| Embed an external engine (Cerbos, OpenFGA, OPA) | A network hop on every decrypt, an extra operational dependency, and a large surface for a policy language this project does not need. Reasonable for a real product; wrong for this scope. |
| Roles only | Cannot express "billing may decrypt card data, but only for a payment purpose, only in production." Purpose limitation is a direct regulatory ask. |
| Full ReBAC / relationship graphs | Solves a problem this system does not have. Decryption is field-scoped, not object-graph-scoped. |
| Allow-by-default with deny lists | A forgotten classification becomes a leak. Inverted from the required failure direction. |
| Policy evaluation inside `api/` handlers | Would make the decision table untestable without HTTP, and would put logic in a layer the README requires to stay thin. |
| Failing open when policy is unavailable | Would make an availability incident into a data breach. |

## Data flow

```
decrypt request
  → api/auth.py resolves principal (identity, roles, clearance)
  → api/routes/decrypt.py builds a RequestContext
       (principal, table, column, subject_id, purpose, env, now)
  → core/policy/schema.py: is (table, column) registered?   ── no ─→ 422, audited
  → core/policy/evaluator.py: Decision                      ── deny ─→ 403 policy_denied,
                                                                       audited with rule_id
  → core/keys/service.py: key state check                   ── revoked ─→ 403
                                                            ── shredded ─→ 410
  → core/crypto: decrypt
  → core/audit: append allow decision with rule_id
```

The encrypt path runs steps 1–3 and the registration check only; encryption is not policy-gated
beyond registration, because writing data the caller already possesses grants no new access.

## Error and security behaviour

| Condition | Status | Code | Audited |
|---|---|---|---|
| Missing or invalid credential | 401 | `unauthenticated` | Yes |
| Policy denies | 403 | `policy_denied` (with `rule_id` in the audit entry, not the response) | Yes |
| Clearance below field class | 403 | `policy_denied` | Yes |
| Key revoked | 403 | `key_revoked` | Yes |
| Key shredded | 410 | `key_shredded` | Yes |
| Field not registered | 422 | `field_not_registered` | Yes |
| Policy set unavailable | 503 | `policy_unavailable` | Yes |

The response body never contains the `rule_id` or the policy reason — that detail goes to the audit
log, where an operator can see it and an attacker probing the API cannot map the policy.

**Accepted trade-off:** a policy misconfiguration causes an outage rather than a leak. That is
chosen deliberately, and it means an operator can turn the system off by deploying a bad policy. The
mitigations are load-time validation, exhaustive decision-table tests, and the denial-rate alert in
the [playbook](../../ENGINEERING_PLAYBOOK.md#observability-and-operational-checks) — a 3× change in
denial rate is the highest-signal alert in the system.

## Testing strategy

- `tests/unit/test_policy_eval.py` — the full decision table: allow by role; deny by role; deny
  overrides allow; each condition type mismatching independently (purpose, env, clearance, time
  window); unknown role; empty policy set. Every row is a named test.
- `tests/unit/test_policy_schema.py` — an invalid policy document is rejected at load.
- `tests/integration/test_unregistered_field.py` — `422` on both encrypt and decrypt, audited.
- `tests/integration/test_policy_unavailable.py` — a load failure denies every decrypt.
- Time-window tests inject a clock; no `time.sleep`, no dependence on the wall clock.
- Release verification exercises the denial path manually and confirms the denial appears in the
  audit log.

## Deferred

- Policy hot-reload without restart — currently reload is explicit; no requirement demands live
  reload yet.
- Delegation and temporary grants with expiry — the time-window condition covers the demonstrable
  case; per-grant tokens are not built speculatively.
- A policy simulation/dry-run endpoint ("would this request be allowed?"). Valuable for operators;
  not required to defend the core claim.
- Per-tenant policy isolation — P10.
- Rate limiting per policy rule rather than per client.
