# ADR-0005 — SDK integration and deployment topology

**Status:** Accepted
**Date:** 2026-08-12
**Contract:** [AD-6](../../README.md#ad-6--integration-is-a-python-sdk-not-a-proxy)
**Source:** `capstone-final-decision.md` §4 (two-repo structure, additive changes to the protected
application accepted)

## Problem

[ADR-0001](0001-write-time-encryption-boundary.md) puts the encryption boundary in the application's
data-access layer. That leaves the mechanical question: **how does the application actually reach the
gateway**, and what happens when the gateway is not there?

The second half matters more than the first. A gateway in the write path is a new failure mode for
the protected application, and the research document names this as the project's main adoption
barrier. The design has to face it rather than assume it away.

## Constraints

- The protected application (*Smolink*) lives in a separate repository and is a FastAPI/Postgres
  service. Additive changes to it are acceptable; a rewrite is not.
- One developer, 14–16 weeks. A SQL-rewriting proxy is out of budget and out of scope.
- The demo must run from a single `docker compose up` on a laptop.
- The gateway is stateless with respect to application data, so it can be scaled horizontally later
  without redesign.
- Nothing may make a plaintext write possible when the gateway is unavailable.

## Decision

### A thin Python SDK, called from the data-access layer

The application depends on `ale_gateway_sdk` and calls it where it already knows the subject, the
table, the column, and the record identifier:

```python
ciphertext, key_id = client.encrypt_field(
    subject_id=user.id, table="links", column="destination_url",
    record_id=link.id, plaintext=url,
)
```

The SDK is deliberately dumb: build the request, authenticate, apply a timeout, parse the response,
raise typed errors. It contains no cryptography and no caching. All security decisions happen
server-side, so an application cannot weaken them by using an old SDK version.

### Failure behaviour is part of the security contract

| Situation | SDK behaviour |
|---|---|
| Gateway unreachable or times out on **encrypt** | Raise. The application's write fails. **Never fall back to plaintext.** |
| Gateway unreachable on **decrypt** | Raise. The application surfaces an error; it must not substitute a placeholder that could be mistaken for data. |
| `403` / `410` / `422` | Raise a distinct typed error per code. **No retry** — a denial is not a transient fault. |
| `429` or `503` | Retry with bounded exponential backoff and jitter, capped. |
| `5xx` on encrypt | Retry within the cap, then raise. |

Timeouts are explicit and short; the SDK never inherits an unbounded default. A circuit breaker is
noted as future work, not shipped speculatively.

### Topology

**Development and demo** — one Compose stack: Postgres, gateway, demo application. Two logical
databases (or two schemas with separate roles) so that "the gateway owns its tables" is enforced by
permissions, not by convention.

**Reference production** — gateway deployed alongside the application on a private network, TLS
between them, KEK from the platform's secret store. Bearer-token authentication today; mutual TLS is
the documented target and its absence is stated in the README rather than glossed.

The gateway holds no application data and no per-request state, so horizontal scaling is adding
replicas. The two shared-state considerations are the DEK cache (per-process, so a cache miss after a
scale-out is a latency event, not a correctness one) and audit-append serialization (a genuine
throughput ceiling — see [ADR-0004](0004-tamper-evident-audit-log.md)).

### Two repositories

The gateway and the demo application stay separate, per `capstone-final-decision.md`. The demo must
consume the SDK the way any adopter would — if the integration only works because both live in one
repository, the integration is not real. A boundary test asserts the SDK does not import the server
package.

## Alternatives rejected

| Alternative | Why rejected |
|---|---|
| SQL-rewriting proxy between application and database | Must parse arbitrary SQL, prepared statements, JSON operators, multi-row writes. Largest surface, highest risk, transparent-but-fragile. Deferred to P3. |
| Sidecar container with a local socket | Reduces network hops but adds deployment complexity for a benefit no current constraint demands. Deferred to P3. |
| ORM hooks / SQLAlchemy type decorators doing encryption implicitly | Attractively invisible, and that is the problem: the encryption boundary becomes hard to see in review, and the AAD components are not always available at the type layer. Rejected in favour of explicit calls. |
| Client-side encryption in the SDK with keys fetched from the gateway | Removes a round trip and would improve latency, but puts unwrapped DEKs in every application process — enlarging the blast radius that per-subject keys exist to shrink. Reconsider only with measurement and an explicit ADR. |
| Merging the demo application into this repository | Would hide integration friction that adopters will hit. |
| Multi-language SDKs in v1 | Honest scope limit. Python-only, stated openly. P4. |

## Data flow

```
application request handler
  → service layer
    → data-access layer
      → ale_gateway_sdk.encrypt_field(...)
        → HTTP POST /v1/encrypt   (bearer token, explicit timeout)
          → gateway: auth → registry → policy(registration) → key service → AEAD → audit
        ← {ciphertext, key_id, version}
      → INSERT ... (ciphertext, key_id)
```

Read is the mirror image, with a policy decision before the key lookup.

The application stores only opaque bytes plus `key_id` and never inspects envelope structure — that
is what allows the envelope format to evolve without touching adopters.

## Error and security behaviour

- **The prohibited behaviour**, tested for explicitly: a gateway failure resulting in a plaintext
  write. `tests/unit/test_sdk_client.py` asserts the SDK raises, and `tests/e2e/test_demo_flow.py`
  asserts with raw SQL that the column never contains plaintext.
- The SDK never logs plaintext, never logs the bearer token, and never includes request payloads in
  exception messages.
- Availability coupling is real and stated: protected writes fail when the gateway is down. The
  mitigations are the gateway's statelessness (run more than one) and short, explicit timeouts so a
  slow gateway degrades into a fast failure rather than a hung request pool.
- The token is per-client and rotatable by configuration plus restart. Until mutual TLS lands, a
  stolen token is constrained only by policy — which is why policy exists, and why the denial-rate
  alert matters.

## Testing strategy

- `tests/unit/test_sdk_client.py` — timeout behaviour; retry only on `429`/`503`/`5xx`; no retry on
  `403`/`410`/`422`; failures raise typed errors.
- `tests/e2e/test_demo_flow.py` — write through the application, then a **raw SQL assertion** that
  the plaintext is absent from the column.
- `tests/boundary/test_sdk_has_no_server_imports.py` — the SDK is independently installable.
- Compose-level smoke test: `docker compose up --build` reaches healthy and the demo flow passes.
- Release verification runs the quickstart on a clean clone with no undocumented steps.

## Deferred

- Circuit breaker and bulkhead in the SDK — add when a benchmark or an incident shows the need.
- Batch encrypt/decrypt endpoints for multi-field writes — likely the largest available latency win;
  deferred until Milestone 8 measures how much it would buy.
- **P2 — mutual TLS.**
- **P3 — sidecar and proxy modes. P4 — Go and TypeScript SDKs.**
- Async/streaming API for large payloads; the 10 MB benchmark case will show whether it is needed.
- Client-side encryption with fetched DEKs — only with measurement and a new ADR, given the blast
  radius trade.
