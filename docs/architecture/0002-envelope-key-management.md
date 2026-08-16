# ADR-0002 — Envelope key management, per-subject DEKs, and crypto-shredding

**Status:** Accepted
**Date:** 2026-08-12
**Contract:** [AD-2](../../README.md#ad-2--aes-256-gcm-as-the-field-aead-with-gateway-owned-nonces-and-mandatory-aad),
[AD-3](../../README.md#ad-3--envelope-encryption-with-per-data-subject-deks)
**Source:** `capstone-final-decision.md` §4; research document, cryptographic-design and
key-management sections

## Problem

Three questions have to be answered together, because answering them separately produces an
inconsistent system:

1. **Which primitive encrypts a field**, and how are its dangerous parameters (nonce, associated
   data) controlled?
2. **How is the key that encrypts a field protected**, given that the key cannot live next to the
   ciphertext?
3. **What is a key's scope**, given that "delete this person's data" must become "destroy this
   person's key"?

Getting (1) wrong — specifically, reusing a GCM nonce — breaks both confidentiality and
authenticity. Getting (3) wrong makes crypto-shredding either impossible (one global key) or
unaffordable (one key per field per row).

## Constraints

- No custom cryptography. Vetted library only (`cryptography`, or Tink if it proves a better fit at
  Milestone 1 — the envelope format does not depend on the choice).
- The gateway must be able to rotate the KEK without re-encrypting the entire dataset.
- The MVP has no KMS. The KEK comes from a sealed environment value, and this limitation must be
  visible rather than hidden.
- Unwrapping on every read is a latency cost in the data path; the design must have a lever for it.
- Ciphertext must remain decryptable years later, after algorithm or format changes.
- Crypto-shredding must be irreversible and provable.

## Decision

### Field encryption

- **AES-256-GCM**, 256-bit DEK, **96-bit nonce**, 128-bit tag.
- The nonce is generated **inside** `core/crypto/aead.py` from the single CSPRNG entry point on every
  encryption. There is no nonce parameter in the public function signature — misuse is prevented by
  the type system and the API shape, not by documentation.
- **AAD is mandatory** and canonical: a length-prefixed encoding of
  `(subject_id, table, column, record_id)`. Length prefixing prevents component-shifting collisions
  (e.g. `("ab", "c")` versus `("a", "bc")`).
- 96 bits follows NIST SP 800-38D's default recommendation for the GCM IV; it is also the size for
  which the primitive's construction is fastest and best analysed.

### Ciphertext envelope

Every ciphertext is self-describing:

```
version (1 byte) || algorithm_id (1 byte) || key_id (16 bytes) || kek_version (2 bytes)
  || nonce (12 bytes) || ciphertext || tag (16 bytes)
```

The exact widths are fixed at Milestone 1.1 and the module docstring is the authority once written;
this record is updated in the same change if they differ. The parser is a **total function** — every
input either parses or returns a typed error, never an unhandled exception.

### Key hierarchy

- **DEK**: one per `(subject_id, field_class)`, 256-bit, CSPRNG-generated.
- **KEK**: one active version, wraps every DEK. Loaded at boot from a sealed environment value into
  memory. Never written to the database, never logged, never returned by any endpoint.
- Wrapping is AEAD-based with `kek_version` as associated data, so a wrapped DEK cannot be replayed
  under a different KEK generation.
- **HKDF-SHA-256** provides context separation where a derived key is needed rather than a stored one.

### Key states and lifecycle

`active → revoked` (deny decrypt, key material retained) and `active|revoked → shredded` (key
material destroyed). Both transitions are audited. `shredded` is terminal.

Rotation is **KEK-level and lazy**: a new KEK version is created, DEKs are re-wrapped on next access,
and a background sweep finishes the remainder. Existing ciphertext keeps decrypting because
`kek_version` travels with it. This is why rotation does not require re-encrypting data.

### Crypto-shredding

Ordered so that a crash at any step leaves a safe, auditable state:

1. Evict the DEK from the in-process cache. **First**, because a cached DEK that outlives the shred
   would serve plaintext for data believed erased.
2. Emit and sign the erasure certificate, naming the `key_id`s and the timestamp.
3. Destroy `wrapped_dek` — overwrite, then delete the column value.
4. Set state to `shredded`.
5. Append the audit entry.

A crash between 3 and 4 leaves an unreadable key row in `active` state, which the next decrypt turns
into an error rather than a leak, and which the key-census check surfaces. A crash before 3 leaves
the subject readable, which is recoverable by re-running the shred. Neither ordering error direction
produces a false claim of erasure.

Audit history for the subject is **not** deleted. Erasure removes the ability to read the data, not
the record that the data existed and was erased — which is what makes the certificate meaningful to
an auditor.

### DEK cache

In-process, bounded, TTL-limited. Never serialized, never persisted, never logged. Invalidated
synchronously on revoke and shred. It exists because unwrapping on every read is measurably slow —
and the benchmark in Milestone 8 has to show that, otherwise the cache should not exist at all.

## Alternatives rejected

| Alternative | Why rejected |
|---|---|
| One global DEK | Crypto-shredding impossible; a single key compromise exposes everything. |
| One DEK per record per field | Correct but key-row count explodes; shredding a subject becomes a fan-out over every row they touch. |
| One DEK per field class (no subject scoping) | Cheap, but "delete my data" would require re-encrypting every other subject's data under a new key. This is the trade that per-subject scoping buys. |
| AES-CBC + HMAC | Two primitives, two failure modes, padding-oracle surface, more room for composition mistakes. GCM is one AEAD call. |
| AES-GCM-SIV now | Genuinely misuse-resistant, but its value is precisely for systems that *cannot* control nonce generation. This gateway owns the nonce, so SIV buys little and costs an unusual primitive. Deferred to P7; the envelope's `algorithm_id` byte reserves room for it. |
| Caller-supplied nonces | The single most common catastrophic misuse. Not exposed at any layer. |
| KEK in the database | Defeats the entire purpose — a database breach would yield both wrapped DEKs and the key that unwraps them. |
| KMS from day one | Correct destination, wrong sequencing for a 14–16 week budget. The KEK source is behind an interface so P1 is an implementation, not a redesign. |

## Data flow

**DEK creation** — first encrypt for a `(subject_id, field_class)`: CSPRNG generates a 256-bit DEK →
wrap under the active KEK with `kek_version` as AAD → insert into `keys` with state `active` →
cache the unwrapped DEK → audit.

**Unwrap on read** — cache hit returns immediately; miss loads `wrapped_dek` from the repository,
unwraps under the KEK version recorded in the row, caches, and proceeds.

**Rotation** — create KEK v(n+1) → new writes wrap under it → on each access under v(n), re-wrap and
update the row → background sweep completes the tail → the old KEK version is retired only when no
row references it, which the key census reports.

## Error and security behaviour

- Missing or malformed KEK at startup: the process **does not start**. There is no default key.
- KEK present but unsealing fails: the service stays sealed; every key-dependent endpoint returns
  `503`; `gateway_sealed` is 1.
- Decrypt against a `revoked` key: `403`, distinct error code from a policy denial.
- Decrypt against a `shredded` key: `410` — deliberately different from `404`, because the data
  provably existed.
- Tag verification failure — tampering, bit rot, or a ciphertext relocated to another row, column, or
  subject: one opaque `decryption_failed`. The error never reveals which check failed.
- Unknown envelope version: `400 unsupported_envelope_version`. Readers for all shipped versions are
  retained; removing one is a breaking change.
- **Loss of the KEK is total, permanent data loss.** This is a documented operational risk, not a
  bug. Backup and sealing procedure is a production-readiness gate in the
  [playbook](../../ENGINEERING_PLAYBOOK.md#production-readiness).

## Testing strategy

- **Known-answer tests** against published AES-GCM vectors, committed as data with their source
  recorded (`tests/vectors/`). Non-negotiable.
- **Property tests**: round-trip for arbitrary plaintext; ciphertext ≠ plaintext; envelope
  parse/serialize symmetry; 100 000 encryptions produce 100 000 distinct nonces.
- **Negative tests**: wrong key, wrong AAD, truncated tag, flipped bits, ciphertext moved between
  rows/columns/subjects.
- **Fuzz** the envelope parser and the decrypt path — never crash, never return plaintext.
- **Rotation test**: ciphertext written under KEK v1 decrypts after rotation to v2; the re-wrap is
  resumable after interruption.
- **Shred tests**: decrypt returns `410`; the key material is gone from the row, not merely flagged;
  a cached DEK does not survive the shred *within the cache TTL window*; the erasure certificate
  verifies; shredding twice is safe.
- **Cache tests**: TTL expiry, bounded size, synchronous invalidation, never returns a key for a
  non-active state.

## Deferred

- **P1 — external KMS for the KEK.** The KEK source sits behind an interface for this reason.
- Shamir-style split unseal so no single operator holds the master key.
- Per-field-class KEKs (a second hierarchy level) — no constraint currently demands it.
- Automatic DEK expiry — the schema carries `expires_at`, but no enforcement job exists until a
  retention requirement is real.
- **P7 — AES-GCM-SIV** as an additional `algorithm_id`.
- Hardware-backed key storage.
