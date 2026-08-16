# ADR-0007 — Deferred ORM integration investigation

**Status:** Deferred
**Contract:** None. The current contract remains [ADR-0005](0005-sdk-integration-and-deployment.md).
**Source:** unverified working research recorded in [docs/prior-art.md](../prior-art.md)

## Problem

[ADR-0001](0001-write-time-encryption-boundary.md) puts the encryption boundary in the application's
data-access layer. [ADR-0005](0005-sdk-integration-and-deployment.md) then chose *explicit* SDK calls
at each call site and **rejected** ORM-layer integration, on the grounds that implicit encryption is
hard to review and that the AAD components are not reliably available at the type layer.

The preserved prior-art research suggests two reasons to reconsider this after the SDK MVP:

1. **Ergonomics are the unclaimed ground.** No maintained Python package offers per-subject
   crypto-shredding as an ORM column type. Every existing Python field-encryption library is
   single-key. The project's defensible claim is precisely *"one line per column, per-subject
   shredding"* — which explicit call sites do not deliver.
2. **The technical objection was half right, and the correct half is decisive.** A SQLAlchemy
   `TypeDecorator` genuinely cannot see the row: `process_bind_param(self, value, dialect)` and
   `process_result_value(self, value, dialect)` receive the scalar value and the dialect, never the
   ORM instance or a sibling column. There is no supported way to reach `subject_id` from inside a
   type processor. So per-subject key selection **cannot** live there.

Granit hit the identical wall in .NET: EF Core value converters receive only a scalar and cannot see
the entity id, so Granit moved key selection into save-interceptors. A second implementation arriving
independently at the same conclusion is the strongest evidence available that this is a structural
constraint, not a gap in our reading of the docs.

The question this record answers: **how do you get ORM ergonomics without putting key selection
somewhere it cannot work?**

## Constraints

- Registering a protected column must be approximately one line on the model. That is the product.
- Per-subject key selection needs the whole instance, not the value.
- A single flush may contain rows belonging to **different subjects** — the design cannot assume one
  subject per transaction.
- Reads of a shredded subject must not crash an ordinary query. `session.query(Model).all()` over a
  mix of live and shredded rows has to return.
- Result processors run on `NULL`s and on outer-join non-matches, so the read path is invoked with
  nothing to decrypt more often than the happy path suggests.
- Must remain compatible with the gateway API in [ADR-0005](0005-sdk-integration-and-deployment.md);
  this record changes *where the SDK is called from*, not the trust boundary.
- Python and SQLAlchemy first. Django is a later target with the same split (custom `Field` for the
  transform, `pre_save`/signals for key selection).

## Decision

**Split the responsibility in two.** A thin type for the storage transform, a session event for the
row-aware decision.

### 1. `EncryptedField` — a thin `TypeDecorator`

Its entire job is to mark a column as protected and to carry bytes to and from the database. It:

- declares the storage type (`LargeBinary`/`BYTEA`, or `JSONB` where an envelope is stored
  structurally),
- records the column's `field_class` in the registry at model-definition time,
- on read, decrypts using a key resolved from context — with a null-safe, shred-safe path,
- **never selects a per-subject key on write.**

```python
class User(Base):
    email = Column(EncryptedField(field_class="PII", subject_attr="id"))
```

`subject_attr` names the attribute the flush listener will read. The type does not read it — it
cannot — but declaring it here keeps the model the single place a developer looks.

### 2. `before_flush` — where key selection actually happens

A `SessionEvents.before_flush` listener iterates `session.new` and `session.dirty`, and for each
instance with protected columns: reads `subject_id` **off the instance** (full object access), resolves
the per-subject DEK through the SDK, encrypts, and writes the envelope to the target attribute.

This is the Python analogue of Granit's save-interceptor. It is the only hook that gives whole-object
access *before* the flush plan is fixed, and it is the only one that handles a flush containing rows
from several subjects.

### 3. `contextvars` fast path

For the common case — one request, one subject — the current subject key context is set in a
`contextvars.ContextVar` at request scope. It is a latency optimization and a convenience for reads,
not the mechanism: when the context is absent or the flush contains multiple subjects, the
`before_flush` listener is authoritative. `ContextVar` is the same pattern used for SQLAlchemy +
Postgres row-level-security multi-tenancy, and it is async- and thread-safe.

### 4. Explicit SDK calls remain supported

`client.encrypt_field(...)` stays public and documented. It is the escape hatch for code outside the
ORM, for bulk paths, for migrations and backfills, and for anyone who prefers the boundary visible.
The ORM layer is built **on** it, not beside it.

### 5. Reads of shredded data return a sentinel, not an exception

`process_result_value` must handle three cases without raising: `None`, an outer-join non-match, and
a value whose key has been shredded. A shredded value decodes to a configurable sentinel — the
default being a distinguishable `Shredded` marker object, not `None`, so that "erased" is never
silently confused with "never set". Raising here would mean a single shredded row breaks any query
that touches it.

The gateway API still returns `410 key_shredded`; the ORM layer maps that status to the sentinel.
Applications that prefer a hard failure can opt into raising per column.

## Open design issue — AAD and the primary key on insert

**Unresolved, and must be settled in Milestone 1.2 before the AAD encoding is frozen.**

[ADR-0002](0002-envelope-key-management.md) specifies AAD over `(subject_id, table, column,
record_id)`. At `before_flush` time, a pending row with a server-generated autoincrement primary key
**has no `record_id` yet** — it is assigned when the INSERT executes. The AAD as specified cannot be
built on the insert path for such models.

Three options, with the current recommendation:

1. **Client-generated UUID primary keys for protected models** (recommended). The id exists before the
   flush, the AAD is complete, and no ordering problem arises. Cost: a constraint on the protected
   application's schema, which must be stated in adopter documentation.
2. **Drop `record_id` from the AAD**, binding only `(subject_id, table, column)`. Cost: a ciphertext
   could be relocated between rows *of the same subject and column* without detection. Narrower than
   it sounds, but a real weakening of AD-2, and it would have to be documented as such.
3. **Encrypt in `before_insert`** (a mapper persistence event) instead. Runs after the flush plan is
   decided; SQLAlchemy permits modifying attributes local to the object's row, which is exactly what
   is needed — but the primary key for a server-side sequence is still not available before execution,
   so this does not actually solve the problem for the case that motivated it.

Option 1 is the recommendation; option 2 is the fallback if an adopter's schema cannot change, in
which case the weaker binding must be recorded in the ciphertext's envelope so the guarantee is not
misrepresented later.

## Alternatives rejected

| Alternative | Why rejected |
|---|---|
| Key selection in `process_bind_param` | **Structurally impossible.** The processor receives only the value and the dialect. Confirmed in SQLAlchemy's documented type contract and corroborated by Granit hitting the same wall in EF Core. This is the single design error this ADR exists to prevent. |
| `contextvars` alone | Cannot express a flush containing rows from multiple subjects, and silently encrypts under the wrong subject's key if the context is stale. Demoted to a fast path with the flush listener authoritative. |
| `before_insert` / `before_update` mapper events as the primary hook | Give per-object access, but run after the flush plan is decided — SQLAlchemy warns that only attributes local to the object's row may be changed and session state must not be altered. Workable but more constrained than `before_flush`, and it does not solve the primary-key timing issue. |
| Composite types or `@hybrid_property` carrying value + key | Leaks the pattern into every model and defeats the one-line-per-column goal that is the project's differentiator. |
| Explicit SDK calls only (the original ADR-0005 position) | Still supported, but it forfeits the unclaimed ground. Every existing Python library already offers roughly this ergonomics with a single key. |
| Encrypting inside the database (pgcrypto) | Puts key material in the process this project treats as an adversary. Rejected in ADR-0001 and unchanged. |

## Data flow

**Write**

```
session.add(user); session.commit()
  → before_flush(session, ...)
      for instance in session.new | session.dirty:
          for column in protected_columns(instance):
              subject_id = getattr(instance, column.subject_attr)
              envelope   = sdk.encrypt_field(subject_id, table, column, record_id, plaintext)
              setattr(instance, column.name, envelope)
  → flush emits INSERT/UPDATE with envelope bytes
```

**Read**

```
SELECT ... → EncryptedField.process_result_value(value, dialect)
    value is None                      → None
    outer-join non-match               → None
    key shredded (gateway 410)         → Shredded sentinel
    key revoked / policy denies (403)  → typed error
    otherwise                          → sdk.decrypt_field(...) → plaintext
```

The read path resolves its subject from `contextvars`, or from the envelope's `key_id`, which is
self-describing — see [ADR-0002](0002-envelope-key-management.md).

## Error and security behaviour

The failure modes below are the ones this integration adds. Each is a Milestone 5 test.

| Condition | Behaviour |
|---|---|
| Gateway unavailable during `before_flush` | The listener raises; the flush fails; the transaction rolls back. **A plaintext write must never occur.** This remains the most dangerous possible bug in the system. |
| Bulk operations bypass the listener | `Session.bulk_insert_mappings`, `bulk_update_mappings`, and Core `insert()`/`update()` do not run `before_flush`, so protected columns would be written **unencrypted**. Mitigation: a guard that raises when a bulk path targets a model with protected columns, plus documentation that protected models must not use bulk ORM shortcuts. Silent bypass is unacceptable; a loud failure is the requirement. |
| `NULL` or outer-join non-match on read | Return `None`. Never raise. |
| Read of a shredded subject | Return the `Shredded` sentinel. A query mixing live and shredded rows must complete. |
| Decrypt fails with the wrong key or corrupted data | Caught and converted to a typed error or the sentinel, never a raw library exception surfacing as a 500. |
| Stale `contextvars` subject | The flush listener overrides context on write; on read, `key_id` in the envelope is authoritative. Context is never the sole source of truth for which key to use. |
| Filtering, ordering, or unique constraints on a protected column | **Not possible.** Ciphertext differs per value and per subject, so server-side `WHERE`, `LIKE`, `ORDER BY`, and unique constraints over plaintext do not work. Documented as a hard limitation; blind-index columns are the deferred answer. |
| Migrating an existing plaintext column to a protected one | An Alembic column-type migration to `BYTEA`/`JSONB` plus a data pass through the SDK. Alembic autogenerate does not reliably detect `TypeDecorator` changes, so these migrations are hand-written and reviewed. Procedure: the six-step backfill in the [playbook](../../ENGINEERING_PLAYBOOK.md#migrations-and-rollback). |

**Security note on implicitness.** ADR-0005's original objection — that implicit encryption is hard to
review — is real and is not dismissed. It is mitigated rather than refuted: the model declaration is
the single visible registration point, the field registry is enumerable and testable, an unregistered
field fails closed at both ends ([ADR-0003](0003-policy-gated-decryption.md)), and the bulk-bypass
guard converts the one silent failure mode into a loud one.

## Testing strategy

- `tests/integration/test_orm_multi_subject_flush.py` — one flush containing rows for two subjects
  encrypts each under its own key. This is the test `contextvars`-only designs fail.
- `tests/integration/test_orm_roundtrip.py` — write through the ORM, read back, and assert with **raw
  SQL** that the column does not contain the plaintext.
- `tests/integration/test_orm_null_and_outer_join.py` — `None` values and outer-join non-matches
  return `None` without raising.
- `tests/integration/test_orm_read_after_shred.py` — a query over a mix of live and shredded rows
  completes and yields the sentinel for shredded rows; the sentinel is distinguishable from `None`.
- `tests/integration/test_orm_bulk_guard.py` — `bulk_insert_mappings` against a protected model
  raises rather than writing plaintext.
- `tests/integration/test_orm_gateway_down.py` — a gateway failure rolls the transaction back and
  leaves no row.
- `tests/integration/test_orm_contextvar_isolation.py` — a stale or absent context never causes an
  encryption under the wrong subject's key; async tasks do not leak context between them.
- `tests/integration/test_alembic_encrypt_column.py` — the hand-written migration path encrypts an
  existing plaintext column and leaves zero unconverted rows.
- `tests/boundary/` — the ORM layer depends on the SDK only, never on the server package.

## Deferred

- **Django support** — same split (custom `Field` for the transform, `pre_save`/signals for key
  selection). Python/SQLAlchemy first.
- **Blind-index columns** for equality lookup on protected fields. This is now a more prominent gap
  than it was, because ORM ergonomics invite people to filter on encrypted columns. Still deferred,
  but it is the most likely first post-v1.0 request.
- **Batch encrypt/decrypt** in a single gateway call per flush. The flush listener already knows the
  whole set, which makes this a natural optimization — deferred until Milestone 8 measures the
  per-field round-trip cost.
- Async SQLAlchemy session support beyond what `contextvars` gives for free.
- Automatic detection of Core-level statements that touch protected columns, beyond the bulk guard.
