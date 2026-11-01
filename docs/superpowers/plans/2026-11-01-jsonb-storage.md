# Native JSONB storage

Requirements 5, 6, 9 and 10; objective OBJ-QUERY-03. This storage prerequisite
does not finish JSON search. No release or security gate is promoted.

The native PostgreSQL baseline passes both SQLAlchemy JSONB null modes. The
first protected journey refuses the currently unsupported type. The receipt and
frozen test source are retained under the private qualification cache.

Use the existing CF1 payload and lifecycle. Add `pg-jsonb-text/v1`, lock/v15 and
a context/v2 null policy that binds `none_as_null`. Keep SQL NULL as no frame;
authenticate JSON null as a non-NULL document. Preserve all earlier descriptors
and readers. Mixed v15 prefix plans must retain their internal-only refusal.

Keep canonical native UTF-8 JSONB text in an immutable internal value. Read
native data through `convert_to(column::text,'UTF8')`, avoiding the driver's
lossy Python float loader. Decode to application Python values only after
authentication. Removal binds retained text with an explicit JSONB cast.
Canonical input follows stdlib JSON acceptance, lossless Decimal parsing,
PostgreSQL numeric bounds/scale and UTF-8 byte-length key ordering. Reject
nonfinite numbers, NUL and invalid Unicode before sending protected plaintext.
No new dependency or cryptographic primitive is needed.

Preserve both native null modes, omitted values, JSON.NULL, SQL null(), mutable
tracking, sync/async results and immutable preparation across provider calls.
Initially refuse protected JSON defaults and JSON search operators explicitly;
both remain product obligations. Pin native serializers/loaders and reject
custom behavior rather than silently reinterpret it.

Verify native/protected CRUD, RETURNING, refresh, savepoints, precision and null
oracles; tampering and callback mutation; both lifecycle layouts; online capture;
all rotations; fresh export/adoption; old-reader refusal; current-value removal
and package-free restart. Preserve failed and skipped receipts. Build and inspect
the exact wheel before installed verification. Update contract owners, current
status and ledger only to the scope actually established.
