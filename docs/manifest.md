# Manifest and compiler reference

This page owns declaration syntax and generated-lock structure.
Use [architecture](architecture/README.md) for component boundaries and
[lifecycle](lifecycle.md) for applying a compiled plan.

## Manifest

The public manifest uses bounded JSON. Its field-intent declaration is independent of existing structural research-header schemas.

| Member or fact | Rule |
|---|---|
| `schema` | `cryptalis.protection/v1` for implemented field intent |
| `profile` | Selected library crypto profile. No arbitrary algorithms or executable normalizers |
| `models`, `fields` | Names resolve within the supplied registry. No imports from strings. Unlisted fields retain native behavior |
| `protect` | True requests protection. Removal requests a verified transition, never automatic plaintext writes |
| `queries` | Empty means storage-only. `equality` includes `IN`. `unique` implies tenant-scoped equality. `order` adds range and sorting on integer, date and naive timestamp fields, and implies equality |
| `accept_leakage` | Required matching acceptance for every search capability. Missing acceptance blocks plan |
| `tenancy` | Exactly `{"column": "attribute_name"}` or `{"single_tenant": true}` per protected table |
| Mapping facts | Text codec, deterministic exact collation, nullability, application-assigned PK, tenant scope, constraint scope, and writer inventory |

`cryptalis manifest inspect cryptalis.json` validates a manifest without a database and
lists each protected field with the search leakage you accepted.

Prefix limits, shared-join domains and arbitrary normalizers remain unadmitted.
Boolean, signed integer, finite Date, UUID, naive timestamp and finite numeric storage use pinned value codecs.
Integer, date and naive timestamp fields admit [`order`](compatibility.md#order-search) search only;
Boolean, UUID and numeric fields admit no search.
The compiler rejects unsupported types, server-generated keys, small-domain searchable fields, missing tenant scope, and unsupported writers at plan time.
Searchable small domains remain unsafe because enumeration can label their equality classes. No invented cardinality threshold supplies evidence.
The planner does not infer every application query. Attached staging tests expose query-level incompatibilities.

The generated public lock records stable domain/field/representation identities, original schema, codecs, DDL, and reader dependencies.
Renames preserve stable identities. Removal and re-addition creates new identities unless an authorized mapping proves continuity.
Unrelated manifest edits do not alter payload AAD. The compiler must not silently remove a constraint or change equivalence.

A deployment-controlled artifact outside database restore pins active lock, target, admitted formats/generations, and wrapped-root identities.
Existing deployment integrity controls authenticate it. Manifest and policy contain no secret key bytes.
A database checkpoint cannot activate a manifest. Startup rejects disagreement among policy, lock, target, and representation.
G-POLICY remains UNKNOWN. The host must supply authenticated publication and restore authorization; local procedures do not qualify that deployment boundary.

### Implemented compiler syntax

**IMPLEMENTED:** `cryptalis.manifest.compiler.compile_protection` uses the declaration below.
[Status](history/implementation-2026-10.md#slice-1-checkpoint-2026-10-08) owns its tested cell and limits.
The compiler accepts bounded UTF-8 JSON with no duplicate or unknown members.
Domain, table, and field IDs are distinct, nonzero canonical UUIDs. Names resolve only in the supplied registry.
The compiler never imports a module from a name.

```json
{
  "schema": "cryptalis.protection/v1",
  "profile": "cf1",
  "domain_id": "10000000-0000-0000-0000-000000000001",
  "models": [{
    "model": "Customer",
    "table_id": "20000000-0000-0000-0000-000000000001",
    "tenancy": {"column": "tenant_id"},
    "fields": [{
      "name": "email",
      "field_id": "30000000-0000-0000-0000-000000000001",
      "protect": true,
      "queries": ["unique"],
      "accept_leakage": ["equality", "unique"]
    }]
  }]
}
```

Queries permit `equality` and `unique`. An empty list means storage-only. Equality also declares `IN`.
Unique implies equality and requires both leakage acknowledgments. `protect` must be true.
Removal uses a semantic diff and a later verified transition.

Without owned sequences, text-only plans emit `cryptalis.lock/v2`. Plans with native VARCHAR emit `cryptalis.lock/v3`
and require `pg-varchar/v1`. A plan with Boolean storage emits `cryptalis.lock/v4`
and requires `boolean-u8/v1`. Mixed fields retain each required reader.
Plans with admitted owned sequences emit `cryptalis.lock/v5`. Other plans retain
their existing format selection and bytes. The explicit public-slot layout emits
`cryptalis.lock/v6`. Signed integer storage emits `cryptalis.lock/v7`
and requires its exact pg-int2/int4/int8-be/v1 codec readers. Date plans emit `cryptalis.lock/v8`; UUID plans emit `cryptalis.lock/v9`.
Naive timestamp plans emit `cryptalis.lock/v10`. Numeric plans emit
`cryptalis.lock/v11`. Current readers accept v1 through v11; older readers refuse
unknown formats before effects.
Older operational readers refuse the embedded v5 lock before effects.
The [VARCHAR decision](history/decisions-2026-10.md#native-varchar-text-admission-2026-10-22) defines assignment and reader boundaries.
Its exact top-level members are
`schema`, `profile`, `domain_id`, `database`, `declaration`, `models`, `writer_inventory`, `search_reviews`, `ddl`, and `required_readers`.
V6 adds `layout: "preserve-public-slots/v1"`. V7 always includes layout as
NULL or that selector and always includes source_metadata.owned_sequences.
For earlier formats, public `layout=None` keeps
the earlier selector. A previous lock does not select a layout implicitly.
The declaration is canonical. Models contain `model`, `table_id`, `schema`, `table`, `record`, `tenancy`, `fields`, `source_schema`, and `source_metadata`.
Fields contain `name`, `column`, `field_id`, `queries`, `representation`, `payload_column`, `unique_indexes`, `original`, `source`, `descriptor`, and `descriptor_digest`.
Boolean fields also contain `application_default`: absent-default NULL or a literal Boolean.
Signed integer storage includes that member only for a literal client
default. Its value is a canonical signed decimal string; pg-integer-default/v1
is then required. Default-free v7 fields retain their existing bytes and readers.
The [installed checkpoint](history/implementation-2026-10.md#integer-literal-default-installed-checkpoint-2026-10-24)
owns the exact default and native ORM-state checks.
The compiler and attachment compare this fact with the current native mapping.
Server, callable and on-update protected defaults remain refused.

The source schema stores inspected relation, column, constraint, index, and dependency facts.
`source_metadata` stores protected-column attributes (comment, statistics target,
storage, compression, options, ACL entries), constraint and index comments, and extended
statistics rebuilt from captured fields. The protection switch applies captured column
grants to the ciphertext column; reverse restores them. Statistics targets use strings because the
manifest integer grammar is non-negative and bounded.
V5 and v6 add `owned_sequences` to every model's source metadata, including empty inventories.
It records stable identity, owner, native configuration, effective ACL and dependency facts.
Atomic ownership transfer preserves the same sequence object through either column switch.
Restore/v2 binds new restored OIDs after exact logical comparison. No cryptographic
value format changes. The [lifecycle contract](lifecycle.md#owned-sequence-preservation-and-restored-identity-2026-10-24)
and [status](history/implementation-2026-10.md#owned-sequence-preservation-and-restore-2026-10-24) define the verification boundary.
The revised query passes source and installed controls. Both fresh-target profiles
pass complete OID mapping, direct generation and repeated adoption. The full
source regression also passes at that checkpoint. The public-slot extension below
has a separate verification boundary. Retained-native preservation remains open.

The opt-in v6 layout converts original public attributes with ALTER TYPE USING
verified staged values. Public CF1 CHECKs and equality indexes precede shadow
removal. Reverse converts the same attributes and restores captured native metadata.
Sequences remain owned by the same attributes. Heap and index storage rewrites
remain outside host-supplied row-rate/WAL estimates. Restore/v3 binds complete ordered
source/target slots for every public column, plus a mandatory sequence map.
Flat lineage composes these maps without changing legacy comparison or source authority.
See the [lifecycle contract](lifecycle.md#public-column-slot-layout-2026-10-24)
and [bounded verification](history/implementation-2026-10.md#public-column-slot-preservation-2026-10-24).
Catalog type modifiers use strings because PostgreSQL uses negative sentinels.
Unrelated SQL definitions use SHA-256 fingerprints of their canonical JSON string values.
Original admitted unique constraints and indexes retain their exact definitions for later restoration.
The lock contains no database connection string or row values. Boolean client defaults are policy facts.
`ddl.expand` contains additive proposals. `ddl.requires_before_switch` names prerequisites that must be verified before switching.
Reader requirements identify exact dependencies; their presence alone does not prove a deployment has qualified readers.

The record codec is `uuid16/v1` or `int64-be/v1`. UUID context uses 16 exact bytes.
Bigint context uses `T` with the `int64` tag and eight signed big-endian bytes, as [security](security.md#cryptographic-format) specifies.
Single-tenant context uses the stable table UUID. The text codec is `utf8-exact/v1`.
The normalizer is `identity/v1`. The null policy is `sql-null/v1`. Composed and decomposed text remain distinct.

Descriptor digests exclude SQL names. They bind the domain, table, field, record codec, tenant codec, text codec, normalizer, null policy, and representation.
The representation is `cf1-storage/v1` or `cf1-packed-equality/v1`. The descriptor schema is `cryptalis.context/v1`.
Boolean storage uses `cryptalis.context/v2` with `value_codec: boolean-u8/v1`
instead of `text_codec`. False encodes as byte 00. True encodes as byte 01.
The descriptor digest binds the value type in the shared authenticated path.
SQL NULL stays SQL NULL. Boolean equality terms remain unadmitted.
Finite NUMERIC uses `pg-numeric-decimal/v1` under context/v2 and lock/v11.
Canonical Decimal strings or typed `{"integer":"…"}` literal defaults preserve their Python
type, sign, exponent and fractional scale before refresh. Numeric fields
pin their source typmod as well as the original catalog snapshot, so attachment,
verification and native exit retain declared precision and scale. Numeric
fields are storage-only; [numeric admission](compatibility.md#numeric-storage)
defines exact input bounds and failures.
Signed integer storage also uses context/v2. Its pinned codecs encode int2/int4/int8
as 2/4/8 signed big-endian bytes. Current Date plans use `pg-date-days-be/v1`
and lock/v8: signed four-byte days from the PostgreSQL epoch. Literal client Date
defaults require `pg-date-default/v1`. The earlier `date-ordinal-u32/v1` reader
retains its unsigned Gregorian ordinal encoding; old bytes are never reinterpreted.
The exact Date domains and native controls are in [compatibility](compatibility.md).
UUID values store sixteen
network-order bytes under `uuid-bytes16/v1` and lock/v9. Nil UUID values are valid;
the public record and tenant UUID codecs keep their separate context role.
Timestamp values use `pg-timestamp-us-be/v1`: eight signed big-endian microseconds
from 2000-01-01 under context/v2 and lock/v10. The input is an exact naive Python
datetime; literal client defaults use a canonical ISO string with six fractional
digits and require `pg-timestamp-default/v1`. This does not reinterpret Date or
UUID frames or admit timezone conversions. Timestamp order additionally pins
`pg-timestamp-order/v1`, with explicit order/equality leakage acceptance. [Timestamp admission](compatibility.md#timestamp-storage)
owns supported precision and source-domain limits.
All other CF1 authenticated context and nonce rules remain unchanged. The
[local scalar checkpoints](history/implementation-2026-10.md#native-uuid-value-storage-2026-10-28)
retain their source, artifact and cost boundaries.
For equality, the stable field UUID identifies the search domain. Crypto implementation and independent vectors belong to slice 2.

`WriterInventory` requires `complete=True` and a nonempty inventory for each protected table.
Writer records name a table UUID, a distinct writer name, a route, an exclusion flag, and a nonsecret evidence reference.
Only `sqlalchemy` routes can remain admitted. `raw_sql`, `copy`, and `external` routes require exclusion. Unknown routes always reject.
`SearchReview` names a searchable field UUID, a small-domain classification, and a nonsecret evidence reference.
These declarations do not prove enforcement.

`PlanningRejected` gives typed issues, remedies, an operation ID, stage, retry classification, and effects `NONE`.
`InspectionUnavailable` gives a safe SQLSTATE and a remedy. Raw driver text and SQL binds do not enter these error messages.
A previous lock must match its declaration, native facts, context descriptors, originals, DDL, and reader requirements before diff.
A lock hash detects change. It does not authenticate deployment authority.

For an already ACTIVE deployment, do not compile the ciphertext column as a new
plaintext source. The [active-field modification route](application.md#modify-active-fields)
accepts the original trusted deployment plus updated intent, preserves the native
schema obligations and stages a verified successor. Its first admitted change
enables equality search on storage-only TEXT/VARCHAR; other schema/profile
changes require their own lifecycle implementation and evidence.
