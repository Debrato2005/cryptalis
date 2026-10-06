# Cryptographer review packet

Frozen export for external human review, 2026-10-07 Asia/Calcutta. This is not a second contract owner.
The canonical owner is [security](../security.md); mapping/semantic/lifecycle dependencies have their linked owners.
The export must be regenerated when a source hash changes. No independent cryptographic review or audit has occurred.
No real customer data, provider credentials or live AWS observation is included.

## Requested review and exact scope

Assess this proposed field-encryption/equality composition under a trusted Python host and external current AWS authority.
Attackers may know source/config/schema and steal or modify DB rows/backups. They lack admitted roots/host plaintext unless a limit states otherwise.
Application compromise/IDOR/query oracle/key copies, same-context authentic replay, omission, nullable absence and hostile global uniqueness
are outside the stronger guarantee. Determine whether those exclusions make the intended confidentiality claim defensible.
AESGCMSIV is not claimed to be key committing. There are zero verified production cells and zero independent audits.

## Frozen source identities

| Canonical source | SHA-256 of exact UTF-8 file bytes |
|---|---|
| [docs/security.md](../security.md) | `fd799b94a6c5fb9f24c1213d9eaec1880157fdb723a95832a8b2d97146a4c3cb` |
| [docs/architecture/README.md](../architecture/README.md) | `31c332e49b3d42d0d6cbb55debac73d060c34be407faad325710dae8122224aa` |
| [docs/compatibility.md](../compatibility.md) | `2092c44c0f96b5eb26526df141fb4bfffd4640ecfad70037df2e3240cd3c7b65` |
| [docs/lifecycle.md](../lifecycle.md) | `2b76d244d1fb780b9698f37eb150bfd0731628c4e554b9adca3c3ef94a00ae86` |

## Exact exported construction

The following extracts reproduce the owned construction, not third-party standards. Header packing, codec bytes, tuple tags,
salt/info positions, descriptor hash domain, roots, nonces, quota bounds and fork invalidation are intentional review inputs.
The sources control if prose outside this export changes. Hash mismatch makes the export stale.

## Cryptographic format

The approved design profile chooses exactly:

| Item | Choice |
|---|---|
| AEAD | AES-256-GCM-SIV, `cryptography.hazmat.primitives.ciphers.aead.AESGCMSIV` |
| Library pin | `cryptography==50.0.2`. Pin and record the actual native backend/wheel per tested compatibility cell |
| Key/nonce/tag | 32-byte key, fresh `os.urandom(12)` per encryption, complete 16-byte tag |
| KDF and digest | HKDF-SHA-256, SHA-256, library implementations |
| Equality PRF | Full 32-byte HMAC-SHA-256, separate independent search-root key |
| Payload format | `CPD2`, internal format 2. Experimental F1/W1 are not production readers |
| Limits | Encoded scalar at most 1,048,576 bytes. Metadata-only KDF/AAD context at most 16 KiB. Wrapped root at most 16 KiB |

`CPD2` fixed header is big-endian `4s B B H 16s Q 32s I 12s`:
magic `CPD2`, suite 1 (AES-256-GCM-SIV), codec entry 1–4, reserved flags 0, scope-root handle UUID bytes,
generation uint64 greater than zero, immutable descriptor SHA-256, encoded scalar length uint32, and nonce 12 bytes.
The body is ciphertext of exactly the declared scalar length followed by a 16-byte tag. No trailing bytes or extensions are accepted.
The fixed header is 80 bytes. Total storage overhead is 96 bytes above encoded scalar length.
Catalogue entries are 1=text, 2=bytes, 3=integer, 4=decimal. Codec version 2 is independent of the candidate codec.
The envelope already authenticates type/descriptor and length. No redundant inner state or length frame is retained.
SQL NULL remains a database NULL with NULL companions, never an encrypted inner-null marker.

| Codec version 2 | Exact non-null payload bytes |
|---|---|
| Text | Strict UTF-8 bytes of the admitted original string. Empty text encodes to empty bytes |
| Bytes | The exact admitted bytes. Empty bytes encodes to empty bytes |
| Integer | Fixed 2/4/8-byte big-endian two's-complement signed integer, as storage_bits pins in the descriptor |
| Decimal | Minimal signed ASCII integer coefficient with no plus, leading zero or negative zero. The descriptor supplies fixed scale |

Decimal coefficient zero is `0`. Decode constructs the exact finite Decimal with that coefficient and exponent -scale without ambient rounding.
Integer widths follow the original SmallInteger/Integer/BigInteger mapping. Reject any inconsistent length, bounds or descriptor.
The one-MiB scalar bound applies to these raw payload bytes. Header/tag add exactly 96 bytes.
Authenticate the full envelope before codec decoding. Freeze independent raw-byte vectors before implementation admission.
Known format structure does not authenticate data. Unknown suite, format, flags, codec, descriptor or generation rejects before key release.

Canonical context encoding is a fixed positional tuple: u16 component count, then u8 type tag, u32 byte length and exact component bytes.
Tags are 1=ASCII label, 2=16-byte UUID, 3=32-byte digest, 4=8-byte unsigned integer, 5=opaque bytes, 6=strict UTF-8 enum.
No implicit type coercion, ambiguous concatenation, recursive metadata, decompression, pickle, dynamic imports or trial keys is permitted.
Tuple positions and fixed tags are part of binding version 2.
All Cryptalis UUID identities/handles and host UUID record/tenant/subject identities must be nonzero.
Integer record zero is a valid typed identity, never absence. No UUID-to-string coercion enters this encoder.

| Expression component | Exact tag and bytes |
|---|---|
| Every leading protocol label | Tag 1, the exact ASCII literal shown |
| domain, tenant, model, table, field, representation, index-domain, root-handle and normalizer IDs | Tag 2, exactly 16 UUID bytes in network order |
| scope_id | Tag 2, tenant UUID for tenant scope or subject-incarnation UUID for subject scope |
| scope/index generation | Tag 4, uint64 big-endian, admitted range 1..2**53-1 |
| codec_id | Tag 4, uint64 big-endian catalogue selector 1..4 |
| descriptor_digest | Tag 3, exact 32 digest bytes |
| complete_header | Tag 5, the complete 80 header bytes exactly as stored |
| subject_or_absent | Tag 2 nonzero subject UUID, or tag 5 empty bytes only when the descriptor admits absence |
| typed_record_identity | Tag 5, one nested kind byte plus UUID16 (kind 2) or uint64BE8 (kind 4), no nested length/header |
| payload purpose | Tag 6, exact UTF-8 bytes of `payload` |
| normalized_value | Tag 5, exact admitted normalizer output bytes defined below |

The table assigns every position in the payload/search expressions. No tag is inferred from a Python type.
The root handle identifies one registry record. It is distinct from scope_id and cannot authorize the returned scope by itself.

Define `E` as that tuple encoder. For payload key derivation:

```text
salt = SHA256(E("cryptalis/payload-extract/2", domain_id, tenant_id,
                scope_id, scope_generation))
key = HKDF-SHA256(root, salt,
      info=E("cryptalis/payload-key/2", model_id, table_id, field_id,
             representation_id, descriptor_digest), length=32)
aad = SHA256(E("cryptalis/payload-aad/2", complete_header,
      domain_id, tenant_id, subject_or_absent, typed_record_identity,
      model_id, table_id, field_id, representation_id,
      descriptor_digest, "payload", scope_generation))
```

`subject_or_absent` is tag 2 UUID when configured, otherwise tag 5 empty bytes. The descriptor pins this choice.
`typed_record_identity` is tag 5 containing tag 2 plus UUID bytes, or tag 4 plus an unsigned 64-bit identity. No leading decimal string ambiguity.
The hashed AAD is 32 bytes. This adds a SHA-256 collision-resistance assumption and avoids borrowing short-AAD bounds for a long context.
The descriptor digest covers exact codec constraints, stable logical IDs, representation, key scope, AEAD/KDF/AAD versions and null policy.
It excludes mutable SQL names, current manifest revision, logging policy and search normalization.
Its hash domain is `cryptalis-payload-descriptor-2`, one zero byte, canonical descriptor JSON.
Historical admitted descriptors remain immutable. Current authorization still applies to old readable data.

Independent payload roots are random 32 bytes, not passwords, IDs or derivatives of a surviving tenant root.
The authority reserves at most 65,536 encryptions per allocation and charges every attempted encryption before use.
Generation ceilings are `2**24` encryptions or `2**40` encoded bytes, whichever comes first, across fields/workers/retries.
Byte quota is reserved for the exact bounded batch. Failed/unused/crashed reservations are burned, never returned or reconstructed from restored DB counters.
Quota exhaustion requires generation rotation and typed denial. It never resets counts or changes algorithm.
These are conservative design ceilings, not a reproduced security proof.
No quantified decryption-forgery bound is claimed. Independent review must assess attempted verification and the full composition.
The per-root ceilings do not follow directly from RFC 8452 and are not a proof of a target failure probability.
The birthday approximation for independent random 96-bit nonces at 2**24 calls is about 2**-49 repeated-nonce probability;
this is not a GCM-SIV confidentiality/forgery bound and is worse under RNG correlation. Aggregate multi-root lifetime matters.
[RFC 8452 sections 6 and 9](https://www.rfc-editor.org/rfc/rfc8452.html#section-9) distinguish maximum message sizes
from security usage analysis. The chosen 1-MiB payload/32-byte hashed AAD are below its maximum sizes.
[AESGCMSIV documentation](https://cryptography.io/en/50.0.2/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCMSIV)
requires a compatible OpenSSL backend (3.2.0 or later). Absence raises a typed capability failure, never algorithm substitution.
The installed local 50.0.2 wheel reports OpenSSL 4.0.3 and passed S4. Target-cell wheel hashes/availability remain release evidence.
[HKDF](https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#hkdf) uses extract AND expand on random roots,
explicit nonsecret salt and domain-separated info. It is not password stretching.

OS RNG exceptions and detected local repeated nonces deny encryption. A bounded detector cannot prove entropy or global nonce uniqueness.
GCM-SIV misuse resistance reduces accidental repeated-nonce harm. It does not authorize fixed nonces or eliminate degraded-RNG assumptions.
Fork invalidates inherited clients, key caches, quota and authority. A PID guard requires child re-admission.
No copied user-space random generator produces nonces. Restart obtains fresh workload and operation authority.
Invisible VM-memory cloning is unsupported because no in-process check can recall keys or a previously authorized instruction stream.

The registry resolves one authorized root for the expected scope/generation. The header is a lookup hint, never provider authority.
Cryptalis neither promises key commitment nor accepts attacker-supplied keys. Exact-key dispatch is not a proof of commitment.
Independent review must validate this narrower authority model and cross-key attack assumptions.
Failure of G-CROSSKEY blocks the selected profile. It cannot trigger an invented committing wrapper or algorithm fallback.

## Context and replay

Expected domain/tenant come from deployment authority and host grant. Expected field/model/table/representation come from admitted mapping.
Point reads bind the separately authorized requested immutable record ID. Returned PK and AAD identity must match it.
Subject ownership must agree with the grant and authenticated payload context. Mutable row ownership alone cannot grant access.
General tenant queries check every returned binding. They cannot prove completeness, honest relational metadata or every omitted row.
Table/column rename preserves stable IDs. A logical move, tenant/subject transfer or representation re-adoption is an authorized re-encryption transition.
Copying ciphertext to another context rejects. Replaying an authentic old envelope in exactly the same still-admitted context can succeed.
AEAD establishes authenticity, not freshness. Mutable DB row revisions assist concurrency but cannot detect malicious rollback of a whole row.
External tombstones and retired format/generation denial prevent managed lifecycle resurrection. They do not supply per-row anti-replay.

Cheap mitigation assessment A3: adding a DB revision to AAD detects an envelope pasted onto a different honest revision,
but an attacker can replay both revision and authentic envelope. Binding all fields to each revision also requires re-encryption
of unchanged fields, consuming quotas and amplifying writes. The revision stays useful for concurrency, not authenticated freshness.
A row/presence MAC would detect a fresh NULL substitution or mixed-field substitution if its MAC remains intact.
An attacker can replay an old valid absent-field marker or omit the entire row. S4 demonstrates both the useful check and its limit.
This profile deliberately rejects the extra presence-MAC format/root/NULL-only-row/projection/rotation machinery: its scoped promise
is authenticity of returned non-null values, not authenticated presence or whole-row consistency. Nullable data requiring that
integrity property is ineligible. Host approval cannot call its requirement satisfied. Required fields retain ordinary NOT NULL,
which is not a defense against a privileged DB writer. This is an explicit narrowed claim, not a proof that MACs have no value.
Authenticated counts or DB-held commitments can themselves be replayed. Per-query full scans change pagination/cost and still
do not establish current external freshness. No implicit scan, external freshness service or anti-omission claim is added.
Human review must confirm that these exclusions fit intended data before production adoption.

## Search and leakage

Each tenant/field has an independent wrapped search root and index generation, separate from payload roots.
Derive the term key with HKDF-SHA-256:

```text
salt = SHA256(E("cryptalis/search-extract/1", domain_id, tenant_id,
                index_root_handle, index_generation))
term_key = HKDF-SHA256(search_root, salt,
           info=E("cryptalis/equality-key/1", field_id,
                  index_domain_id, codec_id, normalizer_id), length=32)
term = HMAC-SHA256(term_key,
       E("cryptalis/equality-term/1", codec_id, normalizer_id, normalized_value))
```

Normalizer IDs are immutable UUID catalogue identities. NULL emits no term.
Text normalizers produce their exact strict UTF-8 result. Exact bytes produce original bytes.
Exact integers produce minimal ASCII decimal. Decimal numeric equality produces the following ASCII grammar:
all zero values become `0e0`. Otherwise remove trailing coefficient zeros, adjust the exponent, and emit optional minus,
nonzero minimal coefficient, literal `e`, and minimal signed decimal exponent with no plus, leading zeros or negative zero.
Examples: `1.00 -> 1e0`, `10 -> 1e1`, `-0 -> 0e0`.
Equality bytes are independent of payload integer/Decimal bytes. E supplies the search-message tag/length.
There is no ambient rounding, repr, float conversion or implicit re-normalization in E.
Normalized output is at most 1,048,576 bytes after normalization. Numeric output has at most 1,024 coefficient digits and exponent -2,048..2,048.
The term-message bound is that value limit plus at most 16 KiB of framing/metadata. It is distinct from the metadata-only KDF/AAD cap.
Expansion beyond the bound denies before crypto/SQL. Frozen independent vectors are mandatory.
Store all 32 bytes in the admitted term slot. Never truncate, use an unkeyed hash, share domains across fields/tenants, or expose tokens to business code.
Full-width terms avoid intentional false positives and make SQL equality/IN and uniqueness practical.
A cryptographic collision remains possible. An unexplained unique conflict pauses for authorized comparison, never deletes data or asserts plaintext equality from tokens.

On returned rows, authenticate payloads, decode, recompute every required term, and check the original logical predicate before buffer handoff.
Payload/term updates are atomic. A mismatch fails the operation. Current validation cannot discover omitted hits or guarantee a hostile DB's completeness.
SQL LIMIT/OFFSET is retained. No silent postfilter/refill/full scan changes pagination.

Accepted leakage `equality-patterns-v1` includes stable same-value classes within tenant/field, frequency, row linkage, nullness,
encoded lengths, insertion/update timing, repeated query terms, returned/accessed rows, result volume and uniqueness-conflict existence.
Separate tenant/field domains reduce cross-domain linkage. They do not hide correlation through visible rows or known external distributions.
An attacker who can insert known values and observe stored terms can label those values and related searches.
Auxiliary knowledge and frequency/skew can recover meaning without breaking HMAC. Rotation does not erase previously observed linkage.
No forward/backward-private dynamic-search, ORAM, PIR, differential-privacy or zero-leakage claim is made.

Search on Boolean, enumeration/status, country, diagnosis/category and declared low-cardinality data is rejected.
Doctor rejects explicit low-cardinality classifications and finite enum/Boolean mappings.
Suspicious names are risk signals, not proof of distribution. They require an explicit semantic classification before search admission.
Mislabeling cannot make a forbidden semantic class supported. Field names never choose a normalizer or algorithm.
Doctor examines field groups and visible structural correlation indicators, including shared record/relational links. It emits WARN for recognizable correlated fields and UNKNOWN for unavailable distribution evidence.
It exports no term histograms, plaintext frequencies or guessed entropy scores. Unknown entropy is never evidence of safety.
An operator cannot waive the default low-cardinality exclusion. Search acceptance for other fields records review of chosen-input and auxiliary-data risk.
Identifiers such as email can also be inferred through an application oracle. Application rate limits and authorization are host responsibilities.

## Keys and caches

Use a dedicated AWS-generated symmetric `SYMMETRIC_DEFAULT` KMS key per protection domain, in the standard single-region key store.
Pin immutable key ARN, account, Region, origin `AWS_KMS` and expected key usage. Aliases are locator hints only.
Imported material, custom/external stores, multi-region KEKs and other providers are excluded from the standard profile.
KMS directly wraps independent tenant/subject payload roots and independent tenant-field search roots.
The KMS encryption context binds nonsecret protocol, domain, pseudonymous scope handle, purpose and generation.
It appears in provider audit logs. Raw email, names, external customer identifiers and secrets never enter it.
Registry records pin wrapper digest and context. Unwrap supplies the exact KMS key identity and expected context.
No custom tenant branch or W1 wrapping layer is used.

Production authenticates through one admitted ECS task role, EKS workload role or EC2 instance profile with automatically refreshed temporary AWS credentials.
No long-lived raw root in `.env` is allowed. The runtime selects only its admitted roots. Dedicated-domain KMS policy constrains domain, purpose and resource.
A shared runtime IAM role does not independently enforce per-subject host grants. Domain-role compromise can unwrap admitted domain wrappers.
Runtime can unwrap only its admitted domain/scopes. It cannot delete, disable, rotate or restore custody.
Migration, key administration and break-glass recovery are separate principals. Provider audit and operator records state the actual event, not a destroyed Boolean.

Material cache: memory only, at most 256 roots and 1 MiB of counted material, maximum age 300 seconds from acquisition,
shorter configured limits allowed, no refresh-on-access, and no persisted/shared/Redis cache. Decoded buffers have separate budgets.
The cache does not confer authorization. Operation authority has a maximum 30-second lifetime and cannot renew during authority outage.
Each protected Session operation's result handoff/commit needs fresh current admission within its deadline.
Already loaded attribute reads use local handle/deadline checks only, with explicit refresh after expiry.
They cannot detect an unseen remote revocation instantly. Returned/copied host plaintext remains outside recall.
Expiry prevents new use, not physical memory destruction.
Fork/restart/deny invalidates handles. Single-flight combines duplicate cold loads. Failure/cancellation wakes waiters with a typed error.
Use boto3 1.43.108 low-level clients with admitted temporary workload credentials.
Reject static environment/shared-file credential fallback and unexpected account/principal before any provider operation.
Create clients once per process, never share Sessions/resources or inherited network clients across fork.
Async operations offload this synchronous SDK to a bounded executor: at most 8 running and 8 queued requests per process.
Admission deadlines bound queue waiting. Cancellation retains request ownership until its worker resolves or is explicitly classified ambiguous.
No returned material from a canceled request becomes application authority.
Configure connect_timeout=1 second, read_timeout=2 seconds and total_max_attempts=1.
The adapter owns the sole visible retry budget. These transport settings do not guarantee cancellation of every running call.
Provider retry defaults: at most 3 attempts within a 5-second preparation deadline, exponential jitter.
A deadline denies new use but cannot forcibly stop an already running SDK call. Late or lost results remain observed and reconciled.
Only reviewed independent read/unwrap calls retry automatically. Conditional writes and destructive calls reconcile exact operation identity first. The operation's tighter deadline wins.
Known permission/disabled/delete-pending failures do not retry as transient errors. Native eventual-consistency reconciliation remains visible.
Currently authorized warm material can operate during a KMS outage until its age/authority deadline. Cold or expired material denies.
Authority outage denies even a warm cache. There is no offline production override or plaintext fallback.

Revocation first records external denial, then fences DB work, invalidates handles and drains registered operations/workers.
It becomes managed completion only after known outputs/commits drain or reconcile. A TTL or KMS disable alone is insufficient.
Already released Python values, suspended process copies, core dumps and host-owned exports remain outside recall/destruction guarantees.
The host must restart a restored VM. Arbitrary invisible RAM rollback is not supported.

## Descriptor and canonical JSON dependencies

Each format-2 descriptor has exactly `descriptor_schema`=2, `model_id`, `table_id`, `field_id`, `representation_id`,
`key_scope`, `suite_id`=1, `payload_format`=2, `kdf_version`=2, `aad_version`=2, `codec_id`, `codec_version`=2,
`codec_parameters`, and `null_policy`=`sql_null`. UUIDs are canonical lowercase strings and codec IDs are integers 1–4.
`codec_parameters` contains only the admitted original length/range/precision/scale bounds from compatibility. Unknown parameters reject.
The lock records immutable UUID normalizer/index domains separately. Search changes do not redefine payload bytes.

JSON uses the chosen bounded canonical profile: ASCII member names, strict Unicode values, no floats, duplicate keys or lone surrogates.
Counters lie in `0..2**53-1`. Application numeric values use separate typed codecs.
Limits: 16 MiB/document, depth 32, 10,000 fields, identifiers at most 128 UTF-8 bytes.
Unknown critical fields, duplicate set entries, conflicting locators and unsafe SQL dependencies reject.
The compiled lock digest is SHA-256 of `cryptalis-lock-v2`, one zero byte, and canonical complete lock bytes.
The deployment registry pins that digest. Changing files does not authorize weaker protection.
Deployment approval follows the [manifest-integrity contract](../security.md#manifest-integrity).
Internal immutable history retains admitted descriptors. Ordinary developers edit one declaration.


## Types and normalization

Payload codec and search normalizer are independent. Returned values preserve exact original payloads.
The [format owner](../security.md#cryptographic-format) defines bare codec-2 payload bytes within a 1 MiB bound.
The existing candidate codecs are executable syntax evidence, not approved runtime crypto.

| Type/profile | Payload and equality definition |
|---|---|
| Exact `str`, `exact-v1` | Strict UTF-8, no added BOM, no lone surrogate or implicit normalization. Equal code points produce equal terms. Leading U+FEFF and whitespace remain content. Mapped PostgreSQL text rejects U+0000 |
| Exact `bytes`, `exact-v1` | Exact bytes, no bytes-like coercion or encoding guess |
| Exact `int`, `exact-v1` | Fixed-width signed 2/4/8-byte payload for the original mapped integer. Search uses minimal ASCII decimal. Bool/subclasses reject |
| Exact finite `Decimal`, `exact-v1` | Codec 2 stores an exact signed coefficient with descriptor-fixed scale. Mapped Numeric accepts only declared scale and nonnegative zero. Numeric equality strips trailing zeros without ambient rounding or float |
| `email-ascii-v1` | ASCII dot-atom local part and DNS LDH domain, domain lowercase only. Exact acceptance rules below. No provider-specific rewriting |
| `phone-e164-v1` | Require `+` followed by 2–15 ASCII digits, first digit nonzero. No country guessing, punctuation or national-number conversion. Equality is exact validated form |
| `unicode-nfc-v1` | NFC using a frozen Unicode 17.0.0 data catalogue, assigned code points only. Original payload unchanged. Exact normalized equality |

`exact-v1` resolves to immutable type-specific catalogue IDs. It does not use generic `str(value)` or repr serialization.
Mapped types are closed: String/Text -> exact str, LargeBinary -> exact bytes, SmallInteger/Integer/BigInteger -> exact int,
and Numeric with explicit precision/scale -> exact Decimal. Database and client encoding must both be UTF8.
Mapped text rejects U+0000, which ordinary PostgreSQL text cannot retain after deprotection.
Preserve SQL String length, signed integer range and Numeric limits before encryption.
Mapped Numeric requires 1 <= precision <= 1000 and 0 <= scale <= precision.
Values must be finite exact Decimal with exponent exactly -scale, no negative zero, and magnitude strictly below 10**(precision-scale).
No implicit quantization, value-changing rounding or extra quantum is accepted.
Applications explicitly quantize before assignment if desired. The original psycopg/PostgreSQL mapping must return the same declared quantum.
Generic candidate vectors retain other Decimal forms as INTERNAL ONLY syntax evidence. They are not all admitted mapped values.
Text/LargeBinary also use the encoded-byte cap. CHAR, Enum, domains, variants, custom TypeDecorator/UserDefinedType,
coercing processors and ambiguous mappings reject. An unsigned context ID must still fit its actual signed PostgreSQL identity column.
Lock codec parameters are `max_characters` for bounded String, `storage_bits`=16/32/64 and `min_value`/`max_value` as minimal decimal strings for integers,
and `precision`/`scale` integers for Numeric. Parameterless Text/bytes use `{}`. No rounding or custom executable codec is admitted.
`email-ascii-v1` local part is 1–64 ASCII bytes. Dot-separated nonempty atoms use letters, digits and the ASCII punctuation set ``!#$%&'*+-/=?^_`{|}~``.
The domain is 1–253 ASCII bytes, with 1–63-byte labels containing letters/digits/hyphen and letter/digit endpoints.
The complete address is at most 254 bytes. Controls, whitespace, consecutive/edge local dots, quoted forms, comments,
IP literals and trailing domain dot reject. Domain letter case folds ASCII only. Local letter case remains significant.
This is a product normalizer, not a claim to implement every RFC-valid email address.
Mapped Decimal scale follows the declared 0..precision rule. Search numeric canonicalization has its own frozen vectors and bounded output.
Existing SQL NUMERIC constraints remain declared. Overflow rejects, never truncates or silently rounds.
Only text fields can use the text-specific normalizers. No algorithm changes based on field names.
Changing a normalizer ID or its frozen tables requires deliberate reindex and duplicate-conflict review.
The [security owner](../security.md#search-and-leakage) freezes exact output bytes and post-normalization limits.
An interpreter Unicode upgrade never changes an existing index in place.
Unicode 18.0.0 upstream documentation exists, but the chosen frozen 17.0.0 catalogue is deliberate compatibility state, not a latest-version claim.
Locale casefolding, automatic full-email lowercase, SQL locale collation, timestamps/timezones, floats/NaN, JSON/mutable collections and arrays are UNSUPPORTED BY DESIGN.
Applications may format phone/email values before assignment. Cryptalis validates the declared equivalence rather than supply a general identity-validation service.

### Ordinary commit evidence

Every protected mutation gets a random operation UUID and immutable request digest before DML, registered externally with
worker incarnation, exact target/fence and original backend fingerprint. Digest covers the canonical operation shape, scoped
identities, expected revisions and a keyed commitment to value bytes, not public low-entropy plaintext hashes.
Choose the lexicographically smallest (root-handle UUID bytes, generation) among the mutation's admitted payload roots as its
immutable commitment anchor. Deletes include the deleted rows' roots. An empty protected mutation requires no mutation record.
Derive `Kop = HKDF-SHA256(anchor_root, salt=payload-extract salt for that root,
info=E("cryptalis/mutation-commitment/1", operation_UUID), length=32)` using the security owner's fixed tag/tuple encoding.
The request digest is full HMAC-SHA-256(Kop, E("cryptalis/mutation-request/1", canonical_request_bytes)).
The last component is tag 5 opaque bytes. The request uses the manifest's canonical JSON rules and exactly these members:
`version`=1, `domain_id`, `target_incarnation`, `fence_token`, `anchor_handle`, `anchor_generation`, `operation_id`,
and `mutations` sorted by model UUID, typed record identity and action. Each mutation contains `model_id`, `record`,
`tenant_id`, `subject_id` (UUID or null), `action` (insert/update/delete), `expected_revision` (uint decimal string or null),
`ordinary_changes` (defined below), and `fields` sorted by field UUID. A field has `field_id`, `descriptor_digest` (lowercase hex), `codec_id`, and
`value` (null or canonical padded Base64 of the encoded scalar bytes). Record identity is exactly
`{"kind":"uuid","value":"canonical UUID"}` or `{"kind":"u64","value":"minimal unsigned decimal"}`.
Integers for tokens/generations follow the bounded manifest counters. Reject duplicate mutation/field identities.
The frozen request also covers every explicitly changed ordinary mapped attribute in an `ordinary_changes` array, with
its lock-pinned original type ID and exact admitted scalar bytes encoded the same way. Unknown/custom processors reject.
The whole canonical request is bounded to 16 MiB and depth 32 before its keyed digest is computed.
Host-side implicit effects outside this closed write inventory are ineligible. The root/generation stays a read dependency
through reconciliation and the retry-retention barrier. Do not log canonical requests or the anchor root/key.
Independent canonical-byte/commitment vectors and full changed-attribute/default inventory remain G-TRANSITION/G-ORM evidence.
All effects (including DELETE and rollback-mirror updates) commit with one logged outcome row in the same PostgreSQL transaction.
The outcome stores domain/target/operation, request digest, worker/token, protocol/generation and committed effect summary;
no plaintext, search terms or raw SQL. UNIQUE(domain, operation) prevents a repeated operation from executing twice.
A different digest under the same ID is `OperationIdentityConflict`. An already committed matching operation returns its
recorded outcome after current authorization, not a fresh mutation. Statement retries after a rolled-back transaction reuse that ID.

If COMMIT was sent and acknowledgement is lost, do not mark rollback, resend effects, clear ownership or delete the outcome.
Reconcile the original external record and backend on the exact current writer target. First establish that original backend
is terminal: completed, rolled back or verified terminated with no prepared transaction. Then read the durable marker using
a fresh current-primary transaction (not a stale replica/snapshot or restored checkpoint). Matching marker means COMMITTED,
including when later work deleted the data row. Absent marker means NOT_COMMITTED only after terminality and trusted target
lineage/durability are proven. Otherwise outcome remains UNKNOWN. Failover data-loss ambiguity cannot manufacture rollback.
No automatic commit retry occurs from marker absence while the original backend might still commit.

External receipts record the observed DB outcome afterwards. They are not atomically committed with PostgreSQL.
Registered operations remain until classification/conditional acknowledgement. Marker GC requires all operation owners terminal,
external acknowledgements durable, no supported delayed retry/recovery dependency and approved retention closure.
There is no fixed TTL or row-delete cascade. Capacity exhaustion in the outcome ledger denies new mutations safely.
Authority loss cannot reconstruct permission from DB markers alone. H2 does not create a cross-service transaction.

## Specific questions requiring a written human answer

| # | Question / required artifact |
|---|---|
| Q1 | Does AES-256-GCM-SIV with OS random 96-bit nonces, 1-MiB payload cap, 32-byte hashed AAD and aggregate 2**24 calls/2**40 bytes per root achieve a defensible multi-key lifetime bound? State assumptions and actual confidentiality/forgery bounds, including rejected decryption attempts |
| Q2 | Is hashing the complete typed AAD context an acceptable SHA-256 composition? Can any tag/position/absence/typed-record encoding collide or admit relocation/type confusion? Supply independent canonical vectors |
| Q3 | Does the descriptor exclude only legitimately mutable data? Are representation/subject incarnation/generation/version domains sufficient across rename, restore, scope transfer and re-adoption? |
| Q4 | Are HKDF extract salts and payload/search/operation-commitment info domains separated correctly under shared payload roots and independent search roots? Assess full-width HMAC request commitments as well |
| Q5 | Is one exact admitted root dispatch sufficient without key commitment for this attacker model? Demonstrate/identify cross-key attacks that still apply without attacker-controlled key registration |
| Q6 | Are raw scalar, Decimal/Unicode/email/phone equivalence and bounded normalization definitions unambiguous and lossless? Confirm independent payload/search byte vectors and invalid-input rejection |
| Q7 | Do durable burned reservations preserve ceilings across fields/workers/retries/fork/restore and rollback mirrors? What root partition or shorter lifetime is necessary if live data cannot fit? |
| Q8 | What RNG/fork/cached-root assumptions are actually required? Confirm that PID rejection and a fresh child nonce sample do not establish entropy, re-admission or memory destruction |
| Q9 | Is the stated equality/frequency/access/volume/chosen-input/conflict leakage adequate? Which intended identifier workloads remain unsafe despite rejecting low-cardinality fields? |
| Q10 | Would a presence/row MAC materially improve this intended product despite historical absence replay/omission? Is explicit nullable-integrity ineligibility acceptable, or must the format change? |
| Q11 | Which rotation/rewrap/old-reader/rollback dependencies can expose or strand data? Confirm that rewrap does not cure an exposed payload root or erase backed-up wrappers |
| Q12 | Does current authority + fence-before-admission + durable worker/mutation drain prevent managed denial resurrection? Identify any unfenced external effect or terminality assumption needing independent operational review |
| Q13 | Can retained exact-version orphan intents and conservative recovery establish only denial/inventory, without falsely proving latestness? List permanent-loss boundaries and required current service observations |
| Q14 | Is managed subject revocation correctly distinguished from domain custody destruction? Define the bounded copy/custody/recovery controls needed before any stronger destruction claim |
| Q15 | What release-blocking changes, reference vectors, negative mutants and human specialist reviews are mandatory before real-data use? Distinguish proof, vendor guarantees and empirical observations |

## Available and missing evidence

[Source verification](hardening-evidence.md) records exact version publication facts and primary API/RFC links.
[Local spikes](../../spikes/README.md) include actual native AESGCMSIV smoke, fork PID rejection, presence-marker counterexample,
real PostgreSQL ORM/search cases and bounded fake-authority exploration. They do not qualify the composed runtime.
S4 uses a synthetic descriptor digest and fixture roots. Full descriptor/normalizer/CPD2 cross-implementation vectors are absent.
Real KMS/IAM/DynamoDB/S3/worker termination/restore/destruction artifacts, target-cell runs and whole-backend benchmarks are absent.
No fake or first-party AI review substitutes for the requested written expert answers.
