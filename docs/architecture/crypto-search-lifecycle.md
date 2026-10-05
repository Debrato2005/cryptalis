# Cryptography, Search, and Key Lifecycle Contract

Status: detailed architecture proposal with private candidate framing and scalar syntax encoding and decoding.
No encryption implementation, frozen wire format, approved suite, or measured gates.

Reviewed: 2026-09-30. First-party reconciliation: 2026-10-01. F1 parser review: 2026-10-05.
W1 parser review: 2026-10-04. Scalar decoder review: 2026-10-04.

This document owns detailed envelopes, derivation, search leakage, providers, caches, fences,
rotation and bounded shredding. The [architecture hub](README.md) owns cross-system invariants.
[Manifest/context/API](manifest-context-api.md) owns logical identities, declarations, grants,
errors and configuration. The [assurance owner](assurance-evidence.md) owns evidence, results and
collectors. [Primary-source evidence](../research/crypto-provider-evidence.md) records inspection.
[Prior art](../prior-art.md) owns positioning. The [tracker](../backend-build-checklist.md) alone
records implementation state.

All capability families remain active research. Search is disabled in the initial runtime target. Equality, IN, and scoped uniqueness are later
individually gated candidates. Advanced search and controlled authority have independent gates. Candidate
bytes and numeric budgets make prototypes falsifiable.

They are not an authenticated protocol implementation, primitive approval, measured performance,
or declaration of production readiness.

## 1. Trust, claims and authority

The trusted application handles plaintext. Database attackers may read, modify, replace or replay
ciphertexts, terms and backups. Root custody is separate. Authenticated encryption with associated
data (AEAD) protects confidentiality and authenticated context under its accepted assumptions.

Additional authenticated data (AAD), also called associated data, binds context without encryption.
AEAD does not supply database completeness, availability, freshness or application authorization.

Every cryptographic operation, token operation and reveal receives an immutable authenticated grant
under the [context owner](manifest-context-api.md). The operation validates tenant and subject
selection before key lookup. The envelope cannot choose an arbitrary provider key, tenant, subject
or historical policy. Ordinary sessions have one tenant authority.

Migration, administration and restore use explicit grants. Request parameters, ambient variables,
model attributes and pooled connections are transport only.

| Claim | Required boundary | What remains recoverable |
|---|---|---|
| Storage confidentiality | Named persistence paths emit randomized authenticated payloads using reviewed primitives | Application plaintext. Length/identity/index metadata. Old ciphertext under retained keys |
| Managed access revoked | Registered workers, release authority, operation fences and supported restoration enforce deny | Offline backed-up wrappers under surviving ancestors. Unmanaged copies. Disclosed plaintext |
| Cryptographic recovery paths destroyed | Every declared recovery path eliminated with evidence, including snapshots/provider copies | Out-of-scope copies, copied plaintext and retained search observations |

A receipt attests recorded observations under its signer's trust model. It does not attest memory
zeroization, legal erasure or control-plane honesty. searchable and strict_shred are policy
profiles, never receipt conclusions.

## Required domain and representation bindings

The [identity owner](manifest-context-api.md#desired-policy-and-active-authority) defines generated IDs and current authority.
The next admitted composition must encode these payload bindings unambiguously in AAD and payload KDF domains:

| Binding | Trusted input and purpose |
|---|---|
| protection_domain_id | Current environment/recovery authority, independent of database restore |
| tenant_id, subject_id, immutable_record_id | Authorized scope and independently checked resource identity |
| model_id, table_id, field_id | Stable logical ownership. Physical names do not enter payload binding |
| representation_id | Never-reused protected incarnation from authenticated descriptor/history |
| immutable descriptor digest and binding/suite/codec versions | Exact creation format, not the whole current manifest digest |
| declared cryptographic purpose and material generation | Catalogue-selected domain and exact authorized generation, not a request-selected decrypt purpose |
| authenticated header, fresh seed and nonce under the selected suite | Strict bounded parse, authorized dispatch, then authentication. No trial-key fallback |

Search derivations, when admitted, bind protection domain, field, search representation/domain, normalizer and codec versions, tenant/scope, purpose, and generation.
Payload, search, wrapping, audit, and receipt purposes cannot substitute for one another.
Wrapper registries bind domain, tenant/subject scope, exact immutable root/version, purpose, and wrapper/material generations.
They cannot accept a header-selected provider or alias as authority.

The existing descriptor schema 1 and F1/W1 structures predate these bindings.
Their current structural parsers and example bytes remain unchanged and unauthenticated.
The candidate v1 AAD/KDF formulas below are pre-reconciliation experiments, not a production composition.
They must change with reviewed descriptor/catalogue/binding versions before real ciphertext.
Exact successor bytes, sole suite/library/key-management composition, and key-commitment policy remain [Q2](README.md#unresolved-research-questions).
No production encryption or ORM transparency proceeds from the parser slice.

Cross-domain, remove/re-add, descriptor substitution, exact-key/alias-retarget, and one-component AAD/KDF vectors gate that revision.
Stable renames must preserve readability. Re-adoption must reject historical-incarnation replay.
Same-record replay within one admitted incarnation remains possible without a separate trusted monotonic freshness authority.
An intentionally copied domain, authority, and keys create cryptographic equivalence. A staging clone cannot claim isolation from those copies.

## 2. Suite candidates and selection

| Candidate | Parameters | Operational obligation | Decision |
|---|---|---|---|
| AES-256-GCM-SIV | 32-byte key, 12-byte nonce, 16-byte tag | Random writes. Usage limits. Pinned OpenSSL availability. Two-pass cost | Leading non-FIPS hypothesis |
| AES-256-GCM | 32-byte key, 12-byte nonce, 16-byte tag | Unique per-write key/nonce pair, reviewed aggregate budget. Reuse catastrophic | Comparative candidate. Possible exact validated-module lane |
| XChaCha20-Poly1305 | 32-byte key, 24-byte nonce, 16-byte tag | Pinned libsodium binding/vectors. Reuse forbidden | Comparative candidate |
| ChaCha20-Poly1305 | 32-byte key, 12-byte nonce, 16-byte tag | Pair uniqueness. No misuse-resistance advantage | Comparative candidate |
| Established high-level envelope/keyset library | Reviewed native key template/format | Separate format/lifecycle analysis. No relabeling as F1 | Integration comparison |

[RFC 8452](https://www.rfc-editor.org/rfc/rfc8452) specifies AES-GCM-SIV. The [cryptography
API](https://cryptography.io/en/stable/hazmat/primitives/aead/) requires a compatible backend.
[libsodium](https://doc.libsodium.org/secret-key_cryptography/aead) documents XChaCha. No suite
passed G-CRYPTO. Dependency upgrades cannot silently change protocol parameters.

FIPS claims require the exact validated module, platform, configuration and operational boundary. An
AES algorithm or backend name is insufficient. Review also considers multi-key security and key
commitment: AEAD authentication is not automatically proof of a unique possible key. Grant and
registry selection forbid arbitrary key trials. A reviewed committing envelope is an explicit
alternative if the threat model requires it. AES-GCM-SIV is not automatically key committing because
it is misuse resistant. F1 must reject attacker-chosen provider locators, keys and generations
before provider access.

One authorized handle resolves to exactly one subject generation and key, with no trial-decrypt
loop. Header and AAD binding constrain selection. They do not prove commitment when an adversary can
choose both candidate keys and context. G-CROSSKEY records whether the threat model excludes
adversarial key registration or requires a reviewed committing construction.

## 3. Candidate field envelope

### 3.1 Framing F1 for the freeze experiment

F1 uses BYTEA storage. Integers are unsigned big-endian. Fixed byte strings are literal bytes.
Opaque stable IDs use manifest-declared canonical encodings, never Python repr, display names,
default JSON or locale strings.

| Offset | Length | Field | Candidate rule |
|---:|---:|---|---|
| 0 | 4 | magic | ASCII CRYP |
| 4 | 1 | format | 1 |
| 5 | 1 | suite | Candidate registry: 1=GCM-SIV, 2=GCM, 3=XChaCha, 4=ChaCha. None approved |
| 6 | 2 | flags | Zero. No extension/compression bits |
| 8 | 2 | header length | Exactly 108 |
| 10 | 1 | nonce length | 12 or 24, fixed by suite |
| 11 | 1 | tag length | Exactly 16 |
| 12 | 4 | ciphertext length | Encoded protected-value length. Excludes header/nonce/tag |
| 16 | 16 | subject key handle | Opaque ID resolved through authorized registry |
| 32 | 8 | subject generation | Nonzero, permitted by grant/read compatibility |
| 40 | 32 | creation policy digest | Original immutable field-policy binding |
| 72 | 32 | value seed | Fresh OS-CSPRNG bytes per encryption attempt. Public diversification |
| 104 | 2 | codec entry ID | Immutable allowlisted catalogue codec/revision pair. Parameters bound by creation descriptor |
| 106 | 2 | AAD binding version | 1 for candidate |
| 108 | suite-dependent | nonce | Fresh OS-CSPRNG bytes |
| after nonce | declared length | ciphertext | Authenticated encoded value |
| final 16 | 16 | tag | Full authentication tag |

Total = 108 + nonce_length + ciphertext_length + 16. Fixed overhead is 136 bytes for 12-byte nonces
or 148 for XChaCha, before codec framing and database/index overhead. G-CRYPTO may reject this
expensive explicit candidate or select different bytes before freeze.

F1 has no provider blob or wrapped per-value key. The random seed diversifies a locally derived
per-value key under an independently random subject key. Branch/subject wrapping records have
separately versioned authenticated framing and limits. A library-native random DEK plus wrapped DEK
is a competing experiment, not an interchangeable parser branch.

### 3.2 Parser and resource limits

Initial private [`parse_candidate_envelope`](../../src/cryptalis/crypto/_candidate_envelope.py)
support checks candidate F1 structure without authentication or decryption.
It accepts immutable bytes and returns a frozen `CandidateEnvelope` with untrusted header and body fields.
It checks the fixed header, candidate suite and codec selectors, binding version, flags, generation,
and exact total length. The encoded ciphertext length is 5..1,048,576 bytes.
The lower bound follows from the five-byte scalar frame.
The total envelope limit is 1,048,724 bytes.
The parser rejects oversized input before header interpretation.
It checks all declared lengths before copying nonce, ciphertext, or tag buffers.
Errors use redacted `EnvelopeMalformed`, `EnvelopeUnsupportedFormat`, and `EnvelopeOversize` categories.
The result's `repr` excludes byte buffers.

This parser is a private candidate experiment. No public API or CLI command enables encryption.
It does not check authorization, descriptor approval, field-specific limits, codec content,
nonce freshness, or authentication tags. Every returned byte remains unauthenticated.
A well-shaped forged digest or tag can pass structural parsing.
The [structural example](../../examples/envelopes/f1-structural.hex) contains synthetic header
and ciphertext bytes. It is not a valid authenticated encryption vector.
Candidate scalar IDs remain provisional. G-CRYPTO remains open.
The full fuzz corpus, authenticated composition, and independent review remain pending.

The complete candidate parser and decryption path must enforce these bounds before allocation or key lookup:

- Encoded value/ciphertext maximum 1,048,576 bytes. Total envelope maximum 1,048,724 bytes. Field
  policy may lower it. The five-byte state/length frame leaves at most 1,048,571 content bytes for
  text or bytes. Typed codec overhead consumes that same budget. Larger values require a separately
  designed chunked format.
- AAD maximum 16,384 bytes. Each variable identity component maximum 128 bytes. No recursive
  metadata, unknown extensions or provider URLs in the envelope.
- Wrapped branch/subject blob maximum 16,384 bytes. An incompatible provider needs another reviewed
  wrapping-record format.
- Overflow, zero/invalid generation, unknown suite/version/flags/codec, wrong fixed lengths,
  truncation, inconsistent total length and trailing bytes fail closed.
- Parsing is linear in bounded input. No decompression, arbitrary-object deserialization, code
  import, provider I/O, multiple-key trials or plaintext fallback.
- Recognition is not authentication. PostgreSQL CHECK or domain predicates can validate structure
  only after freeze. Forged well-shaped bytes still require AEAD verification. SQL NULL presence
  needs a separate constraint. A nullable SQL NULL is unauthenticated, so substitution of an
  envelope with NULL is not an AEAD failure. The [ORM null contract](orm-schema-migration.md) owns
  this integrity limitation and encrypted-null/authenticated-presence admission.
- Failures have redacted typed categories. Public responses do not distinguish a wrong tenant,
  unknown subject, generation or tag as a key-existence oracle. Retry/attempt budgets are bounded.

Decryption returns no plaintext before tag verification and codec validation. The design prefers
verified high-level decrypt APIs. Into-buffer APIs must quarantine output until verification and
document failure behavior. Cancellation and errors release handles and prevent partial
serialization.

Python garbage collection does not prove plaintext/key zeroization.

The scalar codec proposal is state byte + u32 length + exact typed bytes. State 0=null has zero value bytes. State 1=value contains the typed bytes.

Codec IDs distinguish bytes, string, integer and decimal. Each has an explicit canonical specification. The two-byte F1 codec entry selects an immutable
catalogue pair `(logical_codec_id, codec_revision)`. The catalogue never reuses that entry for
changed bytes or semantics. Candidate entries 1–4 all use revision 1 and the respective logical
codec ID below.

The creation descriptor binds the field constraints. The decoder checks entry existence and exact
descriptor match before decode. Candidate scalar codec IDs:

- 1=strict UTF-8 text with no encoder-added BOM and no lone surrogates. It preserves content without
  normalization. A leading U+FEFF in the input is valid content and round-trips unchanged.
- 2=raw bytes.
- 3=integer minimal ASCII decimal (optional minus, no plus, leading zeros or negative zero).
- 4=finite decimal as sign byte (0=positive, 1=negative), signed big-endian two's-complement i32
  scale, unsigned big-endian u32 coefficient length and minimal unsigned ASCII coefficient (zero is
  `0`). Decimal numeric value is (-1)^sign * coefficient * 10^-scale. The codec preserves trailing
  zeros, scale and negative zero when declared. It rejects NaN and infinity. Per-field
  precision/scale bounds apply before allocation. Candidate integer/decimal magnitude has at most
  1,024 decimal digits. Decimal scale is -1,024..1,024, with field constraints allowed to narrow
  these caps. This decimal encoding is inside outer state/length framing.

IDs are provisional until vectors freeze. The codec does not coerce bool to integer. Timestamps, UUID and JSON need new
  explicit codecs. Empty text is not null.

Structured codecs need rules for depth, counts, duplicate keys and numbers. Default JSON encoding is
insufficient.

#### Implemented scalar syntax boundary

The [private scalar codec](../../src/cryptalis/crypto/_candidate_scalar.py) implements candidate syntax for entries 1–4 above.
`encode_candidate_scalar` returns unprotected bytes. `decode_candidate_scalar` returns unauthenticated typed values.
An explicit integer selector chooses the syntax. Unknown selectors reject even for null.
The decoder accepts immutable `bytes` and checks state, exact declared length, truncation, and trailing bytes before typed conversion.
The encoded record has a 1,048,576-byte cap, including its five-byte outer header.
Text and raw bytes can therefore contain at most 1,048,571 bytes.

Integer magnitude and decimal coefficient have at most 1,024 ASCII digits. Decimal scale is -1,024..1,024.
Bounded digit arithmetic avoids Python's ambient integer string-conversion limit.
Decimal tuple construction preserves sign, exponent, and trailing zeros without ambient precision rounding.
Text decoding preserves a leading U+FEFF and Unicode content without normalization.

Null differs from empty text or bytes. Invalid states never substitute null.

Failures use the shared `EnvelopeInvalid` hierarchy. Unknown selectors raise `EnvelopeUnsupportedFormat`.
Resource bounds raise `EnvelopeOversize`. Invalid syntax, framing, or input types raise `EnvelopeMalformed`.

The encoder accepts `None` or the exact `str`, `bytes`, `int`, or `Decimal` type selected by the codec.
It rejects bool, subclasses, mutable byte buffers, and implicit conversion.
Unknown or mistyped selectors reject before null encoding.
Text encoding adds no BOM and preserves Unicode content. Lone surrogates reject.
The encoder checks character count before UTF-8 conversion and byte count before framing.
A rejected multibyte string can allocate at most four times the maximum text payload during that conversion.
Caller-owned inputs and diagnostic object retention remain outside this allocation bound.

Integer range checks precede bounded digit extraction. The encoder does not use ambient integer string conversion.
Decimal validation uses a private explicit context and quantizes to the input's own exponent.
Equal exponents prevent rounding. The precision cap rejects oversized coefficients before digit-tuple extraction.
An explicit scale check follows. Negative zero, trailing zeros, and exponent remain unchanged.
The private context permits all admitted representations, including the largest adjusted exponent.
No operation changes global integer settings or the caller's decimal context.

Safe diagnostics identify the scalar stage or field without input values. Unicode errors retain their original cause.
Host diagnostics must not serialize exception attributes or local values because retained causes can contain input values.

The [boundary tests](../../tests/test_candidate_scalar.py) and
[synthetic vectors](../../examples/scalars/candidate-vectors.json) protect syntax only.
Successful encoding or decoding does not authenticate bytes, approve catalogue entries, match a creation descriptor, or grant release authority.
Field-specific nullability, precision, scale, and negative-zero constraints remain pending.
Before storage, the caller must approve field policy and encrypt the encoded value.
Before plaintext release, the caller must authenticate and approve decoded values.
Public APIs and CLI commands remain pending. No production consumer uses this private codec.

### 3.3 AAD and policy compatibility

Candidate tuple encoder E: unsigned big-endian u16 component count, then each component as u8 tag +
unsigned big-endian u32 byte length + exact bytes. These provisional tag numbers are fixed for
vector comparison:

| Tag | Type and canonical rule |
|---|---|
| 1 | ASCII protocol label (no NUL) |
| 2 | UUID (exactly 16 network-order bytes) |
| 3 | SHA-256 digest (exactly 32 bytes) |
| 4 | Unsigned integer (exactly eight big-endian bytes, no bool coercion) |
| 5 | Opaque byte string |
| 6 | Strict UTF-8 enum string without normalization |

The calling format bounds counts and lengths. Unknown tags, inappropriate tag at a declared
position, noncanonical encodings and trailing bytes reject. Signed decimal scale belongs to the
scalar codec, never tag 4. Manifest lowercase UUID strings become tag 2.

Lowercase digest hex becomes tag 3 after canonical validation. This does not change manifest JCS
bytes. All suite IDs, codec entry IDs, normalization versions, states, binding versions and
generations use tag 4 in E, even when the F1 header stores them in narrower fields. Grant/catalogue
ranges still apply.

Header bytes, value seeds and normalized bytes use tag 5. access_profile_id uses tag 6. It is
exactly the creation descriptor's access_mode enum (`transparent` or `controlled`). It is not the
search or shred policy or an arbitrary runtime profile name. Protocol label is tag 1.

The literal E calls below declare component positions and types. No implicit type inference is
permitted. Index domains are stable UUIDs, and normalizer/codec version references are integers.

Pre-reconciliation candidate AAD, not eligible for production freeze:

```text
E("cryptalis/payload/v1", aad_binding_version, header_bytes,
  stable_tenant_id, stable_subject_id, stable_model_id, stable_table_id,
  stable_field_id, immutable_record_id, access_profile_id)
```

AEAD authenticates the entire header, including policy digest, suite, generation, seed, codec and
lengths. Model, table and field IDs represent logical ownership. They survive display and physical
renames. Record identity exists before encryption.

Point reads get the requested-resource identity from the host's independent authenticated mapping.
They compare that identity with the authenticated immutable record UUID. Swapping a valid envelope
**and** its subject/key/record companion metadata while retaining the requested relational PK must
fail. Database ownership columns alone do not establish this binding.

Server-generated or mutable IDs require a proven creation adapter or rejection. Expected ownership comes from authorized context and persisted relations. It never comes solely from the candidate
header or mutable row values.

Current context manifest digest authorizes a finite explicit compatibility mapping from current
policy to original creation-policy digest/version. It is not substituted into every old envelope's
AAD. Thus, ordinary log-policy edits and physical renames need not reencrypt all payloads. Changes
to logical identity, access profile, codec or crypto binding require an explicit compatible reader
or decrypt/re-encrypt migration.

The exact [immutable field-format
descriptor](manifest-context-api.md#immutable-field-format-descriptor) and domain-labeled JCS hash
define the creation digest. Original policy records remain immutable and digest-verified. Unknown
digests cannot trigger permissive historical reads.

Request ID, expiry, requested release purpose, and principal are runtime grant checks, not changing persisted AAD:
future independently authorized readers must recover the same value. Controlled release separately
binds those properties in section 10.

Raw relocation across tenant, subject, field or record rejects. Replay of old authentic bytes into
the same identity does not. Freshness requires a separately specified trusted version/checkpoint
authority. Mutable database counters cannot prove rollback resistance against a database attacker.

Moves and transfers are migrations with old and new grants, CAS, fencing, index consequences and
restore compatibility. Raw ciphertext copying is forbidden.

### 3.4 KDF, domains and randomness

Pre-reconciliation candidate HKDF-SHA-256 follows [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) with reviewed
libraries. Root, branch, subject and index seeds are independently random 32-byte secrets. They are
never passwords or tenant IDs:

```text
salt = SHA256(E("cryptalis/extract/v1", tenant_id, subject_id, subject_generation))
subject_prk = HKDF-Extract(salt, random_subject_key)
field_key = HKDF-Expand(subject_prk,
  E("cryptalis/payload-key/v1", suite_id, field_id, model_id, table_id,
    immutable_record_id, creation_policy_digest, value_seed), 32)
```

The salt and value seed supply public diversification. They are not secret key material. Each
derived F1 key permits one encryption invocation. A retry that generates ciphertext allocates a new
seed and nonce. Resending the identical existing envelope is permitted under its same context.

Rollback and cancellation never authorize reencrypting with the old pair.

Subject wrapping derives a separate wrapping key with branch generation, tenant, subject handle,
subject generation and fresh wrapper seed. Wrapping AAD binds its record, version and registry
ownership. Never derive a subject secret directly from a surviving tenant branch. Deleting its
record would not stop regeneration.

Root rewrap, branch rotation, subject rotation and payload re-encryption remain different
operations.

Tenant search uses an independently random wrapped index root, separate from payload subject keys.
Index candidate derivation uses HKDF-Extract with salt SHA256(E("cryptalis/index-extract/v1",
tenant_id, index_root_handle, index_generation)), followed by HKDF-Expand to 32 bytes with
E("cryptalis/index-key/v1", capability_id, domain_id, codec_entry_id, normalization_version).
Tenant, root and domain IDs use tag 2. Generation, codec and normalization use tag 4.

The capability enum uses tag 6. Labels use tag 1. Root records pin capability, domain, normalizer
and codec ownership. Index secret and subject secret never substitute for one another.

Subject-scoped search derives a 32-byte key from subject_prk. It uses HKDF-Expand info
E("cryptalis/subject-index-key/v1", capability_id, domain_id, codec_entry_id, normalization_version,
index_generation). It uses the same enum, UUID and integer tags, with a separate registered
index-generation counter. It cannot substitute for tenant or domain search.

Receipt and audit signing keys have separate managed authority. Payload keys never sign receipts.
Migration receives grants, not a derivation label that bypasses lifecycle policy.

Freeze review analyzes the actual composed multi-key bounds. The initial harness caps a subject
generation at 2^24 value derivations or 2^40 encoded plaintext bytes, whichever comes first. These
conservative operational proposals are not primitive-derived security proofs. Ideal 256-bit seed
collision probability at q draws is approximately q(q-1)/2^257.

That estimate does not survive RNG failure or snapshot cloning. Inject a repeated seed AND nonce. No
known-repeat pair may produce another encryption. OS RNG failure fails closed. Python random and
copied PRNG state are forbidden.

Detection cannot prove entropy. Platform, CSPRNG and suite assumptions remain essential.

The following distributed quota reservation protocol is a future fleet profile.
It is not required by the initial single-process target and supplies no implemented exact-use guarantee.
The initial adapter still needs reviewed generation/byte caps, local one-way consumption, and fail-closed exhaustion.
Cross-process allocations and invisible VM-clone claims require their distinct platform evidence before fleet admission.

The reference distributed budget registry lives in the independent durable authority. It does not
live in the application database, cache or their snapshots. **Default preparation reserves bounded
quota at an explicit warm/session preparation boundary. Scalar processors never perform remote
CAS.** A serialized per-generation CAS checks both remaining caps and durably charges a disjoint
allocation ID, worker incarnation, lease expiry, maximum invocation count and maximum encoded-byte
count. One allocation permits at most 256 invocations and 16MiB encoded bytes. A preparation may
request up to four such allocations per affected generation for its declared bounded operation.

Lower application caps apply. Requests exceeding available quota fail before protected DML.
Automatic replenishment inside a hook is forbidden. A later explicit preparation can request a
further allocation. The global charged totals cannot exceed the generation caps, including
outstanding/unused quota.

A warmed handle tracks its allocation's atomic, one-way local consumption of counts and bytes.
Before each encryption, reserve one slot and the exact encoded charge locally. Then generate a fresh
OS-CSPRNG seed and nonce. Reject a seed already observed by that live handle and generation.

Cancellation, crash, failed commit and unused expiry permanently consume or abandon the allocation.
There is no refund, transfer, reassignment or counter reset. A retry with new ciphertext consumes a
fresh slot/seed. Retransmission of an already durable envelope consumes none. Allocation issuance
retries use an idempotency ID.

Return the same disposition and owner. Never return a second uncharged allowance. Local quota
exhaustion fails with Key.QuotaExhausted. It does not call the registry from a scalar processor.

The initial hash-based message authentication code (HMAC) lab profile separately caps each registered index-root generation (or
subject/index/domain generation) at 2^32 token invocations or 2^40 normalized bytes, including
queries, writes and retries. The same upfront allocation protocol charges token invocations and
bytes. Repeated deterministic inputs are allowed. There is no AEAD seed-dedup rule.

Logical IN input encoding/normalization totals are capped at 16MiB per prepared query. Index calls
never silently charge payload counters. These are operational proposals, not primitive-derived
proofs.

Allocations are deliberately non-restorable. Startup, fork, suspension/resume, VM-memory restore or
loss of connection or incarnation discards local quota and handles. Each requires fresh online
registration and charged allocation. The controlled platform must show an observable transition
before resumed code can consume anything. **Invisible process/VM-memory cloning can duplicate local
spent state and is not prevented by a random boot ID or this quota protocol.** A platform unable to
fence that transition cannot claim an exact actual-invocation cap or cross-clone key/pair non-reuse,
and cannot enter this reference profile.

This is an explicit G-CRYPTO/G-LIFECYCLE platform gate, not a promise that Python detects arbitrary
hypervisor restoration. Local known-seed checks also do not supply global detection of RNG failure
or seed duplication. Entropy and fresh process randomness remain actual assumptions. Fault fixtures
test those assumptions. A set lookup does not prove them.

An active alternative performs externally serialized **per-attempt** consumption and global seed
fingerprint registration at an explicit awaitable preparation boundary before each crypto operation.
It rejects generation-wide seed reuse, including the same seed with a different nonce, and keeps
monotonic consumed counts. It pays online latency/availability/retention costs and still requires an
execution/snapshot boundary preventing replay of the already returned one-shot permission. Merely
logging a reservation cannot physically stop a RAM clone.

Select a controlled gateway/attested execution boundary or narrow the clone threat before a stronger
exact-use claim. G-CRYPTO/G-BUDGET compare both profiles, without secretly installing online calls
in descriptor/type hooks.

Restoration compares the live authority's ledger and tombstones. Restored counters cannot lower
charges and restored allocations never reopen. Loss of the authority or unprovable authority
recovery blocks the affected generation. It requires separately authorized new random material, not
a counter reset.

Registry/allocation contention, abandoned quota, preparation RPCs and retained public usage metadata
belong in end-to-end G-BUDGET. The caps bound actual invocations only under the demonstrated honest
worker/incarnation assumptions. They are not a proof against a compromised key-holding workload.

### 3.5 Local secret wrapping candidate W1

Managed-root wrapping of tenant branch bytes uses the provider's pinned native authenticated record
and context. It does not use W1. For local branch wrapping of independently random 32-byte subject
or index-root secrets, W1 is a concrete comparison candidate with no frozen/approved production
bytes. Its 96-byte header contains these fields in order:

| Field | Length/type | Candidate rule |
|---|---|---|
| magic | 4 bytes | ASCII `CRYW` |
| format | u8 | 1 |
| suite | u8 | Same candidate registry as F1 |
| kind | u8 | 1=subject, 2=index root |
| flags | u8 | 0 |
| header length | u16 | 96 |
| nonce length | u8 | 12/24 by suite |
| tag length | u8 | 16 |
| parent branch handle | UUID16 | Parent identity |
| parent generation | u64 | Parent generation |
| child handle | UUID16 | Child identity |
| child generation | u64 | Child generation |
| fresh wrapper seed | 32 bytes | Fresh seed |
| ciphertext length | u32 | 32 |

All integers use big-endian. Both generations are nonzero. Then append fresh nonce, 32-byte
ciphertext and full 16-byte tag. Total 156 or 168 bytes.

Unknown values, lengths, trailing bytes or unauthorized parent/child ownership reject before branch
lookup. The general 16KiB provider-blob cap does not relax W1's exact length.

The [private W1 parser](../../src/cryptalis/crypto/_candidate_wrap.py) implements only these structural checks.
It accepts immutable `bytes`, rejects physical input above 168 bytes before header parsing,
and requires the exact suite-specific frame length. Both generations must be nonzero.
Any declared ciphertext length other than 32 is malformed, including oversized declarations.
It reuses F1's candidate suite registry and `EnvelopeInvalid` error hierarchy.

Unsupported selectors raise `EnvelopeUnsupportedFormat`, oversized physical records raise `EnvelopeOversize`,
and other malformed inputs raise `EnvelopeMalformed`. Safe diagnostics identify the failed field without input bytes.
The returned object is immutable and excludes all byte fields from `repr`.

The [W1 boundary tests](../../tests/test_candidate_wrap.py) and
[synthetic vector](../../examples/envelopes/w1-structural.hex) protect this private experiment.
Every returned identity and byte remains untrusted. Parsing does not check ownership or seed/nonce freshness,
authenticate a tag, derive a key, decrypt a secret, or grant release authority.
Those checks remain required at their authorized boundaries before branch lookup or secret release.
No public API, CLI command, or production consumer uses this parser.

W1 uses HKDF-SHA-256 with these candidate expressions:

```text
extract salt = SHA256(E("cryptalis/wrap-extract/v1", tenant_id, parent_handle, parent_generation))
PRK = HKDF-Extract(salt, random_branch_secret)
key = HKDF-Expand(PRK, E("cryptalis/wrap-key/v1", kind, child_handle, child_generation, wrapper_seed), 32)
AAD = E("cryptalis/wrap/v1", header_bytes, tenant_id, owner_id)
```

The owner is the immutable subject UUID or the authoritative index-domain UUID. Index roots cannot
reinterpret subject ownership. Labels/tag types follow E above. Resolve one authorized immutable
registry record containing kind, tenant, owner, handles, generations, suite and version.

Compare every header component. Reject provider locators and trial parent keys. A wrong owner cannot
be rescued by omitting AAD. Ciphertext plaintext is exactly the randomly generated 32-byte child
secret.

Each wrap/retry uses a new seed/nonce, one derived key/invocation and a consumed branch-generation
pre-reserved quota slot under the section 3.4 protocol, with separate proposed 2^24 invocation/2^40
encoded-byte caps. Rewrap constructs a new wrapper using a new parent generation and fresh attempt.
Its child secret/identity stays the same. Branch material cannot deterministically recreate a
deleted child.

Provider-native library/keyset wrapping is an alternative with its own bytes/vectors. G-CRYPTO,
G-CROSSKEY and G-PROVIDER must review W1, its registry, budget and native-root composition before
admission. Describing these bytes is not a claim of key commitment or subject erasure.

## 4. Normalization and equality semantics

Equality proposes full 32-byte HMAC-SHA-256 terms over E("cryptalis/equality-term/v1",
codec_entry_id, null/value state, normalization_version, normalized_bytes), under separately derived
domain keys. The label uses tag 1, the three numeric references use tag 4, and normalized bytes use
tag 5. No unkeyed hashes. Token storage/version framing freezes with physical schema.

Payloads remain randomized. The initial E1 comparison candidate is exactly the raw 32-byte HMAC
output in BYTEA, with no per-term header or truncation. Its physical term slot and authoritative
manifest/catalogue mapping bind representation version 1, capability/domain, normalizer/codec and
the tenant's admitted index-generation mapping. A term cannot select those facts from its own bytes.
SQL NULL has no E1 bytes. Wrong length or an unknown/unlisted slot/generation raises
Query.IndexInconsistent. A future inline version header is an explicit competing representation and
requires a new slot/schema/query migration. E1 is not frozen until G-EQUALITY/G-ORM-3/6 vectors and
rejection fixtures pass.

Length checks do not authenticate it, so query-result verification remains mandatory.

Normalization declares the Unicode database and version, normalization form, case-folding,
whitespace, locale, email and phone conventions, type tags and bounds. Encryption preserves the
original value. Normalization defines equivalence only. Unicode/rule changes require new normalizers
and index migration. Silently lowercasing an email is not an unspecified default.

Negative equality, NOT IN, empty IN, casts/functions/collation and SQL three-valued logic have
independent fixtures.

Null policy is explicit: sql_null reveals null presence, stores no term and cannot authenticate
substitution of an existing envelope with SQL NULL. See the [ORM null-integrity
contract](orm-schema-migration.md). encrypted_null contains authenticated null with declared
null-token treatment. Unique null semantics are distinct or not-distinct throughout migration.
Non-null fields cannot take nullable shortcuts.

Full terms avoid deliberate truncation in the initial unique profile. Accidental collision remains a
probability, not impossibility. Unique conflicts may require authorized bounded decrypt/
normalization to distinguish duplicates from collisions. No competing plaintext enters diagnostics.

Short indexes and expensive blind-index transforms, including [CipherSweet's
modes](https://ciphersweet.paragonie.com/internals/blind-index), remain experiments with
collision/post-filter/DoS budgets. Slower hashing cannot hide frequency or observed queries.

## 5. Capability leakage, cost and lifecycle matrix

Each capability declares setup/query/update/snapshot/deletion leakage. Attacker profiles distinguish
a snapshot, persistent database plus query observation, auxiliary plaintext or distribution
knowledge, chosen inserts or queries, and index or key compromise. Length/nullness/IDs, equality
classes, counts, result/access sets, timing, update links and retained observations are separate
dimensions. Terms are sensitive metadata.

| Capability | Semantics and leakage | Costs to measure | Rotation and deletion | Status |
|---|---|---|---|---|
| No search | Randomized payload. Length/null/identity linkage | Envelope/decrypt cost. Client filtering requires bounded authorized reads | Payload re-encryption. Key-path/backup caveats remain | Core candidate |
| Equality / IN | Domain HMAC. Static frequency, query repetition, result sizes/access, update links and auxiliary inference | 32-byte term + framing/index. IN and dual-query expansion | Reindex whole domain. Dual generations link through rows. Current subject rows delete, backups/observations survive | Candidate per accepted domain |
| Scoped uniqueness | Equality plus existence/conflict oracle | Contention, null policy, duplicate/collision verification | One authoritative uniqueness domain continuously enforced. Section 6 | Candidate with equality |
| Equijoin / grouping | Shared explicit domain links fields/tables/subjects and group sizes | Cardinality/skew, grouping memory/spills, cross-domain authority | Whole shared-domain rebuild. One subject key cannot destroy shared correlation | Active research |
| Range / order / extrema | Named OPE/ORE or another analyzed scheme. Ordering and variant-specific prefix/distance/comparison leakage, query/result observations | Representation bytes, comparison CPU, planner/selectivity, sorting/updates | Whole rebuild. Generations cannot mix in one ordering. Explicit merge/post-filter. Subject payload shredding leaves terms | Active research. Separate production review |
| Prefix / suffix / substring | Prefix/trigram/token/Bloom candidate generation. Membership/overlap, length/co-occurrence and chosen-query inference | Terms/value, query-length bounds, false-positive fanout/decrypt/pagination | Companion rebuild. Delete all derived rows. Shared vocabulary/backup leakage remains | Active experimental |
| Fuzzy / full text | Explicit phonetic/n-gram/text-score scheme. Vocabulary/overlap and emitted scores/positions/access | Recall/precision, ranking stability, vocabulary/query amplification | Tokenizer/normalizer migration. No implicit approximate unique semantics | Active experimental |
| JSON / path / arrays | Allowlisted path/type/value terms. Shape/presence/cardinality/repeats/array relationships | Depth/path/array limits, write/term amplification, companion integrity | Path/codec drift reindex. Delete companions, document shape residue | Active experimental |

The word ORE does not approve a range protocol. Identify its published variant, leakage and oracle.
[Lewi–Wu](https://eprint.iacr.org/2016/612) is one reference. Leakage can permit recovery without
primitive failure: [Cash et al.](https://eprint.iacr.org/2016/718.pdf) and [2026
LAMa](https://arxiv.org/abs/2508.11563v2) inform auxiliary-data attacks. Forward/backward privacy
are construction properties, not labels earned by deleting rows or rotating terms. [Xu et
al.](https://arxiv.org/abs/2309.04697v2) motivate volume attacks.

Candidate-only search verifies decrypted normalized predicates before returning logical matches.
Database attackers may supply false candidates, omit true candidates or replay terms.
Authentication/post-filtering can reject a false returned match but cannot prove completeness.
Consistency scans require authenticated reads and exact versioned term reconstruction.

Missing observations are inconclusive. If a profile requires a subject-authenticated sidecar binding
ciphertext hash to term set, its key/domain/bytes/rotation must be specified before admission. An ad
hoc MAC or unkeyed digest does not supply completeness.

SQL counts, LIMIT/pagination, grouping and aggregates cannot precede approximate post-filtering
without proven exact semantics. Unauthenticated search terms also cannot select payload/reveal
authority or broaden the grant. Row-binding can detect mismatches on returned rows, not missing
rows.

MongoDB's [current
limitations](https://www.mongodb.com/docs/manual/core/queryable-encryption/reference/limitations/)
exclude persistent/query-transcript adversaries from its stated guarantee. Its protocol is not
evidence that deterministic Cryptalis terms meet that guarantee. [CipherStash's
constructions](https://cipherstash.com/docs/security/cryptography) are comparison targets with a
distinct release model. The provisional portable-envelope effort recorded in [prior
art](../prior-art.md) may supply differential codec/vector ideas. Pre-alpha unreviewed
specifications do not approve a crypto dependency or confer novelty.

Search remains disabled initially. Its presence in a manifest or research prototype cannot enable it.
The first admitted equality/uniqueness transition uses offline REINDEX through the generic engine.
It verifies all terms, normalization/null semantics, and one database-enforced uniqueness domain before activation.
Inference acceptance binds the exact policy, corpus/workload, and observation date.
Changed distributions can worsen leakage. No automatic signal exports terms or value histograms.

The online dual-generation protocol below is a later strategy with separate G-UNIQUE/G-OFFLINE successor evidence.
It is not a prerequisite for no-search field protection.

## 6. Search rotation and continuous uniqueness

Rotation names the source and target index, normalizer and domain. It also names the finite
dual-query window, admitted writers, CAS backfill, complete verification, cutover and contract.
Initially at most two query generations. A third waits or gets a separately reviewed protocol. Reads
use exactly the allowed generations.

Every write includes the authoritative term.

Independent old/new unique indexes do not prevent duplicates when writers emit disjoint versions.
Candidate continuous transition:

1. Require authoritative U from every admitted writer.

   Reject any writer unable to produce U. A changed equivalence or domain needs a separate conflict
   plan.
2. Add V as non-authoritative.
3. Admit only writers that atomically emit U and V for every affected insert or update.
4. **Before** V backfill starts, fence and drain all U-only and incompatible writers.

   U continues enforcing uniqueness.

5. CAS-backfill V without overwriting concurrent changes.
6. Verify complete V coverage and normalized equivalence.

   The result must show zero unresolved duplicate or collision groups, valid unique enforcement and exact null semantics.
7. Reverify that U-only writers remain fenced, including restored jobs and new deployments.
8. Keep U enforced while switching authority to V with migration and writer compatibility.
9. Prove database enforcement and version cutover ordering.
10. Retain a finite dual-read and rollback window.
11. Remove U at authorized contract.

    Old writers cannot return afterward.

Incomplete coverage or invalid concurrent indexes block cutover. Changed normalization may merge
formerly distinct values. Resolve conflicts explicitly without discarding data. A stable separate
unique key is an alternative with a long-lived compromise/leakage domain. An explicit write pause/
offline reindex is acceptable if continuous safety cannot be proven.

## Key operation contract

All key changes reuse the [generic transition engine](orm-schema-migration.md#migration-state-machine-and-concurrency).
The shared owner defines plans, approvals, and receipts. Provider substeps never become separate activation authorities.

| Operation | Actual effect / retained obligations |
|---|---|
| Provider master-key automatic rotation | Changes provider-managed future encryption material. Old decryption material can remain. Does not rewrite wrappers or payloads |
| Wrapper/KEK version change and DEK rewrap | Changes covered wrapping records. Payloads and old backup wrappers can remain unchanged |
| New payload-write generation | Future writes use new material. Existing rows still need old generations |
| Existing payload re-encryption | Explicit KEY_REENCRYPT transforms every covered payload and verifies it. Copied old ciphertext remains |
| Search-key/reindex generation | REINDEX changes terms and uniqueness state independently. Disabled in the initial target |
| Disable/revoke | Denies the named supported authority/provider operation. Cached bytes and offline recovery can survive |
| Scheduled destruction | Requests provider-native delayed deletion. Cancelability, disabled state, and exact observation remain visible |
| Confirmed destruction or irreversible loss | Records destroyed-as-reported or evidenced loss only within declared recovery paths. Requires separate approval and recovery tests |
| Compromise response | Contains affected writes/releases, inventories exposure, introduces approved new material/format, transforms, verifies, and retires through the same engine |

Normal `keys rotate` selects only the safe operation admitted by the configured profile.
It reports the changed layer, whether existing payloads changed, old read dependencies, and retained recovery paths.
It never destroys the old path. Destruction and incident response remain advanced explicit plans.

Exact immutable provider resource/key-version IDs select keys. Aliases are locator hints and resolve only through trusted registry admission.
Some providers hide internal material versions. Do not invent selectable version IDs that their APIs do not expose.
One authorized resolver result supplies one exact key. No multi-key trial loop repairs ambiguity.
G-CROSSKEY and Q2 decide whether the selected composition needs an additional committing construction.
Nonce-misuse resistance, authenticated headers, and exact-key syntax alone do not prove key commitment.

Incident plans distinguish broken algorithms, parser flaws, exposed KEKs, compromised payload generations, and RNG/nonce faults.
They name containment, current readable/writable sets, backup exposure, required rewrap/re-encryption, and denied or unavailable recovery paths.
Ordinary rotation cannot silently stand in for incident remediation.
Re-encryption cannot retract values or ciphertext already copied.

## 7. Key hierarchy and provider interface

```text
provider-qualified root KEK (managed custody)
  -> independently random tenant branch generations
      -> independently random wrapped subject generations
      -> independently random wrapped tenant/domain index roots
subject generation -> domain-derived field/value keys + optional subject-scoped search
separate receipt/audit signing authority
```

Registry records bind an opaque handle to an immutable tenant and subject. They also bind root and
branch generations, wrapper bytes, version, AAD, creation policy, lifecycle epoch, permitted
operations and recovery copies. Provider aliases/mutable names are not permanent key identity. Calls
occur at explicit warm, release and rewrap boundaries.

Warm field crypto and token generation remain local.

The interface wraps and unwraps branch bytes with exact context. It resolves immutable provider
resources and versions. It observes native state. It requests supported lifecycle actions with
bounded idempotent retries.

Preserve native states, configuration and time. Never collapse request success, policy deny,
scheduled deletion and observed destruction into a destroyed Boolean.

| Provider | Documented reference | Adapter obligation |
|---|---|---|
| Local development | Cryptalis-proposed synthetic provider | Fault/deterministic fixtures. No production-custody or erase claim |
| AWS KMS / Encryption SDK | [Hierarchical keyring](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/use-hierarchical-keyring.html) branch caches/native message keys. [rotation](https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html) retains old decrypt material | Pin SDK/root origin/region/identity. Native format/store is an alternative integration. Python multithreading exclusion needs its own gate |
| AWS deletion | [Scheduled deletion](https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html) wait/cancel and origin/replica/store exceptions | Observe actual native time/state, replicas/recovery stores. Local cache removal is separate. Root destruction affects all descendants |
| Google Cloud KMS | [Envelope](https://docs.cloud.google.com/kms/docs/envelope-encryption) local DEKs. [destroy/restore](https://docs.cloud.google.com/kms/docs/destroy-restore) scheduled/restorable window | Pin exact version/configured wait/import/external material/state. Infrastructure-removal commitment is not direct Cryptalis media observation |
| Vault Transit | [Overview](https://developer.hashicorp.com/vault/docs/secrets/transit), [API](https://developer.hashicorp.com/vault/api-docs/secret/transit): rotation, min-version policy, trim, delete, export/backup | Pin version/edition/mount/key. Inspect permission, trim target, exports and snapshots. Context derivation is not independent subject destruction. Policy restriction is not erase |

Wrap context contains only non-secret stable pseudonymous references and its dedicated label.
Missing or wrong AAD fails. Never omit AAD to rescue migration. Raw sensitive identifiers cannot
enter provider logs.

Exact wrapped generation is retained. Live permission, eventual consistency,
outage/throttle/cancel/audit behavior joins the profile.

Rewrap preserves the subject secret/payloads under a new branch/root. Subject rotation creates new
payload keys and requires re-encryption. Index rotation reindexes. None inherently deletes old
wrappers, keys or observations.

Per-value derivation lacks forward secrecy while its subject parent and public seed survive.

Provider receipts preserve native state plus provider, region, immutable resource/version, material origin, observation time, and evidence basis.
States include enabled, disabled, pending deletion, restorable, destroyed as reported, unavailable, and unknown.
Request acceptance is not destruction. Eventual consistency leaves reconciliation pending until current native observations support the claim.
Provider support requires one exact cell after [Q4](README.md#unresolved-research-questions) closes.
AWS, GCP, and Vault references below remain alternatives, not three first-release promises.

## 8. Cache leases, epochs and operation fences

Caches hold material in-process only. Never put plaintext or shared key material in Redis. Entry
keys include provider/resource, branch/subject handle/generation, tenant/domain, operation
permission, policy/manifest compatibility and lifecycle epoch. Capacity, bytes, TTL and leases are
bounded.

Entry existence is not authorization.

Release authority stores monotonic epochs and deny tombstones in a durable independently managed
consistency domain outside application snapshots. Issuance/deny serialize per scope. Renewal reads
current authority. Partitions cannot renew from stale state or extend TTL. Tombstone replicas cannot
use independent last-writer-wins writes. A quorum/linearizable authority or another demonstrated
ordering mechanism is required.

An initial single-authority profile names its availability and disaster-recovery limitations.

Candidate lab budgets are a maximum 60-second release lease and cache-use TTL, and a 10-second
healthy renewal attempt interval. Operation authority has a maximum of 5 seconds. Offline TTL
extension is zero. These define G-LIFECYCLE fixtures, not production defaults. A production profile
chooses and tests its own bounds.

Hour-long caching cannot support a 60-second revocation receipt.

### Initial single-process cache and authority

The first adapter uses bounded size, TTL, invocation/byte budgets, deadlines, and negative-cache duration.
Exact defaults require the selected provider/suite evidence. No duration in a future fleet experiment becomes an initial production promise.
Cache identity includes protection domain, tenant/subject scope, representation/purpose where applicable, exact key/version, and active lifecycle epoch.
Material validity and current operation authority are separate. Both must be valid before supported output or commit.

Process-wide single-flight combines loads for the same admitted identity.
Bounded retries use deadlines and jitter. Failed/denied loads use bounded negative caching without masking new authority or indefinite failure.
Cancellation resolves waiter/owner state and cannot extend a lease, duplicate quota, or publish partial values.
Authority unavailability denies new admission even with cached material. A provider outage never selects plaintext.
Suspension, restart, fork, or restored memory requires fresh admission and invalidates unsupported cached authority.
Python zeroization and recall of released plaintext remain unclaimed.

Herd/throttle/outage/cancellation/expiry/clock/revocation faults must show bounded memory, calls, and exact denial.
Cross-tenant starvation and cardinality limits need evidence for the admitted multi-tenant scope.
External budgets, fleet fairness, partitions, mixed processes, and physical-drain timing require later multi-process gates.

The protocol below describes that future acknowledged-drain profile.
It does not impose fleet machinery on the initial single-process engine or make authority expiry equal physical completion.

### 8.1 Reference acknowledged-drain protocol

The future multi-process reference profile uses one linearizable external authority per deployment, durable
registered worker/incarnation and operation records, and database transaction fences for supported
writers. This is a **proposed protocol**, not an implemented or proven 60-second completion bound.
The authority's recovery quorum/checkpoint is outside application/database snapshots. An inability
to establish that latest durable state is a deployment outage.

Restoring an older authority copy and issuing grants is forbidden. Distributed quorum replication is
an alternative G-LIFECYCLE experiment, not an assumed property of an unspecified cache.

1. While the scope is ACTIVE, register the affected operation with the external authority.

   The registration includes a unique operation ID, grant, scope, epochs, worker boot ID and
   intended output or commit boundary. It includes maximum five-second lab authority. Issuance
   serializes against deny. Cached material/leases alone permit quarantined local preparatory
   crypto, never unregistered output or commit admission.

   Explicit session execute, flush, commit or reveal preparation boundaries supply registrations and
   quotas. Synchronous wrappers wait there as declared. Async wrappers await there **before**
   entering synchronous scalar or descriptor hooks. The allowed shape, cardinality and warmed
   material must cover the whole admitted operation.

   Hooks only validate and consume local handles. A cold or exhausted handle fails. It never
   secretly makes an authority or provider call. Plaintext remains in the trusted internal quarantine until registered authenticated publication. Permit expiry is at most the minimum of
   grant expiry, material lease expiry and the five-second lab budget.

   Operations validate authority after suspension or reconnect and before the irreversible boundary.
   An expired permit prevents starting a new output/commit. Stream chunks each need bounded
   registration. Unbounded streams cannot hold perpetual authority. Registration is control-plane
   work, distinct from provider calls.
2. For protected DML, hold shared locks on the preexisting tenant and all affected fence rows.

   The affected scope rows cover subjects, indexes and migrations. The transaction retains these locks until COMMIT or ROLLBACK. Locks are acquired in canonical
   `(tenant UUID, scope-kind enum, scope UUID)` order before protected DML, and current epochs are
   read after lock acquisition. The tenant guard covers new subjects/inserts without a subject row.
   Missing guards for an existing scope fail closed. A newly authorized subject incarnation may
   install its externally approved fence while holding the preexisting tenant guard, under the
   creation protocol.

   It cannot choose an arbitrary epoch. The [ORM fence contract](orm-schema-migration.md) owns
   SQL/role coverage, schema and ambiguous-COMMIT resolution. A scalar precommit check alone is
   insufficient because deny can race COMMIT.
3. Atomically publish deny in the external authority.

   Deny linearizes there. The atomic transition persists the tombstone, increments affected epochs,
   disables new issuance and renewal, and captures all registered pre-deny operations and workers.
   Restored/new workers cannot join with old epochs. This is the deny point, **not** completion.
4. Acquire exclusive locks on those DB fences in the same canonical order.

   The coordinator acquires these locks. Existing shared-lock transactions must commit or roll back
   before the exclusive lock succeeds. Blocked/missing/ambiguous transactions leave fencing pending.
   It writes the denied/new epoch and commits before releasing locks. Later transactions read denied
   state and fail.

   This database serialization prevents a covered pre-fence transaction from committing after
   acknowledged DB fence completion. Hostile database/fence-row tampering lies outside this honest
   transactional enforcement premise and does not prove external freshness/completeness. Grants
   still depend on external authority. External deny is always durable first, so a crash before DB
   update is pending and cannot reopen issuance.

   Restored DB fence rows must be refreshed from live external authority under an exclusive tenant
   guard before application roles are admitted.
5. Drain each registered worker's affected operations and material.

   Each worker stops affected issuance and marks old operation IDs draining. It cancels unstarted
   outputs, reconciles every commit outcome, drains affected host sinks and evicts material. A
   signed/authenticated acknowledgement binds its incarnation, epoch, final operation dispositions
   and sink/transaction observations. Sink completion means final handoff of bytes or value by the
   managed host API, serializer or transport queue. The caller or network may retain or deliver
   previously handed-off plaintext later.

   For transparent entities, the managed handoff includes all decoded fields in the returned object.
   Subsequent reuse of that host-owned plaintext is outside new-release fencing. Fresh load/refresh
   or controlled reveal requires a new operation. The ORM owner defines descriptor/cache behavior.

   It is not destination receipt or downstream erasure. A check followed by suspension before API
   return is still an outstanding output operation and blocks drain.
6. Establish physical managed completion only with the required drain evidence.

   Completion requires a complete registration set and durable DB-fence observation. It also
   requires terminal drain acknowledgements for **every** pre-deny operation and worker.
   Alternatively, it requires externally verified fencing or termination of that incarnation and
   resolution of all its transactions and sinks. Unknown workers, unreachable or suspended workers,
   unknown COMMIT outcomes and unobserved sinks keep `FENCING`/`DRAINING` or `INCONCLUSIVE`.

   Wall time cannot establish their drain.

A worker acknowledgement cannot be sent while a registered affected output can still return or a
transaction outcome is unknown. Resume/VM-memory restore discards handles and registrations and
requires fresh online authority, worker incarnation and sink/DB admission. Fork children discard
inherited keys/permits. Ordinary operation cancellation releases handles but only observed physical
completion or abort resolves the registry.

Deadline expiry alone does not acknowledge completion. This protocol assumes covered honest workers
obey registration/sink boundaries. Strong protection against a compromised workload holding
transparent keys requires a separate controlled authority. An evicted cache does not constrain
copied secrets.

### 8.2 Expiry evidence and alternatives

At the lab 60-second lease/5-second operation bounds, tested suspend-aware elapsed time or mandatory
resume revalidation can establish **no newly authorized operation after expiry**. It cannot prove
that a previously started physical output/COMMIT completed or disappeared. An indefinitely suspended
process may retain bytes or later finish an already admitted action. An expiry-only receipt
therefore records `AUTHORITY_EXPIRED`, keeps physical completion pending/inconclusive, and cannot
become `COMPLETE_MANAGED` without the drain/fencing evidence above. A monotonic clock that pauses
during suspension cannot alone enforce a wall-time deadline.

Clock uncertainty blocks expiry conclusions. Control-plane time does not prove stale memory
vanished.

Alternatives are a separately serialized release gateway with no transparent keys in workload
processes, host termination plus verified sink/transaction resolution, or a weaker receipt
explicitly limited to authorization expiry. A gateway must define its own in-flight output boundary
and cannot claim downstream plaintext erasure. These alternatives retain G-LIFECYCLE/G-CONTROLLED
gates. A bounded physical completion claim requires a tested bound on drain/termination and
observation. There is no such implemented bound in Cryptalis today.

Provider outage permits prepared warm operations only within remaining material lease and explicit
offline policy while required external-authority registration is available. Provider and authority
availability are separate. Authority outage admits no new registrations/allocations. Only already
registered bounded operations follow their remaining permits, with drain unresolved until observed.
Local crypto preparation does not create a new release grant.

Cold operations fail. Tombstone authority outage cannot renew trust. Single-flight warming is per
authorized domain/epoch. Cancellation cleans waiters and never publishes partial material or extends
authority.

Fork children discard inherited handles/caches. Stampede suppression does not share grants.

## 9. Lifecycle, restoration and destruction receipts

This section describes effect observations inside the shared TransitionRecord, not another transition engine.
The seven generic phases remain the execution contract.
The drain protocol and fleet labels below require their later profile evidence. They are not initial offline prerequisites.

Track requests, authorization, record inventory, native provider observations, epochs and leases.
Also track acknowledgements, fresh and stale processes, restore and reimport, search residue and
unresolved copies. No terminal label discards those dimensions.

```text
ACTIVE -> ROTATING -> ACTIVE(new writes; finite old-read set)
ACTIVE -> DENY_PUBLISHED -> FENCING -> REVOKED
REVOKED -> SHRED_AUTHORIZED -> DRAINING -> RECORDS_REMOVED
        -> PROVIDER_PENDING / OBSERVED -> RESTORE_TESTED
        -> COMPLETE_MANAGED / COMPLETE_RECOVERY_PATHS
        -> PENDING_EXTERNAL / FAILED / INCONCLUSIVE
```

The deny tombstone is durable before destructive work. It records scope, operation, epoch, digest
and witness. No crash between removal and tombstone creation can resurrect release. Idempotency
binds the exact scope and generations.

Retries cannot broaden deletion. Tombstones survive application and database restore. The authority
checks them before key reconstruction or warming. Restored jobs and workers need new grants, new
incarnations and online revalidation.

`REVOKED` and `COMPLETE_MANAGED` require the acknowledged physical drain in section 8.1.
`AUTHORITY_EXPIRED` is a separate observation that leaves unobserved physical work pending.
Revocation reversal requires an explicitly authorized new epoch when policy permits. Shred
tombstones are permanent for a subject incarnation. Handles/IDs never recycle.

Recreating an account creates a new incarnation rather than clearing its deletion history.

Inventory covers every subject generation/wrapper, temporary migration copy, dual-index row, cache,
export and recovery location. Shared root/branch destruction for one subject requires a reviewed
collateral-impact plan. Replicas, WAL/PITR, DB/key-store dumps, provider snapshots, VM images,
queues and plaintext exports have separate treatment. Retention expiry needs evidence of actual
policy execution, not date arithmetic.

### Recovery manifest and restore admission

Cryptalis does not replace PostgreSQL backup tooling. A generated recovery manifest binds these non-secret inputs:

- Exact database/backup identity, recovery target/PITR point, and protection domain
- Binary, catalogue, manifest, descriptor, envelope, codec, and schema compatibility ranges and exact recorded pins
- Active/readable format and schema generations and transition/finalizer obligations
- Exact provider key/version references, material origin, region, and tested recovery prerequisites
- Current external active/denial/tombstone/retirement authority reference and authentication basis
- Known replicas, CDC sinks, exports, queues, snapshots, excluded copies, retention/expiry, and tested restore result

Unknown identity or missing history/key/authority evidence blocks admission.
Q1/Q4/Q5/Q7 remain unresolved selections. No guessed production DR or staging procedure follows from this schema.

Every restore begins quarantined without production application or KMS credentials.
Prefer schema from reviewed migrations and data-only loading.
Data-only loading still requires trusted target objects and inspection. It is not an automatic safe-restore certificate.
Full schema or physical restore remains quarantined until the following surface matches a trusted allowlist:

- Owners, grants, role/database settings, schemas, and effective search_path
- Extensions, functions including SECURITY DEFINER, operators, casts, triggers and event triggers
- Views/materialized views, rules, defaults/generated expressions, and RLS policies
- Publications, subscriptions, slots/CDC, replicas, and external writers
- Active compatibility, descriptor/key references, operation generations, and current denial/retirement state

`restore check` inspects without admission. `restore admit` executes RESTORE_ADMISSION through the shared engine.
Current external ActiveState, tombstones, and retirement facts dominate every restored row, wrapper, counter, and checkpoint.
Production identity connects only after reconciliation and current compatibility evidence.
PITR can resurrect old plaintext, ciphertext, wrappers, and terms. Admission enforces current managed denial, not disappearance of old bytes.
Hostile schema, missing old keys, stale authority, wrong domain, and obsolete formats require explicit repair or refusal.

Each rollback plan names the last reversible point, exact retained representation/keys, binary/readable range, expiry, and recovery procedure.
Retention defaults remain Q8. OBSERVE never implies a usable rollback path.
Deprotection retires current protected columns/terms/read formats/keys only through separate approved finalizers.
Decommission retains any declared recovery reader, backup/key dependencies, and operator-attested external inventory.
DROP COLUMN, VACUUM, uninstall, TTL, or scheduled key deletion does not establish copy sanitization.

### 9.1 Backup recovery counterexample

An old wrapped subject key S plus surviving branch B remains an offline recovery route: unwrap S
using B, then derive payload keys from public seeds. An independent live tombstone denies supported
Cryptalis release/restoration. It does not change backup bytes or constrain an attacker holding B.
Root rewrap, TTL expiry and current-row deletion do not remove this route.

Run these separate restore drills:

1. Test a supported restore with live external authority.

   It must reject tombstoned scope, old grants and jobs, migration checkpoints and restored key
   records.

2. Test isolated offline recovery with covered old wrappers and ancestors.

   Record success or failure as observed. Expected success is a surviving path. Never hide it as a
   failed managed test.

Stronger subject destruction may use independently destructible per-subject provider authority,
expiry of every recovery source, or reviewed puncturable constructions. Each is active research with
provider/call growth, retention, offline availability, fencing and backup-of-punctured-state costs.
It is not silently substituted for the scalable shared-branch baseline.

### 9.2 Search deletion profiles

searchable permits tenant/domain terms and efficient cross-subject lookup. Delete all current
subject-owned term rows. Surviving shared roots, snapshots and observations still disclose past
frequency/correlation. Payload key destruction cannot erase that leakage.

strict_shred allows either no search or subject-scoped domains only. Covered subject-key destruction
prevents new token derivation, but previously stored equal tokens still disclose historical
equality. Tenant-wide lookup needs a token per authorized subject and a separate bounded fanout
operation. Shared uniqueness/join/group/range domains are incompatible unless strict domain
isolation is explicitly abandoned.

Lifecycle labels above are Cryptalis effect substates inside TransitionRecord.
Provider-native states remain separate observations with exact identity, time, and evidence basis.
They do not create a second public state machine or active-policy authority.
Every receipt also binds the [shared transition receipt](manifest-context-api.md#plan-record-approval-and-receipt-schema), protection domain, and representation identity.

### 9.3 Receipts

Receipts contain these fields:

- Scope and incarnation, manifest and creation-policy compatibility, and key and index generations
- Request, deny, fence and completion times and observations
- Registered worker set and incarnations, leases, acknowledgements, and resolved operations,
  transactions and sinks
- Separately reported authority-expiry model
- Removed-record IDs, native provider state and time, and recovery inventory
- Managed and offline trials, index treatment, collector health and witness checkpoint
- Exceptions and signature identity

Receipts contain no plaintext, raw tokens, ciphertext bodies, credentials or keys.

COMPLETE_MANAGED requires covered fresh/stale attempts denied after its completion point. It can
coexist with known offline recovery. COMPLETE_RECOVERY_PATHS requires a complete declared recovery
graph and evidence eliminating every covered path. Unknown/recoverable copies yield pending/
inconclusive or only COMPLETE_MANAGED. Neither erases all plaintext everywhere. [NIST SP 800-88 Rev.
2](https://csrc.nist.gov/pubs/sp/800/88/r2/final) is current sanitization guidance, not
certification of application deletion.

Its [current FAQ](https://csrc.nist.gov/files/pubs/sp/800/88/r2/final/docs/sp800-88r2-faq.pdf)
includes no-prior-plaintext and key-sanitization preconditions. Encrypting an existing plaintext
table does not sanitize prior pages, WAL, snapshots or exports. Those need separate
inventory/treatment before any media-erasure comparison.

## 10. Controlled-access profile

Opaque wrappers can guard accidental serialization. The same broad workload key authority cannot
supply an independent workload-compromise boundary. Strong reveal requires a separate verifier and
release authority. It checks issuer, audience, signature, expiry, end-user identity, tenant,
subject, field, purpose, operation, replay and correlation. A request-supplied purpose is not an
attestation.

Transparent warmed branch keys must not derive controlled secrets. A controlled key wrapped only
under an already available transparent branch can be recovered by that workload regardless of the
wrapper API. Strong controlled authority needs a separate release domain or reviewed split/
identity-aware construction unavailable to broad credentials. G-CONTROLLED chooses provider, cache
and audience boundaries.

Reveal returns a bounded value to an authorized sink with a short-lived handle and redacted
synchronous event. Expiry/revocation fences output. Batch scope is explicit. Serialization remains
opaque without authorization.

The caller can still retain/log revealed plaintext. Search authority is separate. Reveal policy does
not authorize arbitrary existence-oracle token queries.

[CipherStash's split hierarchy](https://cipherstash.com/docs/security/cryptography) is documented
reference material. Proprietary seed production and vendor statements are not reproduced Cryptalis
evidence. Integration and educational study remain active alternatives.

## Research gates

These G-* identifiers own new detailed acceptance contracts. Historical P0–P10 in the [hardening
dossier](../adversarial-architecture-hardening.md) retain original meanings. All production admission gates remain **not
run**. Current bounded parser trials do not complete them. Source review/documentation checks cannot pass them.

The [playbook testing policy](../../ENGINEERING_PLAYBOOK.md#test-layers) prioritizes complete protection workflows.
Focused crypto vectors, parser fuzzing, and lifecycle state checks retain their distinct fault-detection value.
Passing unit or E2E tests alone does not prove cryptographic security or key-byte destruction.
The assurance owner supplies result vocabulary, redacted bundles and positive/negative/mutant
controls. Each report disposes the affected capability as accept, redesign, research-only, integrate
or reject.

| Gate | Experiment and predeclared acceptance | Failure / redesign |
|---|---|---|
| G-FIRST-PROVIDER (Q4) | Select one SDK/service/region/material-origin/recovery cell. Exact-key and alias-retarget, grants/eventual-consistency, disable/enable, schedule/cancel deletion, restore, import/export and outage traces. Named review, zero fictional native-state completion | No first live adapter or dependent KMS behavior before researched closure. Other providers remain alternatives |
| G-SINGLE-CACHE | One-process herd/throttle/cancel/clock/suspend/revoke trials with bounded calls/memory, separate valid material and authority, no plaintext fallback | Provider integration and bounded availability claims blocked. Fleet tests do not substitute for this cell |
| G-CRYPTO | Pin library/backend/module/platform/suite/bytes. All published primitive vectors plus 100 composed cross-process/cross-language vectors per codec/domain/version match an independent implementation. 1,000,000 bounded malformed/mutation inputs per parser/suite, all limit boundaries and forced repeated seed/nonce/fork/crash/retry/snapshot faults. Zero unauthenticated releases, unsafe allocations or ambiguous parses. Reject oversize before key/provider lookup. External composition review: zero unresolved critical/high findings. | Keep bytes/suite unfrozen. Replace format/library or constrain platform. Stress counts are not cryptographic proof. |
| G-CROSSKEY | Substitute handles/generations/suite/provider references across tenants and historical registries. Inject adversarial duplicate-key/alias records and reference-generated multi-key-valid ciphertexts where available. Zero unauthorized key registration/provider loads, exactly one permitted resolver result, no trial-key fallback or cross-domain release. Independent review must resolve whether accepted threat model requires key commitment and analyze the actual suite/composition. AAD alone is not accepted as proof. | Any accepted ciphertext resolving to multiple permitted authorities, attacker-selected key or unresolved commitment requirement blocks suite freeze. Use a reviewed committing envelope or explicitly narrower authority model. |
| G-AAD | Every one-component domain/tenant/subject/model/table/field/representation/record/purpose/generation/policy/version/header substitution. Remove/re-add replay and deliberate DR/staging clone vectors. 100 crash/retry placements per authorized rename/move/transfer. All raw relocations reject. Every committed intended value survives migration with exact original/current compatibility. Replay separate. | Redesign IDs/migration. Reject implicit whole-manifest reinterpretation. Freshness needs trusted checkpoint protocol. |
| G-EQUALITY | Pin type/Unicode/normalization/null/boundary corpus and two colliding-ID tenants. 100,000 generated values/predicates, zero semantic mismatch/cross-domain reuse, every unsupported operator rejects before SQL. Predeclare accepted domain leakage and auxiliary-frequency/chosen-query attacks. | Disable/reclassify affected domain. Secret HMAC keys do not waive inference review. |
| G-UNIQUE | 32 concurrent writers, 10,000 equivalent insert/update attempts across U-only/dual/backfill/cutover/contract, all null semantics, changed equivalence, retries and invalid indexes. Exactly one equivalent non-null value commits. Zero enforcement gap/data loss. U-only writers fenced before V backfill and remain fenced through cutover/removal. | Pause writes, accept separately reviewed stable unique domain or remove uniqueness. |
| G-SEARCH | Per join/range/text/fuzzy/JSON construction: exact paper/variant/oracle, leakage function, snapshot/transcript/auxiliary/chosen-input attackers, differential semantics, rotate/shred and independent production-review path. Exact operators: zero false negatives/semantic differences. Approximate candidates: 100% recall on pinned labeled corpus with measured precision/fanout. No generalization beyond corpus. | Isolate missing-oracle/leakage or over-budget experiment. Other research remains active. No generic search approval. |
| G-PROVIDER | Pin SDK/service configuration. Reproduce context/version/permission/outage/throttle/cancel/rotate/delete/restore/import behavior. 100 independent retry/crash schedules per transition. Zero plaintext fallback, incorrect completion or unbounded retry. | State/config unsupported or pending. Preserve native semantics. |
| G-LIFECYCLE | 3 workers on 2 hosts. Fresh/stale/suspended/restored incarnations. 10,000 model schedules plus deterministic deny/lease/commit boundaries. Proposed 60s/5s lab budgets. Zero post-physical-completion output/commit at the declared managed boundary, wrong-epoch use, TTL extension or tombstone resurrection. Separate deny, authority-expiry and physical-drain outcomes. Force suspension after check/before sink return, COMMIT ambiguity and external-authority snapshot loss. Every expiry lane includes suspend/resume clock evidence and never substitutes for unresolved drain. | Online checks/acks, tighter offline policy or weaker claim. Unknown workers/unproven suspension behavior block completion. |
| G-RESTORE | Enumerate every covered DB/key/export/VM/PITR route and generation. Independent managed-deny and offline-recovery trial per route/material origin. Zero covered managed resurrection after COMPLETE_MANAGED. Stronger completion only when every covered path eliminated with evidence. | Recoverable wrappers keep stronger claim unavailable. Unknown inventory is inconclusive. |
| G-CONTROLLED | Broad workload credential alone fails all reveal/token attempts. Verified end-user grant works only within exact audience/scope/expiry. Substitution/replay/cancel/serializer/cache/task/revoke fixtures, zero unauthorized release. Audit outage behaves as declared. | Classify as accidental-disclosure guard or choose independent release authority. No claim for already revealed plaintext. |
| G-BUDGET | Predeclare equivalent baseline, seed/payload/domain/cardinality/offered load. 10 randomized independent runs, raw distributions and 95% uncertainty. Crypto microbench target: warm provider calls=0, p95 local protected crypto/token overhead <=20%, throughput >=80% equivalent primitive baseline at fixed load, p99 added event-loop lag <=5ms, zero correctness failures/hidden retries. Measure grant/permit/budget-registry integration separately and include all costs in end-to-end reports. No hidden authority I/O. Storage/WAL/lock budgets predeclared. | Publish cost/redesign target. Never select thresholds after measurement or approve fast wrong results. |

### Open decision register

Each question below states its reason, default, alternatives, evidence, blocked claims and safe
work. The same-ID gate table above owns the exact experiment and pass/fail thresholds. A missing
required observation is INCONCLUSIVE, not acceptance. Artifact names describe future outputs, not
existing files. A violated security invariant fails regardless of aggregate performance. The
selected alternative requires a new reviewed protocol/version, never an implicit runtime fallback.

| Gate / question and why | Current default / competing alternatives | Required evidence / blocked claims and safe work |
|---|---|---|
| G-CRYPTO: which composed suite/bytes preserve authenticity and usable cost? A primitive alone is insufficient | F1/W1 with reviewed GCM-SIV library hypothesis versus GCM/XChaCha/ChaCha or library-native envelope | Future composed-vectors/parser/platform/review bundle. Suite freeze and framing CHECK blocked. DTO/parser fixture design safe |
| G-CROSSKEY: must this authority model commit to a unique key? Adversarial registration changes AEAD assumptions | Exactly one authorized registry resolution versus reviewed committing envelope or stricter independent registration authority | Future cross-key substitution/composition review. Unique-key security blocked. Registry denial fixtures safe |
| G-AAD: can legitimate moves preserve values without accepting relocation? Mutable names strand data | Stable creation descriptor/IDs versus explicitly versioned new-binding re-encryption. Externally witnessed freshness is a separate profile | Future relocation/transfer crash bundle. Move compatibility/freshness claims blocked. Authorized migration planning safe |
| G-EQUALITY: which domain normalization/leakage is acceptable? HMAC does not hide distributions | Full HMAC exact domain versus slow/truncated index with reviewed collision protocol, subject-scoped search or no search | Future vectors/query/auxiliary-attack dossier. Domain admission blocked. Synthetic normalization study safe |
| G-UNIQUE: does rotation preserve one race-safe equivalence relation? Independent generations can split enforcement | Dual-writer fence then U-authoritative V backfill versus stable independent unique domain or explicit offline write pause | Future concurrent U/V/normalization/null/collision trials. Online uniqueness rotation blocked. Conflict inventory safe |
| G-SEARCH: which advanced construction supports each named operator within accepted leakage/cost? One search label hides distinct properties | Construction-specific isolated prototype versus mature engine integration or rejecting that operator | Future per-construction oracle/leakage/attack/cost/rotation dossier. Every advanced capability blocked individually. Attributed educational study safe |
| G-PROVIDER: can the native service preserve the needed state/context/recovery meaning? Services are not interchangeable | Narrow KEK adapter versus native SDK/keyset integration or alternate provider/origin | Future native transition/config/permission/fault traces. Adapter support/destruction conclusion blocked. Local emulated fixtures safe |
| G-LIFECYCLE: can authority and physical drain be fenced under failure? Expiry is not acknowledged output completion | Single linearizable external authority plus DB locks/worker-sink drain versus quorum authority, separate release gateway or weaker expiry-only receipts | Future permits/quota/suspend/partition/commit/drain traces. Bounded completion and exact actual-use caps blocked. State-machine modeling safe |
| G-RESTORE: are all declared recovery routes gone? Surviving parent plus wrapper enables offline recovery | Managed tombstone denial with explicit surviving routes versus per-subject destruction authority, full recovery-source expiry or reviewed puncturable construction | Future inventory/managed and offline trials per route. Stronger recovery-path destruction blocked. Inventory design safe |
| G-CONTROLLED: does release narrow broad credential compromise? Local wrapper is bypassable | Separate purpose/end-user release domain versus identity-aware reviewed split authority or accident guard only | Future credential/purpose/replay/cache/serializer traces. Stronger controlled boundary blocked. Opaque-value UX safe |
| G-BUDGET: does the correct profile meet predeclared costs? Network, quota and fences can dominate | Local crypto with explicit quota/permit preparation versus per-attempt authority, native envelope integration or altered bounded deployment | Future pinned raw micro and integrated distributions including all failures/calls/storage. Performance/SLA claims blocked. Fair workload design safe |

G-BUDGET's 20%/5ms figures apply to the declared local crypto/token microbenchmark with its
equivalent primitive baseline. G-ORM-4's 25%/10ms figures apply to the declared ORM/provider latency
matrix. They are separate experiments and neither overrides the other. An integrated capability must
pass every applicable correctness gate and its own predeclared end-to-end budget including
control-plane issuance, budget reservations, network latency, DB fences and sink drain. The lab
workload/cost policy cannot be retroactively changed to hide overhead.

Initial G-SEARCH hard stress caps:

- 256 companion terms/value
- 1,000 logical IN operands (at most 2,000 physical equality-term binds for two generations)
- Two concurrent index generations
- 10,000 candidates and 16MiB candidate ciphertext per bounded logical query

Text/path amplification targets: at most 10x payload-only database bytes and 5x write/WAL cost,
reported for short/long fields separately. Hard caps reject before partial output/SQL expansion.
target failures prompt redesign or an explicit different experimental profile. These are lab
choices, not universal usability/security thresholds. Truncated candidate pagination cannot replace
correct semantics.

Every gate bundle pins source, dependencies, platform, manifest, schema and policy versions, and
corpus and seed. It also pins worker and provider observations, redacted raw results and
uncertainty, collectors, controls, reviewer and disposition. Primitive vectors, composed protocol
checks, inference attacks, correctness and latency answer different questions. No PASS until the
builder manually implements and executes the experiment.

Document publication alone does not change any tracker item to verified.
