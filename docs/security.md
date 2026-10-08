# Security and leakage

**SPECIFIED:** security contract, not an audit. [Status](status.md) owns executable evidence.
IMPLEMENTED has the exact boundary in status. Protection runtime remains isolated spike code.
VERIFIED means only the named recorded checks. All unlabelled requirements below are SPECIFIED.
The selected scope is text storage, equality/IN, and tenant-scoped uniqueness with application-assigned keys.
Advanced search representations and shared joins are INTERNAL ONLY and remain UNSUPPORTED BY DESIGN as public capabilities until admission.
The trusted application transforms protected plaintext before PostgreSQL receives it through an admitted path.
Payload confidentiality depends on uncompromised application and key authority, qualified cryptography, and the declared leakage boundary.

## Current local enforcement evidence: 2026-10-07

**VERIFIED, recorded spike revision:** the [integrated checkpoint](status.md#current-integrated-checkpoint-2026-10-07) guards inspected SQLAlchemy executions at the DBAPI method boundary.
Its raw/COPY/protocol-handle denials occur before driver execution; an independent privileged connection remains outside that boundary.
Missing, unknown or unexcluded writer inventory blocks local transformation. The migrator-owned fixture does not qualify a non-owning runtime role.
A hostile returned row that is valid for another identity fails the captured host-requested point check before value release.
The recorded candidate also rejects changed typed field/domain/tenant/record context, descriptor/header mutations, malformed bounds and retired generations without fallback.
Same-context replay, SQL-NULL presence substitution and omitted rows remain the threat limits below.

New development roots and the local wrapping key are random and memory-only; the older experiments retain public lab roots.
Local cold/warm/expired/outage and rewrap tests are functional evidence only. They do not qualify fork invalidation, independent-process recovery,
remote-provider cancellation, native deletion or production custody. No production provider or deployment procedure has been designated.
Independent human cryptographic/security review is unavailable: `external-review-required` remains UNKNOWN.
Frozen independent admitted text/ID vectors, exact collation evidence, and nonce/usage bounds remain required before security qualification.

## Trust boundaries

| Boundary | Assumption and control |
|---|---|
| Host to adapter | The host authenticates users, authorizes access, and supplies the correct tenant scope |
| Adapter to PostgreSQL | Only ciphertext and declared keyed representations cross admitted writes. Runtime roles cannot replace schema or lifecycle policy |
| PostgreSQL to adapter | Bounded framing, expected context, exact admitted key, AEAD, codec, and companion verification precede value release |
| Adapter to key provider | Workload identity, pinned provider/key identity, exact wrapping context, bounded retries, and memory-only cached material |
| Database restore to deployment | The restored database cannot replace the current externally pinned policy or authorize itself |
| Operator to transition | Inspected target, semantic diff, writer stop, plaintext exposure approval, full verification, and explicit destructive disposition |

The attacker can know source, manifest, algorithms, schema, normalization, ciphertext format, dumps, indexes, and backups.
Confidentiality does not depend on hiding these facts.
The attacker lacks secret roots, provider decrypt authority, host plaintext, and authorized query-oracle access unless a scenario states otherwise.
Chosen inserts, repeated queries, and auxiliary distributions remain important leakage attacks even without key compromise.

## Threat limits

| Threat | Boundary |
|---|---|
| Stolen finalized dump or read-only DBA | Randomized payloads hide value bytes without keys. Search, length, presence, row linkage, and historical plaintext remain exposed |
| Returned bit tamper or cross-field/tenant/record relocation | Context-bound AEAD rejects before that value becomes available |
| Same-context historical replay | Not prevented. AEAD supplies authenticity, not current-row freshness |
| Hostile omitted rows or corrupted unreturned search terms | Not prevented by returned-row authentication. No completeness or adversarial global-uniqueness claim |
| Nullable field replaced with SQL NULL | Presence is not authenticated in the selected default. Required presence needs a separately qualified authenticated-null profile |
| Application compromise/RCE, broken authorization, host plaintext logs/caches/exports | Outside confidentiality boundary. The process legitimately holds plaintext and cached material |
| Key/provider/workload credential compromise | Can recover permitted roots. Least privilege reduces scope but cannot save those values |
| Raw/alternate writers | The intended guarded paths must reject. Complete prototype coverage is unproved. Unknown separate writers block adoption. Schema checks cannot cryptographically certify arbitrary bytes |
| Old deployment or database restore | The intended current deployment pin must block recognized stale generations. Only a policy model ran. Operator quarantine and worker termination remain required |
| Invisible RAM clone or immediate arbitrary-process revocation | Outside the claim. Cache expiry does not recall plaintext or copied keys |
| Plaintext in pre-protection WAL/backups/logs | Remains exposed until its actual custody/retention disposition |

The new design deliberately removes the former distributed instantaneous-denial protocol.
It promises controlled deployment changes and explicit maintenance, not cryptographic recall of previously released data.
No subject-erasure guarantee follows from row deletion, policy denial, or deleting a current wrapped root.

## Key hierarchy and providers

Use two independent random 32-byte roots per tenant/domain key generation:

```text
external provider KEK
  ├── wrapped payload root
  │     └── HKDF payload key for each stable field/record context
  └── wrapped search root
        └── HKDF key for each declared capability/search domain
```

The independent search root permits payload rotation without reindex and explicit search rotation when required.
Shared equality joins are INTERNAL ONLY research. They need a common search-domain identity and identical codec/normalizer before admission.
Other fields and tenants derive different keys. There is no universal global token key.

The internal provider contract is `wrap(root, context)`, `unwrap(wrapper, context)`, and `rewrap(wrapper, new_provider, context)`.
The wrapper records pinned provider identity and nonsecret scope, purpose, root identity, and generation.
The deployment policy selects the exact wrapper. Envelope headers cannot choose provider URLs, credentials, or arbitrary keys.
AWS KMS, Vault Transit, and GCP KMS have relevant envelope/rewrap APIs, but each adapter needs its own custody and failure evidence.
Only a local stand-in ran in the new experiments. None is production-qualified.

Production KEKs normally remain outside PostgreSQL. Generated public wrapper/policy artifacts remain under deployment integrity controls.
A development file/environment key is allowed only in an explicit local profile with reduced guarantees.
It cannot be selected by a production manifest downgrade.
No secret root appears in the public manifest, diagnostic output, database functions, or query terms.

Preload the finite admitted generations for the operation's tenant, not every tenant at application startup.
Cache unwrapped roots only in process memory, with a maximum age and no refresh-on-access.
Invalidate inherited caches/clients after fork. No Redis or persisted raw-key cache is required.
A cold or expired key fails when the provider is unavailable. A warm admitted key can operate until its configured expiry.
Provider disable/deletion does not instantly invalidate existing cached keys.
The operator must stop/drain or restart affected workers before declaring no further managed use.
Async preparation awaits remote work outside synchronous SQLAlchemy hooks.
Cancellation discards late material and reports actual transaction ambiguity rather than assuming rollback.

The policy bundle is the minimum non-restored metadata: active lock/target pin, admitted generations, and wrapped-root identities.
Its integrity comes from the existing trusted deployment system. It is not a signed hash-chain freshness invention.
Current subject denial remains in the host's existing authoritative authorization system when required across database restore.
A deployment with no independent current authorization cannot claim restore-resistant subject revocation.

## Cryptographic format

The selected candidate profile uses library AES-256-GCM-SIV, HKDF-SHA-256, and full HMAC-SHA-256 terms.
VERIFIED, recorded primitive probe: cryptography 50.0.2 supplies native AES-GCM-SIV support.
It reduces accidental nonce-reuse harm but does not permit fixed runtime nonces or remove usage-bound review.
AES-GCM requires stronger nonce uniqueness discipline. ChaCha20-Poly1305 also requires nonce discipline.
Extended-nonce libraries can be alternatives after portability and review. No silent algorithm fallback is allowed.
Primary algorithm and library evidence is in [prior art](prior-art.md).

CF1 payload framing:

| Byte field | Exact encoding |
|---|---|
| Magic | Four bytes `43 46 31 00` |
| Suite | One byte, value 1 for the selected AEAD/KDF profile |
| Flags | One byte. Bit 0 means packed equality term. Bit 1 adds a companion commitment. Bits 2–7 reject |
| Payload generation | Four-byte unsigned big-endian integer, nonzero |
| Search generation | Four-byte unsigned big-endian integer. Zero without search |
| Packed equality term | Exactly 32 bytes when flag 0 is set. Otherwise absent |
| Companion commitment | Exactly 32 bytes when flag 1 is set. Otherwise absent |
| Nonce | Exactly 12 bytes from the operating-system cryptographic RNG |
| Sealed payload | Encoded bytes plus the full 16-byte AEAD tag. Remaining frame bytes |

Reject unknown suite/flags/generations, short/trailing malformed data, and values beyond the qualified field bound.
NULL is SQL NULL, not a zero-byte encrypted value. Empty text remains an authenticated non-null payload.
Storage-only overhead is 42 bytes. Packed equality overhead is 74 bytes, before SQL tuple/index costs.
A companion commitment adds 32 bytes. Derived arrays add their own SQL storage.
The product implements storage-only and packed equality frames. It rejects the companion flag and all advanced representations.
Independent product vectors cover both formats and both admitted record and tenant codecs. Companion vectors remain unqualified.
The first adapter spike uses a different small lab frame. Its success does not verify CF1.
The offline CF1 text fixture passes 30 framing/context/rotation mutation checks. Same-library roundtrips do not qualify independent AEAD vectors or the generic composition.

Define `T(parts)` as a four-byte unsigned big-endian component count, followed by four-byte byte lengths and exact component bytes.
Generation arguments use four-byte unsigned big-endian integers. Domain, tenant, field, root, and search-domain identities use immutable 16-byte IDs.
Codec and normalizer IDs are frozen UTF-8 names. The descriptor digest uses SHA-256.
For the search root, `search_salt` uses the same salt formula with its own root ID and generation.
Strings use strict UTF-8 and stable IDs use 16 bytes. A bigint record ID uses `T("int64", signed_eight_byte_big_endian_value)`.
Other integer/record codecs require their own immutable typed identities.
No `repr`, delimiter concatenation, implicit Unicode normalization, or mutable SQL name enters cryptographic encoding.

```text
salt = SHA256(T("CF1/root", domain_id, tenant_id, root_id, generation))
payload_key = HKDF-SHA256(payload_root, salt,
    info=T("CF1/payload-key", field_id, typed_record_id), length=32)
aad = T("CF1/payload", domain_id, tenant_id, field_id,
        typed_record_id, immutable_codec_descriptor_digest, complete_header)
search_key = HKDF-SHA256(search_root, search_salt,
    info=T("CF1/search-key", search_domain_id, codec_id, normalizer_id, capability), length=32)
term = HMAC-SHA256(search_key, T(capability, canonical_value_or_node))
```

The descriptor pins type, codec, null policy, representation identity, and context encoding.
It excludes mutable table/column names and unrelated manifest edits.
Define the companion commitment as SHA-256 of `T("CF1/companions", entries...)`.
Each entry is `T(capability_id, representation_id, T(sorted_unique_full_terms))`.
Sort entries by capability ID as bytes. Reject duplicates and terms that are not 32 bytes.
The complete header ends after the optional commitment. AAD includes every header byte, including generations and packed term.
The payload processor receives projected companion arrays and verifies their commitment before release.
Adding/removing a capability or rotating search terms therefore requires a fresh nonce and payload reseal, even when its payload key stays unchanged.
The offline text fixture tests the commitment and reseal behavior with public roots.
The service lifecycle lab now reads actual projected arrays and rejects changed/missing/malformed companions before full verification can succeed.
Independent vectors and a complete advanced-field ORM projection remain unqualified.
Expected context comes from the host/mapping and generated row projection, not ciphertext-supplied authority.
Per-record key derivation limits repeated use of one payload key. It does not establish a reviewed aggregate lifetime bound by itself.
No quantified security bound or approved key-retirement threshold exists yet.
Independent review must settle those bounds before real-data admission. The former distributed quota service is not retained by assumption.

### Implemented CF1 primitives and local custody

`cryptalis.crypto` exports `FieldDescriptor`, `seal_text`, `open_text`, `KeyProvider`,
`DevelopmentKeyProvider`, `create_root`, `KeyContext`, `KeyPolicy`, and `Keyring`.
`FieldDescriptor.from_compiled(document, digest)` consumes one trusted compiler descriptor.
A matching digest checks structure. It does not authenticate the deployment policy.
Seal and open take the descriptor, expected tenant and record, and prepared keys.
They encode exact UTF-8 text without NUL and refuse encoded values above **16 MiB**.
Empty text uses an authenticated frame. SQL NULL remains SQL NULL.
Nil UUIDs are valid native tenant and record values. Single-tenant context equals the stable table UUID.

Each keyring pins one immutable policy for one domain and tenant.
The policy admits at most **32 wrapped roots** and selects active write generations.
Frame generations select only already prepared keys. They cannot select provider authority or cause network calls.
`prepare()` and `prepare_async()` return keys for an operation.
The cache defaults to **60 seconds** and permits a maximum of **300 seconds**.
Access does not extend expiry. Each crypto operation checks expiry before it returns a value.
These operational limits are prototype safeguards. They are not reviewed cryptographic usage limits.

`create_root(provider, context)` uses independent operating-system randomness.
Wrapped roots carry exact provider identity, domain, tenant, purpose, root identity, and generation.
Provider payloads are opaque bytes with a **64 KiB** limit.
The development wrapper binds this metadata with AES-256-GCM-SIV and a fresh 12-byte nonce.
Its sealed bytes contain the nonce and a 32-byte root with a full 16-byte tag.
It retains the local key-encryption key only in memory. Process loss prevents recovery.
Local `rewrap` preserves the root and creates a wrapper under the replacement provider.
This does not implement a deployment rotation workflow.

Sync and async preparation publish keys only after every required root passes checks.
Cancellation rejects late provider material, including when a provider suppresses cancellation.
Inherited providers, keyrings, and prepared keys refuse use after fork.
The child must construct a fresh provider and prepare fresh roots.
Python immutable bytes do not give a verified zeroization guarantee.
Failures have safe codes, operation IDs, stages, retry indicators, effect states, and remedies.
Raw provider and cryptographic exception text does not enter those diagnostics.
The [slice 2 checkpoint](status.md#slice-2-checkpoint-2026-10-08) records the exact evidence boundary.

Full-width terms avoid intentional false positives. Exact query claims remain conditional on HMAC collision resistance and intact indexed representations.
Recomputing a term from returned plaintext does not detect a collision with a different value. AEAD cannot repair that semantic error.
No collision detector exists in the small prototype. Do not promise unconditional collision-free queries.
A UNIQUE token conflict fails the write, but does not by itself classify equal values versus a collision.
Human review must accept the computational assumption or require explicit original-predicate validation before capability admission.
Such validation must fail on a mismatch. Hidden filtering and incomplete pagination are forbidden.
A token match never authorizes data access. A UNIQUE conflict leaks membership and requires host authorization and rate limits.
No key-commitment guarantee is claimed. Exact-key resolution and cross-key attacks need human review.

## Capability leakage

Storage/equality/IN/tenant-uniqueness leakage below is the accepted SPECIFIED boundary.
Advanced representations add no accepted public capability or leakage opt-in until [six-gate admission](compatibility.md#capability-admission).

| Representation | What PostgreSQL can learn |
|---|---|
| Storage only | Row linkage, ciphertext length, presence/NULL, write timing, access, and result volumes |
| Equality and IN | Also equal-value classes, frequencies, repeated queries, and queried membership sets within the tenant/domain |
| Tenant-scoped uniqueness | Also existence/membership from uniqueness conflicts within that tenant |
| Shared equality join, INTERNAL ONLY | Also linkage between the explicitly shared fields/tables |
| Tree range, INTERNAL ONLY | Also node membership, frequency, ancestor/intersection relationships, query covers, and structure/access/volume patterns. Known bounds or queries can label ranges |
| Native-order OPE candidate, INTERNAL ONLY | Also complete relative order and equality. Auxiliary distributions and sorting can recover values. Construction-specific leakage needs review |
| Prefix, INTERNAL ONLY | Also shared prefix membership, length through term count, prefix relationships, query repetition, and chosen-input labels |
| Text token candidate, INTERNAL ONLY | Also word/token relationships and frequency. Positions/ranking require further representations and leakage |

A static keyed tree is not MongoDB's full structured-encryption protocol or a forward/backward-private SSE scheme.
It has no ORAM/PIR or opaque-field claim. No home-grown primitive is introduced, but the composition still requires expert review.
The measured frequency attack on 100,000 synthetic skewed names recovered 100% of classes and rows using an independent auxiliary sample.
This is a realistic-shaped synthetic control, not a customer recovery-rate estimate.
The same frequency technique recovered 100% of rows/classes from complete prefix-array signatures.
It recovered 27.211% of rows and 33.333% of classes from range-array signatures over synthetic clipped ages.
The attacker sees arrays and independently sampled auxiliary frequencies, not the secret key.
Range-structure and prefix-specific published attacks remain unexecuted. None of these rates predicts a customer distribution.
`plan` must show that absence and block advanced-capability apply until the required attack evidence exists.
An acknowledgment alone cannot convert missing security evidence to PASS.
G-PROVIDER, G-POLICY, and independent review requirements remain UNKNOWN. No local provider/policy check qualifies production custody or publication.

## Public failure contract

Failures expose an operation ID, stage, safe code, retry class, durable progress, and a concrete remedy.
They do not expose plaintext, key bytes, ciphertext bodies, terms, SQL binds, or raw provider exception text.
Engine defaults use `echo=False` and `hide_parameters=True`. Host logging remains a separate trusted responsibility.

| Condition | Required result |
|---|---|
| Missing or expired key | `KeyUnavailable`, no plaintext fallback |
| Unsupported query/mapping/writer | `UnsupportedProtectedOperation`, reject the affected path before admitted plaintext SQL |
| Wrong context or invalid tag | `AuthenticationFailed`, no unauthenticated value |
| Payload/companion mismatch | `RepresentationMismatch`, fail the operation rather than filter candidates |
| Stale deployment/manifest | `PolicyMismatch`, no automatic activation from database state |
| Failed/incomplete verification | `TransitionIncomplete`, no switch |
| Lost COMMIT/provider reply | Explicit UNKNOWN/PENDING. Inspect the original action before retry |
| Missing required observation | UNKNOWN, never PASS |

CLI exit 0 means complete requested success. Invalid/denied input returns 2, incomplete/UNKNOWN returns 3, and operational/output failure returns 4.
Successful plan output is a proposal, not applied protection.
Report existing effects if cleanup or output also fails. Nothing security-critical may fail silently.

## Human review

Review the implemented codec/frame/KDF/AAD/search composition, usage bounds, provider identity, raw-writer boundary, and restore/erasure claims.
Also review ORM semantics, migration interruption, and package-free removal.
AI council review is first-party criticism. It does not replace an independent cryptographer or production evidence.
The [release gate](../ENGINEERING_PLAYBOOK.md#release-gate) remains mandatory.
