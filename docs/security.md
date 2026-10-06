# Security design and threat model

Status: DESIGNED. This is the canonical security owner, not a cryptographic audit.
Current executable controls are limited to the [status inventory](status.md). All runtime controls below require their named build gates.

## Scope and assumptions

The intended deployment is a trusted Python application with attached SQLAlchemy sessions, AWS RDS PostgreSQL, AWS workload identity,
AWS KMS root custody, a separate regional DynamoDB authority table and an independently administered S3 receipt journal. These are chosen product constraints, not observed deployment facts.
The host supplies authentication and authorization. Cryptalis supplies no login, authorization service, or independent plaintext release gateway.
The application process and release pipeline can access plaintext and locally unwrapped material. Their compromise defeats the core boundary.
Production support remains blocked on executable evidence and independent human review.

The current repository has local file parsers and CLI input/output, private structural records, and synthetic tests/examples.
It has no database, remote key provider, external authority, or protected ORM implementation.
Evidence anchors are [parser](../src/cryptalis/manifest/parser.py), [CLI](../src/cryptalis/cli.py),
[private authority](../src/cryptalis/contracts/development_authority.py), and [synthetic demo](../examples/demo_smolink_crypto.py).
No planned component is presented as a deployed control.

The attacker can possess backend/Cryptalis source, manifest and lock, schema, algorithms, ciphertext formats, database dumps,
snapshots, backups and searchable terms. Configuration confidentiality is unnecessary.
Assume the attacker lacks current external key authority, host plaintext, unwrapped key copies, and permitted query-oracle access unless stated otherwise.
Search leakage can still identify values without key recovery. The guarantee is computational confidentiality subject to the declared leakage.
It is not a guarantee that every protected field remains semantically unknown.

## Assets, entry points and trust boundaries

| Asset | Objective |
|---|---|
| Field values and payload/search roots | Confidentiality before database persistence and after authenticated release only |
| Active digest, epochs, key registry, tombstones and destructive-operation record | Integrity and restore resistance within the external authority boundary |
| Ciphertext context and query terms | Detect returned tampering/relocation and inconsistent indexes |
| Recovery data, keys, readers and operation journals | Availability and truthful rollback/removal/destruction state |
| Package artifacts and dependencies | Authenticated origin and reviewable contents, with independent correctness evidence |

| Edge | Data/channel | Required boundary check |
|---|---|---|
| Host -> attached session | Python values, expressions, host-issued grant | One tenant, authentic issuer/audience/actions/expiry, resource scope, supported query tree |
| Session -> PostgreSQL | TLS, ciphertext, equality terms, public IDs | Exact target, active schema/fence, atomic row representations, least-privilege role |
| PostgreSQL -> session | Untrusted bounded rows and wrapping blobs | Framing bounds, admitted descriptor/generation, expected identity, AEAD, codec and term verification |
| Session -> KMS | Authenticated AWS SDK request, exact resource/context | Workload identity, pinned ARN/origin/Region, least privilege and current local admission |
| Session/lifecycle -> authority | AWS authenticated current transaction read / conditional write | Pinned table identity, current revision, deny/operation state and finite compatibility |
| Operator -> CLI/engine | Plan, action, scope and explicit approval | Current operator grant, target/digest binding, expiry, inspected actual effects |
| File/DB/provider -> diagnostic sink | Bounded result/error record | Fixed safe fields and redaction, observed output success, no secret payloads |
| Source/build -> distributed wheel | Protected CI and PyPI publication | Locked artifacts, origin/provenance checks and clean-artifact inspection |

Untrusted entry points include JSON bytes, local files, envelope headers, wrapping blobs, DB rows, expression parameters, plan files,
provider responses, restore inputs, and dependency artifacts. The manifest cannot request imports or key-provider URLs.
Current parser limits protect local parsing only. They do not prove runtime authentication.

## Adversary matrix

Ratings describe the chosen runtime design after its gates pass, not today's package.
`STOPPED` is conditional on its stated assumptions. `PARTIALLY MITIGATED` must not be marketed as prevention.

| Threat | State | Reason and remaining exposure |
|---|---|---|
| Stolen pg_dump, snapshot or backup after finalization | PARTIALLY MITIGATED | Payload confidentiality holds without external keys. Search/IDs/lengths leak. Historical plaintext backups remain plaintext |
| Curious DBA or cloud DB read access | PARTIALLY MITIGATED | DB has no payload roots. Live query and access observation adds leakage |
| Database write attacker | PARTIALLY MITIGATED | Returned ciphertext authentication detects tampering. Deletion, omission, same-context replay, NULL substitution and DoS remain |
| Ciphertext bit tampering or corrupted envelope | STOPPED | Bound parsing, exact context and full AEAD tag reject before value release |
| Ciphertext relocation, wrong field/record, cross-tenant substitution | STOPPED | Expected immutable typed identity and incarnation bind authenticated context. Authorized host mapping remains trusted |
| Same-context old authentic ciphertext replay | NOT STOPPED | No external per-row freshness service. Current-generation authentic old value may authenticate |
| SQL injection | PARTIALLY MITIGATED | Cryptalis does not prevent injection. Direct extraction returns ciphertext, but application query oracles/host execution can expose plaintext |
| Raw SQL, Core, bulk update and COPY | PARTIALLY MITIGATED | Mediated paths reject. Removed logical columns and shape constraints reject ordinary raw plaintext. Forged frames or privileged bypass require inspection |
| ETL and alternate workers | PARTIALLY MITIGATED | Required writer inventory/roles/doctor gates. Unknown coverage blocks adoption, not a universal enforcement promise |
| CDC/Debezium and writable logical replicas | PARTIALLY MITIGATED | Production profile rejects this topology. Historical plaintext/downstream copies remain external obligations |
| Migration scripts | PARTIALLY MITIGATED | Separate principal, reviewed plan, fence and full verification. Arbitrary owner SQL outside protocol remains possible |
| Compromised application/RCE, malicious authorized code | NOT STOPPED | Plaintext and cached roots exist inside trusted process |
| Broken authorization, IDOR or business logic | NOT STOPPED | Legitimate decrypt privilege does not establish correct host authorization |
| Stolen KMS/workload credentials | NOT STOPPED | Permitted credentials plus registry/wrappers may recover data. Scope constraints limit blast radius but do not save authorized roots |
| KMS/Vault/HSM authority compromise | NOT STOPPED | External key authority is a trust root. Vault/HSM integrations are not part of the supported profile |
| Provider outage or throttling | PARTIALLY MITIGATED | Bounded retries and currently authorized cached material. Cold or expired material denies. Availability is lost |
| Old application binary/stale worker | PARTIALLY MITIGATED | External binary/protocol admission and DB fence reject stale writes. Unobserved rogue clients remain gaps |
| Restored old database | PARTIALLY MITIGATED | New target is quarantined, current authority dominates restored checkpoints, denies survive. Same-context replay remains outside claim |
| Restored old VM/cache | PARTIALLY MITIGATED | Workload restart, fresh external admission, no persisted key cache. Invisible arbitrary RAM cloning and already released values are unsupported |
| Malicious dependency or release-pipeline compromise | PARTIALLY MITIGATED | Artifact/identity/release controls reduce risk. Trusted malicious code can steal plaintext and roots |
| Host plaintext logging, post-decrypt export or legitimate API plaintext response | NOT STOPPED | Transparent values belong to host application. Cryptalis diagnostics are separately constrained |

## Manifest integrity

The manifest needs integrity, not secrecy. Runtime compares canonical compiled bytes with the current externally pinned digest.
Changes to declarations cannot automatically activate weaker policy, remove a search constraint, permit a new writer or retire a reader.
The compiler produces a total semantic diff. Every change is either no-data metadata, additive storage, verified transformation,
security weakening/plaintext publication, destructive retirement, or explicit rejection.
`protect:false`, deletion of a protected field, changed scope/normalizer, and profile changes appear visibly in that diff.
The runtime retains the admitted lock until an authorized transition finishes. Missing active declarations fail startup rather than bypass protection.

Only a separate operator role can approve active-digest changes. Source review and a protected deployment gate review the exact diff.
Runtime credentials cannot approve a transition, delete tombstones, restore authority, or weaken allowed profiles.
Plan digest/action/target/expiry are pinned in external operation state. Editable plan JSON has no authority by itself.
No custom manifest-signing service is required because authenticated external pinning supplies the integrity root.
A signer/provenance record proves bytes and issuer within its trust chain, not source safety or measurement truth.
Compromise of the authorized operator, deployment gate, external authority or host remains outside this protection.

## External authority

One regional DynamoDB base table owns current policy, domain/tenant epochs, pinned compiled-lock digest,
admitted binaries/readers/writer protocol, target incarnations, root registry, usage reservations,
permanent denials, worker incarnations and durable mutation/effect ownership. Pin account, Region, ARN and creation identity.
Use `TransactGetItems` and conditional `TransactWriteItems`, within 100 items/4 MiB. GSIs and streams never authorize.
Larger reads bracket strongly consistent pages with domain AND tenant epoch reads. Each relevant change advances its epoch atomically.
Usage revisions are separate. Changed epochs restart bounded preparation or deny. An unbracketed page set is not a snapshot.
There is one domain lifecycle owner. Multi-region authority, automatic region failover and TTL tombstones are excluded.

### Admission and fencing

The PostgreSQL fence is one nonnegative monotonic token per domain, with a shared row lock for ordinary transactions
and exclusive lock for lifecycle changes. Its row is writable only by the lifecycle role.
Normal protected DML also checks the supplied token against that row inside PostgreSQL, under the shared lock.
The selected implementation must enforce this for INSERT, UPDATE and DELETE with reviewed triggers or guarded database functions;
zero affected rows caused by a token mismatch is `StaleFence`, never success. A process-only comparison is insufficient.
RDS target identity and fence generation must match current authority. A restored row does not authorize its old token.

1. Register a fresh workload-authenticated worker incarnation by conditional authority write before any protected operation.
   Registration is denied during domain maintenance or denial. It records the exact target, binary and owning deployment.
   A heartbeat may identify suspected loss. Expiry never removes ownership or proves termination.
2. Start the DB transaction, acquire its shared fence, then read current external admission. Compare exact token, target,
   grant, scope, descriptors and epochs. Acquire no permit before this fence. Prepare roots and quotas only within that admission.
3. For a mutation, conditionally register an immutable operation UUID, worker incarnation, token, target, request digest,
   transaction UUID and original backend/xid8 fingerprint in authority before its first protected DML. Each later explicit flush
   batch uses a new operation UUID/digest in that same transaction; registration rechecks denial and epochs.
   A read uses the durable worker registration and local in-flight count. It needs no per-read remote registration write.
4. Fetch/transform only under the same transaction and fence. Before buffer publication or COMMIT, read current authority again.
   A pre-denial admitted operation may finish while denial is PENDING if its original token/ownership remains valid.
   A changed generation, expired grant or lost fence denies handoff/new DML. Never reconnect and reuse that permit.
5. Reads keep the fence and worker ownership through complete logical handoff. Mutations write the outcome record atomically
   with all row effects, hold the fence through COMMIT, and retain external operation ownership through terminal reconciliation.
   After a known outcome, conditionally close the mutation record. A lost response does not close it.

The trusted worker tracks all publishable buffers and commits. A drain acknowledgement atomically closes its admission
before asserting zero outstanding buffers/operations and invalidated handles. The authority validates incarnation and drain epoch.
A stopped worker needs independently observed termination plus resolution of every registered mutation/backend.
An empty DB connection list, lost shared lock, client cancellation, heartbeat timeout or lease expiry is insufficient.
Connection/backend identity includes target incarnation, backend PID/start time and server incarnation; PID alone can be reused.
Failover or unprovable backend identity leaves pending outcomes UNKNOWN until the actual writer lineage is established.

Revocation first sets PENDING denial by conditional authority write, blocking new registrations/admissions.
Then all affected domain workers drain or are proven terminal, mutations reconcile, and the lifecycle owner takes the exclusive fence.
It advances the DB token and external epoch through journaled steps while admission remains denied.
Only inspected agreement of target/token/head, complete worker drain and terminal mutations permits managed completion.
This pauses the domain even for a smaller selected data scope. Already returned Python plaintext cannot be recalled.
Invisible memory clones, rogue privileged writers and a compromised host remain outside this model.

### External effects and ownership

Separate runtime, transition, key-administration, journal-custody and break-glass principals enforce these roles.
Runtime cannot replace the table, clear denial, alter the fence or write the recovery archive.
One independently administered same-region S3 bucket stores exact immutable intent/effect versions.
Pin owner/account, Region, bucket identity, VersionId and byte digest. Require COMPLIANCE Object Lock retention for 100 years,
extended before expiry while recovery depends on it. Ordinary principals cannot shorten retention or delete versions.
Finite retained custody is not eternal history, keys or destruction proof.

Before an irreversible effect, the current owner conditionally reserves the operation/action ID, monotonic owner token,
sequence and predecessor digest. This reservation denies new affected admission. Write and read back the full immutable intent
and exact retention before conditionally committing the permanent denial/epoch and archive reference.
Only then drain, acquire the exclusive DB fence and dispatch the reserved effect. Each chunk/switch validates owner/token
in authority CAS and in its data-and-marker DB transaction. Stale owner CAS and DB tokens reject.

AWS KMS/S3 APIs do not accept a Cryptalis fencing token. Do not claim they reject a custom stale token.
Instead, a reserved external action has one immutable dispatcher. Record DISPATCHING before the call.
No lease expiry, timeout or lost reply permits another owner to dispatch, cancel or replace that unresolved action.
Transfer requires proven old-dispatcher termination, terminal DB transactions, native postcondition inspection and reconciliation
of every in-flight external request. A request that may still run keeps the action PENDING even after its client dies.
An action whose postcondition cannot be established stays INCONCLUSIVE. Repeat only when native idempotency or inspected state proves it safe.
SDK request-token windows are not durable identity. Resumption uses the original action ID and immutable proposal.
This sacrifices availability rather than pretending a local token fences an AWS API.

Archive failure blocks new irreversible effects. Lost archive acknowledgement resolves the original exact version or stays denied.
An archived orphan intent is conservative denial during recovery. Completion requires observed native/catalog/row postconditions
and a conditional effect receipt; DB and DynamoDB never have a cross-service atomic commit.
Recovery validates complete version history, sequence/predecessor links, orphan intents, custody and stopped owners.
A retained hash-chain prefix cannot establish latestness. Missing/unprovable current history permanently denies the affected old domain.
Replacing/restoring the table creates another identity and cannot reactivate it. Region loss is an availability failure.

| Failure boundary | Required state and remedy | Invariant |
|---|---|---|
| Denial races admission | Reject new operation. Admitted operation drains under its original fence | No post-completion new release |
| Shared lock/backend lost with live worker | Stop new DML/handoff, retain worker/mutation ownership, reconcile | Lock loss is not worker termination |
| Expired lifecycle lease / stale owner | No takeover of unresolved action; CAS and DB token reject stale effects | One dispatcher per action |
| Response lost after external dispatch | PENDING. Inspect exact native resource/action before retry | No guessed rollback or duplicate effect |
| Authority or archive unavailable | Deny dependent work, retain ownership and known effects | Warm keys cannot authorize |
| Unknown owner/backend/receipt history | UNKNOWN/INCONCLUSIVE, recovery command requires evidence | Missing evidence cannot grant permission |

### Control-plane footprint

AWS-only is retained: one KMS KEK per domain, one regional authority table shared across domains, and one independent receipt bucket.
No always-running Cryptalis service, queue, scheduler, S3 write per ordinary request, custom KMS or freshness service is required.
A small internal provider contract exposes current admission, conditional ownership/quota, exact-root unwrap and retained receipt inspection.
The designed contract selects one AWS production implementation, unimplemented today.
The fake local implementation is test-only and cannot select production admission.
Collapsing authority into restored PostgreSQL loses non-restored denial. Collapsing independent receipts into the mutable authority
loses conservative recovery inventory after authority identity loss. KMS alone cannot store current lifecycle/worker state.
Removing receipts is a different product with permanent loss on every authority failure. It is not a fallback.

For a hot single-tenant operation fitting one authority batch: a read uses two transaction reads;
a mutation uses those two reads plus registration and closure transaction writes. Each uncached root adds one KMS Decrypt.
Encryption adds amortized quota reservations per root/batch. Startup/drain add conditional writes per worker.
Larger root sets add bracketed pages, cold calls and reservations: never advertise a universal two-call request.
Local attribute access within an existing unexpired published handle makes no remote call and cannot see unseen revocation instantly.
S3 is lifecycle/recovery only. IAM needs at least five separated roles plus host workload identity. This is an operational prerequisite.

Monthly cost is `KEK rent + decrypt/wrap calls + transactional read units + transactional write units + storage/receipt requests + logs`.
Transactional reads/writes consume twice the corresponding standard request units, with item-size rounding.
For 300,000 one-row reads/month and five <=4-KiB admission items, two snapshots consume 6,000,000 transactional read units;
this example excludes mutations, cold roots, quota, audit, networking and RDS costs. It is a planning calculation, not a measured bill.
[AWS KMS pricing](https://aws.amazon.com/kms/pricing/) and [DynamoDB pricing](https://aws.amazon.com/dynamodb/pricing/)
supply current region-dependent inputs. No free-tier or universal-dollar claim is made.
The initial footprint TARGET is <=USD50/month incremental custody/authority/receipt service cost at 10,000 hot reads/day,
one domain and five admission items, excluding existing RDS/application and variable audit/network charges. Actual quotes/loads are UNKNOWN.
Regional authority outage stops all operations; KMS outage stops cold/expired keys. Receipt outage stops irreversible lifecycle work.
Lock-in, extra tail latency, IAM review and managed worker drain are acknowledged costs.
G-AUTHORITY/G-PERFORMANCE/G-RELEASE must establish that these costs fit the intended small AWS backend.
Failure requires a product/architecture decision, never stale permission or a giant new orchestration platform.

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
This profile deliberately rejects the extra presence-MAC format/root dependency on NULL-only reads/projection/rotation machinery: its scoped promise
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

## Plaintext boundary and diagnostics

Payloads exist in request objects, application attributes, normalized working copies and validated result buffers before/after crypto.
Host serializers, repr, exception locals, Sentry/APM, tracing, request logs, Redis, Elasticsearch, queues, CSV, analytics and warehouses can receive them.
Debugger access, core dumps and swap can contain plaintext or keys. Cryptalis does not guarantee Python zeroization.
CDC and historical database logs can retain values from pre-protection/deprotection intervals.

Encoding, normalization and redaction are not declassification. Encoded plaintext remains sensitive.
Cryptalis disables its own value logging. Generated engines use `echo=False` and `hide_parameters=True`.
DEBUG result logging, literal-bind diagnostics and parameter-bearing DB/provider exception strings are not emitted by Cryptalis.
The adapter emits fixed operation/stage/error IDs, safe field/constraint IDs, correlation IDs and numerical progress only.
Ciphertext bodies, raw terms, credentials, root material, user identifiers and supplied SQL/bind text are excluded.
Known bad logging settings fail the selected diagnostic profile. Unknown host sinks remain UNKNOWN and outside complete-absence claims.
Canary sink tests must exercise success, failure, cancellation and logging failure. A healthy collector with positive controls is required for absence evidence.

## Public failure contract

Every operation returns success only after its postconditions. It uses a typed Python failure or nonzero CLI exit otherwise.
Partial progress records the operation ID, last durable phase, attempted effects, pending work, safe remedy and recovery obligations.
Retries reuse exact operation/chunk identity after durable reconciliation. Unknown commit/CAS never permits blind replay.
Cleanup failure remains visible alongside the primary failure. Background tasks have an owner that observes terminal failure.

| Operation family | Success | Failure / partial progress | Retry and rollback |
|---|---|---|---|
| init, explain, plan, keys rotate, revoke, destroy, remove | Complete validated proposal/output with PROPOSAL_ONLY and NOT_APPLIED; no activation | Manifest/Mapping/Plan.Invalid or Unavailable, no accepted partial file | Atomic output replacement only for authorized target. Retry after remedy |
| doctor/status/keys status/restore check | Complete bounded findings, health and scope recorded | UNKNOWN on missing observation, FAIL on demonstrated violation. A proven FAIL cannot be erased by UNKNOWN | Read-only retry. No automatic remediation |
| ordinary read | Entire bounded logical result authenticated and consistent | ContextDenied, KeyUnavailable, AuthenticationFailed, IndexInconsistent, UnsupportedProtectedQuery or BufferLimit. No partial publication | Close poisoned session. Corruption needs integrity inspection. Denial needs current authority. Overflow needs a bounded query. Fresh session alone is not a remedy |
| ordinary write | Coherent payload/terms/revision committed under current fence | Typed denial/format/type/query error before DML, or DB/commit ambiguity. Transaction abort/close | Reconcile original operation by terminal backend and durable outcome marker. Never infer commit from current row presence |
| apply (protect/reconfigure/reindex/rotate/upgrade) | All required rows, schema, authority and native states verified before switch | TransitionIncomplete, ApprovalRequired, WrongTarget, StalePlan, ProviderUnavailable or RepairRequired | Use apply --resume OPERATION after current inspection. Rollback only while verified dependencies remain |
| rollback/finalize | Verified reversal / exact approved effects and obligations | IrreversibleState, missing mirror/readers/copies, or pending effects | No generic Alembic downgrade after destructive boundary |
| apply (revoke/destroy/deprotect/remove), restore admit | Scoped state satisfies lifecycle contract | PENDING or INCONCLUSIVE for unproven destruction/drain/recovery, explicit denial for unsafe restore/removal | Reconcile actual provider/authority/DB effects. Never reinterpret pending as erased |

CLI machine output contains schema version, operation, stage, result state, correlation ID, safe code, retryability and permitted progress. Correlation IDs are opaque and have no authorization meaning.
Codes: 0=complete requested result, 2=invalid/unsupported/denied, 3=incomplete/pending/critical UNKNOWN,
4=operational unavailability or output failure. WARN-only read-only reports can exit 0 with explicit warning rows.
An accepted deletion request that is still pending returns 3. A plan is a proposal, never a security PASS.
Output write and flush must succeed. If stderr also fails, nonzero exit remains the failure channel. Consumers require exit 0 and complete framing.
The existing narrow CLI remains unchanged in this documentation pass. It has no mandatory place in the final public surface.

## Priority and abuse paths

| ID | Abuse path | Likelihood / impact / priority | Designed mitigation and residual gap |
|---|---|---|---|
| TM-001 | Raw/worker write bypass -> plaintext storage -> dump disclosure | High / high / critical | Guarded paths, schema checks, role/writer inventory and doctor. Unknown inventory blocks claim |
| TM-002 | DB attacker swaps row context -> unauthorized returned plaintext | Medium / high / high | Expected record/tenant/subject binding, exact registry and AEAD. Host ownership policy remains trusted |
| TM-003 | Query/term mismatch or stale normalizer -> incorrect results/uniqueness | High / high / critical | Atomic writes, full terms, buffered verification, DB UNIQUE and maintenance reindex. Hostile omission remains |
| TM-004 | Stale backup/worker -> old policy/key access -> managed resurrection | Medium / high / high | External current head/tombstones, target quarantine and compatible binary checks. No invisible-RAM recall |
| TM-005 | Crash or wrong-target migration -> false switch/destructive cleanup -> data loss | High / high / critical | Target-bound journal, fences, full verification and exact finalization approval |
| TM-006 | KMS credentials or malicious wheel -> unwrap roots -> plaintext theft | Medium / high / critical | Least privilege, workload identity, protected release and artifact review. Authorized process compromise is not stopped |
| TM-007 | Pipeline/logging failure -> success or secret-bearing diagnostics | High / high / high | Explicit failure channel, safe fields and canary-controlled observations. Host sinks remain external |

Critical means a supported ordinary workflow can expose plaintext, corrupt values or destroy recoverability without an explicit failure.
High means a concrete scoped substitution, stale-policy or diagnostic path crosses the declared boundary.
Medium means bounded availability loss or required-operator misuse without a confidentiality claim.
Low means diagnostic friction without changed authority or data. Counts and severity labels do not replace evidence.

## Independent review and proof

Required human review covers AEAD/nonce bounds, canonical hashed AAD, key resolution/commitment assumptions, HKDF,
blind indexes and full-width collision handling, rotation/rewrap, authority recovery and revocation/destruction claims.
These choices are not audited. AI research and subagent review are first-party design work.
Review implemented crypto, compiler, authority, adapter, provider, lifecycle and release boundaries when they exist. Historical module names do not define the review scope.
The [build guide](build-guide.md#acceptance-evidence) names adversarial oracles. Passing parser tests cannot admit a full runtime profile.
