# Reset research: cryptography and external authority

Access date for every source below: **2026-10-06**. This document records research, not a normative contract or security audit.

The review inspected current official documentation and the cited paper. It ran no provider experiment, cryptographic vector, benchmark, or independent review.
Publication dates are explicit where the source establishes them. An unversioned service page does not identify an SDK release or tested deployment.
The recommendations are design choices. The canonical architecture and security documents own the adopted contracts.

Final selection: the [security owner](../security.md#keys-and-caches) chooses a 300-second material-cache age and a separate 30-second operation deadline.
The 60-second recommendation below is a rejected research input. It does not define runtime behavior.

## Repository basis

The review read `AGENTS.md`, `README.md`, the engineering playbook, the architecture map, and the existing crypto owner and evidence ledger.
The current dependency files pin `cryptography==50.0.2`. The existing F1 and W1 modules check structure. They do not supply runtime encryption or provider authority.
The old design includes alternative primitives, tenant branches, custom wrapping records, distributed quota reservations, and a detailed release-drain service.
Those proposals do not establish an implemented or verified capability.

## Sources actually opened

Vendor navigation started from the AWS KMS, DynamoDB, Vault, cryptography, libsodium, and Tink documentation indexes.
Where a sidebar omitted links, targeted search located a page within that documentation tree. No search excerpt alone supports a technical claim.

| ID | Source, established date/version | What the opened source established |
|---|---|---|
| CA-01 | [cryptography index](https://cryptography.io/en/stable/), 50.0.2 | The library separates high-level recipes from hazardous primitive APIs. |
| CA-02 | [cryptography changelog](https://cryptography.io/en/stable/changelog/), 50.0.2 released 2026-09-30 | Published wheels use OpenSSL 4.0.3. This does not prove the installed backend or platform behavior. |
| CA-03 | [AEAD API](https://cryptography.io/en/stable/hazmat/primitives/aead/), 50.0.2 | AESGCMSIV uses a 12-byte nonce and 16-byte tag, reports authentication failure, and can reject an unsupported backend. |
| CA-04 | [KDF API](https://cryptography.io/en/stable/hazmat/primitives/key-derivation-functions/), 50.0.2 | The library supplies HKDF with an explicit hash, salt, information string, and output length. |
| CA-05 | [Randomness guidance](https://cryptography.io/en/stable/random-numbers/), returned page labeled 50.0.1 | The project directs callers to operating-system randomness rather than Python's general random generator. |
| CA-06 | [RFC 8452](https://datatracker.ietf.org/doc/html/rfc8452.html), April 2019 | AES-GCM-SIV tolerates bounded nonce misuse, recommends random nonces, and specifies usage bounds and vectors. |
| CA-07 | [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869.html), May 2010 | HKDF separates extraction from expansion and uses context-specific information for key separation. |
| CA-08 | [Python os API](https://docs.python.org/3/library/os.html), returned documentation 3.14.8, footer 2026-10-06 | `os.urandom` uses OS randomness. Linux blocks for initialization. Fork hooks exist but do not detect arbitrary VM restoration. |
| CA-09 | [PEP 524](https://peps.python.org/pep-0524/), Python 3.6 design | Linux entropy initialization motivates blocking randomness rather than an unsafe fallback. |
| CA-10 | [libsodium index](https://libsodium.gitbook.io/doc), unversioned | The current index exposes the maintained primitive documentation. |
| CA-11 | [libsodium AEAD comparison](https://doc.libsodium.org/secret-key_cryptography/aead), unversioned | XChaCha permits random 192-bit nonces. Its security still depends on avoiding key/nonce reuse. Current guidance also compares AEGIS. |
| CA-12 | [Tink index](https://developers.google.com/tink), rolling | Tink supplies established high-level primitives and key-management interfaces. |
| CA-13 | [Tink AEAD comparison](https://developers.google.com/tink/aead), updated 2026-06-09 | Tink distinguishes committing CTR-HMAC from noncommitting GCM, GCM-SIV, and XChaCha constructions. |
| CA-14 | [USENIX commitment paper entry](https://www.usenix.org/conference/usenixsecurity22/presentation/albertini), August 2022 | Missing key commitment affects applications that allow adversarial key selection. Ordinary authentication does not prove commitment. |
| CA-15 | [Full commitment paper](https://www.usenix.org/system/files/sec22-albertini.pdf), USENIX Security 2022 | The paper includes AES-GCM-SIV attacks and compositions. Their assumptions require separate analysis before adoption. |
| CA-16 | [AWS KMS index](https://docs.aws.amazon.com/kms/latest/developerguide/overview.html), rolling managed-service guide | KMS protects root key custody. Application envelope keys can exist outside its boundary. |
| CA-17 | [AWS key policies](https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html), rolling | Key policy controls resource access. Resource custody alone does not establish application authorization. |
| CA-18 | [AWS encryption context](https://docs.aws.amazon.com/kms/latest/developerguide/encrypt_context.html), rolling | Context authenticates wrapping metadata and appears in CloudTrail. It must contain no sensitive plaintext identifiers. |
| CA-19 | [AWS rotation](https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html), rolling | KEK rotation retains old decrypt material. It does not rotate payload keys or reencrypt existing data. |
| CA-20 | [AWS deletion](https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html), rolling | Scheduled deletion waits 7–30 days and can be canceled. Actual deletion can occur up to 24 hours later. |
| CA-21 | [Unusable KMS keys and data keys](https://docs.aws.amazon.com/kms/latest/developerguide/unusable-kms-keys.html), rolling | KMS denial is subject to eventual consistency and does not revoke material already unwrapped in a workload. |
| CA-22 | [AWS key stores](https://docs.aws.amazon.com/kms/latest/developerguide/key-store-overview.html), rolling | Standard KMS manages durable encrypted copies. Imported material and custom stores add distinct recovery and operational obligations. |
| CA-23 | [AWS credential-provider index](https://docs.aws.amazon.com/sdkref/latest/guide/standardized-credentials.html), rolling | Managed workload identities supply temporary credentials without a long-lived application secret. |
| CA-24 | [AWS container credentials](https://docs.aws.amazon.com/sdkref/latest/guide/feature-container-credentials.html), rolling | ECS and EKS expose workload credentials through supported SDK providers. Credentials remain powerful inside the workload. |
| CA-25 | [KMS resource quotas](https://docs.aws.amazon.com/kms/latest/developerguide/resource-limits.html), rolling | The documented default permits 100,000 customer keys per account and Region. Dedicated subject keys incur a material quota cost. |
| CA-26 | [KMS pricing](https://aws.amazon.com/kms/pricing/), rolling | Published examples charge $1 per customer key each month plus operation charges. Quotes require Region and current pricing checks. |
| CA-27 | [DynamoDB index](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Introduction.html), rolling | DynamoDB supports native transactions and a separate durable storage boundary. |
| CA-28 | [DynamoDB transactions](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis.html), rolling | Transactional reads/writes provide serializable isolation. Separate multi-item reads do not supply an atomic snapshot. |
| CA-29 | [DynamoDB consistency](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.ReadConsistency.html), rolling | Base tables support current reads. GSIs and streams do not. Global tables now distinguish MREC and MRSC. |
| CA-30 | [DynamoDB restore](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/pointintimerecovery_restores.html), rolling | PITR creates a new table. IAM, deletion protection, and other settings require separate configuration. |
| CA-31 | [Vault index](https://developer.hashicorp.com/vault/docs), selector v2.x latest | The live documentation exposes the current service and administration families. This is not a deployed-version pin. |
| CA-32 | [Vault sensitive-data navigation](https://developer.hashicorp.com/vault/docs/about-vault/why-use-vault/sensitive-data), rolling | Transit is the documented external-payload crypto service. |
| CA-33 | [Vault Transit](https://developer.hashicorp.com/vault/docs/secrets/transit), selector v2.x latest | Transit supports data keys, rotation, derived contexts, and rewrap without storing application payloads. |
| CA-34 | [Vault Transit API](https://developer.hashicorp.com/vault/api-docs/secret/transit), selector v2.x latest | Export and plaintext-backup settings become irreversible when enabled. Delete, trim, and version policy are distinct controls. |
| CA-35 | [Vault snapshot index](https://developer.hashicorp.com/vault/docs/sysadmin/snapshots), rolling | Cluster snapshots support backup and restoration. Live key deletion does not eliminate a retained snapshot. |
| CA-36 | [Vault restore](https://developer.hashicorp.com/vault/docs/sysadmin/snapshots/restore), rolling | Restore needs isolation and original recovery material. Command return does not mean background restoration completed. |
| CA-37 | [Vault storage](https://developer.hashicorp.com/vault/docs/concepts/storage), rolling | Recovery includes encrypted storage and configuration. Configuration backups can include sensitive authority material. |
| CA-38 | [NIST SP 800-88 Rev. 2 entry](https://csrc.nist.gov/pubs/sp/800/88/r2/final), final 2025-09-26 | Revision 2 supersedes Revision 1 and defines sanitization at a stated effort level. |
| CA-39 | [NIST SP 800-88 Rev. 2 publication](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-88r2.pdf), September 2025 | Cryptographic erase requires key/copy analysis, sanitization evidence, and attention to cached descendants and escrow. |
| CA-40 | [NIST current FAQ](https://csrc.nist.gov/files/pubs/sp/800/88/r2/final/docs/sp800-88r2-faq.pdf), dated 2026-07-16, entry planning note 2026-07-17 | CE prerequisites include no prior plaintext, adequate crypto/RNG strength, key sanitization, and applicable federal module validation. |

## Recommended choices and rejected alternatives

### Primitive, limits, and binding

Choose AES-256-GCM-SIV through `cryptography.hazmat.primitives.ciphers.aead.AESGCMSIV`, pinned initially to `cryptography==50.0.2`.
Use a 32-byte key, a fresh `os.urandom(12)` nonce per encryption, and the complete 16-byte authentication tag.
Choose HKDF-SHA-256 for purpose and field separation. Obtain every subject payload root and search root from independent 32-byte randomness.
Do not derive subject roots from a surviving tenant secret. Deleting a derived key would not remove its regeneration path.
Do not truncate the tag, retry with another key, or select the suite from arbitrary database input.
Startup rejects an unsupported backend. A missing dependency or key never selects plaintext.

Reject plain AES-GCM as the default because nonce reuse creates a more severe failure.
Reject XChaCha as the default because it adds a separate binding and lacks nonce-misuse resistance.
Reject a selectable primitive menu. Tink's complete message format remains a credible comparison, but mixing its semantics into F1 adds another contract.
Reject custom key commitment. Trusted key generation and one exact authorized key resolution define the chosen threat boundary.
Adversarial key registration, key-supplier compromise, and unknown-key trial loops are outside that boundary or denied.
AES-GCM-SIV does not become committing under this decision. Independent review must assess the actual authority model.

Proposed conservative limits are 1 MiB per encoded value and 2^24 encryptions or 2^40 encoded bytes per subject generation.
Charge the generation across every derived field key, worker, failed write, and retry.
Reserve bounded quota through the external authority before local crypto. Burn unused reservations after a crash or expiry.
These limits deliberately preserve stricter existing operational caps. They are not a reproduced multi-key security proof.
The implementation must reject exhaustion rather than reset counters or continue under an uncounted key.

Authenticate a SHA-256 digest of the complete canonical header and expected stable location context as the 32-byte AEAD associated data.
Include domain, tenant, subject incarnation, immutable record identity, stable model/field identity, representation, format, codec, purpose, and payload generation.
The expected location comes from admitted policy and row context. A copied header does not establish the expected location.
Bind mutable SQL names through stable logical identifiers. Renaming a SQL column must not silently change a cryptographic identity.
Hashing context adds a collision-resistance assumption and requires independent review of canonical encoding and domain separation.
It also avoids applying RFC short-AAD examples to a long header. Treat the selected numeric caps as test gates.

OS RNG errors deny encryption. A detected duplicate nonce denies the operation and triggers a diagnostic.
A bounded detector cannot prove entropy or global nonce uniqueness. Multi-host randomness depends on healthy independent OS sources.
Fork invalidates inherited key caches, quota reservations, SDK clients, and authority results. A PID guard requires new admission in the child.
Use fresh OS calls rather than copied user-space PRNG state.
Arbitrary invisible VM-memory cloning is unsupported. A restored VM must restart the workload and obtain current external authority.

### Provider and hierarchy

Choose one single-Region AWS-generated symmetric KMS KEK per protection domain in the standard key store.
Pin its account, Region, immutable key ARN, material origin, and expected specification. An alias is not durable identity.
Wrap independent subject payload roots and tenant/field search roots directly with KMS.
Do not introduce a tenant branch or custom W1 wrapping layer without measured necessity.
Cold unwraps and generation creation incur provider I/O. Ordinary warm field crypto remains local.
Batch distinct material preparation at explicit transaction or buffered-result boundaries. Never hide network I/O inside scalar conversion.

Use ECS/EKS/EC2 workload identity through the provider's credential chain. Separate runtime decrypt permission from key administration and destruction.
Pin the identity and resource policy. Reject long-lived raw root secrets in application environment files.
Only opaque nonsecret references belong in KMS encryption context and diagnostics.
Use CloudTrail for provider operations and application audit for local operations. KMS logs do not record every local decryption.

Vault is a credible alternative for existing Vault operators, but do not promise another production adapter in the same support claim.
Vault adds cluster, seal, recovery-holder, snapshot, and patch-management obligations.
Transit live deletion or minimum-version policy does not defeat a recoverable old cluster snapshot.
Imported KMS material, custom HSM stores, and customer escrow are excluded from the default because their recovery paths broaden destruction scope.

### Current authority, cache, and restore

Choose one separately administered regional DynamoDB table with a pinned ARN outside application and VM restore domains.
Store active manifest digest, compatibility/read/write generations, lifecycle epoch, destructive-operation facts, and permanent deny tombstones.
Use conditional CAS and transactional current reads. Do not use eventual reads, GSIs, streams, or expired local state for admission.
No tombstone has a TTL. Denied subject incarnations and retired representations never become valid through handle reuse.
Runtime credentials cannot delete, restore, replace, or retarget the authority. Administrative recovery is a separate privileged operation.

Bound in-process material caching to 60 seconds and a stated capacity. This is a testable design default, not a measured revocation promise.
Entry identity includes key ARN, scope, generation, purpose, manifest compatibility, and lifecycle epoch.
Cached material is not authorization. Check current authority before protected writes and before buffered plaintext release.
An authority outage denies new admission even with cached material. A provider outage denies cold loads and cannot extend cache expiry.
Already admitted in-flight work and plaintext already returned remain outside recall. Do not label TTL expiry as physical key destruction.
A check cannot detect a memory clone resumed after the check. No instantaneous worldwide release-stop claim follows.

Quarantine restored databases. Validate trusted schema and writers before granting production credentials.
Current authority dominates restored manifest heads, wrappers, counters, checkpoints, and deletion records.
DynamoDB PITR creates a different table. Pinning resource identity prevents automatic admission of that old table.
If the authority itself is lost, recover only after independent evidence establishes the current head and complete permanent-deny history.
If that evidence is incomplete, deny admission. An old authority backup is not automatically current authority.

AWS manages recovery copies of AWS-generated KEKs. Cryptalis does not export or escrow them by default.
Protect key-administration credentials and test account/Region recovery and policy recovery.
Permanent loss of a required KEK destroys recovery of every descendant without another surviving copy.
Permanent loss of the subject root similarly destroys its protected payload recovery.
This data-loss boundary must appear before irreversible lifecycle approval.

### Rotation, denial, and bounded destruction

Keep KEK rotation/rewrap, payload-generation replacement, and search-generation replacement distinct.
KEK rewrap preserves payload roots. Payload rotation reencrypts payloads. Search rotation requires reindexing.
Readers admit the new generation before writers use it. Complete verification precedes retirement.
Backups retain finite old-reader/key obligations until their retention expires or an explicit destructive approval abandons recovery.

Choose shared tenant/field equality keys with explicit leakage acceptance.
Managed subject denial prevents Cryptalis-authorized recovery after a current tombstone check. It does not cryptographically destroy backup copies.
A surviving domain KEK can unwrap a backed-up subject root. Shared search keys still allow linkage and candidate testing.
Remove live subject tokens, but report historical frequency, equality, query/access patterns, and retained backups separately.
Per-subject cryptographic destruction is unsupported under the shared-KEK design.
Dedicated subject KMS keys are an alternative with documented monthly cost and quota pressure. Do not conceal that cost behind a subject policy flag.
Subject-specific equality keys would require search fanout and defeat ordinary cross-subject uniqueness. Reject that alternative for the primary query profile.

Bounded destruction covers a whole dedicated domain KEK and its declared descendants after provider deletion and covered cache/copy evidence.
Record denial published, deletion requested, deletion pending/cancelable, provider deletion observed, recoverable copies, and unresolved copies separately.
Never print `ERASED` after a local delete or scheduled deletion. An unknown worker or recoverable key copy blocks destruction completion.
Provider state is an observation, not physical media inspection. The output must preserve that evidence limit.
NIST CE prerequisites do not establish sanitization of a retrofitted database's old plaintext, WAL, snapshots, or exports.
Independent media retention and destruction remain operator obligations. No NIST compliance or universal erasure claim follows.

## Required evidence and independent review

| Gate | Required behavior before a production claim |
|---|---|
| Primitive/backend | Published AES-256-GCM-SIV and HKDF vectors match on every supported wheel/backend. Unsupported backend is denied. |
| Context/format | Tamper, relocation, wrong record/tenant/subject, wrong codec, unknown format, and wrong generation fail before plaintext release. |
| Nonce/limits | RNG error, duplicate injection, fork, retry, crash, counter exhaustion, and parallel budget reservation cannot bypass limits. |
| Authority | Current checks reject stale head, tombstone, restored DB/VM, replaced table, policy downgrade, outage, and old binary. |
| Release boundary | Suspension between check and decode documents in-flight exposure. Lazy/streaming result paths cannot evade the selected buffering rule. |
| Provider | Exact ARN/context/identity tests cover throttling, outage, disable/enable, schedule/cancel deletion, observed deletion, and cache expiry. |
| Rotation | Mixed readers, writer switch, complete backfill, crash/resume, index rebuilding, and old-backup reader obligations match the lifecycle. |
| Recovery | Shred/deny then restore stale data fails managed admission. Offline recovery with surviving KEK is an explicit expected counterexample. |
| Destruction | Cached roots, retired generations, snapshots, exports, and recovery copies prevent a false completion receipt. |
| Performance | Measure cold/warm latency, bounded cache memory, quota contention, canceled requests, and multi-tenant pressure. No benchmark number is assumed. |

Human cryptographer/security review must cover AEAD/nonce use, aggregate limits, canonical hashed AAD, HKDF domains, search construction, rotation, and destruction claims.
The research selects defaults. It does not audit them. Unknown empirical results remain `DECIDED-BLOCKED-ON-TEST` in the decision ledger.
