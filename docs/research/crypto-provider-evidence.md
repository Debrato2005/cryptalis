# Cryptography, Search, and Provider Evidence Ledger

Status: Primary-source documentation review. No Cryptalis execution or reproduction

Initial access date for CP-01–CP-25: **2026-09-30**. Reconciliation on **2026-10-01** reopened
CP-03, CP-08, CP-12 and CP-18 primary pages and corroborated their recorded claims. The review added
CP-26 on 2026-10-01. It tested no runtime behavior.

The reopened GCP page now shows a 2026-09-30 UTC update footer. CP-12 preserves the earlier
observed 2026-09-24 footer rather than silently rewriting that inspection. Recorded 30-day/45-day
semantics still match.

This ledger supports the detailed [crypto/search/lifecycle
owner](../architecture/crypto-search-lifecycle.md). The [prior-art owner](../prior-art.md) owns
comparative positioning. An observed documentation version identifies a source. It does not identify
a supported Cryptalis dependency.

No package installation, cryptographic vector execution, benchmark, cloud-provider mutation, or
independent review occurred in this pass. Official pages are mutable. A future executable bundle
must preserve permitted source digests, exact dependency versions, service configuration, and
retrieval timestamps.

Evidence levels here are **documented** (official product/API documentation) and **paper-inspected**
(published paper or author-submitted research inspected through its text or abstract). Neither means
source-code-inspected, reproduced, benchmarked, or independently reviewed. Numeric Cryptalis budgets
in the design document are proposed acceptance thresholds, not measurements.

## Primitive and standards evidence

| ID | Primary source and exact source scope | Evidence inspected | Design implication and limit |
|---|---|---|---|
| CP-01 | [RFC 8452](https://www.rfc-editor.org/rfc/rfc8452), April 2019, Informational CFRG specification; sections 4, 6, 9 and Appendix C | AES-GCM-SIV specifies 128/256-bit variants, 96-bit nonces and 128-bit tags. Repetition avoids GCM's catastrophic failure but leaks equality. Random nonces are recommended. | Leading non-FIPS candidate remains unselected. Misuse resistance does not authorize repeated nonces or waive usage-bound analysis. Appendix C is a future vector oracle, not an executed test. |
| CP-02 | [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869), May 2010, Informational; sections 2–3 and Appendix A | HKDF separates extract and expand. Salt and application-specific info have distinct roles. The RFC supplies vectors. | Candidate HKDF-SHA-256 labels/encoding are Cryptalis protocol proposals. HKDF does not turn request-selected identities into authority or independently destroy child keys. |
| CP-03 | [cryptography AEAD API](https://cryptography.io/en/stable/hazmat/primitives/aead/), page title **50.0.2** at access; AESGCMSIV added 42.0.0 | AESGCMSIV may raise UnsupportedAlgorithm for the OpenSSL build. APIs return ciphertext with an appended tag and report InvalidTag for authentication failure. | No wheel/OpenSSL/platform compatibility was reproduced. The page lists a 192-bit API key option. Cryptalis's RFC-8452 candidate deliberately accepts only its selected 256-bit variant. API descriptions do not broaden a frozen protocol. |
| CP-04 | [libsodium AEAD constructions](https://doc.libsodium.org/secret-key_cryptography/aead), unversioned documentation; XChaCha available since 1.0.12 | XChaCha20-Poly1305 uses a 192-bit nonce and 128-bit tag. Documentation describes random-nonce use and construction-specific usage/forgery limits. | Comparative candidate needs a pinned binding/library and vectors. XChaCha is not a nonce-misuse-resistant substitute for GCM-SIV. The more specific construction page failed to load in this review. This entry relies on the successfully inspected overview. |
| CP-05 | [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final), November 2007 final; planning note 2024-03-06 | GCM/GMAC specification. NIST states a revision decision. | Track final revision status before suite freeze. No later final publication is inferred. Algorithm choice alone does not establish a validated module or compliant deployment. |
| CP-06 | [NIST SP 800-88 Rev. 2](https://csrc.nist.gov/pubs/sp/800/88/r2/final), final 2025-09-26, supersedes Rev. 1; [full publication](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-88r2.pdf) | Current guidance treats sanitization as rendering target-data access infeasible at a stated effort level. Cryptographic erase depends on appropriate encryption/key sanitization and scope. | A successful application key-record delete is not a media sanitization certificate. No claim of legal erasure, plaintext-copy disappearance, or physical provider-media verification follows. |
| CP-07 | [SP 800-88r2 FAQ](https://csrc.nist.gov/files/pubs/sp/800/88/r2/final/docs/sp800-88r2-faq.pdf), linked by NIST's 2026-07-17 planning note | FAQ dated 2026-07-16 states CE preconditions including no prior plaintext on the target media, adequate algorithm/RNG strength, key zeroization and applicable federal module validation. Supplemental interpretation is separately maintained. | Recheck both publication and FAQ before erasure positioning. This review did not assess a Cryptalis deployment against either document. |

## Provider evidence

Managed services have no single client-package version that determines their semantics. Each future
adapter report must include SDK version, resource/version identity, region, material origin,
protection level, permissions, observed state, and observation time. This ledger identifies
unversioned official API documentation as unversioned. This review does not invent a deployed Vault
or AWS SDK version.

| ID | Primary source and source scope | Evidence inspected | Design implication and limit |
|---|---|---|---|
| CP-08 | [AWS Encryption SDK Hierarchical keyring](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/use-hierarchical-keyring.html), latest developer guide; How it works / cache sections | KMS-protected branch versions live in DynamoDB. Local branch caches reduce KMS calls. Each message has a unique data key and derived wrapping key. Old branch versions support decryption. Python use explicitly excludes multithreading despite generic cache threading descriptions. | The pattern supports the hypothesis of branch prewarm and a local data plane. It does not implement Cryptalis subject erasure. Its SDK message format/key store are separate from Cryptalis's candidate format. Python thread compatibility needs a distinct gate. |
| CP-09 | [AWS KMS rotation](https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html), latest managed-service documentation | Rotation preserves old material for decryption and changes future encryption material. | KEK rotation, branch rotation, subject rotation, payload re-encryption, and search reindexing are separate operations. Rewrap/rotation is not destruction or forward secrecy. |
| CP-10 | [AWS KMS deletion](https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html), waiting-period / special-considerations sections | Customer-managed deletion waits 7–30 days, default 30. Actual deletion may be up to 24 hours later. Pending deletion is cancelable. Replica, imported-material, CloudHSM backup, and external-key cases have distinct exceptions. | Report scheduled/observed state separately. Deleting imported material can allow reimport. Deleting a symmetric KMS resource has different ciphertext-binding consequences. CloudHSM backups and external keys require separate coverage. Cached local keys remain a Cryptalis concern. |
| CP-11 | [Google Cloud KMS envelope encryption](https://docs.cloud.google.com/kms/docs/envelope-encryption), managed-service guidance | Local DEKs protect data. KMS KEKs wrap DEKs, reducing direct KMS payload work. | Supports local crypto with managed root custody. It does not choose tenant/subject key domains or supply subject-specific destruction. |
| CP-12 | [Google Cloud destroy/restore](https://docs.cloud.google.com/kms/docs/destroy-restore), initially observed update footer **2026-09-24 UTC** (reopened 2026-10-01: **2026-09-30 UTC**); [key-version states](https://docs.cloud.google.com/kms/docs/key-states) | Default scheduled destruction is 30 days, configurable at key creation. Scheduled destruction can be restored. Imported material has a reimport exception. Google states infrastructure removal within 45 days of scheduled destruction time. API state and media removal are distinct. | Adapter uses observed configuration/state/time, not a hard-coded universal delay. An example's 24-hour comment does not override the current page's default. External-key material and local caches remain separately scoped. |
| CP-13 | [Vault Transit overview](https://developer.hashicorp.com/vault/docs/secrets/transit), unversioned current documentation | Crypto-service APIs, derived keys, datakeys, rotation and rewrap are available without storing application payloads in Transit. | Narrow adapter can wrap branch material. Invoking Transit per field introduces remote availability/latency. Derived Transit context alone does not make an independently erasable subject key. |
| CP-14 | [Vault Transit HTTP API](https://developer.hashicorp.com/vault/api-docs/secret/transit), key create/config/delete/rotate/trim/backup/restore endpoints | Delete requires deletion_allowed. min_decryption_version restricts permitted versions. Trim deletes older available versions with minimum-version constraints. Exportability and plaintext backup cannot be disabled once enabled. | Policy restriction is not physical destruction. Trim/delete concern the live key ring. Existing snapshots/exports need independent treatment. Pin the deployed Vault edition/version and backup configuration before any receipt conclusion. |
| CP-15 | [Google Cloud KMS AAD](https://docs.cloud.google.com/kms/docs/additional-authenticated-data), managed-service API guidance | Additional data authenticates context without encryption. Decryption requires the matching AAD. | Provider wrapping AAD and payload AAD are distinct encodings. Provider metadata must contain only non-secret pseudonymous references. A matching AAD is not an authorization decision. |

## Search systems and leakage evidence

| ID | Primary source and source scope | Evidence inspected | Design implication and limit |
|---|---|---|---|
| CP-16 | [CipherSweet blind-index internals](https://ciphersweet.paragonie.com/internals/blind-index); [key hierarchy](https://ciphersweet.paragonie.com/internals/key-hierarchy), unversioned design pages | Separate field and blind-index key domains. Fast/slow backend-specific blind-index modes and configurable truncation. | Useful domain/transform/collision reference. Cryptalis proposes full 256-bit equality terms initially. No claim it reproduces CipherSweet's encoding/backend or gains the same security properties. |
| CP-17 | [CipherSweet repository](https://github.com/paragonie/ciphersweet), repository README inspected, no revision pinned | Maintained PHP field/search encryption reference describes randomized field protection and blind indexing. | Educational/reference system, not installed/tested or source-inspected here. Any future reproduction must pin a release/commit and backend. |
| CP-18 | [CipherStash cryptography](https://cipherstash.com/docs/security/cryptography), last updated **2026-07-30** | AES-256-GCM-SIV, HMAC equality, CLLW OPE or block ORE, trigram Bloom-filter search. ZeroKMS seed production and local per-value derivation are separate stages. SDK caches nothing. Proxy caches keyset-scoped cipher objects rather than data keys. | Strong comparator with a different authority/I/O model. Do not restate it as a generic branch-key cache, infer per-subject erasure, or treat vendor immediate-revocation wording as Cryptalis evidence. No benchmark or service behavior was reproduced. |
| CP-19 | [MongoDB encrypted fields / enabled queries](https://www.mongodb.com/docs/manual/core/queryable-encryption/fundamentals/encrypt-and-query/); explicit English v8.2 URL redirected here at access | Equality/range documented as production supported. Text identifies 8.2 prefix/suffix/substring public preview and incompatible eventual GA migration. Selector displays 9.0 Current. | Record the redirect and source's named capability version. It does not establish production string search in a later release. Exact server/driver/crypt_shared/edition must be pinned for comparison. |
| CP-20 | [MongoDB Queryable Encryption limitations](https://www.mongodb.com/docs/manual/core/queryable-encryption/reference/limitations/), current manual, selector 9.0 | Persistent attackers and snapshots combined with query transcripts are outside its stated guarantee, especially range. Unique encrypted values, renames, arrays, and migration have explicit restrictions. | A security comparison must pin attacker observation powers. Cryptalis's deterministic blind index is not MongoDB's protocol. Generalizing snapshot guarantees across constructions would be incorrect. |
| CP-21 | [Acra security controls](https://docs.cossacklabs.com/acra/security-controls/), unversioned official documentation | Data protection plus SQL firewall, anomaly responses, honeytokens, security logging and operational evidence. | Defeats claims that protection competitors omit security controls. No release/edition, performance, or claim of Cryptalis-specific source correlation was independently verified. |
| CP-22 | Cash, Grubbs, Perry, Ristenpart, [Leakage-Abuse Attacks Against Searchable Encryption](https://eprint.iacr.org/2016/718.pdf), CCS 2015, ePrint 2016/718, 14-page author paper | Query/plaintext recovery attacks use leakage and auxiliary knowledge, including chosen-document attacks. Security with a leakage function does not show leakage is harmless. | Require threat-specific auxiliary-data and query-observation attacks. This pass inspected paper text but reproduced no experiments. Reported historical attack percentages are not Cryptalis results. |
| CP-23 | Lewi and Wu, [Order-Revealing Encryption: New Constructions, Applications, and Lower Bounds](https://eprint.iacr.org/2016/612), ePrint 2016/612 | Published ORE construction/lower-bound reference identified through author abstract. | A range prototype must specify the actual variant, comparison leakage and reference implementation. This ledger does not certify an implementation or claim full-paper reproduction. |
| CP-24 | Xu et al., [Leakage-Abuse Attacks Against Forward and Backward Private Searchable Symmetric Encryption](https://arxiv.org/abs/2309.04697v2), v2 **2023-09-13**, author abstract, CCS 2023 short-version note | Frequency/volume attacks remain possible against studied forward/backward-private dynamic schemes. | These terms are precise construction properties, not a label earned by deleting companion rows. Abstract inspected. No universal attack or production conclusion inferred. |
| CP-25 | Blackley et al., [How Query Distribution Knowledge Breaks Multidimensional Encrypted Range Queries, With Guarantees](https://arxiv.org/abs/2508.11563v2), v2 **2026-05-07**, author abstract | LAMa uses query-distribution knowledge plus access patterns for multidimensional plaintext recovery. v1 used a different title. | Range research must model query distributions as auxiliary information. No attack code/corpus reproduced. Exact revised version matters for attribution. |

## Key commitment evidence

| ID | Primary source and exact source scope | Evidence inspected | Design implication and limit |
|---|---|---|---|
| CP-26 | Albertini, Duong, Gueron, Kölbl, Luykx, Schmieg, [How to Abuse and Fix Authenticated Encryption Without Key Commitment](https://www.usenix.org/conference/usenixsecurity22/presentation/albertini), USENIX Security 2022, pp. 3291–3308; [author ePrint 2020/1456](https://eprint.iacr.org/2020/1456), last revision 2021-12-08; abstract and proceedings text inspected | Ordinary AE authentication does not imply key commitment. The authors show real applications that rely on key commitment. They show multi-key-valid AES-GCM ciphertext and explicit composition remedies that require analysis. | F1/W1 must not infer commitment from misuse resistance, authenticated headers or one-handle syntax. G-CROSSKEY restricts authorized resolution and requires external review of whether the actual threat model/composition needs a committing construction. No attack tool or remedy was implemented/reproduced in this pass. |

## Evidence still required

- External review of the composed envelope, KDF, wrapping and search protocol, including key
  commitment where attacker-controlled key selection could matter. AEAD authentication alone does
  not prove unique-key commitment.
- Cross-process and cross-language vectors for the candidate bytes, all primitives, normalization
  and provider wrappers. SDK version, OS, OpenSSL and module evidence for supported platforms.
- Live or emulated provider state-transition traces, permission, outage and cancellation behavior,
  fresh and stale process release outcomes, and independent restoration exercises.
- Construction-specific search attacks with pinned corpus and auxiliary knowledge, correctness,
  false-positive bounds, storage, WAL and query amplification, and migration costs.
- A complete recovery-path inventory, backup and restore retention evidence, and exact signer and
  witness trust boundary before stronger destruction language.
- Documented demand and accepted domain leakage. Reference-system feature existence is not Cryptalis
  adoption evidence.

This ledger establishes research provenance only. Pending experiments remain pending in the
[implementation tracker](../backend-build-checklist.md).
