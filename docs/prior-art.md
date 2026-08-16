# Prior Art and Positioning

What already exists, what does not, and exactly which claim this project is entitled to make.

**Source and limitation.** This is preserved working research, not a completed repository
verification. Its external claims and dates must be rechecked against primary sources before use in
a public statement, product claim, or architecture decision. It may inform investigation; it does
not override the accepted SDK decision in [ADR-0005](architecture/0005-sdk-integration-and-deployment.md).

**Evidence discipline.** Every row below is tagged:

| Tag | Meaning |
|---|---|
| **Verified** | Confirmed against a primary source (repository, package index, standards body, regulator publication). |
| **Unverified** | Encountered but not independently confirmed. Do not cite a figure. |
| **Absence of evidence** | Searched for, not found. This is *not* proof of non-existence and must never be stated as one. |

---

## Claim hypothesis — do not publish without re-verification

> The first open-source **Python ORM-integrated, per-data-subject crypto-shredding** layer with
> signed erasure certificates and a tamper-evident audit log.

Three qualifiers do the work, and none may be dropped:

- **Python ORM-integrated** — the combination is unclaimed in the Python ORM ecosystem specifically.
- **per-data-subject** — key isolation per data subject, not per application, per model, or per key.
- **the combination** — not crypto-shredding, not erasure certificates, not field encryption
  individually. Each of those is owned by someone else.

## Claims that are not available

| Do not claim | Because |
|---|---|
| "First/only crypto-shredding tool" | Acra, CipherStash, Conduktor, Granit (.NET), VeritasChain, and the cloud KMS vendors all ship or frame crypto-shredding. |
| "Novel erasure certificates" | Signed erasure certificates are an established commercial product for disk sanitization (Blancco, Jetico, PIWIPE), and VeritasChain ships an application-layer one. |
| "Crypto-shredding is EDPB-endorsed" | False. The EDPB declined to adopt exactly that language when asked. See [Regulatory position](#regulatory-position). |
| "Crypto-shredding is legally equivalent to erasure" | Unsettled and jurisdiction-dependent. |
| "Novel cryptography" | The research document's own caveats already concede this; the value is correct assembly. |

## Python ORM field encryption — the landscape

**Finding: no maintained Python package combines per-subject key isolation, key destruction, a signed
erasure certificate, and ORM column-type integration.** Every established library is single-key (or
key-rotation-list) encryption at rest. Confidence: **Verified** for each package below;
**absence of evidence** for the negative conclusion overall.

| Package | Key model | Shredding | Certificate | Notes |
|---|---|---|---|---|
| `sqlalchemy-utils` `StringEncryptedType` | Single master key at model-declaration time; key may be a callable | No | No | Most-used option. `EncryptedType` deprecated in favour of `StringEncryptedType` at v0.36.6. A long-standing open issue documents that the AES engine derives a **static IV from SHA-256 of the key** — a real cryptographic weakness, and a useful contrast for this project's gateway-owned nonces. Maintenance is light. |
| `django-fernet-fields` | Single key, list for rotation | No | No | Last real release 0.6 (2019); classified inactive. Compatibility forks exist. |
| `django-cryptography` | Fernet key, optional per-field key, optional TTL | No — TTL expiry is not deliberate destruction | No | Largely dormant. |
| `django-encrypted-model-fields` | Single `FIELD_ENCRYPTION_KEY` | No | No | |
| `django-crypto-fields` | Global RSA+AES key sets in a key path | Adjacent — removing the RSA keys de-identifies the dataset | No | Built for research de-identification. Global key set, no per-subject workflow. Closest in *spirit*, not in mechanism. |
| `django-pgcrypto-fields` | Key passed per query, encryption in Postgres | No | No | Encryption happens inside the database — the adversary this project defends against. |
| `encrypt-decrypt-fields` | Single key, Fernet | No | No | Works for both Django and SQLAlchemy. |
| `django-field-cryptography` | Single `FERNET_KEY` | No | No | |
| A Tink- or Vault-Transit-backed ORM field type | — | — | — | **Absence of evidence.** Searched, not found. |

**Two Python crypto-shredding projects exist, neither ORM-integrated** (Verified):

- `hupe1980/cryptoshredding` — genuine per-key-id shredding on the AWS DynamoDB Encryption SDK with
  KMS. DynamoDB only.
- `veritaschain/vcp-gdpr-poc` — Apache-2.0, announced 2026-01-20, AES-256-GCM plus SHA-256 hash chain
  and erasure-certificate generation. Targets append-only audit logs and MiFID II trading records, as
  a protocol — not an ORM write path.

## Closest prior art, and why it validates the architecture

### Granit (.NET / EF Core) — **the load-bearing precedent**

Per-entity key isolation via an attribute, per-instance AES-256 keys in Vault, a one-call shredder,
and automatic audit. Apache-2.0, actively documented into 2026.

**The finding that changes this project's design:** Granit's own documentation states that EF Core
value converters receive only a scalar value and cannot see the entity type or id, so per-entity key
lookup is impossible in a converter. Granit therefore abandoned the converter layer and uses
**save-interceptors** that walk the change tracker on write.

This is the exact analogue of the SQLAlchemy `TypeDecorator` limitation, and a vendor arriving at the
same wall independently is the strongest available evidence that the constraint is structural rather
than a gap in our understanding. It is why [ADR-0007](architecture/0007-orm-integration-layer.md)
puts key selection in `before_flush` rather than in `process_bind_param`.

**Unverified:** Granit's star count, last-commit date, and canonical repository URL. The name collides
with unrelated projects. Do not cite a figure for any of these. **Absence of evidence:** no Python
port of Granit, by its author or anyone else.

### Everything else, and how this project differs

| Prior art | What it is | Why it is not this |
|---|---|---|
| **Granit** (Verified: license, active docs) | .NET 10 / EF Core, per-entity keys, Vault, shredder, audit | Different runtime and ORM. No Python equivalent exists. |
| **VeritasChain VCP** (Verified) | Python, per-subject shredding, signed erasure certificate, hash chain | An append-only audit-log/fintech protocol, not an ORM column type over Postgres. Also: its "EDPB-endorsed" marketing claim is overstated — its own later writing concedes the question is unsettled. |
| **Acra** (Cossack Labs) | Field-level encryption, unique per-field keys | No per-subject shredding or certificate framing. Note `capstone-final-decision.md` §3 already corrected the research document's "KMS is Enterprise-only" claim. |
| **CipherStash** | Postgres, per-value keys via ZeroKMS, cryptographic audit trails | Queryable encryption and access control; TypeScript-first; commercial. Not destruction certificates. |
| **`axon-crypto-shredding-extension`** (everest-engineering) | Java/Axon, per-subject key isolation for event sourcing, `deleteSecretKey` | Closest conceptual cousin. Event-sourced Java, not a Python ORM. |
| **AWS KMS `ScheduleKeyDeletion`** (Verified) | 7–30 day waiting period, CloudTrail as proof | **Per-KMS-key granularity.** Without further architecture this means whole-database or whole-tenant. |
| **Google Cloud KMS** (Verified) | Distinguishes destruction from deletion; docs endorse destroying a key version to crypto-shred | Per-key-version granularity. |
| **Azure Key Vault** (Unverified — referenced by other tools, docs not fetched) | KMS backend | Same per-key granularity model. |
| **Blancco, Jetico, PIWIPE, D-Secure, Certus** (Verified) | Signed, tamper-proof certificates of erasure per device, tied to NIST 800-88 | Media sanitization per drive serial number. Does not shred one user's row inside a live database. |
| **Apple "Erase all content and settings"** | Effaceable storage | The canonical device-level example of the technique. |

**The engineering contribution, stated precisely:** native cloud KMS crypto-shredding operates at
whole-key granularity. Row and field granularity requires the envelope + per-subject-DEK design in
[ADR-0002](architecture/0002-envelope-key-management.md). That gap — between what a KMS gives you and
what per-subject erasure requires — is the actual work.

## Regulatory position

**The most important caveat in this document.** Cryptographic erasure is technically recognized and
legally unsettled. The project's headline claim depends on stating this correctly.

### Technically recognized

**NIST SP 800-88 Rev. 2**, finalized **26 September 2025** (cover date September 2025; supersedes
Rev. 1 of 2014). Cryptographic Erase is a Purge-level sanitization technique with its own dedicated
§3.2, covering strength of cryptography, applicability, sanitization of keys, quality of
implementations, and traceability. Rev. 2 strengthened the prerequisites: encrypted from first use,
validated encryption, verifiable key destruction, traceability. Confidence: **Verified.**

This is a US technical media-sanitization standard. It validates the technique as technically sound.
It is not a GDPR or DPDP legal instrument and cannot be cited as one.

### Legally unsettled

- **EDPB Guidelines 02/2025** (blockchain; v1 adopted 8 April 2025, v2.0 adopted 7 July 2026): key
  deletion renders data unintelligible, but **"encrypted personal data is still personal data."**
  Erasure compliance is framed as rendering data effectively anonymous. Industry commenters asked the
  EDPB to state that key destruction fulfils the right to erasure; **the EDPB declined**. Confidence:
  **Verified** — and this single fact is why the "EDPB-endorsed" claim is prohibited.
- **EDPB Guidelines 01/2025** (pseudonymisation, adopted 16 January 2025, possibly still in
  consultation — **flagged as uncertain**): deleting the additional information does not automatically
  make data anonymous. The area is shifting after CJEU C-413/23 P.
- **India DPDP Act 2023 / DPDP Rules 2025** (notified November 2025): Rule 8 requires erasure
  generically, with advance notice to the Data Principal and Third-Schedule retention timelines. **No
  rule names cryptographic erasure.** Encryption appears in Rule 6 as a security safeguard, not as a
  substitute for erasure. Confidence: **Verified.**
- **National DPA decisions and ENISA endorsement:** **absence of evidence.** None found adjudicating
  or endorsing crypto-shredding as erasure.

### Required wording

**Use this:**

> Crypto-shredding is a recognized technical method of cryptographic erasure (NIST SP 800-88 Rev. 2,
> §3.2) and is widely proposed as a means of satisfying GDPR Art. 17 and DPDP Rule 8 erasure
> obligations. Its legal sufficiency is jurisdiction-dependent and currently unsettled; the EDPB's
> position is that encrypted personal data remains personal data.

**Never use:** "EDPB-endorsed", "legally equivalent to erasure", "GDPR-compliant erasure",
"satisfies Article 17". This applies to the README, the demo script, the resume line, commit
messages, and any public post. See the
[maintenance rule](#maintenance).

## What would change this analysis

| Trigger | Response |
|---|---|
| A maintained PyPI package appears combining per-subject keys + shredding + ORM column type | Re-scope the novelty claim to the certificate and audit-log combination, and update this document in the same week |
| The EDPB issues final guidance, or a DPA issues a decision, accepting key destruction as Art. 17 erasure | Strengthen the legal wording from "argued" to "recognized" — and only then |
| Granit or another project ships a Python port | Differentiate on the audit log and certificate, or reconsider the project's wedge |
| A CJEU ruling shifts the anonymisation test | Re-read the wording section before any public claim |

Watch: post-C-413/23 P anonymisation guidance; the EDPB pseudonymisation guidelines reaching final form.

## Maintenance

This document is reviewed before any public release or any change to the project's headline claim,
and updated whenever a prior-art item's status changes. It is the only place the competitive
landscape and the legal wording live — the README links here rather than restating, so there is one
place to correct when the landscape moves.
