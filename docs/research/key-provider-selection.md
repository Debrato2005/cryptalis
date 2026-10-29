# Practical key-provider selection

Retrieved 2026-10-29 UTC. This record informs implementation; [security](../security.md)
owns the contract and [status](../status.md) owns verified capability claims.

| Provider | Fit and cost evidence | Decision |
|---|---|---|
| OpenBao Transit | MPL-2.0 software, no cloud per-key/API fee. Operators fund and secure infrastructure, authentication, unsealing, audit, backup and availability. API supplies AEAD AAD, explicit versions and nonexportable keys. | Preferred self-hosted option; implement optional adapter and real local tests. |
| Vault Transit | Mature matching envelope API. Current source uses BSL 1.1 with an additional-use grant; evaluate deployment terms separately. Self-hosting still has operational costs. | Do not add a duplicate adapter or claim compatibility without a distinct requirement and tested service version. |
| AWS KMS | Existing adapter pins full key ARN and EncryptionContext. Published customer-key storage is $1/month; the first two rotations each add $1/month. 20,000 eligible requests/month are free; exclusions apply. | Retain optional adapter. Live cloud/IAM evidence remains unavailable; no resources provisioned. |
| Google Cloud KMS | Software active-version pricing is about $0.06/month; cryptographic operations $0.03/10,000. Free-key eligibility is Autokey-specific. Billing enrollment is required. Managed envelope encryption fits existing roots. | Suitable future managed option; defer an adapter until an authorized live cell and workload requirement justify it. |
| Azure Key Vault | Managed wrapping with software/HSM options. The retrieved pricing page rendered numeric prices as `$-`; exact pricing is UNKNOWN for this retrieval. | No Azure-specific requirement or live account; no adapter added. |
| Local development provider | Existing ephemeral in-process test provider; no remote custody, operational isolation or durable key recovery. | Development only; cannot qualify production. |

The existing protocol and root policy already provide vendor independence. Keep
independent payload/search roots, finite Keyring leases, CF1 context binding and
verified rewrap. A new service does not require a new data-encryption format or
custom primitive. Use the maintained hvac HTTP client, verified TLS, explicit
versioning and narrow runtime policy. Runtime key upsert is refused. The
service's wrapping primitive is separate from CF1 payload encryption.

OpenBao's encrypt endpoint treats `create` permission as key-upsert authority;
`update` alone refuses a missing key. AAD is supported for AEAD keys. A derived
key's `context` is a different facility and is not used. Administrative minimum
versions can be changed again; version revocation is not destruction. Server
metadata reads and TLS authenticate observations, not future administrator
behavior or correct production operation.

Official sources inspected:

- [OpenBao Transit API](https://openbao.org/docs/api/secret/transit/),
  [Transit operations](https://openbao.org/docs/secrets/transit/), and
  [Raft storage](https://openbao.org/docs/configuration/storage/raft/).
  Source pinned to tag 2.7.2, commit `9e0a0d3c3504a0a00b45e61355afac5e35c78379`.
  API and storage source were read directly from this checkout.
- [OpenBao license](https://github.com/openbao/openbao/blob/v2.7.2/LICENSE).
  Source retains HashiCorp copyright and MPL-2.0 notices. No upstream source is
  copied into the adapter.
- [hvac 2.4.0 client](https://github.com/hvac/hvac/blob/v2.4.0/hvac/v1/__init__.py)
  and [HTTP adapter](https://github.com/hvac/hvac/blob/v2.4.0/hvac/adapters.py).
  TLS verification, redirect control, timeout and session ownership were checked
  in exact-tag raw source. Dependency distributions retain upstream notices.
- [Vault Transit API](https://developer.hashicorp.com/vault/api-docs/secret/transit)
  and [current license](https://github.com/hashicorp/vault/blob/main/LICENSE).
- [AWS pricing](https://aws.amazon.com/kms/pricing/).
- [Google pricing](https://cloud.google.com/kms/pricing) and
  [envelope-encryption guide](https://docs.cloud.google.com/kms/docs/envelope-encryption).
- [Azure pricing](https://azure.microsoft.com/en-us/pricing/details/key-vault/).

Successful retrievals had relevant official titles/body passages; raw files and
the pinned Git tree supplied source evidence. The initial obsolete OpenBao
`api-docs` URL and old repository path did not retrieve the API. They are failed
retrievals, not evidence. Initial local service setup also exposed incompatible
older Vault-style `file` storage/`disable_mlock` settings; the working OpenBao
2.7.2 setup uses the documented Raft backend. This does not qualify an upgrade
from an earlier service version.

Local service tests can establish real cryptographic and API behavior without
cloud charges. They cannot replace independent review, HA/outage/recovery drills,
production identity controls, provider-side audit verification or destruction
proof covering backups and all retained copies.
