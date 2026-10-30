# Google Cloud KMS provider

`cryptalis.crypto.google_kms.GoogleKmsKeyProvider` implements the common
`KeyProvider` protocol using the pinned Google Python SDK. It wraps independent
32-byte roots; CF1 still encrypts application values locally with AES-256-GCM-SIV.
**Live Google custody, IAM and production operation are not qualified.**

## Configure an existing key

Install `cryptalis[gcp]`. The optional dependencies pin `google-cloud-kms==3.18.0`
and `google-crc32c==1.9.0`; the core package has no Google dependency. Supply a
host-owned synchronous `KeyManagementServiceClient`, authenticated TLS transport
and least-privilege credentials for an existing enabled `ENCRYPT_DECRYPT` version.
The runtime needs `cloudkms.cryptoKeyVersions.useToEncrypt` and
`cloudkms.cryptoKeyVersions.useToDecrypt`, not administrative permissions.

```python
from uuid import UUID
from google.cloud import kms_v1
from cryptalis.crypto.google_kms import GoogleKmsKeyProvider

client = kms_v1.KeyManagementServiceClient()  # host-configured credentials
provider = GoogleKmsKeyProvider(
    client,
    provider_id=UUID("24a8b671-a013-4130-9ebf-7785c0d567df"),
    key_version="projects/example-project/locations/global/keyRings/app/cryptoKeys/roots/cryptoKeyVersions/1",
    protection_level="SOFTWARE",
    timeout=10,
)
```

Use the host's existing key-policy resolver to supply this provider to
[ApplicationConfig](application.md), runtime attachment and lifecycle commands.
The provider UUID is a deployment identity, not a Google workload identity.
Keep its resource mapping outside database-controlled state. Credentials and SDK
debug logging remain host responsibilities; do not log RPC bodies, roots or their
plaintext checksums. The host closes the client after its users stop. Construct
a fresh client and provider in each child process.

`key_version` must be a full version resource. Primary-key aliases, ambiguous
paths and version zero refuse. `SOFTWARE` and `HSM` are explicit choices; other
protection levels are unadmitted. The response must match the configured level.
Every call sets a finite timeout, up to 60 seconds, and disables SDK retries.
Errors become typed, redacted `KeyUnavailable`; no local fallback occurs.

## Integrity and version limits

AAD binds the provider UUID, configured encryption version, protection level,
domain, tenant, root identity, purpose and generation. Requests carry CRC32C for
root/ciphertext and AAD. Encryption requires both server verification flags, the
exact returned version name, and the ciphertext checksum. Decryption requires a
present matching plaintext checksum and exactly 32 returned bytes. Checksums
detect corruption; authenticated KMS encryption supplies cryptographic integrity.
No plaintext checksum is persisted in a wrapper.

Google's decrypt request names the parent CryptoKey. The service chooses the
version internally, and its decrypt response does **not** identify that version.
AAD still binds the configured version, but the adapter does not claim an
independent observation of the decrypting version. Do not substitute its
`used_primary` flag for that missing identity. Provider-native revocation,
retirement and deletion need separate live evidence.

Keyring retains its bounded root leases. Cancellation discards a late SDK result
but cannot stop an already dispatched blocking request. Rewrap unwraps through
the source, wraps with the explicit destination and verifies recovered bytes.
It performs no provider key administration and does not retire old wrappers.
Python bytes do not provide a verified zeroization guarantee.

## Verification and live qualification

The local suite uses the actual Google SDK and protobuf request/response types
with a local opaque-handle transport. It exercises checksums, AAD/resource/level
mismatch, redacted failure, no retries, cancellation, real fork refusal, cross-
provider rewrap and a real PostgreSQL protection/edit/decrypt-back/removal journey.
It is **not** a live Google service test. The installed release harness runs the
same checks and refuses skipped Google tests. Exact receipts live in [status](status.md).

The opt-in [live test](../tests/test_google_kms_live.py) uses an existing key and
host Application Default Credentials. Before running it, obtain explicit account
and API-cost authorization, choose a dedicated test key, and configure its narrow
principal. Do not use production key material. No key is created, disabled,
rotated or deleted by this test.

Create an absolute, owner-only regular configuration file outside the repository:

```json
{
  "provider_id": "24a8b671-a013-4130-9ebf-7785c0d567df",
  "key_version": "projects/example-project/locations/global/keyRings/app/cryptoKeys/roots/cryptoKeyVersions/1",
  "protection_level": "SOFTWARE"
}
```

After authorization and the [usual private test-target setup](local-development.md),
run with a new receipt path:

```console
CRYPTALIS_GOOGLE_KMS_LIVE_APPROVED=1 CRYPTALIS_GOOGLE_KMS_LIVE_CONFIG=/private/google-test.json .venv/bin/python scripts/test_postgres.py --receipt work/google-live.json -- tests/test_google_kms_live.py -q
```

Without explicit opt-in, the test reports a collection skip. A live pass would
establish only its context-binding and cold root/CF1 recovery checks, including a
fresh positive control after negative service calls. Workload identity/IAM
variants, provider outage, native version revocation, backup custody, combined
database/provider recovery, controlled destruction, audit and independent review
remain separate requirements. No live account or billable call was used for the
local SDK evidence.

The [provider comparison](research/key-provider-selection.md) retains source and
cost evidence. The [security contract](security.md#optional-google-cloud-kms-adapter)
owns this provider's trust boundary.
