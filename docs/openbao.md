# OpenBao Transit provider

Install `cryptalis[openbao]`. OpenBao support uses the existing envelope-root and
`KeyProvider` abstraction. Application data still uses CF1 AES-256-GCM-SIV;
OpenBao wraps the 32-byte payload and search roots with its AES-256-GCM Transit key.
Local integration is verified against OpenBao 2.7.2 and hvac 2.4.0. Cryptalis and
this provider are not production-security-qualified.

An operator provisions a Transit key before application startup. Use a generated
`aes256-gcm96` key with derivation, export, plaintext backup and deletion disabled.
Pin a specific version. Do not grant the application key administration, export,
backup, token minting or `create` on the encrypt endpoint. For a mount `transit`
and key `cryptalis`, the runtime policy needs only:

```hcl
path "transit/keys/cryptalis" { capabilities = ["read"] }
path "transit/encrypt/cryptalis" { capabilities = ["update"] }
path "transit/decrypt/cryptalis" { capabilities = ["update"] }
```

Construct the provider with an authenticated HTTPS endpoint and a callback that
returns a current least-privilege token. Keep authentication secrets out of the
manifest, database, command arguments and logs. For example:

```python
from uuid import UUID
from cryptalis.crypto.openbao import OpenBaoTransitKeyProvider

provider = OpenBaoTransitKeyProvider(
    endpoint="https://bao.example.com:8200",
    token=current_workload_token,  # Host authentication/renewal callback.
    provider_id=UUID("8b0d8bf4-4ca9-48a6-9d01-b375ae4fbf44"),
    mount="transit",
    key_name="cryptalis",
    key_version=1,
    timeout=10,
)
```

For a private CA, supply `ca_cert` as an absolute CA-bundle filename. HTTP,
disabled TLS verification and redirects are refused. HA deployments must route
the configured endpoint to a service that handles the request without redirecting.
The host owns endpoint routing, proxy trust, token renewal and service operations.
Construct a new provider after fork. The adapter opens and closes an SDK session
per operation and obtains a fresh token each time. Keyring retains bounded root
caching; this avoids network calls for each record. Cold wrap/unwrap costs one
metadata read and one cryptographic request per root.

Supply this provider through the existing key-policy resolver used by planning,
attachment and lifecycle operations. No application model or query changes are
required specifically for OpenBao. Provider credentials are not manifest fields.
Full automatic setup and host-factory simplification remain separate work.

For key rotation, provision the new service version, construct the successor
provider with an explicit version and distinct provider UUID, then use the
existing verified root-rewrap lifecycle. Retain old versions until retained
data and backups no longer require them. Payload/search generation rotation
remains a separate Cryptalis lifecycle. The adapter never rotates or deletes a
service key itself.

Service errors, wrong context, missing or revoked versions, malformed replies
and unsafe key metadata fail with `KeyUnavailable`. No raw SDK exception is
included in its displayed traceback. The callback must not log its token.
Individual SDK timeouts are bounded; callback duration and overall operation
duration are not. Cancellation can leave a remote request running, although no
late result is published into Keyring. Revocation cannot erase an already cached
root; existing lease expiry still applies.

Local qualification uses a real HTTPS server, private CA, single-node Raft
storage and separate admin/runtime tokens. It does not qualify HA, secure
unsealing, protected audit storage, service disaster recovery or controlled
destruction. Independent security review and all applicable release gates remain
required. See [security](security.md#optional-openbao-transit-adapter).

## Repeatable local qualification

The Linux qualification runner requires a working local Docker daemon, the
OpenBao extra and an already authorized disposable PostgreSQL 16 test target.
Configure the three private owner/runtime/source URL files through
`CRYPTALIS_TEST_CONFIG_DIR`. The runner probes that target through the mandatory
wrapper before it creates a service. It does not create or substitute PostgreSQL.

```console
.venv/bin/python scripts/openbao_qualification.py --workdir /absolute/private/new-run
```

The work directory must not exist; its parent must exist. The runner creates a
digest-pinned OpenBao 2.7.2 container, a short-lived private test CA, TLS keys,
single-node Raft storage and test initialization credentials. It pins a loopback
port across restart, drops container capabilities and uses a read-only container
root with one private writable mount. It runs the protocol, actual-service,
concurrency, outage/lease/sealed-restart and PostgreSQL lifecycle checks. A
passing result requires no skips. Service setup uses a longer timeout than
runtime key operations; ambiguous initialization failure is not retried.

Use the clean installed interpreter and `--installed-wheel /absolute/package.whl`
to bind every imported Cryptalis module to the inspected artifact. Release CI
uses this route and exports an SBOM with both `--extra openbao` and
`--extra sqlmodel`. Default SBOM exports continue to cover the base package only.

The service stops on exit. The private directory, service keys and container are
retained for inspection; no automatic key deletion is performed. The report
records cleanup failures even when another failure occurred first. Only
`tests.json` and `qualification.json` are public evidence candidates. Never
upload the complete work directory, initialization JSON, TLS private key,
service logs or database credentials. The single-share test unseal arrangement
is unsuitable for production. A retained-node restart is not an independent
snapshot restore or disaster-recovery qualification.
