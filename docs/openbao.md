# OpenBao Transit provider

Install `cryptalis[openbao]`. OpenBao support uses the existing envelope-root and
`KeyProvider` abstraction. Application data still uses CF1 AES-256-GCM-SIV;
OpenBao wraps the 32-byte payload and search roots with its AES-256-GCM Transit key.
Local integration is verified against OpenBao 2.7.2 and hvac 2.4.0. Cryptalis and
this provider are not production-security-qualified.

An operator provisions a Transit key before application startup. Use a generated
`aes256-gcm96` key with derivation, export, plaintext backup and deletion disabled.
Pin a specific version. Do not grant the application key administration, export,
backup, token administration or `create` on the encrypt endpoint. For a mount `transit`
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

## AppRole workload authentication

`OpenBaoAppRoleToken` obtains a fresh bounded service token from an existing
AppRole and plugs into the provider's existing callback. It suppresses hvac's
ambient token discovery, verifies the issued role name and exact policy set,
rejects additional identity policies, and bounds the token lease. It then reads
the exact role using that token and requires SecretID binding, a finite positive
role SecretID TTL and matching service-token policies before returning the token.
Unknown or unreadable role configuration refuses authentication.

The operator configures an AppRole with `bind_secret_id=true`, a finite
`secret_id_ttl`, `token_type=service`, `token_num_uses=0`,
`token_no_default_policy=true`, and token TTL/maximum/explicit maximum within the
application's approved bound. Add only the exact role-read permission to the
Transit policy above, for example:

```hcl
path "auth/approle/role/cryptalis-runtime" { capabilities = ["read"] }
```

Deliver RoleID and expiring SecretID through the host's credential mechanism;
the runtime cannot generate its own SecretIDs or change its role. A one-use
SecretID needs a fresh delivered value for each login. Existing old SecretIDs,
delivery security, native policy contents, CIDR restrictions and their retirement
remain host duties. A current role read cannot prove the history of earlier
credentials or prevent a later administrator change.

```python
from cryptalis.crypto.openbao import OpenBaoAppRoleToken

authentication = OpenBaoAppRoleToken(
    endpoint="https://bao.example.com:8200",
    role_name="cryptalis-runtime",
    role_id=approved_role_id,
    secret_id=current_workload_secret_id,  # Synchronous callback; never logged.
    policies=("cryptalis-runtime",),
    max_token_ttl=60,
)
# Pass token=authentication when constructing OpenBaoTransitKeyProvider.
```

Set the same explicit CA trust and endpoint on the authenticator and provider.
The authenticator caches no token, renews none and performs no automatic retry.
It owns and closes each login/role-inspection SDK session; root caching remains
Keyring's responsibility. Create it afresh after fork. It never enables an auth
method, creates a role, mints a SecretID or changes policy.

`ProviderAuthenticationUnavailable` is a `KeyUnavailable` subtype, with
`effects="UNKNOWN"` and `retryable=False`. A login or failed response check may
already have issued a native token. Inspect credentials, policy and service
issuance before retry. The safe error survives root creation, Keyring sync/async
preparation and supported cross-provider rewrap without exposing its raw cause.
Plaintext keys and issued credentials have no verified Python zeroization claim.

The real local suite exercises least-privilege AppRole access, used-up SecretID
refusal and callback recovery, incorrect identities, policy/lease drift, disabled
SecretID binding, unbounded SecretID lifetime, missing role-read permission and
the native PostgreSQL protection/edit/removal journey. These checks do not
qualify production workload identity, secure credential distribution or HA.

The isolated Raft snapshot journey also restores AppRole authentication to a
new TLS endpoint while the source service remains stopped. The original
authentication endpoint refuses; fresh target authentication recovers cold roots
and authenticated values. This does not qualify production credential delivery
or combined database/provider disaster recovery.

## Diagnose current provider access

To check current provider access, return the application's existing policy
keyrings from a trusted synchronous host factory:

```python
def provider_diagnostics():
    return (application_keyring,)
```

```console
cryptalis doctor --provider-context myapp.security:provider_diagnostics --json
```

Use up to 16 Keyrings per diagnostic. The command checks every admitted root
without using or extending the caller cache and without a database connection.
Python callers can use `cryptalis.doctor.check_keys((application_keyring,))`.
An access PASS remains an aggregate UNKNOWN: it does not prove stored-frame
integrity, backup recoverability or production custody. Failed access exits 4;
invalid context exits 2. An empty tuple exits 4 with UNKNOWN access. Host factory
effects remain UNKNOWN. Do not place tokens or wrapped roots in command arguments.

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

Local qualification uses real HTTPS servers, private CAs, single-node Raft
storage and separate admin/runtime tokens. It covers independent snapshot
recovery on a fresh isolated service. It does not qualify HA, secure unsealing,
protected audit storage, production disaster recovery or controlled destruction.
Independent security review and all applicable release gates remain
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
concurrency, outage/lease/sealed-restart, independent snapshot recovery and
PostgreSQL lifecycle checks. A
passing result requires no skips. Service setup uses a longer timeout than
runtime key operations; ambiguous initialization failure is not retried.

Use the clean installed interpreter and `--installed-wheel /absolute/package.whl`
to bind every imported Cryptalis module to the inspected artifact. Release CI
uses this route and exports an SBOM with both `--extra openbao` and
`--extra sqlmodel`. Default SBOM exports continue to cover the base package only.

The services stop on exit. The private directory, service keys and containers are
retained for inspection; no automatic key deletion is performed. The report
records cleanup failures even when another failure occurred first. Only
`tests.json` and `qualification.json` are public evidence candidates. Never
upload the complete work directory, initialization JSON, TLS private key,
service logs or database credentials. The single-share test unseal arrangement
is unsuitable for production.

The snapshot drill creates a second instance with new TLS credentials and empty
Raft storage. It verifies refusal of mismatched-seal and malformed snapshots,
stops the original service, and restores only into that newly initialized test
target. The documented force-restore API permits importing a different seal;
the original unseal material is still required. The drill confirms cold key
preparation and CF1 decryption at the new endpoint, and confirms that a key
created after the snapshot is absent. The original service stays stopped until
the recovered target stops successfully. Snapshot and bootstrap secrets remain
in the private work directory. This proves the listed local recovery behavior;
production fencing, secure backup custody, retention, RPO/RTO and independent
disaster-recovery acceptance remain unqualified.
