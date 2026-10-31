"""Opt-in, billable calls to an existing explicitly authorized Google key.

No key administration, creation, disabling, retirement or deletion occurs here.
Absent authorization is a collection skip, never live custody evidence.
"""
import json
import os
from pathlib import Path
import stat
from dataclasses import replace
from uuid import UUID, uuid4

import pytest

if os.environ.get('CRYPTALIS_GOOGLE_KMS_LIVE_APPROVED') != '1':
    pytest.skip('live Google KMS requires explicit account/cost authorization', allow_module_level=True)

from google.api_core.client_options import ClientOptions
from google.cloud import kms_v1

from cryptalis.crypto import KeyContext, KeyPolicy, Keyring, KeyUnavailable, WrappedRoot, create_root, open_text, seal_text
from cryptalis.crypto.google_kms import GoogleKmsKeyProvider
from test_cf1 import descriptor


def test_authorized_google_key_context_and_cf1():
    try:
        path = Path(os.environ['CRYPTALIS_GOOGLE_KMS_LIVE_CONFIG'])
        info = path.lstat()
        if (not path.is_absolute() or not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid() or info.st_mode & 0o077 or not 0 < info.st_size <= 65536):
            raise ValueError
        config = json.loads(path.read_bytes())
        if set(config) != {'provider_id', 'key_version', 'protection_level'}:
            raise ValueError
        identity = UUID(config['provider_id'])
    except Exception:
        pytest.fail('Supply an absolute, owner-only regular Google test configuration with exact provider fields.', pytrace=False)
    # ADC is supplied by the authorized host, never by a wrapper or database row.
    client = kms_v1.KeyManagementServiceClient(client_options=ClientOptions(api_endpoint='cloudkms.googleapis.com'))
    try:
        service = GoogleKmsKeyProvider(client, provider_id=identity,
            key_version=config['key_version'], protection_level=config['protection_level'])
        context = KeyContext(UUID(int=1), UUID(int=4), 'payload', uuid4(), 1)
        wrapped = create_root(service, context)
        ring = Keyring(KeyPolicy(context.domain_id, context.tenant_id, (wrapped,), 1), {identity: service})
        prepared = ring.prepare()
        frame = seal_text('public Google qualification fixture', descriptor(), context.tenant_id, UUID(int=5), prepared)
        changed = replace(context, tenant_id=UUID(int=6))
        with pytest.raises(KeyUnavailable):
            service.unwrap(WrappedRoot(identity, changed, wrapped.sealed), changed)
        other = GoogleKmsKeyProvider(client, provider_id=uuid4(), key_version=config['key_version'],
                                    protection_level=config['protection_level'])
        with pytest.raises(KeyUnavailable):
            other.unwrap(WrappedRoot(other.provider_id, context, wrapped.sealed), context)
        # Fresh positive control after the negative service calls rules out a bare outage.
        recovered = Keyring(ring.policy, {identity: service}).prepare()
        assert open_text(frame, descriptor(), context.tenant_id, UUID(int=5), recovered) == 'public Google qualification fixture'
    finally:
        client.transport.close()
