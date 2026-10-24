"""Independent payload-rotation worker with public fixture material only.

The parent test admits database access through the PostgreSQL wrapper. This
worker reloads host artifacts and reconstructs fixture keys in a fresh process.
No root material or development-provider KEK passes between processes.
"""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import signal
import sys
from uuid import UUID, uuid5

from cryptalis import migration as m, rotation as r
from cryptalis.crypto import KeyContext, Keyring
from cryptalis.crypto.keys import KeyUnavailable, WrappedRoot
from test_migration import DOMAIN, PROVIDER, PublicFixtureProvider, engine, keys
from rewrap_worker import PublicRewrapProvider, target_keys as rewrap_keys


TARGET_PROVIDER = UUID(int=9511)
TARGET_WRAPPER = b'PUBLIC PAYLOAD WORKER WRAPPER'


def target_context(tenant):
    return KeyContext(DOMAIN, tenant, 'payload',
                      uuid5(DOMAIN, f'payload-worker:{tenant}:2'), 2)


class PublicPayloadProvider:
    """Synthetic custody for one new independent public payload root."""

    provider_id = TARGET_PROVIDER

    def unwrap(self, wrapper, context):
        if (not isinstance(context, KeyContext)
                or not isinstance(wrapper, WrappedRoot)
                or context != target_context(context.tenant_id)
                or wrapper.provider_id != self.provider_id
                or wrapper.context != context or wrapper.sealed != TARGET_WRAPPER):
            raise KeyUnavailable()
        return hashlib.sha256(b'PUBLIC PAYLOAD WORKER ROOT' + context.tenant_id.bytes
                              + context.generation.to_bytes(4, 'big')).digest()

    async def unwrap_async(self, wrapper, context):
        return self.unwrap(wrapper, context)


def target_keys(tenant):
    """Retain original wrappers and select the new public payload generation."""
    source = keys(tenant)
    if source.policy.payload_generation != 1:
        raise KeyUnavailable()
    provider = PublicPayloadProvider()
    wrapper = WrappedRoot(provider.provider_id, target_context(tenant), TARGET_WRAPPER)
    policy = replace(source.policy, wrappers=source.policy.wrappers + (wrapper,),
                     payload_generation=2)
    return Keyring(policy, {PROVIDER: PublicFixtureProvider(), provider.provider_id: provider})


def rotated_keys(tenant):
    """Keep the public rewrapped readers and add the existing public payload root."""
    old = rewrap_keys(tenant)
    rewrap, payload = PublicRewrapProvider(), PublicPayloadProvider()
    wrapper = WrappedRoot(payload.provider_id, target_context(tenant), TARGET_WRAPPER)
    return Keyring(replace(old.policy, wrappers=old.policy.wrappers + (wrapper,), payload_generation=2),
                   {rewrap.provider_id: rewrap, payload.provider_id: payload})


def _execute(argv):
    connection_engine = None
    try:
        proposal_path, pin_path, approval_path, action, pause = argv
        if action not in ('expand', 'chunk', 'resume', 'abort', 'status') or pause not in ('pause', 'exit'):
            raise ValueError()
        proposal = r.PayloadRotationPlan(Path(proposal_path).read_bytes())
        pin_document = json.loads(Path(pin_path).read_text())
        pin_document.update(target_id=UUID(pin_document['target_id']),
                            operation_id=UUID(pin_document['operation_id']))
        pin = m.DeploymentPin(**pin_document)
        approval = m.MaintenanceApproval(**json.loads(Path(approval_path).read_text()))
        connection_engine = engine('CRYPTALIS_TEST_DATABASE_URL')
        if action == 'status':
            result = r.status_payload_rotation(proposal, connection_engine, pin=pin)
        elif action == 'abort':
            result = r.abort_payload_rotation(proposal, connection_engine, keys=keys,
                                              source_pin=pin, approval=approval)
        else:
            result = r.apply_payload_rotation(
                proposal, connection_engine, keys=keys, target_keys=target_keys,
                pin=pin, approval=approval,
                until='EXPANDED' if action == 'expand' else 'BACKFILLED',
                max_chunks=1 if action == 'chunk' else None)
        return {'phase': result.phase, 'rows': result.committed_rows,
                'chunks': result.committed_chunks, 'operation_id': str(result.operation_id),
                'digest': proposal.digest}, pause
    finally:
        if connection_engine is not None:
            connection_engine.dispose()


def main(argv=None):
    try:
        output, pause = _execute(sys.argv[1:] if argv is None else argv)
        print(json.dumps(output), flush=True)
        if pause == 'pause':
            signal.pause()
        return 0
    except Exception as error:
        output = {'type': type(error).__name__}
        if isinstance(error, m.TransitionFailure):
            output['code'] = error.code
        print(json.dumps(output), flush=True)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
