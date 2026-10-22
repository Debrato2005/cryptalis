"""Independent rewrap executor with public fixture material only.

The parent test admits database access through the PostgreSQL wrapper. This
worker reloads host artifacts and reconstructs fixture keys in a fresh process.
No development-provider KEK or root material passes between processes.
"""
from dataclasses import replace
import json
from pathlib import Path
import signal
import sys
from uuid import UUID

from cryptalis import migration as m, rotation as r
from cryptalis.crypto import Keyring
from cryptalis.crypto.keys import KeyUnavailable, WrappedRoot
from test_migration import engine, keys, PROVIDER, PublicFixtureProvider


TARGET_PROVIDER = UUID(int=9501)
TARGET_WRAPPER = b'PUBLIC REWRAP WORKER WRAPPER'


class PublicRewrapProvider:
    """Distinct synthetic custody for the existing public source roots."""

    provider_id = TARGET_PROVIDER

    def unwrap(self, wrapper, context):
        if (not isinstance(wrapper, WrappedRoot)
                or wrapper.provider_id != self.provider_id
                or wrapper.context != context or wrapper.sealed != TARGET_WRAPPER):
            raise KeyUnavailable()
        original = WrappedRoot(PROVIDER, context, b'PUBLIC TEST WRAPPER')
        return PublicFixtureProvider().unwrap(original, context)

    async def unwrap_async(self, wrapper, context):
        return self.unwrap(wrapper, context)


def target_keys(tenant):
    """Preserve source contexts and roots with distinct fixture wrappers."""
    source = keys(tenant)
    provider = PublicRewrapProvider()
    wrappers = tuple(WrappedRoot(provider.provider_id, item.context, TARGET_WRAPPER)
                     for item in source.policy.wrappers)
    return Keyring(replace(source.policy, wrappers=wrappers),
                   {provider.provider_id: provider})


def _execute(argv):
    connection_engine = None
    try:
        proposal_path, pin_path, approval_path, action, pause = argv
        if action not in ('pending', 'activate') or pause not in ('pause', 'exit'):
            raise ValueError
        proposal = r.RewrapPlan(Path(proposal_path).read_bytes())
        successor = proposal.activation_plan
        pin_document = json.loads(Path(pin_path).read_text())
        pin_document.update(target_id=UUID(pin_document['target_id']),
                            operation_id=UUID(pin_document['operation_id']))
        pin = m.DeploymentPin(**pin_document)
        approval = m.MaintenanceApproval(**json.loads(Path(approval_path).read_text()))
        if action == 'activate' and pin.phase != 'ACTIVATING':
            raise m.TransitionFailure('matching_external_publication_required', successor.operation_id)
        connection_engine = engine('CRYPTALIS_TEST_DATABASE_URL')
        if action == 'pending':
            result = r.apply_rewrap(proposal, connection_engine, keys=keys,
                                    target_keys=target_keys, pin=pin, approval=approval)
            if result.phase != 'PENDING':
                raise m.TransitionFailure('worker_expected_pending', successor.operation_id)
            output = {'phase': 'PENDING'}
        else:
            pending_pin = replace(pin, phase='PENDING')
            observed = m.status(successor, connection_engine, pin=pending_pin)
            if observed.phase != 'PENDING':
                raise m.TransitionFailure('worker_expected_pending', successor.operation_id)
            r.apply_rewrap(proposal, connection_engine, keys=keys,
                           target_keys=target_keys, pin=pending_pin, approval=approval)
            result = m.apply(successor, connection_engine, keys=target_keys,
                             pin=pin, approval=approval, until='ACTIVE')
            if result.phase != 'ACTIVE':
                raise m.TransitionFailure('worker_expected_active', successor.operation_id)
            output = {'observed': observed.phase, 'phase': result.phase,
                      'operation_id': str(successor.operation_id), 'digest': successor.digest}
        return output, pause
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
