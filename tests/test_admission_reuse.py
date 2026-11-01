"""Hot-path shortcuts must not outlive the facts they skip re-checking."""

from dataclasses import replace
from uuid import uuid4

import pytest
from sqlalchemy import event, select

from cryptalis.crypto import DevelopmentKeyProvider
from cryptalis.crypto.keys import Keyring
from cryptalis.sqlalchemy import PolicyMismatch, UnsupportedProtectedOperation
from test_migration import application, TENANT
from test_project import protect, restart


def attached(app, tmp_path):
    provider = DevelopmentKeyProvider()
    protect(app, restart(app, provider, tmp_path / 'state'))
    process = restart(app, provider, tmp_path / 'state')
    return process, process.project.attach(process.runtime)


@pytest.mark.parametrize('predicate', ['unsupported', 'plaintext'])
def test_a_statement_replaced_after_admission_cannot_vouch_for_itself(tmp_path, predicate):
    with application(unique=False, queries=[]) as app:
        process, sessions = attached(app, tmp_path)
        name = process.Customer.name
        replacement = select(process.Customer).where(name.like('%') if predicate == 'unsupported' else name == 'plaintext')

        @event.listens_for(process.runtime, 'before_execute', retval=True)
        def replace_statement(connection, statement, multiparams, params, options):
            return replacement, multiparams, params

        with sessions(tenant_id=TENANT) as session, pytest.raises(UnsupportedProtectedOperation):
            session.execute(select(process.Customer.id))


def test_a_different_policy_is_refused_after_the_first_one_passed(tmp_path):
    with application() as app:
        process, sessions = attached(app, tmp_path)
        with sessions(tenant_id=TENANT) as session:
            session.scalars(select(process.Customer.id)).all()
        owner = sessions._owner
        ring = owner.keys(TENANT)
        policy, wrapper = ring.policy, ring.policy.wrappers[0]
        generation = policy.payload_generation + 1
        added = replace(wrapper, context=replace(wrapper.context, generation=generation, root_id=uuid4()))

        # An equal policy in a new object repeats the full check and passes.
        owner.keys = lambda tenant: Keyring(replace(policy), ring._providers)
        with sessions(tenant_id=TENANT) as session:
            session.scalars(select(process.Customer.id)).all()

        owner.keys = lambda tenant: Keyring(
            replace(policy, payload_generation=generation, wrappers=(*policy.wrappers, added)), ring._providers)
        with pytest.raises(PolicyMismatch), sessions(tenant_id=TENANT):
            pass
