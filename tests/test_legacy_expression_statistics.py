"""Legacy-layout late expression-statistics admission and exact repair."""
from contextlib import contextmanager
from dataclasses import replace
import json
from uuid import uuid4

import pytest
from sqlalchemy import Boolean, String

from cryptalis import deprotection as d, migration as m
from cryptalis.manifest.compiler import SearchReview, Writer, WriterInventory
from test_migration import application, keys, publish, run, FIELD_ID, TABLE_ID
from test_owned_sequences import _snapshot, facts, finish_reverse, install_sequence
import test_deprotection as reverse


@contextmanager
def legacy_application(kind, sequence):
    options = {'rows': 3}
    if kind == 'varchar':
        options['value_type'] = String(64, collation='C')
    elif kind == 'boolean':
        options.update(value_type=Boolean(), queries=[], protected_values=(None, True, False))
    with application(setup=install_sequence if sequence else None, **options) as app:
        # Select the public legacy route explicitly, rather than relying on its default.
        app.plan = m.plan(json.dumps(app.plan.document['lock']['declaration']).encode(),
            app.mapping, app.owner, layout=None,
            writers=WriterInventory(True, (
                Writer(TABLE_ID, 'app', 'sqlalchemy', evidence='owned synthetic application'),)),
            search_reviews=(SearchReview(FIELD_ID, False, 'synthetic unbounded names'),)
                if kind != 'boolean' else (),
            keys=keys, runtime_role=app.role, target_id=uuid4(),
            backfill_rows_per_second=1000, verify_rows_per_second=1000,
            temporary_bytes_per_row=700, wal_bytes_per_row=2000)
        app.pin = m.DeploymentPin(app.plan.target_id, app.plan.operation_id,
                                 app.plan.digest, 'PREPARED')
        version = 5 if sequence else {'text': 2, 'varchar': 3, 'boolean': 4}[kind]
        assert app.plan.document['lock']['schema'] == f'cryptalis.lock/v{version}'
        assert 'layout' not in app.plan.document['lock']
        yield app


@contextmanager
def late_statistics(app, sequence):
    statistics = f'"{app.schema}".late_expression_statistics'
    with app.owner.begin() as connection:
        connection.exec_driver_sql(f'CREATE STATISTICS {statistics} '
            f'ON (pg_catalog.octet_length(name::text)) FROM "{app.schema}".customer')
        assert connection.exec_driver_sql(
            'SELECT s.stxexprs IS NOT NULL AND cardinality(s.stxkeys::int2[])=0 '
            'FROM pg_catalog.pg_statistic_ext s '
            'JOIN pg_catalog.pg_namespace n ON n.oid=s.stxnamespace '
            "WHERE n.nspname=%s AND s.stxname='late_expression_statistics'",
            (app.schema,)).scalar_one() is True
    before, calls = _snapshot(app), []
    sequence_before = facts(app) if sequence else None

    def forbidden(tenant):
        calls.append(tenant)
        pytest.fail('late unadmitted expression statistics reached key resolution')

    try:
        yield forbidden
        assert calls == [] and _snapshot(app) == before
        if sequence:
            assert facts(app) == sequence_before
        with app.owner.connect() as connection:
            assert connection.exec_driver_sql(
                'SELECT count(*) FROM pg_catalog.pg_statistic_ext s '
                'JOIN pg_catalog.pg_namespace n ON n.oid=s.stxnamespace '
                "WHERE n.nspname=%s AND s.stxname='late_expression_statistics'",
                (app.schema,)).scalar_one() == 1
    finally:
        with app.owner.begin() as connection:
            connection.exec_driver_sql(f'DROP STATISTICS IF EXISTS {statistics}')


def refuse(operation):
    with pytest.raises(m.TransitionFailure) as failure:
        operation()
    assert failure.value.code == 'unsupported_dependency'


def remove(app, proposal, phase):
    consent, pin = reverse.consent(proposal, phase)
    removal = d.RemovalApproval(proposal.target_id, proposal.operation_id, proposal.digest,
        'unchanged native current-value reads', 'public disposable fixture only', True)
    return d.remove(proposal, app.owner, pin=pin, approval=app.approval,
                    removal=removal, consent=consent)


# Cover every legacy type/sequence selector at its initial and active boundary.
# Other lifecycle admissions use one sequence-bearing TEXT fixture, without a cross-product.
CASES = [pytest.param(kind, sequence, phase,
                     id=f'{kind}-{"sequence" if sequence else "plain"}-{phase}')
         for kind in ('text', 'varchar', 'boolean') for sequence in (False, True)
         for phase in ('planned', 'active')]
CASES += [pytest.param('text', True, phase, id=phase) for phase in (
    'expanded', 'pending', 'reverse_prepared', 'reverse_expanded',
    'plaintext_pending', 'plaintext_active', 'removed')]


@pytest.mark.parametrize('kind,sequence,phase', CASES)
def test_legacy_late_expression_statistics_refuse_before_keys_and_allow_repair(kind, sequence, phase):
    with legacy_application(kind, sequence) as app:
        original_sequence = facts(app) if sequence else None
        plaintext_role = reverse.least_privilege_role(app)
        proposal = None
        if phase == 'expanded':
            assert run(app, until='EXPANDED').phase == 'EXPANDED'
        elif phase != 'planned':
            assert run(app).phase == 'PENDING'
            if phase != 'pending':
                assert publish(app).phase == 'ACTIVE'
                if phase not in ('active',):
                    proposal = reverse.proposal(app)
                    if phase != 'reverse_prepared':
                        reverse_phase = 'EXPANDED' if phase == 'reverse_expanded' else 'PLAINTEXT_PENDING'
                        assert reverse.reverse(app, proposal, until=reverse_phase).phase == reverse_phase
                    if phase in ('plaintext_active', 'removed'):
                        consent, pin = reverse.consent(proposal, 'PLAINTEXT_ACTIVATING')
                        assert d.apply(proposal, app.owner, keys=keys, pin=pin, approval=app.approval,
                            consent=consent, until='PLAINTEXT_ACTIVE').phase == 'PLAINTEXT_ACTIVE'
                        if phase == 'removed':
                            assert remove(app, proposal, 'REMOVING').phase == 'REMOVED'

        with late_statistics(app, sequence) as forbidden:
            if phase in ('planned', 'expanded'):
                refuse(lambda: run(app, key_resolver=forbidden))
                refuse(lambda: m.status(app.plan, app.owner, pin=app.pin))
                if phase == 'expanded':
                    refuse(lambda: m.abort(app.plan, app.owner, pin=app.pin, approval=app.approval))
            elif phase == 'pending':
                refuse(lambda: run(app, until='ACTIVE', pin=replace(app.pin, phase='ACTIVATING'),
                                   key_resolver=forbidden))
                refuse(lambda: m.status(app.plan, app.owner, pin=app.pin))
            elif phase == 'active':
                refuse(lambda: d.plan(app.plan, app.owner, source_pin=app.pin, keys=forbidden,
                    plaintext_runtime_role=plaintext_role,
                    backfill_rows_per_second=1000, verify_rows_per_second=1000,
                    temporary_bytes_per_row=700, wal_bytes_per_row=700))
            elif phase == 'reverse_prepared':
                refuse(lambda: reverse.reverse(app, proposal, until='EXPANDED', key_resolver=forbidden))
            elif phase == 'reverse_expanded':
                consent, pin = reverse.consent(proposal)
                refuse(lambda: reverse.reverse(app, proposal, key_resolver=forbidden))
                refuse(lambda: d.status(proposal, app.owner, pin=pin))
                refuse(lambda: d.abort(proposal, app.owner, pin=pin,
                                      approval=app.approval, consent=consent))
            elif phase == 'plaintext_pending':
                consent, pin = reverse.consent(proposal, 'PLAINTEXT_ACTIVATING')
                refuse(lambda: d.apply(proposal, app.owner, keys=forbidden, pin=pin,
                    approval=app.approval, consent=consent, until='PLAINTEXT_ACTIVE'))
                refuse(lambda: d.status(proposal, app.owner,
                                        pin=reverse.app_pin(proposal, 'PLAINTEXT_PENDING')))
            elif phase == 'plaintext_active':
                refuse(lambda: remove(app, proposal, 'REMOVING'))
                refuse(lambda: d.status(proposal, app.owner,
                                        pin=reverse.app_pin(proposal, 'PLAINTEXT_ACTIVE')))
            else:
                removed_pin = reverse.app_pin(proposal, 'REMOVED')
                refuse(lambda: d.check_removed(proposal, app.owner, pin=removed_pin))
                refuse(lambda: remove(app, proposal, 'REMOVED'))

        # Removing only the late object restores the same plan's complete lifecycle.
        if phase in ('planned', 'expanded', 'pending'):
            assert run(app).phase == 'PENDING'
            assert publish(app).phase == 'ACTIVE'
        if proposal is None:
            proposal = reverse.proposal(app)
            assert reverse.reverse(app, proposal).phase == 'PLAINTEXT_PENDING'
        elif phase in ('reverse_prepared', 'reverse_expanded'):
            assert reverse.reverse(app, proposal).phase == 'PLAINTEXT_PENDING'
        if phase == 'removed':
            assert d.check_removed(proposal, app.owner, pin=reverse.app_pin(proposal, 'REMOVED')) is None
            assert remove(app, proposal, 'REMOVED').phase == 'REMOVED'
        else:
            finish_reverse(app, proposal)
        assert reverse.native_rows(app) == app.source
        if sequence:
            assert facts(app) == original_sequence
