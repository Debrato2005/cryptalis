"""Native sealed payload publication, current values, and reversible exit."""
from dataclasses import replace
import json
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Column, MetaData, String, Table, Text, Uuid, select
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import registry

from cryptalis import migration as m, rotation as r
from cryptalis.crypto.cf1 import FieldDescriptor, seal_text
from cryptalis.sqlalchemy import attach
from payload_rotation_worker import target_keys
from test_deprotection import (
    app_pin, attached_edits, consent, d, least_privilege_role, native_rows, reverse,
)
from test_migration import application, engine, frames, keys, publish, run, TENANT
from test_migration_multitable import multiple_tables, OTHER_TENANT
from test_payload_rotation_execution import operation_pin, plan, snapshot, stage, staged_frames
from test_rewrap_abort import index_identity
from test_rewrap_plan import _snapshot


def seal(app, proposal, **options):
    return r.seal_payload_rotation(proposal, app.owner, keys=keys, target_keys=target_keys,
        pin=operation_pin(proposal), approval=app.approval,
        copy_rows_per_second=1000, copy_wal_bytes_per_row=2048, **options)


def switch(app, proposal, activation, **options):
    arguments = dict(keys=keys, target_keys=target_keys, pin=app_pin(activation, 'PREPARED'),
                     approval=app.approval)
    arguments.update(options)
    return r.switch_payload_rotation(proposal, activation, app.owner, **arguments)


def activate(app, activation):
    assert m.apply(activation, app.owner, keys=target_keys,
        pin=app_pin(activation, 'ACTIVATING'), approval=app.approval, until='ACTIVE').phase == 'ACTIVE'
    app.plan, app.pin = activation, app_pin(activation, 'ACTIVE')


def customer_sessions(app, varchar=False):
    mapping = registry(metadata=MetaData(schema=app.schema))
    table = Table('customer', mapping.metadata,
        Column('id', Uuid, primary_key=True, autoincrement=False),
        Column('tenant_id', Uuid, nullable=False),
        Column('name', String(64, collation='C') if varchar else Text(collation='C')),
        Column('label', Text))
    class Customer:
        pass
    mapping.map_imperatively(Customer, table)
    runtime = engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
    sessions = attach(mapping, runtime, lock=app.plan.lock_bytes, keys=target_keys,
                      deployment=(app.plan, app.pin))
    return mapping, Customer, sessions, runtime


def remove_current(app):
    proposal = d.plan(app.plan, app.owner, source_pin=app.pin, keys=target_keys,
        plaintext_runtime_role=least_privilege_role(app), backfill_rows_per_second=1000,
        verify_rows_per_second=1000, temporary_bytes_per_row=700, wal_bytes_per_row=700)
    assert reverse(app, proposal, key_resolver=target_keys).phase == 'PLAINTEXT_PENDING'
    pure, _ = consent(proposal)
    assert d.apply(proposal, app.owner, keys=target_keys,
        pin=app_pin(proposal, 'PLAINTEXT_ACTIVATING'), approval=app.approval,
        consent=pure, until='PLAINTEXT_ACTIVE').phase == 'PLAINTEXT_ACTIVE'
    removal = d.RemovalApproval(proposal.target_id, proposal.operation_id, proposal.digest,
        'native latest-value workload after payload rotation', 'retained public source and target roots', True)
    assert d.remove(proposal, app.owner, pin=app_pin(proposal, 'REMOVING'),
        approval=app.approval, removal=removal, consent=pure).phase == 'REMOVED'
    assert d.check_removed(proposal, app.owner, pin=app_pin(proposal, 'REMOVED')) is None


@pytest.mark.parametrize('varchar', [False, True])
def test_sealed_payload_cutover_preserves_search_latest_values_and_native_exit(varchar):
    with application(value_type=String(64, collation='C') if varchar else None) as app:
        run(app); publish(app)
        expected = attached_edits(app)
        source, source_pin = app.plan, app.pin
        proposal = plan(app, target_keys)
        assert stage(app, proposal, target_keys).phase == 'BACKFILLED'
        staged = {identity: values[0] for identity, values in staged_frames(app, proposal).items()}
        index_before = index_identity(app)
        before = snapshot(app, proposal)
        activation = seal(app, proposal)
        assert snapshot(app, proposal) == before
        assert seal(app, proposal).artifact == activation.artifact
        assert snapshot(app, proposal) == before
        assert m.MigrationPlan(activation.artifact).artifact == activation.artifact
        assert activation.document['format'] == 'cryptalis.transition/v3'
        assert activation.document['payload_rotation_plan_digest'] == proposal.digest
        assert activation.document['predecessors'][-2:] == [
            {'operation_id': str(source.operation_id), 'plan_digest': source.digest},
            {'operation_id': str(proposal.operation_id), 'plan_digest': proposal.digest}]
        assert switch(app, proposal, activation).phase == 'PENDING'
        assert frames(app, True) == staged and index_identity(app) == index_before
        committed = _snapshot(app)
        def unavailable_source(tenant):
            raise AssertionError('A committed successor retry must not use the retired source provider.')
        assert switch(app, proposal, activation, keys=unavailable_source).phase == 'PENDING'
        assert _snapshot(app) == committed
        with pytest.raises(m.TransitionFailure):
            m.check_deployment(source, app.owner, pin=source_pin)
        with pytest.raises(m.TransitionFailure):
            stage(app, proposal, target_keys)
        with pytest.raises(m.TransitionFailure):
            r.abort_payload_rotation(proposal, app.owner, keys=keys,
                                     source_pin=source_pin, approval=app.approval)
        runtime = engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
        try:
            with runtime.connect() as connection:
                with pytest.raises(DBAPIError) as blocked:
                    connection.exec_driver_sql(f'UPDATE "{app.schema}".customer SET label=%s', ('paused',))
                assert blocked.value.orig.sqlstate == '55000'
        finally:
            runtime.dispose()
        activate(app, activation)
        assert frames(app, True) == staged and index_identity(app) == index_before
        mapping, Customer, sessions, runtime = customer_sessions(app, varchar)
        try:
            with sessions(tenant_id=TENANT) as session:
                assert {row.id: (row.tenant_id, row.name) for row in session.scalars(select(Customer))} == expected
                assert session.scalar(select(Customer.id).where(
                    Customer.name == 'edited while protected')) == UUID(int=101)
                assert set(session.scalars(select(Customer.id).where(Customer.name.in_(
                    ['edited while protected', 'added while protected'])))) == {UUID(int=101), UUID(int=999)}
                session.add(Customer(id=UUID(int=2000), tenant_id=TENANT,
                                     name='edited while protected', label='duplicate'))
                with pytest.raises(IntegrityError) as duplicate:
                    session.commit()
                assert duplicate.value.orig.sqlstate == '23505'
                session.rollback()
            with sessions(tenant_id=TENANT) as session:
                session.get(Customer, UUID(int=101)).name = 'latest value after payload rotation'
                session.add(Customer(id=UUID(int=2001), tenant_id=TENANT, name=None, label='second SQL NULL'))
                session.commit()
            expected[UUID(int=101)] = (TENANT, 'latest value after payload rotation')
            expected[UUID(int=2001)] = (TENANT, None)
            before = _snapshot(app)
            assert m.apply(activation, app.owner, keys=target_keys, pin=app.pin,
                           approval=app.approval, until='ACTIVE').phase == 'ACTIVE'
            assert _snapshot(app) == before
            assert m.check_deployment(activation, app.owner, pin=app.pin) is None
        finally:
            runtime.dispose()
            mapping.dispose()
        remove_current(app)
        assert native_rows(app) == expected
        with app.owner.connect() as connection:
            assert connection.exec_driver_sql(
                'SELECT data_type,character_maximum_length FROM information_schema.columns '
                'WHERE table_schema=%s AND table_name=%s AND column_name=%s',
                (app.schema, 'customer', 'name')).one() == (
                    ('character varying', 64) if varchar else ('text', None))


def test_multitable_multitenant_payload_publication_preserves_storage_only_fields():
    with multiple_tables() as app:
        run(app); publish(app)
        proposal = plan(app, target_keys)
        assert stage(app, proposal, target_keys).committed_rows == 18
        activation = seal(app, proposal)
        index_before = index_identity(app)
        assert switch(app, proposal, activation).phase == 'PENDING'
        activate(app, activation)
        assert index_identity(app) == index_before
        sessions = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=target_keys,
                          deployment=(app.plan, app.pin))
        for tenant in (TENANT, OTHER_TENANT):
            with sessions(tenant_id=tenant) as session:
                for model, expected in ((app.Customer, app.source), (app.other, app.other_source)):
                    selected = {identity: value for identity, value in expected.items() if value[0] == tenant}
                    actual = {row.id: (row.tenant_id, row.name) for row in session.scalars(
                        select(model).where(model.tenant_id == tenant))}
                    assert actual == selected
                    found = set(session.scalars(select(model.id).where(
                        model.tenant_id == tenant, model.name.in_(['雪😀', '']))))
                    assert found == {identity for identity, (_, value) in selected.items() if value in ('雪😀', '')}
                assert {row.id: row.note for row in session.scalars(select(app.other).where(
                    app.other.tenant_id == tenant))} == {
                        identity: app.notes[identity] for identity, value in app.other_source.items() if value[0] == tenant}


def test_authenticated_shadow_reseal_cannot_replace_the_immutable_sealed_observation():
    with application() as app:
        run(app); publish(app)
        proposal = plan(app, target_keys)
        stage(app, proposal, target_keys)
        activation = seal(app, proposal)
        field = app.plan.document['lock']['models'][0]['fields'][0]
        descriptor = FieldDescriptor.from_compiled(field['descriptor'], field['descriptor_digest'])
        identity = UUID(int=101)
        previous = staged_frames(app, proposal)[identity][0]
        replacement = seal_text(app.source[identity][1], descriptor, TENANT, identity, target_keys(TENANT).prepare())
        assert replacement != previous
        with app.owner.begin() as connection:
            connection.exec_driver_sql(f'UPDATE "{app.schema}".customer SET '
                f'"{field["payload_column"]}_rotation"=%s WHERE id=%s', (replacement, identity))
        before = snapshot(app, proposal)
        with pytest.raises(m.TransitionFailure):
            switch(app, proposal, activation)
        assert snapshot(app, proposal) == before


def test_forged_active_journal_does_not_skip_host_sealed_target_verification():
    with application() as app:
        run(app); publish(app)
        proposal = plan(app, target_keys)
        stage(app, proposal, target_keys)
        activation = seal(app, proposal)
        switch(app, proposal, activation)
        model = app.plan.document['lock']['models'][0]
        field = model['fields'][0]
        descriptor = FieldDescriptor.from_compiled(field['descriptor'], field['descriptor_digest'])
        changed = seal_text('authenticated replacement after forged publication', descriptor,
                            TENANT, UUID(int=101), target_keys(TENANT).prepare())
        with app.owner.begin() as connection:
            state = connection.exec_driver_sql(f'SELECT state FROM "{app.schema}"."_cryptalis_journal" '
                'WHERE operation_id=%s', (activation.operation_id,)).scalar_one()
            m._drop_guards(connection, activation)
            connection.exec_driver_sql(f'UPDATE "{app.schema}".customer SET name=%s WHERE id=%s',
                                       (changed, UUID(int=101)))
            state['phase'] = 'ACTIVE'
            state['models'][model['table_id']]['active_schema'] = m._facts(connection, model)
            m._save(connection, activation, state)
        before = _snapshot(app)
        with pytest.raises(m.TransitionFailure):
            m.apply(activation, app.owner, keys=target_keys,
                pin=app_pin(activation, 'ACTIVATING'), approval=app.approval, until='ACTIVE')
        assert _snapshot(app) == before


@pytest.mark.parametrize('fault', ['pin', 'missing_activation', 'activation_binding',
    'proposal_binding', 'source_changed', 'missing_preparation', 'target_policy'])
def test_wrong_cutover_authority_or_changed_source_has_no_effect(fault):
    with application() as app:
        run(app); publish(app)
        proposal = plan(app, target_keys)
        stage(app, proposal, target_keys)
        activation = seal(app, proposal)
        supplied, pin, target = proposal, app_pin(activation, 'PREPARED'), target_keys
        if fault == 'pin':
            pin = replace(pin, plan_digest='0' * 64)
        elif fault == 'proposal_binding':
            supplied = r.PayloadRotationPlan(m._canonical({**proposal.document, 'operation_id': str(uuid4())}))
        elif fault == 'target_policy':
            target = keys
        elif fault == 'source_changed':
            field = app.plan.document['lock']['models'][0]['fields'][0]
            descriptor = FieldDescriptor.from_compiled(field['descriptor'], field['descriptor_digest'])
            changed = seal_text('latest original generation changed after seal', descriptor,
                                TENANT, UUID(int=101), keys(TENANT).prepare())
            with app.owner.begin() as connection:
                connection.exec_driver_sql(f'UPDATE "{app.schema}".customer SET name=%s WHERE id=%s',
                                           (changed, UUID(int=101)))
        elif fault == 'missing_preparation':
            with app.owner.begin() as connection:
                connection.exec_driver_sql(f'DELETE FROM "{app.schema}"."_cryptalis_journal" '
                                          'WHERE operation_id=%s', (proposal.operation_id,))
        before = snapshot(app, proposal)
        with pytest.raises(m.TransitionFailure):
            if fault == 'missing_activation':
                activation = None
            elif fault == 'activation_binding':
                activation = m.MigrationPlan(m._canonical({**activation.document,
                    'payload_rotation_plan_digest': '0' * 64}))
            r.switch_payload_rotation(supplied, activation, app.owner, keys=keys,
                                      target_keys=target, pin=pin, approval=app.approval)
        assert snapshot(app, proposal) == before


@pytest.mark.parametrize('progress', ['none', 'prefix'])
def test_sealing_requires_complete_native_backfill(progress):
    with application() as app:
        run(app); publish(app)
        proposal = plan(app, target_keys)
        stage(app, proposal, target_keys, until='EXPANDED' if progress == 'none' else 'BACKFILLED',
              max_chunks=1 if progress == 'prefix' else None)
        before = snapshot(app, proposal)
        with pytest.raises(m.TransitionFailure):
            seal(app, proposal)
        assert snapshot(app, proposal) == before


@pytest.mark.parametrize('fault', ['missing_source', 'missing_preparation', 'wrong_link'])
def test_published_payload_lineage_is_required_for_reverse_admission(fault):
    with application() as app:
        run(app); publish(app)
        source = app.plan
        proposal = plan(app, target_keys)
        stage(app, proposal, target_keys)
        activation = seal(app, proposal)
        switch(app, proposal, activation)
        activate(app, activation)
        with app.owner.begin() as connection:
            journal = f'"{app.schema}"."_cryptalis_journal"'
            if fault == 'wrong_link':
                connection.exec_driver_sql(f'UPDATE {journal} SET state=state || %s::jsonb WHERE operation_id=%s',
                    (json.dumps({'superseded_by': {'operation_id': str(uuid4()), 'plan_digest': '0' * 64}}),
                     proposal.operation_id))
            else:
                identity = source.operation_id if fault == 'missing_source' else proposal.operation_id
                connection.exec_driver_sql(f'DELETE FROM {journal} WHERE operation_id=%s', (identity,))
        before = _snapshot(app)
        with pytest.raises(m.TransitionFailure):
            d.plan(activation, app.owner, source_pin=app.pin, keys=target_keys,
                plaintext_runtime_role=least_privilege_role(app), backfill_rows_per_second=1000,
                verify_rows_per_second=1000, temporary_bytes_per_row=700, wal_bytes_per_row=700)
        assert _snapshot(app) == before
