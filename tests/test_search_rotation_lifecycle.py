"""Native search reindex, sealed authority, exact uniqueness and reversible exit."""
from contextlib import contextmanager
from dataclasses import replace
import hashlib
import json
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Column, MetaData, String, Table, Text, Uuid, event, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import registry

from cryptalis import migration as m, rotation as r
from cryptalis.crypto import DevelopmentKeyProvider, KeyContext, Keyring
from cryptalis.crypto import cf1
from cryptalis.crypto.cf1 import FieldDescriptor, open_text, seal_text
from cryptalis.sqlalchemy import attach
from search_rotation_worker import TARGET_PROVIDER, target_keys
from test_deprotection import app_pin, native_rows
from test_migration import application, engine, frames, keys, publish, run, DOMAIN, TENANT
from test_migration_multitable import multiple_tables, other_frames, OTHER_TENANT
from test_payload_rotation_execution import operation_pin, snapshot, staged_frames
from test_payload_rotation_recovery import assert_paused
from test_rewrap_abort import index_identity
from test_rewrap_plan import _snapshot, _target
from test_search_retained_readers import attached, remove_current


def plan(app, target=target_keys, source=keys):
    return r.plan_search_rotation(app.plan, app.owner, source_pin=app.pin, keys=source,
        target_keys=target, backfill_rows_per_second=1000, verify_rows_per_second=1000,
        temporary_bytes_per_row=1024, wal_bytes_per_row=2048, max_batch_rows=3)


def stage(app, proposal, target=target_keys, source=keys, **options):
    return r.apply_search_rotation(proposal, app.owner, keys=source, target_keys=target,
                                   pin=operation_pin(proposal), approval=app.approval, **options)


def seal(app, proposal, target=target_keys, source=keys):
    return r.seal_search_rotation(proposal, app.owner, keys=source, target_keys=target,
        pin=operation_pin(proposal), approval=app.approval,
        copy_rows_per_second=1000, copy_wal_bytes_per_row=2048)


def switch(app, proposal, activation, target=target_keys, source=keys, **options):
    arguments = dict(keys=source, target_keys=target, pin=app_pin(activation, 'PREPARED'), approval=app.approval)
    arguments.update(options)
    return r.switch_search_rotation(proposal, activation, app.owner, **arguments)


def activate(app, activation, target=target_keys):
    assert m.apply(activation, app.owner, keys=target, pin=app_pin(activation, 'ACTIVATING'),
                   approval=app.approval, until='ACTIVE').phase == 'ACTIVE'
    app.plan, app.pin = activation, app_pin(activation, 'ACTIVE')


@contextmanager
def runtime(app, factory, varchar=False):
    if not varchar:
        with attached(app, factory) as current:
            yield current
        return
    mapping = registry(metadata=MetaData(schema=app.schema))
    table = Table('customer', mapping.metadata,
        Column('id', Uuid, primary_key=True, autoincrement=False),
        Column('tenant_id', Uuid, nullable=False), Column('name', String(64, collation='C')),
        Column('label', Text))
    class Customer:
        pass
    mapping.map_imperatively(Customer, table)
    connection_engine = engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
    try:
        sessions = attach(mapping, connection_engine, lock=app.plan.lock_bytes, keys=factory,
                          deployment=(app.plan, app.pin))
        yield SimpleNamespace(Customer=Customer, sessions=sessions, runtime=connection_engine)
    finally:
        connection_engine.dispose()
        mapping.dispose()


@pytest.mark.parametrize('varchar', [False, True])
def test_search_rotation_reindexes_current_values_and_restores_native_application(varchar):
    with application(value_type=String(64, collation='C') if varchar else None) as app:
        run(app); publish(app)
        expected = dict(app.source)
        with runtime(app, keys, varchar) as current:
            with current.sessions(tenant_id=TENANT) as session:
                session.get(current.Customer, UUID(int=101)).name = 'source edit before search rotation'
                session.add(current.Customer(id=UUID(int=999), tenant_id=TENANT, name='new source member'))
                session.delete(session.get(current.Customer, UUID(int=106)))
                session.commit()
        expected[UUID(int=101)] = TENANT, 'source edit before search rotation'
        expected[UUID(int=999)] = TENANT, 'new source member'
        del expected[UUID(int=106)]
        original, index_before = frames(app, True), index_identity(app)
        before = _snapshot(app)
        proposal = plan(app)
        assert _snapshot(app) == before
        first = stage(app, proposal, max_chunks=1)
        assert (first.phase, first.committed_rows, first.committed_chunks) == ('EXPANDED', 3, 1)
        prefix = staged_frames(app, proposal)
        assert frames(app, True) == original
        assert stage(app, proposal).phase == 'BACKFILLED'
        staged = {identity: values[0] for identity, values in staged_frames(app, proposal).items()}
        for identity in (UUID(int=100), UUID(int=101), UUID(int=102)):
            assert staged[identity] == prefix[identity][0]
        for identity, frame in staged.items():
            if frame is not None:
                assert frame[:10] == original[identity][:10]
                assert int.from_bytes(frame[10:14], 'big') == 2
                assert frame[14:46] != original[identity][14:46]
                assert frame[46:58] != original[identity][46:58]
        before = snapshot(app, proposal)
        activation = seal(app, proposal)
        assert seal(app, proposal).artifact == activation.artifact
        assert snapshot(app, proposal) == before
        assert activation.document['format'] == 'cryptalis.transition/v4'
        assert activation.document['kind'] == 'search_rotation'
        assert activation.document['search_rotation_plan_digest'] == proposal.digest
        assert switch(app, proposal, activation).phase == 'PENDING'
        assert frames(app, True) == staged and index_identity(app) == index_before
        committed = _snapshot(app)
        def unavailable_source(tenant):
            raise AssertionError('Committed search cutover must not require retired source custody.')
        assert switch(app, proposal, activation, source=unavailable_source).phase == 'PENDING'
        assert _snapshot(app) == committed
        assert_paused(app)
        activate(app, activation)
        assert frames(app, True) == staged and index_identity(app) == index_before
        with runtime(app, target_keys, varchar) as current:
            C = current.Customer
            with current.sessions(tenant_id=TENANT) as session:
                assert {row.id: (row.tenant_id, row.name) for row in session.scalars(select(C))} == expected
                assert session.scalar(select(C.id).where(C.name == '雪😀')) == UUID(int=102)
                assert set(session.scalars(select(C.id).where(C.name.in_(
                    ['source edit before search rotation', 'new source member'])))) == {UUID(int=101), UUID(int=999)}
                session.add(C(id=UUID(int=2000), tenant_id=TENANT, name='new source member'))
                with pytest.raises(IntegrityError) as duplicate:
                    session.commit()
                assert duplicate.value.orig.sqlstate == '23505'
                session.rollback()
            with current.sessions(tenant_id=TENANT) as session:
                session.get(C, UUID(int=101)).name = 'latest after search publication'
                session.add(C(id=UUID(int=2001), tenant_id=TENANT, name=None))
                session.commit()
            expected[UUID(int=101)] = TENANT, 'latest after search publication'
            expected[UUID(int=2001)] = TENANT, None
            before = _snapshot(app)
            assert m.apply(activation, app.owner, keys=target_keys, pin=app.pin,
                           approval=app.approval, until='ACTIVE').phase == 'ACTIVE'
            assert _snapshot(app) == before
        remove_current(app, target_keys)
        assert native_rows(app) == expected
        with app.owner.connect() as connection:
            assert connection.exec_driver_sql(
                'SELECT data_type,character_maximum_length FROM information_schema.columns '
                'WHERE table_schema=%s AND table_name=%s AND column_name=%s',
                (app.schema, 'customer', 'name')).one() == (
                    ('character varying', 64) if varchar else ('text', None))


def test_multitable_search_rotation_preserves_storage_only_ciphertext_exactly():
    with multiple_tables() as app:
        run(app); publish(app)
        original_notes, index_before = other_frames(app, True, True), index_identity(app)
        proposal = plan(app)
        assert stage(app, proposal).committed_rows == 18
        with app.owner.connect() as connection:
            for model in proposal.source.document['lock']['models']:
                columns = ','.join(m._quote(connection, field['payload_column'] + '_rotation') for field in model['fields'])
                for row in connection.exec_driver_sql(
                    f'SELECT id,tenant_id,{columns} FROM {m._table(connection, model)} ORDER BY id'):
                    expected = app.source if model['table'] == 'customer' else app.other_source
                    for index, field in enumerate(model['fields']):
                        frame = None if row[index + 2] is None else bytes(row[index + 2])
                        descriptor = FieldDescriptor.from_compiled(field['descriptor'], field['descriptor_digest'])
                        value = app.notes[row[0]] if field['column'] == 'note' else expected[row[0]][1]
                        assert open_text(frame, descriptor, row[1], row[0], target_keys(row[1]).prepare()) == value
                        if field['column'] == 'note':
                            assert frame == original_notes[row[0]]
        activation = seal(app, proposal)
        switch(app, proposal, activation)
        activate(app, activation)
        assert other_frames(app, True, True) == original_notes
        assert index_identity(app) == index_before
        sessions = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=target_keys,
                          deployment=(app.plan, app.pin))
        for tenant in (TENANT, OTHER_TENANT):
            with sessions(tenant_id=tenant) as session:
                for model, expected in ((app.Customer, app.source), (app.other, app.other_source)):
                    actual = {row.id: (row.tenant_id, row.name) for row in session.scalars(
                        select(model).where(model.tenant_id == tenant))}
                    assert actual == {identity: value for identity, value in expected.items() if value[0] == tenant}


def test_target_outage_preserves_committed_prefix_and_source_only_abort_restores_writers():
    with application() as app:
        run(app); publish(app)
        original = frames(app, True)
        proposal = plan(app)
        stage(app, proposal, max_chunks=1)
        before = snapshot(app, proposal)
        class Outage:
            provider_id = TARGET_PROVIDER
            def unwrap(self, *args):
                raise RuntimeError('PRIVATE SEARCH PROVIDER OUTAGE')
        def unavailable(tenant):
            good = target_keys(tenant)
            return Keyring(good.policy, {**good._providers, TARGET_PROVIDER: Outage()})
        with pytest.raises(m.TransitionFailure) as caught:
            stage(app, proposal, target=unavailable)
        assert 'PRIVATE SEARCH PROVIDER OUTAGE' not in str(caught.value)
        assert snapshot(app, proposal) == before
        assert_paused(app)
        assert r.abort_search_rotation(proposal, app.owner, keys=keys,
            source_pin=app.pin, approval=app.approval).phase == 'ABORTED'
        assert frames(app, True) == original
        assert m.check_deployment(app.plan, app.owner, pin=app.pin) is None
        with attached(app, keys) as current:
            with current.sessions(tenant_id=TENANT) as session:
                session.get(current.Customer, UUID(int=101)).name = 'writer recovered after search abort'
                session.commit()
        committed = _snapshot(app)
        assert r.abort_search_rotation(proposal, app.owner, keys=keys,
            source_pin=app.pin, approval=app.approval).phase == 'ABORTED'
        assert _snapshot(app) == committed


def test_authentic_same_value_target_reseal_cannot_replace_sealed_search_authority():
    with application() as app:
        run(app); publish(app)
        proposal = plan(app)
        stage(app, proposal)
        activation = seal(app, proposal)
        field = app.plan.document['lock']['models'][0]['fields'][0]
        descriptor = FieldDescriptor.from_compiled(field['descriptor'], field['descriptor_digest'])
        changed = seal_text(app.source[UUID(int=101)][1], descriptor, TENANT, UUID(int=101), target_keys(TENANT).prepare())
        assert changed != staged_frames(app, proposal)[UUID(int=101)][0]
        with app.owner.begin() as connection:
            connection.exec_driver_sql(f'UPDATE "{app.schema}".customer SET '
                f'"{field["payload_column"]}_rotation"=%s WHERE id=%s', (changed, UUID(int=101)))
        before = snapshot(app, proposal)
        with pytest.raises(m.TransitionFailure):
            switch(app, proposal, activation)
        assert snapshot(app, proposal) == before
        assert_paused(app)


@pytest.mark.parametrize('fault', ['proof_digest', 'boolean_counter', 'ancestor_link'])
def test_late_search_publication_drift_refuses_before_provider_access(fault):
    with application() as app:
        run(app); publish(app)
        proposal = plan(app)
        stage(app, proposal)
        activation = seal(app, proposal)
        switch(app, proposal, activation)
        with app.owner.begin() as connection:
            identity = proposal.operation_id if fault == 'ancestor_link' else activation.operation_id
            journal = f'"{app.schema}"."_cryptalis_journal"'
            state = connection.exec_driver_sql(f'SELECT state FROM {journal} WHERE operation_id=%s', (identity,)).scalar_one()
            if fault == 'proof_digest':
                state['search_rotation_plan_digest'] = '0' * 64
            elif fault == 'boolean_counter':
                next(iter(state['models'].values()))['rows'] = True
            else:
                state['superseded_by'] = {'operation_id': str(uuid4()), 'plan_digest': '0' * 64}
            connection.exec_driver_sql(f'UPDATE {journal} SET state=%s::jsonb WHERE operation_id=%s', (json.dumps(state), identity))
        before, calls = _snapshot(app), []
        def unavailable(tenant):
            calls.append(tenant)
            raise RuntimeError('provider must follow metadata admission')
        with pytest.raises(m.TransitionFailure):
            m.apply(activation, app.owner, keys=unavailable, pin=app_pin(activation, 'ACTIVATING'),
                    approval=app.approval, until='ACTIVE')
        assert calls == [] and _snapshot(app) == before
        assert_paused(app)


@pytest.mark.parametrize('boundary', ['copy', 'guard_drop'])
def test_search_cutover_native_failure_rolls_back_source_shadows_and_fence(boundary):
    with application() as app:
        run(app); publish(app)
        proposal = plan(app)
        stage(app, proposal)
        activation = seal(app, proposal)
        original, index_before = frames(app, True), index_identity(app)
        before = snapshot(app, proposal)
        shadow = app.plan.document['lock']['models'][0]['fields'][0]['payload_column'] + '_rotation'
        trigger, reached = '_cryptalis_' + proposal.operation_id.hex + '_pause', []
        def fail_after_effect(connection, cursor, statement, parameters, context, executemany):
            if ((boundary == 'copy' and statement.startswith('UPDATE ') and shadow in statement)
                    or (boundary == 'guard_drop' and statement.startswith('DROP TRIGGER ') and trigger in statement)):
                reached.append(boundary)
                raise RuntimeError('public injected search cutover failure after native effect')
        event.listen(app.owner, 'after_cursor_execute', fail_after_effect)
        try:
            with pytest.raises(m.TransitionFailure):
                switch(app, proposal, activation)
        finally:
            event.remove(app.owner, 'after_cursor_execute', fail_after_effect)
        assert reached == [boundary]
        assert snapshot(app, proposal) == before
        assert frames(app, True) == original and index_identity(app) == index_before
        assert r.status_search_rotation(proposal, app.owner, pin=operation_pin(proposal)).phase == 'BACKFILLED'
        assert_paused(app)
        assert switch(app, proposal, activation).phase == 'PENDING'
        activate(app, activation)


def test_injected_generation_two_term_collision_rolls_back_native_unique_index_copy(monkeypatch):
    with application() as app:
        run(app); publish(app)
        original, index_before = frames(app, True), index_identity(app)
        actual = cf1._term
        # Deliberately violate the full-HMAC collision assumption. Product
        # planning and both frame authentication paths still execute normally.
        def collide(encoded, field, material):
            if material.context.purpose == 'search' and material.context.generation == 2:
                return b'c' * 32
            return actual(encoded, field, material)
        with monkeypatch.context() as patched:
            patched.setattr(cf1, '_term', collide)
            proposal = plan(app)
            stage(app, proposal)
            activation = seal(app, proposal)
            before = snapshot(app, proposal)
            with pytest.raises(m.TransitionFailure) as caught:
                switch(app, proposal, activation)
            assert caught.value.sqlstate == '23505'
            assert snapshot(app, proposal) == before
            assert frames(app, True) == original and index_identity(app) == index_before
            assert_paused(app)
        assert r.abort_search_rotation(proposal, app.owner, keys=keys,
            source_pin=app.pin, approval=app.approval).phase == 'ABORTED'
        assert m.check_deployment(app.plan, app.owner, pin=app.pin) is None
        assert frames(app, True) == original


def test_search_payload_rewrap_search_chain_preserves_latest_values_through_removal():
    with application() as app:
        run(app); publish(app)
        proposal = plan(app)
        stage(app, proposal)
        activation = seal(app, proposal)
        switch(app, proposal, activation)
        activate(app, activation)
        current = target_keys(TENANT)
        provider = DevelopmentKeyProvider()
        context = KeyContext(DOMAIN, TENANT, 'payload', uuid4(), 2)
        wrapper = provider.wrap(hashlib.sha256(b'PUBLIC SEARCH PAYLOAD CHAIN ROOT').digest(), context)
        payload = Keyring(replace(current.policy, wrappers=current.policy.wrappers + (wrapper,), payload_generation=2),
                          {**current._providers, provider.provider_id: provider})
        p = r.plan_payload_rotation(app.plan, app.owner, source_pin=app.pin, keys=current, target_keys=payload,
            backfill_rows_per_second=1000, verify_rows_per_second=1000,
            temporary_bytes_per_row=1024, wal_bytes_per_row=2048)
        assert r.apply_payload_rotation(p, app.owner, keys=current, target_keys=payload,
            pin=operation_pin(p), approval=app.approval).phase == 'BACKFILLED'
        a = r.seal_payload_rotation(p, app.owner, keys=current, target_keys=payload,
            pin=operation_pin(p), approval=app.approval, copy_rows_per_second=1000, copy_wal_bytes_per_row=2048)
        assert r.switch_payload_rotation(p, a, app.owner, keys=current, target_keys=payload,
            pin=app_pin(a, 'PREPARED'), approval=app.approval).phase == 'PENDING'
        activate(app, a, payload)
        custody, _ = _target(lambda tenant: payload)
        p = r.plan_rewrap(app.plan, app.owner, source_pin=app.pin, keys=payload,
                         target_keys=custody, verify_rows_per_second=1000)
        a = p.activation_plan
        assert r.apply_rewrap(p, app.owner, keys=payload, target_keys=custody,
                              pin=app_pin(a, 'PREPARED'), approval=app.approval).phase == 'PENDING'
        activate(app, a, custody)
        selected = target_keys(TENANT, source=custody)
        p = plan(app, source=custody, target=selected)
        stage(app, p, source=custody, target=selected)
        a = seal(app, p, source=custody, target=selected)
        switch(app, p, a, source=custody, target=selected)
        activate(app, a, selected)
        expected = dict(app.source)
        with attached(app, selected) as current:
            with current.sessions(tenant_id=TENANT) as session:
                session.get(current.Customer, UUID(int=101)).name = 'latest search payload rewrap search'
                session.commit()
                assert session.scalar(select(current.Customer.id).where(
                    current.Customer.name == 'latest search payload rewrap search')) == UUID(int=101)
        expected[UUID(int=101)] = TENANT, 'latest search payload rewrap search'
        remove_current(app, selected)
        assert native_rows(app) == expected
