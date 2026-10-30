"""Disabling exact search preserves encrypted current values and native exit."""
import asyncio
from dataclasses import replace
import json
import os
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import String, event, select
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import Session

from cryptalis.migration import TransitionFailure
from cryptalis.sqlalchemy import UnsupportedProtectedOperation
from test_application_config import config
from test_application_modification import propose, prepare, seal, activate_change, configured_change
from test_deprotection import app_pin, native_rows
from test_migration import application, frames, keys, publish, run, TENANT
from test_payload_rotation_execution import snapshot, staged_frames
from test_search_retained_readers import remove_current


def storage_change(app):
    declaration = app.plan.document['lock']['declaration']
    declaration['models'][0]['fields'][0].update(queries=[], accept_leakage=[])
    return config(app, manifest=json.dumps(declaration).encode(), search_reviews=(), queries=())


def indexes(app):
    with app.owner.connect() as connection:
        return connection.exec_driver_sql('SELECT indexname,indexdef FROM pg_catalog.pg_indexes '
            'WHERE schemaname=%s ORDER BY indexname', (app.schema,)).all()


@pytest.mark.parametrize('mode', ['sync', 'async', 'sqlmodel', 'sqlmodel_async'])
@pytest.mark.parametrize('varchar', [False, True])
def test_disable_search_preserves_values_nulls_and_native_schema(mode, varchar):
    with application(unique=False, value_type=String(64, collation='C') if varchar else None) as app:
        native_indexes = indexes(app)
        with Session(app.runtime) as session:
            expected = list(session.execute(select(app.Customer.id, app.Customer.name).order_by(app.Customer.id)))
        run(app); publish(app)
        original = frames(app, True)
        configured = storage_change(app)
        proposal = propose(configured, app)
        assert proposal.document['estimates']['staging_payload_bytes'] == sum(
            len(body) - 32 for body in original.values() if body is not None)
        prepare(configured, app, proposal, max_chunks=1)
        prefix = staged_frames(app, proposal)
        assert frames(app, True) == original
        successor = activate_change(configured, app, proposal)
        assert successor.document['key_policies'] == proposal.source.document['key_policies']
        changed = frames(app, True)
        assert all(body is None if original[identity] is None else len(body) == len(original[identity]) - 32
                   for identity, body in changed.items())
        assert all(changed[identity] == values[0] for identity, values in prefix.items() if values[0] is not None)
        assert not any(name.endswith('_eq') for name, _ in indexes(app))
        statement = select(app.Customer.id, app.Customer.name).order_by(app.Customer.id)
        if 'async' in mode:
            async def exercise():
                runtime = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                    async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
                try:
                    factory = await configured.attach(runtime, deployment=(app.plan, app.pin), keys=keys,
                        adapter='sqlmodel' if mode.startswith('sqlmodel') else 'sqlalchemy')
                    async with factory(tenant_id=TENANT) as session:
                        assert list(await session.execute(statement)) == expected
                        with pytest.raises(UnsupportedProtectedOperation):
                            await session.execute(select(app.Customer).where(app.Customer.name == '雪😀'))
                        (await session.get(app.Customer, UUID(int=101))).name = 'latest without search'
                        await session.commit()
                finally:
                    await runtime.dispose()
            asyncio.run(exercise())
        else:
            factory = configured.attach(app.runtime, deployment=(app.plan, app.pin), keys=keys,
                adapter='sqlmodel' if mode == 'sqlmodel' else 'sqlalchemy')
            with factory(tenant_id=TENANT) as session:
                assert list(session.execute(statement)) == expected
                with pytest.raises(UnsupportedProtectedOperation):
                    session.execute(select(app.Customer).where(app.Customer.name.in_(['雪😀'])))
                session.get(app.Customer, UUID(int=101)).name = 'latest without search'
                session.commit()
        remove_current(app, keys)
        recovered = dict(app.source); recovered[UUID(int=101)] = TENANT, 'latest without search'
        assert native_rows(app) == recovered
        assert indexes(app) == native_indexes


@pytest.mark.parametrize('rows', [0, 3])
def test_disable_empty_or_null_only_data_and_reenable(rows):
    with application(rows=rows, unique=False, protected_values=(None,)) as app:
        run(app); publish(app)
        configured = storage_change(app)
        activate_change(configured, app, propose(configured, app))
        configured = configured_change(app)
        activate_change(configured, app, propose(configured, app))
        assert frames(app, True) == {identity: None for identity in app.source}
        assert any(name.endswith('_eq') for name, _ in indexes(app))
        remove_current(app, keys)


def test_search_uniqueness_cannot_be_removed_as_a_profile_change():
    with application(unique=True) as app:
        run(app); publish(app)
        def forbidden(*args, **kwargs): pytest.fail('uniqueness change reached database or keys')
        event.listen(app.owner, 'engine_connect', forbidden)
        try:
            with pytest.raises(TransitionFailure, match='unsupported_manifest_modification'):
                propose(storage_change(app), app)
        finally:
            event.remove(app.owner, 'engine_connect', forbidden)


def test_disabled_search_query_samples_refuse_before_database():
    with application(unique=False) as app:
        run(app); publish(app)
        configured = replace(storage_change(app), queries=(select(app.Customer).where(app.Customer.name == 'PRIVATE'),))
        def forbidden(*args, **kwargs): pytest.fail('disabled query reached database')
        event.listen(app.owner, 'engine_connect', forbidden)
        try:
            with pytest.raises(TransitionFailure, match='query_samples_incompatible'):
                propose(configured, app)
        finally:
            event.remove(app.owner, 'engine_connect', forbidden)


@pytest.mark.parametrize('action', ['abort', 'failed_switch'])
def test_disabling_search_keeps_source_index_until_atomic_cutover(action):
    with application(unique=False) as app:
        run(app); publish(app)
        configured = storage_change(app)
        proposal = propose(configured, app)
        original, original_indexes = frames(app, True), indexes(app)
        prepare(configured, app, proposal, max_chunks=1)
        if action == 'abort':
            configured.abort_modification(app.owner, proposal=proposal, deployment=(app.plan, app.pin),
                keys=keys, approval=app.approval)
            assert frames(app, True) == original and indexes(app) == original_indexes
            return
        prepare(configured, app, proposal)
        successor = seal(configured, app, proposal)
        before = snapshot(app, proposal)
        def fail_after_index_drop(connection, cursor, statement, parameters, context, executemany):
            if statement.startswith('DROP INDEX'):
                raise RuntimeError('PRIVATE CUTOVER FAILURE')
        event.listen(app.owner, 'after_cursor_execute', fail_after_index_drop)
        try:
            with pytest.raises(TransitionFailure) as caught:
                configured.switch_modification(app.owner, proposal=proposal,
                    deployment=(successor, app_pin(successor, 'PREPARED')), keys=keys, approval=app.approval)
            assert 'PRIVATE CUTOVER FAILURE' not in str(caught.value)
        finally:
            event.remove(app.owner, 'after_cursor_execute', fail_after_index_drop)
        assert snapshot(app, proposal) == before and indexes(app) == original_indexes
        assert configured.switch_modification(app.owner, proposal=proposal,
            deployment=(successor, app_pin(successor, 'PREPARED')), keys=keys, approval=app.approval).phase == 'PENDING'


def test_disable_budget_preserves_source_authentication_bound():
    with application(unique=False) as app:
        run(app); publish(app)
        configured = storage_change(app)
        bound = max(32 + (3 * len(body) - 74 if body is not None else 0) for body in frames(app, True).values())
        with pytest.raises(TransitionFailure): propose(configured, app, max_batch_bytes=bound - 1)
        activate_change(configured, app, propose(configured, app, max_batch_bytes=bound))


def test_disable_nonempty_then_reenable_search_retains_current_values():
    with application(unique=False) as app:
        run(app); publish(app)
        configured = storage_change(app)
        activate_change(configured, app, propose(configured, app))
        configured = configured_change(app)
        activate_change(configured, app, propose(configured, app))
        factory = configured.attach(app.runtime, deployment=(app.plan, app.pin), keys=keys)
        with factory(tenant_id=TENANT) as session:
            assert session.scalar(select(app.Customer.id).where(app.Customer.name == '雪😀')) == UUID(int=102)
        remove_current(app, keys)


@pytest.mark.parametrize('fault', ['source_index', 'source_frame', 'staged_length', 'staged_authentication'])
def test_disable_drift_or_tamper_refuses_without_losing_committed_state(fault):
    with application(unique=False) as app:
        run(app); publish(app)
        configured = storage_change(app)
        proposal = propose(configured, app)
        prepare(configured, app, proposal, max_chunks=1)
        model = app.plan.document['lock']['models'][0]
        field = model['fields'][0]
        with app.owner.begin() as connection:
            if fault == 'source_index':
                connection.exec_driver_sql(f'DROP INDEX "{app.schema}"."{field["payload_column"]}_eq"')
                connection.exec_driver_sql(f'CREATE INDEX "{field["payload_column"]}_eq" ON "{app.schema}".customer(label)')
            else:
                column = 'name' if fault == 'source_frame' else field['payload_column'] + '_rotation'
                body = bytes(connection.exec_driver_sql(f'SELECT "{column}" FROM "{app.schema}".customer WHERE id=%s',
                    (UUID(int=101),)).scalar_one())
                body = body + b'x' if fault == 'staged_length' else body[:-1] + bytes([body[-1] ^ 1])
                connection.exec_driver_sql(f'UPDATE "{app.schema}".customer SET "{column}"=%s WHERE id=%s', (body, UUID(int=101)))
        before, before_indexes = snapshot(app, proposal), indexes(app)
        with pytest.raises(TransitionFailure): prepare(configured, app, proposal)
        assert snapshot(app, proposal) == before and indexes(app) == before_indexes


def test_disable_fixed_tenant_and_other_field_search_remains_admitted():
    from test_single_tenant_update import single_application, snapshot as native_snapshot
    from test_modification_contexts import changed_config
    from test_migration import TABLE_ID
    with single_application() as app:
        native = native_snapshot(app)
        run(app); publish(app)
        configured = changed_config(app, 'unused')
        declaration = json.loads(configured.manifest)
        field = declaration['models'][0]['fields'][0]
        field.update(queries=[], accept_leakage=[])
        configured = replace(configured, manifest=json.dumps(declaration).encode(), search_reviews=())
        activate_change(configured, app, propose(configured, app))
        factory = configured.attach(app.runtime, deployment=(app.plan, app.pin), keys=keys)
        with factory(tenant_id=TABLE_ID) as session:
            assert session.get(app.Customer, UUID(int=102)).value == 'seed'
        remove_current(app, keys)
        assert native_snapshot(app) == native


def test_disable_one_field_keeps_other_ciphertext_and_unique_indexes():
    from test_migration_multitable import multiple_tables, other_frames
    from test_modification_contexts import changed_config
    from test_rewrap_abort import index_identity
    with multiple_tables() as app:
        run(app); publish(app)
        configured = changed_config(app, 'note')
        activate_change(configured, app, propose(configured, app))
        original = frames(app, True), other_frames(app, True), index_identity(app)
        declaration = json.loads(configured.manifest)
        field = next(f for model in declaration['models'] for f in model['fields'] if f['name'] == 'note')
        field.update(queries=[], accept_leakage=[])
        configured = replace(configured, manifest=json.dumps(declaration).encode(),
            search_reviews=tuple(review for review in configured.search_reviews if str(review.field_id) != field['field_id']))
        activate_change(configured, app, propose(configured, app))
        assert (frames(app, True), other_frames(app, True), index_identity(app)) == original
        factory = configured.attach(app.runtime, deployment=(app.plan, app.pin), keys=keys)
        with factory(tenant_id=TENANT) as session:
            assert session.scalar(select(app.Customer.id).where(app.Customer.name == '雪😀')) == UUID(int=102)
