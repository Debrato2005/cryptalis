"""Context, adapter and provider lifecycle composition for active-field changes."""
import asyncio
from dataclasses import replace
import json
import os
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import MetaData, select
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import Session, registry

from cryptalis.application import ApplicationConfig
from cryptalis.crypto import Keyring
from cryptalis.manifest.compiler import SearchReview, Writer, WriterInventory
from cryptalis.migration import TransitionFailure
from test_application_modification import configured_change, propose, prepare, activate_change
from test_migration import application, frames, keys, run, publish, TABLE_ID, TENANT
from test_rewrap_plan import _snapshot
from test_search_retained_readers import remove_current
from test_online_protection import app
from test_online_tenants import tenant_app


def changed_config(app, field_name):
    lock = app.plan.document['lock']
    declaration = lock['declaration']
    changed = []
    for model in declaration['models']:
        for field in model['fields']:
            if field['name'] == field_name:
                field.update(queries=['equality'], accept_leakage=['equality'])
                changed.append(SearchReview(UUID(field['field_id']), False, 'synthetic unbounded text'))
    writers = WriterInventory(True, tuple(Writer(UUID(item['table_id']), item['name'], item['route'],
        item['excluded'], item['evidence']) for item in lock['writer_inventory']['writers']))
    reviews = tuple(SearchReview(UUID(item['field_id']), item['small_domain'], item['evidence']) for item in lock['search_reviews'])
    return ApplicationConfig(json.dumps(declaration).encode(), app.mapping, writers, reviews + tuple(changed))


@pytest.mark.parametrize('mode', ['sync', 'async', 'sqlmodel', 'sqlmodel_async'])
def test_fixed_tenant_adapter_search_and_native_removal(mode):
    from test_single_tenant_update import single_application, snapshot
    with single_application(queries=[]) as app:
        configured = changed_config(app, 'value')
        before = snapshot(app)
        run(app); publish(app)
        activate_change(configured, app, propose(configured, app))
        statement = select(app.Customer.record).where(app.Customer.value.in_(['seed']))
        if 'async' in mode:
            async def exercise():
                runtime = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                    async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
                try:
                    factory = await configured.attach(runtime, deployment=(app.plan, app.pin), keys=keys,
                        adapter='sqlmodel' if mode.startswith('sqlmodel') else 'sqlalchemy')
                    async with factory(tenant_id=TABLE_ID) as session:
                        assert (await session.scalars(statement)).all() == [UUID(int=102)]
                        (await session.get(app.Customer, UUID(int=101))).value = 'latest'
                        await session.commit()
                finally: await runtime.dispose()
            asyncio.run(exercise())
        else:
            factory = configured.attach(app.runtime, deployment=(app.plan, app.pin), keys=keys,
                adapter='sqlmodel' if mode == 'sqlmodel' else 'sqlalchemy')
            with factory(tenant_id=TABLE_ID) as session:
                assert session.scalars(statement).all() == [UUID(int=102)]
                session.get(app.Customer, UUID(int=101)).value = 'latest'
                session.commit()
        remove_current(app, keys)
        assert snapshot(app) == [(identity, 'latest' if identity == UUID(int=101) else value, label)
                                 for identity, value, label in before]


def test_multitable_change_preserves_other_frames_unique_indexes_and_tenant_scope():
    from test_migration_multitable import multiple_tables, other_frames, OTHER_TENANT
    from test_rewrap_abort import index_identity
    with multiple_tables() as app:
        configured = changed_config(app, 'note')
        statement = select(app.other.id).where(app.other.note == app.notes[UUID(int=101)])
        with Session(app.runtime) as session:
            expected = session.scalars(statement).all()
        run(app); publish(app)
        original = frames(app, True), other_frames(app, True), index_identity(app)
        activate_change(configured, app, propose(configured, app))
        assert (frames(app, True), other_frames(app, True), index_identity(app)) == original
        factory = configured.attach(app.runtime, deployment=(app.plan, app.pin), keys=keys)
        with factory(tenant_id=TENANT) as session:
            assert session.scalars(statement).all() == expected
        with factory(tenant_id=OTHER_TENANT) as session:
            assert session.scalars(statement).all() == []


def test_missing_preapproved_search_root_refuses_without_database_effects(monkeypatch):
    import test_migration as fixture
    def storage_keys(tenant):
        original = keys(tenant)
        return Keyring(replace(original.policy, search_generation=None,
            wrappers=tuple(w for w in original.policy.wrappers if w.context.purpose == 'payload')), original._providers)
    monkeypatch.setattr(fixture, 'keys', storage_keys)
    with fixture.application(unique=False, queries=[]) as app:
        configured = configured_change(app)
        fixture.run(app); fixture.publish(app)
        before = _snapshot(app)
        with pytest.raises(TransitionFailure, match='profile_requires_approved_search_root'):
            configured.plan_modification(app.owner, deployment=(app.plan, app.pin), keys=storage_keys,
                backfill_rows_per_second=1000, verify_rows_per_second=1000,
                temporary_bytes_per_row=1024, wal_bytes_per_row=2048)
        assert _snapshot(app) == before


@pytest.mark.parametrize('rows', [0, 3])
def test_empty_and_all_null_scopes_still_require_keys_and_preserve_nulls(rows):
    with application(rows=rows, unique=False, queries=[], protected_values=(None,)) as app:
        configured = configured_change(app)
        run(app); publish(app)
        activate_change(configured, app, propose(configured, app))
        assert frames(app, True) == {identity: None for identity in app.source}
        remove_current(app, keys)


def test_modification_after_online_protection_preserves_access_contract(tenant_app):
    from test_application_online import configuration
    from test_online_protection import _pin, _engine
    from test_online_tenants import _transition_approval
    app = tenant_app
    configured = configuration(app, app.tenant_plan)
    deployment = app.tenant_plan, _pin(app.tenant_plan, 'PREPARED')
    configured.capture_online(app.owner, deployment=deployment, keys=keys, approval=app.approval,
        max_chunks=100, fence=True)
    configured.capture_online(app.owner, deployment=deployment, keys=keys, approval=app.approval, max_chunks=100)
    successor = configured.seal_online(app.owner, deployment=deployment, keys=keys, approval=app.approval)
    configured.switch_online(app.owner, deployment=deployment, successor=successor, keys=keys, approval=app.approval)
    maintenance = _transition_approval(app)
    configured.apply(app.owner, deployment=(successor, _pin(successor, 'ACTIVATING')),
        keys=keys, approval=maintenance, until='ACTIVE')
    app.plan, app.pin, app.approval = successor, _pin(successor, 'ACTIVE'), maintenance
    access = successor.document['access_contract']
    changed = changed_config(app, 'label')
    activate_change(changed, app, propose(changed, app))
    assert app.plan.document['format'] == 'cryptalis.transition/v18'
    assert app.plan.document['access_contract'] == access
    fresh = registry(metadata=MetaData(schema=app.schema))
    models = {}
    for mapper in app.mapping.mappers:
        models[mapper.class_.__name__] = type(mapper.class_.__name__, (), {})
        fresh.map_imperatively(models[mapper.class_.__name__], mapper.local_table.to_metadata(fresh.metadata))
    factory = changed.attach(app.target, deployment=(app.plan, app.pin), keys=keys)
    with factory(tenant_id=TABLE_ID) as session:
        assert session.scalar(select(app.Customer.id).where(app.Customer.label == 'label-20')) == UUID(int=20)

    from test_deprotection import app_pin
    new_tenant = UUID(int=98834)
    addition = changed.plan_tenant(app.owner, deployment=(app.plan, app.pin), keys=keys,
        tenant_id=new_tenant, key_policy=keys(new_tenant), verify_rows_per_second=1000)
    successor = addition.activation_plan
    changed.provision_tenant(app.owner, proposal=addition,
        deployment=(successor, app_pin(successor, 'PREPARED')), keys=keys, approval=app.approval)
    changed.apply(app.owner, deployment=(successor, app_pin(successor, 'ACTIVATING')),
        keys=keys, approval=app.approval, until='ACTIVE')
    runtime = _engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
    try:
        factory = replace(changed, mapping=fresh).attach(runtime,
            deployment=(successor, app_pin(successor, 'ACTIVE')), keys=keys)
        with factory(tenant_id=new_tenant) as session:
            customer = models['TenantCustomer']
            assert session.scalars(select(customer.id).where(customer.name == 'none')).all() == []
    finally:
        runtime.dispose(); fresh.dispose()
