"""Native retained search readers require exact host-pinned policies."""
from contextlib import contextmanager
from dataclasses import replace
import json
from types import SimpleNamespace
from uuid import UUID, uuid5

import pytest
from sqlalchemy import Column, MetaData, Table, Text, Uuid, event, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import registry

from cryptalis import migration as m, rotation as r
from cryptalis.crypto import Keyring, WrappedRoot
from cryptalis.manifest.compiler import SearchReview, Writer, WriterInventory
from cryptalis.sqlalchemy import PolicyMismatch, attach
from test_deprotection import app_pin, consent, d, least_privilege_role, native_rows, reverse
from test_migration import (
    DOMAIN, FIELD_ID, PROVIDER, TABLE_ID, TENANT, PublicFixtureProvider,
    application, engine, frames, keys,
)
from test_payload_rotation_plan import target_factory as payload_target_factory
from test_rewrap_plan import _target as rewrap_target_factory
import test_sqlalchemy_search as unbound


def retained_keys(tenant):
    source = keys(tenant)
    old = next(w for w in source.policy.wrappers if w.context.purpose == 'search')
    context = replace(old.context, root_id=uuid5(DOMAIN, f'{tenant}:retained-search:2'), generation=2)
    selected = WrappedRoot(PROVIDER, context, b'PUBLIC TEST WRAPPER')
    return Keyring(replace(source.policy, wrappers=source.policy.wrappers + (selected,),
                           search_generation=2), {PROVIDER: PublicFixtureProvider()})


def protect(app):
    declaration = app.plan.document['lock']['declaration']
    app.plan = m.plan(json.dumps(declaration).encode(), app.mapping, app.owner,
        writers=WriterInventory(True, (Writer(TABLE_ID, 'app', 'sqlalchemy',
                                              evidence='owned retained-reader fixture'),)),
        search_reviews=(SearchReview(FIELD_ID, False, 'public synthetic values'),),
        keys=retained_keys, runtime_role=app.role, target_id=app.plan.target_id,
        backfill_rows_per_second=1000, verify_rows_per_second=1000,
        temporary_bytes_per_row=700, wal_bytes_per_row=2000)
    app.pin = app_pin(app.plan, 'PREPARED')
    assert m.apply(app.plan, app.owner, keys=retained_keys, pin=app.pin,
                   approval=app.approval).phase == 'PENDING'
    assert m.apply(app.plan, app.owner, keys=retained_keys,
        pin=replace(app.pin, phase='ACTIVATING'), approval=app.approval,
        until='ACTIVE').phase == 'ACTIVE'
    app.pin = replace(app.pin, phase='ACTIVE')


@contextmanager
def attached(app, factory, deployment=None):
    mapping = registry(metadata=MetaData(schema=app.schema))
    table = Table('customer', mapping.metadata,
        Column('id', Uuid, primary_key=True, autoincrement=False),
        Column('tenant_id', Uuid, nullable=False), Column('name', Text(collation='C')),
        Column('label', Text))
    class Customer:
        pass
    mapping.map_imperatively(Customer, table)
    runtime = engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
    try:
        sessions = attach(mapping, runtime, lock=app.plan.lock_bytes, keys=factory,
                          deployment=deployment or (app.plan, app.pin))
        yield SimpleNamespace(Customer=Customer, sessions=sessions, runtime=runtime)
    finally:
        runtime.dispose()
        mapping.dispose()


def remove_current(app, factory):
    proposal = d.plan(app.plan, app.owner, source_pin=app.pin, keys=factory,
        plaintext_runtime_role=least_privilege_role(app), backfill_rows_per_second=1000,
        verify_rows_per_second=1000, temporary_bytes_per_row=700, wal_bytes_per_row=700)
    assert reverse(app, proposal, key_resolver=factory).phase == 'PLAINTEXT_PENDING'
    pure, _ = consent(proposal)
    assert d.apply(proposal, app.owner, keys=factory,
        pin=app_pin(proposal, 'PLAINTEXT_ACTIVATING'), approval=app.approval,
        consent=pure, until='PLAINTEXT_ACTIVE').phase == 'PLAINTEXT_ACTIVE'
    removal = d.RemovalApproval(proposal.target_id, proposal.operation_id, proposal.digest,
        'native latest-value workload with retained search readers', 'retained public fixture roots', True)
    assert d.remove(proposal, app.owner, pin=app_pin(proposal, 'REMOVING'),
        approval=app.approval, removal=removal, consent=pure).phase == 'REMOVED'
    assert d.check_removed(proposal, app.owner, pin=app_pin(proposal, 'REMOVED')) is None


def test_bound_retained_search_readers_preserve_queries_uniqueness_latest_values_and_removal():
    with application() as app:
        protect(app)
        expected = dict(app.source)
        with attached(app, retained_keys) as current:
            C = current.Customer
            with current.sessions(tenant_id=TENANT) as session:
                assert {row.id: (row.tenant_id, row.name) for row in session.scalars(select(C))} == expected
                assert session.scalar(select(C.id).where(C.name == '雪😀')) == UUID(int=102)
                assert set(session.scalars(select(C.id).where(C.name.in_(['雪😀', 'exact', 'absent'])))) == {
                    UUID(int=102), UUID(int=105)}
                session.add(C(id=UUID(int=9900), tenant_id=TENANT, name='exact'))
                with pytest.raises(IntegrityError) as duplicate:
                    session.commit()
                assert duplicate.value.orig.sqlstate == '23505'
                session.rollback()
                session.get(C, UUID(int=101)).name = 'latest retained search'
                session.add(C(id=UUID(int=9901), tenant_id=TENANT, name='added retained search'))
                session.delete(session.get(C, UUID(int=106)))
                session.commit()
            expected[UUID(int=101)] = TENANT, 'latest retained search'
            expected[UUID(int=9901)] = TENANT, 'added retained search'
            del expected[UUID(int=106)]
            with current.sessions(tenant_id=TENANT) as session:
                assert {row.id: (row.tenant_id, row.name) for row in session.scalars(select(C))} == expected
                assert set(session.scalars(select(C.id).where(C.name.in_(
                    ['latest retained search', 'added retained search'])))) == {UUID(int=101), UUID(int=9901)}
        assert all(body is None or int.from_bytes(body[10:14], 'big') == 2 for body in frames(app, True).values())
        remove_current(app, retained_keys)
        assert native_rows(app) == expected


@pytest.mark.parametrize('fault', ['selected_generation', 'selected_root', 'retained_wrapper', 'missing_retained'])
@pytest.mark.parametrize('operation', ['query', 'unique_insert'])
def test_bound_search_policy_mutation_fails_before_sql(fault, operation):
    with application() as app:
        protect(app)
        active = {'ring': retained_keys(TENANT)}
        with attached(app, lambda tenant: active['ring']) as current:
            with current.sessions(tenant_id=TENANT) as session:
                assert session.scalar(select(current.Customer.name).where(current.Customer.id == UUID(int=105))) == 'exact'
            old = active['ring'].policy
            wrappers = list(old.wrappers)
            if fault == 'selected_generation':
                changed = replace(old, search_generation=1)
            else:
                index = next(i for i, item in enumerate(wrappers) if item.context.purpose == 'search'
                             and item.context.generation == (2 if fault == 'selected_root' else 1))
                if fault == 'selected_root':
                    wrappers[index] = replace(wrappers[index], context=replace(wrappers[index].context,
                        root_id=uuid5(DOMAIN, f'{TENANT}:unpublished-search:2')))
                elif fault == 'retained_wrapper':
                    wrappers[index] = replace(wrappers[index], sealed=b'UNPUBLISHED PUBLIC WRAPPER')
                else:
                    wrappers.pop(index)
                changed = replace(old, wrappers=tuple(wrappers))
            active['ring'] = Keyring(changed, {PROVIDER: PublicFixtureProvider()})
            observed = []
            event.listen(current.runtime, 'before_cursor_execute', lambda *args: observed.append(True))
            before = frames(app, True)
            with pytest.raises(PolicyMismatch):
                with current.sessions(tenant_id=TENANT) as session:
                    if operation == 'query':
                        session.scalars(select(current.Customer).where(current.Customer.name == 'exact')).all()
                    else:
                        session.add(current.Customer(id=UUID(int=9910), tenant_id=TENANT, name='exact'))
                        session.commit()
            assert observed == []
            assert frames(app, True) == before


@pytest.mark.parametrize('kind', ['rewrap', 'payload'])
def test_retained_search_admission_survives_later_successor_kinds(kind):
    with application() as app:
        protect(app)
        source, source_pin = app.plan, app.pin
        if kind == 'rewrap':
            target, _ = rewrap_target_factory(retained_keys)
            proposal = r.plan_rewrap(source, app.owner, source_pin=source_pin, keys=retained_keys,
                                    target_keys=target, verify_rows_per_second=1000)
            activation = proposal.activation_plan
            assert r.apply_rewrap(proposal, app.owner, keys=retained_keys, target_keys=target,
                pin=app_pin(activation, 'PREPARED'), approval=app.approval).phase == 'PENDING'
        else:
            target, _ = payload_target_factory(source=retained_keys)
            proposal = r.plan_payload_rotation(source, app.owner, source_pin=source_pin,
                keys=retained_keys, target_keys=target, backfill_rows_per_second=1000,
                verify_rows_per_second=1000, temporary_bytes_per_row=1024, wal_bytes_per_row=2048)
            preparation_pin = m.DeploymentPin(source.target_id, proposal.operation_id,
                                               proposal.digest, 'PREPARED')
            assert r.apply_payload_rotation(proposal, app.owner, keys=retained_keys, target_keys=target,
                pin=preparation_pin, approval=app.approval).phase == 'BACKFILLED'
            activation = r.seal_payload_rotation(proposal, app.owner, keys=retained_keys,
                target_keys=target, pin=preparation_pin, approval=app.approval,
                copy_rows_per_second=1000, copy_wal_bytes_per_row=2048)
            assert r.switch_payload_rotation(proposal, activation, app.owner, keys=retained_keys,
                target_keys=target, pin=app_pin(activation, 'PREPARED'), approval=app.approval).phase == 'PENDING'
        assert m.apply(activation, app.owner, keys=target, pin=app_pin(activation, 'ACTIVATING'),
                       approval=app.approval, until='ACTIVE').phase == 'ACTIVE'
        app.plan, app.pin = activation, app_pin(activation, 'ACTIVE')
        with pytest.raises(PolicyMismatch):
            with attached(app, retained_keys, deployment=(source, source_pin)):
                pass
        with attached(app, target) as current:
            with current.sessions(tenant_id=TENANT) as session:
                assert session.scalar(select(current.Customer.name).where(current.Customer.id == UUID(int=105))) == 'exact'
                session.get(current.Customer, UUID(int=105)).name = 'latest successor retained search'
                session.commit()
                assert session.scalar(select(current.Customer.id).where(
                    current.Customer.name == 'latest successor retained search')) == UUID(int=105)
        assert all(body is None or int.from_bytes(body[10:14], 'big') == 2 for body in frames(app, True).values())


@pytest.mark.parametrize('selected', [1, 2])
def test_unbound_mixed_search_readers_remain_refused_before_sql(selected):
    with unbound.search_application(unique=True) as app:
        old = app.rings[unbound.TENANT].policy
        extra = unbound.create_root(app.provider, unbound.KeyContext(
            unbound.DOMAIN, unbound.TENANT, 'search', uuid5(unbound.DOMAIN, 'unbound-retained-search'), 2))
        app.rings[unbound.TENANT] = Keyring(replace(old, wrappers=old.wrappers + (extra,),
                                                 search_generation=selected), {app.provider.provider_id: app.provider})
        observed = []
        event.listen(app.engine, 'before_cursor_execute', lambda *args: observed.append(True))
        with pytest.raises(PolicyMismatch):
            with app.sessions(tenant_id=unbound.TENANT) as session:
                session.add(unbound._row(app, 'unbound mixed readers', 1))
                session.commit()
        assert observed == []
        with app.owner_engine.connect() as c:
            assert c.exec_driver_sql(f'SELECT count(*) FROM "{app.schema}".customer').scalar_one() == 0
