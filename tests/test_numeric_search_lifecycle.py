"""Numeric equality survives rotation, profile changes, capture and native exit."""
from contextlib import contextmanager
from decimal import Decimal
import os
import subprocess
from uuid import UUID

import pytest
from sqlalchemy import Column, MetaData, Numeric, Table, Text, Uuid, func, insert, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, registry

from cryptalis import deprotection as d, migration as m, online
from cryptalis.sqlalchemy import UnsupportedProtectedOperation, attach
from test_date_lifecycle import date_application, date_keys, remove_date, rotate_all
from test_migration import application, engine, keys, publish, run, TENANT, TABLE_ID
from test_numeric_search import CASES, frozen, observe
from test_online_protection import app, _pin, _payloads, _source_rows


@contextmanager
def attached_numeric(app, dtype, resolver=keys):
    mapping = registry(metadata=MetaData(schema=app.schema))
    table = Table('customer', mapping.metadata,
        Column('id', Uuid, primary_key=True, autoincrement=False), Column('tenant_id', Uuid, nullable=False),
        Column('name', dtype), Column('label', Text))
    class Customer: pass
    mapping.map_imperatively(Customer, table)
    runtime = engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
    try:
        factory = attach(mapping, runtime, lock=app.plan.lock_bytes, keys=resolver,
                         deployment=(app.plan, app.pin))
        yield Customer, factory
    finally:
        runtime.dispose(); mapping.dispose()


@pytest.mark.parametrize('public_slots', [False, True])
@pytest.mark.parametrize('dtype,values,pivots,write', CASES)
def test_numeric_equality_all_rotations_current_edits_and_both_exits(public_slots, dtype, values, pivots, write):
    with date_application(public_slots=public_slots, value_type=dtype, values=values,
                          value_default=None, value_queries=('equality',)) as app:
        with Session(app.runtime) as session:
            expected = observe(session, app.Customer, pivots)
            session.get(app.Customer, UUID(int=101)).name = write
            session.flush()
            changed = observe(session, app.Customer, pivots)
            session.rollback()
        run(app); publish(app); rotate_all(app)
        with attached_numeric(app, dtype, date_keys) as (Customer, factory):
            with factory(tenant_id=TENANT) as session:
                assert observe(session, Customer, pivots) == expected
                session.get(Customer, UUID(int=101)).name = write
                session.commit()
                assert observe(session, Customer, pivots) == changed
        remove_date(app)
        with Session(app.runtime) as session:
            assert observe(session, app.Customer, pivots) == changed


@pytest.mark.parametrize('public_slots', [False, True])
def test_numeric_unique_index_survives_rotations_current_edit_and_removal(public_slots):
    values = (Decimal('1.20'), Decimal('2.30'), Decimal('-0.00'), None,
              Decimal('4.500'), Decimal('-2.00'), Decimal('5.6'))
    def duplicate(model, factory):
        with factory() as session:
            savepoint = session.begin_nested()
            with pytest.raises(IntegrityError) as failure:
                session.execute(insert(model), [{'id': UUID(int=900), 'tenant_id': TENANT,
                                                 'name': Decimal('1.20000')}])
            assert failure.value.orig.sqlstate == '23505'
            savepoint.rollback()
            assert session.scalar(select(model.id).where(model.tenant_id == TENANT,
                model.name == Decimal('1.2'))) == UUID(int=100)
            session.rollback()
    with date_application(public_slots=public_slots, value_type=Numeric(), values=values,
                          value_default=None, value_queries=('equality', 'unique')) as app:
        duplicate(app.Customer, lambda: Session(app.runtime))
        run(app); publish(app); rotate_all(app)
        with attached_numeric(app, Numeric(), date_keys) as (Customer, factory):
            duplicate(Customer, lambda: factory(tenant_id=TENANT))
            with factory(tenant_id=TENANT) as session:
                session.get(Customer, UUID(int=101)).name = Decimal('8.9000')
                session.commit()
        remove_date(app)
        duplicate(app.Customer, lambda: Session(app.runtime))
        with Session(app.runtime) as session:
            assert frozen(session.scalar(select(app.Customer.name).where(
                app.Customer.id == UUID(int=101)))) == frozen(Decimal('8.9000'))


@pytest.mark.parametrize('dtype,values,pivots,write', CASES[:2])
def test_numeric_equality_enable_disable_reenable_retains_current_data(dtype, values, pivots, write):
    from test_application_modification import activate_change, configured_change, propose
    from test_modification_storage import storage_change
    from test_search_retained_readers import remove_current
    with application(value_type=dtype, unique=False, queries=[], protected_values=values) as app:
        with Session(app.runtime) as session:
            expected = observe(session, app.Customer, pivots)
            session.get(app.Customer, UUID(int=101)).name = write
            session.flush()
            changed = observe(session, app.Customer, pivots)
            session.rollback()
        run(app); publish(app)
        configured = configured_change(app)
        activate_change(configured, app, propose(configured, app))
        with attached_numeric(app, dtype) as (Customer, factory):
            with factory(tenant_id=TENANT) as session:
                assert observe(session, Customer, pivots) == expected
        configured = storage_change(app)
        activate_change(configured, app, propose(configured, app))
        with attached_numeric(app, dtype) as (Customer, factory):
            with factory(tenant_id=TENANT) as session:
                with pytest.raises(UnsupportedProtectedOperation):
                    session.execute(select(Customer).where(Customer.tenant_id == TENANT,
                        Customer.name == pivots[0]))
                session.get(Customer, UUID(int=101)).name = write
                session.commit()
        configured = configured_change(app)
        activate_change(configured, app, propose(configured, app))
        with attached_numeric(app, dtype) as (Customer, factory):
            with factory(tenant_id=TENANT) as session:
                assert observe(session, Customer, pivots) == changed
        remove_current(app, keys)
        with Session(app.runtime) as session:
            assert observe(session, app.Customer, pivots) == changed


ONLINE_CASES = [(dtype, (values[0], values[1], None), ('equality',))
                for dtype, values, _, _ in CASES]


def online_queries(session, model):
    result = {}
    for name, predicate in {
        'all': None, 'scale': model.body == Decimal('1.200'),
        'unrounded': model.body == Decimal('1.205'), 'rounded': model.body == Decimal('1.21'),
        'zero': model.body == 0, 'null': model.body.is_(None),
        'in': model.body.in_([Decimal('1.2000'), Decimal('15000.0'), None]),
        'not_in': model.body.not_in([Decimal('1.2'), None]),
    }.items():
        statement = select(model.id, model.body).order_by(model.id)
        if predicate is not None:
            statement = statement.where(predicate)
        result[name] = [tuple(frozen(value) for value in row) for row in session.execute(statement)]
    result['distinct'] = session.scalar(select(func.count(model.body.distinct())))
    return result


@pytest.mark.parametrize('app', ONLINE_CASES, indirect=True)
def test_online_numeric_equality_capture_resume_current_values_and_native_exit(app):
    first = online.apply(app.plan, app.owner, keys=keys, pin=app.pin, approval=app.approval, max_chunks=1)
    assert first.committed_chunks == 1
    source = _source_rows(app)
    with app.source_factory() as session:
        # An equivalent Decimal scale can be a native ORM no-op. Force a real
        # value change so capture invalidation is observable in every typmod.
        session.get(app.Customer, UUID(int=10)).body = None
        session.add(app.Customer(id=UUID(int=5), body=source[UUID(int=10)][0], label='captured new'))
        session.delete(session.get(app.Customer, UUID(int=30)))
        session.commit()
        expected = online_queries(session, app.Customer)
    assert _payloads(app, app.plan)[UUID(int=10)] == (None, None)
    online.apply(type(app.plan)(app.plan.artifact), app.owner, keys=keys, pin=app.pin,
                 approval=app.approval, max_chunks=1)
    online.apply(app.plan, app.owner, keys=keys, pin=app.pin, approval=app.approval, fence=True)
    with pytest.raises(m.TransitionFailure, match='online_catchup_required'):
        online.seal(app.plan, app.owner, keys=keys, pin=app.pin, approval=app.approval)
    assert online.status(app.plan, app.owner, pin=app.pin).phase == 'FENCED'
    online.apply(app.plan, app.owner, keys=keys, pin=app.pin, approval=app.approval, max_chunks=10)
    successor = online.seal(app.plan, app.owner, keys=keys, pin=app.pin, approval=app.approval)
    online.switch(app.plan, app.owner, successor=successor, keys=keys, pin=app.pin, approval=app.approval)
    maintenance = m.MaintenanceApproval(app.approval.owner_writer_exclusion, 3600)
    m.apply(successor, app.owner, keys=keys, pin=_pin(successor, 'ACTIVATING'), approval=maintenance, until='ACTIVE')
    factory = attach(app.mapping, app.target, lock=successor.lock_bytes, keys=keys,
                     deployment=(successor, _pin(successor, 'ACTIVE')))
    with factory(tenant_id=TABLE_ID) as session:
        assert online_queries(session, app.Customer) == expected
        session.get(app.Customer, UUID(int=20)).body = None
        session.commit()
        latest = online_queries(session, app.Customer)
    reverse = d.plan(successor, app.owner, source_pin=_pin(successor, 'ACTIVE'), keys=keys,
        plaintext_runtime_role=app.source_role, backfill_rows_per_second=1000,
        verify_rows_per_second=1000, temporary_bytes_per_row=1024, wal_bytes_per_row=2048)
    consent = d.PlaintextApproval(reverse.target_id, reverse.operation_id, reverse.digest,
                                 True, 'Public disposable numeric equality capture fixture.')
    d.apply(reverse, app.owner, keys=keys, pin=_pin(reverse, 'PREPARED'), approval=maintenance, consent=consent)
    d.apply(reverse, app.owner, keys=keys, pin=_pin(reverse, 'PLAINTEXT_ACTIVATING'),
            approval=maintenance, consent=consent, until='PLAINTEXT_ACTIVE')
    removal = d.RemovalApproval(reverse.target_id, reverse.operation_id, reverse.digest,
        'Native numeric equality and current values match.', 'No retained protected fixture.', True)
    d.remove(reverse, app.owner, pin=_pin(reverse, 'REMOVING'), approval=maintenance,
             removal=removal, consent=consent)
    with app.source_factory() as session:
        assert online_queries(session, app.Customer) == latest


@pytest.mark.parametrize('search', [False, True])
def test_retained_v12_reader_accepts_numeric_storage_and_refuses_equality_before_sql(tmp_path, search):
    reader = os.environ.get('CRYPTALIS_NUMERIC_SEARCH_PREVIOUS_READER_PYTHON')
    if not reader:
        pytest.skip('supply the retained installed v12 reader interpreter')
    with application(value_type=Numeric(), unique=False, queries=['equality'] if search else [],
                     protected_values=(Decimal('1.2300'), None)) as app:
        artifact = tmp_path / 'saved-plan.json'
        artifact.write_bytes(app.plan.artifact)
        child = subprocess.run([reader, '-B', '-I', '-c', '''
from pathlib import Path
import sys
from sqlalchemy.engine import Engine
def forbidden(*args, **kwargs):
    raise AssertionError('historical reader attempted SQL')
Engine.connect = forbidden
from cryptalis.migration import MigrationPlan, TransitionFailure
try:
    MigrationPlan(Path(sys.argv[1]).read_bytes()).document
except TransitionFailure as failure:
    assert sys.argv[2] == 'search' and failure.code == 'invalid_plan'
else:
    assert sys.argv[2] == 'storage'
print('reader boundary passed')
''', str(artifact), 'search' if search else 'storage'], capture_output=True, text=True, timeout=30)
        assert child.returncode == 0, 'historical reader boundary failed; diagnostics withheld'
        assert child.stdout.strip() == 'reader boundary passed'
