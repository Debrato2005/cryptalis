"""Searchable JSONB retains current native bytes through the full lifecycle."""
from copy import deepcopy
import os
from pathlib import Path
import subprocess
from uuid import UUID

import pytest
from sqlalchemy import Column, JSON, MetaData, String, Table, Uuid, bindparam, func, insert, null, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, registry

from cryptalis import deprotection as d, migration as m, online
from cryptalis.sqlalchemy import UnsupportedProtectedOperation, attach
from test_application_modification import activate_change, configured_change, propose
from test_date_lifecycle import date_application, date_keys, remove_date, rotate_all
from test_jsonb_lifecycle import native_restart, native_wire, protected_wire, seed_native
from test_jsonb_search import OBJECT, VALUES, attached_jsonb, observe
from test_jsonb_storage import state, wire
from test_migration import TABLE_ID, TENANT, application, keys, publish, run
from test_modification_storage import storage_change
from test_online_protection import app, _payloads, _pin
from test_search_retained_readers import remove_current


def current_edits(session, model):
    session.get(model, UUID(int=100)).name = {'current': [1.0, True, None]}
    session.get(model, UUID(int=101)).name = None
    session.get(model, UUID(int=102)).name = JSON.NULL
    session.delete(session.get(model, UUID(int=106)))
    session.add_all((model(id=UUID(int=950), tenant_id=TENANT, name={'current': [1, True, None]}),
                    model(id=UUID(int=951), tenant_id=TENANT, name=null())))
    session.flush()


@pytest.mark.parametrize('public_slots', [False, True])
@pytest.mark.parametrize('none_as_null', [False, True])
def test_jsonb_equality_rotations_current_wire_and_package_free_native_exit(public_slots, none_as_null):
    with date_application(public_slots=public_slots, value_type=JSONB(none_as_null=none_as_null),
                          values=deepcopy(VALUES), value_default=None, value_queries=('equality',)) as app:
        seed_native(app)
        source = wire(app)
        with Session(app.runtime) as session:
            original = observe(session, app.Customer)
            current_edits(session, app.Customer)
            latest = wire(app, session.connection())
            changed = observe(session, app.Customer)
            session.rollback()
        run(app); publish(app)
        assert protected_wire(app, keys) == source
        rotate_all(app)
        assert protected_wire(app, date_keys) == source
        with attached_jsonb(app, none_as_null, date_keys) as (Model, factory):
            with factory(tenant_id=TENANT) as session:
                assert observe(session, Model) == original
                current_edits(session, Model)
                session.commit()
                assert observe(session, Model) == changed
        assert protected_wire(app, date_keys) == latest
        remove_date(app)
        assert wire(app) == latest
        with Session(app.runtime) as session:
            assert observe(session, app.Customer) == changed
        native_restart(app.schema, latest, none_as_null=none_as_null,
                       directory=os.environ.get('TMPDIR', '/tmp'))


def test_jsonb_scoped_unique_index_survives_three_rotations_and_native_removal():
    values = tuple({'unique': index} for index in range(6)) + (None,)
    def duplicate(factory, Model):
        with factory() as session:
            savepoint = session.begin_nested()
            with pytest.raises(IntegrityError) as failure:
                session.execute(insert(Model), [{'id': UUID(int=900), 'tenant_id': TENANT,
                                                  'name': {'unique': 1.000}}])
            assert failure.value.orig.sqlstate == '23505'; savepoint.rollback()
            assert session.scalar(select(Model.id).where(Model.tenant_id == TENANT,
                Model.name == {'unique': 1.0})) == UUID(int=101)
            session.rollback()
    with date_application(public_slots=True, value_type=JSONB(), values=values,
                          value_default=None, value_queries=('equality', 'unique')) as app:
        duplicate(lambda: Session(app.runtime), app.Customer)
        run(app); publish(app); rotate_all(app)
        with attached_jsonb(app, False, date_keys) as (Model, factory):
            duplicate(lambda: factory(tenant_id=TENANT), Model)
            with factory(tenant_id=TENANT) as session:
                session.get(Model, UUID(int=100)).name = {'latest': 8.9000}
                session.commit()
        expected = protected_wire(app, date_keys)
        remove_date(app)
        assert wire(app) == expected
        duplicate(lambda: Session(app.runtime), app.Customer)


@pytest.mark.parametrize('none_as_null', [False, True])
def test_jsonb_equality_enable_disable_reenable_preserves_current_native_values(none_as_null):
    with application(value_type=JSONB(none_as_null=none_as_null), unique=False, queries=[],
                     protected_values=deepcopy(VALUES)) as app:
        with Session(app.runtime) as session:
            original = observe(session, app.Customer)
            session.get(app.Customer, UUID(int=101)).name = {'modified': [1.0, True]}
            session.flush()
            changed = observe(session, app.Customer)
            latest = wire(app, session.connection())
            session.rollback()
        run(app); publish(app)
        configured = configured_change(app)
        activate_change(configured, app, propose(configured, app))
        with attached_jsonb(app, none_as_null) as (Model, factory):
            with factory(tenant_id=TENANT) as session:
                assert observe(session, Model) == original
        configured = storage_change(app)
        activate_change(configured, app, propose(configured, app))
        with attached_jsonb(app, none_as_null) as (Model, factory):
            with factory(tenant_id=TENANT) as session:
                with pytest.raises(UnsupportedProtectedOperation):
                    session.execute(select(Model.id).where(Model.tenant_id == TENANT,
                        Model.name == deepcopy(OBJECT)))
                session.get(Model, UUID(int=101)).name = {'modified': [1.0, True]}
                session.commit()
        configured = configured_change(app)
        activate_change(configured, app, propose(configured, app))
        with attached_jsonb(app, none_as_null) as (Model, factory):
            with factory(tenant_id=TENANT) as session:
                assert observe(session, Model) == changed
        remove_current(app, keys)
        assert wire(app) == latest
        native_restart(app.schema, latest, none_as_null=none_as_null,
                       directory=os.environ.get('TMPDIR', '/tmp'))


@pytest.mark.parametrize('app', [(JSONB(), (deepcopy(OBJECT), JSON.NULL, None), ['equality'])], indirect=True)
def test_online_jsonb_equality_capture_catchup_current_wire_and_native_exit(app):
    def queries(session, Model):
        result = {}
        for name, predicate in {
            'all': None, 'captured': Model.body == {'captured': [1.000, None]},
            'json_null': Model.body == bindparam('json_null', type_=JSONB()),
            'in': Model.body.in_(bindparam('documents', type_=JSONB(), expanding=True)),
            'sql_null': Model.body.is_(None), 'active': Model.body == {'active': [1, True]},
        }.items():
            statement = select(Model.id, Model.body).order_by(Model.id)
            if predicate is not None:
                statement = statement.where(predicate)
            parameters = ({'json_null': JSON.NULL} if name == 'json_null' else
                          {'documents': [{'captured': [1.0, None]}, JSON.NULL, None]} if name == 'in' else {})
            result[name] = [(identity, state(value)) for identity, value in session.execute(statement, parameters)]
        result['distinct_count'] = session.scalar(select(func.count(Model.body.distinct())))
        return result

    def current(session, Model):
        session.get(Model, UUID(int=20)).body = {'active': [1.0, True]}
        session.get(Model, UUID(int=10)).body = null()
        session.flush()

    seed_native(app, column='body', scoped=False)
    first = online.apply(app.plan, app.owner, keys=keys, pin=app.pin, approval=app.approval, max_chunks=1)
    assert first.phase == 'CAPTURING' and first.committed_chunks == 1
    with app.source_factory() as session:
        session.get(app.Customer, UUID(int=10)).body = {'captured': [1.0, None]}
        session.get(app.Customer, UUID(int=20)).body = null()
        session.add(app.Customer(id=UUID(int=5), body={'captured': [1, None]}, label='captured below cursor'))
        session.delete(session.get(app.Customer, UUID(int=30)))
        session.commit()
        expected = queries(session, app.Customer)
        expected_wire = native_wire(app, column='body', connection=session.connection())
        current(session, app.Customer)
        latest = queries(session, app.Customer)
        latest_wire = native_wire(app, column='body', connection=session.connection())
        session.rollback()
    assert _payloads(app, app.plan)[UUID(int=10)] == (None, None)
    online.apply(type(app.plan)(app.plan.artifact), app.owner, keys=keys, pin=app.pin,
                 approval=app.approval, max_chunks=1)
    online.apply(app.plan, app.owner, keys=keys, pin=app.pin, approval=app.approval, max_chunks=0, fence=True)
    with pytest.raises(m.TransitionFailure) as pending:
        online.seal(app.plan, app.owner, keys=keys, pin=app.pin, approval=app.approval)
    assert pending.value.code == 'online_catchup_required'
    online.apply(app.plan, app.owner, keys=keys, pin=app.pin, approval=app.approval, max_chunks=20)
    successor = online.seal(app.plan, app.owner, keys=keys, pin=app.pin, approval=app.approval)
    online.switch(app.plan, app.owner, successor=successor, keys=keys, pin=app.pin, approval=app.approval)
    maintenance = m.MaintenanceApproval(app.approval.owner_writer_exclusion, 3600)
    m.apply(successor, app.owner, keys=keys, pin=_pin(successor, 'ACTIVATING'),
            approval=maintenance, until='ACTIVE')
    app.plan = successor
    assert protected_wire(app, keys, column='body', scoped=False) == expected_wire
    factory = attach(app.mapping, app.target, lock=successor.lock_bytes, keys=keys,
                     deployment=(successor, _pin(successor, 'ACTIVE')))
    with factory(tenant_id=TABLE_ID) as session:
        assert queries(session, app.Customer) == expected
        current(session, app.Customer)
        session.commit()
        assert queries(session, app.Customer) == latest
    assert protected_wire(app, keys, column='body', scoped=False) == latest_wire
    reverse = d.plan(successor, app.owner, source_pin=_pin(successor, 'ACTIVE'), keys=keys,
        plaintext_runtime_role=app.source_role, backfill_rows_per_second=1000,
        verify_rows_per_second=1000, temporary_bytes_per_row=4096, wal_bytes_per_row=8192)
    consent = d.PlaintextApproval(reverse.target_id, reverse.operation_id, reverse.digest,
        True, 'Disposable JSONB equality capture fixture; native current values and terms agree.')
    d.apply(reverse, app.owner, keys=keys, pin=_pin(reverse, 'PREPARED'), approval=maintenance, consent=consent)
    d.apply(reverse, app.owner, keys=keys, pin=_pin(reverse, 'PLAINTEXT_ACTIVATING'),
            approval=maintenance, consent=consent, until='PLAINTEXT_ACTIVE')
    removal = d.RemovalApproval(reverse.target_id, reverse.operation_id, reverse.digest,
        'Native JSONB equality/current bytes match.', 'No retained protected fixture.', True)
    d.remove(reverse, app.owner, pin=_pin(reverse, 'REMOVING'), approval=maintenance,
             removal=removal, consent=consent)
    assert native_wire(app, column='body') == latest_wire
    mapping = registry(metadata=MetaData(schema=app.schema))
    table = Table('customer', mapping.metadata, Column('id', Uuid, primary_key=True, autoincrement=False),
                  Column('body', JSONB()), Column('label', String(64, collation='C')))
    class Native: pass
    mapping.map_imperatively(Native, table)
    try:
        with Session(app.source) as session:
            assert queries(session, Native) == latest
    finally:
        mapping.dispose()
    native_restart(app.schema, latest_wire, column='body', scoped=False,
        directory=os.environ.get('TMPDIR', '/tmp'), database_variable='CRYPTALIS_TEST_SOURCE_URL')


def test_genuine_v16_reader_accepts_jsonb_storage_and_refuses_search_before_sql(tmp_path):
    reader = os.environ.get('CRYPTALIS_JSONB_SEARCH_PREVIOUS_READER_PYTHON')
    if not reader:
        pytest.skip('supply the genuine immutable v16 installed reader interpreter')
    assert Path(reader).is_absolute() and Path(reader).is_file()
    artifacts = []
    for search in (False, True):
        with application(rows=2, value_type=JSONB(), unique=False,
                         queries=['equality'] if search else [], value_default={'default': True},
                         protected_values=({'source': 1.20}, None)) as app:
            saved = tmp_path / ('search-plan.json' if search else 'storage-plan.json')
            saved.write_bytes(app.plan.artifact)
            artifacts.append(str(saved))
    child = subprocess.run([reader, '-B', '-I', '-c', '''
from pathlib import Path
import sys
from sqlalchemy.engine import Engine
attempted = []
def forbidden(*args, **kwargs):
    attempted.append(True)
    raise AssertionError('Historical reader attempted SQL')
Engine.connect = forbidden
from cryptalis.migration import MigrationPlan, TransitionFailure
for number, filename in enumerate(sys.argv[1:]):
    try: MigrationPlan(Path(filename).read_bytes()).document
    except TransitionFailure as failure:
        assert number == 1 and failure.code == 'invalid_plan'
    else: assert number == 0
assert attempted == []
print('v16 storage accepted; v17 search refused before SQL')
''', *artifacts], capture_output=True, text=True, timeout=30,
        env={'PATH': os.environ.get('PATH', ''), 'LANG': 'C.UTF-8'})
    assert child.returncode == 0, 'genuine v16 reader boundary failed; diagnostics withheld'
    assert child.stdout.strip() == 'v16 storage accepted; v17 search refused before SQL'
