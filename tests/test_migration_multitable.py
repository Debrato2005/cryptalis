"""Native same-schema application behavior, real PG faults and independent CF1 decoding."""
from contextlib import contextmanager
from dataclasses import replace
import json
import signal
from uuid import UUID

import pytest
from psycopg import sql
from sqlalchemy import Column, Index, Table, Text, Uuid, event, select
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import sessionmaker

from cryptalis.manifest.compiler import SearchReview, Writer, WriterInventory
from cryptalis.crypto.cf1 import FieldDescriptor, seal_text
from cryptalis.sqlalchemy import attach
from test_migration import application, child, frames, independent_open, keys, publish, run, FIELD_ID, TABLE_ID, TENANT

OTHER_TABLE, OTHER_FIELD, OTHER_TENANT = (UUID(int=i) for i in (801, 802, 803))
NOTE_FIELD = UUID(int=804)


@contextmanager
def multiple_tables():
    with application() as app:
        table = Table('other_customer', app.mapping.metadata,
            Column('id', Uuid, primary_key=True, autoincrement=False),
            Column('tenant_id', Uuid, nullable=False), Column('name', Text(collation='C')), Column('note', Text))
        Index('other_native_name', table.c.tenant_id, table.c.name, unique=True)
        class OtherCustomer: pass
        app.mapping.map_imperatively(OtherCustomer, table)
        table.create(app.owner)
        with app.owner.begin() as c:
            c.exec_driver_sql(f'GRANT SELECT, INSERT, UPDATE, DELETE ON "{app.schema}".other_customer TO "{app.role}"')
        app.other = OtherCustomer
        app.other_source = {identity: (tenant, None if value is None else 'other:' + value)
                            for identity, (tenant, value) in app.source.items()}
        # Same record IDs and tenants across tables, different field IDs and
        # values. A reused descriptor from the wrong field cannot authenticate.
        extras = {UUID(int=901): (OTHER_TENANT, '雪😀'), UUID(int=902): (OTHER_TENANT, '')}
        app.notes = {k: None if k==UUID(int=103) else '' if k==UUID(int=104) else 'notes:' + str(k)
                     for k in app.other_source.keys() | extras.keys()}
        with sessionmaker(app.runtime)() as session:
            session.add_all(OtherCustomer(id=k, tenant_id=t, name=v, note=app.notes[k]) for k,(t,v) in app.other_source.items())
            for model in (app.Customer, OtherCustomer):
                session.add_all(model(id=k, tenant_id=t, name=v, **({'note':app.notes[k]} if model==OtherCustomer else {})) for k,(t,v) in extras.items())
            session.commit()
        app.source.update(extras); app.other_source.update(extras)
        declaration = app.plan.document['lock']['declaration']
        declaration['models'].append({'model':'OtherCustomer','table_id':str(OTHER_TABLE),
            'tenancy':{'column':'tenant_id'},'fields':[{'name':'name','field_id':str(OTHER_FIELD),
                'protect':True,'queries':['equality','unique'],'accept_leakage':['equality','unique']},
                {'name':'note','field_id':str(NOTE_FIELD),'protect':True,'queries':[],'accept_leakage':[]}]})
        app.plan = app.m.plan(json.dumps(declaration).encode(), app.mapping, app.owner,
            writers=WriterInventory(True, tuple(Writer(t, 'app', 'sqlalchemy', evidence='native two-table application')
                                                 for t in (TABLE_ID, OTHER_TABLE))),
            search_reviews=tuple(SearchReview(f, False, 'synthetic unbounded names') for f in (FIELD_ID, OTHER_FIELD)),
            keys=keys, runtime_role=app.role, target_id=app.plan.target_id,
            backfill_rows_per_second=1000, verify_rows_per_second=1000,
            temporary_bytes_per_row=700, wal_bytes_per_row=2000)
        app.pin = app.m.DeploymentPin(app.plan.target_id, app.plan.operation_id, app.plan.digest, 'PREPARED')
        yield app


def other_frames(app, switched=False, note=False):
    column = ('note' if note else 'name') if switched else '_cryptalis_' + (NOTE_FIELD if note else OTHER_FIELD).hex
    with app.owner.connect() as c:
        return {r[0]:bytes(r[1]) if r[1] is not None else None for r in
                c.exec_driver_sql(f'SELECT id,"{column}" FROM "{app.schema}".other_customer ORDER BY id')}


def native_values(app):
    with sessionmaker(app.runtime)() as session:
        assert {r.id:r.note for r in session.scalars(select(app.other))} == app.notes
        return [{r.id:(r.tenant_id,r.name) for r in session.scalars(select(model))}
                for model in (app.Customer, app.other)]


def assert_independent_values(app):
    for table_id, expected, observed in ((TABLE_ID, app.source, frames(app, True)),
                                        (OTHER_TABLE, app.other_source, other_frames(app, True))):
        descriptor = next(m['fields'][0]['descriptor'] for m in app.plan.document['lock']['models']
                          if m['table_id'] == str(table_id))
        assert observed.keys() == expected.keys()
        for identity, frame in observed.items():
            tenant, value = expected[identity]
            assert independent_open(frame, descriptor, tenant, identity,
                                    field_id=FIELD_ID if table_id==TABLE_ID else OTHER_FIELD) == value
    descriptor = next(f['descriptor'] for m in app.plan.document['lock']['models'] for f in m['fields']
                      if f['field_id']==str(NOTE_FIELD))
    observed = other_frames(app, True, True)
    assert observed.keys() == app.notes.keys()
    for identity, frame in observed.items():
        assert independent_open(frame, descriptor, app.other_source[identity][0], identity, field_id=NOTE_FIELD) == app.notes[identity]


def assert_no_guards(app):
    with app.owner.connect() as c:
        assert c.exec_driver_sql('SELECT count(*) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=%s', (app.schema,)).scalar_one() == 0
        assert c.exec_driver_sql('SELECT count(*) FROM pg_catalog.pg_trigger g JOIN pg_catalog.pg_class r ON r.oid=g.tgrelid JOIN pg_catalog.pg_namespace n ON n.oid=r.relnamespace WHERE n.nspname=%s AND NOT g.tgisinternal', (app.schema,)).scalar_one() == 0


def test_same_schema_tables_publish_and_use_native_application_values():
    with multiple_tables() as app:
        assert native_values(app) == [app.source, app.other_source]
        assert run(app).phase == 'PENDING'
        assert_independent_values(app)
        for model in (app.Customer, app.other):
            with sessionmaker(app.runtime)() as session:
                # A typed native DELETE reaches the statement guard even after
                # protection has changed the physical column to bytea.
                with pytest.raises(DBAPIError) as failure:
                    session.execute(model.__table__.delete().where(model.id==UUID(int=103)))
                assert getattr(getattr(failure.value, 'orig', None), 'sqlstate', None) == '55000'
        with app.owner.connect() as c:
            # Native catalog proves separate table triggers refer to the one
            # operation function, with no change to the recorded names.
            assert c.exec_driver_sql('SELECT count(*),count(DISTINCT g.tgrelid),count(DISTINCT g.tgfoid) FROM pg_catalog.pg_trigger g JOIN pg_catalog.pg_class r ON r.oid=g.tgrelid JOIN pg_catalog.pg_namespace n ON n.oid=r.relnamespace WHERE n.nspname=%s AND NOT g.tgisinternal', (app.schema,)).one() == (2, 2, 1)
        publish(app); assert_no_guards(app)
        sessions = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys, deployment=(app.plan, app.pin))
        for tenant in (TENANT, OTHER_TENANT):
            with sessions(tenant_id=tenant) as session:
                for model, expected in ((app.Customer, app.source), (app.other, app.other_source)):
                    observed = {r.id:(r.tenant_id,r.name) for r in session.scalars(select(model).where(model.tenant_id==tenant))}
                    assert observed == {k:v for k,v in expected.items() if v[0] == tenant}
                    if model == app.other:
                        assert {r.id:r.note for r in session.scalars(select(model).where(model.tenant_id==tenant))} == {k:v for k,v in app.notes.items() if expected[k][0]==tenant}
        with sessions(tenant_id=TENANT) as session:
            for model in (app.Customer, app.other): session.get(model, UUID(int=103)).name = 'current edit'
            session.commit()
            assert all(session.scalar(select(model.name).where(model.id==UUID(int=103))) == 'current edit'
                       for model in (app.Customer, app.other))


@pytest.mark.parametrize('phase', ['EXPANDED','BACKFILLED','VERIFIED','PENDING','ACTIVE'])
def test_same_schema_sigkill_resume_keeps_committed_frames(phase, tmp_path):
    with multiple_tables() as app:
        if phase == 'ACTIVE': run(app); app.pin = replace(app.pin, phase='ACTIVATING')
        process = child(app, tmp_path, phase, True)
        try:
            assert process.stdout.readline().strip() == phase
            switched = phase in ('PENDING','ACTIVE')
            before = frames(app, switched), other_frames(app, switched), other_frames(app, switched, True)
            process.send_signal(signal.SIGKILL); assert process.wait(timeout=10) == -signal.SIGKILL
            resumed = child(app, tmp_path, 'ACTIVE' if phase=='ACTIVE' else 'PENDING')
            stdout, stderr = resumed.communicate(timeout=20)
            assert resumed.returncode == 0, 'independent resume failed; diagnostics withheld'
            assert stdout.strip() == ('ACTIVE' if phase=='ACTIVE' else 'PENDING')
            if phase != 'EXPANDED': assert before == (frames(app, True), other_frames(app, True), other_frames(app, True, True))
            assert_independent_values(app)
        finally:
            if process.poll() is None: process.kill(); process.wait(timeout=10)


@pytest.mark.parametrize('phase', ['EXPANDED','BACKFILLED','VERIFIED'])
def test_same_schema_abort_restores_native_writes_idempotently(phase):
    with multiple_tables() as app:
        run(app, phase)
        assert app.m.abort(app.plan, app.owner, pin=app.pin, approval=app.approval).phase == 'ABORTED'
        assert native_values(app) == [app.source, app.other_source]
        assert_no_guards(app)
        with sessionmaker(app.runtime)() as session:
            for model in (app.Customer, app.other): session.get(model, UUID(int=103)).name = 'native after abort'
            session.commit()
        assert app.m.abort(app.plan, app.owner, pin=app.pin, approval=app.approval).phase == 'ABORTED'
        with pytest.raises(app.m.TransitionFailure, match='operation_aborted'): run(app)


def test_same_schema_failed_second_expansion_is_atomic_and_resumable():
    with multiple_tables() as app:
        def fail_second(connection, cursor, statement, parameters, context, many):
            if statement.startswith(f'ALTER TABLE "{app.schema}"."other_customer" ADD COLUMN'):
                connection.exec_driver_sql('SELECT 1/0')
        event.listen(app.owner, 'before_cursor_execute', fail_second)
        try:
            with pytest.raises(app.m.TransitionFailure) as failure: run(app)
            assert failure.value.sqlstate == '22012'
        finally:
            event.remove(app.owner, 'before_cursor_execute', fail_second)
        assert native_values(app) == [app.source, app.other_source]
        assert_no_guards(app)
        with app.owner.connect() as c:
            assert c.exec_driver_sql('SELECT pg_catalog.to_regclass(%s)', (f'"{app.schema}"._cryptalis_journal',)).scalar_one() is None
        assert run(app).phase == 'PENDING'
        assert_independent_values(app)


def test_same_schema_existing_function_is_not_replaced_or_adopted():
    with multiple_tables() as app:
        function = '_cryptalis_' + app.plan.operation_id.hex + '_guard'
        body = 'BEGIN RAISE EXCEPTION USING ERRCODE=\'P0001\'; END'
        with app.owner.begin() as c:
            literal = sql.Literal(body).as_string(c.connection.driver_connection)
            c.exec_driver_sql(f'CREATE FUNCTION "{app.schema}"."{function}"() RETURNS trigger LANGUAGE plpgsql AS {literal}')
        with pytest.raises(app.m.TransitionFailure, match='guard_function_conflict'): run(app)
        assert native_values(app) == [app.source, app.other_source]
        with app.owner.begin() as c:
            assert c.exec_driver_sql('SELECT p.prosrc FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=%s AND p.proname=%s', (app.schema,function)).scalar_one() == body
            assert c.exec_driver_sql('SELECT pg_catalog.to_regclass(%s)', (f'"{app.schema}"._cryptalis_journal',)).scalar_one() is None
            c.exec_driver_sql(f'DROP FUNCTION "{app.schema}"."{function}"()')
        assert run(app).phase == 'PENDING'
        assert_independent_values(app)


@pytest.mark.parametrize('operation', ['activation','abort'])
def test_same_schema_second_guard_retirement_failure_keeps_all_fences(operation):
    with multiple_tables() as app:
        run(app, 'PENDING' if operation=='activation' else 'BACKFILLED')
        if operation == 'activation': app.pin = replace(app.pin, phase='ACTIVATING')
        def fail_second(connection, cursor, statement, parameters, context, many):
            if statement.startswith('DROP TRIGGER ') and statement.endswith(f'ON "{app.schema}"."other_customer"'):
                connection.exec_driver_sql('SELECT 1/0')
        event.listen(app.owner, 'before_cursor_execute', fail_second)
        try:
            with pytest.raises(app.m.TransitionFailure) as failure:
                if operation == 'activation': run(app, 'ACTIVE')
                else: app.m.abort(app.plan, app.owner, pin=app.pin, approval=app.approval)
            assert failure.value.sqlstate == '22012'
        finally:
            event.remove(app.owner, 'before_cursor_execute', fail_second)
        # Native writes to both tables still reject; retiring the first trigger
        # and function must not escape the failed second retirement transaction.
        for model in (app.Customer, app.other):
            with sessionmaker(app.runtime)() as session:
                with pytest.raises(DBAPIError) as failure:
                    session.execute(model.__table__.delete().where(model.id==UUID(int=103)))
                assert failure.value.orig.sqlstate == '55000'
        with app.owner.connect() as c:
            assert c.exec_driver_sql(f'SELECT state->>\'phase\' FROM "{app.schema}"._cryptalis_journal').scalar_one() == ('PENDING' if operation=='activation' else 'BACKFILLED')
        if operation == 'activation':
            assert run(app, 'ACTIVE').phase == 'ACTIVE'; assert_independent_values(app)
        else:
            assert app.m.abort(app.plan, app.owner, pin=app.pin, approval=app.approval).phase == 'ABORTED'
            assert native_values(app) == [app.source, app.other_source]
        assert_no_guards(app)


@pytest.mark.parametrize('context', ['field','tenant','record'])
def test_reused_descriptors_still_reject_valid_wrong_context_frames(context):
    with multiple_tables() as app:
        run(app, 'BACKFILLED')
        good = other_frames(app)
        model = next(m for m in app.plan.document['lock']['models'] if m['table_id']==str(OTHER_TABLE))
        descriptor = model['fields'][0]['descriptor']
        digest = model['fields'][0]['descriptor_digest']
        tenant, record = TENANT, UUID(int=103)
        value = app.other_source[record][1]
        if context == 'field':
            other = next(m['fields'][0] for m in app.plan.document['lock']['models'] if m['table_id']==str(TABLE_ID))
            descriptor, digest = other['descriptor'], other['descriptor_digest']
        elif context == 'tenant': tenant = OTHER_TENANT
        else: record = UUID(int=7001)
        frame = seal_text(value, FieldDescriptor.from_compiled(descriptor, digest), tenant, record, keys(tenant).prepare())
        # Separate decoder proves this is a valid frame for a different context,
        # with the exact destination value. Value comparison alone cannot help.
        assert independent_open(frame, descriptor, tenant, record,
                                field_id=FIELD_ID if context=='field' else OTHER_FIELD) == value
        column = model['fields'][0]['payload_column']
        with app.owner.begin() as c:
            c.exec_driver_sql(f'UPDATE "{app.schema}".other_customer SET "{column}"=%s WHERE id=%s', (frame,UUID(int=103)))
        with pytest.raises(app.m.TransitionFailure): run(app)
        assert native_values(app) == [app.source, app.other_source]
        with app.owner.begin() as c:
            assert c.exec_driver_sql(f'SELECT state->>\'phase\' FROM "{app.schema}"._cryptalis_journal').scalar_one() == 'BACKFILLED'
            c.exec_driver_sql(f'UPDATE "{app.schema}".other_customer SET "{column}"=%s WHERE id=%s', (good[UUID(int=103)],UUID(int=103)))
        assert run(app).phase == 'PENDING'; assert_independent_values(app)


@pytest.mark.parametrize('operation', ['activation','abort'])
def test_second_table_fence_drift_cannot_remove_first_table_fence(operation):
    with multiple_tables() as app:
        run(app, 'PENDING' if operation=='activation' else 'BACKFILLED')
        if operation == 'activation': app.pin = replace(app.pin, phase='ACTIVATING')
        trigger = '_cryptalis_' + app.plan.operation_id.hex + '_pause'
        with app.owner.begin() as c:
            c.exec_driver_sql(f'ALTER TABLE "{app.schema}".other_customer DISABLE TRIGGER "{trigger}"')
        with pytest.raises(app.m.TransitionFailure, match='writer_fence_changed'):
            if operation == 'activation': run(app, 'ACTIVE')
            else: app.m.abort(app.plan, app.owner, pin=app.pin, approval=app.approval)
        with sessionmaker(app.runtime)() as session:
            with pytest.raises(DBAPIError) as failure:
                session.execute(app.table.delete().where(app.Customer.id==UUID(int=103)))
            assert failure.value.orig.sqlstate == '55000'
        with app.owner.begin() as c:
            assert c.exec_driver_sql(f'SELECT state->>\'phase\' FROM "{app.schema}"._cryptalis_journal').scalar_one() == ('PENDING' if operation=='activation' else 'BACKFILLED')
            c.exec_driver_sql(f'ALTER TABLE "{app.schema}".other_customer ENABLE ALWAYS TRIGGER "{trigger}"')
        if operation == 'activation':
            assert run(app, 'ACTIVE').phase == 'ACTIVE'; assert_independent_values(app)
        else:
            assert app.m.abort(app.plan, app.owner, pin=app.pin, approval=app.approval).phase == 'ABORTED'
            assert native_values(app) == [app.source, app.other_source]
