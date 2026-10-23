"""Native-only parameterized CASE prototype; no adapter admission is changed."""
from contextlib import contextmanager
from copy import deepcopy
import json
from uuid import UUID

from psycopg import sql
import pytest
from sqlalchemy import Column, Index, LargeBinary, MetaData, Table, Text, Uuid, bindparam, case, cast, event, func, literal, select, String, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, registry

from cryptalis.crypto import FieldDescriptor, open_text, seal_text
from test_bulk_insert_native import assert_aborted, native_application
from test_bulk_update_native import FOREIGN, MISSING, OTHER, empty_result, record
from test_migration import keys, TENANT


INVALID = b'PUBLIC VARCHAR OVERFLOW SENTINEL'


@contextmanager
def carrier_application():
    with native_application(True) as app:
        mapping = registry(metadata=MetaData(schema=app.schema))
        table = Table('carrier', mapping.metadata,
            Column('id', Uuid, primary_key=True), Column('tenant_id', Uuid, nullable=False),
            Column('name', LargeBinary), Column('label', Text))
        Index('carrier_unique', table.c.tenant_id, func.substr(table.c.name, 15, 32), unique=True)
        class Carrier:
            pass
        mapping.map_imperatively(Carrier, table)
        field = json.loads(app.plan.lock_bytes)['models'][0]['fields'][0]
        descriptor = FieldDescriptor.from_compiled(field['descriptor'], field['descriptor_digest'])
        material = keys(TENANT).prepare()
        def frame(identity, value):
            return seal_text(value, descriptor, TENANT, identity, material)
        mapping.metadata.create_all(app.owner)
        with app.owner.begin() as connection:
            connection.exec_driver_sql(sql.SQL('GRANT SELECT,INSERT,UPDATE,DELETE ON {} TO {}').format(
                sql.Identifier(app.schema, 'carrier'), sql.Identifier(app.role)).as_string())
            connection.execute(table.insert(), [
                {'id': identity, 'tenant_id': tenant, 'name': frame(identity, value), 'label': 'public source'}
                for identity, (tenant, value) in app.source.items()])
            connection.execute(table.insert(), [{'id': FOREIGN, 'tenant_id': OTHER,
                'name': seal_text('else', descriptor, OTHER, FOREIGN, keys(OTHER).prepare()),
                'label': 'public foreign'}])
        try:
            yield app, Carrier, table, descriptor, frame
        finally:
            mapping.dispose()


def statement(model):
    body = bindparam('carrier_frame', type_=LargeBinary())
    overflow = func.pg_catalog.varchar(cast(literal('xx'), String()), literal(5), literal(False))
    assignment = case((body == literal(INVALID, LargeBinary()), cast(overflow, LargeBinary())), else_=body)
    return update(model).where(model.tenant_id == TENANT).values(name=assignment)


def plans(session, schema):
    return [dict(statement=row[0], generic=row[1], custom=row[2]) for row in
            session.connection().exec_driver_sql(
                'SELECT statement,generic_plans,custom_plans FROM pg_prepared_statements '
                'WHERE statement LIKE %s ORDER BY name', (f'UPDATE {schema}.carrier%',)).all()]


def invoke(session, model, rows):
    return session.execute(statement(model), rows, execution_options={'synchronize_session': False})


@pytest.mark.parametrize('mode', ['force_custom_plan', 'force_generic_plan', 'auto'])
def test_parameterized_case_matches_native_update_planning_and_preserves_frames(mode, record_property):
    with carrier_application() as (app, model, table, descriptor, frame):
        with app.owner.connect() as connection:
            before = connection.execute(select(table).order_by(table.c.id)).all()
        sent, outcomes = [], []
        def rendered(connection, cursor, query, parameters, context, executemany):
            if query.lstrip().upper().startswith('UPDATE '):
                entry = {'sql': query, 'executemany': executemany}
                if entry not in sent:
                    sent.append(entry)
                assert 'e\u0301😀界' not in repr(parameters)
        event.listen(app.runtime, 'before_cursor_execute', rendered)
        try:
            with Session(app.runtime) as session:
                driver = session.connection().connection.driver_connection
                driver.prepare_threshold = 5 if mode == 'auto' else 0
                session.connection().exec_driver_sql(f'SET LOCAL plan_cache_mode = {mode}')
                savepoint = session.begin_nested()
                valid = [
                    {'id': UUID(int=100), 'carrier_frame': frame(UUID(int=100), 'e\u0301😀界'), 'label': 'public unicode'},
                    {'id': UUID(int=101), 'carrier_frame': None},
                    {'id': UUID(int=102), 'carrier_frame': frame(UUID(int=102), 'go  ')},
                ]
                original = deepcopy(valid)
                empty_result(invoke(session, model, valid))
                actual = {row.id: row.name for row in session.execute(select(table)).all()}
                assert actual[UUID(int=100)] == valid[0]['carrier_frame']
                assert actual[UUID(int=101)] is None
                assert actual[UUID(int=102)] == valid[2]['carrier_frame']
                assert open_text(actual[UUID(int=100)], descriptor, TENANT, UUID(int=100), keys(TENANT).prepare()) == 'e\u0301😀界'
                assert valid == original
                savepoint.rollback()
                for shape in ('single', 'same_group', 'heterogeneous'):
                    for target, identity in [('matching', UUID(int=100)), ('missing', MISSING), ('foreign', FOREIGN)]:
                        if mode == 'auto':
                            for _ in range(12):
                                empty_result(invoke(session, model, [{'id': UUID(int=101),
                                    'carrier_frame': frame(UUID(int=101), 'good')}]))
                        savepoint = session.begin_nested()
                        rows = [{'id': identity, 'carrier_frame': INVALID}]
                        if shape != 'single':
                            rows.insert(0, {'id': UUID(int=101), 'carrier_frame': frame(UUID(int=101), 'good'),
                                **({'label': 'public prefix'} if shape == 'heterogeneous' else {})})
                        original = deepcopy(rows)
                        observation = {'shape': shape, 'target': target, 'prepared_before': plans(session, app.schema)}
                        try:
                            empty_result(invoke(session, model, rows))
                        except DBAPIError as failed:
                            observation['sqlstate'] = failed.orig.sqlstate
                            assert failed.orig.sqlstate == '22001'
                            assert_aborted(session)
                        else:
                            observation['sqlstate'] = None
                            observation['prepared_after'] = plans(session, app.schema)
                            current = dict(session.execute(select(table.c.id, table.c.name)).all())
                            assert INVALID not in current.values()
                            assert current[FOREIGN] == dict((row.id, row.name) for row in before)[FOREIGN]
                        savepoint.rollback()
                        assert rows == original
                        outcomes.append(observation)
                session.rollback()
        finally:
            event.remove(app.runtime, 'before_cursor_execute', rendered)
        with app.owner.connect() as connection:
            assert connection.execute(select(table).order_by(table.c.id)).all() == before
        record(record_property, 'varchar_update_case_carrier_observations', {
            'mode': mode, 'sent': sent, 'outcomes': outcomes,
        })
        for outcome in outcomes:
            expected_error = mode == 'force_custom_plan' or outcome['target'] == 'matching'
            assert outcome['sqlstate'] == ('22001' if expected_error else None)
