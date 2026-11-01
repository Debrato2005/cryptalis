"""Native prefix bytes, indexed plans, frame authentication and scope controls."""
import json
import os
from pathlib import Path
from uuid import UUID

import pytest

from sqlalchemy import Boolean, Column, MetaData, Table, Text, Uuid, bindparam, event, literal, select
from sqlalchemy.orm import Session, registry

from cryptalis.crypto import CryptoFailure
from cryptalis.sqlalchemy import UnsupportedProtectedOperation, attach
from test_migration import FIELD_ID, TENANT, application, engine, frames, independent_open, keys, publish, run
from test_prefix_search import BOUNDS, VALUES, configured

pytestmark = pytest.mark.prefix_qualification


def test_native_prefix_bytes_independent_hmac_full_header_and_tamper_refusal():
    with configured() as app:
        with app.owner.connect() as connection:
            expected = {identity: (value, prefixes) for identity, value, prefixes in connection.exec_driver_sql(f'''
                SELECT id, convert_to(name,'UTF8'),
                    ARRAY(SELECT convert_to(left(name,n),'UTF8') FROM generate_series(%s,
                        least(char_length(name),%s)) AS n)
                FROM "{app.schema}".customer
            ''', (BOUNDS['min'], BOUNDS['max']))}
        run(app); publish(app)
        descriptor = json.loads(app.plan.lock_bytes)['models'][0]['fields'][0]['descriptor']
        stored = frames(app, True)
        for identity, (value, prefixes) in expected.items():
            assert independent_open(stored[identity], descriptor, TENANT, identity,
                return_bytes=True, prefix_bytes=prefixes) == value
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                         deployment=(app.plan, app.pin))
        identity = UUID(int=102)
        original = stored[identity]
        for position in (14, 46, 1100, len(original)-1):
            modified = bytearray(original)
            modified[position] ^= 1
            with app.owner.begin() as connection:
                connection.exec_driver_sql(f'UPDATE "{app.schema}".customer SET name=%s WHERE id=%s',
                                           (bytes(modified), identity))
            try:
                with factory(tenant_id=TENANT) as session:
                    with pytest.raises(CryptoFailure):
                        session.scalar(select(app.Customer.name).where(app.Customer.id == identity))
            finally:
                with app.owner.begin() as connection:
                    connection.exec_driver_sql(f'UPDATE "{app.schema}".customer SET name=%s WHERE id=%s',
                                               (original, identity))
        with factory(tenant_id=TENANT) as session:
            assert session.get(app.Customer, identity).name == VALUES[2]


def test_prefix_gin_eligibility_custom_generic_plans_and_index_drift_refusal():
    values = ('alpha', 'alphabet', *(f'unmatched-{number}' for number in range(1022)))
    with application(rows=len(values), value_type=Text(collation='C'), queries=['equality', 'prefix'],
                     unique=False, protected_values=values, value_prefix_bounds=BOUNDS) as app:
        run(app); publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                         deployment=(app.plan, app.pin))
        captured = []
        def capture(connection, cursor, statement, parameters, context, executemany):
            if statement.startswith('SELECT') and app.schema in statement:
                captured.append((statement, parameters))
        event.listen(app.runtime, 'before_cursor_execute', capture)
        try:
            with factory(tenant_id=TENANT) as session:
                assert list(session.scalars(select(app.Customer.id).where(app.Customer.tenant_id == TENANT,
                    app.Customer.name.like('alph%')))) == [UUID(int=100), UUID(int=101)]
        finally:
            event.remove(app.runtime, 'before_cursor_execute', capture)
        statement, parameters = captured[-1]
        index = '_cryptalis_' + FIELD_ID.hex + '_prefix'
        with app.owner.begin() as connection:
            assert connection.exec_driver_sql('SELECT rolsuper FROM pg_roles WHERE rolname=current_user').scalar_one() is False
            # Bulk backfill leaves native GIN fastupdate entries pending. This
            # checks index eligibility after ordinary maintenance, not latency
            # or whether the optimizer prefers GIN while that list is large.
            cleaned = connection.exec_driver_sql('SELECT pg_catalog.gin_clean_pending_list(%s::regclass)',
                (f'"{app.schema}"."{index}"',)).scalar_one()
            connection.exec_driver_sql(f'ANALYZE "{app.schema}".customer')
            if report := os.environ.get('CRYPTALIS_PREFIX_INDEX_REPORT'):
                definition = connection.exec_driver_sql('SELECT pg_get_indexdef(%s::regclass)',
                    (f'"{app.schema}"."{index}"',)).scalar_one()
                Path(report).write_text(json.dumps({'statement_without_values': statement,
                    'index_definition': definition, 'pending_pages_cleaned': cleaned}, indent=2) + '\n')
            connection.exec_driver_sql('SET LOCAL enable_seqscan=off')
            for mode in ('force_custom_plan', 'force_generic_plan'):
                connection.exec_driver_sql('SET LOCAL plan_cache_mode=' + mode)
                plan = connection.connection.driver_connection.execute('EXPLAIN (FORMAT JSON) ' + statement,
                    parameters, prepare=True).fetchone()[0]
                assert index in json.dumps(plan)
        # Eligibility under forced planning does not measure selectivity or cost.
        def fresh_attachment():
            mapping = registry(metadata=MetaData(schema=app.schema))
            table = Table('customer', mapping.metadata,
                Column('id', Uuid, primary_key=True, autoincrement=False), Column('tenant_id', Uuid, nullable=False),
                Column('name', Text(collation='C')), Column('label', Text))
            class Customer: pass
            mapping.map_imperatively(Customer, table)
            runtime = engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
            try:
                attach(mapping, runtime, lock=app.plan.lock_bytes, keys=keys, deployment=(app.plan, app.pin))
            finally:
                runtime.dispose(); mapping.dispose()
        fresh_attachment()
        with app.owner.begin() as connection:
            connection.exec_driver_sql(f'DROP INDEX "{app.schema}"."{index}"')
        with pytest.raises(CryptoFailure):
            fresh_attachment()


def test_false_boolean_prefix_predicates_keep_positive_tenant_guards():
    other = UUID(int=777)
    def seed(connection, schema, role):
        connection.exec_driver_sql(f'INSERT INTO "{schema}".customer(id,tenant_id,name,label) VALUES (%s,%s,%s,%s)',
                                   (UUID(int=800), other, 'outside scope', 'other tenant'))
    with application(rows=3, value_type=Text(collation='C'), queries=['equality', 'prefix'], unique=False,
            protected_values=('alpha', 'beta', None), value_prefix_bounds=BOUNDS, setup=seed) as app:
        def statements(model):
            predicate = model.name.like('a%')
            conditions = (
                predicate == False, literal(False) == predicate, predicate != True,
                ~(predicate == True), (predicate == bindparam('flag', type_=Boolean())))
            return [(select(model.id).where(condition).order_by(model.id), {'flag': False} if index == 4 else {})
                    for index, condition in enumerate(conditions)]
        with Session(app.runtime) as session:
            expected = [list(session.scalars(statement.where(app.Customer.tenant_id == TENANT), parameters))
                        for statement, parameters in statements(app.Customer)]
        assert expected == [[UUID(int=101)]] * 5
        run(app); publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                         deployment=(app.plan, app.pin))
        with factory(tenant_id=TENANT) as session:
            assert [list(session.scalars(statement, parameters))
                    for statement, parameters in statements(app.Customer)] == expected


def test_public_boolean_comparisons_and_shared_named_flags_retain_native_binding():
    with configured() as app:
        def public(model):
            # Native default resolution of public binds remains untouched.
            first = (model.label == 'label-102') == bindparam('flag', True, type_=Boolean())
            second = (model.label == 'label-103') == bindparam('flag', False, type_=Boolean())
            return select(model.id).where(model.tenant_id == TENANT, first | second).order_by(model.id)
        def shared(model):
            first = model.name.like('a%') == bindparam('flag', True, type_=Boolean())
            second = (model.label == 'label-103') == bindparam('flag', False, type_=Boolean())
            return select(model.id).where(model.tenant_id == TENANT, first, second).order_by(model.id)
        with Session(app.runtime) as session:
            expected_public = list(session.scalars(public(app.Customer)))
            expected_shared = {flag: list(session.scalars(shared(app.Customer), {'flag': flag})) for flag in (False, True)}
        run(app); publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                         deployment=(app.plan, app.pin))
        with factory(tenant_id=TENANT) as session:
            assert list(session.scalars(public(app.Customer))) == expected_public
            with pytest.raises(UnsupportedProtectedOperation):
                session.execute(shared(app.Customer))
            session.rollback()
            assert {flag: list(session.scalars(shared(app.Customer), {'flag': flag}))
                    for flag in (False, True)} == expected_shared
