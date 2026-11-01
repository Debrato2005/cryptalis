"""Native JSONB client defaults survive writes, rotations and package-free exit."""
import asyncio
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import ColumnDefault, JSON, insert, inspect, null, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy.orm import Session

from cryptalis.sqlalchemy import PolicyMismatch, attach
from test_date_lifecycle import date_application, date_keys, remove_date, rotate_all
from test_driver_event_boundary import raw_calls
from test_jsonb_boundaries import CallbackProvider, stored_rows
from test_jsonb_lifecycle import protected_wire
from test_jsonb_storage import COERCIONS, mapping_for, state, values, wire
from test_migration import TENANT, application, keys, publish, run


DEFAULT = {'first': 'default sentinel', 'nested': [True, 1.0, -0.0, {'雪': '😀'}]}
LITERALS = (DEFAULT, [None, True, {'nested': 'array'}], (True, {'tuple': (1, 2)}),
            'literal default', 17, -0.0, False, JSON.NULL, COERCIONS, '\ud83d\ude00')


def copied(value):
    return JSON.NULL if value is JSON.NULL else deepcopy(value)


def exercise(factory, model, *, mutable=False):
    """Observe native pending state, refresh, bulk NULL policy and savepoints."""
    with factory() as session:
        original = values(session, model)
        savepoint = session.begin_nested()
        observations = []
        assignments = ({}, {'name': None}, {'name': {'explicit': True}}) if mutable else (
            {}, {'name': None}, {'name': JSON.NULL}, {'name': null()}, {'name': {'explicit': True}})
        for index, attributes in enumerate(assignments):
            row = model(id=UUID(int=900 + index), tenant_id=TENANT, **attributes)
            session.add(row)
            session.flush()
            pending = state(row.name), tuple(sorted(inspect(row).expired_attributes))
            session.refresh(row)
            observations.append((pending, state(row.name)))
        for render_nulls in (False, True):
            start = 920 + 10 * render_nulls
            created = session.execute(insert(model).returning(model.id, model.name),
                [{'id': UUID(int=start), 'tenant_id': TENANT},
                 {'id': UUID(int=start + 1), 'tenant_id': TENANT, 'name': None},
                 {'id': UUID(int=start + 2), 'tenant_id': TENANT, 'name': JSON.NULL},
                 {'id': UUID(int=start + 3), 'tenant_id': TENANT, 'name': null()},
                 {'id': UUID(int=start + 4), 'tenant_id': TENANT, 'name': {'explicit': [True, None]}}],
                execution_options={'render_nulls': render_nulls}).all()
            observations.append(sorted((identity, state(value)) for identity, value in created))
        observations.append(list(session.scalars(select(model.id).where(model.name.is_(None)).order_by(model.id))))
        savepoint.rollback()
        session.expire_all()
        assert values(session, model) == original
        session.rollback()
        return observations


@pytest.mark.parametrize('none_as_null', [False, True])
@pytest.mark.parametrize('default', LITERALS, ids=['object', 'array', 'tuple', 'string', 'integer',
                                                'float', 'boolean', 'json-null', 'coercions', 'surrogate-pair'])
def test_jsonb_literal_defaults_match_native_pending_refresh_bulk_returning_and_savepoint(default, none_as_null):
    with application(rows=2, unique=False, queries=[], value_type=JSONB(none_as_null=none_as_null),
                     value_default=copied(default), protected_values=({'baseline': True}, None)) as app:
        expected = exercise(lambda: Session(app.runtime, expire_on_commit=False), app.Customer)
        run(app); publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                         deployment=(app.plan, app.pin))
        assert exercise(lambda: factory(tenant_id=TENANT, expire_on_commit=False), app.Customer) == expected


async def async_default_journey(app, *, none_as_null, protected):
    mapping, table, Model = mapping_for(app.schema, none_as_null)
    table.c.name.default = ColumnDefault(deepcopy(DEFAULT))
    database = create_async_engine('postgresql+psycopg://', hide_parameters=True,
        async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
    try:
        factory = await attach(mapping, database, lock=app.plan.lock_bytes, keys=keys,
            deployment=(app.plan, app.pin)) if protected else lambda **options: AsyncSession(database, **options)
        async with factory(**({'tenant_id': TENANT} if protected else {}), expire_on_commit=False) as session:
            async def observed():
                return [(identity, state(value)) for identity, value in (await session.execute(
                    select(Model.id, Model.name).order_by(Model.id))).all()]
            original = await observed()
            observations = []
            for index, attributes in enumerate(({}, {'name': None})):
                row = Model(id=UUID(int=900 + index), tenant_id=TENANT, **attributes)
                session.add(row)
                await session.flush()
                pending = state(row.name), tuple(sorted(inspect(row).expired_attributes))
                await session.refresh(row)
                observations.append((pending, state(row.name)))
            for render_nulls in (False, True):
                start = 920 + 10 * render_nulls
                created = (await session.execute(insert(Model).returning(Model.id, Model.name),
                    [{'id': UUID(int=start), 'tenant_id': TENANT},
                     {'id': UUID(int=start + 1), 'tenant_id': TENANT, 'name': None}],
                    execution_options={'render_nulls': render_nulls})).all()
                observations.append(sorted((identity, state(value)) for identity, value in created))
            observations.append(list((await session.scalars(select(Model.id).where(
                Model.name.is_(None)).order_by(Model.id))).all()))
            await session.rollback()
            assert await observed() == original
            await session.rollback()
            return observations
    finally:
        await database.dispose(); mapping.dispose()


@pytest.mark.parametrize('none_as_null', [False, True])
def test_jsonb_async_defaults_match_native_flush_refresh_bulk_null_policy_and_rollback(none_as_null):
    with application(rows=2, unique=False, queries=[], value_type=JSONB(none_as_null=none_as_null),
                     value_default=deepcopy(DEFAULT), protected_values=({'baseline': True}, None)) as app:
        expected = asyncio.run(async_default_journey(app, none_as_null=none_as_null, protected=False))
        run(app); publish(app)
        assert asyncio.run(async_default_journey(app, none_as_null=none_as_null, protected=True)) == expected


def mutable_default_journey(factory, model):
    observations = exercise(factory, model, mutable=True)
    with factory() as session:
        original = values(session, model)
        row = model(id=UUID(int=960), tenant_id=TENANT)
        session.add(row)
        session.flush()
        assert isinstance(row.name, MutableDict)
        observations.append(state(row.name))
        row.name['shallow'] = 'tracked current edit'
        assert session.is_modified(row)
        session.flush(); session.refresh(row)
        observations.append(state(row.name))
        row.name['nested'][0] = False
        assert not session.is_modified(row)  # Native MutableDict tracks top-level changes only.
        session.flush(); session.refresh(row)
        observations.append(state(row.name))
        session.rollback()
        assert values(session, model) == original
        session.rollback()
    return observations


@pytest.mark.parametrize('none_as_null', [False, True])
def test_jsonb_mutable_object_default_matches_native_coercion_and_shallow_tracking(none_as_null):
    with application(rows=2, unique=False, queries=[],
                     value_type=MutableDict.as_mutable(JSONB(none_as_null=none_as_null)),
                     value_default=deepcopy(DEFAULT), protected_values=({'baseline': True}, None)) as app:
        expected = mutable_default_journey(lambda: Session(app.runtime, expire_on_commit=False), app.Customer)
        run(app); publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                         deployment=(app.plan, app.pin))
        assert mutable_default_journey(lambda: factory(tenant_id=TENANT, expire_on_commit=False), app.Customer) == expected


def current_edits(session, model):
    session.get(model, UUID(int=100)).name = {'current edit': [True, 1.0, None]}
    session.delete(session.get(model, UUID(int=106)))
    session.add_all((model(id=UUID(int=950), tenant_id=TENANT),
                    model(id=UUID(int=951), tenant_id=TENANT, name=None),
                    model(id=UUID(int=952), tenant_id=TENANT, name=JSON.NULL),
                    model(id=UUID(int=953), tenant_id=TENANT, name=null())))
    session.flush()


def native_default_restart(app, expected, *, none_as_null):
    """A fresh native ORM process uses the same client default without Cryptalis."""
    child = subprocess.run([sys.executable, '-B', '-I', '-c', '''
import importlib.abc, json, os, sys
from uuid import UUID
class Deny(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'cryptalis' or fullname.startswith('cryptalis.'):
            raise ImportError('Cryptalis import denied after removal')
sys.meta_path.insert(0, Deny())
import psycopg
from sqlalchemy import Column, JSON, MetaData, Table, Text, Uuid, create_engine, null
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Session, registry
schema = os.environ['JSONB_DEFAULT_SCHEMA']
expected = json.loads(os.environ['JSONB_DEFAULT_EXPECTED'])
database = create_engine('postgresql+psycopg://', hide_parameters=True,
    creator=lambda: psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
mapping = registry(metadata=MetaData(schema=schema))
table = Table('customer', mapping.metadata, Column('id', Uuid, primary_key=True, autoincrement=False),
    Column('tenant_id', Uuid, nullable=False), Column('name',
        JSONB(none_as_null=os.environ['JSONB_DEFAULT_NULL_MODE'] == '1'),
        default=json.loads(os.environ['JSONB_DEFAULT_LITERAL'])), Column('label', Text))
class Customer: pass
mapping.map_imperatively(Customer, table)
def observed(connection):
    return {str(identity): [missing, None if body is None else bytes(body).hex()]
        for identity, missing, body in connection.exec_driver_sql(
            f'SELECT id,name IS NULL,pg_catalog.jsonb_send(name) FROM "{schema}".customer')}
with Session(database) as session:
    assert observed(session.connection()) == expected
    created = [Customer(id=UUID(int=980), tenant_id=UUID(os.environ['JSONB_DEFAULT_TENANT'])),
        Customer(id=UUID(int=981), tenant_id=UUID(os.environ['JSONB_DEFAULT_TENANT']), name=None),
        Customer(id=UUID(int=982), tenant_id=UUID(os.environ['JSONB_DEFAULT_TENANT']), name=JSON.NULL),
        Customer(id=UUID(int=983), tenant_id=UUID(os.environ['JSONB_DEFAULT_TENANT']), name=null())]
    session.add_all(created); session.flush()
    for row in created: session.refresh(row)
    assert created[0].name == json.loads(os.environ['JSONB_DEFAULT_LITERAL'])
    assert created[1].name == (created[0].name if os.environ['JSONB_DEFAULT_NULL_MODE'] == '1' else None)
    actual = observed(session.connection())
    assert actual[str(created[2].id)] == [False, b'\\x01null'.hex()]
    assert actual[str(created[3].id)] == [True, None]
    session.rollback()
with database.connect() as connection: assert observed(connection) == expected
database.dispose(); mapping.dispose()
assert not any(name == 'cryptalis' or name.startswith('cryptalis.') for name in sys.modules)
print('native JSONB default package-free restart passed')
'''], env=dict(os.environ, JSONB_DEFAULT_SCHEMA=app.schema,
        JSONB_DEFAULT_NULL_MODE='1' if none_as_null else '0',
        JSONB_DEFAULT_LITERAL=json.dumps(DEFAULT), JSONB_DEFAULT_TENANT=str(TENANT),
        JSONB_DEFAULT_EXPECTED=json.dumps({str(identity): [missing, None if body is None else body.hex()]
            for identity, (missing, body) in expected.items()})),
        cwd=os.environ.get('TMPDIR', '/tmp'), capture_output=True, text=True, timeout=30)
    assert child.returncode == 0, 'native JSONB default restart failed; diagnostics withheld'
    assert child.stdout.strip() == 'native JSONB default package-free restart passed'


@pytest.mark.parametrize('public_slots', [False, True])
@pytest.mark.parametrize('none_as_null', [False, True])
def test_jsonb_defaults_all_rotations_current_values_removal_and_package_free_restart(public_slots, none_as_null):
    with date_application(public_slots=public_slots, value_type=JSONB(none_as_null=none_as_null),
                          value_default=deepcopy(DEFAULT), values=({'source': [True, None]}, None)) as app:
        with Session(app.runtime) as session:
            current_edits(session, app.Customer)
            expected = wire(app, session.connection())
            expected_values = values(session, app.Customer)
            session.rollback()
        run(app); publish(app)
        rotate_all(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=date_keys,
                         deployment=(app.plan, app.pin))
        with factory(tenant_id=TENANT) as session:
            current_edits(session, app.Customer)
            session.commit()
            assert values(session, app.Customer) == expected_values
        assert protected_wire(app, date_keys) == expected
        remove_date(app)
        assert wire(app) == expected
        native_default_restart(app, expected, none_as_null=none_as_null)


@pytest.mark.parametrize('mutation', ['python-type', 'unicode-spelling'])
def test_jsonb_literal_default_mapping_drift_refuses_before_keys_or_sql(mutation, monkeypatch):
    with application(rows=2, unique=False, queries=[], value_type=JSONB(),
                     value_default=deepcopy(DEFAULT), protected_values=({'source': True}, None)) as app:
        run(app); publish(app)
        calls = []
        def resolve(tenant):
            calls.append(True)
            return keys(tenant)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=resolve,
                         deployment=(app.plan, app.pin))
        before = stored_rows(app)
        default = app.table.c.name.default.arg
        if mutation == 'python-type':
            default['nested'][0] = 1  # Python equality hides this change in the pinned literal.
            assert default == DEFAULT
        else:
            default['nested'][3]['雪'] = '\ud83d\ude00'
            assert default != DEFAULT and json.dumps(default) == json.dumps(DEFAULT)
        def forbidden(*args, **kwargs):
            raise AssertionError('Changed JSONB default reached SQL')
        with monkeypatch.context() as patch:
            patch.setattr(Engine, 'connect', forbidden)
            with pytest.raises(PolicyMismatch):
                factory(tenant_id=TENANT)
        assert calls == []
        assert stored_rows(app) == before


@pytest.mark.parametrize('route', ['flush', 'bulk_insert'])
def test_jsonb_default_mutation_after_provider_await_refuses_before_insert(route, monkeypatch):
    with application(rows=2, unique=False, queries=[], value_type=JSONB(),
                     value_default=deepcopy(DEFAULT), protected_values=({'source': True}, None)) as app:
        run(app); publish(app)
        default = deepcopy(DEFAULT)
        provider = CallbackProvider(lambda: default['nested'].__setitem__(0, 1))
        before = stored_rows(app)

        async def check():
            mapping, table, Model = mapping_for(app.schema, False)
            table.c.name.default = ColumnDefault(default)
            database = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
            try:
                factory = await attach(mapping, database, lock=app.plan.lock_bytes, keys=provider.resolve,
                                       deployment=(app.plan, app.pin))
                with raw_calls(monkeypatch, app.schema, 'INSERT', asynchronous=True) as calls:
                    async with factory(tenant_id=TENANT) as session:
                        provider.armed = True
                        with pytest.raises(PolicyMismatch):
                            if route == 'flush':
                                session.add(Model(id=UUID(int=970), tenant_id=TENANT))
                                await session.flush()
                            else:
                                await session.execute(insert(Model), [{'id': UUID(int=970), 'tenant_id': TENANT}])
                        provider.armed = False
                        await session.rollback()
                        assert provider.changed == [True] and 'async' in provider.preparations
                        assert calls == [] and default == DEFAULT and stored_rows(app) == before
                        default['nested'][0] = True
                        session.add(Model(id=UUID(int=971), tenant_id=TENANT))
                        await session.commit()
                    assert calls  # Positive control: this collector observes a healthy native INSERT.
            finally:
                await database.dispose(); mapping.dispose()
        asyncio.run(check())


def test_frozen_v15_reader_accepts_jsonb_without_default_and_refuses_v16_before_sql(tmp_path):
    reader = os.environ.get('CRYPTALIS_JSONB_DEFAULT_PREVIOUS_READER_PYTHON')
    if not reader:
        pytest.skip('supply the genuine frozen installed v15 reader interpreter')
    assert Path(reader).is_absolute() and Path(reader).is_file()
    artifacts = []
    for label, default in (('without-default', None), ('literal-default', deepcopy(DEFAULT))):
        with application(rows=2, unique=False, queries=[], value_type=JSONB(), value_default=default,
                         protected_values=({'source': True}, None)) as app:
            saved = tmp_path / (label + '.json')
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
for index, artifact in enumerate(sys.argv[1:]):
    try: MigrationPlan(Path(artifact).read_bytes()).document
    except TransitionFailure as failure:
        assert index == 1 and failure.code == 'invalid_plan'
    else: assert index == 0
assert attempted == []
print('frozen v15 JSONB control accepted; v16 default refused before SQL')
''', *artifacts], capture_output=True, text=True, timeout=30,
        env={'PATH': os.environ.get('PATH', ''), 'LANG': 'C.UTF-8'})
    assert child.returncode == 0, 'genuine previous reader boundary failed; diagnostics withheld'
    assert child.stdout.strip() == 'frozen v15 JSONB control accepted; v16 default refused before SQL'
