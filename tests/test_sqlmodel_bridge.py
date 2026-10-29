"""Optional SQLModel 0.0.48 behavior against native PostgreSQL."""

from contextlib import contextmanager
import json
from types import MethodType, SimpleNamespace
from uuid import UUID, uuid4

import pytest

sqlmodel = pytest.importorskip('sqlmodel', reason='optional SQLModel 0.0.48 profile')
pytestmark = pytest.mark.skipif(sqlmodel.__version__ != '0.0.48', reason='exact SQLModel 0.0.48 profile')

from pydantic import ValidationError
from sqlalchemy import MetaData, String, Text, event, select as sqlalchemy_select
from sqlalchemy.exc import DataError, PendingRollbackError
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import registry
from sqlmodel import Field, Session, SQLModel, select
from sqlmodel.sql.sqltypes import AutoString

from cryptalis.crypto import CryptoFailure
from cryptalis.manifest.compiler import PlanningRejected, Writer, WriterInventory
from cryptalis.sqlalchemy import UnsupportedProtectedOperation
from test_migration import (DOMAIN, FIELD_ID, TABLE_ID, TENANT, application, engine,
                            keys, publish, run)


@contextmanager
def record_application():
    owner, runtime = engine('CRYPTALIS_TEST_DATABASE_URL'), engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
    schema = 'sqlmodel_bridge_' + uuid4().hex
    mapping = registry(metadata=MetaData(schema=schema))

    class Base(SQLModel, registry=mapping):
        pass

    class Record(Base, table=True):
        id: UUID = Field(default_factory=uuid4, primary_key=True)
        tenant_id: UUID
        name: str | None = Field(default=None, max_length=12)
        public: str = Field(max_length=20)

    try:
        with owner.begin() as connection:
            connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
        mapping.metadata.create_all(owner)
        with runtime.connect() as connection:
            role = connection.exec_driver_sql('SELECT current_user').scalar_one()
        with owner.begin() as connection:
            q = connection.dialect.identifier_preparer.quote
            connection.exec_driver_sql(f'REVOKE ALL ON SCHEMA "{schema}" FROM PUBLIC')
            connection.exec_driver_sql(f'GRANT USAGE ON SCHEMA "{schema}" TO {q(role)}')
            connection.exec_driver_sql(f'GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA "{schema}" TO {q(role)}')
        yield SimpleNamespace(owner=owner, runtime=runtime, schema=schema, mapping=mapping,
                              Record=Record, role=role)
    finally:
        runtime.dispose()
        with owner.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        owner.dispose()
        mapping.dispose()


def protect(app, *, attach_runtime=True):
    import cryptalis.migration as migration
    declaration = {'schema': 'cryptalis.protection/v1', 'profile': 'cf1', 'domain_id': str(DOMAIN),
        'models': [{'model': 'Record', 'table_id': str(TABLE_ID), 'tenancy': {'column': 'tenant_id'},
                    'fields': [{'name': 'name', 'field_id': str(FIELD_ID), 'protect': True,
                                'queries': [], 'accept_leakage': []}]}]}
    app.m = migration
    app.plan = migration.plan(json.dumps(declaration).encode(), app.mapping, app.owner,
        writers=WriterInventory(True, (Writer(TABLE_ID, 'app', 'sqlalchemy', evidence='owned SQLModel profile'),)),
        keys=keys, runtime_role=app.role, target_id=uuid4(), backfill_rows_per_second=1000,
        verify_rows_per_second=1000, temporary_bytes_per_row=1000, wal_bytes_per_row=3000)
    app.pin = migration.DeploymentPin(app.plan.target_id, app.plan.operation_id, app.plan.digest, 'PREPARED')
    app.approval = migration.MaintenanceApproval('disposable application stopped; inventoried writers excluded', 3600)
    run(app)
    publish(app)
    if not attach_runtime:
        return
    from cryptalis.sqlmodel import attach
    return attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys, deployment=(app.plan, app.pin))


def workflow(factory, model):
    with pytest.raises(ValidationError):
        model.model_validate({'tenant_id': TENANT, 'name': 'x' * 13, 'public': 'valid'})
    record = model.model_validate({'tenant_id': TENANT, 'name': '雪😀', 'public': 'visible'})
    assert type(record.id) is UUID
    with factory() as session:
        assert isinstance(session, Session)
        session.add(record)
        session.flush()
        session.refresh(record)
        assert session.exec(select(model).where(model.id == record.id)).one() is record
        assert session.exec(select(model.name).where(model.id == record.id)).one() == '雪😀'
        pair = session.exec(select(model.id, model.name).where(model.id == record.id)).one()
        assert tuple(pair) == (record.id, '雪😀')
        assert session.exec(sqlalchemy_select(model).where(model.id == record.id)).one()[0] is record
        record.sqlmodel_update({'name': None})
        session.commit()
        session.refresh(record)
        assert record.name is None
        record.name = 'é' * 12 + '   '
        session.flush()
        pending = record.name
        session.refresh(record)
        stored = record.name
        assert stored == 'é' * 12
        session.commit()
        identity = record.id
        session.delete(record)
        session.commit()
        assert session.get(model, identity) is None
        return pending, stored, type(pair).__name__


def test_sqlmodel_validation_defaults_null_refresh_and_native_exec_shapes():
    with record_application() as app:
        native = workflow(lambda: Session(app.runtime, expire_on_commit=False), app.Record)
        seed = app.Record.model_validate({'tenant_id': TENANT, 'name': 'retained', 'public': 'seed'})
        with Session(app.runtime) as session:
            session.add(seed)
            session.commit()
        factory = protect(app)
        document = json.loads(app.plan.lock_bytes)
        field = document['models'][0]['fields'][0]
        assert field['source']['type'] == 'varchar'
        assert 'pg-varchar/v1' in document['required_readers']
        parameters = []
        def capture(connection, cursor, statement, values, context, many):
            parameters.append(repr(values))
        event.listen(app.runtime, 'before_cursor_execute', capture)
        try:
            protected = workflow(lambda: factory(tenant_id=TENANT, expire_on_commit=False), app.Record)
        finally:
            event.remove(app.runtime, 'before_cursor_execute', capture)
        assert protected == native
        assert '雪😀' not in ''.join(parameters)
        with factory(tenant_id=TENANT) as session:
            assert session.exec(select(app.Record.name)).one() == 'retained'
        with app.owner.connect() as connection:
            assert bytes(connection.exec_driver_sql(f'SELECT name FROM "{app.schema}".record').scalar_one()).startswith(b'CF1\0')


def test_sqlmodel_constructor_overflow_preserves_native_failed_session_and_retry():
    with record_application() as app:
        def check(factory, protected):
            with factory() as session:
                row = app.Record(tenant_id=TENANT, name='x' * 13, public='visible')
                session.add(row)
                with pytest.raises(CryptoFailure if protected else DataError) as failure:
                    session.flush()
                assert (failure.value.sqlstate if protected else failure.value.orig.sqlstate) == '22001'
                assert session.is_active is False
                with pytest.raises(PendingRollbackError):
                    session.exec(select(app.Record.id))
                session.rollback()
                session.add(app.Record(tenant_id=TENANT, name=None, public='recovered'))
                session.commit()
        check(lambda: Session(app.runtime), False)
        factory = protect(app)
        check(lambda: factory(tenant_id=TENANT), True)


@pytest.mark.parametrize('change', ['subclass', 'variant', 'load_hook', 'bind_hook', 'impl'])
def test_changed_autostring_mappings_are_refused_before_key_resolution(change, monkeypatch):
    def no_keys(tenant):
        pytest.fail('key resolution preceded mapping refusal')
    monkeypatch.setattr('test_migration.keys', no_keys)
    dtype = AutoString(12)
    if change == 'subclass':
        class Custom(AutoString):
            cache_ok = True
        dtype = Custom(12)
    elif change == 'variant':
        dtype = dtype.with_variant(String(12), 'postgresql')
    elif change == 'load_hook':
        dtype.load_dialect_impl = MethodType(lambda self, dialect: self.impl_instance, dtype)
    elif change == 'bind_hook':
        monkeypatch.setattr(AutoString, 'process_bind_param', lambda self, value, dialect: value)
    else:
        dtype.impl = Text()
    # Planning is inside application(); every native schema is disposable.
    with pytest.raises(PlanningRejected):
        with application(rows=0, unique=False, queries=[], value_type=dtype):
            pytest.fail('changed AutoString admitted')


def test_optional_async_bridge_refuses_invalid_lock_before_connection_or_key_work():
    from cryptalis.sqlmodel import attach
    from cryptalis.sqlalchemy import PolicyMismatch
    engine = create_async_engine('postgresql+psycopg://', hide_parameters=True)
    observed = []
    event.listen(engine.sync_engine, 'connect', lambda *args: observed.append('connected'))
    try:
        with pytest.raises(PolicyMismatch):
            attach(registry(), engine, lock=b'', keys=lambda tenant: pytest.fail('key resolution'))
        assert observed == []
    finally:
        import asyncio
        asyncio.run(engine.dispose())


def test_optional_bridge_refuses_unqualified_version_before_effects(monkeypatch):
    from sqlalchemy import create_engine
    import cryptalis.sqlmodel as bridge
    monkeypatch.setattr(bridge, '_version', '0.0.47')
    engine = create_engine('postgresql+psycopg://', hide_parameters=True)
    observed = []
    event.listen(engine, 'connect', lambda *args: observed.append('connected'))
    try:
        with pytest.raises(bridge.SQLModelVersionUnsupported):
            bridge.attach(registry(), engine, lock=b'', keys=lambda tenant: pytest.fail('key resolution'))
        assert observed == []
    finally:
        engine.dispose()
