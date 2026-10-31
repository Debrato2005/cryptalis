"""Range and ORDER BY on encrypted fields, with native PostgreSQL as the oracle.

Every query runs on the plaintext table first. The same query must then return the
same rows in the same order through Cryptalis, across the whole lifecycle.
"""
import asyncio
from contextlib import contextmanager
from datetime import date, datetime, timedelta
import hashlib
import hmac
import json
import os
import random
import subprocess
from types import SimpleNamespace
from uuid import UUID, uuid4

import psycopg
import pytest
from sqlalchemy import (BigInteger, Boolean, Column, Date, DateTime, Float, Index, Integer, MetaData, SmallInteger, Table, Text, Uuid,
                        and_, bindparam, func, not_, or_, select)
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.dialects.postgresql import TIMESTAMP
from sqlalchemy.orm import aliased, registry, sessionmaker

from cryptalis import Project
from cryptalis.crypto import AuthenticationFailed, DevelopmentKeyProvider, InvalidValue
from cryptalis.manifest.compiler import PlanningRejected
from cryptalis.sqlalchemy import UnsupportedProtectedOperation
from test_migration import engine

DOMAIN, TABLE_ID = UUID(int=9300), UUID(int=9301)
FIELD_IDS = {'small': UUID(int=9302), 'amount': UUID(int=9303), 'big': UUID(int=9304), 'due': UUID(int=9305), 'moment': UUID(int=9306)}
TENANT, OTHER = UUID(int=9310), UUID(int=9311)
STOPPED = 'Fixture writers are stopped; the attached application is the only writer.'
REVIEWED = 'Fixture values are not enumerable; order, equality and frequency leakage are accepted.'
COLUMNS = tuple(FIELD_IDS)
PIVOTS = {'small': (-1, 0, 7, 32767, -32768), 'amount': (-1, 0, 12345, 2**31 - 1, -2**31),
          'big': (-1, 0, 2**40, 2**63 - 1, -2**63),
          'due': (date(2000, 1, 1), date(1999, 12, 31), date(2026, 10, 31), date.max, date.min),
          'moment': (datetime(2000, 1, 1), datetime(1999, 12, 31, 23, 59, 59, 999999),
                     datetime(2000, 1, 1, microsecond=1), datetime.max, datetime.min)}


def values(column, rng):
    bounds = PIVOTS[column]
    choice = rng.random()
    if choice < .12:
        return None
    if choice < .3:
        return rng.choice(bounds)
    if column == 'due':
        return date(2000, 1, 1) + timedelta(days=rng.randint(-4000, 12000))
    if column == 'moment':
        return datetime(2000, 1, 1) + timedelta(days=rng.randint(-4000, 12000), microseconds=rng.randint(0, 86399999999))
    width = {'small': 15, 'amount': 31, 'big': 63}[column]
    return rng.randint(-2**width, 2**width - 1) if rng.random() < .5 else rng.randint(-20, 20)


def mapping_for(schema, indexed=True, timestamp_type=DateTime):
    mapping = registry(metadata=MetaData(schema=schema))
    table = Table('invoice', mapping.metadata, Column('id', Uuid, primary_key=True, autoincrement=False),
                  Column('tenant_id', Uuid, nullable=False), Column('small', SmallInteger), Column('amount', Integer),
                  Column('big', BigInteger), Column('due', Date), Column('moment', timestamp_type), Column('label', Text))
    if indexed:
        Index('native_amount', table.c.amount)
    class Invoice: pass
    mapping.map_imperatively(Invoice, table)
    return mapping, Invoice


def manifest(search=('equality', 'order')):
    return json.dumps({'schema': 'cryptalis.protection/v1', 'profile': 'cf1', 'domain_id': str(DOMAIN),
        'models': [{'model': 'Invoice', 'table_id': str(TABLE_ID), 'tenancy': {'column': 'tenant_id'}, 'fields': [
            {'name': name, 'field_id': str(field), 'protect': True, 'queries': list(search), 'accept_leakage': list(search)}
            for name, field in FIELD_IDS.items()]}]}).encode()


@contextmanager
def invoices(tmp_path, *, search=('equality', 'order'), timestamp_type=DateTime):
    owner = engine('CRYPTALIS_TEST_DATABASE_URL')
    schema = 'cryptalis_order_' + uuid4().hex
    runtime = engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
    with runtime.connect() as connection:
        role = connection.exec_driver_sql('SELECT current_user').scalar_one()
    created = [runtime]
    provider = DevelopmentKeyProvider()
    keep, initial = [], search
    def process(provider=provider, search=search):
        mapping, Invoice = mapping_for(schema, indexed=bool(initial), timestamp_type=timestamp_type)
        fresh = engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
        created.append(fresh)
        keep.append((mapping, Invoice))
        return SimpleNamespace(Invoice=Invoice, runtime=fresh, mapping=mapping,
            project=Project(manifest(search), mapping, provider=provider, state_dir=tmp_path))
    try:
        mapping, Invoice = mapping_for(schema, indexed=bool(search), timestamp_type=timestamp_type)
        with owner.begin() as connection:
            connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
            connection.exec_driver_sql(f'GRANT USAGE ON SCHEMA "{schema}" TO "{role}"')
        mapping.metadata.create_all(owner)
        with owner.begin() as connection:
            connection.exec_driver_sql(f'GRANT SELECT, INSERT, UPDATE, DELETE ON "{schema}".invoice TO "{role}"')
        rng = random.Random(9300)
        with sessionmaker(owner)() as session:
            for number in range(120):
                session.add(Invoice(id=UUID(int=10000 + number), tenant_id=TENANT if number % 6 else OTHER,
                                    label=f'label-{number % 5}', **{c: values(c, rng) for c in COLUMNS}))
            session.commit()
        yield SimpleNamespace(owner=owner, schema=schema, role=role, process=process, native=(Invoice, sessionmaker(owner)),
                              provider=provider)
    finally:
        for item in created:
            item.dispose()
        with owner.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        owner.dispose()


def queries(Invoice):
    """Named SELECTs. Every result has a total order, so lists compare exactly."""
    base = lambda *entities: select(*entities).where(Invoice.tenant_id == TENANT)
    result = {}
    for name in COLUMNS:
        column = getattr(Invoice, name)
        for pivot in PIVOTS[name]:
            shapes = {'lt': column < pivot, 'le': column <= pivot, 'gt': column > pivot, 'ge': column >= pivot,
                      'eq': column == pivot, 'ne': column != pivot, 'not_lt': not_(column < pivot), 'not_ge': not_(column >= pivot),
                      'in': column.in_([pivot, PIVOTS[name][0]]), 'not_in': column.not_in([pivot]),
                      'or': or_(column < pivot, column > pivot), 'and_public': and_(column >= pivot, Invoice.label != 'label-0'),
                      'range_or_null': or_(column.is_(None), column >= pivot)}
            for shape, predicate in shapes.items():
                result[f'{name}/{shape}/{pivot}'] = base(Invoice.id, column).where(predicate).order_by(Invoice.id)
        low, high = sorted(PIVOTS[name][:3])[0], sorted(PIVOTS[name][:3])[-1]
        result[f'{name}/between'] = base(Invoice.id).where(column.between(low, high)).order_by(Invoice.id)
        result[f'{name}/negated_between'] = base(Invoice.id).where(not_(column.between(low, high))).order_by(Invoice.id)
        result[f'{name}/null'] = base(Invoice.id).where(column.is_(None)).order_by(Invoice.id)
        result[f'{name}/bound_parameter'] = (base(Invoice.id, column).where(column > bindparam('floor'))
                                             .order_by(Invoice.id).params(floor=PIVOTS[name][1]))
        sorts = {'asc': column.asc(), 'desc': column.desc(), 'bare': column,
                 'nulls_first': column.asc().nulls_first(), 'nulls_last': column.desc().nulls_last()}
        for sort, clause in sorts.items():
            result[f'{name}/sort/{sort}'] = base(Invoice.id, column).order_by(clause, Invoice.id)
            result[f'{name}/page/{sort}'] = base(Invoice.id, column).order_by(clause, Invoice.id).limit(7).offset(5)
        result[f'{name}/sort_public_first'] = base(Invoice.id).order_by(Invoice.label, column, Invoice.id)
        result[f'{name}/sort_unselected'] = base(Invoice.id).where(column.is_not(None)).order_by(column.desc(), Invoice.id)
        result[f'{name}/filter_and_sort'] = base(Invoice.id, column).where(column > PIVOTS[name][0]).order_by(column, Invoice.id).limit(9)
        for population, predicate in {'all': Invoice.label.is_not(None), 'empty': Invoice.id == UUID(int=0),
                                      'null': column.is_(None), 'filtered': column >= PIVOTS[name][0]}.items():
            result[f'{name}/extrema/{population}'] = base(func.min(column), func.max(column), func.count(column)).where(predicate)
    return result


def run_all(session, Invoice):
    return {name: [tuple(row) for row in session.execute(statement)] for name, statement in queries(Invoice).items()}


def native_answers(app):
    Invoice, factory = app.native
    with factory() as session:
        return run_all(session, Invoice)


def different(expected, actual):
    return {name: (expected[name][:4], actual[name][:4]) for name in expected if expected[name] != actual[name]}


def protect(process, app):
    process.project.protect(app.owner, runtime_role=app.role, writers_stopped=STOPPED, search_reviewed=REVIEWED)


def frames(app, name='amount'):
    with app.owner.connect() as connection:
        return {row[0]: (row[1], bytes(row[2]) if row[2] is not None else None) for row in connection.exec_driver_sql(
            f'SELECT id, tenant_id, {name} FROM "{app.schema}".invoice')}


@pytest.mark.parametrize('timestamp_type', [DateTime(), TIMESTAMP(precision=6)])
def test_protected_results_match_native_through_the_whole_lifecycle(tmp_path, timestamp_type):
    with invoices(tmp_path, timestamp_type=timestamp_type) as app:
        expected = native_answers(app)
        assert sum(map(len, expected.values())) > 5000 and len(expected) > 300
        protect(app.process(), app)
        stored = frames(app)
        assert all(frame is None or frame[:3] == b'CF1' for _, frame in stored.values())

        process = app.process()
        with process.project.attach(process.runtime)(tenant_id=TENANT) as session:
            assert different(expected, run_all(session, process.Invoice)) == {}

        for purpose in ('search', 'payload'):
            app.process().project.rotate(app.owner, purpose, writers_stopped=STOPPED)
            process = app.process()
            with process.project.attach(process.runtime)(tenant_id=TENANT) as session:
                assert different(expected, run_all(session, process.Invoice)) == {}, purpose
        rotated = frames(app)
        assert all((rotated[key][1] is None) == (stored[key][1] is None) for key in stored)
        assert all(rotated[key][1][14:46] != stored[key][1][14:46] for key in stored if stored[key][1])

        # New and edited rows join the same order; compare with the same edits applied natively.
        process = app.process()
        edits = {UUID(int=10001): {'amount': -2**31, 'due': date.min, 'small': None, 'big': 2**63 - 1, 'moment': datetime.min}}
        added = dict(id=UUID(int=20000), tenant_id=TENANT, label='label-new', small=7, amount=12345, big=2**40,
                     due=date(2026, 10, 31), moment=datetime(2026, 11, 1, 12, 34, 56, 123456))
        with process.project.attach(process.runtime)(tenant_id=TENANT) as session:
            row = session.get(process.Invoice, UUID(int=10001))
            for name, value in edits[UUID(int=10001)].items():
                setattr(row, name, value)
            session.add(process.Invoice(**added))
            session.commit()
            attached = run_all(session, process.Invoice)
        process = app.process()
        assert process.project.decrypt(app.owner, plaintext_role=_plaintext_role(app), writers_stopped=STOPPED, accept_plaintext=True,
            retained_backups='No backups were taken of this disposable fixture.').phase == 'PLAINTEXT_ACTIVE'
        # Exit: the native table answers every query exactly as the attached session did.
        assert different(attached, native_answers(app)) == {}
        assert app.process().project.remove(app.owner, writers_stopped=STOPPED, old_workers_stopped=True,
            application_verified='Compared above against the attached answers.').phase == 'REMOVED'
        assert different(attached, native_answers(app)) == {}
        with app.owner.connect() as connection:
            assert connection.exec_driver_sql("SELECT indexname FROM pg_catalog.pg_indexes WHERE schemaname=%s AND indexname='native_amount'",
                                              (app.schema,)).scalar_one() == 'native_amount'


def _plaintext_role(app):
    with app.owner.connect() as connection:
        rows = connection.exec_driver_sql(
            "SELECT rolname, pg_catalog.pg_has_role(rolname, current_user, 'MEMBER') FROM pg_catalog.pg_roles "
            "WHERE NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolbypassrls AND NOT rolreplication ORDER BY rolname").all()
    for name, member in rows:
        if not member and name != app.role:
            return name
    pytest.skip('no distinct non-inherited least-privilege role is available')


def test_async_sessions_match_native(tmp_path):
    with invoices(tmp_path) as app:
        expected = native_answers(app)
        protect(app.process(), app)
        async def run():
            process = app.process()
            runtime = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
            try:
                sessions = await process.project.attach(runtime)
                async with sessions(tenant_id=TENANT) as session:
                    return {name: [tuple(row) for row in await session.execute(statement)]
                            for name, statement in queries(process.Invoice).items()}
            finally:
                await runtime.dispose()
        assert different(expected, asyncio.run(run())) == {}


def test_keyset_pagination_walks_all_rows_in_native_order(tmp_path):
    with invoices(tmp_path) as app:
        Invoice, factory = app.native
        with factory() as session:
            wanted = session.scalars(select(Invoice.amount).where(Invoice.tenant_id == TENANT, Invoice.amount.is_not(None))
                                     .distinct().order_by(Invoice.amount)).all()
        protect(app.process(), app)
        process = app.process()
        seen, last = [], None
        with process.project.attach(process.runtime)(tenant_id=TENANT) as session:
            while True:
                statement = (select(process.Invoice.id, process.Invoice.amount).where(process.Invoice.tenant_id == TENANT,
                             process.Invoice.amount.is_not(None)).order_by(process.Invoice.amount, process.Invoice.id).limit(1))
                if last is not None:
                    statement = statement.where(process.Invoice.amount > last)
                row = session.execute(statement).first()
                if row is None:
                    break
                seen.append(row.amount)
                last = row.amount
        assert seen == wanted


@pytest.mark.parametrize('column', ['amount', 'moment'])
def test_range_and_sort_use_the_generated_index(tmp_path, column):
    with invoices(tmp_path) as app:
        protect(app.process(), app)
        index = '_cryptalis_' + FIELD_IDS[column].hex + '_eq'
        with app.owner.begin() as connection:
            connection.exec_driver_sql('SET LOCAL enable_seqscan = off')
            connection.exec_driver_sql('SET LOCAL enable_bitmapscan = off')
            plan = '\n'.join(row[0] for row in connection.exec_driver_sql(
                f'EXPLAIN SELECT id FROM "{app.schema}".invoice WHERE tenant_id = %s '
                f'AND pg_catalog.substring({column}, 15, 32) > %s ORDER BY pg_catalog.substring({column}, 15, 32) LIMIT 5',
                (TENANT, b'\x7f' * 32)))
        assert index in plan and 'Sort' not in plan


def test_each_tenant_has_its_own_order_and_a_tampered_term_is_refused(tmp_path):
    with invoices(tmp_path) as app:
        protect(app.process(), app)
        process = app.process()
        sessions = process.project.attach(process.runtime)
        for tenant in (TENANT, OTHER):
            with sessions(tenant_id=tenant) as session:
                session.add(process.Invoice(id=UUID(int=30000 + tenant.int % 2), tenant_id=tenant, amount=424242, label='same value'))
                session.commit()
        stored = frames(app)
        first, second = stored[UUID(int=30000)][1], stored[UUID(int=30001)][1]
        assert first[14:46] != second[14:46]  # The same value gives unrelated terms across tenants.
        target = next(key for key, (tenant, frame) in stored.items() if tenant == TENANT and frame and key.int < 20000)
        tampered = bytearray(stored[target][1])
        tampered[20] ^= 1
        with app.owner.begin() as connection:
            connection.exec_driver_sql(f'ALTER TABLE "{app.schema}".invoice DISABLE TRIGGER ALL')
            connection.exec_driver_sql(f'UPDATE "{app.schema}".invoice SET amount = %s WHERE id = %s', (bytes(tampered), target))
            connection.exec_driver_sql(f'ALTER TABLE "{app.schema}".invoice ENABLE TRIGGER ALL')
        process = app.process()
        with process.project.attach(process.runtime)(tenant_id=TENANT) as session:
            with pytest.raises(AuthenticationFailed):
                session.execute(select(process.Invoice.amount).where(process.Invoice.id == target)).all()


def test_order_term_matches_an_independent_implementation_and_sorts_across_boundaries():
    """Essential format vector: a separate derivation must produce the same stored term."""
    from cryptalis.crypto.cf1 import FieldDescriptor, seal_value
    from cryptalis.crypto.keys import KeyContext, KeyPolicy, Keyring, create_root
    provider = DevelopmentKeyProvider()
    roots = [create_root(provider, KeyContext(DOMAIN, TENANT, purpose, uuid4(), 1)) for purpose in ('payload', 'search')]
    keys = Keyring(KeyPolicy(DOMAIN, TENANT, tuple(roots), 1, 1), {provider.provider_id: provider}).prepare()
    def field(codec):
        document = {'schema': 'cryptalis.context/v2', 'domain_id': str(DOMAIN), 'table_id': str(TABLE_ID), 'field_id': str(FIELD_IDS['big']),
                    'value_codec': codec, 'normalizer': 'identity/v1', 'null_policy': 'sql-null/v1', 'record_codec': 'uuid16/v1',
                    'tenant_codec': 'uuid16/v1', 'representation': 'cf1-packed-order/v1'}
        digest = hashlib.sha256(json.dumps(document, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        return FieldDescriptor.from_compiled(document, digest)
    def pack(*parts):
        return len(parts).to_bytes(4, 'big') + b''.join(len(part).to_bytes(4, 'big') + part for part in parts)
    def independent(number, width, bits, codec):
        material = keys._resolve(DOMAIN, TENANT, 'search', 1)
        context = material.context
        salt = hashlib.sha256(pack(b'CF1/root', DOMAIN.bytes, TENANT.bytes, context.root_id.bytes, (1).to_bytes(4, 'big'))).digest()
        prk = hmac.digest(salt, material.root, 'sha256')
        info = pack(b'CF1/search-key', FIELD_IDS['big'].bytes, codec.encode(), b'identity/v1', b'order')
        key = hmac.digest(prk, info + b'\x01', 'sha256')
        unsigned, output, prefix = (number + (1 << (width - 1))), bytearray(), bytearray()
        for shift in range(width - bits, -1, -bits):
            digit = (unsigned >> shift) & ((1 << bits) - 1)
            offset = int.from_bytes(hmac.digest(key, pack(b'order', bytes(prefix)), 'sha256')[:8], 'big') % (257 - (1 << bits))
            output.append(offset + digit)
            prefix.append(digit)
        return bytes(output).ljust(32, b'\0')
    for codec, width, bits in (('pg-int2-be/v1', 16, 1), ('pg-int4-be/v1', 32, 1), ('pg-int8-be/v1', 64, 2)):
        descriptor = field(codec)
        ordered = sorted({-(1 << (width - 1)), -(1 << (width - 1)) + 1, -256, -2, -1, 0, 1, 2, 255, 256, 257, (1 << (width - 1)) - 2, (1 << (width - 1)) - 1})
        terms = [seal_value(number, descriptor, TENANT, uuid4(), keys)[14:46] for number in ordered]
        assert terms == sorted(terms) and len(set(terms)) == len(terms)
        assert terms == [independent(number, width, bits, codec) for number in ordered]


@pytest.mark.parametrize('field_type,search', [(Text(collation='C'), ('equality', 'order')), (Boolean(), ('equality', 'order')),
                                               (Uuid(), ('equality', 'order')), (Integer(), ('equality',)),
                                               (DateTime(), ('equality',))])
def test_planning_refuses_order_on_unsupported_types_and_equality_alone_on_numbers(tmp_path, field_type, search):
    owner = engine('CRYPTALIS_TEST_DATABASE_URL')
    schema = 'cryptalis_order_' + uuid4().hex
    mapping = registry(metadata=MetaData(schema=schema))
    table = Table('invoice', mapping.metadata, Column('id', Uuid, primary_key=True, autoincrement=False),
                  Column('tenant_id', Uuid, nullable=False), Column('value', field_type))
    class Invoice: pass
    mapping.map_imperatively(Invoice, table)
    document = json.dumps({'schema': 'cryptalis.protection/v1', 'profile': 'cf1', 'domain_id': str(DOMAIN),
        'models': [{'model': 'Invoice', 'table_id': str(TABLE_ID), 'tenancy': {'column': 'tenant_id'}, 'fields': [
            {'name': 'value', 'field_id': str(UUID(int=9320)), 'protect': True, 'queries': list(search), 'accept_leakage': list(search)}]}]}).encode()
    try:
        with owner.begin() as connection:
            connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
        mapping.metadata.create_all(owner)
        with pytest.raises(PlanningRejected, match='unsupported_query'):
            Project(document, mapping, provider=DevelopmentKeyProvider(), state_dir=tmp_path).protect(
                owner, runtime_role='unused', writers_stopped=STOPPED, search_reviewed=REVIEWED)
    finally:
        with owner.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        owner.dispose()


@pytest.mark.parametrize('bind_type', [DateTime(timezone=True), TIMESTAMP(timezone=True)])
def test_timestamp_order_refuses_timezone_cast_binds_with_different_native_semantics(tmp_path, bind_type):
    with invoices(tmp_path) as app:
        Invoice, factory = app.native
        identity = UUID(int=31000)
        with factory() as session:
            session.add(Invoice(id=identity, tenant_id=TENANT, moment=datetime(2020, 3, 8, 3)))
            session.commit()
            session.connection().exec_driver_sql("SET LOCAL TIME ZONE 'America/New_York'")
            statement = (select(Invoice.id).where(Invoice.id == identity, Invoice.tenant_id == TENANT,
                Invoice.moment < bindparam('cutoff', datetime(2020, 3, 8, 2, 30), type_=bind_type)))
            assert list(session.scalars(statement)) == [identity]
        protect(app.process(), app)
        process = app.process()
        Invoice = process.Invoice
        with process.project.attach(process.runtime)(tenant_id=TENANT) as session:
            statement = (select(Invoice.id).where(Invoice.id == identity, Invoice.tenant_id == TENANT,
                Invoice.moment < bindparam('cutoff', datetime(2020, 3, 8, 2, 30), type_=bind_type)))
            with pytest.raises(UnsupportedProtectedOperation):
                session.execute(statement).all()


def test_extrema_preserve_native_expression_keys_and_aliases(tmp_path):
    def observe(factory, Invoice):
        observed = []
        for index, model in enumerate((Invoice, aliased(Invoice), aliased(Invoice, Invoice.__table__.alias().alias()))):
            first, last = func.min(model.amount), func.max(model.moment).label('last_seen')
            with factory() as session:
                try:
                    row = session.execute(select(first, last).where(model.tenant_id == TENANT)).one()
                except UnsupportedProtectedOperation as failure:
                    failure.add_note(f'Extremum oracle alias depth {index}')
                    raise
                observed.append((tuple(row), tuple(row._mapping), row._mapping[first],
                                 row._mapping[last], row._mapping['last_seen']))
        return observed
    with invoices(tmp_path) as app:
        Invoice, factory = app.native
        expected = observe(factory, Invoice)
        protect(app.process(), app)
        process = app.process()
        factory = process.project.attach(process.runtime)
        assert observe(lambda: factory(tenant_id=TENANT), process.Invoice) == expected


def test_extrema_refuse_an_explicit_native_result_conversion(tmp_path):
    with invoices(tmp_path) as app:
        Invoice, factory = app.native
        with factory() as session:
            assert type(session.scalar(select(func.min(Invoice.amount, type_=Float()))
                                       .where(Invoice.tenant_id == TENANT))) is float
        protect(app.process(), app)
        process = app.process()
        with process.project.attach(process.runtime)(tenant_id=TENANT) as session:
            with pytest.raises(UnsupportedProtectedOperation):
                session.scalar(select(func.min(process.Invoice.amount, type_=Float()))
                               .where(process.Invoice.tenant_id == TENANT))


@pytest.mark.parametrize('offset', [20, -1], ids=['term', 'payload'])
def test_extrema_authenticate_the_selected_packet(tmp_path, offset):
    with invoices(tmp_path) as app:
        protect(app.process(), app)
        target, (tenant, frame) = next((key, value) for key, value in frames(app).items()
                                     if value[0] == TENANT and value[1] is not None)
        tampered = bytearray(frame)
        tampered[offset] ^= 1
        with app.owner.begin() as connection:
            connection.exec_driver_sql(f'ALTER TABLE "{app.schema}".invoice DISABLE TRIGGER ALL')
            connection.exec_driver_sql(f'UPDATE "{app.schema}".invoice SET amount=%s WHERE id=%s', (bytes(tampered), target))
            connection.exec_driver_sql(f'ALTER TABLE "{app.schema}".invoice ENABLE TRIGGER ALL')
        process = app.process()
        Invoice = process.Invoice
        with process.project.attach(process.runtime)(tenant_id=TENANT) as session:
            with pytest.raises(AuthenticationFailed):
                session.execute(select(func.min(Invoice.amount), func.max(Invoice.amount))
                                .where(Invoice.tenant_id == TENANT, Invoice.id == target)).one()


def test_unsupported_order_queries_refuse_loudly(tmp_path):
    with invoices(tmp_path) as app:
        protect(app.process(), app)
        process = app.process()
        Invoice = process.Invoice
        sessions = process.project.attach(process.runtime)
        amount = Invoice.amount
        other_alias = aliased(Invoice)
        refused = {
            'sort across tenants': select(Invoice.id).order_by(amount),
            'minimum across tenants': select(func.min(amount)),
            'maximum across tenants': select(func.max(amount)),
            'minimum scoped through a different source': select(func.min(amount)).where(other_alias.tenant_id == TENANT),
            'sort under an expression': select(Invoice.id).where(Invoice.tenant_id == TENANT).order_by(func.abs(amount)),
            'minimum under an expression': select(func.min(amount + 1)).where(Invoice.tenant_id == TENANT),
            'field to field': select(Invoice.id).where(Invoice.tenant_id == TENANT, amount > Invoice.small),
            'arithmetic': select(Invoice.id).where(Invoice.tenant_id == TENANT, amount + 1 > 5),
            'group by': select(amount).where(Invoice.tenant_id == TENANT).group_by(amount).order_by(amount),
            'grouped minimum': select(func.min(amount)).where(Invoice.tenant_id == TENANT).group_by(Invoice.label),
            'window maximum': select(func.max(amount).over()).where(Invoice.tenant_id == TENANT),
        }
        with sessions(tenant_id=TENANT) as session:
            for name, statement in refused.items():
                with pytest.raises(UnsupportedProtectedOperation):
                    session.execute(statement).all()
                    pytest.fail(name)
                session.rollback()
            # Values a column cannot hold refuse instead of comparing as something else.
            for statement in (select(Invoice.id).where(Invoice.small > 100000), select(Invoice.id).where(amount > 'not a number'),
                              select(Invoice.id).where(Invoice.due > date(2026, 1, 1).isoformat())):
                with pytest.raises(Exception) as failure:
                    session.execute(statement).all()
                assert isinstance(failure.value, InvalidValue) or isinstance(getattr(failure.value, 'orig', None), InvalidValue)
                session.rollback()


@pytest.mark.parametrize('ordered', [False, True])
def test_timestamp_order_refuses_a_retained_storage_only_reader(tmp_path, ordered):
    from test_migration import application
    reader = os.environ.get('CRYPTALIS_TIMESTAMP_ORDER_PREVIOUS_READER_PYTHON')
    if not reader:
        pytest.skip('supply the retained installed v10 timestamp storage reader')
    with application(rows=1, unique=False, value_type=DateTime(), queries=['equality', 'order'] if ordered else [],
                     protected_values=(datetime(2000, 1, 1),)) as app:
        artifact = tmp_path / 'plan.json'
        artifact.write_bytes(app.plan.artifact)
        child = subprocess.run([reader, '-I', '-c', '''
from pathlib import Path
import sys
from cryptalis.migration import MigrationPlan, TransitionFailure
try:
    MigrationPlan(Path(sys.argv[1]).read_bytes()).document
except TransitionFailure as failure:
    assert sys.argv[2] == 'ordered' and failure.code == 'invalid_plan'
else:
    assert sys.argv[2] == 'storage'
print('reader boundary passed')
''', str(artifact), 'ordered' if ordered else 'storage'], capture_output=True, text=True, timeout=30)
        assert child.returncode == 0, 'previous-reader control failed; diagnostics withheld'
        assert child.stdout.strip() == 'reader boundary passed'


def test_order_search_can_be_added_to_and_removed_from_a_protected_field(tmp_path):
    with invoices(tmp_path, search=()) as app:
        expected = native_answers(app)
        protect(app.process(search=()), app)
        before = app.process(search=())
        with before.project.attach(before.runtime)(tenant_id=TENANT) as session:
            with pytest.raises(UnsupportedProtectedOperation):
                session.execute(select(before.Invoice.id).where(before.Invoice.amount > 0)).all()
            with pytest.raises(UnsupportedProtectedOperation):
                session.scalar(select(func.min(before.Invoice.amount)).where(before.Invoice.tenant_id == TENANT))
        ordered = ('equality', 'order')
        assert app.process(search=ordered).project.modify(app.owner, writers_stopped=STOPPED, search_reviewed=REVIEWED).phase == 'ACTIVE'
        process = app.process(search=ordered)
        with process.project.attach(process.runtime)(tenant_id=TENANT) as session:
            assert different(expected, run_all(session, process.Invoice)) == {}
        assert app.process(search=()).project.modify(app.owner, writers_stopped=STOPPED).phase == 'ACTIVE'
        process = app.process(search=())
        with process.project.attach(process.runtime)(tenant_id=TENANT) as session:
            assert session.execute(select(process.Invoice.amount).where(process.Invoice.id == UUID(int=10001))).scalar_one() == \
                next(row[1] for row in expected['amount/sort/asc'] if row[0] == UUID(int=10001))
            with pytest.raises(UnsupportedProtectedOperation):
                session.execute(select(process.Invoice.id).where(process.Invoice.amount > 0)).all()
            with pytest.raises(UnsupportedProtectedOperation):
                session.scalar(select(func.max(process.Invoice.amount)).where(process.Invoice.tenant_id == TENANT))
