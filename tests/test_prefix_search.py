"""Native PostgreSQL LIKE/startswith behavior is the exact prefix-search oracle."""
import asyncio
import os
from uuid import UUID

import psycopg
import pytest

from sqlalchemy import (String, Text, and_, bindparam, cast, delete, event, func, insert,
                        inspect, literal, not_, or_, select, update)
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import Session, aliased

from cryptalis.crypto import CryptoFailure
from cryptalis.sqlalchemy import attach
from test_driver_event_boundary import raw_calls
from test_migration import application, keys, publish, run, TENANT

pytestmark = pytest.mark.prefix_qualification


BOUNDS = {'min': 1, 'max': 16}
LONG_VALUE = '0123456789abcdef' + ('long source text ' * 80)
VALUES = (None, '', 'alpha', 'alphabet', 'a%b', 'a_b', 'a\\tail', 'a%',
          'a/b', 'a^b', 'aé%b', 'abc%', 'abc\\tail', 'ab\\tail', 'abc', 'abacus',
          'e\u0301clair', 'éclair', '雪😀family', '👩\u200d💻dev', '👩tail',
          'ABC', '\\alpha', 'line\nbreak', LONG_VALUE)
WRITE = 'private_%_\\alphabet' + (' latest source tail' * 16)
DTYPES = (Text(collation='C'), Text(), String(4096, collation='C'))


def configured(dtype=None, *, bounds=BOUNDS):
    return application(rows=len(VALUES), value_type=Text(collation='C') if dtype is None else dtype,
        unique=False, queries=['equality', 'prefix'], protected_values=VALUES,
        value_prefix_bounds=bounds)


def query_cases(model):
    scope = model.tenant_id == TENANT
    base = lambda predicate: select(model.id, model.name).where(scope, predicate).order_by(model.id)
    patterns = {
        'exact': model.name.like('abc'), 'exact_empty': model.name.like(''),
        'exact_long': model.name.like(LONG_VALUE),
        'all': model.name.like('%'), 'all_multiple': model.name.like('%%%'),
        'prefix': model.name.like('a%'), 'multiple_terminal': model.name.like('a%%%'),
        'escaped_percent': model.name.like(r'a\%b'),
        'escaped_underscore': model.name.like(r'a\_b'),
        'escaped_percent_prefix': model.name.like(r'a\%%'),
        'literal_backslash_prefix': model.name.like(r'a\\%'),
        'disabled_escape': model.name.like('a\\%', escape=''),
        'explicit_escape': model.name.like('a^%b', escape='^'),
        'unicode_escape': model.name.like('aé%b', escape='é'),
        'unicode_escape_prefix': model.name.like('aé%%', escape='é'),
        'escape_regular_letter': model.name.like(r'\abc%'),
        'not_like': model.name.not_like('a%'),
        'startswith': model.name.startswith('a'),
        'startswith_all': model.name.startswith(''),
        'startswith_wildcard': model.name.startswith('a%'),
        'startswith_autoescape': model.name.startswith('a%', autoescape=True),
        'startswith_specials': model.name.startswith('a_b', autoescape=True),
        'startswith_backslash_becomes_exact': model.name.startswith('abc\\'),
        'startswith_regular_escape': model.name.startswith(r'a\b'),
        'startswith_escape_disabled': model.name.startswith('ab\\', escape=''),
        'startswith_explicit_escape': model.name.startswith('a%b', escape='^', autoescape=True),
        'startswith_escape_itself': model.name.startswith('a^b', escape='^', autoescape=True),
        'startswith_unicode_escape': model.name.startswith('aé%b', escape='é', autoescape=True),
        'unicode_combining': model.name.startswith('e', autoescape=True),
        'unicode_decomposed': model.name.startswith('e\u0301', autoescape=True),
        'unicode_composed': model.name.startswith('é', autoescape=True),
        'unicode_emoji': model.name.startswith('👩', autoescape=True),
        'unicode_zwj': model.name.startswith('👩\u200d', autoescape=True),
        'unicode_multibyte': model.name.startswith('雪😀', autoescape=True),
        'maximum_prefix': model.name.startswith(LONG_VALUE[:16], autoescape=True),
        'not_startswith': not_(model.name.startswith('a', autoescape=True)),
        'or_null': or_(model.name.like('a%'), model.name.is_(None)),
        'and_public': and_(model.name.startswith('a', autoescape=True), model.label != 'label-102'),
        'not_and': not_(and_(model.name.like('a%'), model.label != 'label-102')),
        'or_prefixes': or_(model.name.like('a%'), model.name.like('é%')),
        'equal': model.name == 'a%b', 'in': model.name.in_(['a%b', '', None]),
    }
    for name, predicate in patterns.items():
        yield name, base(predicate), {}
    predicate = model.name.startswith('a%', autoescape=True)
    yield 'projection', select(model.id, predicate.label('matches'), (~predicate).label('negated'),
        model.name.like('%').label('all_text')).where(scope).order_by(model.id), {}
    for name, condition in {
        'true': predicate == True, 'false': predicate == False,
        'reversed_true': literal(True) == predicate,
        'reversed_false': literal(False) == predicate,
    }.items():
        yield 'boolean/' + name, base(condition), {}
    late_like = base(model.name.like(bindparam('pattern', type_=Text())))
    for number, value in enumerate((None, '', 'abc', 'a%', '%', 'a%%', r'a\%b', 'é%')):
        yield f'late_like/{number}', late_like, {'pattern': value}
    late_prefix = base(model.name.startswith(bindparam('prefix', type_=String())))
    for number, value in enumerate((None, '', 'a', 'abc\\', 'a%', 'e\u0301', '👩')):
        yield f'late_prefix/{number}', late_prefix, {'prefix': value}
    yield 'nullable_projection', select(model.id,
        model.name.startswith(bindparam('prefix', type_=Text())).label('matches')).where(scope).order_by(model.id), {'prefix': None}
    yield 'count_filtered', select(func.count(model.name)).where(scope, model.name.like('a%')), {}
    yield 'distinct_filtered', select(func.count(model.name.distinct())).where(scope, model.name.like('a%')), {}
    yield 'page', base(model.name.like('a%')).limit(3).offset(2), {}


def observe(session, model):
    result = {}
    for kind, selected in (('mapped', model), ('alias', aliased(model))):
        for name, statement, parameters in query_cases(selected):
            try:
                result[kind + '/' + name] = [tuple(row) for row in session.execute(statement, parameters)]
            except Exception as failure:
                failure.add_note('prefix oracle case: ' + kind + '/' + name)
                raise
    return result


@pytest.mark.parametrize('dtype', DTYPES)
def test_prefix_like_effective_escapes_unicode_null_aliases_and_booleans_match_native(dtype):
    with configured(dtype) as app:
        with Session(app.runtime) as session:
            expected = observe(session, app.Customer)
        run(app); publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                         deployment=(app.plan, app.pin))
        seen = []
        def private_binds(connection, cursor, statement, parameters, context, executemany):
            for group in parameters if isinstance(parameters, list) else [parameters]:
                values = group.values() if isinstance(group, dict) else group
                assert not any(type(value) is str and value and value in
                    {'abc', 'a%', 'a%%', 'é%', LONG_VALUE, '👩', 'e\u0301'} for value in values)
            seen.append(True)
        event.listen(app.runtime, 'before_cursor_execute', private_binds)
        try:
            with factory(tenant_id=TENANT) as session:
                assert observe(session, app.Customer) == expected
            assert seen
        finally:
            event.remove(app.runtime, 'before_cursor_execute', private_binds)


def write_journey(factory, model):
    with factory() as session:
        row = model(id=UUID(int=900), tenant_id=TENANT)
        session.add(row)
        session.flush()
        result = [row.name, bool(inspect(row).expired_attributes)]
        session.refresh(row)
        result.append(row.name)
        savepoint = session.begin_nested()
        created = session.execute(insert(model).returning(model.name.label('created')),
            [{'id': UUID(int=901), 'tenant_id': TENANT, 'name': 'a%_\\literal'}]).one()
        changed = session.execute(update(model).where(model.id == row.id, model.tenant_id == TENANT)
            .values(name=WRITE).returning(model.name.label('changed')),
            execution_options={'synchronize_session': False}).one()
        session.refresh(row)
        result.extend((created.created, changed.changed, row.name,
            list(session.scalars(select(model.id).where(model.tenant_id == TENANT,
                model.name.startswith(WRITE[:12], autoescape=True)).order_by(model.id)))))
        deleted = session.execute(delete(model).where(model.id == UUID(int=901), model.tenant_id == TENANT)
            .returning(model.name), execution_options={'synchronize_session': False}).scalar_one()
        result.append(deleted)
        savepoint.rollback()
        session.refresh(row)
        result.append(row.name)
        session.rollback()
        return result


@pytest.mark.parametrize('dtype', DTYPES)
def test_prefix_native_crud_null_omission_returning_savepoints_and_long_values(dtype):
    with configured(dtype) as app:
        expected = write_journey(lambda: Session(app.runtime, expire_on_commit=False), app.Customer)
        run(app); publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                         deployment=(app.plan, app.pin))
        assert write_journey(lambda: factory(tenant_id=TENANT, expire_on_commit=False), app.Customer) == expected


@pytest.mark.parametrize('dtype', DTYPES[:2])
def test_prefix_async_native_queries_crud_and_rollback(dtype):
    async def scenario(app, protected):
        database = create_async_engine('postgresql+psycopg://', hide_parameters=True,
            async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
        try:
            factory = await attach(app.mapping, database, lock=app.plan.lock_bytes, keys=keys,
                deployment=(app.plan, app.pin)) if protected else lambda **options: AsyncSession(database, **options)
            async with factory(**({'tenant_id': TENANT} if protected else {}), expire_on_commit=False) as session:
                result = {}
                for name, statement, parameters in query_cases(aliased(app.Customer)):
                    result[name] = [tuple(row) for row in (await session.execute(statement, parameters)).all()]
                row = app.Customer(id=UUID(int=900), tenant_id=TENANT)
                session.add(row)
                await session.flush(); await session.refresh(row)
                result['default'] = row.name
                created = (await session.execute(insert(app.Customer).returning(app.Customer.name),
                    [{'id': UUID(int=901), 'tenant_id': TENANT, 'name': 'a%_\\literal'}])).scalar_one()
                changed = (await session.execute(update(app.Customer).where(app.Customer.id == row.id,
                    app.Customer.tenant_id == TENANT).values(name=WRITE).returning(app.Customer.name),
                    execution_options={'synchronize_session': False})).scalar_one()
                result['written'] = created, changed
                result['matches'] = list((await session.scalars(select(app.Customer.id).where(
                    app.Customer.tenant_id == TENANT, app.Customer.name.startswith(WRITE[:12], autoescape=True))
                    .order_by(app.Customer.id))).all())
                result['deleted'] = (await session.execute(delete(app.Customer).where(
                    app.Customer.id == UUID(int=901), app.Customer.tenant_id == TENANT).returning(app.Customer.name),
                    execution_options={'synchronize_session': False})).scalar_one()
                await session.rollback()
                assert await session.get(app.Customer, UUID(int=900)) is None
                return result
        finally:
            await database.dispose()
    with configured(dtype) as app:
        expected = asyncio.run(scenario(app, False))
        run(app); publish(app)
        assert asyncio.run(scenario(app, True)) == expected


def unsupported(model):
    yield 'interior_percent', model.name.like('a%b%')
    yield 'underscore', model.name.like('a_b%')
    yield 'leading_percent', model.name.like('%alpha')
    yield 'contains', model.name.contains('alpha')
    yield 'suffix', model.name.endswith('alpha')
    yield 'ilike', model.name.ilike('a%')
    yield 'istartswith', model.name.istartswith('a')
    yield 'long_prefix', model.name.like(('a' * 17) + '%')
    yield 'long_startswith', model.name.startswith('a' * 17, autoescape=True)
    yield 'invalid_escape', model.name.like('a%', escape='ab')
    yield 'nul_escape', model.name.like('a%', escape='\x00')
    yield 'surrogate_escape', model.name.like('a%', escape='\ud800')
    yield 'escape_ends_pattern', model.name.like('abc\\')
    yield 'escape_percent', model.name.startswith('a', escape='%')
    yield 'cast_column', cast(model.name, Text()).like('a%')
    yield 'cast_bind', model.name.like(cast(literal('a%', Text()), Text()))
    yield 'reversed', literal('alpha', Text()).startswith(model.name)
    yield 'integer', model.name.like(123)
    yield 'callable', model.name.like(bindparam('pattern', callable_=lambda: 'a%', type_=Text()))


def test_prefix_unadmitted_patterns_bounds_casts_and_hooks_refuse_before_raw_sql(monkeypatch):
    with configured() as app:
        run(app); publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                         deployment=(app.plan, app.pin))
        with raw_calls(monkeypatch, app.schema, 'SELECT') as calls:
            with factory(tenant_id=TENANT) as session:
                assert list(session.scalars(select(app.Customer.id).where(app.Customer.tenant_id == TENANT,
                    app.Customer.name.like('a%'))))
                assert calls
                session.rollback()
                calls.clear()
                for name, predicate in unsupported(app.Customer):
                    with pytest.raises(CryptoFailure):
                        session.execute(select(app.Customer.id).where(app.Customer.tenant_id == TENANT, predicate))
                    session.rollback()
                    assert calls == [], name


def test_prefix_query_bounds_do_not_truncate_source_or_restrict_exact_like_literals(monkeypatch):
    with configured(bounds={'min': 2, 'max': 4}) as app:
        def cases(model):
            return [select(model.id, model.name).where(model.tenant_id == TENANT, predicate).order_by(model.id)
                for predicate in (model.name.like('alph%'), model.name.like(LONG_VALUE),
                    model.name == LONG_VALUE, model.name.like('%'), model.name.startswith(''))]
        with Session(app.runtime) as session:
            expected = [list(session.execute(statement)) for statement in cases(app.Customer)]
        run(app); publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                         deployment=(app.plan, app.pin))
        with factory(tenant_id=TENANT) as session:
            assert [list(session.execute(statement)) for statement in cases(app.Customer)] == expected
            assert session.get(app.Customer, UUID(int=100 + len(VALUES) - 1)).name == LONG_VALUE
            for value in ('a%', 'alpha%'):
                with raw_calls(monkeypatch, app.schema, 'SELECT') as calls:
                    with pytest.raises(CryptoFailure):
                        session.execute(select(app.Customer).where(app.Customer.tenant_id == TENANT,
                            app.Customer.name.like(value)))
                    session.rollback()
                    assert calls == []
