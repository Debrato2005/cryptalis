"""Native deterministic default equality admission and strict source identity."""

def test_native_deterministic_default_text_equality_in_and_unique_match_bytes(record_property):
    """Independent PG16 oracle; no compiler admission or application alteration."""
    import json
    from uuid import uuid4
    import pytest
    from sqlalchemy import Column, Integer, MetaData, String, Table, Text, select
    from sqlalchemy.exc import IntegrityError
    from test_migration import engine
    owner = engine('CRYPTALIS_TEST_DATABASE_URL')
    schema = 'default_equality_' + uuid4().hex
    metadata = MetaData(schema=schema)
    table = Table('native_values', metadata, Column('id', Integer, primary_key=True),
        Column('plain', Text, unique=True), Column('bounded', String(255), unique=True))
    values = [None, '', 'é', 'e\u0301', 'a', 'A', 'a ', '雪😀', 'ß', 'ss']
    try:
        with owner.begin() as connection:
            connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
        metadata.create_all(owner)
        with owner.begin() as connection:
            context = connection.exec_driver_sql(
                "SELECT co.collname,co.collprovider,co.collisdeterministic, "
                "d.datlocprovider,d.datcollate,d.datctype FROM pg_catalog.pg_collation co "
                "CROSS JOIN pg_catalog.pg_database d WHERE co.oid='pg_catalog.default'::regcollation "
                "AND d.datname=current_database()").one()
            assert context[:3] == ('default', 'd', True)
            connection.execute(table.insert(), [{'id': i, 'plain': value, 'bounded': value}
                                               for i, value in enumerate(values)])
            # Compare both planner settings; no physical plan claim is inferred.
            for index_scan in (False, True):
                connection.exec_driver_sql('SET LOCAL enable_seqscan=' + ('off' if index_scan else 'on'))
                for column in (table.c.plain, table.c.bounded):
                    for value in values[1:]:
                        expected = [i for i, candidate in enumerate(values) if candidate == value]
                        assert connection.scalars(select(table.c.id).where(column == value)).all() == expected
                        assert connection.scalars(select(table.c.id).where(column.in_([value, None]))).all() == expected
                        assert connection.scalars(select(table.c.id).where(column.in_([]))).all() == []
            for column in (table.c.plain, table.c.bounded):
                for value in values[1:]:
                    with pytest.raises(IntegrityError) as caught:
                        with connection.begin_nested():
                            connection.execute(table.insert().values(id=100, **{column.name: value}))
                    assert caught.value.orig.sqlstate == '23505'
                connection.execute(table.insert().values(id=100 if column.name == 'plain' else 101))
            assert sorted(connection.scalars(select(table.c.id).where(table.c.plain.is_(None))).all()) == [0, 100, 101]
            record_property('default_collation_context', json.dumps(list(context)))
            record_property('equivalence', 'TEXT and VARCHAR255; exact UTF8 equality/IN and unique; seqscan settings on/off; distinctNULL')
            import os
            from pathlib import Path
            evidence = os.environ.get('CRYPTALIS_SQLMODEL_NATIVE_COLLATION_RECEIPT')
            if evidence:
                with Path(evidence).open('x') as stream:
                    json.dump({'scope': 'Native PostgreSQL16 deterministic default collation oracle; no protected admission claim',
                        'collation_context': list(context), 'types': ['TEXT', 'VARCHAR255'],
                        'values': values, 'equality_and_in': 'byte-exact for each native value; NULL and emptyIN preserved',
                        'uniqueness': 'distinct Unicode/case/trailingspace retained; exact duplicates23505 inside savepoints; NULLs distinct',
                        'query_modes': ['enable_seqscan on', 'enable_seqscan off (physical plans not asserted)'], 'gate': 'UNKNOWN'}, stream, indent=2)
                    stream.write('\n')
    finally:
        with owner.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        owner.dispose()


import pytest


@pytest.mark.parametrize('fault', ['shadow_C', 'shadow_default', 'nondeterministic', 'mapping', 'index'])
def test_native_source_collation_mismatch_remains_a_typed_refusal(fault):
    import json
    from uuid import UUID, uuid4
    from sqlalchemy import Column, MetaData, Table, Text, Uuid
    from sqlalchemy.orm import registry
    from cryptalis.manifest.compiler import compile_protection, PlanningRejected, Writer, WriterInventory, SearchReview
    from test_migration import engine, DOMAIN
    owner = engine('CRYPTALIS_TEST_DATABASE_URL')
    schema = 'collation_refusal_' + uuid4().hex
    mapping = registry(metadata=MetaData(schema=schema))
    try:
        with owner.begin() as c:
            c.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
            if fault.startswith('shadow_'):
                name = fault.removeprefix('shadow_')
                c.exec_driver_sql(f'CREATE COLLATION "{schema}"."{name}" FROM pg_catalog."C"')
                collation = f'"{schema}"."{name}"'
            elif fault == 'nondeterministic':
                supported = c.exec_driver_sql("SELECT count(*) FROM pg_catalog.pg_collation WHERE collprovider='i'").scalar_one()
                if not supported:
                    pytest.skip('native PostgreSQL build has no ICU nondeterministic collation support')
                from sqlalchemy.exc import DBAPIError
                try:
                    with c.begin_nested():
                        c.exec_driver_sql(f'CREATE COLLATION "{schema}".nondeterministic (provider=icu,locale=\'und\',deterministic=false)')
                except DBAPIError as failure:
                    # Recovered catalog rows do not prove the current server
                    # binary supports ICU. Admit only this exact native refusal.
                    if (failure.orig.sqlstate == '0A000' and
                            failure.orig.diag.message_primary == 'ICU is not supported in this build'):
                        pytest.skip('native PostgreSQL build has no ICU nondeterministic collation support')
                    raise
                collation = f'"{schema}".nondeterministic'
            else: collation = 'pg_catalog."default"'
            c.exec_driver_sql(f'CREATE TABLE "{schema}".subject (id uuid PRIMARY KEY, value text COLLATE {collation})')
            index_collation = ' COLLATE pg_catalog."C"' if fault == 'index' else ''
            c.exec_driver_sql(f'CREATE UNIQUE INDEX native_value ON "{schema}".subject (value{index_collation})')
        table = Table('subject', mapping.metadata, Column('id', Uuid, primary_key=True),
                      Column('value', Text(collation='C' if fault in ('mapping', 'shadow_C') else None)))
        class Subject: pass
        mapping.map_imperatively(Subject, table)
        table_id, field_id = UUID(int=1910), UUID(int=1911)
        declaration = {'schema':'cryptalis.protection/v1','profile':'cf1','domain_id':str(DOMAIN),
            'models':[{'model':'Subject','table_id':str(table_id),'tenancy':{'single_tenant':True},
                       'fields':[{'name':'value','field_id':str(field_id),'protect':True,
                                  'queries':['equality','unique'],'accept_leakage':['equality','unique']}]}]}
        with pytest.raises(PlanningRejected) as caught:
            compile_protection(json.dumps(declaration).encode(), mapping, owner,
                writers=WriterInventory(True,(Writer(table_id,'fixture','sqlalchemy',evidence='public isolated fixture'),)),
                search_reviews=(SearchReview(field_id,False,'public opaque fixture domain only'),))
        assert {'unsupported_collation','unsupported_uniqueness'} & {issue.code for issue in caught.value.issues}
    finally:
        with owner.begin() as c: c.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        owner.dispose()
        mapping.dispose()

def serialized_refusals(proposal, field_name='email'):
    from cryptalis import migration as m
    from cryptalis.manifest.compiler import _canonical
    import pytest
    assert m.MigrationPlan(proposal.artifact).artifact == proposal.artifact
    for fault in ('provider', 'determinism', 'shadow', 'index'):
        document = proposal.document
        model = document['lock']['models'][0]
        column = next(value for value in model['source_schema']['columns'] if value['name'] == field_name)
        if fault == 'provider': column['provider'] = 'c'
        elif fault == 'determinism': column['deterministic'] = False
        elif fault == 'shadow':
            column['collation_schema'] = 'shadow'
            column['collation'] = 'shadow.default'
            next(value for value in model['fields'] if value['column'] == field_name)['source']['collation'] = 'shadow.default'
        else:
            next(value for value in model['source_schema']['indexes'] if field_name in value['columns'])['collations'] = ['pg_catalog.C']
        with pytest.raises(m.TransitionFailure):
            m.MigrationPlan(_canonical(document))


@pytest.mark.parametrize('varchar', [False, True])
def test_default_collation_plan_reloads_without_weakening_source_facts(varchar):
    from sqlalchemy import String, Text
    from cryptalis import migration as m
    from test_migration import application
    with application(value_type=String(64) if varchar else Text()) as app:
        assert m.MigrationPlan(app.plan.artifact).artifact == app.plan.artifact
        model = app.plan.document['lock']['models'][0]
        source = next(value for value in model['source_schema']['columns'] if value['name'] == 'name')
        assert (source['collation'], source['provider'], source['deterministic']) == ('pg_catalog.default', 'd', True)
        serialized_refusals(app.plan, 'name')
