"""Independent native Boolean/default semantics before protected admission."""
import json
import os
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import Boolean, Column, MetaData, Table, Uuid, insert, select
from sqlalchemy.exc import IntegrityError, StatementError
from sqlalchemy.orm import Session, registry

from test_migration import engine


@pytest.mark.parametrize('default', [False, True])
def test_native_boolean_default_pending_refresh_rollback_and_dictionary_insert(default):
    owner = engine('CRYPTALIS_TEST_DATABASE_URL')
    schema = 'boolean_native_' + uuid4().hex
    mapping = registry(metadata=MetaData(schema=schema))
    table = Table('subject', mapping.metadata, Column('id', Uuid, primary_key=True),
        Column('flag', Boolean, nullable=False, default=default), Column('optional', Boolean))
    class Subject: pass
    mapping.map_imperatively(Subject, table)
    observations = []
    try:
        with owner.begin() as connection:
            connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
        mapping.metadata.create_all(owner)
        for label, supplied, expected in [('omitted', {}, default), ('none', {'flag': None}, default),
                ('false', {'flag': False}, False), ('true', {'flag': True}, True),
                ('zero', {'flag': 0}, False), ('one', {'flag': 1}, True),
                ('zero_float', {'flag': 0.0}, False), ('one_float', {'flag': 1.0}, True)]:
            with Session(owner, expire_on_commit=False) as session:
                row = Subject(id=uuid4(), **supplied)
                session.add(row)
                before = row.flag
                session.flush()
                pending, pending_type = row.flag, type(row.flag).__name__
                session.refresh(row)
                assert type(row.flag) is bool and row.flag is expected
                assert row.optional is None
                session.commit()
                observations.append(dict(label=label, before=before, pending=pending,
                    pending_type=pending_type, refreshed=row.flag))
                row.flag = None
                with pytest.raises(IntegrityError) as failure:
                    session.flush()
                assert failure.value.orig.sqlstate == '23502' and not session.is_active
                session.rollback()
                assert session.get(Subject, row.id).flag is expected
        for value in (2, 'true', 0.5, 2.0):
            with Session(owner) as session:
                session.add(Subject(id=uuid4(), flag=value))
                with pytest.raises(StatementError):
                    session.flush()
                assert not session.is_active
                session.rollback()
        for render_nulls in (False, True):
            with Session(owner) as session:
                identity = uuid4()
                session.execute(insert(Subject), [{'id': identity}],
                                execution_options={'render_nulls': render_nulls})
                assert session.get(Subject, identity).flag is default
                explicit = uuid4()
                if render_nulls:
                    with pytest.raises(IntegrityError) as failure:
                        session.execute(insert(Subject), [{'id': explicit, 'flag': None}],
                                        execution_options={'render_nulls': True})
                    assert failure.value.orig.sqlstate == '23502'
                else:
                    session.execute(insert(Subject), [{'id': explicit, 'flag': None}])
                    assert session.get(Subject, explicit).flag is default
                session.rollback()
        evidence = os.environ.get('CRYPTALIS_BOOLEAN_NATIVE_RECEIPT')
        if evidence:
            with (Path(evidence).parent / (Path(evidence).stem + '-' + str(default).lower() + '.json')).open('x') as stream:
                json.dump(dict(default=default, observations=observations,
                    invalid_python_values='2, string true and floats0.5/2.0 refuse in native bind processing',
                    dictionary_insert='omitted/None uses scalar default; render_nulls=True explicitNone gives23502',
                    update='explicitNone gives23502 and rollback retains current flag', gate='UNKNOWN'), stream, indent=2)
                stream.write('\n')
    finally:
        mapping.dispose()
        with owner.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        owner.dispose()
