"""Native PostgreSQL UUID identity inputs, without Cryptalis attachment."""

import json
import os
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Column, MetaData, Table, Text, Uuid, event, select
from sqlalchemy.exc import DBAPIError, InvalidRequestError, NoResultFound, StatementError
from sqlalchemy.orm import Session, registry

from test_migration import engine, keys, TABLE_ID, FIELD_ID, DOMAIN
from cryptalis import migration as m
from cryptalis.manifest.compiler import Writer, WriterInventory
from cryptalis.sqlalchemy import attach


@pytest.mark.parametrize("protected", [False, True])
def test_native_uuid_get_carriers_errors_rollback_and_identity_reuse(protected):
    owner = engine('CRYPTALIS_TEST_DATABASE_URL')
    runtime = engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
    observed_engine = runtime if protected else owner
    factory = lambda **options: Session(owner, **options)
    schema = 'uuid_identity_native_' + uuid4().hex
    mapping = registry(metadata=MetaData(schema=schema))
    table = Table('subject', mapping.metadata,
        Column('id', Uuid(as_uuid=True), primary_key=True, autoincrement=False),
        Column('label', Text, nullable=False))
    class Subject: pass
    mapping.map_imperatively(Subject, table)
    identity = UUID('12345678-1234-4abc-8def-1234567890ab')
    absent = UUID('12345678-1234-4abc-8def-1234567890ac')
    statements = []
    def observe(connection, cursor, statement, parameters, context, many):
        statements.append(None)  # Count statements without retaining SQL or parameters.
    if not protected:
        event.listen(observed_engine, 'before_cursor_execute', observe)
    observations = {'accepted': [], 'invalid': [], 'missing': [], 'invalid_carriers': []}
    valid = [('uuid', identity), ('canonical', str(identity)), ('upper', str(identity).upper()),
        ('braces', '{' + str(identity) + '}'), ('hyphenless', identity.hex),
        ('per_four', '1234-5678-1234-4abc-8def-1234-5678-90ab'),
        ('max_braced', '{1234-5678-1234-4abc-8def-1234-5678-90ab}'),
        ('mixed_hyphens', identity.hex[:12] + '-' + identity.hex[12:20] + '-' + identity.hex[20:])]
    carriers = [('scalar', lambda value: value), ('mapping', lambda value: {'id': value}),
                ('list', lambda value: [value]), ('tuple', lambda value: (value,))]
    try:
        with owner.begin() as connection:
            connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
        mapping.metadata.create_all(owner)
        with Session(owner) as session:
            session.add(Subject(id=identity, label='PUBLIC native UUID fixture'))
            session.commit()
        if protected:
            with runtime.connect() as connection:
                role = connection.exec_driver_sql('SELECT current_user').scalar_one()
            with owner.begin() as connection:
                quote = connection.dialect.identifier_preparer.quote
                connection.exec_driver_sql(f'REVOKE ALL ON SCHEMA "{schema}" FROM PUBLIC')
                connection.exec_driver_sql(f'GRANT USAGE ON SCHEMA "{schema}" TO {quote(role)}')
                connection.exec_driver_sql(f'GRANT SELECT,INSERT,UPDATE,DELETE ON "{schema}".subject TO {quote(role)}')
            declaration = {'schema':'cryptalis.protection/v1','profile':'cf1','domain_id':str(DOMAIN),
                'models':[{'model':'Subject','table_id':str(TABLE_ID),'tenancy':{'single_tenant':True},
                    'fields':[{'name':'label','field_id':str(FIELD_ID),'protect':True,
                               'queries':[],'accept_leakage':[]}]}]}
            proposal = m.plan(json.dumps(declaration).encode(),mapping,owner,
                writers=WriterInventory(True,(Writer(TABLE_ID,'native UUID oracle','sqlalchemy',
                    evidence='public fixture with native identity parity'),)), keys=keys, runtime_role=role,
                target_id=uuid4(),backfill_rows_per_second=1000,verify_rows_per_second=1000,
                temporary_bytes_per_row=700,wal_bytes_per_row=2000)
            approval = m.MaintenanceApproval('local fixture stopped; inventoried owner writers excluded',3600)
            def pin(phase): return m.DeploymentPin(proposal.target_id,proposal.operation_id,proposal.digest,phase)
            assert m.apply(proposal,owner,keys=keys,pin=pin('PREPARED'),approval=approval).phase=='PENDING'
            assert m.apply(proposal,owner,keys=keys,pin=pin('ACTIVATING'),approval=approval,until='ACTIVE').phase=='ACTIVE'
            sessions=attach(mapping,runtime,lock=proposal.lock_bytes,keys=keys,deployment=(proposal,pin('ACTIVE')))
            factory=lambda **options: sessions(tenant_id=TABLE_ID,**options)
            event.listen(observed_engine, 'before_cursor_execute', observe)
        for method in ('get', 'get_one'):
            for label, value in valid:
                for carrier, wrap in carriers:
                    with factory(expire_on_commit=False) as session:
                        lookup = getattr(session, method)
                        before = len(statements)
                        first = lookup(Subject, wrap(value))
                        cold = len(statements) - before
                        assert type(first.id) is UUID and first.id == identity
                        assert first.label == 'PUBLIC native UUID fixture'
                        before = len(statements)
                        assert lookup(Subject, wrap(value)) is first
                        repeated = len(statements) - before
                        before = len(statements)
                        assert session.get(Subject, identity) is first
                        assert len(statements) == before
                        observations['accepted'].append(dict(method=method, value=label,
                            carrier=carrier, cold_statements=cold,
                            repeated_statements=repeated, uuid_identity_cache_hit=True))

        # PostgreSQL, rather than Python's UUID parser, determines text admission.
        invalid = [('malformed', 'not-a-uuid'), ('truncated', str(identity)[:-1]),
            ('urn', 'urn:uuid:' + str(identity)), ('leading_space', ' ' + str(identity)),
            ('trailing_space', str(identity) + ' '), ('empty', ''),
            ('non_ascii', str(identity).replace('1', '\uff11', 1)),
            ('non_hex', str(identity)[:-1] + 'z'), ('integer', 7)]
        for method in ('get', 'get_one'):
            for label, value in invalid:
                for carrier, wrap in carriers:
                    with factory() as session:
                        lookup = getattr(session, method)
                        with pytest.raises(StatementError) as caught:
                            lookup(Subject, wrap(value))
                        state = getattr(caught.value.orig, 'sqlstate', None)
                        server_failure = isinstance(caught.value, DBAPIError)
                        active_after_failure = session.is_active
                        if server_failure:
                            assert state in ('22P02', '42846')
                            with pytest.raises(DBAPIError) as aborted:
                                session.get(Subject, identity)
                            assert aborted.value.orig.sqlstate == '25P02'
                        else:
                            assert state is None
                            assert session.get(Subject, identity).id == identity
                        session.rollback()
                        assert session.get(Subject, identity).id == identity
                        observations['invalid'].append(dict(method=method, value=label,
                            carrier=carrier, failure=type(caught.value).__name__, sqlstate=state,
                            session_active_after_error=active_after_failure,
                            transaction_aborted=server_failure, rollback_recovered=True))

        for value_label, value in [('uuid', absent), ('canonical', str(absent))]:
            for carrier, wrap in carriers:
                with factory() as session:
                    assert session.get(Subject, wrap(value)) is None
                    with pytest.raises(NoResultFound):
                        session.get_one(Subject, wrap(value))
                    assert session.get(Subject, identity).id == identity
                    observations['missing'].append(dict(value=value_label, carrier=carrier,
                        get='None', get_one='NoResultFound', transaction_usable=True))

        with factory() as session:
            assert [row.id for row in session.scalars(select(Subject).where(
                Subject.id.in_([identity.hex, str(identity).upper()])))] == [identity]
            assert list(session.scalars(select(Subject).where(Subject.id.in_([])))) == []
            with pytest.raises(DBAPIError) as mixed:
                session.scalars(select(Subject).where(Subject.id.in_([str(identity), 'not-a-uuid']))).all()
            assert mixed.value.orig.sqlstate == '22P02'
            with pytest.raises(DBAPIError) as aborted:
                session.get(Subject, identity)
            assert aborted.value.orig.sqlstate == '25P02'
            session.rollback()
            assert session.get(Subject, identity).id == identity
        observations['IN'] = ['valid aliases return one native row', 'empty list returns no row',
                              'one invalid member gives22P02; aborted transaction requires rollback']

        for method in ('get', 'get_one'):
            for label, value in [('empty_list', []), ('empty_tuple', ()), ('empty_dict', {}),
                    ('wrong_dict_key', {'unknown': identity}), ('two_values', [identity, absent])]:
                with factory() as session:
                    before = len(statements)
                    with pytest.raises(InvalidRequestError):
                        getattr(session, method)(Subject, value)
                    assert len(statements) == before
                    assert session.get(Subject, identity).id == identity
                    observations['invalid_carriers'].append(dict(method=method, value=label,
                        failure='InvalidRequestError', before_sql=True, transaction_usable=True))

        evidence = os.environ.get('CRYPTALIS_UUID_IDENTITY_NATIVE_RECEIPT')
        if evidence:
            with Path(evidence).with_name(Path(evidence).stem + ('-protected' if protected else '-native') + Path(evidence).suffix).open('x') as stream:
                json.dump({'scope': 'Native/attached PostgreSQL16 SQLAlchemy Uuid(as_uuid=True) Session identity differential oracle',
                    'fixture': 'public application-assigned UUID primary key', 'protected':protected,
                    'observations': observations, 'private_values_recorded': False,
                    'gate': 'UNKNOWN'}, stream, indent=2)
                stream.write('\n')
    finally:
        if event.contains(observed_engine, 'before_cursor_execute', observe):
            event.remove(observed_engine, 'before_cursor_execute', observe)
        runtime.dispose()
        mapping.dispose()
        with owner.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        owner.dispose()
