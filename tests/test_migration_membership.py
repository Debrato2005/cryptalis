"""Native column permissions and independent journal bytes are the oracles."""
import hashlib
import json
from uuid import UUID

import pytest
from sqlalchemy import BigInteger, Column, Table, Text, Uuid
from sqlalchemy.exc import DBAPIError

from cryptalis.manifest.compiler import Writer, WriterInventory, compile_protection
from test_migration import application, frames, independent_open, run, TABLE_ID, TENANT


def membership(rows):
    digest = hashlib.sha256()
    for record, tenant in rows:
        digest.update(json.dumps([str(record), str(tenant)], sort_keys=True,
                                 separators=(',', ':')).encode())
    return {'count': len(rows), 'membership': digest.hexdigest()}


@pytest.mark.parametrize('record_type', ['uuid', 'bigint'])
@pytest.mark.parametrize('scoped', [True, False])
def test_membership_needs_only_native_identity_permissions(record_type, scoped):
    with application(rows=0) as app:
        table_id = UUID(int=701)
        columns = [Column('id', Uuid if record_type == 'uuid' else BigInteger,
                          primary_key=True, autoincrement=False)]
        if scoped:
            columns.append(Column('tenant_id', Uuid, nullable=False))
        columns.extend((Column('name', Text), Column('note', Text)))
        table = Table('membership_probe', app.mapping.metadata, *columns)
        class Probe: pass
        app.mapping.map_imperatively(Probe, table)
        table.create(app.owner)
        identities = ([UUID(int=i) for i in range(1007)] if record_type == 'uuid'
                      else [-2**63, -1, 0, *range(1, 1004), 2**63-1])
        # More than one scan page, nil identities, signed boundaries, multiple
        # fields, tenants and large text that membership must never need.
        source = [dict(id=record, name=[None, '', '雪😀', 'e\u0301'][i % 4],
                       note='雪' * 400_000 if i == 0 else 'native note',
                       **({'tenant_id': UUID(int=i % 3)} if scoped else {}))
                  for i, record in enumerate(identities)]
        with app.owner.begin() as c:
            c.execute(table.insert(), source)
            names = 'id,tenant_id' if scoped else 'id'
            c.exec_driver_sql(f'GRANT SELECT ({names}) ON "{app.schema}".membership_probe TO "{app.role}"')
        declaration = {'schema': 'cryptalis.protection/v1', 'profile': 'cf1',
            'domain_id': str(UUID(int=501)), 'models': [{'model': 'Probe',
            'table_id': str(table_id), 'tenancy': {'column': 'tenant_id'} if scoped else {'single_tenant': True},
            'fields': [{'name': name, 'field_id': str(UUID(int=702+i)),
                        'protect': True, 'queries': [], 'accept_leakage': []}
                       for i, name in enumerate(('name', 'note'))]}]}
        compiled = compile_protection(json.dumps(declaration).encode(), app.mapping, app.owner,
            writers=WriterInventory(True, (Writer(table_id, 'app', 'sqlalchemy', evidence='native identity permissions'),)))
        model = json.loads(compiled.lock_bytes)['models'][0]
        with app.owner.connect() as c:
            native = c.exec_driver_sql(f'SELECT {names} FROM "{app.schema}".membership_probe ORDER BY id').all()
        expected = membership([(row[0], row[1] if scoped else table_id) for row in native])
        # Native denial demonstrates the fixture really excludes source data.
        with app.runtime.connect() as c:
            with pytest.raises(DBAPIError) as denied:
                c.exec_driver_sql(f'SELECT name,note FROM "{app.schema}".membership_probe')
            assert denied.value.orig.sqlstate == '42501'
        with app.runtime.connect() as c:
            assert c.exec_driver_sql(f'SELECT {names} FROM "{app.schema}".membership_probe ORDER BY id').all() == native
            try:
                observed = app.m._scope(c, model)
            except DBAPIError as failure:
                observed = ('native SQLSTATE', failure.orig.sqlstate)
            assert observed == expected


def test_membership_journal_is_compatible_and_every_value_is_still_verified():
    with application(rows=1007) as app:
        with app.owner.connect() as c:
            native = c.exec_driver_sql(f'SELECT id,tenant_id FROM "{app.schema}".customer ORDER BY id').all()
        expected = membership(native)
        run(app, 'BACKFILLED', chunk_size=173)
        with app.owner.connect() as c:
            state = c.exec_driver_sql(f'SELECT state FROM "{app.schema}"._cryptalis_journal').scalar_one()
        assert state['models'][str(TABLE_ID)]['scope'] == expected
        assert state['models'][str(TABLE_ID)]['rows'] == len(native)
        assert run(app).phase == 'PENDING'
        field = app.plan.document['lock']['models'][0]['fields'][0]
        observed = frames(app, True)
        assert observed.keys() == app.source.keys()
        for record, frame in observed.items():
            assert independent_open(frame, field['descriptor'], TENANT, record) == app.source[record][1]
