"""Native scalar writes remain current through capture, publication and exit."""
from datetime import date, datetime
from uuid import UUID

import pytest
from sqlalchemy import BigInteger, Boolean, Date, DateTime, Integer, SmallInteger, Uuid, select
from sqlalchemy.exc import DBAPIError

from cryptalis import deprotection as d, migration as m, online
from cryptalis.sqlalchemy import attach
from test_migration import keys, TABLE_ID
from test_online_protection import app, _pin, _payloads, _source_rows


SCALARS = [(Boolean(), (False, True, None)), (SmallInteger(), (-32768, 32767, None)),
           (Integer(), (-2**31, 2**31-1, None)), (BigInteger(), (-2**63, 2**63-1, None)),
           (Date(), (date.min, date.max, None)),
           (DateTime(), (datetime.min, datetime.max, None)),
           (Uuid(), (UUID(int=0), UUID(int=2**128-1), None))]


@pytest.mark.parametrize('app', SCALARS, indirect=True)
@pytest.mark.parametrize('abort', [False, True])
def test_online_scalar_current_values_resume_abort_or_native_exit(app, abort):
    expected = _source_rows(app)
    first = online.apply(app.plan, app.owner, keys=keys, pin=app.pin,
                         approval=app.approval, max_chunks=1)
    assert first.committed_chunks == 1
    before = _payloads(app, app.plan)[UUID(int=10)]
    with app.source_factory() as session:
        session.get(app.Customer, UUID(int=10)).body = expected[UUID(int=20)][0]
        session.add(app.Customer(id=UUID(int=5), body=expected[UUID(int=10)][0], label='new'))
        session.delete(session.get(app.Customer, UUID(int=30)))
        session.commit()
    expected[UUID(int=5)] = expected[UUID(int=10)][0], 'new'
    expected[UUID(int=10)] = expected[UUID(int=20)][0], expected[UUID(int=10)][1]
    del expected[UUID(int=30)]
    assert _source_rows(app) == expected
    assert _payloads(app, app.plan)[UUID(int=10)] == (None, None)
    assert before != (None, None)
    online.apply(app.plan, app.owner, keys=keys, pin=app.pin, approval=app.approval, max_chunks=1)
    completed = _payloads(app, app.plan)[UUID(int=5)]
    online.apply(type(app.plan)(app.plan.artifact), app.owner, keys=keys, pin=app.pin,
                 approval=app.approval, max_chunks=1, fence=True)
    assert _payloads(app, app.plan)[UUID(int=5)] == completed
    if abort:
        assert online.abort(app.plan, app.owner, pin=app.pin, approval=app.approval).phase == 'ABORTED'
        assert _source_rows(app) == expected
        return
    with pytest.raises(DBAPIError):
        with app.source_factory() as session:
            session.get(app.Customer, UUID(int=10)).label = 'blocked'
            session.commit()
    online.apply(app.plan, app.owner, keys=keys, pin=app.pin, approval=app.approval, max_chunks=10)
    successor = online.seal(app.plan, app.owner, keys=keys, pin=app.pin, approval=app.approval)
    online.switch(app.plan, app.owner, successor=successor, keys=keys, pin=app.pin, approval=app.approval)
    approval = m.MaintenanceApproval(app.approval.owner_writer_exclusion, 3600)
    m.apply(successor, app.owner, keys=keys, pin=_pin(successor, 'ACTIVATING'), approval=approval, until='ACTIVE')
    factory = attach(app.mapping, app.target, lock=successor.lock_bytes, keys=keys,
                     deployment=(successor, _pin(successor, 'ACTIVE')))
    with factory(tenant_id=TABLE_ID) as session:
        assert {row.id: (row.body, row.label) for row in session.scalars(select(app.Customer))} == expected
        session.get(app.Customer, UUID(int=20)).body = None
        session.commit()
    expected[UUID(int=20)] = None, expected[UUID(int=20)][1]
    reverse = d.plan(successor, app.owner, source_pin=_pin(successor, 'ACTIVE'), keys=keys,
        plaintext_runtime_role=app.source_role, backfill_rows_per_second=1000,
        verify_rows_per_second=1000, temporary_bytes_per_row=1000, wal_bytes_per_row=2000)
    consent = d.PlaintextApproval(reverse.target_id, reverse.operation_id, reverse.digest,
                                 True, 'Public disposable scalar capture fixture.')
    d.apply(reverse, app.owner, keys=keys, pin=_pin(reverse, 'PREPARED'), approval=approval, consent=consent)
    d.apply(reverse, app.owner, keys=keys, pin=_pin(reverse, 'PLAINTEXT_ACTIVATING'),
            approval=approval, consent=consent, until='PLAINTEXT_ACTIVE')
    removal = d.RemovalApproval(reverse.target_id, reverse.operation_id, reverse.digest,
        'Current native source-role values match.', 'No retained protected fixture.', True)
    d.remove(reverse, app.owner, pin=_pin(reverse, 'REMOVING'), approval=approval, removal=removal, consent=consent)
    assert _source_rows(app) == expected


@pytest.mark.parametrize('app', [(Date(), (date.min, date.max, None)),
                               (DateTime(), (datetime.min, datetime.max, None))], indirect=True)
def test_out_of_range_temporal_value_written_during_capture_refuses_atomically(app):
    online.apply(app.plan, app.owner, keys=keys, pin=app.pin, approval=app.approval, max_chunks=1)
    kind = app.plan.document['lock']['models'][0]['fields'][0]['source']['type']
    assert kind in ('date', 'timestamp')
    with app.source.begin() as connection:
        connection.exec_driver_sql(f'INSERT INTO "{app.schema}".customer(id,body) VALUES (%s,\'infinity\'::{kind})', (UUID(int=5),))
    before = _payloads(app, app.plan)
    with pytest.raises(m.TransitionFailure) as failure:
        online.apply(app.plan, app.owner, keys=keys, pin=app.pin, approval=app.approval, max_chunks=1)
    assert failure.value.code == kind + '_outside_python_range'
    assert _payloads(app, app.plan) == before
    assert online.status(app.plan, app.owner, pin=app.pin).committed_chunks == 1


@pytest.mark.parametrize('app', [(Date(), (date.min, date.max, None)),
                               (DateTime(), (datetime.min, datetime.max, None))], indirect=True)
def test_post_plan_temporal_domain_drift_refuses_before_capture_effects(app):
    kind = app.plan.document['lock']['models'][0]['fields'][0]['source']['type']
    assert kind in ('date', 'timestamp')
    with app.source.begin() as connection:
        connection.exec_driver_sql(f'INSERT INTO "{app.schema}".customer(id,body) VALUES (%s,\'infinity\'::{kind})', (UUID(int=5),))
    with pytest.raises(m.TransitionFailure) as failure:
        online.apply(app.plan, app.owner, keys=keys, pin=app.pin, approval=app.approval, max_chunks=0)
    assert failure.value.code == kind + '_source_domain'
    with app.owner.connect() as connection:
        assert connection.exec_driver_sql('SELECT count(*) FROM information_schema.columns '
            'WHERE table_schema=%s AND column_name LIKE %s', (app.schema, '_cryptalis_%')).scalar_one() == 0
        assert not connection.exec_driver_sql('SELECT relhastriggers FROM pg_catalog.pg_class '
            'WHERE oid=pg_catalog.to_regclass(%s)', (f'"{app.schema}".customer',)).scalar_one()
