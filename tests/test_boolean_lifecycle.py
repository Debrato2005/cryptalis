"""Mixed text/search/Boolean lifecycle with two tables and tenant isolation."""
from contextlib import contextmanager
from datetime import date
from uuid import UUID

import pytest
from sqlalchemy import Boolean, Column, Date, MetaData, Table, Text, Uuid, select
from sqlalchemy.orm import registry, sessionmaker

from cryptalis import deprotection as d, migration as m, rotation as r
from cryptalis.crypto import KeyUnavailable
from cryptalis.sqlalchemy import attach
from test_deprotection import app_pin, consent, least_privilege_role
from test_migration import engine, keys, publish, run, TENANT
from test_migration_multitable import multiple_tables, other_frames, OTHER_TENANT
from test_payload_rotation_execution import staged_frames


@contextmanager
def scalar_mapping(app, dtype):
    mapping = registry(metadata=MetaData(schema=app.schema))
    customer = Table('customer', mapping.metadata,
        Column('id', Uuid, primary_key=True, autoincrement=False),
        Column('tenant_id', Uuid, nullable=False), Column('name', Text(collation='C')), Column('label', Text))
    other = Table('other_customer', mapping.metadata,
        Column('id', Uuid, primary_key=True, autoincrement=False),
        Column('tenant_id', Uuid, nullable=False), Column('name', Text(collation='C')), Column('note', dtype))
    class Customer: pass
    class OtherCustomer: pass
    mapping.map_imperatively(Customer, customer)
    mapping.map_imperatively(OtherCustomer, other)
    runtime = engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
    try:
        yield mapping, Customer, OtherCustomer, runtime
    finally:
        runtime.dispose()
        mapping.dispose()


def note_frames(app):
    return other_frames(app, True, note=True)


@pytest.mark.parametrize('purpose', ['rewrap', 'payload', 'search'])
@pytest.mark.parametrize('dtype', [Boolean, Date, Uuid])
def test_scalar_mixed_rotations_interruption_tenants_and_latest_value_removal(purpose, dtype):
    dates = dtype is Date
    uuids = dtype is Uuid
    entered, latest = ((UUID(int=2024), UUID(int=2025)) if uuids else
                       (date(2024, 2, 29), date(2025, 3, 1)) if dates else (True, False))
    if purpose == 'rewrap':
        from rewrap_worker import target_keys
    elif purpose == 'payload':
        from payload_rotation_worker import target_keys
    else:
        from search_rotation_worker import target_keys
    with multiple_tables(boolean_note=dtype is Boolean, date_note=dates, uuid_note=uuids) as app:
        run(app); publish(app)
        source, source_pin = app.plan, app.pin
        sessions = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                          deployment=(app.plan, app.pin))
        identity = UUID(int=101)
        with sessions(tenant_id=TENANT) as session:
            row = session.get(app.other, identity)
            row.note = entered
            session.commit()
        expected = dict(app.notes)
        expected[identity] = entered
        before = note_frames(app)
        if purpose == 'rewrap':
            preparation = r.plan_rewrap(source, app.owner, source_pin=source_pin,
                keys=keys, target_keys=target_keys, verify_rows_per_second=1000)
            activation = preparation.activation_plan
            assert r.apply_rewrap(preparation, app.owner, keys=keys, target_keys=target_keys,
                pin=app_pin(activation, 'PREPARED'), approval=app.approval).phase == 'PENDING'
            assert note_frames(app) == before
        else:
            preparation = getattr(r, 'plan_' + purpose + '_rotation')(
                source, app.owner, source_pin=source_pin, keys=keys, target_keys=target_keys,
                backfill_rows_per_second=1000, verify_rows_per_second=1000,
                temporary_bytes_per_row=1024, wal_bytes_per_row=2048, max_batch_rows=3)
            operation_pin = m.DeploymentPin(source.target_id, preparation.operation_id, preparation.digest, 'PREPARED')
            apply = getattr(r, 'apply_' + purpose + '_rotation')
            paused = apply(preparation, app.owner, keys=keys, target_keys=target_keys,
                pin=operation_pin, approval=app.approval, max_chunks=1)
            assert paused.phase == 'EXPANDED' and paused.committed_chunks == 1
            prefix = staged_frames(app, preparation)
            assert note_frames(app) == before
            assert apply(type(preparation)(preparation.artifact), app.owner, keys=keys,
                target_keys=target_keys, pin=operation_pin, approval=app.approval).phase == 'BACKFILLED'
            complete = staged_frames(app, preparation)
            for key, values in prefix.items():
                if any(value is not None for value in values):
                    assert complete[key] == values
            activation = getattr(r, 'seal_' + purpose + '_rotation')(
                preparation, app.owner, keys=keys, target_keys=target_keys, pin=operation_pin,
                approval=app.approval, copy_rows_per_second=1000, copy_wal_bytes_per_row=2048)
            assert getattr(r, 'switch_' + purpose + '_rotation')(
                preparation, activation, app.owner, keys=keys, target_keys=target_keys,
                pin=app_pin(activation, 'PREPARED'), approval=app.approval).phase == 'PENDING'
        with pytest.raises(m.TransitionFailure):
            m.check_deployment(source, app.owner, pin=source_pin)
        assert m.apply(activation, app.owner, keys=target_keys, pin=app_pin(activation, 'ACTIVATING'),
            approval=app.approval, until='ACTIVE').phase == 'ACTIVE'
        app.plan, app.pin = activation, app_pin(activation, 'ACTIVE')
        after = note_frames(app)
        if purpose in ('search', 'rewrap'):
            assert after == before
        else:
            assert all(after[key] != frame if frame is not None else after[key] is None
                       for key, frame in before.items())
        if purpose == 'rewrap':
            with sessions(tenant_id=TENANT) as stale:
                assert stale.get(app.other, identity).note == entered  # Root bytes and generations stay unchanged.
        else:
            with pytest.raises(KeyUnavailable):
                with sessions(tenant_id=TENANT) as stale:
                    stale.get(app.other, identity)
        with scalar_mapping(app, dtype) as (mapping, Customer, Other, runtime):
            current = attach(mapping, runtime, lock=activation.lock_bytes, keys=target_keys,
                             deployment=(activation, app.pin))
            for tenant in (TENANT, OTHER_TENANT):
                with current(tenant_id=tenant) as session:
                    observed = {row.id: row.note for row in session.scalars(
                        select(Other).where(Other.tenant_id == tenant))}
                    assert observed == {key: value for key, value in expected.items()
                                        if app.other_source[key][0] == tenant}
                    assert all(type(value) is (UUID if uuids else date if dates else bool) or value is None for value in observed.values())
                    assert session.scalar(select(Customer.id).where(
                        Customer.tenant_id == tenant, Customer.name == app.source[
                            UUID(int=102) if tenant == TENANT else UUID(int=901)][1])) is not None
            with current(tenant_id=TENANT) as session:
                session.get(Other, identity).note = latest
                session.commit()
            expected[identity] = latest
        reverse = d.plan(app.plan, app.owner, source_pin=app.pin, keys=target_keys,
            plaintext_runtime_role=least_privilege_role(app), backfill_rows_per_second=1000,
            verify_rows_per_second=1000, temporary_bytes_per_row=1024, wal_bytes_per_row=2048)
        pure, pin = consent(reverse)
        paused = d.apply(reverse, app.owner, keys=target_keys, pin=pin, approval=app.approval,
                         consent=pure, until='BACKFILLED', chunk_size=2)
        assert paused.phase == 'BACKFILLED' and paused.committed_chunks > 1
        assert d.apply(type(reverse)(reverse.artifact), app.owner, keys=target_keys,
            pin=pin, approval=app.approval, consent=pure).phase == 'PLAINTEXT_PENDING'
        assert d.apply(reverse, app.owner, keys=target_keys, pin=app_pin(reverse, 'PLAINTEXT_ACTIVATING'),
            approval=app.approval, consent=pure, until='PLAINTEXT_ACTIVE').phase == 'PLAINTEXT_ACTIVE'
        removal = d.RemovalApproval(reverse.target_id, reverse.operation_id, reverse.digest,
            'native scalar latest-value restart', 'public disposable fixture values', True)
        assert d.remove(reverse, app.owner, pin=app_pin(reverse, 'REMOVING'), approval=app.approval,
                        removal=removal, consent=pure).phase == 'REMOVED'
        assert d.check_removed(reverse, app.owner, pin=app_pin(reverse, 'REMOVED')) is None
        with scalar_mapping(app, dtype) as (_, _, Other, runtime):
            with sessionmaker(runtime)() as session:
                assert {row.id: row.note for row in session.scalars(select(Other))} == expected
        with app.owner.connect() as connection:
            assert connection.exec_driver_sql('SELECT data_type FROM information_schema.columns '
                'WHERE table_schema=%s AND table_name=%s AND column_name=%s',
                (app.schema, 'other_customer', 'note')).scalar_one() == ('uuid' if uuids else 'date' if dates else 'boolean')
