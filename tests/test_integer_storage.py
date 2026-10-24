"""Protected native signed integer storage requires compiler and lifecycle proof."""
import pytest
from sqlalchemy import BigInteger, Integer, SmallInteger
from test_migration import application


@pytest.mark.parametrize('dtype,bits', [(SmallInteger, 16), (Integer, 32), (BigInteger, 64)])
def test_integer_compiler_binds_width_codec_and_new_reader_boundary(dtype, bits):
    lower, upper = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
    with application(value_type=dtype(), queries=[], value_nullable=True,
                     protected_values=(lower, upper, None)) as app:
        lock = app.plan.document['lock']
        codec = 'pg-int' + str(bits // 8) + '-be/v1'
        assert lock['schema'] == 'cryptalis.lock/v7' and lock['layout'] is None
        assert codec in lock['required_readers']
        field = lock['models'][0]['fields'][0]
        assert field['source']['type'] == 'int' + str(bits // 8)
        assert field['descriptor']['schema'] == 'cryptalis.context/v2'
        assert field['descriptor']['value_codec'] == codec
        assert lock['models'][0]['source_metadata']['owned_sequences'] == []


@pytest.mark.parametrize('dtype,bits', [(SmallInteger, 16), (Integer, 32), (BigInteger, 64)])
@pytest.mark.parametrize('public_slots', [False, True])
def test_integer_migration_entity_projection_latest_edit_and_native_removal(dtype, bits, public_slots):
    from uuid import UUID
    from sqlalchemy import select
    from cryptalis.sqlalchemy import attach
    from test_migration import run, publish, keys, TENANT
    from test_deprotection import proposal as reverse_plan, reverse as reverse_apply, app_pin, consent, d
    lower, upper = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
    with application(value_type=dtype(), queries=[], protected_values=(lower, upper, None, 0, -1)) as app:
        if public_slots:
            from test_public_slots import select_layout, slots
            original_slots = slots(app)
            select_layout(app)
        run(app); publish(app)
        if public_slots:
            assert slots(app) == original_slots
        sessions = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                          deployment=(app.plan, app.pin))
        with sessions(tenant_id=TENANT) as session:
            observed = {row.id: row.name for row in session.scalars(select(app.Customer))}
            assert observed == {identity: value for identity, (_, value) in app.source.items()}
            assert all(value is None or type(value) is int for value in observed.values())
            current = session.get(app.Customer, UUID(int=101))
            current.name = lower + 1
            session.commit()
            session.expire_all()
            assert session.get(app.Customer, current.id).name == lower + 1
        proposal = reverse_plan(app)
        reverse_apply(app, proposal)
        reverse_apply(app, proposal, until='PLAINTEXT_ACTIVE', phase='PLAINTEXT_ACTIVATING')
        expected = dict(app.source)
        expected[UUID(int=101)] = TENANT, lower + 1
        active_consent, _ = consent(proposal, 'PLAINTEXT_ACTIVATING')
        removal = d.RemovalApproval(proposal.target_id, proposal.operation_id, proposal.digest,
            'native integer width and latest-value fixture', 'public backup fixture only', True)
        assert d.remove(proposal, app.owner, pin=app_pin(proposal, 'REMOVING'), approval=app.approval,
                        removal=removal, consent=active_consent).phase == 'REMOVED'
        with app.owner.connect() as connection:
            assert {row[0]: (row[1], row[2]) for row in connection.exec_driver_sql(
                f'SELECT id,tenant_id,name FROM "{app.schema}".customer')} == expected
            assert connection.exec_driver_sql('SELECT a.atttypid::regtype::text FROM pg_catalog.pg_attribute a '
                'WHERE a.attrelid=pg_catalog.to_regclass(%s) AND a.attname=%s',
                (f'"{app.schema}".customer', 'name')).scalar_one() == {16: 'smallint',32: 'integer',64: 'bigint'}[bits]
        if public_slots:
            assert slots(app) == original_slots


@pytest.mark.parametrize('dtype,bits', [(SmallInteger, 16), (Integer, 32), (BigInteger, 64)])
@pytest.mark.parametrize('route', ['flush', 'dictionary_insert', 'scoped_update'])
def test_integer_out_of_width_matches_native_transaction_and_savepoint(dtype, bits, route):
    from uuid import UUID, uuid4
    from sqlalchemy import insert, select, update
    from sqlalchemy.exc import DBAPIError
    from sqlalchemy.orm import Session
    from cryptalis.crypto import CryptoFailure
    from cryptalis.sqlalchemy import attach
    from test_migration import run, publish, keys, TENANT
    value = (1 << (bits - 1)) + 37
    with application(value_type=dtype(), queries=[], protected_values=(0, 1, None)) as app:
        def write(session):
            if route == 'flush':
                row = session.get(app.Customer, UUID(int=100))
                row.name = value
                session.flush()
            elif route == 'dictionary_insert':
                session.execute(insert(app.Customer), [{'id': uuid4(), 'tenant_id': TENANT, 'name': value}])
            else:
                session.execute(update(app.Customer).where(app.Customer.tenant_id == TENANT),
                    [{'id': UUID(int=100), 'name': value}], execution_options={'synchronize_session': False})
        def scenario(factory, protected):
            with factory() as session:
                driver = session.connection().connection.driver_connection
                with pytest.raises(CryptoFailure if protected else DBAPIError) as failure:
                    write(session)
                sqlstate = getattr(failure.value, 'sqlstate', None) if protected else failure.value.orig.sqlstate
                assert sqlstate == '22003'
                assert str(value) not in str(failure.value) if protected else True
                observed = session.is_active, driver.info.transaction_status.name
                session.rollback()
                assert session.get(app.Customer, UUID(int=100)).name == 0
            with factory() as session:
                savepoint = session.begin_nested()
                with pytest.raises(CryptoFailure if protected else DBAPIError): write(session)
                savepoint.rollback()
                assert session.get(app.Customer, UUID(int=100)).name == 0
                session.rollback()
            return observed
        expected = scenario(lambda: Session(app.runtime), False)
        run(app); publish(app)
        sessions = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                          deployment=(app.plan, app.pin))
        assert scenario(lambda: sessions(tenant_id=TENANT), True) == expected


@pytest.mark.parametrize('dtype,bits', [(SmallInteger, 16), (Integer, 32), (BigInteger, 64)])
@pytest.mark.parametrize('mode', ['force_custom_plan', 'force_generic_plan'])
def test_integer_prepared_zero_match_scoped_update_preserves_native_timing(dtype, bits, mode):
    import os
    import psycopg
    from uuid import uuid4
    from sqlalchemy import create_engine, update
    from sqlalchemy.exc import DBAPIError
    from sqlalchemy.orm import Session
    from cryptalis.crypto import CryptoFailure
    from cryptalis.sqlalchemy import attach
    from test_migration import run, publish, keys, TENANT
    with application(value_type=dtype(), queries=[], protected_values=(0, 1, None)) as app:
        app.runtime.dispose()
        app.runtime = create_engine('postgresql+psycopg://', hide_parameters=True,
            creator=lambda: psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'],
                options='-c plan_cache_mode=' + mode, prepare_threshold=0))
        bad = (1 << (bits - 1)) + 37
        def scenario(factory, protected):
            with factory() as session:
                driver = session.connection().connection.driver_connection
                try:
                    session.execute(update(app.Customer).where(app.Customer.tenant_id == TENANT),
                        [{'id': uuid4(), 'name': bad}], execution_options={'synchronize_session': False})
                except (CryptoFailure, DBAPIError) as error:
                    code = getattr(error, 'sqlstate', None) if isinstance(error, CryptoFailure) else error.orig.sqlstate
                    assert code == '22003'
                    result = 'error', code, driver.info.transaction_status.name
                else:
                    result = 'zero_rows', None, driver.info.transaction_status.name
                session.rollback()
                return result
        expected = scenario(lambda: Session(app.runtime), False)
        assert expected == (('error', '22003', 'INERROR') if mode == 'force_custom_plan' else ('zero_rows', None, 'INTRANS'))
        run(app); publish(app)
        sessions = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                          deployment=(app.plan, app.pin))
        assert scenario(lambda: sessions(tenant_id=TENANT), True) == expected


@pytest.mark.parametrize('dtype,bits', [(SmallInteger, 16), (Integer, 32), (BigInteger, 64)])
@pytest.mark.parametrize('mode', ['force_custom_plan', 'force_generic_plan'])
def test_integer_dictionary_positive_writes_keep_exact_values_and_no_plaintext_binds(dtype, bits, mode):
    import os
    import psycopg
    from uuid import uuid4
    from sqlalchemy import create_engine, event, insert, select, update
    from cryptalis.sqlalchemy import attach
    from test_migration import run, publish, keys, TENANT
    value = (1 << (bits - 1)) - 37
    with application(value_type=dtype(), queries=[], protected_values=(0, 1, None)) as app:
        app.runtime.dispose()
        app.runtime = create_engine('postgresql+psycopg://', hide_parameters=True,
            creator=lambda: psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'],
                options='-c plan_cache_mode=' + mode, prepare_threshold=0))
        run(app); publish(app)
        sessions = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                          deployment=(app.plan, app.pin))
        observed = []
        def inspect_parameters(connection, cursor, statement, parameters, context, executemany):
            groups = parameters if isinstance(parameters, list) else [parameters]
            for group in groups:
                values = group.values() if isinstance(group, dict) else group
                assert all(type(item) is not int or abs(item) != value for item in values)
                assert all(type(item) is not str or item not in (str(value), str(-value)) for item in values)
            observed.append(True)
        event.listen(app.runtime, 'before_cursor_execute', inspect_parameters)
        with sessions(tenant_id=TENANT) as session:
            identity = uuid4()
            session.execute(insert(app.Customer), [{'id': identity, 'tenant_id': TENANT, 'name': value}])
            assert session.get(app.Customer, identity).name == value
            session.execute(update(app.Customer).where(app.Customer.tenant_id == TENANT),
                [{'id': identity, 'name': -value}], execution_options={'synchronize_session': False})
            session.expire_all()
            assert session.get(app.Customer, identity).name == -value
            assert session.scalar(select(app.table.c.name).where(app.table.c.id == identity)) == -value
            session.commit()
        assert observed


@pytest.mark.parametrize('dtype,bits', [(SmallInteger, 16), (Integer, 32), (BigInteger, 64)])
@pytest.mark.parametrize('mode', ['force_custom_plan', 'force_generic_plan'])
def test_integer_stale_entity_range_assignment_preserves_native_prepared_result(dtype, bits, mode):
    import os
    import psycopg
    from uuid import UUID
    from sqlalchemy import create_engine, insert
    from sqlalchemy.exc import DBAPIError
    from sqlalchemy.orm import Session
    from sqlalchemy.orm.exc import StaleDataError
    from cryptalis.crypto import CryptoFailure
    from cryptalis.sqlalchemy import attach
    from test_migration import run, publish, keys, TENANT
    with application(value_type=dtype(), queries=[], protected_values=(0, 1, None)) as app:
        app.runtime.dispose()
        app.runtime = create_engine('postgresql+psycopg://', hide_parameters=True,
            creator=lambda: psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'],
                options='-c plan_cache_mode=' + mode, prepare_threshold=0))
        def scenario(factory):
            with factory() as first:
                row = first.get(app.Customer, UUID(int=100))
                with factory() as second:
                    second.delete(second.get(app.Customer, row.id))
                    second.commit()
                row.name = (1 << (bits - 1)) + 37
                try:
                    first.flush()
                except (CryptoFailure, DBAPIError, StaleDataError) as error:
                    code = getattr(error, 'sqlstate', None) if isinstance(error, CryptoFailure) else getattr(getattr(error, 'orig', None), 'sqlstate', None)
                    result = ('range', code) if code is not None else (type(error).__name__, None)
                else:
                    pytest.fail('stale entity assignment unexpectedly succeeded')
                assert first.is_active is False
                first.rollback()
                return result
        expected = scenario(lambda: Session(app.runtime))
        assert expected == (('range', '22003') if mode == 'force_custom_plan' else ('StaleDataError', None))
        with app.owner.begin() as connection:
            connection.execute(insert(app.table), {'id': UUID(int=100), 'tenant_id': TENANT, 'name': 0, 'label': 'label-100'})
        run(app); publish(app)
        sessions = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                          deployment=(app.plan, app.pin))
        assert scenario(lambda: sessions(tenant_id=TENANT)) == expected


@pytest.mark.parametrize('dtype,bits', [(SmallInteger, 16), (Integer, 32), (BigInteger, 64)])
@pytest.mark.parametrize('public_slots', [False, True])
def test_integer_async_crud_failures_and_savepoint_recovery_match_native(dtype, bits, public_slots):
    import asyncio
    import os
    import psycopg
    from uuid import UUID, uuid4
    from sqlalchemy import insert, select, update
    from sqlalchemy.exc import DBAPIError
    from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
    from cryptalis.crypto import CryptoFailure
    from cryptalis.sqlalchemy import attach
    from test_migration import run, publish, keys, TENANT
    bound = 1 << (bits - 1)
    with application(rows=3, value_type=dtype(), queries=[], protected_values=(-bound, bound - 1, None)) as app:
        async def scenario(protected):
            runtime = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
            try:
                factory = await attach(app.mapping, runtime, lock=app.plan.lock_bytes, keys=keys,
                    deployment=(app.plan, app.pin)) if protected else lambda **kw: AsyncSession(runtime, **kw)
                options = {'tenant_id': TENANT} if protected else {}
                results = []
                async with factory(**options) as session:
                    assert (await session.scalars(select(app.Customer.name).order_by(app.Customer.id))).all() == [-bound, bound - 1, None]
                    created = app.Customer(id=uuid4(), tenant_id=TENANT, name=-17)
                    session.add(created)
                    await session.flush()
                    created.name = 23
                    await session.flush()
                    await session.refresh(created)
                    assert created.name == 23
                    await session.execute(insert(app.Customer).returning(app.Customer.name),
                        [{'id': uuid4(), 'tenant_id': TENANT, 'name': -29}])
                    await session.execute(update(app.Customer).where(app.Customer.tenant_id == TENANT),
                        [{'id': created.id, 'name': None}], execution_options={'synchronize_session': False})
                    await session.refresh(created)
                    assert created.name is None
                    await session.delete(created)
                    await session.flush()
                    await session.rollback()
                for route in ('flush', 'insert', 'update'):
                    async with factory(**options) as session:
                        transaction = await session.begin_nested()
                        driver = await session.run_sync(lambda sync: sync.connection().connection.driver_connection)
                        with pytest.raises(CryptoFailure if protected else DBAPIError) as failure:
                            if route == 'flush':
                                row = await session.get(app.Customer, UUID(int=100))
                                row.name = bound + 37
                                await session.flush()
                            elif route == 'insert':
                                await session.execute(insert(app.Customer),
                                    [{'id': uuid4(), 'tenant_id': TENANT, 'name': bound + 37}])
                            else:
                                await session.execute(update(app.Customer).where(app.Customer.tenant_id == TENANT),
                                    [{'id': UUID(int=100), 'name': bound + 37}], execution_options={'synchronize_session': False})
                        code = getattr(failure.value, 'sqlstate', None) if protected else failure.value.orig.sqlstate
                        assert code == '22003'
                        results.append((session.is_active, driver.info.transaction_status.name))
                        await transaction.rollback()
                        assert (await session.get(app.Customer, UUID(int=100))).name == -bound
                        await session.rollback()
                return results
            finally:
                await runtime.dispose()
        expected = asyncio.run(scenario(False))
        if public_slots:
            from test_public_slots import select_layout
            select_layout(app)
        run(app); publish(app)
        assert asyncio.run(scenario(True)) == expected


@pytest.mark.parametrize('custom', ['subclass', 'decorator', 'variant', 'instance_processor'])
def test_integer_custom_mapping_hooks_remain_unadmitted(custom):
    from sqlalchemy.types import TypeDecorator
    from cryptalis.manifest.compiler import PlanningRejected
    class CustomInteger(Integer): pass
    class DecoratedInteger(TypeDecorator):
        impl = Integer
        cache_ok = True
    dtype = (CustomInteger() if custom == 'subclass' else DecoratedInteger() if custom == 'decorator'
        else Integer().with_variant(Integer(), 'postgresql') if custom == 'variant' else Integer())
    if custom == 'instance_processor':
        dtype.bind_processor = lambda dialect: int
    with pytest.raises(PlanningRejected) as refused:
        with application(rows=0, value_type=dtype, queries=[]):
            pytest.fail('unqualified integer mapping reached planning')
    assert 'unsupported_type' in {issue.code for issue in refused.value.issues}


@pytest.mark.parametrize('default', [0, lambda: 1])
def test_integer_defaults_require_separate_admission(default):
    from cryptalis.manifest.compiler import PlanningRejected
    with pytest.raises(PlanningRejected) as refused:
        with application(rows=0, value_type=Integer(), queries=[], value_default=default):
            pytest.fail('unqualified integer default reached planning')
    assert 'protected_default' in {issue.code for issue in refused.value.issues}


@pytest.mark.parametrize('dtype,bits', [(SmallInteger, 16), (Integer, 32), (BigInteger, 64)])
def test_integer_lock_tampering_and_query_refusals_precede_key_resolution(dtype, bits):
    from sqlalchemy import cast, func, select
    from cryptalis import migration as m
    from cryptalis.manifest.compiler import _canonical
    from cryptalis.sqlalchemy import UnsupportedProtectedOperation, attach
    from test_migration import run, publish, keys, TENANT
    with application(value_type=dtype(), queries=[], protected_values=(0, 1, None)) as app:
        for fault in ('old_schema', 'reader', 'codec', 'width', 'sequences', 'layout'):
            document = app.plan.document
            lock, field = document['lock'], document['lock']['models'][0]['fields'][0]
            if fault == 'old_schema': lock['schema'] = 'cryptalis.lock/v6'
            elif fault == 'reader': lock['required_readers'].remove('pg-int' + str(bits // 8) + '-be/v1')
            elif fault == 'codec': field['descriptor']['value_codec'] = 'utf8-exact/v1'
            elif fault == 'width': field['source']['type'] = 'int8' if bits != 64 else 'int2'
            elif fault == 'sequences': lock['models'][0]['source_metadata'].pop('owned_sequences')
            else: lock['layout'] = 'unqualified-layout'
            with pytest.raises(m.TransitionFailure): m.MigrationPlan(_canonical(document))
        run(app); publish(app)
        prepared = []
        def resolve(tenant):
            prepared.append(tenant)
            return keys(tenant)
        sessions = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=resolve,
                          deployment=(app.plan, app.pin))
        count = len(prepared)
        for statement in (select(app.Customer).where(app.Customer.name == 1),
                select(app.Customer).where(app.Customer.name.in_([0, 1])),
                select(app.Customer).where(app.Customer.name > 0),
                select(app.Customer).order_by(app.Customer.name),
                select(func.sum(app.Customer.name)), select(cast(app.Customer.name, Integer))):
            with sessions(tenant_id=TENANT) as session:
                count = len(prepared)  # The factory validates the tenant policy before a statement exists.
                with pytest.raises(UnsupportedProtectedOperation): session.execute(statement)
                assert len(prepared) == count
        with sessions(tenant_id=TENANT) as session:
            assert {row.id: row.name for row in session.scalars(select(app.Customer))} == {key: value for key, (_, value) in app.source.items()}
        assert len(prepared) > count



@pytest.mark.parametrize('dtype,bits', [(SmallInteger, 16), (Integer, 32), (BigInteger, 64)])
@pytest.mark.parametrize('public_slots', [False, True])
def test_integer_root_rewrap_payload_restart_and_latest_native_exit(dtype, bits, public_slots):
    from uuid import UUID
    from sqlalchemy import Column, MetaData, Table, Text, Uuid, select
    from sqlalchemy.orm import registry
    from cryptalis import deprotection as d, migration as m, rotation as r
    from cryptalis.sqlalchemy import attach
    from rewrap_worker import target_keys as rewrapped_keys
    from payload_rotation_worker import rotated_keys
    from test_migration import frames, run, publish, keys, TENANT
    from test_deprotection import app_pin, consent, least_privilege_role
    from test_payload_rotation_execution import staged_frames
    lower, upper = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
    with application(value_type=dtype(), queries=[], protected_values=(lower, upper, 0, None)) as app:
        if public_slots:
            from test_public_slots import select_layout
            select_layout(app)
        run(app); publish(app)
        initial_plan, initial_pin = app.plan, app.pin
        before = frames(app, True)
        root = r.plan_rewrap(app.plan, app.owner, source_pin=app.pin,
            keys=keys, target_keys=rewrapped_keys, verify_rows_per_second=1000)
        assert r.apply_rewrap(root, app.owner, keys=keys, target_keys=rewrapped_keys,
            pin=app_pin(root.activation_plan, 'PREPARED'), approval=app.approval).phase == 'PENDING'
        assert m.apply(root.activation_plan, app.owner, keys=rewrapped_keys,
            pin=app_pin(root.activation_plan, 'ACTIVATING'), approval=app.approval, until='ACTIVE').phase == 'ACTIVE'
        assert frames(app, True) == before
        app.plan, app.pin = root.activation_plan, app_pin(root.activation_plan, 'ACTIVE')
        with pytest.raises(m.TransitionFailure): m.check_deployment(initial_plan, app.owner, pin=initial_pin)
        payload = r.plan_payload_rotation(app.plan, app.owner, source_pin=app.pin,
            keys=rewrapped_keys, target_keys=rotated_keys, backfill_rows_per_second=1000,
            verify_rows_per_second=1000, temporary_bytes_per_row=1024, wal_bytes_per_row=2048, max_batch_rows=3)
        operation_pin = m.DeploymentPin(app.plan.target_id, payload.operation_id, payload.digest, 'PREPARED')
        assert r.apply_payload_rotation(payload, app.owner, keys=rewrapped_keys, target_keys=rotated_keys,
            pin=operation_pin, approval=app.approval, max_chunks=1).committed_chunks == 1
        prefix = staged_frames(app, payload)
        assert r.apply_payload_rotation(type(payload)(payload.artifact), app.owner, keys=rewrapped_keys,
            target_keys=rotated_keys, pin=operation_pin, approval=app.approval).phase == 'BACKFILLED'
        complete = staged_frames(app, payload)
        assert all(complete[key] == value for key, value in prefix.items() if any(frame is not None for frame in value))
        activation = r.seal_payload_rotation(payload, app.owner, keys=rewrapped_keys, target_keys=rotated_keys,
            pin=operation_pin, approval=app.approval, copy_rows_per_second=1000, copy_wal_bytes_per_row=2048)
        assert r.switch_payload_rotation(payload, activation, app.owner, keys=rewrapped_keys, target_keys=rotated_keys,
            pin=app_pin(activation, 'PREPARED'), approval=app.approval).phase == 'PENDING'
        assert m.apply(activation, app.owner, keys=rotated_keys, pin=app_pin(activation, 'ACTIVATING'),
            approval=app.approval, until='ACTIVE').phase == 'ACTIVE'
        app.plan, app.pin = activation, app_pin(activation, 'ACTIVE')
        after = frames(app, True)
        assert all(after[key] != value if value is not None else after[key] is None
                   for key, value in before.items())
        mapping = registry(metadata=MetaData(schema=app.schema))
        table = Table('customer', mapping.metadata, Column('id', Uuid, primary_key=True, autoincrement=False),
            Column('tenant_id', Uuid, nullable=False), Column('name', dtype()), Column('label', Text))
        class Customer: pass
        mapping.map_imperatively(Customer, table)
        try:
            sessions = attach(mapping, app.runtime, lock=app.plan.lock_bytes, keys=rotated_keys,
                              deployment=(app.plan, app.pin))
            with sessions(tenant_id=TENANT) as session:
                assert {row.id: (row.tenant_id, row.name) for row in session.scalars(select(Customer))} == app.source
                session.get(Customer, UUID(int=101)).name = lower + 17
                session.commit()
            expected = dict(app.source)
            expected[UUID(int=101)] = TENANT, lower + 17
            reverse = d.plan(app.plan, app.owner, source_pin=app.pin, keys=rotated_keys,
                plaintext_runtime_role=least_privilege_role(app), backfill_rows_per_second=1000,
                verify_rows_per_second=1000, temporary_bytes_per_row=1024, wal_bytes_per_row=2048)
            pure, pin = consent(reverse)
            assert d.apply(reverse, app.owner, keys=rotated_keys, pin=pin, approval=app.approval,
                consent=pure).phase == 'PLAINTEXT_PENDING'
            assert d.apply(reverse, app.owner, keys=rotated_keys, pin=app_pin(reverse, 'PLAINTEXT_ACTIVATING'),
                approval=app.approval, consent=pure, until='PLAINTEXT_ACTIVE').phase == 'PLAINTEXT_ACTIVE'
            removal = d.RemovalApproval(reverse.target_id, reverse.operation_id, reverse.digest,
                'integer latest values after root and payload rotation', 'public fixture backup', True)
            assert d.remove(reverse, app.owner, pin=app_pin(reverse, 'REMOVING'), approval=app.approval,
                removal=removal, consent=pure).phase == 'REMOVED'
            with app.owner.connect() as connection:
                assert {row[0]: (row[1], row[2]) for row in connection.exec_driver_sql(
                    f'SELECT id,tenant_id,name FROM "{app.schema}".customer')} == expected
        finally:
            mapping.dispose()


@pytest.mark.parametrize('dtype,bits', [(SmallInteger, 16), (Integer, 32), (BigInteger, 64)])
@pytest.mark.parametrize('route', ['entity_insert', 'dictionary_insert'])
@pytest.mark.parametrize('overflow_first', [False, True])
def test_integer_insert_batch_preserves_native_constraint_error_order(dtype, bits, route, overflow_first):
    from uuid import UUID
    from sqlalchemy import insert
    from sqlalchemy.exc import DBAPIError
    from sqlalchemy.orm import Session
    from cryptalis.crypto import CryptoFailure
    from cryptalis.sqlalchemy import attach
    from test_migration import run, publish, keys, TENANT
    with application(value_type=dtype(), queries=[], protected_values=(0, 1, None)) as app:
        rows = [{'id': UUID(int=100), 'tenant_id': TENANT, 'name': 17},
                {'id': UUID(int=999), 'tenant_id': TENANT, 'name': (1 << (bits - 1)) + 37}]
        if overflow_first: rows.reverse()
        def scenario(factory):
            with factory() as session:
                driver = session.connection().connection.driver_connection
                with pytest.raises((CryptoFailure, DBAPIError)) as failure:
                    if route == 'entity_insert':
                        session.add_all(app.Customer(**row) for row in rows)
                        session.flush()
                    else:
                        session.execute(insert(app.Customer), rows)
                code = getattr(failure.value, 'sqlstate', None) if isinstance(failure.value, CryptoFailure) else failure.value.orig.sqlstate
                result = code, session.is_active, driver.info.transaction_status.name
                session.rollback()
                assert session.get(app.Customer, UUID(int=100)).name == 0
                assert session.get(app.Customer, UUID(int=999)) is None
                return result
        expected = scenario(lambda: Session(app.runtime))
        assert expected[0] == ('22003' if overflow_first else '23505')
        run(app); publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                         deployment=(app.plan, app.pin))
        assert scenario(lambda: factory(tenant_id=TENANT)) == expected


@pytest.mark.parametrize('native', ['width_mismatch', 'domain'])
def test_integer_native_width_and_domain_identity_must_match_mapping(native):
    from cryptalis.manifest.compiler import PlanningRejected
    def setup(connection, schema, role):
        native_type = 'pg_catalog.int8'
        if native == 'domain':
            native_type = f'"{schema}".signed_integer_domain'
            connection.exec_driver_sql(f'CREATE DOMAIN {native_type} AS pg_catalog.int4')
        connection.exec_driver_sql(f'ALTER TABLE "{schema}".customer ALTER COLUMN name TYPE {native_type}')
    with pytest.raises(PlanningRejected) as refused:
        with application(rows=0, setup=setup, value_type=Integer(), queries=[]):
            pytest.fail('unqualified native width or domain reached planning')
    assert 'unsupported_type' in {issue.code for issue in refused.value.issues}


@pytest.mark.parametrize('public_slots', [False, True])
def test_previous_installed_reader_refuses_integer_plan_before_sql(tmp_path, public_slots):
    import os
    import subprocess
    reader = os.environ.get('CRYPTALIS_PREVIOUS_READER_PYTHON')
    if not reader:
        pytest.skip('supply the retained installed pre-integer reader interpreter')
    with application(rows=0, value_type=BigInteger(), queries=[]) as app:
        if public_slots:
            from test_public_slots import select_layout
            select_layout(app)
        artifact = tmp_path / 'integer-plan.json'
        artifact.write_bytes(app.plan.artifact)
        child = subprocess.run([reader, '-B', '-I', '-c', '''
from pathlib import Path
import sys
from sqlalchemy.engine import Engine
def forbidden(*args, **kwargs):
    raise AssertionError('old reader must refuse before SQL')
Engine.connect = forbidden
from cryptalis import migration as m
try:
    m.MigrationPlan(Path(sys.argv[1]).read_bytes())
except m.TransitionFailure:
    print('old installed reader refused v7 before SQL')
else:
    raise AssertionError('old reader admitted new integer plan')
''', str(artifact)], capture_output=True, text=True, timeout=20)
        assert child.returncode == 0, 'retained-reader refusal failed; diagnostics withheld'
        assert child.stdout.strip() == 'old installed reader refused v7 before SQL'
