"""Real PostgreSQL decrypt-back and removal evidence for cryptalis.reverse/v1."""
from dataclasses import replace
import hashlib
import importlib
from uuid import UUID

import pytest
from sqlalchemy import Column, MetaData, Table, Text, Uuid, select
from sqlalchemy.orm import registry, sessionmaker

from cryptalis.crypto import Keyring
from cryptalis.sqlalchemy import UnsupportedProtectedOperation, attach
from test_migration import (application, engine, frames, keys, publish, run,
                            PublicFixtureProvider, PROVIDER, FIELD_ID, TENANT)

d = importlib.import_module('cryptalis.deprotection')


class WrongProvider(PublicFixtureProvider):
    def unwrap(self, wrapper, context):
        return hashlib.sha256(('WRONG ROOT:' + str(context)).encode()).digest()


def bad_keys(tenant):
    good = keys(tenant)
    return Keyring(good.policy, {PROVIDER: WrongProvider()})


def least_privilege_role(app):
    with app.owner.connect() as c:
        rows = c.exec_driver_sql(
            "SELECT rolname, pg_catalog.pg_has_role(rolname, current_user, 'MEMBER') "
            "FROM pg_catalog.pg_roles WHERE NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb "
            "AND NOT rolbypassrls AND NOT rolreplication ORDER BY rolname").all()
    for name, member in rows:
        if not member and name != app.role:
            return name
    pytest.skip('no distinct non-inherited least-privilege role is available')


def proposal(app):
    return d.plan(app.plan, app.owner, source_pin=app.pin, keys=keys,
                  plaintext_runtime_role=least_privilege_role(app),
                  backfill_rows_per_second=1000, verify_rows_per_second=1000,
                  temporary_bytes_per_row=700, wal_bytes_per_row=700)


def consent(plan, phase='PREPARED'):
    return d.PlaintextApproval(plan.target_id, plan.operation_id, plan.digest, True,
                               'synthetic public backup recovery evidence'), \
        app_pin(plan, phase)


def app_pin(plan, phase):
    import cryptalis.migration as migration
    return migration.DeploymentPin(plan.target_id, plan.operation_id, plan.digest, phase)


def reverse(app, plan, until='PLAINTEXT_PENDING', phase='PREPARED', chunk_size=2, key_resolver=None):
    pure, pin = consent(plan, phase)
    return d.apply(plan, app.owner, keys=key_resolver or keys, pin=pin, approval=app.approval,
                   consent=pure, chunk_size=chunk_size, until=until)


def data_type(app, column):
    with app.owner.connect() as c:
        return c.exec_driver_sql(
            'SELECT data_type FROM information_schema.columns WHERE table_schema=%s AND table_name=%s AND column_name=%s',
            (app.schema, 'customer', column)).scalar_one_or_none()


def native_rows(app):
    fresh = engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
    mapping = registry(metadata=MetaData(schema=app.schema))
    table = Table('customer', mapping.metadata, Column('id', Uuid, primary_key=True, autoincrement=False),
                  Column('tenant_id', Uuid, nullable=False), Column('name', Text(collation='C')),
                  Column('label', Text))
    class Customer: pass
    mapping.map_imperatively(Customer, table)
    try:
        with sessionmaker(fresh)() as session:
            return {row.id: (row.tenant_id, row.name) for row in session.scalars(select(Customer))}
    finally:
        fresh.dispose()
        mapping.dispose()


def attached_edits(app):
    sessions = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                      deployment=(app.plan, app.pin))
    with sessions(tenant_id=TENANT) as session:
        row = session.get(app.Customer, UUID(int=101))
        row.name = 'edited while protected'
        session.commit()
        session.add(app.Customer(id=UUID(int=999), tenant_id=TENANT,
                                 name='added while protected', label='fresh'))
        session.commit()
        session.delete(session.get(app.Customer, UUID(int=106)))
        session.commit()
    with sessions(tenant_id=TENANT) as session:
        return {row.id: (row.tenant_id, row.name) for row in session.scalars(select(app.Customer))}


def test_full_decrypt_back_preserves_edited_values_and_removes_cryptalis():
    with application() as app:
        run(app)
        publish(app)
        expected = attached_edits(app)
        plan = proposal(app)
        assert reverse(app, plan).phase == 'PLAINTEXT_PENDING'
        assert data_type(app, 'name') == 'text'
        assert native_rows(app) == expected
        active, pin = consent(plan, 'PLAINTEXT_ACTIVATING')
        assert d.apply(plan, app.owner, keys=keys, pin=pin, approval=app.approval,
                       consent=active, until='PLAINTEXT_ACTIVE').phase == 'PLAINTEXT_ACTIVE'
        repeated = d.apply(plan, app.owner, keys=keys, pin=replace(pin, phase='PLAINTEXT_ACTIVE'),
                           approval=app.approval, consent=active, until='PLAINTEXT_ACTIVE')
        assert repeated.phase == 'PLAINTEXT_ACTIVE'
        assert native_rows(app) == expected
        with pytest.raises(UnsupportedProtectedOperation):
            attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                   deployment=(app.plan, app.pin))
        removal = d.RemovalApproval(plan.target_id, plan.operation_id, plan.digest,
                                    'synthetic package-free workload run', 'synthetic backup recovery', True)
        assert d.remove(plan, app.owner, pin=replace(pin, phase='REMOVING'), approval=app.approval,
                        removal=removal, consent=active).phase == 'REMOVED'
        assert d.check_removed(plan, app.owner, pin=replace(pin, phase='REMOVED')) is None
        assert native_rows(app) == expected
        with app.owner.connect() as c:
            assert c.exec_driver_sql('SELECT count(*) FROM information_schema.columns WHERE table_schema=%s '
                                     "AND pg_catalog.strpos(column_name,'_cryptalis')=1",
                                     (app.schema,)).scalar_one() == 0


def test_reverse_resume_after_lost_replies_is_idempotent():
    with application() as app:
        run(app)
        publish(app)
        before = frames(app, True)
        plan = proposal(app)
        assert reverse(app, plan, until='EXPANDED', chunk_size=1).phase == 'EXPANDED'
        assert reverse(app, plan, until='EXPANDED', chunk_size=1).phase == 'EXPANDED'
        assert frames(app, True) == before
        assert reverse(app, plan, until='BACKFILLED', chunk_size=1).phase == 'BACKFILLED'
        assert reverse(app, plan, until='BACKFILLED', chunk_size=1).phase == 'BACKFILLED'
        assert reverse(app, plan, until='VERIFIED').phase == 'VERIFIED'
        assert reverse(app, plan).phase == 'PLAINTEXT_PENDING'
        assert reverse(app, plan).phase == 'PLAINTEXT_PENDING'
        assert native_rows(app) == app.source


def test_interrupted_guard_or_corrupt_frame_never_switches():
    with application() as app:
        run(app)
        publish(app)
        plan = proposal(app)
        reverse(app, plan, until='BACKFILLED')
        with app.owner.begin() as c:
            c.exec_driver_sql(f'UPDATE "{app.schema}".customer SET name=set_byte(name,'
                              'octet_length(name)-1,get_byte(name,octet_length(name)-1) # 1) '
                              'WHERE id=%s', (UUID(int=103),))
        with pytest.raises(app.m.TransitionFailure):
            reverse(app, plan, until='PLAINTEXT_PENDING')
        assert data_type(app, 'name') == 'bytea'
        with app.owner.begin() as c:
            c.exec_driver_sql(f'ALTER TABLE "{app.schema}".customer DISABLE TRIGGER ALL')
        with pytest.raises(app.m.TransitionFailure, match='writer_fence_changed'):
            reverse(app, plan, until='VERIFIED')


def test_wrong_custody_never_commits_plaintext_staging():
    with application() as app:
        run(app)
        publish(app)
        plan = proposal(app)
        with pytest.raises(app.m.TransitionFailure):
            reverse(app, plan, until='BACKFILLED', chunk_size=100, key_resolver=bad_keys)
        with app.owner.connect() as c:
            staged = '_cryptalis_' + FIELD_ID.hex + '_plain'
            assert c.exec_driver_sql(f'SELECT count(*) FROM "{app.schema}".customer '
                                     f'WHERE "{staged}" IS NOT NULL').scalar_one() == 0
        assert reverse(app, plan, until='BACKFILLED', chunk_size=100).phase == 'BACKFILLED'


def test_abort_removes_additive_objects_and_keeps_protection_current():
    with application() as app:
        run(app)
        publish(app)
        plan = proposal(app)
        reverse(app, plan, until='EXPANDED')
        assert d.abort(plan, app.owner, pin=app_pin(plan, 'EXPANDED'), approval=app.approval,
                       consent=consent(plan)[0]).phase == 'ABORTED'
        assert app.m.check_deployment(app.plan, app.owner, pin=app.pin) is None
        assert data_type(app, 'name') == 'bytea'
        with pytest.raises(app.m.TransitionFailure, match='operation_aborted'):
            reverse(app, plan, until='PLAINTEXT_PENDING')
        second = proposal(app)
        assert second.document['retirable_aborted'] == [
            {'operation_id': str(plan.operation_id), 'plan_digest': plan.digest}]
        reverse(app, second, until='PLAINTEXT_PENDING')
        active = consent(second, 'PLAINTEXT_ACTIVATING')[0]
        d.apply(second, app.owner, keys=keys, pin=app_pin(second, 'PLAINTEXT_ACTIVATING'),
                approval=app.approval, consent=active, until='PLAINTEXT_ACTIVE')
        removal = d.RemovalApproval(second.target_id, second.operation_id, second.digest,
                                    'synthetic package-free run', 'synthetic backup recovery', True)
        d.remove(second, app.owner, pin=app_pin(second, 'REMOVING'), approval=app.approval,
                 removal=removal, consent=active)
        d.check_removed(second, app.owner, pin=app_pin(second, 'REMOVED'))
        assert native_rows(app) == app.source


def test_metadata_is_restored_except_recorded_limits():
    with application() as app:
        run(app)
        publish(app)
        plan = proposal(app)
        reverse(app, plan, until='PLAINTEXT_PENDING')
        active = consent(plan, 'PLAINTEXT_ACTIVATING')[0]
        d.apply(plan, app.owner, keys=keys, pin=app_pin(plan, 'PLAINTEXT_ACTIVATING'),
                approval=app.approval, consent=active, until='PLAINTEXT_ACTIVE')
        removal = d.RemovalApproval(plan.target_id, plan.operation_id, plan.digest,
                                    'synthetic package-free run', 'synthetic backup recovery', True)
        d.remove(plan, app.owner, pin=app_pin(plan, 'REMOVING'), approval=app.approval,
                 removal=removal, consent=active)
        for model in app.plan.document['lock']['models']:
            with app.owner.connect() as c:
                current = app.m._facts(c, model)
            assert d._metadata_diff(model['source_schema'], current) == []
        with app.owner.connect() as c:
            assert c.exec_driver_sql(
                'SELECT co.collname FROM pg_catalog.pg_attribute a '
                'JOIN pg_catalog.pg_collation co ON co.oid=a.attcollation '
                'JOIN pg_catalog.pg_class t ON t.oid=a.attrelid '
                'JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace '
                'WHERE n.nspname=%s AND t.relname=%s AND a.attname=%s',
                (app.schema, 'customer', 'name')).scalar_one() == 'C'


def catalog_metadata(app):
    with app.owner.connect() as c:
        table = c.exec_driver_sql(
            'SELECT pg_catalog.obj_description(t.oid) FROM pg_catalog.pg_class t '
            'JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace '
            "WHERE n.nspname=%s AND t.relname='customer'", (app.schema,)).scalar_one()
        columns = {row[0]: row[1:] for row in c.exec_driver_sql(
            'SELECT a.attname, pg_catalog.col_description(t.oid, a.attnum), a.attstattarget, '
            'a.attstorage, a.attacl::text, a.attcompression, a.attoptions::text '
            'FROM pg_catalog.pg_attribute a '
            'JOIN pg_catalog.pg_class t ON t.oid=a.attrelid '
            'JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace '
            "WHERE n.nspname=%s AND t.relname='customer' AND a.attnum>0 AND NOT a.attisdropped "
            'ORDER BY a.attname', (app.schema,)).all()}
        index = c.exec_driver_sql(
            'SELECT i.reloptions::text, pg_catalog.obj_description(i.oid) FROM pg_catalog.pg_class i '
            'JOIN pg_catalog.pg_namespace n ON n.oid=i.relnamespace '
            "WHERE n.nspname=%s AND i.relname='native_name'", (app.schema,)).one()
        constraint = c.exec_driver_sql(
            'SELECT pg_catalog.obj_description(o.oid, %s) FROM pg_catalog.pg_constraint o '
            'JOIN pg_catalog.pg_class t ON t.oid=o.conrelid '
            'JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace '
            "WHERE n.nspname=%s AND t.relname='customer' AND o.conname='customer_pkey'",
            ('pg_constraint', app.schema)).scalar_one()
        statistics = c.exec_driver_sql(
            'SELECT s.stxkind::text[], s.stxstattarget, pg_catalog.obj_description(s.oid, %s), '
            '(SELECT pg_catalog.array_agg(a.attname ORDER BY a.attnum) '
            ' FROM pg_catalog.unnest(s.stxkeys::int2[]) AS k(attnum) '
            ' JOIN pg_catalog.pg_attribute a ON a.attrelid=s.stxrelid AND a.attnum=k.attnum) '
            'FROM pg_catalog.pg_statistic_ext s '
            'JOIN pg_catalog.pg_class t ON t.oid=s.stxrelid '
            'JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace '
            "WHERE n.nspname=%s AND t.relname='customer' AND s.stxname=%s",
            ('pg_statistic_ext', app.schema, 'name_stats')).one_or_none()
    return table, columns, index, constraint, statistics


def test_reverse_refuses_metadata_added_while_protected():
    import cryptalis.migration as migration
    with application() as app:
        run(app)
        publish(app)
        with app.owner.begin() as c:
            c.exec_driver_sql(f'COMMENT ON COLUMN "{app.schema}".customer.name IS \'late comment\'')
            c.exec_driver_sql(f'ALTER TABLE "{app.schema}".customer ALTER COLUMN name SET STATISTICS 100')
            c.exec_driver_sql(f'GRANT SELECT (name) ON "{app.schema}".customer TO PUBLIC')
        with pytest.raises(migration.TransitionFailure) as caught:
            proposal(app)
        assert caught.value.code == 'unsupported_protected_metadata'


def test_reverse_refuses_extended_statistics_on_protected_column():
    import cryptalis.migration as migration
    with application() as app:
        run(app)
        publish(app)
        with app.owner.begin() as c:
            c.exec_driver_sql(f'CREATE STATISTICS "{app.schema}".late_stats '
                              f'(ndistinct) ON name, label FROM "{app.schema}".customer')
        with pytest.raises(migration.TransitionFailure) as caught:
            proposal(app)
        assert caught.value.code == 'unsupported_dependency'


def test_reverse_refuses_sequence_owned_by_protected_column():
    import cryptalis.migration as migration
    with application() as app:
        run(app)
        publish(app)
        with app.owner.begin() as c:
            c.exec_driver_sql(f'CREATE SEQUENCE "{app.schema}".late_seq')
            c.exec_driver_sql(f'ALTER SEQUENCE "{app.schema}".late_seq '
                              f'OWNED BY "{app.schema}".customer.name')
        with pytest.raises(migration.TransitionFailure) as caught:
            proposal(app)
        assert caught.value.code == 'unsupported_dependency'


def test_source_metadata_is_preserved_through_decrypt_back():
    """Captured protected metadata plus surviving metadata restores exactly."""

    def setup(c, schema, role):
        c.exec_driver_sql(f'COMMENT ON TABLE "{schema}".customer IS \'table comment\'')
        c.exec_driver_sql(f'COMMENT ON COLUMN "{schema}".customer.label IS \'plain column comment\'')
        c.exec_driver_sql(f'COMMENT ON COLUMN "{schema}".customer.name IS \'protected column comment\'')
        c.exec_driver_sql(f'ALTER TABLE "{schema}".customer ALTER COLUMN name SET STATISTICS 500')
        c.exec_driver_sql(f'ALTER TABLE "{schema}".customer ALTER COLUMN name SET STORAGE EXTERNAL')
        c.exec_driver_sql(f'ALTER TABLE "{schema}".customer ALTER COLUMN name SET COMPRESSION pglz')
        c.exec_driver_sql(f'ALTER TABLE "{schema}".customer ALTER COLUMN name SET (n_distinct=10)')
        c.exec_driver_sql(f"""COMMENT ON CONSTRAINT customer_pkey ON "{schema}".customer IS 'primary key comment'""")
        c.exec_driver_sql(f"""COMMENT ON INDEX "{schema}".native_name IS 'index comment'""")
        c.exec_driver_sql(f'ALTER INDEX "{schema}".native_name SET (fillfactor=70)')
        c.exec_driver_sql(f'GRANT SELECT (label) ON "{schema}".customer TO "{role}"')
        c.exec_driver_sql(f'CREATE STATISTICS "{schema}".name_stats (ndistinct, dependencies) '
                          f'ON name, label FROM "{schema}".customer')
        c.exec_driver_sql(f'ALTER STATISTICS "{schema}".name_stats SET STATISTICS 700')
        c.exec_driver_sql(f"""COMMENT ON STATISTICS "{schema}".name_stats IS 'protected statistics comment'""")
        c.exec_driver_sql(f'CREATE STATISTICS "{schema}".label_stats (ndistinct) '
                          f'ON label, tenant_id FROM "{schema}".customer')
        c.exec_driver_sql(f'CREATE SEQUENCE "{schema}".label_seq')
        c.exec_driver_sql(f'ALTER SEQUENCE "{schema}".label_seq OWNED BY "{schema}".customer.label')
        c.exec_driver_sql(f'ALTER TABLE "{schema}".customer SET (autovacuum_enabled=false)')

    with application(setup=setup) as app:
        before_table, before_columns, before_index, before_constraint, before_stats = catalog_metadata(app)
        assert before_table == 'table comment'
        assert before_columns['label'][0] == 'plain column comment'
        assert before_columns['label'][3] is not None
        assert before_columns['name'][0] == 'protected column comment'
        assert before_columns['name'][1] == 500
        assert before_columns['name'][2] == 'e'
        assert before_columns['name'][3] is None
        assert before_columns['name'][4] == 'p'
        assert before_columns['name'][5] == '{n_distinct=10}'
        assert 'fillfactor=70' in before_index[0]
        assert before_index[1] == 'index comment'
        assert before_constraint == 'primary key comment'
        assert before_stats == (['d', 'f'], 700, 'protected statistics comment', ['name', 'label'])
        with app.owner.connect() as c:
            before_options = c.exec_driver_sql(
                'SELECT reloptions::text FROM pg_catalog.pg_class '
                'WHERE oid=pg_catalog.to_regclass(%s)',
                (f'{app.schema}.customer',)).scalar_one()
        with app.owner.connect() as c:
            assert c.exec_driver_sql(
                'SELECT count(*) FROM pg_catalog.pg_statistic_ext '
                'WHERE stxrelid=pg_catalog.to_regclass(%s)',
                (f'{app.schema}.customer',)).scalar_one() == 2
        run(app)
        publish(app)
        plan = proposal(app)
        reverse(app, plan, until='PLAINTEXT_PENDING')
        active = consent(plan, 'PLAINTEXT_ACTIVATING')[0]
        d.apply(plan, app.owner, keys=keys, pin=app_pin(plan, 'PLAINTEXT_ACTIVATING'),
                approval=app.approval, consent=active, until='PLAINTEXT_ACTIVE')
        removal = d.RemovalApproval(plan.target_id, plan.operation_id, plan.digest,
                                    'synthetic package-free run', 'synthetic backup recovery', True)
        d.remove(plan, app.owner, pin=app_pin(plan, 'REMOVING'), approval=app.approval,
                 removal=removal, consent=active)
        after_table, after_columns, after_index, after_constraint, after_stats = catalog_metadata(app)
        assert after_table == 'table comment'
        assert after_columns['label'] == before_columns['label']
        assert after_columns['name'] == before_columns['name']
        assert after_columns['name'][0] == 'protected column comment'
        assert after_columns['name'][1] == 500
        assert after_columns['name'][2] == 'e'
        assert after_columns['name'][4] == 'p'
        assert after_columns['name'][5] == '{n_distinct=10}'
        assert 'fillfactor=70' in after_index[0]
        assert after_index[1] == 'index comment'
        assert after_constraint == 'primary key comment'
        assert after_stats[:3] == before_stats[:3]
        assert sorted(after_stats[3]) == ['label', 'name']
        with app.owner.connect() as c:
            assert c.exec_driver_sql(
                'SELECT reloptions::text FROM pg_catalog.pg_class '
                'WHERE oid=pg_catalog.to_regclass(%s)',
                (f'{app.schema}.customer',)).scalar_one() == before_options
            assert c.exec_driver_sql(
                'SELECT pg_catalog.to_regclass(%s)',
                (f'{app.schema}.label_seq',)).scalar_one() is not None
        for model in app.plan.document['lock']['models']:
            with app.owner.connect() as c:
                current = app.m._facts(c, model)
            assert d._metadata_diff(model['source_schema'], current) == []


def test_plan_and_removal_refuse_unsafe_inputs():
    with application() as app:
        run(app)
        publish(app)
        with pytest.raises(app.m.TransitionFailure, match='source_pin_must_be_active'):
            d.plan(app.plan, app.owner, source_pin=app_pin(app.plan, 'PENDING'), keys=keys,
                   plaintext_runtime_role=least_privilege_role(app),
                   backfill_rows_per_second=1000, verify_rows_per_second=1000,
                   temporary_bytes_per_row=700, wal_bytes_per_row=700)
        with pytest.raises(app.m.TransitionFailure, match='distinct_plaintext_runtime_role_required'):
            d.plan(app.plan, app.owner, source_pin=app.pin, keys=keys,
                   plaintext_runtime_role=app.role,
                   backfill_rows_per_second=1000, verify_rows_per_second=1000,
                   temporary_bytes_per_row=700, wal_bytes_per_row=700)
        with pytest.raises(app.m.TransitionFailure, match='invalid_reverse_plan'):
            d.DeprotectionPlan(b'{not json')
        plan = proposal(app)
        with pytest.raises(app.m.TransitionFailure, match='invalid_reverse_plan'):
            d.DeprotectionPlan(plan.artifact[:-2])
        with pytest.raises(app.m.TransitionFailure, match='restored_or_missing_reverse_transition'):
            d.remove(plan, app.owner, pin=app_pin(plan, 'REMOVING'), approval=app.approval,
                     removal=d.RemovalApproval(plan.target_id, plan.operation_id, plan.digest,
                                               'synthetic run', 'synthetic recovery', True),
                     consent=consent(plan)[0])
        reverse(app, plan, until='PLAINTEXT_PENDING')
        active = consent(plan, 'PLAINTEXT_ACTIVATING')[0]
        with pytest.raises(app.m.TransitionFailure, match='removal_approval_required'):
            d.remove(plan, app.owner, pin=app_pin(plan, 'REMOVING'), approval=app.approval,
                     removal=d.RemovalApproval(plan.target_id, plan.operation_id, 'f' * 64,
                                               'synthetic run', 'synthetic recovery', True),
                     consent=active)
        with pytest.raises(app.m.TransitionFailure, match='matching_external_publication_required'):
            d.check_removed(plan, app.owner, pin=app_pin(plan, 'PLAINTEXT_ACTIVE'))
        with pytest.raises(app.m.TransitionFailure, match='removal_approval_required'):
            d.remove(plan, app.owner, pin=app_pin(plan, 'REMOVING'), approval=app.approval,
                     removal=d.RemovalApproval(plan.target_id, plan.operation_id, plan.digest,
                                               'synthetic run', 'synthetic recovery', False),
                     consent=active)
        with pytest.raises(app.m.TransitionFailure, match='restored_state_behind_external_pin'):
            d.remove(plan, app.owner, pin=app_pin(plan, 'PLAINTEXT_ACTIVE'), approval=app.approval,
                     removal=d.RemovalApproval(plan.target_id, plan.operation_id, plan.digest,
                                               'synthetic run', 'synthetic recovery', True),
                     consent=active)
