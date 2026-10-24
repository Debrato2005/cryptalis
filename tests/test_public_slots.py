"""Explicit public-column layout admission and current-value native exit."""
from uuid import uuid4

import pytest
from sqlalchemy import Boolean, String, select

from cryptalis import migration as m
from cryptalis.manifest.compiler import SearchReview, Writer, WriterInventory
from test_migration import application, frames, keys, publish, run, FIELD_ID, TABLE_ID, TENANT
from cryptalis.sqlalchemy import attach
import test_deprotection as reverse
from test_owned_sequences import facts, finish_reverse, install_sequence, _snapshot


LAYOUT = 'preserve-public-slots/v1'


def slots(app):
    table = f'"{app.schema}".customer'
    with app.owner.connect() as connection:
        oid = connection.exec_driver_sql('SELECT pg_catalog.to_regclass(%s)::oid::text', (table,)).scalar_one()
        columns = connection.exec_driver_sql('SELECT attname,attnum FROM pg_catalog.pg_attribute '
            'WHERE attrelid=pg_catalog.to_regclass(%s) AND attnum>0 AND NOT attisdropped ORDER BY attnum',
            (table,)).all()
        order = tuple(connection.exec_driver_sql(f'SELECT * FROM {table} LIMIT 0').keys())
    return oid, tuple(columns), order


def original_gap(connection, schema, role, *, sequence, kind='text'):
    table = f'"{schema}".customer'
    quoted = connection.dialect.identifier_preparer.quote(role)
    connection.exec_driver_sql(f'DROP TABLE {table}')
    native_type = {'text': 'text COLLATE pg_catalog."C"',
                   'varchar': 'varchar(64) COLLATE pg_catalog."C"', 'boolean': 'boolean'}[kind]
    connection.exec_driver_sql(f'CREATE TABLE {table} (id uuid PRIMARY KEY,tenant_id uuid NOT NULL,'
        f'original_gap text,name {native_type},label text)')
    connection.exec_driver_sql(f'ALTER TABLE {table} DROP COLUMN original_gap')
    if kind != 'boolean':
        connection.exec_driver_sql(f'CREATE UNIQUE INDEX native_name ON {table} (tenant_id,name)')
    connection.exec_driver_sql(f'GRANT SELECT,INSERT,UPDATE,DELETE ON {table} TO {quoted}')
    connection.exec_driver_sql(f'GRANT SELECT(name) ON {table} TO {quoted} WITH GRANT OPTION')
    connection.exec_driver_sql(f'ALTER TABLE {table} ALTER COLUMN name SET STATISTICS 500')
    if kind != 'boolean':
        connection.exec_driver_sql(f'ALTER TABLE {table} ALTER COLUMN name SET STORAGE EXTERNAL')
        connection.exec_driver_sql(f'ALTER TABLE {table} ALTER COLUMN name SET COMPRESSION pglz')
    connection.exec_driver_sql(f'ALTER TABLE {table} ALTER COLUMN name SET (n_distinct=10)')
    connection.exec_driver_sql(f"COMMENT ON COLUMN {table}.name IS 'public original-slot fixture'")
    if sequence:
        install_sequence(connection, schema, role)


def select_layout(app):
    declaration = app.plan.document['lock']['declaration']
    searchable = bool(app.plan.document['lock']['models'][0]['fields'][0]['queries'])
    proposal = m.plan(m._canonical(declaration), app.mapping, app.owner, layout=LAYOUT,
        writers=WriterInventory(True, (Writer(TABLE_ID, 'app', 'sqlalchemy', evidence='owned synthetic application'),)),
        search_reviews=(SearchReview(FIELD_ID, False, 'synthetic unbounded names'),) if searchable else (),
        keys=keys, runtime_role=app.role, target_id=uuid4(),
        backfill_rows_per_second=1000, verify_rows_per_second=1000,
        temporary_bytes_per_row=700, wal_bytes_per_row=2000)
    app.plan = proposal
    app.pin = m.DeploymentPin(proposal.target_id, proposal.operation_id, proposal.digest, 'PREPARED')


def test_default_layout_keeps_legacy_column_replacement_behavior():
    with application() as app:
        original = slots(app)
        assert app.plan.document['lock']['schema'] == 'cryptalis.lock/v2'
        run(app)
        assert slots(app)[0] == original[0]
        assert slots(app)[1:] != original[1:]


@pytest.mark.parametrize('sequence', [False, True])
@pytest.mark.parametrize('kind', ['text', 'varchar', 'boolean'])
def test_original_slots_opt_in_preserves_latest_values_through_removal(sequence, kind):
    def setup(connection, schema, role):
        original_gap(connection, schema, role, sequence=sequence, kind=kind)
    options = {'value_type': String(64, collation='C')} if kind == 'varchar' else (
        {'value_type': Boolean(), 'queries': [], 'protected_values': (None, True, False), 'rows': 3}
        if kind == 'boolean' else {})
    with application(setup=setup, **options) as app:
        original = slots(app)
        assert original[1] == (('id', 1), ('tenant_id', 2), ('name', 4), ('label', 5))
        original_sequence = facts(app) if sequence else None
        select_layout(app)
        assert app.plan.document['lock']['schema'] == 'cryptalis.lock/v6'
        assert app.plan.document['lock']['layout'] == LAYOUT
        assert run(app, until='VERIFIED').phase == 'VERIFIED'
        staged = frames(app)
        assert run(app).phase == 'PENDING'
        assert frames(app, switched=True) == staged
        assert slots(app) == original
        publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                         deployment=(app.plan, app.pin))
        with factory(tenant_id=TENANT) as session:
            rows = session.scalars(select(app.Customer).order_by(app.Customer.id)).all()
            rows[1].name = False if kind == 'boolean' else 'latest original-slot edit 雪😀'
            session.commit()
            expected = {row.id: (row.tenant_id, row.name) for row in session.scalars(select(app.Customer))}
        assert slots(app) == original
        proposal = reverse.proposal(app)
        assert reverse.reverse(app, proposal).phase == 'PLAINTEXT_PENDING'
        finish_reverse(app, proposal)
        assert slots(app) == original and reverse.native_rows(app) == expected
        if sequence:
            assert facts(app) == original_sequence


@pytest.mark.parametrize('phase', ['planned', 'active'])
def test_late_expression_statistics_refuse_without_effects_and_allow_exact_repair(phase):
    def setup(connection, schema, role):
        original_gap(connection, schema, role, sequence=False)
    with application(setup=setup) as app:
        select_layout(app)
        if phase == 'active':
            run(app)
            publish(app)
        name = f'"{app.schema}".late_expression_statistics'
        with app.owner.begin() as connection:
            connection.exec_driver_sql(f'CREATE STATISTICS {name} '
                f'ON (pg_catalog.octet_length(name)) FROM "{app.schema}".customer')
        before, calls = _snapshot(app), []
        def forbidden(tenant):
            calls.append(tenant)
            pytest.fail('unadmitted expression statistics reached reverse providers')
        with pytest.raises(m.TransitionFailure):
            if phase == 'planned':
                run(app)
            else:
                import cryptalis.deprotection as deprotection
                deprotection.plan(app.plan, app.owner, source_pin=app.pin, keys=forbidden,
                    plaintext_runtime_role=reverse.least_privilege_role(app),
                    backfill_rows_per_second=1000, verify_rows_per_second=1000,
                    temporary_bytes_per_row=700, wal_bytes_per_row=700)
        assert _snapshot(app) == before and calls == []
        with app.owner.begin() as connection:
            assert connection.exec_driver_sql('SELECT count(*) FROM pg_catalog.pg_statistic_ext s '
                'JOIN pg_catalog.pg_namespace n ON n.oid=s.stxnamespace '
                "WHERE n.nspname=%s AND s.stxname='late_expression_statistics'", (app.schema,)).scalar_one() == 1
            connection.exec_driver_sql(f'DROP STATISTICS {name}')
        if phase == 'planned':
            run(app)
            publish(app)
        proposal = reverse.proposal(app)
        assert reverse.reverse(app, proposal).phase == 'PLAINTEXT_PENDING'
        finish_reverse(app, proposal)
