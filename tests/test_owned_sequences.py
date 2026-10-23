"""Native ownership DDL and public protect/decrypt-back sequence continuity."""
from dataclasses import replace
import os

import psycopg
from sqlalchemy import create_engine, event
from sqlalchemy.exc import DBAPIError

from cryptalis import migration as m
from migration_commit_proxy import lost_commit_reply

import pytest

from cryptalis import deprotection as d
from test_migration import application, run, publish, keys
import test_deprotection as reverse


def _snapshot(app):
    with app.owner.connect() as connection:
        journal = f'"{app.schema}"."{m.JOURNAL}"'
        exists = connection.exec_driver_sql('SELECT pg_catalog.to_regclass(%s)', (journal,)).scalar_one()
        state = None if exists is None else connection.exec_driver_sql(
            f'SELECT operation_id,plan_digest,state FROM {journal} ORDER BY operation_id').all()
        rows = connection.exec_driver_sql(
            f'SELECT id,tenant_id,name,label FROM "{app.schema}".customer ORDER BY id').all()
        schema = m._facts(connection, app.plan.document['lock']['models'][0])
    return state, rows, schema


def install_sequence(connection, schema, role, table='customer', column='name', *, cache=1, name='preserved_seq'):
    sequence = f'"{schema}".' + connection.dialect.identifier_preparer.quote(name)
    connection.exec_driver_sql(f'CREATE SEQUENCE {sequence} AS bigint INCREMENT BY 7 MINVALUE 11 '
                              f'MAXVALUE 999999 START WITH 101 CACHE {cache} NO CYCLE')
    connection.exec_driver_sql(f'ALTER SEQUENCE {sequence} OWNED BY "{schema}"."{table}"."{column}"')
    connection.exec_driver_sql(f"COMMENT ON SEQUENCE {sequence} IS 'public owned sequence fixture'")
    quoted = connection.dialect.identifier_preparer.quote(role)
    connection.exec_driver_sql(f'GRANT USAGE,SELECT ON SEQUENCE {sequence} TO {quoted} WITH GRANT OPTION')


def sequence_facts(connection, schema, name='preserved_seq'):
    """Independent native identity, configuration, ACL and ownership oracle."""
    return tuple(connection.exec_driver_sql(
        'SELECT s.oid::text,n.nspname,s.relname,pg_catalog.pg_get_userbyid(s.relowner),'
        's.relpersistence,q.seqtypid::pg_catalog.regtype::text,q.seqstart::text,q.seqincrement::text,'
        'q.seqmin::text,q.seqmax::text,q.seqcache::text,q.seqcycle,s.relacl::text,'
        "pg_catalog.obj_description(s.oid,'pg_class'),d.deptype,tn.nspname,t.relname,a.attname "
        'FROM pg_catalog.pg_class s JOIN pg_catalog.pg_namespace n ON n.oid=s.relnamespace '
        'JOIN pg_catalog.pg_sequence q ON q.seqrelid=s.oid '
        "LEFT JOIN pg_catalog.pg_depend d ON d.classid='pg_catalog.pg_class'::regclass AND d.objid=s.oid "
        "AND d.refclassid='pg_catalog.pg_class'::regclass AND d.refobjsubid>0 AND d.deptype IN ('a','i') "
        'LEFT JOIN pg_catalog.pg_class t ON t.oid=d.refobjid '
        'LEFT JOIN pg_catalog.pg_namespace tn ON tn.oid=t.relnamespace '
        'LEFT JOIN pg_catalog.pg_attribute a ON a.attrelid=t.oid AND a.attnum=d.refobjsubid '
        "WHERE n.nspname=%s AND s.relname=%s AND s.relkind='S'", (schema, name)).one())


def facts(app, name='preserved_seq'):
    with app.owner.connect() as connection:
        return sequence_facts(connection, app.schema, name)


def next_value(app, name='preserved_seq'):
    # A separate native connection preserves the existing finite attached grammar.
    with psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'], connect_timeout=5) as connection:
        return connection.execute('SELECT pg_catalog.nextval(%s::pg_catalog.regclass)',
                                  (f'"{app.schema}"."{name}"',)).fetchone()[0]


def test_native_owned_drop_detach_reattach_rollback_and_nontransactional_counter():
    with application(rows=0) as app:
        with app.owner.begin() as connection:
            connection.exec_driver_sql(f'CREATE TABLE "{app.schema}".native_slots '
                                      '(first text,middle text,last text)')
            install_sequence(connection, app.schema, app.role, 'native_slots', 'middle')
            original = sequence_facts(connection, app.schema)
            assert original[-4:] == ('a', app.schema, 'native_slots', 'middle')
            connection.exec_driver_sql(f'ALTER TABLE "{app.schema}".native_slots ADD COLUMN replacement text')
        assert next_value(app) == 101
        with app.owner.begin() as connection:
            savepoint = connection.begin_nested()
            connection.exec_driver_sql(f'ALTER TABLE "{app.schema}".native_slots DROP COLUMN middle')
            assert connection.exec_driver_sql('SELECT pg_catalog.to_regclass(%s)',
                (f'"{app.schema}".preserved_seq',)).scalar_one() is None
            savepoint.rollback()
            assert sequence_facts(connection, app.schema) == original
            # Sequence increments survive rollback. Only ownership/DDL rolls back.
            savepoint = connection.begin_nested()
            assert connection.exec_driver_sql('SELECT pg_catalog.nextval(%s::pg_catalog.regclass)',
                (f'"{app.schema}".preserved_seq',)).scalar_one() == 108
            connection.exec_driver_sql(f'ALTER SEQUENCE "{app.schema}".preserved_seq OWNED BY NONE')
            assert sequence_facts(connection, app.schema)[-4:] == (None, None, None, None)
            savepoint.rollback()
            assert sequence_facts(connection, app.schema) == original
        assert next_value(app) == 115
        with app.owner.begin() as connection:
            sequence = f'"{app.schema}".preserved_seq'
            table = f'"{app.schema}".native_slots'
            connection.exec_driver_sql(f'ALTER SEQUENCE {sequence} OWNED BY NONE')
            connection.exec_driver_sql(f'ALTER TABLE {table} DROP COLUMN middle')
            connection.exec_driver_sql(f'ALTER TABLE {table} RENAME COLUMN replacement TO middle')
            connection.exec_driver_sql(f'ALTER SEQUENCE {sequence} OWNED BY {table}.middle')
            assert sequence_facts(connection, app.schema) == original
        assert next_value(app) == 122
        assert facts(app) == original


@pytest.mark.parametrize('cache', [1, 3])
def test_public_lifecycle_preserves_owned_sequence_identity_metadata_and_current_counter(cache):
    def setup(connection, schema, role):
        install_sequence(connection, schema, role, cache=cache)
    # Each fresh backend reserves a full cache block. Unused values are native gaps.
    expected_counter = iter(101 + 7 * cache * index for index in range(5))
    with application(setup=setup) as app:
        original = facts(app)
        assert original[-4:] == ('a', app.schema, 'customer', 'name')
        assert app.plan.document['lock']['schema'] == 'cryptalis.lock/v5'
        # Planning must not consume, reset or freeze the mutable counter.
        assert next_value(app) == next(expected_counter)
        assert run(app).phase == 'PENDING'
        assert facts(app) == original
        assert publish(app).phase == 'ACTIVE'
        assert facts(app) == original
        assert next_value(app) == next(expected_counter)
        expected = reverse.attached_edits(app)
        assert facts(app) == original
        plan = reverse.proposal(app)
        assert next_value(app) == next(expected_counter)  # A legitimate increment after reverse planning.
        assert reverse.reverse(app, plan).phase == 'PLAINTEXT_PENDING'
        assert facts(app) == original and reverse.native_rows(app) == expected
        assert next_value(app) == next(expected_counter)
        consent, pin = reverse.consent(plan, 'PLAINTEXT_ACTIVATING')
        assert d.apply(plan, app.owner, keys=keys, pin=pin, approval=app.approval,
                       consent=consent, until='PLAINTEXT_ACTIVE').phase == 'PLAINTEXT_ACTIVE'
        assert facts(app) == original
        removal = d.RemovalApproval(plan.target_id, plan.operation_id, plan.digest,
            'native current-value CRUD and sequence continuity', 'public disposable fixture backup', True)
        assert d.remove(plan, app.owner, pin=replace(pin, phase='REMOVING'), approval=app.approval,
                        removal=removal, consent=consent).phase == 'REMOVED'
        assert d.check_removed(plan, app.owner, pin=replace(pin, phase='REMOVED')) is None
        assert facts(app) == original and reverse.native_rows(app) == expected
        assert next_value(app) == next(expected_counter)


def finish_reverse(app, plan):
    consent, pin = reverse.consent(plan, 'PLAINTEXT_ACTIVATING')
    assert d.apply(plan, app.owner, keys=keys, pin=pin, approval=app.approval,
                   consent=consent, until='PLAINTEXT_ACTIVE').phase == 'PLAINTEXT_ACTIVE'
    removal = d.RemovalApproval(plan.target_id, plan.operation_id, plan.digest,
        'native sequence ownership and latest-data exit', 'public disposable fixture only', True)
    assert d.remove(plan, app.owner, pin=replace(pin, phase='REMOVING'), approval=app.approval,
                    removal=removal, consent=consent).phase == 'REMOVED'
    assert d.check_removed(plan, app.owner, pin=replace(pin, phase='REMOVED')) is None


@pytest.mark.parametrize('direction', ['forward', 'reverse'])
def test_real_detach_failure_rolls_back_ownership_data_and_journal_without_rewinding_sequence(direction):
    with application(setup=install_sequence) as app:
        if direction == 'forward':
            assert run(app, 'VERIFIED').phase == 'VERIFIED'
            plan, pin, consent = app.plan, app.pin, None
        else:
            run(app); publish(app)
            plan = reverse.proposal(app)
            assert reverse.reverse(app, plan, until='VERIFIED').phase == 'VERIFIED'
            consent, pin = reverse.consent(plan)
        original, before, advanced = facts(app), _snapshot(app), []
        def fail_after_detach(connection, cursor, statement, parameters, context, many):
            if statement.upper().startswith('ALTER SEQUENCE') and 'OWNED BY NONE' in statement.upper():
                advanced.append(connection.exec_driver_sql('SELECT pg_catalog.nextval(%s::regclass)',
                    (f'"{app.schema}".preserved_seq',)).scalar_one())
                raise RuntimeError('public interruption after real sequence detach')
        event.listen(app.owner, 'after_cursor_execute', fail_after_detach)
        try:
            with pytest.raises(m.TransitionFailure):
                if direction == 'forward': run(app)
                else: reverse.reverse(app, plan)
        finally:
            event.remove(app.owner, 'after_cursor_execute', fail_after_detach)
        assert len(advanced) == 1
        assert facts(app) == original and _snapshot(app) == before
        assert next_value(app) == advanced[0] + 7
        if direction == 'forward':
            assert run(app).phase == 'PENDING'
            publish(app)
        else:
            assert reverse.reverse(app, plan).phase == 'PLAINTEXT_PENDING'
            finish_reverse(app, plan)
        assert facts(app) == original


@pytest.mark.parametrize('direction', ['forward', 'reverse'])
def test_real_lost_switch_commit_reply_resumes_same_sequence_without_reset(direction):
    with application(setup=install_sequence) as app:
        if direction == 'forward':
            assert run(app, 'VERIFIED').phase == 'VERIFIED'
            plan, pin, consent = app.plan, app.pin, None
        else:
            run(app); publish(app)
            plan = reverse.proposal(app)
            assert reverse.reverse(app, plan, until='VERIFIED').phase == 'VERIFIED'
            consent, pin = reverse.consent(plan)
        original = facts(app)
        observed = next_value(app)
        with lost_commit_reply(os.environ['CRYPTALIS_TEST_DATABASE_URL'], commit_number=3) as (url, dropped):
            proxied = create_engine('postgresql+psycopg://', hide_parameters=True,
                                   creator=lambda: psycopg.connect(url, connect_timeout=5))
            try:
                with pytest.raises(m.TransitionFailure):
                    if direction == 'forward':
                        m.apply(plan, proxied, keys=keys, pin=pin, approval=app.approval)
                    else:
                        d.apply(plan, proxied, keys=keys, pin=pin, approval=app.approval, consent=consent)
                assert dropped.wait(5), 'proxy did not discard the committed reply'
            finally:
                proxied.dispose()
        phase = 'PENDING' if direction == 'forward' else 'PLAINTEXT_PENDING'
        status = m.status(plan, app.owner, pin=pin) if direction == 'forward' else d.status(plan, app.owner, pin=pin)
        assert status.phase == phase and facts(app) == original
        assert next_value(app) == observed + 7
        committed = _snapshot(app)
        if direction == 'forward': assert run(app).phase == phase
        else: assert reverse.reverse(app, plan).phase == phase
        assert _snapshot(app) == committed and facts(app) == original
        assert next_value(app) == observed + 14
        if direction == 'forward': publish(app)
        else: finish_reverse(app, plan)
        assert facts(app) == original


@pytest.mark.parametrize('phase', ['planned', 'active'])
def test_owned_sequence_drift_refuses_without_effects_and_exact_repair_recovers(phase):
    with application(setup=install_sequence) as app:
        if phase == 'active': run(app); publish(app)
        original = facts(app)
        table, sequence = f'"{app.schema}".customer', f'"{app.schema}".preserved_seq'
        role = app.owner.dialect.identifier_preparer.quote(app.role)
        for fault in ('rename', 'ownership', 'configuration', 'acl', 'inbound_default'):
            with app.owner.begin() as connection:
                if fault == 'rename': connection.exec_driver_sql(f'ALTER SEQUENCE {sequence} RENAME TO moved_seq')
                elif fault == 'ownership': connection.exec_driver_sql(f'ALTER SEQUENCE {sequence} OWNED BY {table}.label')
                elif fault == 'configuration': connection.exec_driver_sql(f'ALTER SEQUENCE {sequence} INCREMENT BY 9')
                elif fault == 'acl': connection.exec_driver_sql(f'REVOKE SELECT ON SEQUENCE {sequence} FROM {role}')
                else:
                    connection.exec_driver_sql(f'''CREATE TABLE "{app.schema}".external_consumer
                        (id bigint DEFAULT nextval('"{app.schema}".preserved_seq'::regclass))''')
            changed = _snapshot(app)
            with app.owner.connect() as connection:
                changed_sequence = sequence_facts(connection, app.schema,
                    'moved_seq' if fault == 'rename' else 'preserved_seq')
            with pytest.raises(m.TransitionFailure):
                if phase == 'planned': run(app)
                else: reverse.proposal(app)
            assert _snapshot(app) == changed
            with app.owner.connect() as connection:
                assert sequence_facts(connection, app.schema,
                    'moved_seq' if fault == 'rename' else 'preserved_seq') == changed_sequence
            with app.owner.begin() as connection:
                if fault == 'rename': connection.exec_driver_sql(f'ALTER SEQUENCE "{app.schema}".moved_seq RENAME TO preserved_seq')
                elif fault == 'ownership': connection.exec_driver_sql(f'ALTER SEQUENCE {sequence} OWNED BY {table}.name')
                elif fault == 'configuration': connection.exec_driver_sql(f'ALTER SEQUENCE {sequence} INCREMENT BY 7')
                elif fault == 'acl': connection.exec_driver_sql(f'GRANT SELECT ON SEQUENCE {sequence} TO {role} WITH GRANT OPTION')
                else: connection.exec_driver_sql(f'DROP TABLE "{app.schema}".external_consumer')
            assert facts(app) == original
        # The runtime cannot acquire ownership or sequence DDL rights.
        with app.runtime.connect() as connection:
            with pytest.raises(DBAPIError) as denied:
                connection.exec_driver_sql(f'ALTER SEQUENCE {sequence} OWNER TO {role}')
            assert denied.value.orig.sqlstate == '42501'
        assert facts(app) == original
        if phase == 'planned': run(app); publish(app)
        plan = reverse.proposal(app)
        assert reverse.reverse(app, plan).phase == 'PLAINTEXT_PENDING'
        finish_reverse(app, plan)
        assert facts(app) == original


def test_same_name_replacement_oid_is_not_admitted_or_silently_recreated():
    with application(setup=install_sequence) as app:
        original = facts(app)
        sequence, saved = f'"{app.schema}".preserved_seq', f'"{app.schema}".saved_original'
        with app.owner.begin() as connection:
            connection.exec_driver_sql(f'ALTER SEQUENCE {sequence} RENAME TO saved_original')
            connection.exec_driver_sql(f'ALTER SEQUENCE {saved} OWNED BY NONE')
            install_sequence(connection, app.schema, app.role)
        replacement = facts(app)
        assert replacement[0] != original[0] and replacement[1:] == original[1:]
        before = _snapshot(app)
        with pytest.raises(m.TransitionFailure): run(app)
        assert facts(app) == replacement and _snapshot(app) == before
        with app.owner.begin() as connection:
            connection.exec_driver_sql(f'DROP SEQUENCE {sequence}')
            connection.exec_driver_sql(f'ALTER SEQUENCE {saved} RENAME TO preserved_seq')
            connection.exec_driver_sql(f'ALTER SEQUENCE {sequence} OWNED BY "{app.schema}".customer.name')
        assert facts(app) == original
        run(app); publish(app)
        assert facts(app) == original and next_value(app) == 101


def test_old_lock_late_owned_sequence_is_still_refused():
    with application() as app:
        assert app.plan.document['lock']['schema'] != 'cryptalis.lock/v5'
        with app.owner.begin() as connection:
            install_sequence(connection, app.schema, app.role)
        original, before = facts(app), _snapshot(app)
        with pytest.raises(m.TransitionFailure): run(app)
        assert facts(app) == original and _snapshot(app) == before


@pytest.mark.parametrize('kind', ['varchar', 'boolean'])
def test_v5_keeps_native_varchar_and_boolean_rules_through_current_value_exit(kind):
    from sqlalchemy import Boolean, String
    options = dict(value_type=String(64, collation='C')) if kind == 'varchar' else dict(
        value_type=Boolean(), queries=[], protected_values=(None, True, False), rows=3)
    with application(setup=install_sequence, **options) as app:
        original = facts(app)
        assert app.plan.document['lock']['schema'] == 'cryptalis.lock/v5'
        assert m.MigrationPlan(app.plan.artifact).artifact == app.plan.artifact
        run(app); publish(app)
        assert facts(app) == original
        plan = reverse.proposal(app)
        assert d.DeprotectionPlan(plan.artifact).artifact == plan.artifact
        assert reverse.reverse(app, plan).phase == 'PLAINTEXT_PENDING'
        finish_reverse(app, plan)
        assert reverse.native_rows(app) == app.source and facts(app) == original


@pytest.mark.parametrize('terminal', ['commit', 'rollback'])
def test_native_sequence_alter_lock_blocks_other_nextval_without_advancing_counter(terminal):
    with application(rows=0) as app:
        with app.owner.begin() as connection:
            install_sequence(connection, app.schema, app.role)
        original = facts(app)
        assert next_value(app) == 101
        with app.owner.connect() as owner:
            transaction = owner.begin()
            owner.exec_driver_sql(f'ALTER SEQUENCE "{app.schema}".preserved_seq OWNED BY NONE')
            with psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'], connect_timeout=5) as runtime:
                runtime.execute("SET LOCAL lock_timeout = '100ms'")
                with pytest.raises(psycopg.errors.LockNotAvailable) as blocked:
                    runtime.execute('SELECT pg_catalog.nextval(%s::regclass)',
                                    (f'"{app.schema}".preserved_seq',))
                assert blocked.value.sqlstate == '55P03'
                runtime.rollback()
            if terminal == 'commit':
                owner.exec_driver_sql(f'ALTER SEQUENCE "{app.schema}".preserved_seq '
                                      f'OWNED BY "{app.schema}".customer.name')
                transaction.commit()
            else:
                transaction.rollback()
        assert facts(app) == original
        assert next_value(app) == 108


def test_admitted_native_prefixed_sequence_survives_but_unrecorded_object_blocks_removal():
    name = '_cryptalis_native_seq'
    def setup(connection, schema, role):
        install_sequence(connection, schema, role, name=name)
    with application(setup=setup) as app:
        original = facts(app, name)
        run(app); publish(app)
        expected = reverse.attached_edits(app)
        plan = reverse.proposal(app)
        assert reverse.reverse(app, plan).phase == 'PLAINTEXT_PENDING'
        consent, pin = reverse.consent(plan, 'PLAINTEXT_ACTIVATING')
        assert d.apply(plan, app.owner, keys=keys, pin=pin, approval=app.approval,
                       consent=consent, until='PLAINTEXT_ACTIVE').phase == 'PLAINTEXT_ACTIVE'
        removal = d.RemovalApproval(plan.target_id, plan.operation_id, plan.digest,
            'recorded native sequence survives package-free exit', 'public disposable fixture', True)
        with app.owner.begin() as connection:
            connection.exec_driver_sql(f'CREATE SEQUENCE "{app.schema}"._cryptalis_unrecorded_seq')
        before = _snapshot(app)
        with pytest.raises(m.TransitionFailure):
            d.remove(plan, app.owner, pin=replace(pin, phase='REMOVING'), approval=app.approval,
                     removal=removal, consent=consent)
        assert _snapshot(app) == before and facts(app, name) == original
        with app.owner.begin() as connection:
            assert connection.exec_driver_sql('SELECT pg_catalog.to_regclass(%s)',
                (f'"{app.schema}"._cryptalis_unrecorded_seq',)).scalar_one() is not None
            connection.exec_driver_sql(f'DROP SEQUENCE "{app.schema}"._cryptalis_unrecorded_seq')
        assert d.remove(plan, app.owner, pin=replace(pin, phase='REMOVING'), approval=app.approval,
                        removal=removal, consent=consent).phase == 'REMOVED'
        assert d.check_removed(plan, app.owner, pin=replace(pin, phase='REMOVED')) is None
        assert facts(app, name) == original and reverse.native_rows(app) == expected
        assert next_value(app, name) == 101


@pytest.mark.parametrize('phase', ['planned', 'expanded'])
def test_reverse_sequence_drift_refuses_before_effects_keys_status_and_staged_abort(phase):
    with application(setup=install_sequence) as app:
        run(app); publish(app)
        plan = reverse.proposal(app)
        if phase == 'expanded':
            assert reverse.reverse(app, plan, until='EXPANDED').phase == 'EXPANDED'
        original = facts(app)
        with app.owner.begin() as connection:
            connection.exec_driver_sql(f'ALTER SEQUENCE "{app.schema}".preserved_seq INCREMENT BY 9')
        changed, metadata, calls = _snapshot(app), facts(app), []
        def forbidden(tenant):
            calls.append(tenant)
            pytest.fail('reverse sequence drift reached keys')
        with pytest.raises(m.TransitionFailure):
            reverse.reverse(app, plan, key_resolver=forbidden)
        assert calls == [] and _snapshot(app) == changed and facts(app) == metadata
        consent, pin = reverse.consent(plan)
        with pytest.raises(m.TransitionFailure):
            d.status(plan, app.owner, pin=pin)
        if phase == 'expanded':
            with pytest.raises(m.TransitionFailure):
                d.abort(plan, app.owner, pin=pin, approval=app.approval, consent=consent)
        assert _snapshot(app) == changed and facts(app) == metadata
        with app.owner.begin() as connection:
            connection.exec_driver_sql(f'ALTER SEQUENCE "{app.schema}".preserved_seq INCREMENT BY 7')
        assert facts(app) == original
        def counted(tenant):
            calls.append(tenant)
            return keys(tenant)
        assert reverse.reverse(app, plan, key_resolver=counted).phase == 'PLAINTEXT_PENDING'
        assert calls
        finish_reverse(app, plan)
        assert facts(app) == original
