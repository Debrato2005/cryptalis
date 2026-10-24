"""Native recovery controls for the explicitly selected public-slot layout."""
import json
import os
import select
import signal

import psycopg
import pytest
from sqlalchemy import create_engine, event

from cryptalis import deprotection as d, migration as m, rotation
from migration_commit_proxy import lost_commit_reply
from rewrap_worker import target_keys
from test_migration import application, child, frames, keys, publish, run
from test_owned_sequences import _snapshot, facts, finish_reverse, next_value
from test_public_slots import original_gap, select_layout, slots
import test_deprotection as reverse


@pytest.fixture
def preserved():
    def setup(connection, schema, role):
        original_gap(connection, schema, role, sequence=True)
    with application(setup=setup) as app:
        select_layout(app)
        yield app


def snapshot(app):
    with app.owner.connect() as connection:
        table = f'"{app.schema}".customer'
        relation = connection.exec_driver_sql(
            'SELECT oid::text,relfilenode::text FROM pg_catalog.pg_class '
            'WHERE oid=pg_catalog.to_regclass(%s)', (table,)).one()
        indexes = connection.exec_driver_sql(
            'SELECT c.relname,c.oid::text,c.relfilenode::text FROM pg_catalog.pg_index i '
            'JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid '
            'WHERE i.indrelid=pg_catalog.to_regclass(%s) ORDER BY c.relname', (table,)).all()
        metadata = connection.exec_driver_sql(
            'SELECT attname,attstattarget,attstorage,attcompression,attoptions::text,attacl::text,'
            'pg_catalog.col_description(attrelid,attnum) FROM pg_catalog.pg_attribute '
            'WHERE attrelid=pg_catalog.to_regclass(%s) AND attnum>0 AND NOT attisdropped '
            'ORDER BY attnum', (table,)).all()
    return _snapshot(app), slots(app), facts(app), relation, indexes, metadata


def prepare_switch(app, direction):
    if direction == 'forward':
        assert run(app, until='VERIFIED').phase == 'VERIFIED'
        return app.plan, app.pin, None
    run(app)
    publish(app)
    plan = reverse.proposal(app)
    assert reverse.reverse(app, plan, until='VERIFIED').phase == 'VERIFIED'
    consent, pin = reverse.consent(plan)
    return plan, pin, consent


@pytest.mark.parametrize('direction', ['forward', 'reverse'])
@pytest.mark.parametrize('boundary', ['alter', 'dependencies'])
def test_real_type_conversion_and_dependency_failure_roll_back_every_durable_effect(preserved, direction, boundary):
    app = preserved
    original_slots, original_sequence = slots(app), facts(app)
    plan, pin, consent = prepare_switch(app, direction)
    before, advanced = snapshot(app), []

    def interrupt(connection, cursor, statement, parameters, context, many):
        rewritten = statement.startswith('ALTER TABLE ') and ' TYPE ' in statement and ' USING ' in statement
        rebuilt = (statement.startswith('CREATE UNIQUE INDEX ')
                   and ('_eq' in statement if direction == 'forward' else 'native_name' in statement))
        if (boundary == 'alter' and rewritten) or (boundary == 'dependencies' and rebuilt):
            advanced.append(connection.exec_driver_sql('SELECT pg_catalog.nextval(%s::regclass)',
                (f'"{app.schema}".preserved_seq',)).scalar_one())
            raise RuntimeError('public interruption after real layout DDL')

    event.listen(app.owner, 'after_cursor_execute', interrupt)
    try:
        with pytest.raises(m.TransitionFailure):
            if direction == 'forward':
                m.apply(plan, app.owner, keys=keys, pin=pin, approval=app.approval)
            else:
                d.apply(plan, app.owner, keys=keys, pin=pin, approval=app.approval, consent=consent)
    finally:
        event.remove(app.owner, 'after_cursor_execute', interrupt)
    assert len(advanced) == 1
    assert snapshot(app) == before and facts(app) == original_sequence
    assert next_value(app) == advanced[0] + 7
    if direction == 'forward':
        assert run(app).phase == 'PENDING'
        publish(app)
    else:
        assert reverse.reverse(app, plan).phase == 'PLAINTEXT_PENDING'
        finish_reverse(app, plan)
    assert slots(app) == original_slots and facts(app) == original_sequence


@pytest.mark.parametrize('direction', ['forward', 'reverse'])
def test_lost_real_switch_commit_reply_retries_without_another_rewrite(preserved, direction):
    app = preserved
    original_slots, original_sequence = slots(app), facts(app)
    plan, pin, consent = prepare_switch(app, direction)
    counter = next_value(app)
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
    observed = m.status(plan, app.owner, pin=pin) if direction == 'forward' else d.status(plan, app.owner, pin=pin)
    assert observed.phase == phase and slots(app) == original_slots and facts(app) == original_sequence
    assert next_value(app) == counter + 7
    committed = snapshot(app)
    assert (run(app) if direction == 'forward' else reverse.reverse(app, plan)).phase == phase
    assert snapshot(app) == committed
    assert next_value(app) == counter + 14
    if direction == 'forward':
        publish(app)
    else:
        finish_reverse(app, plan)
    assert slots(app) == original_slots and facts(app) == original_sequence


def swap_public_names(connection, app):
    table = f'"{app.schema}".customer'
    connection.exec_driver_sql(f'ALTER TABLE {table} RENAME COLUMN label TO temporary_label')
    connection.exec_driver_sql(f'ALTER TABLE {table} RENAME COLUMN tail TO label')
    connection.exec_driver_sql(f'ALTER TABLE {table} RENAME COLUMN temporary_label TO tail')


@pytest.mark.parametrize('phase', ['active', 'reverse_paused'])
def test_source_layout_refuses_real_slot_drift_even_when_the_progress_snapshot_agrees(phase):
    def setup(connection, schema, role):
        original_gap(connection, schema, role, sequence=True)
        connection.exec_driver_sql(f'ALTER TABLE "{schema}".customer ADD COLUMN tail text')
    with application(setup=setup) as app:
        with app.owner.begin() as connection:
            connection.exec_driver_sql(f'UPDATE "{app.schema}".customer SET tail=label')
        select_layout(app)
        original_slots = slots(app)
        run(app)
        publish(app)
        plan = app.plan
        if phase == 'reverse_paused':
            plan = reverse.proposal(app)
            assert reverse.reverse(app, plan, until='EXPANDED').phase == 'EXPANDED'
        before = snapshot(app)
        journal = f'"{app.schema}"."{m.JOURNAL}"'
        with app.owner.begin() as connection:
            state = connection.exec_driver_sql(f'SELECT state FROM {journal} WHERE operation_id=%s',
                (plan.operation_id,)).scalar_one()
            original_state = json.dumps(state)
            swap_public_names(connection, app)
            model = plan.document['lock']['models'][0]
            state['models'][model['table_id']]['active_schema' if phase == 'active' else 'schema'] = m._facts(connection, model)
            connection.exec_driver_sql(f'UPDATE {journal} SET state=%s::jsonb WHERE operation_id=%s',
                (json.dumps(state), plan.operation_id))
        changed, calls = snapshot(app), []
        assert slots(app) != before[1]

        def forbidden(tenant):
            calls.append(tenant)
            pytest.fail('changed public slots reached key preparation')

        with pytest.raises(m.TransitionFailure) as refused:
            if phase == 'active':
                rotation.plan_rewrap(plan, app.owner, source_pin=app.pin, keys=forbidden,
                    target_keys=forbidden, verify_rows_per_second=1000)
            else:
                reverse.reverse(app, plan, key_resolver=forbidden)
        assert refused.value.code == 'public_slots_changed' and calls == []
        assert snapshot(app) == changed
        with app.owner.begin() as connection:
            swap_public_names(connection, app)
            connection.exec_driver_sql(f'UPDATE {journal} SET state=%s::jsonb WHERE operation_id=%s',
                (original_state, plan.operation_id))
        assert snapshot(app) == before

        def counted(tenant):
            calls.append(tenant)
            return keys(tenant)

        if phase == 'active':
            rotation.plan_rewrap(plan, app.owner, source_pin=app.pin, keys=counted,
                target_keys=target_keys, verify_rows_per_second=1000)
            plan = reverse.proposal(app)
        assert reverse.reverse(app, plan, key_resolver=counted).phase == 'PLAINTEXT_PENDING'
        assert calls
        finish_reverse(app, plan)
        assert slots(app) == original_slots


@pytest.mark.skipif(not hasattr(signal, 'SIGKILL'), reason='requires POSIX SIGKILL')
def test_killed_independent_v6_executor_resumes_committed_layout_without_rewrite(preserved, tmp_path):
    app = preserved
    original_slots, original_sequence = slots(app), facts(app)
    process = child(app, tmp_path, 'PENDING', True)
    resumed = None
    try:
        ready, _, _ = select.select([process.stdout], [], [], 20)
        assert ready, 'independent executor did not report its committed phase'
        assert process.stdout.readline().strip() == 'PENDING'
        committed, ciphertext = snapshot(app), frames(app, switched=True)
        process.send_signal(signal.SIGKILL)
        assert process.wait(timeout=10) == -signal.SIGKILL
        resumed = child(app, tmp_path)
        stdout, _ = resumed.communicate(timeout=25)
        assert resumed.returncode == 0, 'independent resume failed; diagnostics suppressed'
        assert stdout.strip() == 'PENDING'
        assert snapshot(app) == committed and frames(app, switched=True) == ciphertext
        assert slots(app) == original_slots and facts(app) == original_sequence
        publish(app)
    finally:
        for worker in (process, resumed):
            if worker is None:
                continue
            if worker.poll() is None:
                worker.kill()
                worker.wait(timeout=10)
            for stream in (worker.stdout, worker.stderr):
                if stream is not None:
                    stream.close()
