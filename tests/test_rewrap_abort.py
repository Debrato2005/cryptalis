"""Native pending-rewrap cancellation and source-authority recovery controls."""
from dataclasses import asdict, replace
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
from uuid import UUID

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.exc import DBAPIError

from cryptalis import migration as m, rotation as r
from cryptalis.sqlalchemy import attach
from test_migration import application, frames, keys, publish, run, TENANT
from test_rewrap_plan import _snapshot
from test_rewrap_execution import proposal, apply, activate, target_factory
from test_deprotection import app_pin, consent, d, least_privilege_role, native_rows, reverse


def abort(app, plan, source=keys, pin=None, engine=None):
    return r.abort_rewrap(plan, app.owner if engine is None else engine, keys=source,
                           pin=app.pin if pin is None else pin, approval=app.approval)


def index_identity(app):
    field = app.plan.document['lock']['models'][0]['fields'][0]
    with app.owner.connect() as c:
        return c.exec_driver_sql('SELECT c.oid::text,c.relfilenode::text FROM pg_catalog.pg_class c '
            'JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace '
            'WHERE n.nspname=%s AND c.relname=%s', (app.schema,field['payload_column']+'_eq')).one()


def test_abort_restores_source_writers_without_target_custody_and_preserves_bytes():
    with application() as app:
        run(app); publish(app)
        plan, target, provider = proposal(app)
        before = frames(app, True)
        index_before = index_identity(app)
        apply(app, plan, target)
        # The target provider is deliberately unusable after committed PENDING.
        provider.unwrap = lambda *args: (_ for _ in ()).throw(RuntimeError('private target outage'))
        assert abort(app, plan).phase == 'ABORTED'
        assert frames(app, True) == before
        assert index_identity(app) == index_before
        assert m.status(app.plan, app.owner, pin=app.pin).phase == 'ACTIVE'
        with pytest.raises(m.TransitionFailure):
            m.apply(plan.activation_plan, app.owner, keys=target,
                     pin=app_pin(plan.activation_plan, 'ACTIVATING'), approval=app.approval, until='ACTIVE')
        sessions = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes,
                          keys=keys, deployment=(app.plan, app.pin))
        with sessions(tenant_id=TENANT) as session:
            record = session.get(app.Customer, UUID(int=101))
            record.name = 'edited after canceled custody change'
            session.commit()
        edited = _snapshot(app)
        assert abort(app, r.RewrapPlan(plan.artifact)).phase == 'ABORTED'
        assert _snapshot(app) == edited
        with sessions(tenant_id=TENANT) as session:
            assert session.scalar(select(app.Customer.id).where(
                app.Customer.name == 'edited after canceled custody change')) == UUID(int=101)
        # The canceled row does not prevent a new, independently planned custody change.
        next_plan, next_target, _ = proposal(app)
        apply(app, next_plan, next_target)
        activate(app, next_plan, next_target)
        with pytest.raises(m.TransitionFailure):
            abort(app, plan, pin=app_pin(plan.source, 'ACTIVE'))


@pytest.mark.parametrize('fault', ['successor_pin', 'source_phase', 'pin_digest', 'source_state',
    'successor_digest', 'successor_proposal', 'successor_link', 'disabled_guard', 'schema',
    'frame', 'membership', 'source_keys', 'source_outage', 'source_phase_claim',
    'unreviewed_operation', 'approval'])
def test_abort_refusal_keeps_current_pending_state_and_guard(fault):
    with application() as app:
        run(app); publish(app)
        plan, target, _ = proposal(app)
        apply(app, plan, target)
        pin, source, approval = app.pin, keys, app.approval
        journal = f'"{app.schema}"."_cryptalis_journal"'
        successor = plan.activation_plan
        with app.owner.begin() as c:
            if fault == 'successor_pin': pin = app_pin(successor, 'PREPARED')
            if fault == 'source_phase': pin = replace(pin, phase='PENDING')
            if fault == 'pin_digest': pin = replace(pin, plan_digest='0'*64)
            if fault == 'source_keys': source = target
            if fault == 'source_outage':
                def source(tenant): raise RuntimeError('private source outage')
            if fault == 'approval': approval = m.MaintenanceApproval('', 0)
            if fault == 'source_state':
                c.exec_driver_sql(f'UPDATE {journal} SET state=state || %s::jsonb WHERE operation_id=%s',
                                  (json.dumps({'unplanned': True}), app.plan.operation_id))
            if fault == 'source_phase_claim':
                c.exec_driver_sql(f'UPDATE {journal} SET state=state || %s::jsonb WHERE operation_id=%s',
                                  (json.dumps({'phase':'ACTIVE'}), app.plan.operation_id))
            if fault == 'successor_digest':
                c.exec_driver_sql(f'UPDATE {journal} SET plan_digest=%s WHERE operation_id=%s',
                                  ('0'*64, successor.operation_id))
            if fault == 'successor_proposal':
                c.exec_driver_sql(f'UPDATE {journal} SET state=state || %s::jsonb WHERE operation_id=%s',
                                  (json.dumps({'rewrap_plan_digest':'0'*64}), successor.operation_id))
            if fault == 'successor_link':
                c.exec_driver_sql(f'UPDATE {journal} SET state=state || %s::jsonb WHERE operation_id=%s',
                                  (json.dumps({'superseded_by':{'operation_id':str(UUID(int=9)),
                                                              'plan_digest':successor.digest}}), app.plan.operation_id))
            if fault == 'disabled_guard':
                trigger, _ = m._guard_names(successor, successor.document['lock']['models'][0])
                c.exec_driver_sql(f'ALTER TABLE "{app.schema}".customer DISABLE TRIGGER "{trigger}"')
            if fault == 'schema':
                c.exec_driver_sql(f'ALTER TABLE "{app.schema}".customer ADD COLUMN unplanned text')
            if fault == 'frame':
                c.exec_driver_sql(f'UPDATE "{app.schema}".customer SET name=pg_catalog.set_byte(name, '
                    'octet_length(name)-1,pg_catalog.get_byte(name,octet_length(name)-1) # 1) WHERE id=%s',
                    (UUID(int=101),))
            if fault == 'membership':
                c.exec_driver_sql(f'DELETE FROM "{app.schema}".customer WHERE id=%s', (UUID(int=101),))
            if fault == 'unreviewed_operation':
                c.exec_driver_sql(f'INSERT INTO {journal} VALUES (%s,%s,%s::jsonb)',
                                  (UUID(int=99),'0'*64,json.dumps({'phase':'ACTIVE'})))
        before = _snapshot(app)
        with pytest.raises(m.TransitionFailure) as failure:
            r.abort_rewrap(plan, app.owner, keys=source, pin=pin, approval=approval)
        assert 'private source outage' not in str(failure.value)
        assert _snapshot(app) == before
        if fault != 'disabled_guard':
            with app.runtime.connect() as c:
                with pytest.raises(DBAPIError) as denied:
                    c.exec_driver_sql(f'UPDATE "{app.schema}".customer SET label=%s', ('still paused',))
                assert denied.value.orig.sqlstate == '55000'


def test_active_successor_cannot_be_canceled():
    with application() as app:
        run(app); publish(app)
        plan, target, _ = proposal(app)
        source_pin = app.pin
        apply(app, plan, target)
        activate(app, plan, target)
        before = _snapshot(app)
        with pytest.raises(m.TransitionFailure):
            abort(app, plan, pin=source_pin)
        assert _snapshot(app) == before


def test_abort_second_rewrap_preserves_edits_and_exact_ancestry_through_removal():
    with application() as app:
        run(app); publish(app)
        first, target, _ = proposal(app)
        apply(app, first, target)
        activate(app, first, target)
        mapping, Customer, sessions = target_factory(app, target)
        try:
            with sessions(tenant_id=TENANT) as session:
                session.get(Customer, UUID(int=101)).name = 'latest value before canceled second rewrap'
                session.commit()
        finally:
            mapping.dispose()
        current = target
        second, target, _ = proposal(app, current)
        before = frames(app, True)
        apply(app, second, target, current)
        assert abort(app, second, current).phase == 'ABORTED'
        assert frames(app, True) == before
        reverse_plan = d.plan(app.plan, app.owner, source_pin=app.pin, keys=current,
            plaintext_runtime_role=least_privilege_role(app), backfill_rows_per_second=1000,
            verify_rows_per_second=1000, temporary_bytes_per_row=700, wal_bytes_per_row=700)
        assert reverse(app, reverse_plan, key_resolver=current).phase == 'PLAINTEXT_PENDING'
        pure, _ = consent(reverse_plan)
        assert d.apply(reverse_plan, app.owner, keys=current,
            pin=app_pin(reverse_plan,'PLAINTEXT_ACTIVATING'), approval=app.approval,
            consent=pure, until='PLAINTEXT_ACTIVE').phase == 'PLAINTEXT_ACTIVE'
        removal = d.RemovalApproval(reverse_plan.target_id, reverse_plan.operation_id, reverse_plan.digest,
                                    'native app uses no crypto columns', 'retained public fixture roots', True)
        assert d.remove(reverse_plan, app.owner, pin=app_pin(reverse_plan,'REMOVING'),
            approval=app.approval, removal=removal, consent=pure).phase == 'REMOVED'
        assert native_rows(app)[UUID(int=101)][1] == 'latest value before canceled second rewrap'


def test_abort_uses_current_verification_cost_instead_of_historical_protection_cost():
    # Build the source with a slow historical backfill estimate, then approve
    # only the newly measured rewrap verification. No historical work repeats.
    with application() as app:
        document = app.plan.document
        document['estimates']['backfill_rows_per_second'] = .001
        document['estimates']['writer_pause_seconds_estimate'] = m._estimate_seconds(
            document['estimates']['rows'], .001, document['estimates']['verify_rows_per_second'])
        app.plan = m.MigrationPlan(m._canonical(document))
        app.pin = app_pin(app.plan, 'PREPARED')
        app.approval = m.MaintenanceApproval('all fixture writers stopped',10001)
        run(app); publish(app)
        plan, target, _ = proposal(app)
        app.approval = replace(app.approval, approved_pause_seconds=10)
        apply(app, plan, target)
        assert abort(app, plan).phase == 'ABORTED'


def test_failure_after_guard_drop_rolls_back_all_cancellation_effects(monkeypatch):
    with application() as app:
        run(app); publish(app)
        plan, target, _ = proposal(app)
        apply(app, plan, target)
        before = _snapshot(app)
        original = m._drop_guards
        def interrupted(c, successor):
            original(c, successor)
            raise RuntimeError('private abort interruption')
        monkeypatch.setattr(m, '_drop_guards', interrupted)
        with pytest.raises(m.TransitionFailure) as failure: abort(app, plan)
        assert 'private abort interruption' not in str(failure.value)
        assert _snapshot(app) == before
        with app.runtime.connect() as c:
            with pytest.raises(DBAPIError) as denied:
                c.exec_driver_sql(f'UPDATE "{app.schema}".customer SET label=%s', ('still paused',))
            assert denied.value.orig.sqlstate == '55000'


def test_canceled_process_restart_reloads_original_artifacts_without_target_keys(tmp_path):
    from rewrap_worker import target_keys
    with application() as app:
        run(app); publish(app)
        plan = r.plan_rewrap(app.plan, app.owner, source_pin=app.pin, keys=keys,
                             target_keys=target_keys, verify_rows_per_second=1000)
        apply(app, plan, target_keys)
        before, index_before = frames(app, True), index_identity(app)
        artifact, pin_file, approval_file = (tmp_path / name for name in ('plan.json','pin.json','approval.json'))
        artifact.write_bytes(plan.artifact)
        pin_file.write_text(json.dumps(asdict(app.pin), default=str))
        approval_file.write_text(json.dumps(asdict(app.approval)))
        command = [sys.executable, str(Path(__file__).with_name('rewrap_worker.py')),
                   str(artifact), str(pin_file), str(approval_file), 'abort']
        child = subprocess.Popen(command + ['pause'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            with selectors.DefaultSelector() as ready:
                ready.register(child.stdout, selectors.EVENT_READ)
                assert ready.select(timeout=20), 'abort worker did not report committed progress'
            expected = {'phase':'ABORTED','source_phase':'ACTIVE',
                        'operation_id':str(plan.operation_id),'digest':plan.activation_plan.digest}
            assert json.loads(child.stdout.readline()) == expected
            child.kill()
            child.communicate(timeout=20)
            assert child.returncode == -signal.SIGKILL
            restarted = subprocess.run(command + ['exit'], capture_output=True, text=True, timeout=30)
            assert restarted.returncode == 0
            assert json.loads(restarted.stdout) == expected
            assert frames(app, True) == before
            assert index_identity(app) == index_before
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=20)


def test_lost_abort_commit_reply_resumes_original_terminal_marker():
    import psycopg
    from migration_commit_proxy import lost_commit_reply
    with application() as app:
        run(app); publish(app)
        plan, target, _ = proposal(app)
        apply(app, plan, target)
        before = frames(app, True)
        with lost_commit_reply(os.environ['CRYPTALIS_TEST_DATABASE_URL'], commit_number=2) as (url, dropped):
            proxied = create_engine('postgresql+psycopg://', hide_parameters=True,
                                    creator=lambda: psycopg.connect(url))
            try:
                with pytest.raises(m.TransitionFailure): abort(app, plan, engine=proxied)
                assert dropped.is_set()
            finally:
                proxied.dispose()
        committed = _snapshot(app)
        assert m.status(app.plan, app.owner, pin=app.pin).phase == 'ACTIVE'
        assert abort(app, plan).phase == 'ABORTED'
        assert _snapshot(app) == committed
        assert frames(app, True) == before


def test_wrong_native_target_refuses_before_key_access():
    with application() as app:
        run(app); publish(app)
        plan, target, _ = proposal(app)
        apply(app, plan, target)
        document = plan.document
        document['source_plan']['target'][0] = 'wrong-native-target'
        source = m.MigrationPlan(m._canonical(document['source_plan']))
        document['source_pin']['plan_digest'] = source.digest
        changed = r.RewrapPlan(m._canonical(document))
        before = _snapshot(app)
        def forbidden(tenant): pytest.fail('wrong-target cancellation accessed keys')
        with pytest.raises(m.TransitionFailure, match='wrong_database_target'):
            r.abort_rewrap(changed, app.owner, keys=forbidden,
                           pin=app_pin(source,'ACTIVE'), approval=app.approval)
        assert _snapshot(app) == before


def test_invalid_cancellation_input_refuses_before_connection():
    with pytest.raises(m.TransitionFailure, match='invalid_rewrap_plan'):
        r.abort_rewrap(None, None, keys=None, pin=None, approval=None)


def test_multi_table_tenant_cancellation_releases_shared_guard_without_frame_changes():
    from cryptalis.crypto import DevelopmentKeyProvider, Keyring
    from cryptalis.crypto._rewrap import prepare_rewrap
    from test_migration_multitable import (multiple_tables, other_frames, assert_independent_values,
                                          assert_no_guards, OTHER_TENANT)
    with multiple_tables() as app:
        run(app); publish(app)
        provider, policies = DevelopmentKeyProvider(), {}
        def target(tenant):
            if tenant not in policies:
                policy = prepare_rewrap(keys(tenant), provider)
                policies[tenant] = Keyring(policy, {provider.provider_id:provider})
            return policies[tenant]
        plan = r.plan_rewrap(app.plan, app.owner, source_pin=app.pin, keys=keys,
                             target_keys=target, verify_rows_per_second=1000)
        before = frames(app, True), other_frames(app, True), other_frames(app, True, True)
        apply(app, plan, target)
        for table in ('customer','other_customer'):
            with app.runtime.connect() as c:
                with pytest.raises(DBAPIError) as denied:
                    c.exec_driver_sql(f'DELETE FROM "{app.schema}"."{table}" WHERE id=%s', (UUID(int=101),))
                assert denied.value.orig.sqlstate == '55000'
        assert abort(app, plan).phase == 'ABORTED'
        assert_no_guards(app)
        assert (frames(app, True), other_frames(app, True), other_frames(app, True, True)) == before
        assert_independent_values(app)
        sessions = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes,
                          keys=keys, deployment=(app.plan,app.pin))
        for tenant in (TENANT,OTHER_TENANT):
            with sessions(tenant_id=tenant) as session:
                for model, expected in ((app.Customer,app.source),(app.other,app.other_source)):
                    assert {row.id:(row.tenant_id,row.name) for row in session.scalars(
                        select(model).where(model.tenant_id==tenant))} == {
                            identity:values for identity,values in expected.items() if values[0]==tenant}
