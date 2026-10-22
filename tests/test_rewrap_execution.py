"""Native root-custody cutover, restart inspection and decrypt-back oracles."""
from dataclasses import asdict, replace
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Column, MetaData, Table, Text, Uuid, create_engine, select
from sqlalchemy.orm import registry
from sqlalchemy.exc import DBAPIError

from cryptalis import migration as m, rotation as r
from cryptalis.sqlalchemy import attach
from test_migration import application, frames, keys, publish, run, TENANT
from test_rewrap_plan import _target, _snapshot
from test_deprotection import app_pin, consent, d, least_privilege_role, native_rows, reverse


def proposal(app, source=keys):
    target, provider = _target(source if callable(source) else lambda tenant: source)
    plan = r.plan_rewrap(app.plan, app.owner, source_pin=app.pin, keys=source,
                         target_keys=target, verify_rows_per_second=1000)
    return plan, target, provider


def apply(app, plan, target, source=keys, phase='PREPARED', **kwargs):
    return r.apply_rewrap(plan, app.owner, keys=source, target_keys=target,
                          pin=app_pin(plan.activation_plan, phase), approval=app.approval, **kwargs)


def activate(app, plan, target):
    successor = plan.activation_plan
    result = m.apply(successor, app.owner, keys=target,
                     pin=app_pin(successor, 'ACTIVATING'), approval=app.approval, until='ACTIVE')
    assert result.phase == 'ACTIVE'
    app.plan, app.pin = successor, app_pin(successor, 'ACTIVE')


def target_factory(app, target):
    mapping = registry(metadata=MetaData(schema=app.schema))
    table = Table('customer', mapping.metadata, Column('id', Uuid, primary_key=True, autoincrement=False),
                  Column('tenant_id', Uuid, nullable=False), Column('name', Text(collation='C')),
                  Column('label', Text))
    class Customer: pass
    mapping.map_imperatively(Customer, table)
    return mapping, Customer, attach(mapping, app.runtime, lock=app.plan.lock_bytes,
                                     keys=target, deployment=(app.plan, app.pin))


def test_rewrap_switch_preserves_frames_and_reuses_publication_and_native_search():
    with application() as app:
        run(app); publish(app)
        source, old_pin = app.plan, app.pin
        plan, target, _ = proposal(app)
        before = frames(app, True)
        successor = plan.activation_plan
        assert successor.document['kind'] == 'rewrap'
        assert successor.operation_id == plan.operation_id
        assert successor.lock_bytes == source.lock_bytes
        assert m.MigrationPlan(successor.artifact).artifact == successor.artifact
        assert apply(app, plan, target).phase == 'PENDING'
        assert frames(app, True) == before
        with pytest.raises(m.TransitionFailure, match='superseded'):
            m.check_deployment(source, app.owner, pin=old_pin)
        with pytest.raises(m.TransitionFailure):
            m.check_deployment(successor, app.owner, pin=app_pin(successor, 'ACTIVE'))
        with app.runtime.connect() as c:
            with pytest.raises(DBAPIError) as blocked:
                c.exec_driver_sql(f'UPDATE "{app.schema}".customer SET label=%s', ('paused',))
            assert blocked.value.orig.sqlstate == '55000'
        assert m.status(successor, app.owner, pin=app_pin(successor, 'PREPARED')).phase == 'PENDING'
        activate(app, plan, target)
        assert frames(app, True) == before
        mapping, Customer, sessions = target_factory(app, target)
        try:
            with sessions(tenant_id=TENANT) as session:
                actual = {row.id: (row.tenant_id, row.name) for row in session.scalars(select(Customer))}
                assert actual == app.source
                record = UUID(int=101)
                assert session.scalar(select(Customer.id).where(Customer.name == app.source[record][1])) == record
                session.get(Customer, record).name = 'current edit after root rewrap'
                session.commit()
            with sessions(tenant_id=TENANT) as session:
                assert session.get(Customer, UUID(int=101)).name == 'current edit after root rewrap'
        finally:
            mapping.dispose()


def test_pending_retry_inspects_original_identity_and_preserves_bytes():
    with application() as app:
        run(app); publish(app)
        plan, target, _ = proposal(app)
        first = apply(app, plan, target)
        before = _snapshot(app)
        assert apply(app, r.RewrapPlan(plan.artifact), target) == first
        assert _snapshot(app) == before
        activate(app, plan, target)
        before = _snapshot(app)
        assert m.apply(app.plan, app.owner, keys=target, pin=app.pin,
                       approval=app.approval, until='ACTIVE').phase == 'ACTIVE'
        assert _snapshot(app) == before


@pytest.mark.parametrize('fault', ['source_edit', 'source_journal', 'target_roots', 'target_pin', 'approval'])
def test_failed_rewrap_does_not_publish_or_modify_source(fault):
    with application() as app:
        run(app); publish(app)
        plan, target, _ = proposal(app)
        if fault == 'source_edit':
            with app.owner.begin() as c:
                c.exec_driver_sql(f'UPDATE "{app.schema}".customer SET label=%s', ('changed unprotected',))
                c.exec_driver_sql(f'DELETE FROM "{app.schema}".customer WHERE id=%s', (UUID(int=101),))
        elif fault == 'source_journal':
            with app.owner.begin() as c:
                c.exec_driver_sql(f'UPDATE "{app.schema}"."_cryptalis_journal" SET state=state || %s::jsonb',
                                  (json.dumps({'unexpected': True}),))
        elif fault == 'target_roots':
            target = keys(TENANT)
        before = _snapshot(app)
        pin = app_pin(plan.activation_plan, 'PREPARED')
        approval = app.approval
        if fault == 'target_pin': pin = replace(pin, plan_digest='0'*64)
        if fault == 'approval': approval = m.MaintenanceApproval('', 0)
        with pytest.raises(m.TransitionFailure):
            r.apply_rewrap(plan, app.owner, keys=keys, target_keys=target, pin=pin, approval=approval)
        assert _snapshot(app) == before
        assert m.status(app.plan, app.owner, pin=app.pin).phase == 'ACTIVE'


def test_target_failure_during_publication_keeps_writer_fence():
    with application() as app:
        run(app); publish(app)
        plan, target, _ = proposal(app)
        apply(app, plan, target)
        before = _snapshot(app)
        with pytest.raises(m.TransitionFailure):
            m.apply(plan.activation_plan, app.owner, keys=keys,
                     pin=app_pin(plan.activation_plan, 'ACTIVATING'), approval=app.approval, until='ACTIVE')
        assert _snapshot(app) == before
        assert m.status(plan.activation_plan, app.owner,
                        pin=app_pin(plan.activation_plan, 'PREPARED')).phase == 'PENDING'
        activate(app, plan, target)


def test_two_rewraps_preserve_current_values_through_native_decrypt_back_and_removal():
    with application() as app:
        run(app); publish(app)
        original_frames = frames(app, True)
        current = keys
        for _ in range(2):
            plan, target, _ = proposal(app, current)
            apply(app, plan, target, current)
            activate(app, plan, target)
            current = target
        assert frames(app, True) == original_frames
        assert len(app.plan.document['predecessors']) == 2
        mapping, Customer, sessions = target_factory(app, current)
        try:
            with sessions(tenant_id=TENANT) as session:
                session.get(Customer, UUID(int=101)).name = 'latest edit after two custody changes'
                session.commit()
            app.source[UUID(int=101)] = (TENANT, 'latest edit after two custody changes')
        finally:
            mapping.dispose()
        reverse_plan = d.plan(app.plan, app.owner, source_pin=app.pin, keys=current,
            plaintext_runtime_role=least_privilege_role(app), backfill_rows_per_second=1000,
            verify_rows_per_second=1000, temporary_bytes_per_row=700, wal_bytes_per_row=700)
        assert reverse(app, reverse_plan, key_resolver=current).phase == 'PLAINTEXT_PENDING'
        pure, _ = consent(reverse_plan)
        assert d.apply(reverse_plan, app.owner, keys=current,
            pin=app_pin(reverse_plan, 'PLAINTEXT_ACTIVATING'), approval=app.approval,
            consent=pure, until='PLAINTEXT_ACTIVE').phase == 'PLAINTEXT_ACTIVE'
        removal = d.RemovalApproval(reverse_plan.target_id, reverse_plan.operation_id, reverse_plan.digest,
                                    'native app uses no crypto columns', 'retained public fixture roots', True)
        assert d.remove(reverse_plan, app.owner, pin=app_pin(reverse_plan, 'REMOVING'),
            approval=app.approval, removal=removal, consent=pure).phase == 'REMOVED'
        assert native_rows(app) == app.source


@pytest.mark.parametrize('fault', ['missing', 'digest', 'successor'])
def test_predecessor_tampering_blocks_reverse_admission(fault):
    with application() as app:
        run(app); publish(app)
        source = app.plan
        plan, target, _ = proposal(app)
        apply(app, plan, target)
        activate(app, plan, target)
        with app.owner.begin() as c:
            table = f'"{app.schema}"."_cryptalis_journal"'
            if fault == 'missing':
                c.exec_driver_sql(f'DELETE FROM {table} WHERE operation_id=%s', (source.operation_id,))
            elif fault == 'digest':
                c.exec_driver_sql(f'UPDATE {table} SET plan_digest=%s WHERE operation_id=%s', ('0'*64,source.operation_id))
            else:
                c.exec_driver_sql(f'UPDATE {table} SET state=state || %s::jsonb WHERE operation_id=%s',
                                  (json.dumps({'superseded_by': {'operation_id':str(uuid4()), 'plan_digest':'0'*64}}), source.operation_id))
        before = _snapshot(app)
        with pytest.raises(m.TransitionFailure):
            d.plan(app.plan, app.owner, source_pin=app.pin, keys=target,
                plaintext_runtime_role=least_privilege_role(app), backfill_rows_per_second=1000,
                verify_rows_per_second=1000, temporary_bytes_per_row=700, wal_bytes_per_row=700)
        assert _snapshot(app) == before


def test_journal_claim_of_active_does_not_skip_publication_verification():
    with application() as app:
        run(app); publish(app)
        plan, target, _ = proposal(app)
        apply(app, plan, target)
        successor = plan.activation_plan
        with app.owner.begin() as c:
            state = c.exec_driver_sql(f'SELECT state FROM "{app.schema}"."_cryptalis_journal" '
                                      'WHERE operation_id=%s', (successor.operation_id,)).scalar_one()
            m._drop_guards(c, successor)
            c.exec_driver_sql(f'DELETE FROM "{app.schema}".customer WHERE id=%s', (UUID(int=101),))
            for model in successor.document['lock']['models']:
                state['models'][model['table_id']]['active_schema'] = m._facts(c, model)
            state['phase'] = 'ACTIVE'
            m._save(c, successor, state)
        before = _snapshot(app)
        with pytest.raises(m.TransitionFailure, match='rewrap_source_changed'):
            m.apply(successor, app.owner, keys=target, pin=app_pin(successor, 'ACTIVATING'),
                     approval=app.approval, until='ACTIVE')
        assert _snapshot(app) == before


@pytest.mark.parametrize('fault', ['plan', 'pin'])
def test_invalid_apply_artifacts_refuse_before_connection(fault):
    with application() as app:
        run(app); publish(app)
        plan, _, _ = proposal(app)
        successor, pin = plan.activation_plan, app_pin(plan.activation_plan, 'ACTIVATING')
        class Closed:
            def connect(self): pytest.fail('invalid admission opened a connection')
        with pytest.raises(m.TransitionFailure, match='external_policy_mismatch'):
            m.apply(None if fault == 'plan' else successor, Closed(), keys=keys,
                     pin=None if fault == 'pin' else pin, approval=app.approval, until='ACTIVE')


@pytest.mark.parametrize('fault', ['empty_lineage', 'self_lineage', 'self_alias', 'duplicate', 'bad_digest',
                                  'missing_proof', 'bool_rows', 'missing_model', 'row_total'])
def test_malformed_successor_artifacts_have_typed_admission_failures(fault):
    with application() as app:
        run(app); publish(app)
        plan, _, _ = proposal(app)
        document = plan.activation_plan.document
        if fault == 'empty_lineage': document['predecessors'] = []
        elif fault == 'self_lineage':
            document['predecessors'][0]['operation_id'] = document['operation_id']
        elif fault == 'self_alias':
            document['operation_id'] = 'AAAAAAAA-AAAA-4AAA-AAAA-AAAAAAAAAAAA'
            document['predecessors'][0]['operation_id'] = document['operation_id'].lower()
        elif fault == 'duplicate': document['predecessors'].append(document['predecessors'][0])
        elif fault == 'bad_digest': document['predecessors'][0]['plan_digest'] = 'INVALID'
        elif fault == 'missing_proof': document.pop('rewrap_plan_digest')
        elif fault == 'bool_rows': next(iter(document['rewrap_observations'].values()))['rows'] = True
        elif fault == 'missing_model': document['rewrap_observations'] = {}
        else: document['estimates']['rows'] += 1
        with pytest.raises(m.TransitionFailure, match='invalid_plan'):
            m.MigrationPlan(m._canonical(document))


def test_lost_commit_reply_is_inspected_before_resuming_the_same_rewrap():
    import psycopg
    from migration_commit_proxy import lost_commit_reply
    with application() as app:
        run(app); publish(app)
        plan, target, _ = proposal(app)
        before = frames(app, True)
        with lost_commit_reply(os.environ['CRYPTALIS_TEST_DATABASE_URL'], commit_number=2) as (url, dropped):
            proxied = create_engine('postgresql+psycopg://', hide_parameters=True,
                                    creator=lambda: psycopg.connect(url))
            try:
                with pytest.raises(m.TransitionFailure):
                    r.apply_rewrap(plan, proxied, keys=keys, target_keys=target,
                        pin=app_pin(plan.activation_plan, 'PREPARED'), approval=app.approval)
                assert dropped.is_set()
            finally:
                proxied.dispose()
        assert frames(app, True) == before
        committed = _snapshot(app)
        assert m.status(plan.activation_plan, app.owner,
                        pin=app_pin(plan.activation_plan, 'PREPARED')).phase == 'PENDING'
        assert apply(app, plan, target).phase == 'PENDING'
        assert _snapshot(app) == committed
        activate(app, plan, target)
        assert frames(app, True) == before


def test_killed_pending_executor_resumes_from_disk_in_a_fresh_process(tmp_path):
    from rewrap_worker import target_keys
    with application() as app:
        run(app); publish(app)
        plan = r.plan_rewrap(app.plan, app.owner, source_pin=app.pin, keys=keys,
                             target_keys=target_keys, verify_rows_per_second=1000)
        before = frames(app, True)
        field = app.plan.document['lock']['models'][0]['fields'][0]
        def index_identity():
            with app.owner.connect() as c:
                return c.exec_driver_sql('SELECT c.oid::text,c.relfilenode::text FROM pg_catalog.pg_class c '
                    'JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace '
                    'WHERE n.nspname=%s AND c.relname=%s', (app.schema,field['payload_column']+'_eq')).one()
        index_before = index_identity()
        artifact, pin_file, approval_file = (tmp_path / name for name in ('plan.json','pin.json','approval.json'))
        artifact.write_bytes(plan.artifact)
        pin_file.write_text(json.dumps(asdict(app_pin(plan.activation_plan, 'PREPARED')), default=str))
        approval_file.write_text(json.dumps(asdict(app.approval)))
        command = [sys.executable, str(Path(__file__).with_name('rewrap_worker.py')),
                   str(artifact), str(pin_file), str(approval_file)]
        child = subprocess.Popen(command + ['pending','pause'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            with selectors.DefaultSelector() as ready:
                ready.register(child.stdout, selectors.EVENT_READ)
                assert ready.select(timeout=20), 'rewrap worker did not report committed progress'
            assert json.loads(child.stdout.readline())['phase'] == 'PENDING'
            assert frames(app, True) == before
            child.kill()
            child.communicate(timeout=20)
            assert child.returncode == -signal.SIGKILL
            pin_file.write_text(json.dumps(asdict(app_pin(plan.activation_plan, 'ACTIVATING')), default=str))
            restarted = subprocess.run(command + ['activate','exit'], capture_output=True, text=True, timeout=30)
            assert restarted.returncode == 0
            report = json.loads(restarted.stdout)
            assert report == {'observed':'PENDING','phase':'ACTIVE',
                              'operation_id':str(plan.operation_id),'digest':plan.activation_plan.digest}
            assert frames(app, True) == before
            assert index_identity() == index_before
            m.check_deployment(plan.activation_plan, app.owner, pin=app_pin(plan.activation_plan, 'ACTIVE'))
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=20)
