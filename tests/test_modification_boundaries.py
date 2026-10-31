"""Native profile transition refusal, atomic progress and publication boundaries."""
from dataclasses import replace
import json
from uuid import UUID, uuid4

import pytest
from sqlalchemy import ColumnDefault, event, select

from cryptalis.application import ConfigurationInvalid
from cryptalis.manifest.compiler import PlanningRejected, SearchReview, WriterInventory
from cryptalis.manifest.parser import ManifestInvalid
from cryptalis.migration import TransitionFailure
from cryptalis.modification import ModificationPlan
from test_application_modification import configured_change, propose, prepare, seal, activate_change
from test_deprotection import app_pin
from test_migration import application, frames, keys, publish, run, FIELD_ID, TENANT
from test_payload_rotation_execution import operation_pin, snapshot, staged_frames
from test_rewrap_plan import _snapshot


def forbidden(*args, **kwargs):
    pytest.fail('refused intent reached a database or provider')


@pytest.mark.parametrize('fault', ['no_leakage', 'small_domain', 'field_id', 'tenancy', 'unique',
    'inventory', 'queries', 'mapping_default', 'tenant_nullable', 'record_onupdate'])
def test_unsupported_intent_refuses_before_database_or_keys(fault):
    with application(unique=False, queries=[]) as app:
        configured = configured_change(app)
        run(app); publish(app)
        declaration = json.loads(configured.manifest)
        field = declaration['models'][0]['fields'][0]
        if fault == 'no_leakage': field['accept_leakage'] = []
        if fault == 'field_id': field['field_id'] = str(uuid4())
        if fault == 'tenancy': declaration['models'][0]['tenancy'] = {'single_tenant': True}
        if fault == 'unique': field.update(queries=['equality', 'unique'], accept_leakage=['equality', 'unique'])
        if fault == 'no_leakage':
            with pytest.raises(ManifestInvalid): replace(configured, manifest=json.dumps(declaration).encode())
            return
        configured = replace(configured, manifest=json.dumps(declaration).encode())
        if fault == 'small_domain': configured = replace(configured, search_reviews=(SearchReview(FIELD_ID, True, 'enumerable'),))
        if fault == 'inventory': configured = replace(configured, writers=WriterInventory(False, ()))
        if fault == 'queries': configured = replace(configured, queries=(select(app.Customer).where(
            app.Customer.name.like('PRIVATE_PATTERN%')),))
        if fault == 'mapping_default': app.table.c.name.default = ColumnDefault('private default')
        if fault == 'tenant_nullable': app.table.c.tenant_id.nullable = True
        if fault == 'record_onupdate': app.table.c.id.onupdate = ColumnDefault(uuid4)
        event.listen(app.owner, 'engine_connect', forbidden)
        try:
            with pytest.raises((TransitionFailure, PlanningRejected, ManifestInvalid, ConfigurationInvalid)):
                configured.plan_modification(app.owner, deployment=(app.plan, app.pin), keys=forbidden,
                    backfill_rows_per_second=1000, verify_rows_per_second=1000,
                    temporary_bytes_per_row=1024, wal_bytes_per_row=2048)
        finally:
            event.remove(app.owner, 'engine_connect', forbidden)


@pytest.mark.parametrize('fault', ['copied_source', 'changed_target', 'oversized_target', 'cursor_rollback', 'guard', 'pin', 'approval'])
def test_tampering_or_wrong_authority_preserves_committed_prefix(fault):
    with application(unique=False, queries=[]) as app:
        configured = configured_change(app)
        run(app); publish(app)
        proposal = propose(configured, app)
        prepare(configured, app, proposal, max_chunks=1)
        model = app.plan.document['lock']['models'][0]
        shadow = model['fields'][0]['payload_column'] + '_rotation'
        with app.owner.begin() as connection:
            if fault == 'copied_source':
                connection.exec_driver_sql(f'UPDATE "{app.schema}".customer SET "{shadow}"=name WHERE id=%s', (UUID(int=101),))
            if fault == 'changed_target':
                connection.exec_driver_sql(f'UPDATE "{app.schema}".customer SET "{shadow}"=pg_catalog.set_byte("{shadow}",'
                    f'octet_length("{shadow}")-1,pg_catalog.get_byte("{shadow}",octet_length("{shadow}")-1) # 1) WHERE id=%s', (UUID(int=101),))
            if fault == 'oversized_target':
                connection.exec_driver_sql(f'UPDATE "{app.schema}".customer SET "{shadow}"="{shadow}" || %s WHERE id=%s', (b'x' * 1024, UUID(int=101)))
            if fault == 'cursor_rollback':
                state = connection.exec_driver_sql(f'SELECT state FROM "{app.schema}"._cryptalis_journal WHERE operation_id=%s', (proposal.operation_id,)).scalar_one()
                state['models'][model['table_id']].update(rows=0, chunks=0, cursor=None)
                connection.exec_driver_sql(f'UPDATE "{app.schema}"._cryptalis_journal SET state=%s::jsonb WHERE operation_id=%s', (json.dumps(state), proposal.operation_id))
            if fault == 'guard':
                connection.exec_driver_sql(f'ALTER TABLE "{app.schema}".customer DISABLE TRIGGER "_cryptalis_{proposal.operation_id.hex}_pause"')
        before = snapshot(app, proposal)
        pin = operation_pin(proposal)
        if fault == 'pin': pin = replace(pin, plan_digest='0' * 64)
        approval = app.approval if fault != 'approval' else app.m.MaintenanceApproval('', 0)
        with pytest.raises(TransitionFailure):
            configured.prepare_modification(app.owner, deployment=(proposal, pin), keys=keys, approval=approval)
        assert snapshot(app, proposal) == before


def test_failed_chunk_resumes_and_source_authority_cancels_without_losing_current_data(monkeypatch):
    from cryptalis import modification
    with application(unique=False, queries=[]) as app:
        configured = configured_change(app)
        run(app); publish(app)
        proposal = propose(configured, app)
        original = frames(app, True)
        prepare(configured, app, proposal, max_chunks=1)
        before = snapshot(app, proposal)
        transform = modification.transform_value
        calls = 0
        def fail_late(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2: raise RuntimeError('PRIVATE PROFILE FAILURE')
            return transform(*args, **kwargs)
        with monkeypatch.context() as patch:
            patch.setattr(modification, 'transform_value', fail_late)
            with pytest.raises(TransitionFailure) as caught: prepare(configured, app, proposal)
        assert calls == 2 and 'PRIVATE PROFILE FAILURE' not in str(caught.value)
        assert snapshot(app, proposal) == before
        assert prepare(configured, app, proposal).phase == 'BACKFILLED'
        assert configured.abort_modification(app.owner, proposal=proposal, deployment=(app.plan, app.pin),
            keys=keys, approval=app.approval).phase == 'ABORTED'
        assert frames(app, True) == original
        source_config = replace(configured, manifest=json.dumps(app.plan.document['lock']['declaration']).encode(), search_reviews=())
        factory = source_config.attach(app.runtime, deployment=(app.plan, app.pin), keys=keys)
        with factory(tenant_id=TENANT) as session:
            session.get(app.Customer, UUID(int=101)).name = 'latest after cancellation'
            session.commit()
            assert session.get(app.Customer, UUID(int=101)).name == 'latest after cancellation'
        with pytest.raises(TransitionFailure, match='operation_aborted'): prepare(configured, app, proposal)


def test_failed_index_creation_rolls_back_entire_cutover_then_retries(monkeypatch):
    with application(unique=False, queries=[]) as app:
        configured = configured_change(app)
        run(app); publish(app)
        proposal = propose(configured, app)
        prepare(configured, app, proposal)
        successor = seal(configured, app, proposal)
        before = snapshot(app, proposal)
        def refuse_index(connection, cursor, statement, parameters, context, executemany):
            if statement.startswith('CREATE INDEX'):
                raise RuntimeError('PRIVATE INDEX BUILD FAILURE')
        event.listen(app.owner, 'before_cursor_execute', refuse_index)
        try:
            with pytest.raises(TransitionFailure) as caught:
                configured.switch_modification(app.owner, proposal=proposal, deployment=(successor, app_pin(successor, 'PREPARED')),
                    keys=keys, approval=app.approval)
            assert 'PRIVATE INDEX BUILD FAILURE' not in str(caught.value)
        finally:
            event.remove(app.owner, 'before_cursor_execute', refuse_index)
        assert snapshot(app, proposal) == before
        assert configured.switch_modification(app.owner, proposal=proposal, deployment=(successor, app_pin(successor, 'PREPARED')),
            keys=keys, approval=app.approval).phase == 'PENDING'
        with pytest.raises(TransitionFailure): app.m.check_deployment(app.plan, app.owner, pin=app.pin)
        configured.apply(app.owner, deployment=(successor, app_pin(successor, 'ACTIVATING')),
            keys=keys, approval=app.approval, until='ACTIVE')


def test_plan_byte_budget_includes_grown_ciphertext_and_final_verification():
    with application(unique=False, queries=[]) as app:
        configured = configured_change(app)
        run(app); publish(app)
        before = _snapshot(app)
        values = frames(app, True)
        # UUID row + tenant, source frame, target frame and typed plaintext;
        # final target-only verification has the larger 3*target-header cost.
        bound = max(32 + (3 * (len(body) + 32) - 74 if body is not None else 0) for body in values.values())
        with pytest.raises(TransitionFailure): propose(configured, app, max_batch_bytes=bound - 1)
        assert _snapshot(app) == before
        proposal = propose(configured, app, max_batch_bytes=bound)
        assert proposal.document['estimates']['staging_payload_bytes'] == sum(len(body) + 32 for body in values.values() if body is not None)
        activate_change(configured, app, proposal)


@pytest.mark.parametrize('fault', ['target_descriptor', 'policy', 'generation', 'boolean_cost', 'operation', 'target_rows'])
def test_retained_proposal_rejects_forged_contract_or_cost(fault):
    with application(unique=False, queries=[]) as app:
        configured = configured_change(app)
        run(app); publish(app)
        document = propose(configured, app).document
        if fault == 'target_descriptor': document['target_lock']['models'][0]['fields'][0]['descriptor']['field_id'] = str(uuid4())
        if fault == 'policy': document['key_policies'][str(TENANT)]['target'] = '0' * 64
        if fault == 'generation': document['key_policies'][str(TENANT)]['search_generation'] = None
        if fault == 'boolean_cost': document['estimates']['backfill_seconds_estimate'] = True
        if fault == 'operation': document['successor_operation_id'] = document['operation_id']
        if fault == 'target_rows': next(iter(document['models'].values()))['target_frame_bytes'] = 0
        with pytest.raises(TransitionFailure, match='invalid_modification_plan'):
            ModificationPlan(app.m._canonical(document))
