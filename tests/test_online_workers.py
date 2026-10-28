"""Real concurrent cryptography keeps online SQL/progress atomic and bounded."""
from threading import Barrier, get_ident, local
from uuid import UUID

import pytest
from sqlalchemy import event

from cryptalis import migration as m, online
from cryptalis.crypto import InvalidValue
from test_migration import keys
from test_online_protection import app, _payloads, _source_rows, _pin


def bigger_plan(app):
    with app.source_factory() as session:
        session.add_all(app.Customer(id=UUID(int=i), body=f'body-{i}', label=f'label-{i}') for i in range(100, 132))
        session.commit()
    document = app.plan.document
    document['batch_limits']['max_rows'] = 16
    app.plan = online.OnlineProtectionPlan(m._canonical(document))
    app.pin = _pin(app.plan, 'PREPARED')


@pytest.mark.parametrize('workers', [1, 4])
def test_worker_overlap_adaptation_resume_and_current_native_abort(app, workers, monkeypatch):
    bigger_plan(app)
    expected = _source_rows(app)
    native_seal, observed, worker_state = online.seal_value, set(), local()
    barrier, row_limits = Barrier(workers), []
    def seal(*args):
        observed.add(get_ident())
        if not hasattr(worker_state, 'entered'):
            worker_state.entered = True
            barrier.wait(timeout=10)
        return native_seal(*args)
    def collect(connection, cursor, sql, parameters, context, many):
        if 'LIMIT %s FOR UPDATE' in sql and '_dirty' in sql:
            row_limits.append(parameters[0])
    event.listen(app.owner, 'before_cursor_execute', collect)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(online, 'seal_value', seal)
            progress = online.apply(app.plan, app.owner, keys=keys, pin=app.pin, approval=app.approval,
                                   workers=workers, max_chunks=4, target_chunk_seconds=1e-6)
        assert progress.committed_chunks == 4
        assert len(observed) == workers
        assert row_limits[:4] == [16, 8, 4, 2]
        completed = _payloads(app, app.plan)
        with app.source_factory() as session:
            session.get(app.Customer, UUID(int=10)).body = 'native edit after parallel chunk'
            session.commit()
        expected[UUID(int=10)] = 'native edit after parallel chunk', 'label-10'
        online.apply(type(app.plan)(app.plan.artifact), app.owner, keys=keys, pin=app.pin,
                     approval=app.approval, workers=workers, max_chunks=10, fence=True)
        final = _payloads(app, app.plan)
        assert final[UUID(int=10)] != completed[UUID(int=10)]
        for identity, frames in completed.items():
            if identity != UUID(int=10) and any(value is not None for value in frames):
                assert final[identity] == frames
        # Full authenticated proof detects lost, duplicate, or context-mixed rows.
        online.seal(app.plan, app.owner, keys=keys, pin=app.pin, approval=app.approval)
        assert online.abort(app.plan, app.owner, pin=app.pin, approval=app.approval).phase == 'ABORTED'
        assert _source_rows(app) == expected
        assert max(row_limits) <= 16
    finally:
        event.remove(app.owner, 'before_cursor_execute', collect)


def test_parallel_row_failure_leaves_no_payload_or_progress_and_retries(app, monkeypatch):
    bigger_plan(app)
    online.apply(app.plan, app.owner, keys=keys, pin=app.pin, approval=app.approval, max_chunks=0)
    before = _payloads(app, app.plan)
    native_seal = online.seal_value
    def fail(value, *args):
        if value == 'body-20':
            raise InvalidValue()
        return native_seal(value, *args)
    with monkeypatch.context() as patch:
        patch.setattr(online, 'seal_value', fail)
        with pytest.raises(m.TransitionFailure) as failure:
            online.apply(app.plan, app.owner, keys=keys, pin=app.pin, approval=app.approval,
                         workers=4, max_chunks=1)
    assert failure.value.code == 'InvalidValue'
    assert _payloads(app, app.plan) == before
    assert online.status(app.plan, app.owner, pin=app.pin).committed_chunks == 0
    assert online.apply(app.plan, app.owner, keys=keys, pin=app.pin, approval=app.approval,
                        workers=4, max_chunks=1).committed_chunks == 1


@pytest.mark.parametrize('options', [{'workers': 0}, {'workers': 17}, {'workers': True},
    {'target_chunk_seconds': 0}, {'target_chunk_seconds': float('nan')}, {'target_chunk_seconds': 61}])
def test_invalid_execution_bounds_refuse_before_database_access(options):
    with pytest.raises(m.TransitionFailure) as failure:
        online.apply(None, None, keys=None, pin=None, approval=None, **options)
    assert failure.value.code == 'invalid_online_worker_bound'
