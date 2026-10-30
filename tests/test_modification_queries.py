"""Inspect target query structures before effects; never execute sample values."""
from dataclasses import replace
from uuid import UUID

import pytest
from sqlalchemy import event, select
from sqlalchemy.orm import Session, aliased

from cryptalis.migration import TransitionFailure
from cryptalis.modification import plan
from cryptalis.sqlalchemy import _Attachment
from test_application_modification import activate_change, configured_change
from test_migration import application, keys, publish, run, TENANT
from test_rewrap_plan import _snapshot


def options():
    return dict(backfill_rows_per_second=1000, verify_rows_per_second=1000,
                temporary_bytes_per_row=1024, wal_bytes_per_row=2048)


def test_target_query_samples_are_inspected_before_keys_and_match_native_after_publication(monkeypatch):
    with application(unique=False, queries=[]) as app:
        selection = select(app.Customer.id).where(app.Customer.name.in_(['雪😀', 'é'])).order_by(app.Customer.id)
        with Session(app.runtime) as session: expected = session.scalars(selection).all()
        other = aliased(app.Customer)
        configured = replace(configured_change(app), queries=(selection, select(other.name).where(
            other.name == 'PRIVATE_NEVER_EXECUTED'), select(app.Customer).where(app.Customer.name.is_(None))))
        run(app); publish(app)
        before, mapped_type = _snapshot(app), app.table.c.name.type
        admit = _Attachment.admit
        state = dict(inspecting=False, inspected=0, keys=0)
        def inspect(self, statement, *args, **kwargs):
            state['inspecting'] = True
            try: return admit(self, statement, *args, **kwargs)
            finally:
                state['inspecting'] = False
                state['inspected'] += 1
        def observe(connection, cursor, statement, parameters, context, many):
            assert not state['inspecting'], 'query sample inspection executed SQL'
        def resolve(tenant):
            assert not state['inspecting'] and state['inspected'] == len(configured.queries)
            state['keys'] += 1
            return keys(tenant)
        def forbidden(*args, **kwargs): pytest.fail('query inspection entered runtime attachment')
        event.listen(app.owner, 'before_cursor_execute', observe)
        try:
            with monkeypatch.context() as patch:
                patch.setattr(_Attachment, 'admit', inspect)
                for name in ('activate', 'validate', '_ring'): patch.setattr(_Attachment, name, forbidden)
                proposal = configured.plan_modification(app.owner, deployment=(app.plan, app.pin), keys=resolve, **options())
        finally: event.remove(app.owner, 'before_cursor_execute', observe)
        assert state['inspected'] == 3 and state['keys'] > 0
        assert _snapshot(app) == before and app.table.c.name.type is mapped_type
        assert b'PRIVATE_NEVER_EXECUTED' not in proposal.artifact
        activate_change(configured, app, proposal)
        factory = configured.attach(app.runtime, deployment=(app.plan, app.pin), keys=keys)
        with factory(tenant_id=TENANT) as session:
            assert session.scalars(selection).all() == expected
            assert session.scalar(select(app.Customer.id).where(app.Customer.name == '雪😀')) == UUID(int=102)


@pytest.mark.parametrize('unavailable', [False, True])
def test_failed_or_unknown_inspection_refuses_before_connection_or_keys(monkeypatch, unavailable):
    with application(unique=False, queries=[]) as app:
        configured = replace(configured_change(app), queries=(select(app.Customer).where(
            app.Customer.name.like('PRIVATE_PATTERN%')),))
        run(app); publish(app)
        before = _snapshot(app)
        def forbidden(*args, **kwargs): pytest.fail('query rejection reached database or keys')
        def interrupted(*args, **kwargs): raise RuntimeError('PRIVATE_INSPECTION_FAILURE')
        if unavailable: monkeypatch.setattr(_Attachment, 'admit', interrupted)
        event.listen(app.owner, 'engine_connect', forbidden)
        try:
            with pytest.raises(TransitionFailure) as failure:
                configured.plan_modification(app.owner, deployment=(app.plan, app.pin), keys=forbidden, **options())
        finally: event.remove(app.owner, 'engine_connect', forbidden)
        assert failure.value.code == ('query_inspection_unavailable' if unavailable else 'query_samples_incompatible')
        assert 'PRIVATE' not in str(failure.value) and _snapshot(app) == before


@pytest.mark.parametrize('queries', [None, [], (None,) * 129])
def test_direct_planner_rejects_invalid_sample_container_before_effects(queries):
    with application(unique=False, queries=[]) as app:
        configured = configured_change(app)
        run(app); publish(app)
        with pytest.raises(TransitionFailure, match='invalid_query_samples'):
            plan(app.plan, None, source_pin=app.pin, manifest=configured.manifest, mapping=app.mapping,
                writers=configured.writers, search_reviews=configured.search_reviews, keys=None,
                queries=queries, **options())
