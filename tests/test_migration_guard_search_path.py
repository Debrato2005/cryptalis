"""Writer-fence continuity survives a real application's connection search path."""
import os

import psycopg
import pytest
from sqlalchemy import create_engine

from cryptalis import migration as m
from test_migration import application, keys


def test_resume_canonicalizes_unchanged_guard_and_still_refuses_a_disabled_guard():
    with application() as app:
        assert m.apply(app.plan, app.owner, keys=keys, pin=app.pin,
                       approval=app.approval, until='EXPANDED').phase == 'EXPANDED'
        model = app.plan.document['lock']['models'][0]
        with app.owner.begin() as c:
            before = c.exec_driver_sql('SHOW search_path').scalar_one()
            canonical = m._guard_facts(c, app.plan, model)
            assert c.exec_driver_sql('SHOW search_path').scalar_one() == before
            c.exec_driver_sql("SELECT pg_catalog.set_config('search_path', %s, true)", (app.schema,))
            assert m._guard_facts(c, app.plan, model) == canonical
            assert c.exec_driver_sql('SHOW search_path').scalar_one() == app.schema
        alternate = create_engine('postgresql+psycopg://', hide_parameters=True,
            creator=lambda: psycopg.connect(os.environ['CRYPTALIS_TEST_DATABASE_URL'],
                                           options='-csearch_path=' + app.schema))
        try:
            assert m.status(app.plan, alternate, pin=app.pin).phase == 'EXPANDED'
            assert m.apply(app.plan, alternate, keys=keys, pin=app.pin,
                           approval=app.approval, until='BACKFILLED').phase == 'BACKFILLED'
            trigger = m._guard_names(app.plan, model)[0]
            with alternate.begin() as c:
                c.exec_driver_sql(f'ALTER TABLE "{app.schema}".customer DISABLE TRIGGER "{trigger}"')
            with pytest.raises(m.TransitionFailure, match='writer_fence_changed'):
                m.apply(app.plan, alternate, keys=keys, pin=app.pin, approval=app.approval)
            with alternate.begin() as c:
                c.exec_driver_sql(f'ALTER TABLE "{app.schema}".customer ENABLE REPLICA TRIGGER "{trigger}"')
                with pytest.raises(m.TransitionFailure, match='writer_fence_changed'):
                    # Replica-only execution is also a real change from the always-enabled fence.
                    m._check_guard(c, app.plan, model)
                assert c.exec_driver_sql('SHOW search_path').scalar_one() == app.schema
                c.exec_driver_sql(f'ALTER TABLE "{app.schema}".customer ENABLE ALWAYS TRIGGER "{trigger}"')
            assert m.apply(app.plan, alternate, keys=keys, pin=app.pin, approval=app.approval).phase == 'PENDING'
        finally:
            alternate.dispose()
