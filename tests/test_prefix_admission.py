"""Ordinary prefix entry points refuse before SQL or key access."""
from dataclasses import replace
import json

import pytest
from sqlalchemy import select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from cryptalis import migration as m
from cryptalis._search_layout import _prefix_qualification
from cryptalis.crypto.keys import PrefixCapabilityUnadmitted
from cryptalis.manifest.compiler import compile_protection
from cryptalis.sqlalchemy import attach
from test_prefix_lifecycle import configuration
from test_prefix_search import BOUNDS, configured, TENANT, keys, publish, run


def test_prefix_plan_saved_plan_apply_status_and_attach_require_admission_before_effects(monkeypatch):
    # A synthetic fixture may prepare the internal format. Ordinary callers
    # still cannot use either its declaration or saved artifact.
    with _prefix_qualification():
        with configured() as app:
            config = configuration(app, ['equality', 'prefix'], BOUNDS)
            lock = app.plan.lock_bytes
            target = app.plan.target_id
            with Session(app.runtime) as session:
                before = list(session.execute(select(app.Customer.id, app.Customer.name).order_by(app.Customer.id)))
            samples = replace(config, queries=(select(app.Customer.id).where(app.Customer.name.like('a%')),))
            diagnosis = samples.diagnose(app.owner)
            assert diagnosis['status'] == 'UNKNOWN'
            assert diagnosis['checks']['manifest_schema'] == 'PASS'
            assert diagnosis['checks']['query_samples'] == 'PASS'
            assert diagnosis['query_samples']['execution'] == 'NOT_PERFORMED'
            assert diagnosis['query_samples']['items'] == [{'index': 0, 'status': 'STRUCTURE_ADMITTED'}]
            assert diagnosis['checks']['provider_keys'] == 'UNKNOWN'
            unsupported = replace(config, queries=(select(app.Customer.id).where(app.Customer.name.contains('alpha')),))
            assert unsupported.diagnose(app.owner)['status'] == 'FAIL'
            observations = []
            declaration = json.loads(lock)['declaration']
            for model in declaration['models']:
                for field in model['fields']:
                    field.update(queries=[], accept_leakage=[])
                    field.pop('prefix_lengths', None)
            def forbidden(*args, **kwargs):
                observations.append(True)
                raise AssertionError('Unadmitted prefix reached SQL or keys.')
            with _prefix_qualification(False), monkeypatch.context() as patch:
                patch.setattr(Engine, 'connect', forbidden)
                actions = (
                    lambda: config.plan(app.owner, keys=forbidden, runtime_role=app.role, target_id=target,
                        backfill_rows_per_second=1000, verify_rows_per_second=1000,
                        temporary_bytes_per_row=4096, wal_bytes_per_row=8192),
                    lambda: m.MigrationPlan(app.plan.artifact).document,
                    lambda: m.apply(app.plan, app.owner, keys=forbidden, pin=app.pin,
                                    approval=app.approval, until='PENDING'),
                    lambda: m.status(app.plan, app.owner, pin=app.pin),
                    lambda: attach(app.mapping, app.runtime, lock=lock, keys=forbidden,
                                   deployment=(app.plan, app.pin)),
                    lambda: compile_protection(json.dumps(declaration).encode(), app.mapping, app.owner,
                        writers=config.writers, previous_lock=lock),
                    lambda: m.check_attachment(None, lock, None),
                )
                for action in actions:
                    with pytest.raises(PrefixCapabilityUnadmitted):
                        action()
                diagnosis = samples.diagnose(app.owner)
                assert diagnosis['status'] == 'FAIL'
                assert diagnosis['issues'][0]['code'] == 'Capability.Unadmitted'
                assert observations == []
            with Session(app.runtime) as session:
                assert list(session.execute(select(app.Customer.id, app.Customer.name).order_by(app.Customer.id))) == before
            with app.owner.connect() as connection:
                assert connection.exec_driver_sql('SELECT pg_catalog.to_regclass(%s)',
                    (f'"{app.schema}"._cryptalis_journal',)).scalar_one() is None


def test_retained_prefix_factory_session_and_result_cannot_escape_synthetic_scope(monkeypatch):
    with _prefix_qualification(), configured() as app:
        run(app); publish(app)
        calls = []
        def resolve(tenant):
            calls.append('keys')
            return keys(tenant)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=resolve,
                         deployment=(app.plan, app.pin))
        with factory(tenant_id=TENANT) as session:
            row = session.get(app.Customer, next(iter(app.source)))
            result = session.execute(select(app.Customer.name).where(app.Customer.tenant_id == TENANT))
            before = len(calls)
            def forbidden(*args, **kwargs):
                calls.append('sql')
                raise AssertionError('Retained prefix runtime reached SQL.')
            with _prefix_qualification(False), monkeypatch.context() as patch:
                patch.setattr(Engine, 'connect', forbidden)
                for action in (
                    lambda: factory(tenant_id=TENANT),
                    lambda: session.get(app.Customer, row.id),
                    lambda: session.execute(select(app.Customer.id)),
                    result.first,
                ):
                    with pytest.raises(PrefixCapabilityUnadmitted):
                        action()
                assert len(calls) == before
            assert session.get(app.Customer, row.id) is row


def test_saved_prefix_disable_activation_refuses_before_sql_or_keys(monkeypatch):
    from test_application_modification import prepare, propose, seal
    from test_deprotection import app_pin
    with _prefix_qualification(), configured() as app:
        run(app); publish(app)
        config = configuration(app, ['equality'])
        proposal = propose(config, app)
        prepare(config, app, proposal)
        successor = seal(config, app, proposal)
        assert successor.document['lock']['schema'] != 'cryptalis.lock/v14'
        assert successor.document['profile_source_lock']['schema'] == 'cryptalis.lock/v14'
        pin = app_pin(successor, 'PREPARED')
        observations = []
        def forbidden(*args, **kwargs):
            observations.append(True)
            raise AssertionError('Saved prefix activation reached SQL or keys.')
        with _prefix_qualification(False), monkeypatch.context() as patch:
            patch.setattr(Engine, 'connect', forbidden)
            for action in (
                lambda: successor.document,
                lambda: m.MigrationPlan(successor.artifact),
                lambda: m.status(successor, app.owner, pin=pin),
                lambda: m.apply(successor, app.owner, keys=forbidden, pin=pin,
                                approval=app.approval, until='PENDING'),
            ):
                with pytest.raises(PrefixCapabilityUnadmitted):
                    action()
            assert observations == []
