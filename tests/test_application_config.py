"""One declaration survives diagnosis, planning, native ORM work and removal."""
import asyncio
from dataclasses import replace
import json
import os
import sys
from types import ModuleType
from uuid import UUID, uuid4

import psycopg
import pytest
from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import Session

from cryptalis.application import ApplicationConfig, ConfigurationInvalid
from cryptalis.crypto import Keyring
from cryptalis.manifest.compiler import SearchReview, Writer, WriterInventory
from cryptalis.migration import TransitionFailure
from test_deprotection import consent, d, native_rows, proposal, reverse
from test_migration import application, engine, frames, keys, publish, run, FIELD_ID, TABLE_ID, TENANT
from test_operational_cli import invoke
from test_owned_sequences import _snapshot


def config(app, **overrides):
    args = dict(manifest=json.dumps(app.plan.document['lock']['declaration'], indent=2).encode(),
        mapping=app.mapping,
        writers=WriterInventory(True, (Writer(TABLE_ID, 'app', 'sqlalchemy', evidence='owned synthetic application'),)),
        search_reviews=(SearchReview(FIELD_ID, False, 'synthetic unbounded names'),),
        queries=(select(app.Customer).where(app.Customer.name == 'PRIVATE_SAMPLE'),))
    args.update(overrides)
    return ApplicationConfig(**args)


def authority(app, resolver=keys):
    return dict(keys=resolver, runtime_role=app.role, target_id=app.plan.target_id,
        backfill_rows_per_second=1000, verify_rows_per_second=1000,
        temporary_bytes_per_row=700, wal_bytes_per_row=2000)


@pytest.mark.parametrize('adapter,asynchronous', [('sqlalchemy', False), ('sqlalchemy', True),
                                                 ('sqlmodel', False), ('sqlmodel', True)])
def test_shared_configuration_native_values_search_edit_and_removal(adapter, asynchronous, monkeypatch):
    if adapter == 'sqlmodel': pytest.importorskip('sqlmodel')
    with application() as app:
        configured = config(app)
        before = _snapshot(app)
        def forbidden(*args, **kwargs): pytest.fail('diagnosis must not prepare provider keys')
        with monkeypatch.context() as no_keys:
            no_keys.setattr(Keyring, 'prepare', forbidden)
            report = configured.diagnose(app.owner)
        assert report['checks']['manifest_schema'] == report['checks']['query_samples'] == 'PASS'
        assert report['status'] == report['checks']['query_routes'] == 'UNKNOWN'
        assert _snapshot(app) == before
        app.plan = configured.plan(app.owner, **authority(app))
        app.pin = replace(app.pin, operation_id=app.plan.operation_id, plan_digest=app.plan.digest)
        assert _snapshot(app) == before
        statement = select(app.Customer.id, app.Customer.name).where(app.Customer.tenant_id == TENANT).order_by(app.Customer.id)
        with Session(app.runtime) as native: expected = list(native.execute(statement))
        run(app); publish(app)
        assert all(type(value) is bytes or value is None for value in frames(app, True).values())
        def exercise_sync():
            factory = configured.attach(app.runtime, keys=keys, deployment=(app.plan, app.pin), adapter=adapter)
            with factory(tenant_id=TENANT) as session:
                assert list(session.execute(statement)) == expected
                session.get(app.Customer, UUID(int=101)).name = 'current encrypted edit'
                session.commit()
                query = select(app.Customer.id).where(app.Customer.tenant_id == TENANT,
                    app.Customer.name.in_(['current encrypted edit']))
                assert session.scalars(query).all() == [UUID(int=101)]
                if adapter == 'sqlmodel':
                    from sqlmodel import select as model_select
                    assert session.exec(model_select(app.Customer.name).where(app.Customer.id == UUID(int=101),
                        app.Customer.tenant_id == TENANT)).one() == 'current encrypted edit'
        async def exercise_async():
            runtime = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
            try:
                factory = await configured.attach(runtime, keys=keys, deployment=(app.plan, app.pin), adapter=adapter)
                async with factory(tenant_id=TENANT) as session:
                    assert list((await session.execute(statement))) == expected
                    (await session.get(app.Customer, UUID(int=101))).name = 'current encrypted edit'
                    await session.commit()
                    query = select(app.Customer.id).where(app.Customer.tenant_id == TENANT,
                        app.Customer.name.in_(['current encrypted edit']))
                    assert (await session.scalars(query)).all() == [UUID(int=101)]
                    if adapter == 'sqlmodel':
                        from sqlmodel import select as model_select
                        assert (await session.exec(model_select(app.Customer.name).where(app.Customer.id == UUID(int=101),
                            app.Customer.tenant_id == TENANT))).one() == 'current encrypted edit'
            finally:
                await runtime.dispose()
        if asynchronous: asyncio.run(exercise_async())
        else: exercise_sync()
        expected_values = dict(app.source)
        expected_values[UUID(int=101)] = (TENANT, 'current encrypted edit')
        removal_plan = proposal(app)
        assert reverse(app, removal_plan).phase == 'PLAINTEXT_PENDING'
        approval, pin = consent(removal_plan, 'PLAINTEXT_ACTIVATING')
        d.apply(removal_plan, app.owner, keys=keys, pin=pin, approval=app.approval,
                consent=approval, until='PLAINTEXT_ACTIVE')
        removal = d.RemovalApproval(removal_plan.target_id, removal_plan.operation_id, removal_plan.digest,
            'native fixture current values verified', 'public fixture custody retained', True)
        assert d.remove(removal_plan, app.owner, pin=replace(pin, phase='REMOVING'), approval=app.approval,
            removal=removal, consent=approval).phase == 'REMOVED'
        assert native_rows(app) == expected_values


@pytest.mark.parametrize('fault', ['domain', 'field', 'queries', 'deployment', 'adapter',
                                 'writer', 'incomplete_inventory', 'review'])
def test_configuration_drift_and_invalid_attachment_refuse_before_database_or_keys(monkeypatch, fault):
    with application() as app:
        configured = config(app)
        declaration = json.loads(configured.manifest)
        if fault == 'domain': declaration['domain_id'] = str(uuid4())
        if fault == 'field': declaration['models'][0]['fields'][0]['field_id'] = str(uuid4())
        if fault == 'queries':
            declaration['models'][0]['fields'][0].update(queries=[], accept_leakage=[])
        configured = replace(configured, manifest=json.dumps(declaration).encode())
        if fault == 'writer':
            configured = replace(configured, writers=WriterInventory(True, configured.writers.writers +
                (Writer(TABLE_ID, 'added route', 'raw_sql', True, 'new excluded route'),)))
        if fault == 'incomplete_inventory': configured = replace(configured, writers=WriterInventory(False, ()))
        if fault == 'review': configured = replace(configured, search_reviews=(SearchReview(FIELD_ID, False, 'changed review'),))
        def forbidden(*args, **kwargs): pytest.fail('configuration refusal reached database or keys')
        event.listen(app.runtime, 'engine_connect', forbidden)
        try:
            with pytest.raises(ConfigurationInvalid) as failure:
                configured.attach(app.runtime, keys=forbidden,
                    deployment=None if fault == 'deployment' else (app.plan, app.pin),
                    adapter='PRIVATE_INVALID_ADAPTER' if fault == 'adapter' else 'sqlalchemy')
            assert 'PRIVATE' not in str(failure.value)
            assert failure.value.code == ('Application.InvalidDeployment' if fault == 'deployment' else
                'Application.InvalidAdapter' if fault == 'adapter' else
                'Application.HostEvidenceMismatch' if fault in ('writer', 'review', 'incomplete_inventory') else
                'Application.ManifestMismatch')
        finally: event.remove(app.runtime, 'engine_connect', forbidden)


@pytest.mark.parametrize('unavailable', [False, True])
def test_query_admission_blocks_python_and_cli_planning_before_key_resolution(tmp_path, monkeypatch, capsys, unavailable):
    with application() as app:
        configured = config(app, queries=(select(app.Customer).where(app.Customer.name.like('PRIVATE_SAMPLE%')),))
        before = _snapshot(app)
        if unavailable:
            # A local admission fault is not a successful or complete inspection.
            from cryptalis.sqlalchemy import _Attachment
            def interrupted(*args, **kwargs): raise RuntimeError('PRIVATE_INSPECTION_FAILURE')
            monkeypatch.setattr(_Attachment, 'admit', interrupted)
        assert configured.diagnose(app.owner)['checks']['query_samples'] == ('UNKNOWN' if unavailable else 'FAIL')
        def forbidden(*args, **kwargs): pytest.fail('incompatible query reached key resolver')
        with pytest.raises(TransitionFailure) as failure:
            configured.plan(app.owner, **authority(app, forbidden))
        expected_code = 'query_inspection_unavailable' if unavailable else 'query_samples_incompatible'
        assert failure.value.code == expected_code
        module = ModuleType('configuration_query_' + uuid4().hex)
        module.factory = lambda: configured.planning_context(engine('CRYPTALIS_TEST_DATABASE_URL'), **authority(app, forbidden))
        monkeypatch.setitem(sys.modules, module.__name__, module)
        manifest, output = tmp_path / 'intent.json', tmp_path / 'plan.json'
        manifest.write_bytes(configured.manifest)
        code, text, error = invoke(capsys, 'plan', str(manifest), '--host-context', module.__name__ + ':factory',
                                  '--out', str(output), '--json')
        assert code == (4 if unavailable else 2) and text == '' and json.loads(error)['error']['code'] == expected_code
        assert 'PRIVATE_SAMPLE' not in error and 'PRIVATE_INSPECTION_FAILURE' not in error
        assert not output.exists() and _snapshot(app) == before


@pytest.mark.parametrize('mismatch', [False, True])
def test_shared_configuration_cli_doctor_init_and_manifest_bound_plan(tmp_path, monkeypatch, capsys, mismatch):
    with application() as app:
        configured, observed = config(app), {'connect': 0, 'dispose': 0, 'keys': 0}
        def owned():
            e = engine('CRYPTALIS_TEST_DATABASE_URL')
            event.listen(e, 'connect', lambda *args: observed.__setitem__('connect', observed['connect'] + 1))
            event.listen(e, 'engine_disposed', lambda *args: observed.__setitem__('dispose', observed['dispose'] + 1))
            return e
        def resolver(tenant):
            observed['keys'] += 1
            return keys(tenant)
        module = ModuleType('application_configuration_' + uuid4().hex)
        module.inspect_context = lambda: configured.initialization_context(owned())
        module.plan_context = lambda: configured.planning_context(owned(), **authority(app, resolver))
        monkeypatch.setitem(sys.modules, module.__name__, module)
        manifest, output = tmp_path / 'intent.json', tmp_path / 'plan.json'
        before = _snapshot(app)
        code, text, error = invoke(capsys, 'doctor', '--initialization-context', module.__name__ + ':inspect_context', '--json')
        assert code == 0 and error == '' and observed['keys'] == 0
        assert json.loads(text)['checks']['query_samples'] == 'PASS'
        code, text, error = invoke(capsys, 'init', '--host-context', module.__name__ + ':inspect_context',
                                  '--out', str(manifest), '--json')
        assert code == 0 and error == '' and manifest.read_bytes() == configured.manifest
        if mismatch:
            changed = json.loads(configured.manifest);changed['domain_id'] = str(uuid4())
            manifest.write_text(json.dumps(changed))
        observed.update(connect=0, dispose=0, keys=0)
        code, text, error = invoke(capsys, 'plan', str(manifest), '--host-context', module.__name__ + ':plan_context',
                                  '--out', str(output), '--json')
        if mismatch:
            assert code == 2 and text == '' and json.loads(error)['error']['code'] == 'ManifestMismatch'
            assert observed == {'connect': 0, 'dispose': 1, 'keys': 0} and not output.exists()
        else:
            assert code == 0 and error == '' and observed['keys'] > 0 and observed['dispose'] == 1
            planned = app.m.MigrationPlan(output.read_bytes())
            assert planned.document['lock']['declaration'] == json.loads(configured.manifest)
        assert _snapshot(app) == before
