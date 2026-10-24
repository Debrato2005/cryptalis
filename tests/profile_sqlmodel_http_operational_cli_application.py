"""Opt-in unchanged HTTP/auth application through the public operational CLI.

Public fixture custody and opaque fixture email review do not qualify production
custody, host authorization, external mail or deployment behavior.
"""
from dataclasses import asdict
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
import cryptalis
from sqlmodel import Session, select

from cryptalis import deprotection as d, migration as m, rotation as r
from cryptalis.manifest.declaration import parse_protection_declaration
from cryptalis.sqlmodel import attach
from profile_sqlmodel_operational_cli_application import HOST, LAUNCH, search_keys
from profile_sqlmodel_public_slots_application import public_slots, field_frames
from profile_sqlmodel_searchable_application import native_catalog
from payload_rotation_worker import rotated_keys
from rewrap_worker import target_keys as rewrapped_keys
from sqlmodel_http_mail_workload import workflow as mail_workflow
from sqlmodel_http_package_free import run as package_free
from sqlmodel_http_workload import workflow as http_workflow
from test_deprotection import least_privilege_role
from test_migration import DOMAIN, keys
from test_sqlmodel_application import native_engine, settings, TABLE, FIELD
from test_sqlmodel_http_application import SOURCE


ROOT = Path(__file__).resolve().parents[1]


def test_original_http_auth_mail_operational_cli_rotations_and_latest_native_exit(tmp_path, monkeypatch):
    location = os.environ.get('CRYPTALIS_SQLMODEL_HTTP_SOURCE')
    if not location:
        pytest.skip('set CRYPTALIS_SQLMODEL_HTTP_SOURCE to the pinned complete HTTP snapshot')
    assert sys.version_info >= (3, 13)
    assert not any(name == 'app' or name.startswith('app.') for name in sys.modules)
    source, copied = Path(location), tmp_path / 'original'
    hashes = {}
    for name, expected in SOURCE['files'].items():
        raw = (source / name).read_bytes()
        assert hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == expected
        destination = copied / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
        hashes[name] = hashlib.sha256(raw).hexdigest()
    assert len(hashes) == 26
    backend = copied / 'backend'
    monkeypatch.syspath_prepend(str(backend))
    monkeypatch.chdir(tmp_path)
    settings(monkeypatch)
    for name, value in dict(ENVIRONMENT='local', SMTP_HOST='', SMTP_USER='', SMTP_PASSWORD='',
                           EMAILS_FROM_EMAIL='', SENTRY_DSN='', FRONTEND_HOST='http://localhost:5173').items():
        monkeypatch.setenv(name, value)
    schema = 'sqlmodel_http_cli_' + uuid4().hex
    owner = native_engine('CRYPTALIS_TEST_DATABASE_URL', schema)
    current_app = None
    process = None
    boundaries, checkpoint_phases, digests = {}, {}, {}

    def close_application():
        nonlocal current_app
        if current_app is not None:
            current_app.runtime.dispose()
            current_app.original_engine.dispose()
            current_app.mapping.dispose()
            current_app.mapping.metadata.clear()
            current_app = None
        for name in tuple(sys.modules):
            if name == 'app' or name.startswith('app.'):
                del sys.modules[name]

    def load_application(plan=None, resolver=None):
        nonlocal current_app
        close_application()
        from app.models import SQLModel, User
        from app.main import app as api
        from app.core.db import engine as original_engine
        runtime = native_engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL', schema)
        current_app = SimpleNamespace(api=api, mapping=User._sa_registry, runtime=runtime,
            original_engine=original_engine, models=SQLModel, User=User)
        if plan is None:
            current_app.factory = lambda: Session(runtime)
        else:
            sessions = attach(User._sa_registry, runtime, lock=plan.lock_bytes, keys=resolver,
                              deployment=(plan, pin(plan, 'ACTIVE')))
            current_app.factory = lambda: sessions(tenant_id=TABLE)
        return current_app

    def pin(plan, phase):
        target = plan.source.target_id if isinstance(plan, (r.PayloadRotationPlan, r.SearchRotationPlan)) else plan.target_id
        return m.DeploymentPin(target, plan.operation_id, plan.digest, phase)

    def exercise(name, retained=None):
        current = http_workflow(current_app.api, current_app.factory, retained=retained)
        assert current['is_active'] is True
        mail = mail_workflow(current_app.api, current_app.factory, current, monkeypatch)
        assert mail['smtp_messages'] == 4
        boundaries[name] = {'http_controls': current['controls'], 'local_smtp': mail,
                            'retained_latest': retained is not None, 'inactive_false': True}
        return current

    def indices():
        with owner.connect() as connection:
            return connection.exec_driver_sql('SELECT c.relname,c.oid::text,c.relfilenode::text '
                'FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid '
                'WHERE i.indrelid=\'"user"\'::regclass ORDER BY c.relname').all()

    try:
        initial = load_application()
        with owner.begin() as connection:
            connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
        initial.models.metadata.create_all(owner)
        with initial.runtime.connect() as connection:
            role = connection.exec_driver_sql('SELECT current_user').scalar_one()
        with owner.begin() as connection:
            quote = connection.dialect.identifier_preparer.quote
            connection.exec_driver_sql(f'REVOKE ALL ON SCHEMA "{schema}" FROM PUBLIC')
            connection.exec_driver_sql(f'GRANT USAGE ON SCHEMA "{schema}" TO {quote(role)}')
            connection.exec_driver_sql(f'GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA "{schema}" TO {quote(role)}')
        retained = exercise('native')
        native_slots, catalog = public_slots(owner), native_catalog(owner)
        declaration = {'schema': 'cryptalis.protection/v1', 'profile': 'cf1', 'domain_id': str(DOMAIN),
            'models': [{'model': 'User', 'table_id': str(TABLE), 'tenancy': {'single_tenant': True}, 'fields': [
                {'name': 'full_name', 'field_id': str(FIELD), 'protect': True, 'queries': [], 'accept_leakage': []},
                {'name': 'email', 'field_id': str(UUID(int=1903)), 'protect': True,
                    'queries': ['equality', 'unique'], 'accept_leakage': ['equality', 'unique']},
                {'name': 'is_active', 'field_id': str(UUID(int=1904)), 'protect': True, 'queries': [], 'accept_leakage': []}]}]}
        intent, manifest = tmp_path / 'explicit-public-intent.json', tmp_path / 'cryptalis.json'
        intent.write_text(json.dumps(declaration, indent=2))
        pin_path, approval_path = tmp_path / 'pin.json', tmp_path / 'maintenance.json'
        approval_path.write_text(json.dumps(asdict(m.MaintenanceApproval(
            'local TestClient and SMTP work completed; all inventoried writers stopped', 3600))))
        configuration_path = tmp_path / 'host.json'
        configuration = {'schema': schema, 'runtime_role': role, 'target_id': str(uuid4()),
            'declaration_path': str(intent), 'pin_path': str(pin_path), 'approval_path': str(approval_path),
            'checkpoint': str(tmp_path / 'committed-checkpoint')}
        module = 'original_http_cli_host_' + uuid4().hex
        (tmp_path / (module + '.py')).write_text(HOST)
        expected_origin = Path(cryptalis.__file__).resolve()
        source_origin = str(expected_origin.parent.parent) if expected_origin.parent.parent == ROOT / 'src' else ''
        paths = json.dumps([str(tmp_path), str(backend), str(ROOT / 'tests')])
        environment = dict(os.environ, OPERATIONAL_HOST_CONFIGURATION=str(configuration_path))

        def save_configuration():
            configuration_path.write_text(json.dumps(configuration))

        def authorize(plan, phase):
            pin_path.write_text(json.dumps(asdict(pin(plan, phase)), default=str))

        def command(*arguments):
            return [sys.executable, '-I', '-B', '-c', LAUNCH, str(expected_origin), source_origin, paths, *arguments]

        def execute(*arguments):
            result = subprocess.run(command(*arguments), env=environment, capture_output=True, text=True, timeout=60)
            assert result.returncode == 0, 'HTTP operational CLI child failed; diagnostics suppressed'
            assert result.stderr == '' and 'PRIVATE_OPERATIONAL_HOST_OR_PROVIDER' not in result.stdout
            assert all(os.environ[name] not in result.stdout for name in ('CRYPTALIS_TEST_DATABASE_URL', 'CRYPTALIS_TEST_RUNTIME_DATABASE_URL'))
            return json.loads(result.stdout)

        def killed_checkpoint(name, arguments, inspect, observed_values):
            nonlocal process
            marker = Path(configuration['checkpoint'])
            marker.unlink(missing_ok=True)
            configuration['pause_after_dispose'] = True
            save_configuration()
            process = subprocess.Popen(command(*arguments), env=environment, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, text=True)
            deadline = time.monotonic() + 45
            while not marker.exists():
                assert process.poll() is None, 'HTTP lifecycle checkpoint child exited early; diagnostics suppressed'
                assert time.monotonic() < deadline, 'HTTP lifecycle committed checkpoint was not observed'
                time.sleep(0.05)
            progress = inspect()
            assert progress.phase == ('BACKFILLED' if name in ('protection', 'reverse') else 'PENDING')
            values = observed_values()
            process.kill()
            process.communicate(timeout=15)
            assert process.returncode == -signal.SIGKILL
            configuration['pause_after_dispose'] = False
            save_configuration()
            checkpoint_phases[name] = {'phase': progress.phase, 'committed_rows': progress.committed_rows,
                                       'committed_chunks': progress.committed_chunks, 'sigkill': True}
            return values

        save_configuration()
        initialized = execute('init', '--host-context', module + ':initializing', '--out', str(manifest), '--json')
        assert initialized['status'] == 'UNKNOWN' and initialized['inspection']['checks']['manifest_schema'] == 'PASS'
        assert all(value == 'UNKNOWN' for name, value in initialized['inspection']['checks'].items() if name != 'manifest_schema')
        assert manifest.read_bytes() == parse_protection_declaration(intent.read_bytes()).canonical_bytes()
        assert initialized['manifest_digest'] == hashlib.sha256(manifest.read_bytes()).hexdigest()
        assert public_slots(owner) == native_slots and native_catalog(owner) == catalog
        plan_path = tmp_path / 'protection.json'
        execute('plan', str(manifest), '--host-context', module + ':planning', '--out', str(plan_path),
                '--layout', 'preserve-public-slots/v1', '--json')
        plan = m.MigrationPlan(plan_path.read_bytes())
        digests['protection'] = plan.digest
        authorize(plan, 'PREPARED')
        with owner.connect() as connection:
            initial_ids = {str(row[0]) for row in connection.exec_driver_sql('SELECT id FROM "user"')}
        model = plan.document['lock']['models'][0]
        prefix = killed_checkpoint('protection', ('apply', str(plan_path), '--host-context', module + ':applying',
            '--until', 'BACKFILLED', '--chunk-size', '1', '--json'),
            lambda: m.status(plan, owner, pin=pin(plan, 'PREPARED')), lambda: field_frames(owner, model, staged=True))
        assert set(prefix) == initial_ids and checkpoint_phases['protection']['committed_rows'] == len(initial_ids)
        execute('apply', str(plan_path), '--host-context', module + ':applying', '--resume', str(plan.operation_id),
                '--until', 'VERIFIED', '--chunk-size', '1', '--json')
        assert field_frames(owner, model, staged=True) == prefix
        assert execute('apply', str(plan_path), '--host-context', module + ':applying', '--json')['phase'] == 'PENDING'
        authorize(plan, 'ACTIVATING')
        assert execute('apply', str(plan_path), '--host-context', module + ':applying', '--until', 'ACTIVE', '--json')['phase'] == 'ACTIVE'
        assert field_frames(owner, model, staged=False) == prefix
        load_application(plan, keys)
        retained = exercise('protected', retained)
        rotation_indexes = indices()

        source_plan, source_pin = plan, pin(plan, 'ACTIVE')
        proposal_path, activation_path = tmp_path / 'rewrap.json', tmp_path / 'rewrap-a.json'
        authorize(plan, 'ACTIVE')
        execute('keys', 'rotate', 'rewrap', 'plan', str(plan_path), '--host-context', module + ':rewrap_planning',
                '--out', str(proposal_path), '--json')
        proposal = r.RewrapPlan(proposal_path.read_bytes())
        activation = proposal.activation_plan
        authorize(activation, 'PREPARED')
        before = field_frames(owner, model, staged=False)
        committed = killed_checkpoint('rewrap', ('keys', 'rotate', 'rewrap', 'apply', str(proposal_path),
            '--host-context', module + ':rewrap_applying', '--out', str(activation_path), '--json'),
            lambda: m.status(activation, owner, pin=pin(activation, 'PREPARED')),
            lambda: field_frames(owner, model, staged=False))
        assert committed == before and activation_path.read_bytes() == activation.artifact
        execute('keys', 'rotate', 'rewrap', 'apply', str(proposal_path), '--host-context', module + ':rewrap_applying',
                '--out', str(activation_path), '--resume', str(proposal.operation_id), '--json')
        configuration.update(rewrap_source_unavailable=True, current_target_custody=True)
        save_configuration(); authorize(activation, 'ACTIVATING')
        assert execute('keys', 'rotate', 'rewrap', 'activate', str(activation_path),
                       '--host-context', module + ':rewrap_activating', '--json')['phase'] == 'ACTIVE'
        assert field_frames(owner, model, staged=False) == before and indices() == rotation_indexes
        with pytest.raises(m.TransitionFailure): m.check_deployment(source_plan, owner, pin=source_pin)
        digests['rewrap_proposal'], digests['rewrap_activation'] = proposal.digest, activation.digest
        plan, plan_path = activation, activation_path
        load_application(plan, rewrapped_keys)
        retained = exercise('rewrapped', retained)

        for purpose, constructor, resolver in (('payload', r.PayloadRotationPlan, rotated_keys),
                                               ('search', r.SearchRotationPlan, search_keys)):
            source_plan, source_pin = plan, pin(plan, 'ACTIVE')
            authorize(plan, 'ACTIVE')
            proposal_path, activation_path = tmp_path / (purpose + '.json'), tmp_path / (purpose + '-a.json')
            def action(name, path, *extra):
                return ('keys', 'rotate', purpose, name, str(path), '--host-context', module + ':' + purpose + '_' + {
                    'plan': 'planning', 'apply': 'applying', 'status': 'status', 'seal': 'sealing',
                    'switch': 'switching', 'activate': 'activating'}[name], *extra, '--json')
            execute(*action('plan', plan_path, '--out', str(proposal_path)))
            preparation = constructor(proposal_path.read_bytes())
            authorize(preparation, 'PREPARED')
            before = field_frames(owner, model, staged=False)
            assert execute(*action('apply', proposal_path, '--max-chunks', '1'))['phase'] == 'EXPANDED'
            assert execute(*action('apply', proposal_path, '--resume', str(preparation.operation_id)))['phase'] == 'BACKFILLED'
            assert execute(*action('status', proposal_path))['verification'] == 'NOT_PERFORMED'
            sealed = execute(*action('seal', proposal_path, '--out', str(activation_path)))
            assert 'phase' not in sealed and 'known_result' not in sealed
            activation = m.MigrationPlan(activation_path.read_bytes())
            repeated = tmp_path / (purpose + '-identical-a.json')
            execute(*action('seal', proposal_path, '--out', str(repeated)))
            assert repeated.read_bytes() == activation_path.read_bytes()
            fields = sorted(model['fields'], key=lambda field: field['column'])
            with owner.connect() as connection:
                quote = connection.dialect.identifier_preparer.quote
                columns = [quote(field['payload_column'] + '_rotation') for field in fields]
                staged = {str(row[0]): tuple(None if value is None else bytes(value) for value in row[1:])
                    for row in connection.exec_driver_sql('SELECT id,' + ','.join(columns) + ' FROM "user" ORDER BY id')}
            for identity, values in staged.items():
                for field, old, frame in zip(fields, before[identity], values):
                    if purpose == 'search' and field['column'] != 'email':
                        assert frame == old
                    elif frame is not None:
                        assert frame != old and int.from_bytes(frame[6:10], 'big') == 2
                        if purpose == 'payload':
                            assert frame[10:14] == old[10:14]
                            if field['column'] == 'email': assert frame[14:46] == old[14:46]
                        else:
                            assert frame[:10] == old[:10] and int.from_bytes(frame[10:14], 'big') == 2
                            assert frame[14:46] != old[14:46] and frame[46:58] != old[46:58]
                    else: assert old is None
            authorize(activation, 'PREPARED')
            switched = killed_checkpoint(purpose, action('switch', proposal_path, '--activation', str(activation_path)),
                lambda: m.status(activation, owner, pin=pin(activation, 'PREPARED')),
                lambda: field_frames(owner, model, staged=False))
            assert switched == staged
            configuration[purpose + '_source_unavailable'] = True
            save_configuration()
            assert execute(*action('switch', proposal_path, '--activation', str(activation_path),
                '--resume', str(activation.operation_id)))['phase'] == 'PENDING'
            authorize(activation, 'ACTIVATING')
            assert execute(*action('activate', activation_path))['phase'] == 'ACTIVE'
            configuration['current_' + purpose + '_custody'] = True
            save_configuration()
            assert indices() == rotation_indexes and public_slots(owner, native_slots) == native_slots
            with pytest.raises(m.TransitionFailure): m.check_deployment(source_plan, owner, pin=source_pin)
            digests[purpose + '_proposal'], digests[purpose + '_activation'] = preparation.digest, activation.digest
            plan, plan_path = activation, activation_path
            load_application(plan, resolver)
            retained = exercise(purpose + '_published', retained)

        authorize(plan, 'ACTIVE')
        configuration['plaintext_runtime_role'] = least_privilege_role(SimpleNamespace(owner=owner, role=role))
        save_configuration()
        reverse_path = tmp_path / 'reverse.json'
        execute('plan', '--reverse', str(plan_path), '--host-context', module + ':reverse_planning', '--out', str(reverse_path), '--json')
        reverse = d.DeprotectionPlan(reverse_path.read_bytes())
        digests['reverse'] = reverse.digest
        consent = d.PlaintextApproval(reverse.target_id, reverse.operation_id, reverse.digest, True, 'public disposable HTTP backup obligations')
        consent_path, removal_path = tmp_path / 'plaintext-consent.json', tmp_path / 'removal.json'
        consent_path.write_text(json.dumps(asdict(consent), default=str))
        configuration.update(consent_path=str(consent_path), removal_path=str(removal_path))
        with current_app.factory() as session:
            expected_plaintext = {str(row.id): (row.email, row.full_name, row.is_active)
                for row in session.exec(select(current_app.User)).all()}
        with owner.connect() as connection:
            source_ids = {str(row[0]) for row in connection.exec_driver_sql('SELECT id FROM "user"')}
        assert set(expected_plaintext) == source_ids
        authorize(reverse, 'PREPARED')
        def plaintext_staging():
            fields = sorted(reverse.document['lock']['models'][0]['fields'], key=lambda field: field['column'])
            with owner.connect() as connection:
                quote = connection.dialect.identifier_preparer.quote
                columns = [quote('_cryptalis_' + UUID(field['field_id']).hex + '_plain') for field in fields]
                return {str(row[0]): tuple(row[1:]) for row in connection.exec_driver_sql('SELECT id,' + ','.join(columns) + ' FROM "user" ORDER BY id')}
        staged = killed_checkpoint('reverse', ('rollback', str(reverse_path), '--host-context', module + ':reversing',
            '--until', 'BACKFILLED', '--chunk-size', '1', '--json'),
            lambda: d.status(reverse, owner, pin=pin(reverse, 'PREPARED')), plaintext_staging)
        assert staged == expected_plaintext and checkpoint_phases['reverse']['committed_rows'] == len(source_ids)
        execute('rollback', str(reverse_path), '--host-context', module + ':reversing', '--resume', str(reverse.operation_id),
                '--until', 'VERIFIED', '--chunk-size', '1', '--json')
        assert plaintext_staging() == staged
        assert execute('rollback', str(reverse_path), '--host-context', module + ':reversing', '--json')['phase'] == 'PLAINTEXT_PENDING'
        authorize(reverse, 'PLAINTEXT_ACTIVATING')
        assert execute('apply', str(reverse_path), '--host-context', module + ':reversing', '--until', 'PLAINTEXT_ACTIVE', '--json')['phase'] == 'PLAINTEXT_ACTIVE'
        native = load_application()
        with native.factory() as session:
            latest = session.get(native.User, UUID(retained['id']))
            assert (latest.email, latest.full_name, latest.is_active) == (retained['email'], retained['full_name'], True)
            assert session.get(native.User, UUID(retained['inactive']['id'])).is_active is False
        retained = exercise('plaintext_published', retained)
        removal = d.RemovalApproval(reverse.target_id, reverse.operation_id, reverse.digest,
            'original HTTP/JWT restart with Cryptalis imports denied', 'public retained fixture readers only', True)
        removal_path.write_text(json.dumps(asdict(removal), default=str))
        authorize(reverse, 'REMOVING')
        assert execute('remove', str(reverse_path), '--host-context', module + ':removing', '--json')['phase'] == 'REMOVED'
        authorize(reverse, 'REMOVED')
        assert execute('remove', str(reverse_path), '--host-context', module + ':removing', '--json')['phase'] == 'REMOVED'
        assert d.check_removed(reverse, owner, pin=pin(reverse, 'REMOVED')) is None
        assert public_slots(owner) == native_slots and native_catalog(owner) == catalog
        child = package_free(copied, schema, retained)
        assert hashes == {name: hashlib.sha256((copied / name).read_bytes()).hexdigest() for name in hashes}
        assert set(checkpoint_phases) == {'protection', 'rewrap', 'payload', 'search', 'reverse'}
        receipt = os.environ.get('CRYPTALIS_SQLMODEL_HTTP_OPERATIONAL_CLI_RECEIPT')
        if receipt:
            with Path(receipt).open('x') as stream:
                json.dump({'application_revision': SOURCE['revision'], 'application_source_sha256': hashes,
                    'model_changes': [], 'query_changes': [], 'route_changes': [],
                    'protected_fields': ['User.email', 'User.full_name', 'User.is_active'],
                    'layout': 'preserve-public-slots/v1', 'initialization_manifest_digest': initialized['manifest_digest'],
                    'initialization_inspection': initialized['inspection'], 'operation_digests': digests,
                    'http_boundaries': boundaries, 'committed_checkpoints': checkpoint_phases,
                    'payload_generation': 2, 'search_generation': 2, 'target_only_retry_and_publication': True,
                    'rotation_index_and_public_slot_identity': True, 'search_storage_frames_preserved_exactly': True,
                    'latest_value_decryptback': True, 'native_schema_restored': True, 'removed_original_http': child,
                    'runtime': {name: importlib.metadata.version(name) for name in (
                        'fastapi', 'starlette', 'httpx', 'emails', 'sqlmodel', 'pydantic', 'SQLAlchemy', 'psycopg', 'cryptography')},
                    'python': sys.version.split()[0],
                    'boundary': 'Unchanged original local TestClient HTTP/ASGI/JWT and real loopback SMTP joined to public fixture CLI lifecycle; no browser, external mail, fresh-cluster, production host/custody or deployment qualification',
                    'gates': 'all seven UNKNOWN'}, stream, indent=2)
                stream.write('\n')
    finally:
        if process is not None and process.poll() is None:
            process.kill(); process.communicate(timeout=15)
        close_application()
        with owner.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        owner.dispose()
