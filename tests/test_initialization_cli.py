"""Initialization saves explicit intent after key-free native schema admission."""
import errno
import hashlib
import io
import json
import os
import stat
import sys
from types import ModuleType
from uuid import uuid4

import psycopg
import pytest
from sqlalchemy import create_engine, event

from cryptalis import cli
from cryptalis.crypto import Keyring
from cryptalis.manifest.compiler import SearchReview, Writer, WriterInventory
from cryptalis.manifest.declaration import parse_protection_declaration
from test_migration import application, engine, FIELD_ID, TABLE_ID
from test_operational_cli import invoke
from test_owned_sequences import _snapshot


def test_init_publishes_private_canonical_declaration_after_key_free_read_only_preflight(tmp_path, monkeypatch, capsys):
    with application() as app:
        supplied = json.dumps(app.plan.document['lock']['declaration'], indent=2).encode()
        expected = parse_protection_declaration(supplied).canonical_bytes()
        output = tmp_path / 'cryptalis-protection.json'
        module = ModuleType('initialization_host_' + uuid4().hex)
        observed = {'factory': 0, 'dispose': 0}

        def factory():
            # Keep the old parser RED observable rather than an import failure.
            from cryptalis.cli_host import InitializationContext
            observed['factory'] += 1
            owned = engine('CRYPTALIS_TEST_DATABASE_URL')
            event.listen(owned, 'engine_disposed', lambda *args: observed.__setitem__('dispose', observed['dispose'] + 1))
            return InitializationContext(engine=owned, mapping=app.mapping, declaration=supplied,
                writers=WriterInventory(True, (Writer(TABLE_ID, 'app', 'sqlalchemy', evidence='owned native fixture'),)),
                search_reviews=(SearchReview(FIELD_ID, False, 'public synthetic unbounded fixture names'),))

        module.factory = factory
        monkeypatch.setitem(sys.modules, module.__name__, module)
        before = _snapshot(app)
        def forbidden(*args, **kwargs):
            raise AssertionError('initialization must not prepare provider keys')
        with monkeypatch.context() as no_keys:
            no_keys.setattr(Keyring, 'prepare', forbidden)
            code, text, error = invoke(capsys, 'init', '--host-context', module.__name__ + ':factory',
                                       '--out', str(output), '--json')
        assert code == 0 and error == '', (code, error)
        assert output.read_bytes() == expected and parse_protection_declaration(output.read_bytes()).canonical_bytes() == expected
        assert stat.S_IMODE(output.stat().st_mode) == 0o600
        summary = json.loads(text)
        assert summary['scope'] == 'initialization' and summary['status'] == 'UNKNOWN'
        inspection = summary['inspection']
        assert inspection['format'] == 'cryptalis.doctor/v1' and inspection['scope'] == 'pre_adoption'
        assert inspection['checks']['manifest_schema'] == 'PASS'
        assert all(value == 'UNKNOWN' for name, value in inspection['checks'].items() if name != 'manifest_schema')
        artifact = summary['artifact_result']
        assert summary['manifest_digest'] == artifact['manifest_digest'] == hashlib.sha256(expected).hexdigest()
        assert artifact['artifact_published'] is artifact['artifact_directory_durable'] is True
        assert all(name not in summary for name in ('operation_id', 'phase', 'known_result'))
        assert all(name not in artifact for name in ('operation_id', 'phase', 'committed_rows', 'committed_chunks'))
        assert _snapshot(app) == before and observed == {'factory': 1, 'dispose': 1}


def host(app, monkeypatch, **options):
    supplied = json.dumps(app.plan.document['lock']['declaration']).encode()
    configuration = dict(declaration=supplied)
    configuration.update(options)
    observed = {'factory': 0, 'connect': 0, 'dispose': 0}
    module = ModuleType('initialization_context_' + uuid4().hex)
    def factory():
        from cryptalis.cli_host import InitializationContext, PayloadStatusContext
        observed['factory'] += 1
        if configuration.get('wrong_password'):
            owned = create_engine('postgresql+psycopg://', echo=False, hide_parameters=True,
                creator=lambda: psycopg.connect(os.environ['CRYPTALIS_TEST_DATABASE_URL'],
                    user='initialization_missing_' + uuid4().hex, password='PRIVATE_OPERATIONAL_HOST_OR_PROVIDER', connect_timeout=5))
        else:
            owned = engine('CRYPTALIS_TEST_DATABASE_URL')
        event.listen(owned, 'connect', lambda *args: observed.__setitem__('connect', observed['connect'] + 1))
        def disposed(*args):
            observed['dispose'] += 1
            if configuration.get('cleanup_failure'):
                print('PRIVATE_OPERATIONAL_HOST_OR_PROVIDER')
                raise OSError('PRIVATE_OPERATIONAL_HOST_OR_PROVIDER')
        event.listen(owned, 'engine_disposed', disposed)
        if configuration.get('wrong_context'):
            return PayloadStatusContext(engine=owned, pin=app.pin)
        if configuration.get('echo'):
            owned.echo = True
        return InitializationContext(engine=owned, mapping=app.mapping, declaration=configuration['declaration'],
            writers=WriterInventory(True, (Writer(TABLE_ID, 'app', 'sqlalchemy', evidence='owned native fixture'),)),
            search_reviews=(SearchReview(FIELD_ID, False, 'public synthetic unbounded fixture names'),))
    module.factory = factory
    monkeypatch.setitem(sys.modules, module.__name__, module)
    return module.__name__ + ':factory', configuration, observed


def command(reference, output):
    return ('init', '--host-context', reference, '--out', str(output), '--json')


def phase_free(diagnostic):
    assert all(name not in diagnostic for name in ('known_result', 'operation_id', 'phase'))
    assert diagnostic['effects'] == 'NONE' and diagnostic['effects_scope'] == 'compiler_inspection'
    assert diagnostic['host_configuration_effects'] == 'UNKNOWN'
    if 'artifact_result' in diagnostic:
        assert all(name not in diagnostic['artifact_result'] for name in ('operation_id', 'phase', 'committed_rows', 'committed_chunks'))


@pytest.mark.parametrize('fault', ['json', 'leakage', 'tenancy', 'oversized'])
def test_invalid_explicit_intent_refuses_before_connection_and_never_infers_acceptance(tmp_path, monkeypatch, capsys, fault):
    with application() as app:
        document = app.plan.document['lock']['declaration']
        if fault == 'leakage': document['models'][0]['fields'][0]['accept_leakage'] = []
        if fault == 'tenancy': document['models'][0].pop('tenancy')
        raw = json.dumps(document).encode()
        if fault == 'json': raw = b'{"schema":'
        if fault == 'oversized':
            from cryptalis.manifest.parser import MAX_DOCUMENT_BYTES
            raw = b' ' * (MAX_DOCUMENT_BYTES + 1)
        reference, _, observed = host(app, monkeypatch, declaration=raw)
        output, before = tmp_path / 'refused-intent.json', _snapshot(app)
        def forbidden(*args, **kwargs): pytest.fail('invalid intent reached provider preparation')
        with monkeypatch.context() as no_keys:
            no_keys.setattr(Keyring, 'prepare', forbidden)
            code, text, error = invoke(capsys, *command(reference, output))
        diagnostic = json.loads(error)['error']
        assert code == 2 and text == '' and diagnostic['code'] == 'Manifest.Invalid'
        phase_free(diagnostic)
        assert observed == {'factory': 1, 'connect': 0, 'dispose': 1}
        assert not output.exists() and _snapshot(app) == before


@pytest.mark.parametrize('fault', ['wrong_context', 'echo', 'declaration_type'])
def test_invalid_host_context_disposes_owned_engine_before_inspection(tmp_path, monkeypatch, capsys, fault):
    with application() as app:
        options = {fault: True} if fault != 'declaration_type' else {'declaration': '{}'}
        reference, _, observed = host(app, monkeypatch, **options)
        output, before = tmp_path / 'refused-context.json', _snapshot(app)
        code, text, error = invoke(capsys, *command(reference, output))
        diagnostic = json.loads(error)['error']
        assert code == 2 and text == ''
        assert diagnostic['code'] == ('UnsafeEngine' if fault == 'echo' else 'HostContextInvalid')
        phase_free(diagnostic)
        assert observed == {'factory': 1, 'connect': 0, 'dispose': 1}
        assert not output.exists() and _snapshot(app) == before


def test_incompatible_actual_schema_leaves_no_artifact_then_exact_repair_initializes(tmp_path, monkeypatch, capsys):
    with application() as app:
        with app.owner.begin() as connection:
            connection.exec_driver_sql(f"ALTER TABLE \"{app.schema}\".customer ALTER COLUMN name SET DEFAULT 'public unplanned default'")
        reference, _, observed = host(app, monkeypatch)
        output, before = tmp_path / 'schema-refused.json', _snapshot(app)
        code, text, error = invoke(capsys, *command(reference, output))
        diagnostic = json.loads(error)['error']
        assert code == 2 and text == '' and diagnostic['code'] == 'SchemaIncompatible'
        assert diagnostic['inspection']['status'] == diagnostic['inspection']['checks']['manifest_schema'] == 'FAIL'
        assert diagnostic['inspection']['issues'] and all(issue['remedy'] for issue in diagnostic['inspection']['issues'])
        phase_free(diagnostic)
        assert not output.exists() and _snapshot(app) == before and observed['dispose'] == 1
        with app.owner.begin() as connection:
            connection.exec_driver_sql(f'ALTER TABLE "{app.schema}".customer ALTER COLUMN name DROP DEFAULT')
        code, text, error = invoke(capsys, *command(reference, output))
        assert code == 0 and error == '' and json.loads(text)['inspection']['checks']['manifest_schema'] == 'PASS'


def test_real_unavailable_database_role_reports_unknown_without_artifact_or_private_output(tmp_path, monkeypatch, capsys):
    with application() as app:
        reference, _, observed = host(app, monkeypatch, wrong_password=True)
        output, before = tmp_path / 'unavailable.json', _snapshot(app)
        code, text, error = invoke(capsys, *command(reference, output))
        diagnostic = json.loads(error)['error']
        assert code == 4 and text == '' and diagnostic['code'] == 'InspectionUnavailable'
        inspection = diagnostic['inspection']
        assert inspection['status'] == 'UNKNOWN' and all(value == 'UNKNOWN' for value in inspection['checks'].values())
        assert inspection['issues'] and all(issue['remedy'] for issue in inspection['issues'])
        phase_free(diagnostic)
        assert observed == {'factory': 1, 'connect': 0, 'dispose': 1}
        assert not output.exists() and _snapshot(app) == before


@pytest.mark.parametrize('fault', ['output', 'directory_sync', 'cleanup'])
def test_lost_initialization_reply_retains_inspection_and_only_real_artifact_facts(tmp_path, monkeypatch, capsys, fault):
    with application() as app:
        reference, configuration, observed = host(app, monkeypatch, cleanup_failure=fault == 'cleanup')
        output, before = tmp_path / 'retained-intent.json', _snapshot(app)
        expected = parse_protection_declaration(configuration['declaration']).canonical_bytes()
        arguments = command(reference, output)
        if fault == 'output':
            with io.TextIOWrapper(io.FileIO('/dev/full', 'w'), write_through=True) as unavailable, monkeypatch.context() as stream:
                stream.setattr(sys, 'stdout', unavailable)
                code = cli.main(list(arguments))
            captured = capsys.readouterr()
            text, error = captured.out, captured.err
        elif fault == 'directory_sync':
            native = os.fsync
            def broken(descriptor):
                if stat.S_ISDIR(os.fstat(descriptor).st_mode): raise OSError(errno.EIO, 'PRIVATE_OPERATIONAL_HOST_OR_PROVIDER')
                return native(descriptor)
            with monkeypatch.context() as unavailable:
                unavailable.setattr(os, 'fsync', broken)
                code, text, error = invoke(capsys, *arguments)
        else:
            code, text, error = invoke(capsys, *arguments)
        diagnostic = json.loads(error)['error']
        assert code == 4 and text == '' and 'PRIVATE_OPERATIONAL_HOST_OR_PROVIDER' not in error
        assert diagnostic['code'] == {'output': 'OutputUnavailable', 'directory_sync': 'ArtifactOutputUnavailable', 'cleanup': 'CleanupUnavailable'}[fault]
        assert diagnostic['inspection']['checks']['manifest_schema'] == 'PASS'
        assert diagnostic['inspection']['status'] == 'UNKNOWN'
        artifact = diagnostic['artifact_result']
        assert artifact['manifest_digest'] == hashlib.sha256(expected).hexdigest()
        assert artifact['artifact_published'] is True and artifact['artifact_directory_durable'] is (fault != 'directory_sync')
        phase_free(diagnostic)
        assert output.read_bytes() == expected and stat.S_IMODE(output.stat().st_mode) == 0o600
        assert observed['dispose'] == 1 and _snapshot(app) == before


@pytest.mark.parametrize('symlink', [False, True])
def test_existing_destination_refuses_before_host_and_preserves_every_byte(tmp_path, monkeypatch, capsys, symlink):
    with application() as app:
        reference, _, observed = host(app, monkeypatch)
        target, output = tmp_path / 'existing.json', tmp_path / 'requested.json'
        original = b'public existing file must never be replaced'
        target.write_bytes(original)
        if symlink: output.symlink_to(target)
        else: output.write_bytes(original)
        before = _snapshot(app)
        code, text, error = invoke(capsys, *command(reference, output))
        diagnostic = json.loads(error)['error']
        assert code == 2 and text == '' and diagnostic['code'] == 'ArtifactExists'
        phase_free(diagnostic)
        assert observed == {'factory': 0, 'connect': 0, 'dispose': 0}
        assert output.read_bytes() == target.read_bytes() == original and _snapshot(app) == before
