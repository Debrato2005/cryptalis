"""Status reports explicit backup obligations without asserting recovery authority."""
from dataclasses import replace
import io
import json
import os
import sys
from types import ModuleType
from uuid import UUID, uuid4

import psycopg
import pytest

from cryptalis import cli, migration as m, rotation as r
from cryptalis.crypto import Keyring
from test_migration import application, run, publish, keys
from test_operational_cli import invoke
from test_owned_sequences import _snapshot
from test_status_cli import inputs, arguments


def test_status_reports_host_declared_lineage_backup_without_preparing_keys(tmp_path, monkeypatch, capsys):
    with application() as app:
        run(app); publish(app)
        paths = inputs(app, tmp_path)
        module = ModuleType('retained_status_host_' + uuid4().hex)
        backup_id = uuid4()
        def factory():
            from cryptalis.cli_host import RetainedBackupObligation, RetainedObligationsContext
            return RetainedObligationsContext(app.plan.operation_id, app.plan.digest,
                (RetainedBackupObligation(backup_id, app.plan.artifact, 'a' * 64, None, None),))
        module.factory = factory
        monkeypatch.setitem(sys.modules, module.__name__, module)
        before = _snapshot(app)
        def forbidden(*args, **kwargs):
            raise AssertionError('metadata status must not prepare provider keys')
        with monkeypatch.context() as no_keys:
            no_keys.setattr(Keyring, 'prepare', forbidden)
            code, text, error = invoke(capsys, *arguments(paths), '--host-context', module.__name__ + ':factory')
        assert code == 0 and error == '', (code, error)
        summary = json.loads(text)
        retained = summary['retained_obligations']
        assert retained['status'] == retained['inventory_completeness'] == 'UNKNOWN'
        assert retained['reader_availability'] == retained['provider_availability'] == 'UNKNOWN'
        assert retained['verification'] == 'NOT_PERFORMED' and retained['reported_count'] == 1
        record = retained['records'][0]
        assert record['backup_id'] == str(backup_id) and record['source_plan_digest'] == app.plan.digest
        assert record['required_policy_digests'] == app.plan.document['key_policies']
        assert record['reader_sha256'] is record['drill_sha256'] is None
        assert record['provenance'] == 'HOST_DECLARED_DIGEST_REFERENCES'
        assert _snapshot(app) == before


def host(app, monkeypatch, *, records=None, **overrides):
    from cryptalis.cli_host import RetainedBackupObligation, RetainedObligationsContext
    context = RetainedObligationsContext(app.plan.operation_id, app.plan.digest,
        (RetainedBackupObligation(uuid4(), app.plan.artifact, 'a' * 64, 'b' * 64, 'c' * 64),)
        if records is None else records)
    configuration = {'context': replace(context, **overrides)}
    calls = []
    module = ModuleType('retained_context_' + uuid4().hex)
    def factory():
        calls.append(True)
        print('PRIVATE_OPERATIONAL_HOST_OR_PROVIDER')
        if configuration.get('unavailable'):
            raise RuntimeError('PRIVATE_OPERATIONAL_HOST_OR_PROVIDER')
        return configuration['context']
    module.factory = factory
    monkeypatch.setitem(sys.modules, module.__name__, module)
    return module.__name__ + ':factory', configuration, calls


def no_keys(*args, **kwargs):
    pytest.fail('metadata-only status reached provider preparation')


def no_connect(*args, **kwargs):
    pytest.fail('invalid host metadata reached database access')


def test_legacy_status_json_and_text_bytes_remain_exact_when_host_is_omitted(tmp_path, capsys):
    with application() as app:
        paths = inputs(app, tmp_path)
        observed = m.status(app.plan, app.owner, pin=app.pin)
        expected = dict(scope='protection_transition', operation_id=str(app.plan.operation_id),
            phase=observed.phase, external_phase=observed.external_phase, committed_rows=observed.committed_rows,
            committed_chunks=observed.committed_chunks, runtime_metadata_matches=observed.runtime_metadata_matches,
            verification=observed.verification, authority='HOST_SUPPLIED_PIN', effects='NONE', remedy=observed.remedy)
        code, text, error = invoke(capsys, *arguments(paths))
        assert code == 3 and error == '' and text == json.dumps(expected, sort_keys=True, separators=(',', ':')) + '\n'
        code, text, error = invoke(capsys, *arguments(paths)[:-1])
        expected_text = '\n'.join(f'{key}: {str(value).lower() if type(value) is bool else "UNKNOWN" if value is None else value}'
                                  for key, value in expected.items()) + '\n'
        assert code == 3 and error == '' and text == expected_text


@pytest.mark.parametrize('size', [0, 64])
def test_empty_or_bounded_host_inventory_keeps_completeness_unknown_and_incomplete_exit(tmp_path, monkeypatch, capsys, size):
    from cryptalis.cli_host import RetainedBackupObligation
    with application() as app:
        records = tuple(RetainedBackupObligation(uuid4(), app.plan.artifact, 'a' * 64, None, None) for _ in range(size))
        reference, _, calls = host(app, monkeypatch, records=records)
        before = _snapshot(app)
        with monkeypatch.context() as no_provider:
            no_provider.setattr(Keyring, 'prepare', no_keys)
            code, text, error = invoke(capsys, *arguments(inputs(app, tmp_path)), '--host-context', reference)
        report = json.loads(text)
        assert code == 3 and error == '' and len(calls) == 1
        assert report['phase'] == 'PREPARED' and report['host_configuration_effects'] == 'UNKNOWN'
        retained = report['retained_obligations']
        assert retained['reported_count'] == size and len(retained['records']) == size
        assert retained['inventory_completeness'] == retained['status'] == 'UNKNOWN'
        assert _snapshot(app) == before


@pytest.mark.parametrize('fault', ['operation', 'context_digest', 'context_type', 'list_records', 'record_type',
    'duplicate_backup', 'zero_uuid', 'bad_dump', 'bad_reader', 'bad_drill', 'extra_record',
    'malformed_source', 'unrelated_source', 'oversized', 'too_many'])
def test_metadata_refusals_precede_connection_and_never_echo_host_values(tmp_path, monkeypatch, capsys, fault):
    from cryptalis.cli_host import RetainedBackupObligation
    with application() as app:
        reference, configuration, calls = host(app, monkeypatch)
        context = configuration['context']
        record = context.records[0]
        if fault == 'operation': context = replace(context, operation_id=uuid4())
        elif fault == 'context_digest': context = replace(context, plan_digest='0' * 64)
        elif fault == 'context_type': context = {'PRIVATE_OPERATIONAL_HOST_OR_PROVIDER': True}
        elif fault == 'list_records': context = replace(context, records=list(context.records))
        elif fault == 'record_type': context = replace(context, records=(dict(backup_id=str(uuid4())),))
        elif fault == 'duplicate_backup': context = replace(context, records=(record, record))
        elif fault == 'zero_uuid': context = replace(context, records=(replace(record, backup_id=UUID(int=0)),))
        elif fault == 'bad_dump': context = replace(context, records=(replace(record, dump_sha256='A' * 64),))
        elif fault == 'bad_reader': context = replace(context, records=(replace(record, reader_sha256='private-reader-path'),))
        elif fault == 'bad_drill': context = replace(context, records=(replace(record, drill_sha256=0),))
        elif fault == 'extra_record':
            object.__setattr__(record, 'PRIVATE_OPERATIONAL_HOST_OR_PROVIDER', True)
        elif fault == 'malformed_source': context = replace(context, records=(replace(record, source_plan=b'PRIVATE_OPERATIONAL_HOST_OR_PROVIDER'),))
        elif fault == 'unrelated_source':
            doc = app.plan.document
            doc['operation_id'] = str(uuid4())
            unrelated = m.MigrationPlan(m._canonical(doc))
            context = replace(context, records=(replace(record, source_plan=unrelated.artifact),))
        elif fault == 'oversized':
            from cryptalis.manifest.parser import MAX_DOCUMENT_BYTES
            context = replace(context, records=(replace(record, source_plan=b' ' * (MAX_DOCUMENT_BYTES + 1)),))
        elif fault == 'too_many':
            context = replace(context, records=tuple(replace(record, backup_id=uuid4()) for _ in range(65)))
        configuration['context'] = context
        paths, before = inputs(app, tmp_path), _snapshot(app)
        with monkeypatch.context() as forbidden:
            forbidden.setattr(psycopg, 'connect', no_connect)
            forbidden.setattr(Keyring, 'prepare', no_keys)
            code, text, error = invoke(capsys, *arguments(paths), '--host-context', reference)
        diagnostic = json.loads(error)['error']
        assert code == 2 and text == '' and diagnostic['code'] == 'RetainedObligationsInvalid'
        assert diagnostic['effects'] == 'NONE' and diagnostic['host_configuration_effects'] == 'UNKNOWN'
        assert 'known_result' not in diagnostic and calls == [True] and _snapshot(app) == before


@pytest.mark.parametrize('damage', ['plan', 'pin'])
def test_original_artifact_and_pin_admission_precede_host_loading(tmp_path, monkeypatch, capsys, damage):
    with application() as app:
        reference, _, calls = host(app, monkeypatch)
        paths = inputs(app, tmp_path)
        if damage == 'plan': paths['plan'].write_bytes(b'PRIVATE_OPERATIONAL_HOST_OR_PROVIDER')
        else:
            raw = json.loads(paths['pin'].read_text()); raw['plan_digest'] = '0' * 64
            paths['pin'].write_text(json.dumps(raw))
        before = _snapshot(app)
        with monkeypatch.context() as forbidden:
            forbidden.setattr(psycopg, 'connect', no_connect)
            code, text, error = invoke(capsys, *arguments(paths), '--host-context', reference)
        assert code == 2 and text == '' and json.loads(error)['error']['code'] == 'InvalidInput'
        assert calls == [] and _snapshot(app) == before


def test_host_failure_stays_operational_and_safe_before_command_managed_database_access(tmp_path, monkeypatch, capsys):
    with application() as app:
        reference, configuration, calls = host(app, monkeypatch)
        configuration['unavailable'] = True
        paths, before = inputs(app, tmp_path), _snapshot(app)
        with monkeypatch.context() as forbidden:
            forbidden.setattr(psycopg, 'connect', no_connect)
            code, text, error = invoke(capsys, *arguments(paths), '--host-context', reference)
        diagnostic = json.loads(error)['error']
        assert code == 4 and text == '' and diagnostic['code'] == 'HostContextUnavailable'
        assert diagnostic['effects'] == 'NONE' and diagnostic['host_configuration_effects'] == 'UNKNOWN'
        assert 'known_result' not in diagnostic and calls == [True] and _snapshot(app) == before


def test_removed_status_retains_ancestor_backup_reference_despite_absent_journal(tmp_path, monkeypatch, capsys):
    from cryptalis.cli_host import RetainedBackupObligation
    from rewrap_worker import target_keys
    from test_deprotection import app_pin, d, least_privilege_role, native_rows
    with application() as app:
        run(app); publish(app)
        source = app.plan
        rewrap = r.plan_rewrap(source, app.owner, source_pin=app.pin, keys=keys,
            target_keys=target_keys, verify_rows_per_second=1000)
        successor = rewrap.activation_plan
        assert r.apply_rewrap(rewrap, app.owner, keys=keys, target_keys=target_keys,
            pin=app_pin(successor, 'PREPARED'), approval=app.approval).phase == 'PENDING'
        assert m.apply(successor, app.owner, keys=target_keys, pin=app_pin(successor, 'ACTIVATING'),
            approval=app.approval, until='ACTIVE').phase == 'ACTIVE'
        reverse = d.plan(successor, app.owner, source_pin=app_pin(successor, 'ACTIVE'), keys=target_keys,
            plaintext_runtime_role=least_privilege_role(app), backfill_rows_per_second=1000,
            verify_rows_per_second=1000, temporary_bytes_per_row=700, wal_bytes_per_row=700)
        consent = d.PlaintextApproval(reverse.target_id, reverse.operation_id, reverse.digest, True,
            'public declared fixture backup; status does not prove its availability')
        assert d.apply(reverse, app.owner, keys=target_keys, pin=app_pin(reverse, 'PREPARED'),
            approval=app.approval, consent=consent).phase == 'PLAINTEXT_PENDING'
        assert d.apply(reverse, app.owner, keys=target_keys, pin=app_pin(reverse, 'PLAINTEXT_ACTIVATING'),
            approval=app.approval, consent=consent, until='PLAINTEXT_ACTIVE').phase == 'PLAINTEXT_ACTIVE'
        removal = d.RemovalApproval(reverse.target_id, reverse.operation_id, reverse.digest,
            'fixture native latest-value workload', 'fixture backup references remain unqualified', True)
        assert d.remove(reverse, app.owner, pin=app_pin(reverse, 'REMOVING'), approval=app.approval,
            consent=consent, removal=removal).phase == 'REMOVED'
        app.plan, app.pin = reverse, app_pin(reverse, 'REMOVED')
        assert native_rows(app) == app.source
        with app.owner.connect() as connection:
            assert connection.exec_driver_sql('SELECT pg_catalog.to_regclass(%s)',
                (f'"{app.schema}"."_cryptalis_journal"',)).scalar_one() is None
        backup = RetainedBackupObligation(uuid4(), source.artifact, 'a' * 64, 'b' * 64, 'c' * 64)
        reference, _, _ = host(app, monkeypatch, records=(backup,))
        paths, before = inputs(app, tmp_path), _snapshot(app)
        with monkeypatch.context() as forbidden:
            forbidden.setattr(Keyring, 'prepare', no_keys)
            code, text, error = invoke(capsys, *arguments(paths), '--host-context', reference)
        assert code == 0 and error == ''
        summary = json.loads(text)
        record = summary['retained_obligations']['records'][0]
        assert summary['phase'] == 'REMOVED' and summary['runtime_metadata_matches'] is True
        assert record['source_operation_id'] == str(source.operation_id) and record['source_plan_digest'] == source.digest
        assert record['required_policy_digests'] == source.document['key_policies']
        assert summary['retained_obligations']['status'] == summary['retained_obligations']['inventory_completeness'] == 'UNKNOWN'
        assert _snapshot(app) == before
        with io.TextIOWrapper(io.FileIO('/dev/full', 'w'), write_through=True) as output, monkeypatch.context() as stream:
            stream.setattr(sys, 'stdout', output)
            code = cli.main(list(arguments(paths) + ('--host-context', reference)))
        diagnostic = json.loads(capsys.readouterr().err)['error']
        assert code == 4 and diagnostic['code'] == 'OutputUnavailable'
        assert diagnostic['retained_obligations']['records'][0] == record and 'known_result' not in diagnostic
        assert _snapshot(app) == before
