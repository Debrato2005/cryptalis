"""Pre-adoption CLI diagnostics preserve the compiler and trusted-host boundary."""

import errno
import json
import os
from pathlib import Path
import subprocess
import sys

import psycopg
import pytest
from sqlalchemy.engine import Engine

import cryptalis
from cryptalis import cli
from test_protection_compiler import app, declaration, engine, snapshot


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_PATH = str(Path(cryptalis.__file__).resolve().parent.parent)
PRIVATE = 'PRIVATE_DOCTOR_HOST_DETAIL'


def inputs(directory, body, manifest=None):
    module = directory / 'doctor_host.py'
    module.write_text(body)
    manifest_path = directory / 'manifest.json'
    manifest_path.write_text(json.dumps(declaration() if manifest is None else manifest))
    database = directory / 'database.txt'
    database.write_text('postgresql://unused.invalid/unused')
    return module, manifest_path, database


def arguments(paths):
    return ['doctor', '--pre-adoption', str(paths[1]), '--host-context',
            'doctor_host:context', '--database-url-file', str(paths[2]), '--json']


def invoke(paths, *extra):
    child_env = dict(os.environ, PYTHONPATH=os.pathsep.join((PACKAGE_PATH,
        str(paths[0].parent), os.environ.get('PYTHONPATH', ''))), PYTHONDONTWRITEBYTECODE='1')
    return subprocess.run([sys.executable, '-m', 'cryptalis', *arguments(paths), *extra],
        cwd=ROOT, env=child_env, capture_output=True, text=True, timeout=10)


def error(result, exit_code, code=None):
    assert result.returncode == exit_code
    assert result.stdout == ''
    assert PRIVATE not in result.stderr and 'Traceback' not in result.stderr
    observed = json.loads(result.stderr)['error']
    if code is not None:
        assert observed['code'] == code
    return observed


@pytest.mark.parametrize('failure', ['RuntimeError', 'ImportError', 'SystemExit'])
def test_host_factory_failure_is_redacted(tmp_path, failure):
    paths = inputs(tmp_path, f'def context():\n    raise {failure}({PRIVATE!r})\n')
    observed = error(invoke(paths), 4, 'HostContextUnavailable')
    assert observed['stage'] == 'host_context'
    assert observed['host_configuration_effects'] == 'UNKNOWN'


@pytest.mark.parametrize('raises', [False, True])
def test_host_python_prints_do_not_corrupt_diagnostics(tmp_path, raises):
    finish = (f'raise RuntimeError({PRIVATE!r})' if raises else
              'return registry(), WriterInventory(False, ()), ()')
    paths = inputs(tmp_path, f'''
import sys
from sqlalchemy.orm import registry
from cryptalis.manifest.compiler import WriterInventory
print({PRIVATE!r})
print({PRIVATE!r}, file=sys.stderr)
def context():
    print({PRIVATE!r})
    print({PRIVATE!r}, file=sys.stderr)
    {finish}
''')
    observed = error(invoke(paths), 4 if raises else 3,
                     'HostContextUnavailable' if raises else 'SchemaIncompatible')
    assert observed['host_configuration_effects'] == 'UNKNOWN'


@pytest.mark.parametrize('extra', [
    ['--pin', 'PRIVATE_DOCTOR_HOST_DETAIL'], ['--restore-binding', 'PRIVATE_DOCTOR_HOST_DETAIL'],
    ['PRIVATE_DOCTOR_HOST_DETAIL'],
])
def test_mixed_modes_refuse_before_host_import_or_file_access(tmp_path, extra):
    marker = tmp_path / 'imported'
    paths = inputs(tmp_path, f'from pathlib import Path\nPath({str(marker)!r}).touch()\n')
    paths[1].unlink()
    observed = error(invoke(paths, *extra), 2, 'InvalidArguments')
    assert observed['stage'] == 'arguments'
    assert not marker.exists()


@pytest.mark.parametrize('change', ['missing_context', 'missing_manifest', 'invalid_reference'])
def test_incomplete_or_malformed_mode_refuses_before_host_import(tmp_path, change):
    marker = tmp_path / 'imported'
    paths = inputs(tmp_path, f'from pathlib import Path\nPath({str(marker)!r}).touch()\n')
    args = arguments(paths)
    if change == 'invalid_reference':
        args[args.index('--host-context') + 1] = '../doctor_host:context'
    else:
        option = '--host-context' if change == 'missing_context' else '--pre-adoption'
        index = args.index(option)
        del args[index:index + 2]
    child_env = dict(os.environ, PYTHONPATH=os.pathsep.join((PACKAGE_PATH, str(tmp_path))))
    result = subprocess.run([sys.executable, '-m', 'cryptalis', *args],
        cwd=ROOT, env=child_env, capture_output=True, text=True, timeout=10)
    error(result, 2, 'InvalidArguments')
    assert not marker.exists()


@pytest.mark.parametrize('fault', ['manifest', 'manifest_limit', 'database', 'database_limit'])
def test_invalid_inputs_refuse_before_host_import(tmp_path, fault):
    marker = tmp_path / 'imported'
    paths = inputs(tmp_path, f'from pathlib import Path\nPath({str(marker)!r}).touch()\n')
    if fault == 'manifest':
        paths[1].write_text('{PRIVATE_DOCTOR_HOST_DETAIL')
    elif fault == 'manifest_limit':
        paths[1].write_bytes(b' ' * (16 * 1024 * 1024 + 1))
    elif fault == 'database':
        paths[2].write_text(PRIVATE + '\x00')
    else:
        paths[2].write_text(' ' * 65537)
    observed = error(invoke(paths), 2)
    assert observed['stage'] == 'inputs'
    assert not marker.exists()


@pytest.mark.parametrize('body', [
    'def context():\n    return ()\n',
    'def context():\n    return (None, None, ())\n',
    'context = None\n',
    'async def context():\n    return ()\n',
])
def test_invalid_host_context_refuses_without_database_connection(tmp_path, body):
    paths = inputs(tmp_path, body)
    observed = error(invoke(paths), 2, 'HostContextInvalid')
    assert observed['stage'] == 'host_context'


def test_equals_option_parse_failure_retains_pre_adoption_uncertainty(tmp_path):
    paths = inputs(tmp_path, 'def context():\n    raise AssertionError("must not load")\n')
    result = subprocess.run([sys.executable, '-m', 'cryptalis', 'doctor',
        '--pre-adoption=' + str(paths[1]), '--host-context=doctor_host:context', '--json'],
        cwd=ROOT, env=dict(os.environ, PYTHONPATH=PACKAGE_PATH),
        capture_output=True, text=True, timeout=10)
    observed = error(result, 2, 'InvalidArguments')
    assert observed['scope'] == 'pre_adoption'
    assert observed['host_configuration_effects'] == 'UNKNOWN'


@pytest.mark.parametrize('connection_info,expected', [
    ('dbname=public_fixture password=postgresql+psycopg://public_fixture',
     'dbname=public_fixture password=postgresql+psycopg://public_fixture'),
    ('postgresql+psycopg://public_fixture@unused.invalid/public_fixture',
     'postgresql://public_fixture@unused.invalid/public_fixture'),
])
def test_connection_normalization_preserves_conninfo_values(
        tmp_path, monkeypatch, capsys, connection_info, expected):
    paths = inputs(tmp_path, '''
from uuid import UUID
from sqlalchemy.orm import registry
from cryptalis.manifest.compiler import Writer, WriterInventory, SearchReview
def context():
    return (registry(), WriterInventory(True, (Writer(
        UUID('20000000-0000-0000-0000-000000000001'), 'fixture', 'sqlalchemy',
        evidence='public fixture'),)), (SearchReview(
        UUID('30000000-0000-0000-0000-000000000001'), False, 'public fixture'),))
''')
    paths[2].write_text(connection_info)
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.delitem(sys.modules, 'doctor_host', raising=False)
    observed = []
    def unavailable(value, **kwargs):
        observed.append(value)
        raise psycopg.errors.DivisionByZero(PRIVATE)
    monkeypatch.setattr(psycopg, 'connect', unavailable)
    assert cli.main(arguments(paths)) == 4
    captured = capsys.readouterr()
    error(subprocess.CompletedProcess([], 4, captured.out, captured.err), 4, 'InspectionUnavailable')
    assert observed == [expected]


@pytest.fixture
def native_inputs(app, tmp_path):
    _, _, _, schema = app
    paths = inputs(tmp_path, f'''
from uuid import UUID
from sqlalchemy import Column, MetaData, Table, Text, UniqueConstraint, Uuid
from sqlalchemy.orm import registry
from cryptalis.manifest.compiler import Writer, WriterInventory, SearchReview
from pathlib import Path
Path({str(tmp_path / 'imported')!r}).touch()
def context():
    global Customer
    mapping = registry(metadata=MetaData(schema={schema!r}))
    table = Table('customer', mapping.metadata,
        Column('id', Uuid, primary_key=True), Column('tenant_id', Uuid, nullable=False),
        Column('email', Text(collation='C')), Column('note', Text),
        UniqueConstraint('tenant_id', 'email', name='email_unique'))
    class Customer:
        pass
    mapping.map_imperatively(Customer, table)
    writers = WriterInventory(True, (Writer(UUID('20000000-0000-0000-0000-000000000001'),
        'application', 'sqlalchemy', False, 'native application fixture'),))
    reviews = (SearchReview(UUID('30000000-0000-0000-0000-000000000001'), False,
        'host review: free-form email, no finite value set'),)
    return mapping, writers, reviews
''')
    paths[2].write_text(os.environ['CRYPTALIS_TEST_DATABASE_URL'])
    return paths


def test_native_preflight_cli_keeps_host_effects_unknown_and_database_unchanged(app, native_inputs):
    before = snapshot(app)
    result = invoke(native_inputs)
    assert result.returncode == 0 and result.stderr == ''
    report = json.loads(result.stdout)
    assert report['scope'] == 'pre_adoption' and report['status'] == 'UNKNOWN'
    assert report['checks']['manifest_schema'] == 'PASS'
    assert all(value == 'UNKNOWN' for name, value in report['checks'].items() if name != 'manifest_schema')
    assert report['effects'] == 'NONE' and report['effects_scope'] == 'compiler_inspection'
    assert report['host_configuration_effects'] == 'UNKNOWN'
    assert (native_inputs[0].parent / 'imported').exists()
    assert snapshot(app) == before


@pytest.mark.parametrize('unsupported', [False, True])
def test_native_query_samples_have_explicit_cli_results_and_preserve_schema(app, native_inputs, unsupported):
    before = snapshot(app)
    module = native_inputs[0]
    expression = "select(Customer).where(Customer.email.ilike('PRIVATE_QUERY_PATTERN'))" if unsupported else 'select(Customer)'
    module.write_text(module.read_text().replace('    return mapping, writers, reviews',
        '    from sqlalchemy import select\n    return mapping, writers, reviews, (' + expression + ',)'))
    result = invoke(native_inputs)
    if unsupported:
        observed = error(result, 3, 'QueryIncompatible')
        assert observed['checks']['manifest_schema'] == 'PASS'
        assert observed['checks']['query_routes'] == 'FAIL'
    else:
        assert result.returncode == 0 and result.stderr == ''
        observed = json.loads(result.stdout)
        assert observed['checks']['query_samples'] == 'PASS'
        assert observed['checks']['query_routes'] == observed['status'] == 'UNKNOWN'
    assert 'PRIVATE_QUERY_PATTERN' not in result.stdout + result.stderr
    assert snapshot(app) == before


@pytest.mark.parametrize('shape', ['plain', 'columns', 'entity', 'labeled'])
def test_native_insert_samples_have_explicit_uninspected_parameter_cli_results(app, native_inputs, shape):
    before = snapshot(app)
    expression = {
        'plain': 'insert(Customer)',
        'columns': 'insert(Customer).returning(Customer.id, Customer.email)',
        'entity': 'insert(Customer).returning(Customer)',
        'labeled': "insert(Customer).returning(Customer.email.label('protected value'))",
    }[shape]
    module = native_inputs[0]
    module.write_text(module.read_text().replace('    return mapping, writers, reviews',
        '    from sqlalchemy import insert\n    return mapping, writers, reviews, (' + expression + ',)'))
    result = invoke(native_inputs)
    assert result.returncode == 0 and result.stderr == ''
    report = json.loads(result.stdout)
    assert report['query_samples']['scope'] == 'supplied_statement_structures'
    assert report['query_samples']['execution'] == 'NOT_PERFORMED'
    assert report['query_samples']['items'] == [dict(index=0, kind='insert',
        parameters='NOT_INSPECTED', status='STRUCTURE_ADMITTED')]
    assert report['status'] == report['checks']['query_routes'] == 'UNKNOWN'
    assert report['checks']['provider_keys'] == report['checks']['writer_exclusion'] == 'UNKNOWN'
    assert report['host_configuration_effects'] == 'UNKNOWN'
    assert snapshot(app) == before


def test_unsupported_insert_cli_sample_never_discloses_embedded_values(app, native_inputs):
    before = snapshot(app)
    module = native_inputs[0]
    module.write_text(module.read_text().replace('    return mapping, writers, reviews',
        "    from sqlalchemy import insert\n    return mapping, writers, reviews, (insert(Customer).values(email='PRIVATE_INSERT_VALUE'),)"))
    result = invoke(native_inputs)
    report = error(result, 3, 'QueryIncompatible')
    assert report['checks']['query_samples'] == report['checks']['query_routes'] == 'FAIL'
    assert 'PRIVATE_INSERT_VALUE' not in result.stdout + result.stderr
    assert snapshot(app) == before


def test_query_inspection_outage_has_nonzero_unknown_cli_result(native_inputs, monkeypatch, capsys):
    from cryptalis.sqlalchemy import _Attachment
    module = native_inputs[0]
    module.write_text(module.read_text().replace('    return mapping, writers, reviews',
        '    from sqlalchemy import select\n    return mapping, writers, reviews, (select(Customer),)'))
    monkeypatch.syspath_prepend(str(module.parent))
    monkeypatch.delitem(sys.modules, 'doctor_host', raising=False)
    def unavailable(*args, **kwargs):
        raise RuntimeError(PRIVATE)
    monkeypatch.setattr(_Attachment, 'admit', unavailable)
    assert cli.main(arguments(native_inputs)) == 4
    captured = capsys.readouterr()
    observed = error(subprocess.CompletedProcess([], 4, captured.out, captured.err), 4, 'QueryInspectionUnavailable')
    assert observed['checks']['manifest_schema'] == 'PASS'
    assert observed['checks']['query_samples'] == observed['checks']['query_routes'] == 'UNKNOWN'


def test_native_schema_refusal_has_nonzero_exit_and_actionable_issues(app, native_inputs):
    before = snapshot(app)
    doc = declaration()
    doc['models'][0]['tenancy'] = {'column': 'missing_tenant'}
    native_inputs[1].write_text(json.dumps(doc))
    observed = error(invoke(native_inputs), 3, 'SchemaIncompatible')
    assert observed['checks']['manifest_schema'] == 'FAIL'
    assert observed['issues'] and all(issue['remedy'] for issue in observed['issues'])
    assert snapshot(app) == before


def test_native_inspection_failure_is_unknown_with_safe_sqlstate(native_inputs, monkeypatch, capsys):
    monkeypatch.syspath_prepend(str(native_inputs[0].parent))
    monkeypatch.delitem(sys.modules, 'doctor_host', raising=False)
    def unavailable(*args, **kwargs):
        raise psycopg.errors.DivisionByZero(PRIVATE)
    monkeypatch.setattr(psycopg, 'connect', unavailable)
    assert cli.main(arguments(native_inputs)) == 4
    captured = capsys.readouterr()
    observed = error(subprocess.CompletedProcess([], 4, captured.out, captured.err), 4, 'InspectionUnavailable')
    assert observed['status'] == observed['checks']['manifest_schema'] == 'UNKNOWN'
    assert observed['sqlstate'] == '22012'


def test_engine_cleanup_failure_is_loud_and_preserves_schema_result(native_inputs, monkeypatch, capsys):
    import gc
    import cryptalis.doctor as doctor
    monkeypatch.syspath_prepend(str(native_inputs[0].parent))
    monkeypatch.delitem(sys.modules, 'doctor_host', raising=False)
    native_preflight = doctor.preflight
    def collect_before_inspection(*args, **kwargs):
        gc.collect()
        return native_preflight(*args, **kwargs)
    monkeypatch.setattr(doctor, 'preflight', collect_before_inspection)
    def unavailable(self, *args, **kwargs):
        raise OSError(errno.EIO, PRIVATE)
    monkeypatch.setattr(Engine, 'dispose', unavailable)
    assert cli.main(arguments(native_inputs)) == 4
    captured = capsys.readouterr()
    observed = error(subprocess.CompletedProcess([], 4, captured.out, captured.err), 4, 'CleanupUnavailable')
    assert observed['inspection']['checks']['manifest_schema'] == 'PASS', observed['inspection']['issues']


@pytest.mark.skipif(not Path('/dev/full').exists(), reason='requires /dev/full')
def test_preflight_output_failure_remains_explicit(native_inputs):
    child_env = dict(os.environ, PYTHONPATH=os.pathsep.join((PACKAGE_PATH, str(native_inputs[0].parent))))
    with open('/dev/full', 'w') as output:
        result = subprocess.run([sys.executable, '-m', 'cryptalis', *arguments(native_inputs)],
            cwd=ROOT, env=child_env, stdout=output, stderr=subprocess.PIPE, text=True, timeout=10)
    observed = error(subprocess.CompletedProcess([], result.returncode, '', result.stderr), 4, 'OutputUnavailable')
    assert observed['output_role'] == 'stdout'
