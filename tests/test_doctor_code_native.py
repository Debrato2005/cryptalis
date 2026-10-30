"""Actual ast-grep parsing/matching boundary; no mocked scanner authority."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

import pytest

from cryptalis.cli import main
from cryptalis.doctor import scan_routes
from cryptalis._doctor_code import RULES


@pytest.fixture
def scanner():
    value = os.environ.get('CRYPTALIS_TEST_SCANNER')
    if value is None:
        pytest.skip('explicit isolated ast-grep 0.51.0 executable required')
    path = Path(value)
    assert path.is_absolute() and path.is_file(), 'invalid explicit ast-grep executable'
    return path


def test_native_aliases_call_inventory_no_execution_or_source_disclosure(tmp_path, scanner, capsys):
    source = tmp_path / 'application.py'
    marker = tmp_path / 'executed'
    source.write_text('from sqlalchemy import create_engine as factory, text\n'
        'from psycopg import connect as direct\nfrom pathlib import Path\n'
        f'Path({str(marker)!r}).write_text("MUST_NOT_EXECUTE")\n'
        'engine = factory("PRIVATE_LITERAL")\n'
        'session.execute(text("PRIVATE_LITERAL"))\n'
        'session.add(entity)\nsession.scalars(query)\n'
        'cursor.copy("PRIVATE_LITERAL")\nconnection = direct("PRIVATE_LITERAL")\n')
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    # Native JSON includes the matched source; prove the privacy collector sees it.
    inline = '\n---\n'.join(json.dumps(rule) for rule in json.loads(RULES.read_bytes()))
    result = subprocess.run([str(scanner), 'scan', '--inline-rules', inline,
        '--json=compact', '--custom-languages=ignore', '.'], cwd=tmp_path,
        capture_output=True, text=True, timeout=30)
    assert result.returncode == 0 and 'PRIVATE_LITERAL' in result.stdout
    report = scan_routes(tmp_path, scanner=scanner)
    assert report['checks']['scanner_execution'] == 'PASS' and report['status'] == 'UNKNOWN'
    assert {item['kind'] for item in report['items']} == {'connection_configuration', 'execution_candidate',
        'sql_text_candidate', 'write_candidate', 'query_candidate', 'copy_candidate', 'driver_candidate'}
    assert all(item['status'] == 'UNKNOWN' for item in report['items'])
    assert not marker.exists() and hashlib.sha256(source.read_bytes()).hexdigest() == before
    assert 'PRIVATE_LITERAL' not in json.dumps(report) and 'MUST_NOT_EXECUTE' not in json.dumps(report)
    assert main(['doctor', '--code-root', str(tmp_path), '--scanner', str(scanner), '--json']) == 0
    output = capsys.readouterr()
    assert output.err == '' and json.loads(output.out)['items'] == report['items']


def test_native_ignore_overrides_and_untrusted_project_config_are_explicit(tmp_path, scanner):
    (tmp_path/'visible.py').write_text('session.execute(statement)\n')
    (tmp_path/'ignored.py').write_text('session.execute(statement)\n')
    (tmp_path/'.hidden.py').write_text('session.execute(statement)\n')
    (tmp_path/'suppressed.py').write_text('# ast-grep-ignore\nsession.execute(statement)\n')
    (tmp_path/'.ignore').write_text('ignored.py\n')
    (tmp_path/'sgconfig.yml').write_text('invalid untrusted project configuration: [\n')
    (tmp_path/'large.py').write_text('# public filler\n' * 80000 + 'session.execute(statement)\n')
    report = scan_routes(tmp_path, scanner=scanner)
    assert report['checks']['scanner_execution'] == 'PASS'
    assert report['observation']['scanned_paths'] == report['observation']['skipped_paths'] == 'UNKNOWN'
    assert {item['path'] for item in report['items']} == {'visible.py', 'ignored.py', '.hidden.py', 'large.py'}
    assert report['checks']['complete_route_inventory'] == report['checks']['code_validity'] == 'UNKNOWN'
    assert 'native inline suppressions apply' in report['selection']


def test_native_parser_recovery_never_establishes_code_validity(tmp_path, scanner):
    import ast
    source = 'session.execute("PRIVATE_PARSE_LITERAL")\ndef broken(:\n    pass\n'
    with pytest.raises(SyntaxError): ast.parse(source)
    (tmp_path/'broken.py').write_text(source)
    report = scan_routes(tmp_path, scanner=scanner)
    assert report['checks']['scanner_execution'] == 'PASS'
    assert report['checks']['code_validity'] == report['checks']['complete_route_inventory'] == 'UNKNOWN'
    assert report['observation']['parser_recoveries'] == 0  # Native recovery is not a syntax oracle.
    assert 'PRIVATE_PARSE_LITERAL' not in json.dumps(report)
