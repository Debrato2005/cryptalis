"""Failure, privacy and process bounds for the local code-inventory command."""
import io
import json
import os
from pathlib import Path
import sys
import time

import pytest

from cryptalis.cli import main
from cryptalis.doctor import scan_routes

PRIVATE = 'PRIVATE_SOURCE_AND_SCANNER_DETAIL'


def executable(tmp_path, body):
    path = tmp_path / 'trusted-scanner'
    path.write_text('#!' + sys.executable + "\nimport sys\nif '--version' in sys.argv:\n"
                    " print('ast-grep 0.51.0'); raise SystemExit(0)\n" + body)
    path.chmod(0o700)
    return path


def native_report():
    return [dict(ruleId='cryptalis-route-execution', file='app.py',
        range=dict(start=dict(line=6)), text=PRIVATE, message=PRIVATE)]


def scripted_report(tmp_path, document):
    return executable(tmp_path, 'import json\nprint(json.dumps(' + repr(document) + '))\n')


def test_candidate_privacy_and_unknown_coverage_survive_success_and_cli(tmp_path, capsys):
    scanner = scripted_report(tmp_path, native_report())
    report = scan_routes(tmp_path, scanner=scanner)
    assert report['checks']['scanner_execution'] == 'PASS' and report['status'] == 'UNKNOWN'
    assert all(v == 'UNKNOWN' for k,v in report['checks'].items() if k != 'scanner_execution')
    assert report['items'] == [dict(path='app.py', line=7, kind='execution_candidate',
                                   rule='cryptalis-route-execution', status='UNKNOWN')]
    assert PRIVATE not in json.dumps(report)
    assert main(['doctor', '--code-root', str(tmp_path), '--scanner', str(scanner), '--json']) == 0
    out = capsys.readouterr()
    assert out.err == '' and json.loads(out.out) == report and PRIVATE not in out.out
    assert main(['doctor', '--code-root', str(tmp_path), '--scanner', str(scanner)]) == 0
    out = capsys.readouterr()
    assert out.err == '' and report['selection'] in out.out and PRIVATE not in out.out


@pytest.mark.parametrize('case', ['outside', 'unknown_rule', 'partial', 'malformed'])
def test_scanner_uncertainty_never_becomes_clear_code_or_coverage(tmp_path, case):
    document = native_report()
    if case == 'outside': document[0]['file'] = '../outside.py'
    elif case == 'unknown_rule': document[0]['ruleId'] = PRIVATE
    elif case == 'partial': document.append(dict(ruleId='cryptalis-parse-recovery', file='app.py',
        range=dict(start=dict(line=9)), text=PRIVATE))
    else: document = {'invalid': PRIVATE}
    report = scan_routes(tmp_path, scanner=scripted_report(tmp_path, document))
    assert report['status'] == report['checks']['scanner_execution'] == 'UNKNOWN'
    assert report['checks']['complete_route_inventory'] == 'UNKNOWN'
    assert PRIVATE not in json.dumps(report)
    if case == 'partial':
        assert len(report['items']) == 1
        assert report['issues'][0]['code'] == 'Code.ParseRecovery'


def test_unqualified_tool_version_refuses_before_scan(tmp_path):
    path = executable(tmp_path, 'raise AssertionError("scan dispatched")')
    path.write_text(path.read_text().replace('ast-grep 0.51.0', 'ast-grep unqualified'))
    report = scan_routes(tmp_path, scanner=path)
    assert report['issues'][0]['code'] == 'Code.ScannerVersion'


@pytest.mark.parametrize('stream', ['stdout', 'stderr'])
def test_large_tool_output_is_bounded_and_redacted(tmp_path, stream):
    scanner = executable(tmp_path, 'import sys\n' +
        f'sys.{stream}.write({PRIVATE!r} * 1000000)\nsys.{stream}.flush()\n')
    report = scan_routes(tmp_path, scanner=scanner, timeout=5)
    assert report['checks']['scanner_execution'] == 'UNKNOWN'
    assert report['issues'][0]['code'] == 'Code.ReportLimit'
    assert PRIVATE not in json.dumps(report)


def test_timeout_terminates_child_holding_pipes_after_parent_exits(tmp_path):
    child_file = tmp_path / 'child.pid'
    scanner = executable(tmp_path, 'import pathlib,subprocess,sys\n'
        'child=subprocess.Popen([sys.executable,"-c","import time; time.sleep(60)"])\n'
        f'pathlib.Path({str(child_file)!r}).write_text(str(child.pid))\n')
    report = scan_routes(tmp_path, scanner=scanner, timeout=1)
    assert report['issues'][0]['code'] == 'Code.ScannerTimeout'
    child = int(child_file.read_text())
    deadline = time.monotonic() + 3
    while True:
        try:
            state = Path(f'/proc/{child}/stat').read_text().split()[2]
        except (FileNotFoundError, ProcessLookupError):
            break  # The killed child may disappear during the procfs read.
        if state == 'Z': break
        assert time.monotonic() < deadline, 'scanner child survived timeout'
        time.sleep(0.02)


def test_missing_tool_and_invalid_arguments_are_explicit_and_do_not_import_host(tmp_path, capsys):
    code = main(['doctor', '--code-root', str(tmp_path), '--scanner', str(tmp_path/'missing'), '--json'])
    out = capsys.readouterr()
    assert code == 4 and out.out == ''
    assert json.loads(out.err)['error']['scope'] == 'static_code_routes'
    code = main(['doctor', '--code-root', str(tmp_path), '--host-context', PRIVATE, '--json'])
    out = capsys.readouterr()
    assert code == 2 and out.out == '' and PRIVATE not in out.err
    assert json.loads(out.err)['error']['scope'] == 'static_code_routes'
    assert scan_routes(None)['issues'][0]['code'] == 'Code.InvalidInput'


def test_nonzero_tool_exit_retains_known_candidates_without_tool_diagnostics(tmp_path):
    scanner = executable(tmp_path, 'import json,sys\nprint(json.dumps(' + repr(native_report()) + '))\n'
        f'print({PRIVATE!r},file=sys.stderr)\nraise SystemExit(2)\n')
    report = scan_routes(tmp_path, scanner=scanner)
    assert report['checks']['scanner_execution'] == 'UNKNOWN' and len(report['items']) == 1
    assert report['issues'][0]['code'] == 'Code.ScannerFailed'
    assert PRIVATE not in json.dumps(report)


def test_cli_output_failure_keeps_observation_and_nonzero_exit(tmp_path, monkeypatch, capsys):
    scanner = scripted_report(tmp_path, native_report())
    class Unavailable(io.StringIO):
        def write(self, value): raise BrokenPipeError(PRIVATE)
    with monkeypatch.context() as patch:
        patch.setattr(sys, 'stdout', Unavailable())
        code = main(['doctor', '--code-root', str(tmp_path), '--scanner', str(scanner), '--json'])
    result = capsys.readouterr()
    assert code == 4 and result.out == '' and PRIVATE not in result.err
    report = json.loads(result.err)['error']
    assert report['checks']['scanner_execution'] == 'PASS' and report['status'] == 'UNKNOWN'
