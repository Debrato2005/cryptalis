"""Bounded local ast-grep integration; findings never authorize a writer route."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import selectors
import shutil
import signal
import subprocess
import tempfile
import time

VERSION = '0.51.0'
RULES = Path(__file__).with_name('_doctor_routes.json')
KINDS = {
    'cryptalis-route-configuration': 'connection_configuration',
    'cryptalis-route-query': 'query_candidate',
    'cryptalis-route-write': 'write_candidate',
    'cryptalis-route-execution': 'execution_candidate',
    'cryptalis-route-copy': 'copy_candidate',
    'cryptalis-route-driver': 'driver_candidate',
    'cryptalis-route-text': 'sql_text_candidate',
}


class _Unavailable(Exception):
    def __init__(self, code):
        self.code = code


def _capture(command, root, environment, timeout):
    """Bound both pipes and the process group, including a surviving core child."""
    process = subprocess.Popen(command, cwd=root, env=environment,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    output, sizes = bytearray(), {}
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selection:
            for stream in (process.stdout, process.stderr):
                os.set_blocking(stream.fileno(), False)
                selection.register(stream, selectors.EVENT_READ)
                sizes[stream] = 0
            while selection.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise _Unavailable('Code.ScannerTimeout')
                for key, _ in selection.select(min(remaining, 0.1)):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selection.unregister(key.fileobj)
                        continue
                    sizes[key.fileobj] += len(chunk)
                    limit = 16 * 1024 * 1024 if key.fileobj is process.stdout else 1024 * 1024
                    if sizes[key.fileobj] > limit:
                        raise _Unavailable('Code.ReportLimit')
                    if key.fileobj is process.stdout:
                        output.extend(chunk)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _Unavailable('Code.ScannerTimeout')
            try:
                return process.wait(timeout=remaining), bytes(output)
            except subprocess.TimeoutExpired:
                raise _Unavailable('Code.ScannerTimeout') from None
    finally:
        # Until wait reaps the parent, its identity still protects the group ID.
        # On failure terminate the dedicated group, including inherited pipes
        # held by a core child. Do not signal a reaped, reusable process ID.
        try:
            if process.returncode is None:
                os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        finally:
            process.wait()
            process.stdout.close()
            process.stderr.close()


def _path(value):
    if type(value) is not str or len(value) > 4096 or '\\' in value or '\x00' in value:
        raise _Unavailable('Code.ScannerProtocol')
    path = PurePosixPath(value)
    if path.is_absolute() or '..' in path.parts or not path.parts:
        raise _Unavailable('Code.ScannerProtocol')
    return str(path)


def _observations(raw, report):
    if type(raw) is not list:
        raise _Unavailable('Code.ScannerProtocol')
    if len(raw) > 8192:
        raise _Unavailable('Code.ReportLimit')
    findings, parse_recoveries = set(), set()
    for item in raw:
        rule = item['ruleId']
        path = _path(item['file'])
        line = item['range']['start']['line']
        if type(line) is not int or not 0 <= line < 1000000000:
            raise _Unavailable('Code.ScannerProtocol')
        if rule == 'cryptalis-parse-recovery':
            parse_recoveries.add((path, line + 1))
        elif rule in KINDS:
            findings.add((path, line + 1, rule))
        else:
            raise _Unavailable('Code.ScannerProtocol')
    report['items'] = [dict(path=path, line=line, kind=KINDS[rule], rule=rule, status='UNKNOWN')
                       for path, line, rule in sorted(findings)]
    report['parse_recoveries'] = [dict(path=path, line=line, status='UNKNOWN')
                                for path, line in sorted(parse_recoveries)]
    report['observation'] = dict(matched_paths=len({item['file'] for item in raw}),
        candidate_calls=len(findings), parser_recoveries=len(parse_recoveries),
        scanned_paths='UNKNOWN', skipped_paths='UNKNOWN')
    if parse_recoveries:
        raise _Unavailable('Code.ParseRecovery')


def scan_routes(root, *, scanner=None, timeout=60):
    """Inventory candidate Python calls with a trusted local ast-grep executable.

    Never imports application modules or executes SQL. Relative file names and line
    numbers are reported, never source snippets, literal values or tool diagnostics.
    Scanner success is not code validity, complete coverage or runtime admission.
    """
    report = dict(format='cryptalis.doctor/v1', scope='static_code_routes', status='UNKNOWN',
        effects='LOCAL_SCANNER', source_execution='NOT_REQUESTED',
        selection='Python glob; ignore files disabled; native inline suppressions apply; symlinks not followed',
        checks={name: 'UNKNOWN' for name in ('scanner_execution', 'code_validity',
            'complete_route_inventory', 'protected_query_compatibility', 'writer_exclusion',
            'tenant_isolation', 'runtime_deployment')}, items=[], issues=[])
    try:
        if (not isinstance(root, (str, Path)) or type(timeout) not in (int, float)
                or not 0 < timeout <= 300 or os.name != 'posix'):
            raise _Unavailable('Code.InvalidInput')
        root = Path(root).resolve(strict=True)
        if not root.is_dir() or (scanner is not None and not isinstance(scanner, (str, Path))):
            raise _Unavailable('Code.InvalidInput')
        executable = shutil.which('ast-grep') if scanner is None else str(Path(scanner).resolve(strict=True))
        if executable is None:
            raise _Unavailable('Code.ScannerUnavailable')
        rules = RULES.read_bytes()
        report['rules_sha256'] = hashlib.sha256(rules).hexdigest()
        started = time.monotonic()
        environment = {key: value for key, value in os.environ.items() if not key.startswith('AST_GREP_')}
        code, version = _capture([executable, '--version'], root, environment, timeout)
        if code != 0 or version.strip() != ('ast-grep ' + VERSION).encode():
            raise _Unavailable('Code.ScannerVersion')
        report['scanner_version'] = VERSION
        inline = '\n---\n'.join(json.dumps(rule) for rule in json.loads(rules))
        with tempfile.TemporaryDirectory(prefix='cryptalis-code-') as temporary:
            config = Path(temporary) / 'sgconfig.yml'
            config.write_text('{"ruleDirs": []}\n')
            command = [executable, 'scan', '--config', str(config), '--custom-languages=ignore',
                '--inline-rules', inline, '--json=compact', '--globs=*.py', '--threads=1',
                '--max-results=8193']
            for ignore in ('hidden', 'dot', 'exclude', 'global', 'parent', 'vcs'):
                command += ['--no-ignore', ignore]
            command.append('.')
            remaining = timeout - (time.monotonic() - started)
            if remaining <= 0:
                raise _Unavailable('Code.ScannerTimeout')
            code, output = _capture(command, root, environment, remaining)
        if RULES.read_bytes() != rules:
            raise _Unavailable('Code.RulesChanged')
        _observations(json.loads(output), report)
        if code != 0:
            raise _Unavailable('Code.ScannerFailed')
    except _Unavailable as failure:
        code = failure.code
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        code = 'Code.InspectionUnavailable'
    else:
        report['checks']['scanner_execution'] = 'PASS'
        report['issues'].append(dict(code='Code.CoverageUnknown',
            remedy='Review candidate calls against the manifest and writer inventory. Account for ignored, oversized, unparsed, generated, dynamic and external routes; verify admitted operations in real application journeys.'))
        return report
    if code == 'Code.InvalidInput':
        report['status'] = report['checks']['scanner_execution'] = 'FAIL'
    report['issues'].append(dict(code=code,
        remedy='Inspect the selected source directory and trusted ast-grep 0.51.0 installation. Resolve scanner errors or limits and repeat; no complete route coverage has been established.'))
    return report
