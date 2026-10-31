"""Run pytest only after fresh private credentials pass real PostgreSQL probes.

Usage: .venv/bin/python scripts/test_postgres.py -- [pytest arguments]
No inherited test URL is admitted. Failure output contains no connection detail.
"""
import argparse
import atexit
from contextlib import redirect_stderr, redirect_stdout
import errno
import hashlib
import importlib
import importlib.util
import io
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import re
import shutil
import socket
import stat
import sys
import subprocess
import tempfile
import time
from types import ModuleType
import zipfile

try:
    import psycopg
    from psycopg.conninfo import conninfo_to_dict, make_conninfo
except ImportError:
    psycopg = None


VARIABLES = ("CRYPTALIS_TEST_DATABASE_URL", "CRYPTALIS_TEST_RUNTIME_DATABASE_URL")
FILES = (".cryptalis-test-url", ".cryptalis-test-runtime-url")
SOURCE_VARIABLE = "CRYPTALIS_TEST_SOURCE_URL"
SOURCE_FILE = ".cryptalis-test-source-url"
CONFIG_DIRECTORY = "CRYPTALIS_TEST_CONFIG_DIR"
ROOT = Path(__file__).resolve().parents[1]
_RUNTIME_CACHE = None


def source_hashes():
    files = sorted(path for directory in ('src/cryptalis', 'tests', 'scripts')
                   for path in (ROOT / directory).rglob('*.py'))
    return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in files}


class RuntimeBindingError(Exception):
    """The package imported for qualification does not match its declared source."""


def _runtime_cache():
    """Compile package imports from the bound source files, not stale pyc files."""
    global _RUNTIME_CACHE
    if _RUNTIME_CACHE is None:
        _RUNTIME_CACHE = tempfile.TemporaryDirectory(prefix="cryptalis-runtime-pycache-")
        sys.pycache_prefix = _RUNTIME_CACHE.name
        atexit.register(_RUNTIME_CACHE.cleanup)


def _candidate_package_root():
    try:
        spec = importlib.util.find_spec("cryptalis")
        if spec is None or spec.origin is None:
            raise RuntimeBindingError
        origin_path = Path(spec.origin)
        locations = list(spec.submodule_search_locations or ())
        if (origin_path.is_symlink() or any(Path(location).is_symlink() for location in locations)
                or origin_path.name != "__init__.py" or len(locations) != 1):
            raise RuntimeBindingError
        origin = origin_path.resolve(strict=True)
        package_root = Path(locations[0]).resolve(strict=True)
        if origin.parent != package_root:
            raise RuntimeBindingError
        return package_root
    except RuntimeBindingError:
        raise
    except Exception:
        raise RuntimeBindingError from None


def _module_key(relative):
    return "cryptalis/" + relative.as_posix()


def _module_digest(modules):
    hashes = {name: hashlib.sha256(content).hexdigest()
              for name, content in sorted(modules.items())}
    encoded = json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode()
    return hashes, hashlib.sha256(encoded).hexdigest()


def _read_installed_wheel(installed_wheel):
    try:
        candidate = Path(installed_wheel).expanduser()
        if candidate.is_symlink():
            raise RuntimeBindingError
        wheel_path = candidate.resolve(strict=True)
        if not wheel_path.is_file() or wheel_path.suffix != ".whl":
            raise RuntimeBindingError
        wheel_bytes = wheel_path.read_bytes()
        wheel_sha256 = hashlib.sha256(wheel_bytes).hexdigest()
        modules = {}
        with zipfile.ZipFile(io.BytesIO(wheel_bytes)) as archive:
            names = archive.namelist()
            if len(names) != len(set(names)):
                raise RuntimeBindingError
            for name in names:
                if not name.startswith("cryptalis/") or not name.endswith(".py"):
                    continue
                relative = PurePosixPath(name)
                if (relative.is_absolute() or "\\" in name
                        or any(part in ("", ".", "..") for part in name.split("/"))):
                    raise RuntimeBindingError
                modules[name] = archive.read(name)
        if "cryptalis/__init__.py" not in modules:
            raise RuntimeBindingError
        return wheel_path, wheel_sha256, modules
    except RuntimeBindingError:
        raise
    except Exception:
        raise RuntimeBindingError from None


def _read_package_modules(package_root):
    try:
        modules = {}
        for path in sorted(package_root.rglob("*.py")):
            if path.is_symlink():
                raise RuntimeBindingError
            modules[_module_key(path.relative_to(package_root))] = path.read_bytes()
        if "cryptalis/__init__.py" not in modules:
            raise RuntimeBindingError
        return modules
    except RuntimeBindingError:
        raise
    except Exception:
        raise RuntimeBindingError from None


def _validate_package_tree(package_root, expected_hashes):
    try:
        modules = _read_package_modules(package_root)
        actual_hashes, _ = _module_digest(modules)
        if actual_hashes != expected_hashes:
            raise RuntimeBindingError
        for name, module in tuple(sys.modules.items()):
            if name != "cryptalis" and not name.startswith("cryptalis."):
                continue
            filename = getattr(module, "__file__", None)
            if not isinstance(filename, (str, os.PathLike)):
                raise RuntimeBindingError
            source_path = Path(filename)
            if source_path.is_symlink() or source_path.suffix != ".py":
                raise RuntimeBindingError
            path = source_path.resolve(strict=True)
            relative = path.relative_to(package_root)
            key = _module_key(relative)
            if key not in expected_hashes or hashlib.sha256(path.read_bytes()).hexdigest() != expected_hashes[key]:
                raise RuntimeBindingError
    except RuntimeBindingError:
        raise
    except Exception:
        raise RuntimeBindingError from None


def _import_bound_package(package_root):
    try:
        # Startup hooks and package import diagnostics are not trusted output.
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            package = importlib.import_module("cryptalis")
        origin_path = Path(package.__file__)
        locations = list(package.__path__)
        if (origin_path.is_symlink() or any(Path(location).is_symlink() for location in locations)
                or origin_path.resolve(strict=True) != package_root / "__init__.py"
                or len(locations) != 1 or Path(locations[0]).resolve(strict=True) != package_root):
            raise RuntimeBindingError
    except RuntimeBindingError:
        raise
    except Exception:
        raise RuntimeBindingError from None


def runtime_binding(installed_wheel=None):
    """Bind imported Cryptalis module bytes to this checkout or one wheel."""
    _runtime_cache()
    package_root = _candidate_package_root()
    wheel_path = None
    wheel_sha256 = None
    expected_root = (ROOT / "src" / "cryptalis").resolve()
    if installed_wheel is None:
        if package_root != expected_root:
            raise RuntimeBindingError
        mode = "source"
        modules = _read_package_modules(package_root)
    else:
        wheel_path, wheel_sha256, modules = _read_installed_wheel(installed_wheel)
        if package_root == expected_root or expected_root in package_root.parents:
            raise RuntimeBindingError
        mode = "installed-wheel"
    expected_hashes, modules_sha256 = _module_digest(modules)
    _validate_package_tree(package_root, expected_hashes)
    _import_bound_package(package_root)
    _validate_package_tree(package_root, expected_hashes)
    return {
        "mode": mode,
        "runtime_root": str(package_root),
        "module_count": len(modules),
        "modules_sha256": modules_sha256,
        "wheel": str(wheel_path) if wheel_path else None,
        "wheel_sha256": wheel_sha256,
    }


def configuration_directory():
    """Select an explicit private-file directory without changing HOME."""
    selected = os.environ.get(CONFIG_DIRECTORY)
    if selected is None:
        return Path.home()
    directory = Path(selected)
    if not selected or not directory.is_absolute():
        raise ValueError("Configuration.InvalidDirectory")
    return directory


def _private_url(path):
    # Check the opened inode: no symlink following, FIFO blocking or unbounded read.
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or not 0 < info.st_size <= 65536):
            raise ValueError("Configuration.UnsafeFile")
        content = source.read(65537)
        if not 0 < len(content) <= 65536:
            raise ValueError("Configuration.UnsafeFile")
    value = content.decode("utf-8").strip()
    if not value:
        raise ValueError("Configuration.EmptyFile")
    return value.replace("postgresql+psycopg://", "postgresql://", 1)


def load_urls(*, source_role=False):
    for name in (*VARIABLES, SOURCE_VARIABLE):
        os.environ.pop(name, None)
    files = FILES + ((SOURCE_FILE,) if source_role else ())
    directory = configuration_directory()
    return tuple(_private_url(directory / name) for name in files)


def fingerprints(urls):
    return tuple(hashlib.sha256(value.encode()).hexdigest()[:8] for value in urls)


def preflight(urls, *, observations=None):
    try:
        for value in urls:
            with psycopg.connect(value, connect_timeout=5) as connection:
                if observations is not None:
                    connection.execute('SET TRANSACTION READ ONLY')
                if connection.execute("select 1").fetchone() != (1,):
                    raise RuntimeError("unexpected probe result")
                if observations is not None:
                    facts = connection.execute("""
                        SELECT current_database(), current_user, inet_server_addr()::text,
                            inet_server_port(), (SELECT oid::text FROM pg_catalog.pg_database
                                WHERE datname=current_database()),
                            current_setting('server_version_num')::int,
                            pg_catalog.pg_is_in_recovery(),
                            current_setting('default_transaction_read_only')::boolean,
                            session_user=current_user, rolsuper, rolcreaterole, rolcreatedb,
                            rolreplication, rolbypassrls,
                            pg_catalog.has_database_privilege(current_database(),'CREATE'),
                            pg_catalog.has_database_privilege(current_database(),'CONNECT')
                        FROM pg_catalog.pg_roles WHERE rolname=current_user
                    """).fetchone()
                    assumes_owner = bool(observations) and connection.execute(
                        "SELECT pg_catalog.pg_has_role(%s,'MEMBER')",
                        (observations[0]['facts'][1],)).fetchone()[0]
                    owns_objects = connection.execute("""
                        SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_class c
                            JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
                            JOIN pg_catalog.pg_roles r ON r.oid=c.relowner
                            WHERE r.rolname=current_user AND left(n.nspname,3) <> 'pg_'
                                AND n.nspname <> 'information_schema')
                        OR EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n
                            JOIN pg_catalog.pg_roles r ON r.oid=n.nspowner
                            WHERE r.rolname=current_user AND left(n.nspname,3) <> 'pg_'
                                AND n.nspname <> 'information_schema')
                    """).fetchone()[0]
                    observations.append({'facts': facts, 'assumes_owner': assumes_owner,
                                         'owns_objects': owns_objects})
    except Exception as exc:
        if observations is None:
            print(type(exc).__name__, *fingerprints(urls), flush=True)
        else:
            state = getattr(exc, 'sqlstate', None)
            observations.append({'failure': 'PostgreSQL.AuthenticationDenied'
                                 if state and state.startswith('28') else 'PostgreSQL.Unavailable'})
        return False
    return True


def development_preflight():
    """Diagnose this execution context without running pytest or changing policy.

    Private test files identify the configured target. Only the operator can
    authorize that target as disposable. No name or successful probe proves it.
    """
    checks = {}
    def record(name, status, code, remedy='', classification=None):
        checks[name] = dict(status=status, code=code, classification=classification, remedy=remedy)
    def finish():
        blocked = any(c['status'] == 'FAIL' for c in checks.values())
        print(json.dumps({'status': 'BLOCKED' if blocked else 'READY_FOR_APPROVED_TESTS',
                          'checks': checks}, sort_keys=True))
        return 2 if blocked else 0

    record('target_authorization', 'UNKNOWN', 'Target.OperatorAuthorizationRequired',
           'Use only an operator-approved disposable target. This check authorizes no database changes.',
           'external_prerequisite')
    try:
        if sys.version_info < (3, 12):
            raise ImportError
        for name in ('pytest', 'sqlalchemy', 'psycopg', 'greenlet'):
            importlib.import_module(name)
        from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
        if psycopg is None or AESGCMSIV is None:
            raise ImportError
        record('dependencies', 'PASS', 'Dependencies.Available')
    except Exception:
        record('dependencies', 'FAIL', 'Dependencies.Unavailable',
               'Use Python 3.12+ with the locked project environment.', 'external_prerequisite')
        return finish()
    uv_on_path = shutil.which('uv')
    uv = uv_on_path or str(Path.home() / '.local/bin/uv')
    if shutil.which('git') and os.access(uv, os.X_OK):
        record('build_tools', 'PASS', 'Tools.Available',
               'Include the uv executable directory in PATH for builds.',
               None if uv_on_path else 'automatically_repairable')
    else:
        record('build_tools', 'FAIL', 'Tools.Unavailable',
               'Provide git and uv in the development environment.', 'external_prerequisite')
    pg_bin = Path('/usr/lib/postgresql/16/bin')
    available = True
    for name in ('postgres', 'initdb', 'pg_ctl', 'pg_dump', 'pg_restore'):
        executable = shutil.which(name) or str(pg_bin / name)
        try:
            result = subprocess.run([executable, '--version'], capture_output=True, text=True,
                                    check=True, timeout=5)
            available = bool(re.search(r'\(PostgreSQL\) 16(?:\.|$)', result.stdout.strip())) and available
        except (OSError, subprocess.SubprocessError):
            available = False
    record('fresh_cluster_tools', 'PASS' if available else 'UNKNOWN', 'Tools.PostgreSQL16',
           '' if available else 'Provide PostgreSQL 16 tools before fresh-cluster qualification.')
    try:
        git_dir = subprocess.run(['git', 'rev-parse', '--absolute-git-dir'], cwd=ROOT,
                                 capture_output=True, text=True, check=True).stdout.strip()
        for directory in (ROOT, git_dir):
            with tempfile.TemporaryFile(dir=directory) as probe:
                probe.write(b'cryptalis-development-preflight')
                probe.flush()
                probe.seek(0)
                if probe.read() != b'cryptalis-development-preflight':
                    raise RuntimeError
        record('git_metadata', 'PASS', 'Git.Writable')
    except OSError as exc:
        restricted = exc.errno in (errno.EROFS, errno.EPERM, errno.EACCES)
        record('git_metadata', 'FAIL', 'Git.WriteUnavailable',
               'Use scoped supported approval or a complete clone in an approved writable location. Do not remount or change ownership.',
               'authorized_alternative' if restricted else 'external_prerequisite')
    except Exception:
        record('git_metadata', 'FAIL', 'Git.InspectionFailed',
               'Inspect the checkout and Git executable before continuing.', 'implementation_defect')
    try:
        urls = load_urls()
        config = [conninfo_to_dict(url) for url in urls]
        target = lambda value: tuple(value.get(key) for key in ('host', 'hostaddr', 'port', 'dbname', 'service'))
        if (any(not all(value.get(key) for key in ('host', 'port', 'dbname', 'user')) for value in config)
                or target(config[0]) != target(config[1]) or config[0]['user'] == config[1]['user']
                or any(value.get('service') or ',' in value['host'] for value in config)):
            raise ValueError
        record('test_configuration', 'PASS', 'Configuration.PrivateFilesAndSeparateRoles')
    except Exception:
        record('test_configuration', 'FAIL', 'Configuration.UnsafeOrUnavailable',
               'Provide two owned private regular test URL files for one explicit target and separate roles. Do not use production.',
               'external_prerequisite')
        return finish()
    try:
        family = socket.AF_UNIX if all(value['host'].startswith('/') for value in config) else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM):
            pass
        record('sockets', 'PASS', 'Socket.CreationAllowed')
    except OSError:
        record('sockets', 'FAIL', 'Socket.CreationDenied',
               'Use the supported scoped execution approval. Do not change sandbox policy.', 'authorized_alternative')
    if any(c['status'] == 'FAIL' for c in checks.values()):
        return finish()
    observations = []
    if not preflight(urls, observations=observations):
        record('postgresql16', 'FAIL', observations[-1]['failure'],
               'Inspect service availability and approved credentials. Correct the cause before another probe.',
               'external_prerequisite')
        return finish()
    owner, runtime = (item['facts'] for item in observations)
    identity = lambda facts: (facts[0], *facts[2:5])
    native = all(facts[5] // 10000 == 16 and not any(facts[6:8]) and facts[8] for facts in (owner, runtime))
    record('postgresql16', 'PASS' if native else 'FAIL', 'PostgreSQL.VersionAndWritablePrimary',
           '' if native else 'Use the approved PostgreSQL 16 writable primary.',
           None if native else 'external_prerequisite')
    restricted = (identity(owner) == identity(runtime) and owner[1] != runtime[1]
                  and not any(owner[9:14]) and not any(runtime[9:14])
                  and owner[14] and owner[15] and not runtime[14] and runtime[15]
                  and not observations[1]['assumes_owner'] and not observations[1]['owns_objects'])
    record('restricted_roles', 'PASS' if restricted else 'FAIL', 'PostgreSQL.SeparateRestrictedRoles',
           '' if restricted else 'Provision separate nonprivileged roles on the same disposable target. The owner needs database CREATE. Runtime must lack database CREATE, cannot assume the owner, and cannot own application schemas or relations.',
           None if restricted else 'external_prerequisite')
    return finish()


class Results:
    def __init__(self):
        from _pytest.reports import TestReport
        try:
            from _pytest.subtests import SubtestReport
        except ImportError:
            SubtestReport = ()
        self._test_report_type = TestReport
        self._subtest_report_type = SubtestReport
        self._reports = []
        self._collection_reports = []
        self.counts = {}
        self.modules = {}
        self.pytest_report_counts = {}

    def pytest_runtest_logreport(self, report):
        if isinstance(report, self._test_report_type):
            self._reports.append(report)
        if report.when == "call" or report.failed:
            key = report.outcome if report.when == "call" else "errors"
            self.counts[key] = self.counts.get(key, 0) + 1
            counts = self.modules.setdefault(report.nodeid.split("::", 1)[0], {})
            counts[key] = counts.get(key, 0) + 1

    def pytest_collectreport(self, report):
        if report.skipped or report.failed:
            self._collection_reports.append(report)

    def pytest_sessionfinish(self, session, exitstatus):
        # Reporting hooks can change a parent outcome after a subtest fails.
        # Keep report references and partition their final raw outcomes here.
        counts = {name: {} for name in (
            'test_calls', 'subtest_calls', 'setup', 'teardown', 'collection')}
        # A parallel controller collects nothing; each selected test still reports.
        counts['selected_items'] = len(session.items) or len({report.nodeid for report in self._reports})
        for report in self._reports:
            if report.when == 'call':
                category = ('subtest_calls' if isinstance(report, self._subtest_report_type)
                            else 'test_calls')
            else:
                category = report.when
            bucket = counts[category]
            bucket[report.outcome] = bucket.get(report.outcome, 0) + 1
        for report in self._collection_reports:
            bucket = counts['collection']
            bucket[report.outcome] = bucket.get(report.outcome, 0) + 1
        self.pytest_report_counts = counts


def main():
    for name in (*VARIABLES, SOURCE_VARIABLE):
        os.environ.pop(name, None)
    parser = argparse.ArgumentParser(description=__doc__)
    diagnostics = parser.add_mutually_exclusive_group()
    diagnostics.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--source-role", action="store_true",
                        help="Also require and probe .cryptalis-test-source-url in the private configuration directory.")
    parser.add_argument("--installed-wheel", type=Path,
                        help="Bind imported Cryptalis Python modules to this inspected wheel.")
    diagnostics.add_argument("--runtime-binding-only", action="store_true",
                             help="Verify and report runtime package identity without database access or pytest.")
    diagnostics.add_argument("--development-preflight", action="store_true",
                             help="Diagnose local tools, Git access and restricted PostgreSQL prerequisites; run no tests.")
    diagnostics.add_argument("--wrong-password-proof", action="store_true",
                             help="Use a public wrong password in the owner probe; run no tests.")
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--scope", default="PostgreSQL verification; research prototype")
    parser.add_argument("--receipt-dir", type=Path,
                        help="Write new revision-bound full and slice 3/4/5 receipts.")
    parser.add_argument("pytest_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.development_preflight:
        return development_preflight()
    try:
        runtime_before = runtime_binding(args.installed_wheel)
    except Exception:
        print("Verification.RuntimeBindingFailed: imported package does not match the selected runtime.",
              flush=True)
        return 4
    if args.runtime_binding_only:
        print(json.dumps({"runtime_binding": runtime_before}, sort_keys=True), flush=True)
        return 0
    if psycopg is None:
        print('Dependencies.Unavailable: use the locked project environment.', flush=True)
        return 2
    try:
        urls = load_urls(source_role=args.source_role)
        if not all(urls):
            raise ValueError("empty credentials")
        if args.wrong_password_proof:
            values = conninfo_to_dict(urls[0])
            values["password"] = "CRYPTALIS_WRONG_PASSWORD_AUDIT_20261009"
            urls = (make_conninfo(**values), *urls[1:])
    except Exception as exc:
        print(type(exc).__name__, flush=True)
        return 2
    if not preflight(urls):
        return 2
    if args.wrong_password_proof:
        print("UnexpectedAuthenticationSuccess", *fingerprints(urls), flush=True)
        return 2
    print("PostgreSQL preflight passed", *fingerprints(urls), flush=True)
    if args.preflight_only:
        return 0
    variables = VARIABLES + ((SOURCE_VARIABLE,) if args.source_role else ())
    for name, value in zip(variables, urls):
        os.environ[name] = value
    # In-process attestation cannot arrive through inherited environment values.
    admission = ModuleType("_cryptalis_test_preflight")
    admission.fingerprints = fingerprints(urls)
    sys.modules[admission.__name__] = admission
    import pytest
    results = Results()
    pytest_args = args.pytest_args
    if pytest_args[:1] == ["--"]:
        pytest_args = pytest_args[1:]
    os.chdir(ROOT)
    try:
        hashes = source_hashes()
    except OSError as error:
        print('Verification.SourceUnavailable', type(error).__name__, flush=True)
        return 4
    base = None
    if args.receipt or args.receipt_dir:
        base = subprocess.run(["git", "rev-parse", "HEAD"],
                              cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, check=True).stdout.strip()
    started = time.perf_counter()
    pytest_code = int(pytest.main(pytest_args, plugins=[results]))
    elapsed = time.perf_counter() - started
    try:
        after = source_hashes()
    except OSError as error:
        print('Verification.SourceUnavailable', type(error).__name__, flush=True)
        return 4
    changed = sorted(path for path in hashes.keys() | after.keys() if hashes.get(path) != after.get(path))
    runtime_after = None
    runtime_changed = False
    try:
        runtime_after = runtime_binding(args.installed_wheel)
        runtime_changed = runtime_after != runtime_before
    except Exception:
        runtime_changed = True
    code = 4 if changed or runtime_changed else pytest_code
    if changed:
        print('Verification.SourceChanged: review the changes, then run the wrapper again.', flush=True)
    if runtime_changed:
        print('Verification.RuntimeBindingChanged: runtime package bytes changed during pytest.', flush=True)
    if args.receipt or args.receipt_dir:
        revision = hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()
        receipt = {
            "scope": args.scope,
            "base_revision": base,
            "fixing_revision": "worktree-" + revision[:16],
            "source_test_sha256": hashes,
            "source_stability": {"unchanged": not changed, "changed_paths": changed},
            "source_after_sha256": {path: after.get(path) for path in changed},
            "runtime_binding": runtime_before,
            "runtime_binding_stability": {"unchanged": not runtime_changed,
                                          "after": runtime_after},
            "preflight": {"select_1_each": "passed", "sha256_prefixes": fingerprints(urls)},
            "pytest_args": pytest_args, "counts": results.counts, "exit_code": code,
            "pytest_report_counts": results.pytest_report_counts,
            "pytest_exit_code": pytest_code,
            "modules": results.modules, "elapsed_seconds": elapsed,
            "gates": {name: "UNKNOWN" for name in (
                "G-ADAPTER", "G-CRYPTO", "G-QUERY", "G-LIFECYCLE", "G-PROVIDER", "G-POLICY", "G-RELEASE")},
        }
        def write(path, content):
            # Existing receipts are immutable; a repeated revision needs a new
            # explicitly chosen filename, never an overwrite.
            with path.open("x") as stream:
                stream.write(json.dumps(content, indent=2) + "\n")
        if args.receipt:
            write(args.receipt, receipt)
        if args.receipt_dir:
            write(args.receipt_dir / f"audit-verification-{revision[:16]}.json", receipt)
            for slice_id, modules in ((3, ("test_sqlalchemy_adapter.py",)),
                                      (4, ("test_sqlalchemy_search.py",)),
                                      (5, ("test_migration.py", "test_migration_audit.py"))):
                counts = {module: results.modules.get("tests/" + module, {}) for module in modules}
                write(args.receipt_dir / f"slice{slice_id}-audit-{revision[:16]}.json",
                      dict(receipt, scope=f"Slice {slice_id} corrective rerun; research prototype",
                           slice_modules=counts))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
