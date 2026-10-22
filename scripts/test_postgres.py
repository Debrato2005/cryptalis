"""Run pytest only after fresh private credentials pass real PostgreSQL probes.

Usage: .venv/bin/python scripts/test_postgres.py -- [pytest arguments]
No inherited test URL is admitted. Failure output contains no connection detail.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import subprocess
import time
from types import ModuleType

import psycopg
from psycopg.conninfo import conninfo_to_dict, make_conninfo


VARIABLES = ("CRYPTALIS_TEST_DATABASE_URL", "CRYPTALIS_TEST_RUNTIME_DATABASE_URL")
FILES = (".cryptalis-test-url", ".cryptalis-test-runtime-url")
ROOT = Path(__file__).resolve().parents[1]


def source_hashes():
    files = sorted(path for directory in ('src/cryptalis', 'tests', 'scripts')
                   for path in (ROOT / directory).rglob('*.py'))
    return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in files}


def load_urls():
    for name in VARIABLES:
        os.environ.pop(name, None)
    return tuple((Path.home() / name).read_text().strip().replace(
        "postgresql+psycopg://", "postgresql://", 1) for name in FILES)


def fingerprints(urls):
    return tuple(hashlib.sha256(value.encode()).hexdigest()[:8] for value in urls)


def preflight(urls):
    try:
        for value in urls:
            with psycopg.connect(value, connect_timeout=5) as connection:
                if connection.execute("select 1").fetchone() != (1,):
                    raise RuntimeError("unexpected probe result")
    except Exception as exc:
        print(type(exc).__name__, *fingerprints(urls), flush=True)
        return False
    return True


class Results:
    def __init__(self):
        self.counts = {}
        self.modules = {}

    def pytest_runtest_logreport(self, report):
        if report.when == "call" or report.failed:
            key = report.outcome if report.when == "call" else "errors"
            self.counts[key] = self.counts.get(key, 0) + 1
            counts = self.modules.setdefault(report.nodeid.split("::", 1)[0], {})
            counts[key] = counts.get(key, 0) + 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--wrong-password-proof", action="store_true",
                        help="Use a public wrong password in the owner probe; run no tests.")
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--scope", default="PostgreSQL verification; research prototype")
    parser.add_argument("--receipt-dir", type=Path,
                        help="Write new revision-bound full and slice 3/4/5 receipts.")
    parser.add_argument("pytest_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    try:
        urls = load_urls()
        if not all(urls):
            raise ValueError("empty credentials")
        if args.wrong_password_proof:
            values = conninfo_to_dict(urls[0])
            values["password"] = "CRYPTALIS_WRONG_PASSWORD_AUDIT_20261009"
            urls = (make_conninfo(**values), urls[1])
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
    for name, value in zip(VARIABLES, urls):
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
    code = 4 if changed else pytest_code
    if changed:
        print('Verification.SourceChanged: review the changes, then run the wrapper again.', flush=True)
    if args.receipt or args.receipt_dir:
        revision = hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()
        receipt = {
            "scope": args.scope,
            "base_revision": base,
            "fixing_revision": "worktree-" + revision[:16],
            "source_test_sha256": hashes,
            "source_stability": {"unchanged": not changed, "changed_paths": changed},
            "source_after_sha256": {path: after.get(path) for path in changed},
            "preflight": {"select_1_each": "passed", "sha256_prefixes": fingerprints(urls)},
            "pytest_args": pytest_args, "counts": results.counts, "exit_code": code,
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
