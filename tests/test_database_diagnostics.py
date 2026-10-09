"""Real authentication failures must not expose private connection details."""
import os
from pathlib import Path
import subprocess
import sys

import psycopg
import pytest


@pytest.mark.parametrize("route", ["driver", "sqlalchemy", "async"])
def test_suite_suppresses_real_authentication_failures(tmp_path, route):
    root = Path(__file__).resolve().parents[1]
    (tmp_path / "conftest.py").write_text((root / "tests/conftest.py").read_text())
    # This child first passes BOTH real fresh-file probes. Only the test's own
    # connection then gets a public wrong password, leaving credentials intact.
    source = '''import asyncio, os
import psycopg
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from sqlalchemy import create_engine

def test_connection():
    values = conninfo_to_dict(os.environ["CRYPTALIS_TEST_DATABASE_URL"])
    values["password"] = "CRYPTALIS_DIAGNOSTIC_WRONG_PASSWORD"
    url = make_conninfo(**values)
    if ROUTE == "driver":
        psycopg.connect(url, connect_timeout=5)
    elif ROUTE == "sqlalchemy":
        create_engine("postgresql+psycopg://", creator=lambda: psycopg.connect(url, connect_timeout=5)).connect()
    else:
        asyncio.run(psycopg.AsyncConnection.connect(url, connect_timeout=5))
'''.replace("ROUTE", repr(route))
    target = tmp_path / "test_authentication.py"
    target.write_text(source)
    child = subprocess.run([sys.executable, str(root / "scripts/test_postgres.py"), "--",
                            "-q", str(target), "--tb=long", "--showlocals"],
                           cwd=root, capture_output=True, text=True, timeout=30)
    output = child.stdout + child.stderr
    assert child.returncode == 1
    assert "OperationalError; database failure details suppressed" in output
    private = psycopg.conninfo.conninfo_to_dict(os.environ["CRYPTALIS_TEST_DATABASE_URL"])
    needles = [os.environ["CRYPTALIS_TEST_DATABASE_URL"], "CRYPTALIS_DIAGNOSTIC_WRONG_PASSWORD"]
    needles += [private.get(name, "") for name in ("host", "user", "password")]
    # Assert booleans only: a broken redactor must not leak via this assertion.
    assert not any(value and value in output for value in needles)
