"""Require the fresh-credential wrapper and redact real connection failures."""
import os
import sys

import psycopg
import pytest
from sqlalchemy.exc import DBAPIError


def pytest_sessionstart(session):
    if "_cryptalis_test_preflight" not in sys.modules:
        raise pytest.UsageError("Run tests through .venv/bin/python scripts/test_postgres.py -- [pytest arguments].")


@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if call.excinfo is None:
        return
    seen, error = set(), call.excinfo.value
    while error is not None and id(error) not in seen:
        seen.add(id(error))
        if isinstance(error, (psycopg.OperationalError, psycopg.InterfaceError, DBAPIError)):
            # Do not format tracebacks, chained driver messages, SQL, or locals.
            report.longrepr = f"{item.nodeid}: {type(error).__name__}; database failure details suppressed."
            report.sections = []
            return
        error = error.__cause__ or error.__context__
    # Connection messages embedded in assertion/report text must not leak either.
    if report.failed and report.longrepr:
        rendered = str(report.longrepr)
        for name in ("CRYPTALIS_TEST_DATABASE_URL", "CRYPTALIS_TEST_RUNTIME_DATABASE_URL"):
            value = os.environ.get(name)
            if value and value in rendered:
                report.longrepr = f"{item.nodeid}: database credential diagnostics suppressed."
                report.sections = []
                return
