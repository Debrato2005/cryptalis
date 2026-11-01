"""Require the fresh-credential wrapper and redact real connection failures."""
import os
from pathlib import Path
import re
import sys

import psycopg
import pytest
from sqlalchemy.exc import DBAPIError


def pytest_sessionstart(session):
    # Parallel workers are started by a controller that has already passed the wrapper.
    if not hasattr(session.config, "workerinput") and "_cryptalis_test_preflight" not in sys.modules:
        raise pytest.UsageError("Run tests through .venv/bin/python scripts/test_postgres.py -- [pytest arguments].")


@pytest.fixture(autouse=True)
def synthetic_prefix_qualification(request):
    if request.node.get_closest_marker('prefix_qualification') is None:
        yield
        return
    from cryptalis._search_layout import _prefix_qualification
    with _prefix_qualification():
        yield


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
            state = getattr(getattr(error, 'orig', error), 'sqlstate', None)
            state = state if type(state) is str and re.fullmatch('[0-9A-Z]{5}', state) else 'UNKNOWN'
            location, frame = 'UNKNOWN', error.__traceback__
            root = Path(__file__).resolve().parents[1]
            while frame is not None:
                try:
                    path = Path(frame.tb_frame.f_code.co_filename).resolve().relative_to(root)
                except ValueError:
                    pass
                else:
                    if path.parts and path.parts[0] in ('src', 'tests', 'scripts') and path.suffix == '.py':
                        location = f'{path.as_posix()}:{frame.tb_lineno}'
                frame = frame.tb_next
            report.longrepr = (f'{item.nodeid}: {type(error).__name__}; SQLSTATE={state}; '
                               f'phase={report.when}; location={location}; database failure details suppressed.')
            report.sections = []
            return
        error = error.__cause__ or error.__context__
    # Connection messages embedded in assertion/report text must not leak either.
    if report.failed and report.longrepr:
        rendered = str(report.longrepr)
        for name in ("CRYPTALIS_TEST_DATABASE_URL", "CRYPTALIS_TEST_RUNTIME_DATABASE_URL", "CRYPTALIS_TEST_SOURCE_URL"):
            value = os.environ.get(name)
            if value and value in rendered:
                report.longrepr = f"{item.nodeid}: database credential diagnostics suppressed."
                report.sections = []
                return
