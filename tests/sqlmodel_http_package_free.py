"""Original HTTP restart in a child that refuses Cryptalis imports."""
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory


_CHILD = r'''
import importlib.abc, json, os, runpy, sys
from uuid import UUID

class DenyCryptalis(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'cryptalis' or fullname.startswith('cryptalis.'):
            raise ImportError('Cryptalis import denied after removal')

sys.meta_path.insert(0, DenyCryptalis())
sys.path[:0] = json.loads(os.environ['SQLMODEL_HTTP_CHILD_PATHS'])
try:
    import cryptalis
except ImportError:
    pass
else:
    raise AssertionError('Cryptalis import guard did not refuse')

import psycopg
from sqlalchemy import create_engine
from sqlmodel import Session
from app.main import app
from app.models import User
from app.core.db import engine as original_engine

workload = runpy.run_path(os.environ['SQLMODEL_HTTP_CHILD_WORKLOAD'])
engine = create_engine('postgresql+psycopg://', hide_parameters=True,
    creator=lambda: psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'],
        options='-csearch_path=' + os.environ['SQLMODEL_HTTP_CHILD_SCHEMA']))
try:
    retained = json.loads(sys.stdin.read())
    current = workload['workflow'](app, lambda: Session(engine), retained=retained)
    assert type(current['is_active']) is bool and current['is_active'] is True
    assert all(type(current[field]) is str for field in ('id', 'email', 'full_name'))
    assert str(UUID(current['id'])) == current['id']
    with Session(engine) as session:
        latest = session.get(User, UUID(current['id']))
        assert latest.email == current['email'] and latest.full_name == current['full_name']
        assert type(latest.is_active) is bool and latest.is_active is True
        inactive = session.get(User, UUID(current['inactive']['id']))
        assert inactive.email == current['inactive']['email']
        assert type(inactive.is_active) is bool and inactive.is_active is False
    assert not any(name == 'cryptalis' or name.startswith('cryptalis.') for name in sys.modules)
    print(json.dumps({'native_http': 'passed', 'retained_latest': 'passed',
        'inactive_false': True, 'cryptalis_imported': False,
        'cryptalis_import_refused': True, 'smtp_exercised': False}))
finally:
    engine.dispose()
    original_engine.dispose()
'''


def run(copied, schema, retained):
    """Return a safe summary after the unchanged original HTTP journey."""
    environment = dict(os.environ,
        PROJECT_NAME='Cryptalis disposable HTTP restart profile',
        POSTGRES_SERVER='unused.invalid', POSTGRES_USER='unused',
        POSTGRES_PASSWORD='PUBLIC unused', FIRST_SUPERUSER='owner@example.com',
        FIRST_SUPERUSER_PASSWORD='PUBLIC unused password',
        SECRET_KEY='PUBLIC disposable configuration key 2026',
        ENVIRONMENT='local', SMTP_HOST='', EMAILS_FROM_EMAIL='', SENTRY_DSN='',
        SQLMODEL_HTTP_CHILD_PATHS=json.dumps([str(Path(copied).resolve() / 'backend'), *sys.path]),
        SQLMODEL_HTTP_CHILD_SCHEMA=schema,
        SQLMODEL_HTTP_CHILD_WORKLOAD=str(Path(__file__).with_name('sqlmodel_http_workload.py').resolve()))
    with TemporaryDirectory(prefix='cryptalis-http-package-free-') as directory:
        empty = Path(directory) / 'empty'
        empty.mkdir()
        try:
            child = subprocess.run([sys.executable, '-B', '-I', '-c', _CHILD],
                input=json.dumps(retained), env=environment, cwd=empty,
                capture_output=True, text=True, timeout=120)
        except subprocess.TimeoutExpired:
            raise AssertionError('Package-free HTTP restart timed out; diagnostics suppressed') from None
    assert child.returncode == 0, 'Package-free HTTP restart failed; diagnostics suppressed'
    expected = {'native_http': 'passed', 'retained_latest': 'passed',
        'inactive_false': True, 'cryptalis_imported': False,
        'cryptalis_import_refused': True, 'smtp_exercised': False}
    try:
        observed = json.loads(child.stdout)
    except (ValueError, TypeError):
        raise AssertionError('Package-free HTTP restart output failed; diagnostics suppressed') from None
    assert observed == expected, 'Package-free HTTP restart summary failed'
    return observed
