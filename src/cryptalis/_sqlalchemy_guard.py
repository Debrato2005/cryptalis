"""Guard the attached engine's public driver routes, including reconnects."""

from contextvars import ContextVar
from sqlalchemy import event

_driver_permit = ContextVar("cryptalis_driver_permit", default=None)


class _Info:
    def __init__(self, raw, error):
        self._raw, self._error = raw, error

    def __getattr__(self, name):
        if name in ("parameter_status", "transaction_status", "server_version", "encoding", "backend_pid", "status"):
            return getattr(self._raw, name)
        raise self._error()


class _Cursor:
    def __init__(self, raw, connection, error):
        self._raw, self._connection, self._error = raw, connection, error

    def __getattr__(self, name):
        if name in ("description", "rowcount", "arraysize", "fetchone", "fetchmany", "fetchall", "close", "closed", "statusmessage"):
            return getattr(self._raw, name)
        raise self._error()

    def __setattr__(self, name, value):
        if name == "arraysize":
            self._raw.arraysize = value
        else:
            object.__setattr__(self, name, value)

    def _check(self):
        if _driver_permit.get() not in (self, self._connection):
            raise self._error()

    def execute(self, *args, **kwargs):
        self._check()
        self._raw.execute(*args, **kwargs)
        return self

    def executemany(self, *args, **kwargs):
        self._check()
        self._raw.executemany(*args, **kwargs)
        return self

    def copy(self, *args, **kwargs):
        raise self._error()

    def __iter__(self):
        return iter(self._raw)

    def __enter__(self):
        self._raw.__enter__()
        return self

    def __exit__(self, *args):
        return self._raw.__exit__(*args)


class _Connection:
    def __init__(self, raw, error):
        object.__setattr__(self, "_raw", raw)
        object.__setattr__(self, "_error", error)

    def __getattr__(self, name):
        if name == "info":
            return _Info(self._raw.info, self._error)
        if name == "_connection":
            # Async dialect driver_connection must not expose its underlying
            # psycopg AsyncConnection. Only the native adapter uses that handle.
            return self
        if name in ("commit", "rollback", "close", "closed", "broken", "autocommit", "isolation_level", "read_only", "deferrable"):
            return getattr(self._raw, name)
        raise self._error()

    def __setattr__(self, name, value):
        if name in ("autocommit", "isolation_level", "read_only", "deferrable"):
            setattr(self._raw, name, value)
        else:
            raise self._error()

    def cursor(self, *args, **kwargs):
        return _Cursor(self._raw.cursor(*args, **kwargs), self, self._error)

    def execute(self, *args, **kwargs):
        raise self._error()


def install_guard(engine, error, before_execute, check_cursor):
    """Install only after target validation and draining idle native handles."""
    event.listen(engine, "before_execute", before_execute, retval=True)

    def wrap(raw, entry):
        entry.dbapi_connection = _Connection(raw, error)

    event.listen(engine.pool, "connect", wrap)

    def execute(cursor, statement, parameters, context):
        check_cursor(context)
        token = _driver_permit.set(cursor)
        try:
            cursor.execute(statement, parameters)
        finally:
            _driver_permit.reset(token)
        return True

    def executemany(cursor, statement, parameters, context):
        check_cursor(context)
        token = _driver_permit.set(cursor)
        try:
            cursor.executemany(statement, parameters)
        finally:
            _driver_permit.reset(token)
        return True

    def no_parameters(cursor, statement, context):
        check_cursor(context)
        token = _driver_permit.set(cursor)
        try:
            cursor.execute(statement)
        finally:
            _driver_permit.reset(token)
        return True

    event.listen(engine.dialect, "do_execute", execute)
    event.listen(engine.dialect, "do_executemany", executemany)
    event.listen(engine.dialect, "do_execute_no_params", no_parameters)

    # The dialect's own fixed liveness check bypasses execution events.
    native_ping = engine.dialect.do_ping
    def ping(connection):
        token = _driver_permit.set(connection)
        try:
            return native_ping(connection)
        finally:
            _driver_permit.reset(token)
    engine.dialect.do_ping = ping
