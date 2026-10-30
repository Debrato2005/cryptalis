"""Guard the attached engine's public driver routes, including reconnects."""

from contextvars import ContextVar
from datetime import date, datetime, time, timedelta
from decimal import Decimal
from functools import wraps
from uuid import UUID
from sqlalchemy import event

_driver_permit = ContextVar("cryptalis_driver_permit", default=None)


def _snapshot(value, binary):
    if type(value) is binary:
        if type(value.obj) not in (bytes, bytearray, memoryview):
            raise TypeError()
        return binary, memoryview(value.obj).tobytes()
    if type(value) in (bytearray, memoryview):
        return type(value), bytes(value)
    if type(value) is dict:
        if any(not isinstance(key, str) for key in value):
            raise TypeError()
        return dict, tuple((id(type(key)), str.__str__(key), _snapshot(item, binary), type(key))
                           for key, item in value.items())
    if type(value) in (list, tuple):
        return type(value), tuple(_snapshot(item, binary) for item in value)
    if type(value) is float:
        return float, value.hex()
    if type(value) is Decimal:
        return Decimal, value.as_tuple()
    if type(value) in (type(None), bool, int, str, bytes, UUID, date, datetime, time, timedelta):
        return type(value), value
    # Unknown native adapters are unprotected values. Retain their identity,
    # including a reference that prevents object-ID reuse during dispatch.
    return type(value), id(value), value


def _checked(value, check_process):
    if not callable(value):
        return value
    @wraps(value)
    def invoke(*args, **kwargs):
        # Capturing a bound native method before fork must not bypass ownership.
        check_process()
        return value(*args, **kwargs)
    return invoke


class _Info:
    def __init__(self, raw, error, check_process):
        self._raw, self._error, self._check_process = raw, error, check_process

    def __getattr__(self, name):
        self._check_process()
        if name in ("parameter_status", "transaction_status", "server_version", "encoding", "backend_pid", "status"):
            return _checked(getattr(self._raw, name), self._check_process)
        raise self._error()


class _Cursor:
    def __init__(self, raw, connection, error, check_process):
        self._raw, self._connection, self._error = raw, connection, error
        self._check_process = check_process
        self._pending = None
        self._completed = None
        self._native_page = None

    def __getattr__(self, name):
        self._check_process()
        if name in ("description", "rowcount", "arraysize", "fetchone", "fetchmany", "fetchall", "close", "closed", "statusmessage"):
            return _checked(getattr(self._raw, name), self._check_process)
        raise self._error()

    def __setattr__(self, name, value):
        if name == "arraysize":
            self._check_process()
            self._raw.arraysize = value
        else:
            object.__setattr__(self, name, value)

    def _check(self):
        self._check_process()
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
        self._check_process()
        raise self._error()

    def __iter__(self):
        self._check_process()
        return self

    def __next__(self):
        self._check_process()
        return next(self._raw)

    def __enter__(self):
        self._check_process()
        self._raw.__enter__()
        return self

    def __exit__(self, *args):
        self._check_process()
        return self._raw.__exit__(*args)


class _Connection:
    def __init__(self, raw, error, check_process):
        object.__setattr__(self, "_raw", raw)
        object.__setattr__(self, "_error", error)
        object.__setattr__(self, "_check_process", check_process)

    def __getattr__(self, name):
        self._check_process()
        if name == "info":
            return _Info(self._raw.info, self._error, self._check_process)
        if name == "_connection":
            # Async dialect driver_connection must not expose its underlying
            # psycopg AsyncConnection. Only the native adapter uses that handle.
            return self
        if name in ("commit", "rollback", "close", "closed", "broken", "autocommit", "isolation_level", "read_only", "deferrable"):
            return _checked(getattr(self._raw, name), self._check_process)
        raise self._error()

    def __setattr__(self, name, value):
        self._check_process()
        if name in ("autocommit", "isolation_level", "read_only", "deferrable"):
            setattr(self._raw, name, value)
        else:
            raise self._error()

    def cursor(self, *args, **kwargs):
        self._check_process()
        return _Cursor(self._raw.cursor(*args, **kwargs), self, self._error, self._check_process)

    def execute(self, *args, **kwargs):
        self._check_process()
        raise self._error()


def install_guard(engine, error, before_execute, check_cursor, listener_error, prepare_many, check_process):
    """Install only after target validation and draining idle native handles."""
    # Refuse the attached engine's public entrypoints before pool mutexes. A
    # fresh engine plus a fresh mapping/attachment is required in a child.
    engine.connect = _checked(engine.connect, check_process)
    engine.raw_connection = _checked(engine.raw_connection, check_process)
    event.listen(engine, "before_execute", before_execute, retval=True)

    def first(context):
        listeners = tuple(context.root_connection.dispatch.before_cursor_execute)
        return listeners and listeners[0] is capture and listeners.count(capture) == 1

    def values(parameters):
        try:
            return _snapshot(parameters, engine.dialect.dbapi.Binary) if parameters else ()
        except (TypeError, ValueError, RecursionError):
            raise listener_error() from None

    def capture(connection, cursor, statement, parameters, context, executemany):
        if not first(context) or type(cursor) is not _Cursor or type(statement) is not str:
            raise listener_error()
        cursor._completed = None
        cursor._pending = context, statement, values(parameters)
        return statement, parameters

    # retval=True preserves this function's identity in effective dispatch.
    # SQLAlchemy's insert=True does not prepend ConnectionEvents listeners.
    event.listen(engine, 'before_cursor_execute', capture, retval=True)

    def completed(connection, cursor, statement, parameters, context, executemany):
        seen, cursor._completed = cursor._completed, None
        pending, cursor._pending = cursor._pending, None
        if seen is not context or pending is not None:
            raise listener_error()

    # Dialect callbacks can return True before our dispatch handler. Require
    # actual guarded execution before SQLAlchemy reports ORM/result success.
    event.listen(engine, 'after_cursor_execute', completed)

    native_many = engine.dialect._deliver_insertmanyvalues_batches

    def many(connection, cursor, statement, parameters, generic_setinputsizes, context):
        scoped = prepare_many(context, parameters)
        if type(scoped) is not bool:
            raise listener_error()
        delegate = native_many(connection, cursor, statement, parameters, generic_setinputsizes, context)
        if not scoped:
            yield from delegate
            return
        try:
            if (type(cursor) is not _Cursor or cursor._native_page is not None or
                    type(parameters) not in (list, tuple) or not parameters):
                raise listener_error()
            original = tuple(values(row) for row in parameters)
            offset = 0
            for page in delegate:
                if type(page.batch) not in (list, tuple):
                    raise listener_error()
                size = len(page.batch)
                if (cursor._native_page is not None or type(page.current_batch_size) is not int or
                        size <= 0 or page.current_batch_size != size or offset + size > len(original) or
                        tuple(values(row) for row in page.batch) != original[offset:offset + size] or
                        type(page.replaced_statement) is not str):
                    raise listener_error()
                cursor._native_page = context, page.replaced_statement, values(page.replaced_parameters)
                offset += size
                yield page
                if cursor._native_page is not None:
                    raise listener_error()
            if offset != len(original):
                raise listener_error()
        finally:
            if type(cursor) is _Cursor:
                cursor._native_page = None
            delegate.close()

    engine.dialect._deliver_insertmanyvalues_batches = many

    def final(cursor, statement, parameters, context):
        expected, cursor._pending = cursor._pending, None
        page, cursor._native_page = cursor._native_page, None
        sent = values(parameters)
        if (expected is None or expected[0] is not context or not first(context) or type(statement) is not str or
                expected[1] != statement or expected[2] != sent):
            raise listener_error()
        if page is not None and (page[0] is not context or page[1] != statement or page[2] != sent):
            raise listener_error()
        check_cursor(context, statement, parameters, native_page=page is not None)

    def wrap(raw, entry):
        check_process()
        entry.dbapi_connection = _Connection(raw, error, check_process)

    event.listen(engine.pool, "connect", wrap)

    def execute(cursor, statement, parameters, context):
        final(cursor, statement, parameters, context)
        token = _driver_permit.set(cursor)
        try:
            cursor.execute(statement, parameters)
            cursor._completed = context
        finally:
            _driver_permit.reset(token)
        return True

    def executemany(cursor, statement, parameters, context):
        final(cursor, statement, parameters, context)
        token = _driver_permit.set(cursor)
        try:
            cursor.executemany(statement, parameters)
            cursor._completed = context
        finally:
            _driver_permit.reset(token)
        return True

    def no_parameters(cursor, statement, context):
        final(cursor, statement, (), context)
        token = _driver_permit.set(cursor)
        try:
            cursor.execute(statement)
            cursor._completed = context
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
