"""Optional synchronous and asynchronous PostgreSQL bridge for SQLModel 0.0.48."""

try:
    from sqlmodel import Session as _NativeSession
    from sqlmodel.ext.asyncio.session import AsyncSession as _NativeAsyncSession
except ModuleNotFoundError as error:
    if error.name != 'sqlmodel':
        raise
    _NativeSession = None
    _NativeAsyncSession = None

from sqlalchemy.ext.asyncio import AsyncEngine

from ._sqlmodel_types import _version
from .sqlalchemy import (_Factory as _AlchemyFactory, _Session as _AlchemySession,
                         _AsyncSession as _AlchemyAsyncSession, _async_method,
                         UnsupportedProtectedOperation, attach as _attach)


class SQLModelUnavailable(UnsupportedProtectedOperation):
    stage = 'SQLModel dependency admission'
    remedy = 'Install the optional SQLModel 0.0.48 dependency, then restart before attachment.'


class SQLModelVersionUnsupported(UnsupportedProtectedOperation):
    stage = 'SQLModel version admission'
    remedy = 'Use SQLModel 0.0.48, then restart before attachment.'


if _NativeSession is not None:
    class _Session(_AlchemySession, _NativeSession):
        pass

    class _AsyncSession(_AlchemyAsyncSession, _NativeAsyncSession):
        _sync_session_class = _Session

        # Native exec enters a greenlet directly. Reuse execute admission and
        # awaited preparation before entering SQLModel's native result handling.
        exec = _async_method('execute', native=_NativeAsyncSession.exec)
else:
    _Session = None
    _AsyncSession = None


class _Factory(_AlchemyFactory):
    _sync_session = _Session
    _async_session = _AsyncSession


def attach(mapping, engine, *, lock, keys, deployment=None):
    """Attach with native SQLModel Session.exec scalar and tuple results.

    The host supplies the same lock, key policy and tenant scope as for the
    SQLAlchemy adapter. Await this call for an AsyncEngine.
    """
    if _NativeSession is None:
        raise SQLModelUnavailable()
    if _version != '0.0.48':
        raise SQLModelVersionUnsupported()
    factory = _attach(mapping, engine, lock=lock, keys=keys, deployment=deployment)
    if isinstance(engine, AsyncEngine):
        async def finish():
            return _Factory((await factory)._owner)
        return finish()
    return _Factory(factory._owner)
