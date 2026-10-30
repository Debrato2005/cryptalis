"""Optional sync and async PostgreSQL bridge for SQLModel 0.0.48."""

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
        _sync_session = _Session
        exec = _async_method('exec', _NativeAsyncSession.exec)
else:
    _Session = None
    _AsyncSession = None


class _Factory(_AlchemyFactory):
    _sync_session = _Session
    _async_session = _AsyncSession


def attach(mapping, engine, *, lock, keys, deployment=None):
    """Attach with native SQLModel Session.exec scalar and tuple results.

    The host supplies the same lock, key policy and tenant scope as for the
    SQLAlchemy adapter. Await attachment for an AsyncEngine.
    """
    if _NativeSession is None:
        raise SQLModelUnavailable()
    if _version != '0.0.48':
        raise SQLModelVersionUnsupported()
    if isinstance(engine, AsyncEngine):
        async def attach_async():
            factory = await _attach(mapping, engine, lock=lock, keys=keys, deployment=deployment)
            return _Factory(factory._owner)
        return attach_async()
    factory = _attach(mapping, engine, lock=lock, keys=keys, deployment=deployment)
    return _Factory(factory._owner)
