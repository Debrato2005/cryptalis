"""Async psycopg method guard for the bounded local fixture, not provider qualification."""
import os

import psycopg
from sqlalchemy.ext.asyncio import create_async_engine

from integration_adapter import BoundaryConnection, BoundaryCursor
from probe_service import EXPECTED


class AsyncBoundaryCursor(BoundaryCursor):
    async def execute(self, query, parameters=None, **kwargs):
        self.connection.consume()
        await self._cursor.execute(query, parameters, **kwargs)
        return self

    async def executemany(self, query, parameters, **kwargs):
        self.connection.consume()
        await self._cursor.executemany(query, parameters, **kwargs)
        return self

    async def close(self):
        await self._cursor.close()

    async def fetchone(self):
        return await self._cursor.fetchone()

    async def fetchmany(self, *args, **kwargs):
        return await self._cursor.fetchmany(*args, **kwargs)

    async def fetchall(self):
        return await self._cursor.fetchall()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()

    def __aiter__(self):
        return self._cursor.__aiter__()

    @property
    def pgresult(self):
        # Read-only result metadata required by this installed psycopg dialect.
        return self._cursor.pgresult

    def _close(self):
        # SQLAlchemy's installed psycopg adapter calls this cursor protocol.
        # No SQLAlchemy private state is changed. Other versions are unqualified.
        self._cursor._close()


class AsyncBoundaryConnection(BoundaryConnection):
    def cursor(self, *args, **kwargs):
        return AsyncBoundaryCursor(self, self._raw.cursor(*args, **kwargs))

    async def execute(self, query, parameters=None, **kwargs):
        return await self.cursor().execute(query, parameters, **kwargs)

    async def commit(self):
        await self._raw.commit()

    async def rollback(self):
        self._ticket = False
        await self._raw.rollback()

    async def close(self):
        await self._raw.close()

    async def set_autocommit(self, value):
        await self._raw.set_autocommit(value)

    async def set_isolation_level(self, value):
        await self._raw.set_isolation_level(value)

    async def set_read_only(self, value):
        await self._raw.set_read_only(value)

    async def set_deferrable(self, value):
        await self._raw.set_deferrable(value)


def create_guarded_async_engine(attachment):
    async def creator():
        # The private URL is used only for the authorized connection.
        raw = await psycopg.AsyncConnection.connect(os.environ["CRYPTALIS_TEST_DATABASE_URL"], **EXPECTED, hostaddr="127.0.0.1", connect_timeout=3)
        return AsyncBoundaryConnection(raw, attachment)

    engine = create_async_engine(attachment.engine.url, async_creator=creator, hide_parameters=True,
                                 echo=False, use_native_hstore=False)
    engine = engine.execution_options(**attachment.engine.get_execution_options())
    attachment.install(engine.sync_engine)
    return engine
