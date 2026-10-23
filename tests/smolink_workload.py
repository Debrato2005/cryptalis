"""Cryptalis-free HTTP and repository workload for the pinned Smolink app."""
from datetime import timedelta

USER_ID = 10001
PUBLIC_SECRET = 'PUBLIC SMOLINK ADOPTION TEST ONLY ' * 2


async def workflow(api, factory, alias, *, retained=None):
    """Original HTTP validation, authentication, service, repository, and commit/refresh."""
    from httpx import ASGITransport, AsyncClient
    from app.db.session import get_session
    from app.models.url import Url
    from app.repositories.url_repository import get_url_by_short_code
    from app.utils.security import create_access_token

    async def sessions():
        async with factory() as session:
            yield session
    api.dependency_overrides[get_session] = sessions
    token = create_access_token(user_id=USER_ID, auth_version=1, secret=PUBLIC_SECRET,
                                issuer='smolink-test', audience='smolink-test', expires_in=timedelta(minutes=5))
    payload = {'destination': 'https://example.invalid/' + alias + '?marker=private-destination', 'alias': alias}
    async with AsyncClient(transport=ASGITransport(app=api), base_url='https://short.example.invalid') as client:
        health = await client.get('/health')
        assert health.status_code == 200 and health.json() == {'status': 'ok'}
        response = await client.post('/api/v1/urls', json=payload)
        assert response.status_code == 201, response.status_code
        guest = response.json()
        assert guest['destination'] == payload['destination']
        assert guest['short_code'] == alias and guest['expires_at'] is None and guest['created_at']
        assert guest['short_url'] == 'https://short.example.invalid/' + alias
        response = await client.post('/api/v1/urls', json=payload)
        assert response.status_code == 409 and response.json()['error'] == 'alias_taken'
        response = await client.post('/api/v1/urls', json={**payload, 'alias': alias + '-owner'},
                                     headers={'Authorization': 'Bearer ' + token})
        assert response.status_code == 201
        owned = response.json()
        assert owned['destination'] == payload['destination']
        response = await client.post('/api/v1/urls', json=payload,
                                     headers={'Authorization': 'Bearer invalid'})
        assert response.status_code == 401
        response = await client.post('/api/v1/urls', json={**payload, 'alias': 'bad alias!'})
        assert response.status_code == 422 and response.json()['error'] == 'invalid_alias'
        response = await client.post('/api/v1/urls', json={**payload, 'expires_at': '2000-01-01T00:00:00Z'})
        assert response.status_code == 422 and response.json()['error'] == 'invalid_expiry'
        response = await client.post('/api/v1/urls', json={'destination': 'invalid URL'})
        assert response.status_code == 422

    async with factory() as session:
        guest_row = await get_url_by_short_code(session, alias)
        owner_row = await get_url_by_short_code(session, alias + '-owner')
        assert guest_row.owner_id is None and owner_row.owner_id == USER_ID
        assert guest_row.destination == payload['destination']
        if retained:
            current = await get_url_by_short_code(session, retained['alias'])
            assert current.destination == retained['destination']
        guest_row.destination = 'https://example.invalid/edited-' + alias + '?marker=latest-private-destination'
        guest_row.total_clicks += 1
        await session.commit()
        await session.refresh(guest_row)
        assert guest_row.total_clicks == 1
        assert guest_row.destination.endswith('marker=latest-private-destination')
        retained = {'alias': alias, 'destination': guest_row.destination, 'id': guest_row.id}
        await session.delete(owner_row)
        await session.commit()
    async with factory() as session:
        assert await get_url_by_short_code(session, alias + '-owner') is None
        assert (await session.get(Url, retained['id'])).destination == retained['destination']
    async with AsyncClient(transport=ASGITransport(app=api), base_url='https://short.example.invalid') as client:
        for _ in range(11):
            response = await client.post('/api/v1/urls', json=payload)
            assert response.status_code in (409, 429)
            if response.status_code == 429:
                assert 0 < int(response.headers['Retry-After']) <= 60
                break
        else:
            raise AssertionError('original Redis rate limiter did not refuse excess requests')
    return retained


def restart_without_cryptalis(backend, schema, current):
    """Run the original application in a fresh interpreter that denies Cryptalis."""
    import json
    import os
    from pathlib import Path
    import subprocess
    import sys
    child = subprocess.run([sys.executable, '-I', '-c', '''

import asyncio, importlib.abc, json, os, runpy, sys
class DenyCryptalis(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'cryptalis' or fullname.startswith('cryptalis.'):
            raise ImportError('Cryptalis import denied after removal')
sys.meta_path.insert(0, DenyCryptalis())
sys.path[:0] = json.loads(os.environ['SMOLINK_CHILD_PATHS'])
import psycopg
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from app.main import app as api
from app.core.redis import get_redis_client
for name, module in tuple(sys.modules.items()):
    if name == 'app' or name.startswith('app.'):
        origin = getattr(module, '__file__', None)
        if origin:
            assert __import__('pathlib').Path(origin).is_relative_to(os.environ['SMOLINK_BACKEND'])
namespace = runpy.run_path(os.environ['SMOLINK_WORKLOAD_HELPER'])
async def main():
    engine = create_async_engine('postgresql+psycopg://', hide_parameters=True,
        async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'],
            options='-csearch_path=' + os.environ['SMOLINK_SCHEMA']))
    try:
        await namespace['workflow'](api, async_sessionmaker(engine, expire_on_commit=False),
            'package-free', retained=json.loads(os.environ['SMOLINK_CURRENT']))
    finally:
        await get_redis_client().aclose()
        await engine.dispose()
asyncio.run(main())
assert not any(n == 'cryptalis' or n.startswith('cryptalis.') for n in sys.modules)
print(json.dumps({'native_router_crud': 'passed', 'cryptalis_imported': False}))

'''], env=dict(os.environ, SMOLINK_CHILD_PATHS=json.dumps(sys.path),
        SMOLINK_SCHEMA=schema, SMOLINK_BACKEND=str(backend), SMOLINK_CURRENT=json.dumps(current),
        SMOLINK_WORKLOAD_HELPER=str(Path(__file__).resolve())), capture_output=True, text=True, timeout=60)
    assert child.returncode == 0, 'package-free Smolink router restart failed; diagnostics suppressed'
    assert json.loads(child.stdout) == {'native_router_crud': 'passed', 'cryptalis_imported': False}
