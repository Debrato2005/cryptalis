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
