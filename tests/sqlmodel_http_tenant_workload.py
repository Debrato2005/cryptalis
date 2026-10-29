"""Original HTTP routes for existing account owners; no Cryptalis imports."""
from contextlib import contextmanager
from datetime import timedelta
from uuid import UUID, uuid4

PASSWORD = 'PUBLIC tenant HTTP fixture password 2026'


@contextmanager
def native_requests(api, factory):
    from app.api.deps import get_db
    previous = api.dependency_overrides.copy()
    def database():
        with factory() as session:
            yield session
    api.dependency_overrides[get_db] = database
    try:
        yield
    finally:
        api.dependency_overrides.clear()
        api.dependency_overrides.update(previous)


def seed(factory):
    """Account provisioning uses the original application CRUD implementation."""
    from app import crud
    from app.models import UserCreate
    result = {}
    with factory() as session:
        for name in ('admin', 'alice', 'bob', 'self_delete', 'admin_delete', 'rollback', 'inactive', 'deleted'):
            user = crud.create_user(session=session, user_create=UserCreate(
                email=uuid4().hex + '@example.com', password=PASSWORD,
                full_name='PUBLIC tenant ' + name, is_superuser=name == 'admin',
                is_active=name != 'inactive'))
            result[name] = {'id': str(user.id), 'email': user.email}
        session.delete(session.get(type(user), UUID(result['deleted']['id'])))
        session.commit()
    return result


def workflow(api, accounts, public_factory, *, host=None):
    """Return observable controls after real JWT, owner, admin and cascade routes."""
    import jwt
    from fastapi.testclient import TestClient
    from sqlmodel import select
    from app.core import security
    from app.core.config import settings
    from app.models import Item, User

    def body(response, status=200):
        assert response.status_code == status, (response.status_code, status)
        return response.json()
    controls = []
    with TestClient(api) as client:
        def login(name):
            token = body(client.post('/api/v1/login/access-token', data={
                'username': accounts[name]['email'], 'password': PASSWORD}))['access_token']
            return {'Authorization': 'Bearer ' + token}
        headers = {name: login(name) for name in accounts if name not in ('inactive', 'deleted')}
        before = len(host.scopes) if host else None
        body(client.get('/api/v1/items/'), 401)
        body(client.get('/api/v1/items/', headers={'Authorization': 'Bearer invalid'}), 403)
        expired = security.create_access_token(accounts['alice']['id'], expires_delta=timedelta(minutes=-1))
        body(client.get('/api/v1/items/', headers={'Authorization': 'Bearer ' + expired}), 403)
        forged = jwt.encode({'sub': accounts['admin']['id'], 'exp': 4102444800},
            'PUBLIC wrong tenant HTTP signing key', algorithm=security.ALGORITHM)
        body(client.get('/api/v1/items/', headers={'Authorization': 'Bearer ' + forged}), 403)
        for name, status in (('inactive', 400), ('deleted', 404)):
            token = security.create_access_token(accounts[name]['id'], expires_delta=timedelta(minutes=5))
            body(client.get('/api/v1/items/', headers={'Authorization': 'Bearer ' + token}), status)
        if host:
            assert len(host.scopes) == before, 'invalid account authority must not select a tenant'
        controls.append('original password/JWT, missing, invalid, expired, forged, inactive and deleted account authority')

        def create(name, title=None):
            return body(client.post('/api/v1/items/', headers=headers[name], json={
                'title': title or ('PUBLIC tenant 雪😀 ' + uuid4().hex),
                'description': 'PUBLIC description 雪😀', 'owner_id': accounts['bob']['id']}))
        own, other = create('alice'), create('bob')
        assert own['owner_id'] == accounts['alice']['id']
        own_path, other_path = '/api/v1/items/' + own['id'], '/api/v1/items/' + other['id']
        before = len(host.scopes) if host else None
        for method in ('get', 'put', 'delete'):
            options = {'json': {'title': 'PUBLIC forbidden change'}} if method == 'put' else {}
            body(getattr(client, method)(other_path, headers=headers['alice'], **options), 403)
        body(client.get('/api/v1/items/' + str(uuid4()), headers=headers['alice']), 404)
        if host:
            assert len(host.scopes) == before, 'cross-owner and missing items must refuse before payload authority'
        assert body(client.get(other_path, headers=headers['bob'])) == other
        latest_title = 'PUBLIC latest tenant 雪😀 ' + uuid4().hex
        latest = body(client.put(own_path, headers=headers['alice'], json={
            'title': latest_title, 'description': None}))
        assert latest['title'] == latest_title and latest['description'] is None
        claimed = jwt.encode({'sub': accounts['alice']['id'], 'tenant_id': accounts['bob']['id'],
            'exp': 4102444800}, settings.SECRET_KEY, algorithm=security.ALGORITHM)
        assert body(client.get(own_path, headers={'Authorization': 'Bearer ' + claimed})) == latest
        temporary = [create('alice') for _ in range(2)]
        with public_factory() as session:
            expected_own = [str(row) for row in session.exec(select(Item.id)
                .where(Item.owner_id == UUID(accounts['alice']['id']))
                .order_by(Item.created_at.desc())).all()]
        assert len(expected_own) >= 3
        for skip, limit in ((0, 100), (0, 2), (1, 1), (len(expected_own), 2)):
            ordinary = body(client.get(f'/api/v1/items/?skip={skip}&limit={limit}', headers=headers['alice']))
            assert ordinary['count'] == len(expected_own)
            assert [row['id'] for row in ordinary['data']] == expected_own[skip:skip + limit]
            assert all(row['owner_id'] == accounts['alice']['id'] for row in ordinary['data'])
        for item in temporary:
            body(client.delete('/api/v1/items/' + item['id'], headers=headers['alice']))
            body(client.get('/api/v1/items/' + item['id'], headers=headers['alice']), 404)
        controls.append('owner CRUD, exact owner count/order/offset/limit/empty page, Unicode/NULL, ignored owner input/tenant claim and cross-owner 403 before payload load')

        # The exact public ordering/page is the oracle, never a decrypted candidate filter.
        assert body(client.get(other_path, headers=headers['admin'])) == other
        changed = body(client.put(other_path, headers=headers['admin'], json={
            'description': 'PUBLIC authorized administrator edit'}))
        assert changed['owner_id'] == accounts['bob']['id']
        create('admin')
        with public_factory() as session:
            expected = [str(row) for row in session.exec(select(Item.id).order_by(Item.created_at.desc())).all()]
        for skip, limit in ((0, 2), (1, 1), (len(expected), 2)):
            page = body(client.get(f'/api/v1/items/?skip={skip}&limit={limit}', headers=headers['admin']))
            assert page['count'] == len(expected)
            assert [row['id'] for row in page['data']] == expected[skip:skip + limit]
        body(client.delete(other_path, headers=headers['admin']))
        body(client.get(other_path, headers=headers['admin']), 404)
        controls.append('global administrator cross-owner read/update/delete and exact count/order/offset/limit')

        body(client.delete('/api/v1/users/' + accounts['bob']['id'], headers=headers['alice']), 403)
        body(client.delete('/api/v1/users/me', headers=headers['admin']), 403)
        body(client.delete('/api/v1/users/' + accounts['admin']['id'], headers=headers['admin']), 403)
        self_item = create('self_delete')
        body(client.delete('/api/v1/users/me', headers=headers['self_delete']))
        body(client.get('/api/v1/users/me', headers=headers['self_delete']), 404)
        victims = [create('admin_delete') for _ in range(2)]
        body(client.delete('/api/v1/users/' + accounts['admin_delete']['id'], headers=headers['admin']))
        with public_factory() as session:
            assert session.get(User, UUID(accounts['self_delete']['id'])) is None
            assert session.get(User, UUID(accounts['admin_delete']['id'])) is None
            for item in [self_item, *victims]:
                assert session.exec(select(Item.id).where(Item.id == UUID(item['id']))).first() is None
        controls.append('original own/admin User DELETE, superuser self-delete 403 and complete Item cascade')

        if host:
            # Account registration is global/native. A newly registered owner
            # has no published Item key policy in this bounded integration.
            new_email = uuid4().hex + '@example.com'
            registered = body(client.post('/api/v1/users/signup', json={
                'email': new_email, 'password': PASSWORD}))
            new_token = body(client.post('/api/v1/login/access-token', data={
                'username': new_email, 'password': PASSWORD}))['access_token']
            new_headers = {'Authorization': 'Bearer ' + new_token}
            assert body(client.get('/api/v1/users/me', headers=new_headers))['id'] == registered['id']
            before = len(host.scopes)
            refused = body(client.post('/api/v1/items/', headers=new_headers,
                json={'title': 'PUBLIC unapproved new owner ' + uuid4().hex}), 409)
            assert refused == {'detail': 'Item owner policy is not approved'}
            assert len(host.scopes) == before, 'unapproved owner must not call the scoped session factory'
            with public_factory() as session:
                assert session.exec(select(Item.id).where(Item.owner_id == UUID(registered['id']))).all() == []
            controls.append('new global signup/login succeeds; unapproved Item owner409 before scoped factory/key lookup with no Item write')
            rollback_item = create('rollback')
            host.fail_next_account_commit = True
            with TestClient(api, raise_server_exceptions=False) as failing:
                assert failing.delete('/api/v1/users/' + accounts['rollback']['id'],
                    headers=headers['admin']).status_code == 500
            with public_factory() as session:
                assert session.get(User, UUID(accounts['rollback']['id'])) is not None
                assert session.exec(select(Item.id).where(Item.id == UUID(rollback_item['id']))).one() is not None
            assert body(client.get('/api/v1/items/' + rollback_item['id'], headers=headers['rollback'])) == rollback_item
            controls.append('injected precommit failure rolls back scoped Item deletions and global account deletion together')
        return {'controls': controls, 'latest': latest, 'accounts': accounts}


def verify_retained_items(api, factory, expectations):
    """Read every pre-exit current Item through its original owner's HTTP login."""
    from fastapi.testclient import TestClient
    rows, accounts = expectations['rows'], expectations['accounts']
    assert rows and set(accounts) == {values[0] for values in rows.values()}
    with native_requests(api, factory), TestClient(api) as client:
        headers = {}
        for owner, account in accounts.items():
            response = client.post('/api/v1/login/access-token', data={
                'username': account['email'], 'password': account['password']})
            assert response.status_code == 200
            headers[owner] = {'Authorization': 'Bearer ' + response.json()['access_token']}
            current = client.get('/api/v1/users/me', headers=headers[owner])
            assert current.status_code == 200 and current.json()['id'] == owner
        for identity, (owner, title, description) in rows.items():
            response = client.get('/api/v1/items/' + identity, headers=headers[owner])
            assert response.status_code == 200
            observed = response.json()
            assert {name: observed[name] for name in ('id', 'owner_id', 'title', 'description')} == {
                'id': identity, 'owner_id': owner, 'title': title, 'description': description}
    return {'retained_item_http': 'passed', 'retained_item_count': len(rows),
        'retained_item_owner_count': len(accounts)}
