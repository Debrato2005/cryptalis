"""Original HTTP authentication and CRUD; no Cryptalis import or auth override."""
from datetime import timedelta
from uuid import uuid4

PUBLIC_PASSWORD = 'PUBLIC local HTTP fixture password 2026'
PUBLIC_NEW_PASSWORD = 'PUBLIC updated HTTP fixture password 2026'


def workflow(api, factory, retained=None):
    """Exercise original routes with one original request-session dependency."""
    import jwt
    from fastapi.testclient import TestClient
    from app import crud
    from app.api.deps import get_db
    from app.core import security
    from app.core.config import settings
    from app.models import UserCreate

    assert not settings.emails_enabled, 'HTTP workload excludes SMTP delivery'
    def request_session():
        with factory() as session:
            yield session
    previous = api.dependency_overrides.copy()
    api.dependency_overrides[get_db] = request_session
    controls = []
    def address():
        return uuid4().hex + '@example.com'
    def body(response, status=200):
        assert response.status_code == status
        if status == 200:
            result = response.json()
            assert 'password' not in result and 'hashed_password' not in result
            return result
    try:
        # No public endpoint bootstraps the first superuser. Use original CRUD.
        admin_email = address()
        with factory() as session:
            admin = crud.create_user(session=session, user_create=UserCreate(
                email=admin_email, password=PUBLIC_PASSWORD, is_superuser=True,
                full_name='PUBLIC HTTP fixture administrator'))
            admin_id = str(admin.id)
        with TestClient(api) as client:
            def login(email, updated=False):
                result = body(client.post('/api/v1/login/access-token', data={
                    'username': email,
                    'password': PUBLIC_NEW_PASSWORD if updated else PUBLIC_PASSWORD}))
                assert result['token_type'] == 'bearer'
                return {'Authorization': 'Bearer ' + result['access_token']}
            admin_headers = login(admin_email)
            if retained:
                old_headers = login(retained['email'], updated=True)
                old = body(client.get('/api/v1/users/me', headers=old_headers))
                for field in ('id', 'email', 'full_name', 'is_active'):
                    assert old[field] == retained[field]
                body(client.post('/api/v1/login/access-token', data={
                    'username': retained['email'], 'password': PUBLIC_PASSWORD}), 400)
                old_inactive = body(client.get('/api/v1/users/' + retained['inactive']['id'],
                                                headers=admin_headers))
                assert old_inactive['is_active'] is False
                body(client.post('/api/v1/login/access-token', data={
                    'username': retained['inactive']['email'], 'password': PUBLIC_PASSWORD}), 400)
                controls.append('retained latest credentials, values and inactive flag')

            email = address()
            public = body(client.post('/api/v1/users/signup', json={
                'email': email, 'password': PUBLIC_PASSWORD, 'full_name': 'PUBLIC HTTP name 雪😀'}))
            identity = public['id']
            assert public['email'] == email and public['is_active'] is True
            body(client.post('/api/v1/users/signup', json={'email': email, 'password': PUBLIC_PASSWORD}), 400)
            body(client.post('/api/v1/users/signup', json={'email': 'invalid', 'password': 'short'}), 422)
            body(client.post('/api/v1/login/access-token', data={}), 422)
            body(client.post('/api/v1/login/access-token', data={
                'username': email, 'password': 'PUBLIC incorrect password'}), 400)
            headers = login(email)
            body(client.get('/api/v1/users/me'), 401)
            body(client.get('/api/v1/users/me', headers={'Authorization': 'Bearer invalid'}), 403)
            expired = security.create_access_token(identity, expires_delta=timedelta(minutes=-1))
            body(client.get('/api/v1/users/me', headers={'Authorization': 'Bearer ' + expired}), 403)
            forged = jwt.encode({'sub': identity, 'exp': 4102444800},
                                'PUBLIC wrong signing key for local HTTP fixture 2026', algorithm=security.ALGORITHM)
            body(client.get('/api/v1/users/me', headers={'Authorization': 'Bearer ' + forged}), 403)
            current = body(client.get('/api/v1/users/me', headers=headers))
            assert current == public
            assert body(client.post('/api/v1/login/test-token', headers=headers)) == public
            controls.append('signup, duplicate/invalid input, real password/JWT login and token refusals')

            current = body(client.patch('/api/v1/users/me', headers=headers, json={'full_name': None}))
            assert current['full_name'] is None
            latest_email, latest_name = address(), 'PUBLIC latest HTTP name 雪😀 ' + uuid4().hex
            current = body(client.patch('/api/v1/users/me', headers=headers,
                                        json={'email': latest_email, 'full_name': latest_name}))
            assert current['email'] == latest_email and current['full_name'] == latest_name
            body(client.post('/api/v1/login/access-token', data={
                'username': email, 'password': PUBLIC_PASSWORD}), 400)
            headers = login(latest_email)
            body(client.patch('/api/v1/users/me', headers=headers, json={'email': admin_email}), 409)
            assert body(client.get('/api/v1/users/me', headers=headers))['email'] == latest_email
            body(client.patch('/api/v1/users/me/password', headers=headers, json={
                'current_password': 'PUBLIC wrong password', 'new_password': PUBLIC_NEW_PASSWORD}), 400)
            body(client.patch('/api/v1/users/me/password', headers=headers, json={
                'current_password': PUBLIC_PASSWORD, 'new_password': PUBLIC_PASSWORD}), 400)
            body(client.patch('/api/v1/users/me/password', headers=headers, json={
                'current_password': PUBLIC_PASSWORD, 'new_password': PUBLIC_NEW_PASSWORD}))
            body(client.post('/api/v1/login/access-token', data={
                'username': latest_email, 'password': PUBLIC_PASSWORD}), 400)
            headers = login(latest_email, updated=True)
            controls.append('own NULL/Unicode/email changes, uniqueness409 and password change with old/new login')

            body(client.get('/api/v1/users/', headers=headers), 403)
            body(client.get('/api/v1/users/' + admin_id, headers=headers), 403)
            body(client.post('/api/v1/users/', headers=headers,
                             json={'email': address(), 'password': PUBLIC_PASSWORD}), 403)
            body(client.patch('/api/v1/users/' + admin_id, headers=headers, json={'is_active': False}), 403)
            body(client.delete('/api/v1/users/' + admin_id, headers=headers), 403)
            assert body(client.get('/api/v1/users/' + identity, headers=headers))['id'] == identity
            assert body(client.get('/api/v1/users/' + identity, headers=admin_headers))['id'] == identity
            body(client.get('/api/v1/users/' + str(uuid4()), headers=admin_headers), 404)
            body(client.delete('/api/v1/users/me', headers=admin_headers), 403)
            body(client.delete('/api/v1/users/' + admin_id, headers=admin_headers), 403)
            controls.append('ordinary-user admin/cross-user refusals; own/admin reads; superuser self-delete refusal')

            inactive = body(client.patch('/api/v1/users/' + identity, headers=admin_headers,
                                         json={'is_active': False}))
            assert inactive['is_active'] is False
            body(client.get('/api/v1/users/me', headers=headers), 400)
            body(client.post('/api/v1/login/access-token', data={
                'username': latest_email, 'password': PUBLIC_NEW_PASSWORD}), 400)
            reactivated = body(client.patch('/api/v1/users/' + identity, headers=admin_headers,
                                            json={'is_active': True}))
            assert reactivated['is_active'] is True
            assert body(client.get('/api/v1/users/me', headers=headers))['is_active'] is True
            inactive_email = address()
            inactive = body(client.post('/api/v1/users/', headers=admin_headers, json={
                'email': inactive_email, 'password': PUBLIC_PASSWORD, 'is_active': False}))
            assert inactive['is_active'] is False
            body(client.post('/api/v1/login/access-token', data={
                'username': inactive_email, 'password': PUBLIC_PASSWORD}), 400)
            controls.append('encrypted inactive denial, reactivation and one committed inactive user')

            own_item = body(client.post('/api/v1/items/', headers=headers,
                                        json={'title': 'PUBLIC own item 雪😀', 'description': None}))
            own_path = '/api/v1/items/' + own_item['id']
            assert own_item['owner_id'] == identity
            assert body(client.get(own_path, headers=headers))['id'] == own_item['id']
            edited = body(client.put(own_path, headers=headers,
                                     json={'title': 'PUBLIC edited item 雪😀', 'description': 'latest'}))
            assert edited['description'] == 'latest'
            listing = body(client.get('/api/v1/items/', headers=headers))
            assert own_item['id'] in {item['id'] for item in listing['data']}
            victim_email = address()
            victim = body(client.post('/api/v1/users/', headers=admin_headers,
                                       json={'email': victim_email, 'password': PUBLIC_PASSWORD}))
            victim_headers = login(victim_email)
            victim_item = body(client.post('/api/v1/items/', headers=victim_headers,
                                           json={'title': 'PUBLIC victim item'}))
            victim_path = '/api/v1/items/' + victim_item['id']
            for method, payload in (('GET', None), ('PUT', {'title': 'PUBLIC forbidden'}), ('DELETE', None)):
                body(client.request(method, victim_path, headers=headers, json=payload), 403)
            assert body(client.get(victim_path, headers=victim_headers))['title'] == 'PUBLIC victim item'
            assert body(client.get(victim_path, headers=admin_headers))['id'] == victim_item['id']
            listing = body(client.get('/api/v1/items/', headers=headers))
            assert victim_item['id'] not in {item['id'] for item in listing['data']}
            body(client.get('/api/v1/items/' + str(uuid4()), headers=headers), 404)
            body(client.delete(own_path, headers=headers))
            body(client.get(own_path, headers=headers), 404)
            controls.append('own item CRUD/list; other-owner read/update/delete refusal and unchanged value')

            temporary_email = address()
            body(client.post('/api/v1/users/signup',
                json={'email': temporary_email, 'password': PUBLIC_PASSWORD}))
            temporary_headers = login(temporary_email)
            body(client.delete('/api/v1/users/me', headers=temporary_headers))
            body(client.get('/api/v1/users/me', headers=temporary_headers), 404)
            body(client.post('/api/v1/login/access-token', data={
                'username': temporary_email, 'password': PUBLIC_PASSWORD}), 400)
            listed = body(client.get('/api/v1/users/?skip=0&limit=100', headers=admin_headers))
            assert {identity, admin_id, inactive['id'], victim['id']} <= {user['id'] for user in listed['data']}
            assert listed['count'] >= 4
            body(client.delete('/api/v1/users/' + victim['id'], headers=admin_headers))
            body(client.get('/api/v1/users/' + victim['id'], headers=admin_headers), 404)
            body(client.get(victim_path, headers=admin_headers), 404)
            controls.append('admin list, user self-delete and admin victim/item cascade deletion')
            current = body(client.get('/api/v1/users/me', headers=headers))
            assert current['email'] == latest_email and current['full_name'] == latest_name
            assert current['is_active'] is True
            return {**current, 'inactive': {'id': inactive['id'], 'email': inactive_email},
                    'admin': {'id': admin_id, 'email': admin_email}, 'controls': controls,
                    'mail_boundary': 'SMTP delivery and password-reset email leg not exercised'}
    finally:
        api.dependency_overrides.clear()
        api.dependency_overrides.update(previous)
