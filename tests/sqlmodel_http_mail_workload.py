"""Original email routes deliver real MIME messages to a local SMTP fixture."""
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
from queue import Empty
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

from sqlmodel_http_smtp import capture_smtp
from sqlmodel_http_workload import PUBLIC_PASSWORD, PUBLIC_NEW_PASSWORD


def workflow(api, factory, retained, monkeypatch):
    from fastapi.testclient import TestClient
    from app.api.deps import get_db
    from app.core.config import settings
    from app.utils import generate_password_reset_token

    def request_session():
        with factory() as session:
            yield session
    previous = api.dependency_overrides.copy()
    api.dependency_overrides[get_db] = request_session
    observed = []
    try:
        with capture_smtp() as (host, port, messages), monkeypatch.context() as configured:
            for name, value in dict(SMTP_HOST=host, SMTP_PORT=port, SMTP_TLS=False,
                                    SMTP_SSL=False, SMTP_USER=None, SMTP_PASSWORD=None,
                                    FRONTEND_HOST='http://localhost:5173',
                                    EMAILS_FROM_EMAIL='owner@example.com').items():
                configured.setattr(settings, name, value)
            def received(address):
                message = messages.get(timeout=3)
                assert message['recipients'] == (address,)
                mime = BytesParser(policy=policy.default).parsebytes(message['data'])
                body = mime.get_body(preferencelist=('html',))
                assert body is not None and body.get_content_type() == 'text/html'
                observed.append(str(mime['Subject']))
                return body.get_content()
            def no_delivery():
                try:
                    messages.get_nowait()
                except Empty:
                    return
                raise AssertionError('Unexpected local SMTP delivery')
            class Links(HTMLParser):
                def __init__(self):
                    super().__init__(); self.tokens = []
                def handle_starttag(self, tag, attrs):
                    if tag == 'a':
                        link = dict(attrs).get('href', '')
                        parsed = urlparse(link)
                        if parsed.hostname == 'localhost' and parsed.path == '/reset-password':
                            self.tokens.extend(parse_qs(parsed.query).get('token', []))
            with TestClient(api) as client:
                unknown = uuid4().hex + '@example.com'
                absent = client.post('/api/v1/password-recovery/' + unknown)
                assert absent.status_code == 200
                no_delivery()
                response = client.post('/api/v1/password-recovery/' + retained['email'])
                assert response.status_code == 200 and response.json() == absent.json()
                parsed = Links(); parsed.feed(received(retained['email']))
                assert parsed.tokens and len(set(parsed.tokens)) == 1
                token = parsed.tokens[0]
                reset_password = 'PUBLIC local SMTP reset password 2026'
                with monkeypatch.context() as expired_settings:
                    expired_settings.setattr(settings,'EMAIL_RESET_TOKEN_EXPIRE_HOURS',-1)
                    expired = generate_password_reset_token(retained['email'])
                for invalid in ('invalid', expired):
                    assert client.post('/api/v1/reset-password/', json={
                        'token': invalid, 'new_password': reset_password}).status_code == 400
                assert client.post('/api/v1/reset-password/', json={
                    'token': token, 'new_password': reset_password}).status_code == 200
                assert client.post('/api/v1/login/access-token', data={
                    'username': retained['email'], 'password': PUBLIC_NEW_PASSWORD}).status_code == 400
                login = client.post('/api/v1/login/access-token', data={
                    'username': retained['email'], 'password': reset_password})
                assert login.status_code == 200
                user_headers = {'Authorization': 'Bearer ' + login.json()['access_token']}
                current = client.get('/api/v1/users/me', headers=user_headers)
                assert current.status_code == 200 and current.json()['id'] == retained['id']
                assert client.patch('/api/v1/users/me/password', headers=user_headers, json={
                    'current_password': reset_password, 'new_password': PUBLIC_NEW_PASSWORD}).status_code == 200
                assert client.post('/api/v1/password-recovery/' + retained['inactive']['email']).status_code == 200
                inactive = Links(); inactive.feed(received(retained['inactive']['email']))
                assert inactive.tokens
                assert client.post('/api/v1/reset-password/', json={
                    'token': inactive.tokens[0], 'new_password': reset_password}).status_code == 400
                assert client.post('/api/v1/password-recovery-html-content/' + retained['email'],
                                   headers=user_headers).status_code == 403
                admin = client.post('/api/v1/login/access-token', data={
                    'username': retained['admin']['email'], 'password': PUBLIC_PASSWORD})
                assert admin.status_code == 200
                admin_headers = {'Authorization': 'Bearer ' + admin.json()['access_token']}
                content = client.post('/api/v1/password-recovery-html-content/' + retained['email'],
                                      headers=admin_headers)
                assert content.status_code == 200 and 'text/html' in content.headers['content-type']
                assert '/reset-password?token=' in content.text
                no_delivery()
                assert client.post('/api/v1/utils/test-email/', params={'email_to': retained['email']},
                                   headers=admin_headers).status_code == 201
                assert retained['email'] in received(retained['email'])
                new_email = uuid4().hex + '@example.com'
                created = client.post('/api/v1/users/', headers=admin_headers, json={
                    'email': new_email, 'password': PUBLIC_PASSWORD, 'full_name': 'PUBLIC SMTP fixture'})
                assert created.status_code == 200
                assert PUBLIC_PASSWORD in received(new_email)
                assert client.delete('/api/v1/users/' + created.json()['id'], headers=admin_headers).status_code == 200
                no_delivery()
        return {'smtp_messages': len(observed), 'controls': [
            'unknown and existing account recovery response parity', 'actual template MIME delivery and token reset',
            'invalid/expired reset token and inactive account refusal', 'admin HTML/test-email/new-account delivery',
            'latest credentials restored after SMTP password reset']}
    finally:
        api.dependency_overrides.clear()
        api.dependency_overrides.update(previous)
