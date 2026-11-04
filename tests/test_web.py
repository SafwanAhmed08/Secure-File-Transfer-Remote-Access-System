"""Exercise the real HTTP API against disposable accounts and file storage.

These tests never modify the user's project or know any of their passwords.
"""
import http.client
import json
import os
from pathlib import Path
import shutil
import ssl
import tempfile
import threading
import unittest
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from server import Application, WebServer, normalise_public_origin

SOURCE = Path(os.environ.get('RELAY_TEST_PROJECT_DIR', str(Path(__file__).resolve().parents[1])))


class BrowserAPITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory()
        cls.root = Path(cls.folder.name)
        for name in ('auth.py', 'database.py', 'tls_transport.py', 'setup_tls.py'):
            shutil.copyfile(SOURCE / name, cls.root / name)
        cls.app = Application(cls.root, secure=False)
        cls.app.auth.set_password('alice', 'alice-test-password', cls.app.db_path)
        cls.app.auth.set_password('bob', 'bob-test-password', cls.app.db_path)
        cls.app.grant_admin('alice')
        cls.server = WebServer(('127.0.0.1', 0), cls.app)
        cls.port = cls.server.server_port
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(3)
        cls.folder.cleanup()

    def setUp(self):
        with self.app.lock:
            self.app.attempts.clear()
        self.alice = self.login('alice')
        self.bob = self.login('bob')

    def request(self, method, path, data=None, session=None, headers=None, raw=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        request_headers = dict(headers or {})
        if session:
            request_headers['Cookie'] = session['cookie']
            if method != 'GET':
                request_headers['X-CSRF-Token'] = session['csrf']
        body = raw
        if data is not None:
            body = json.dumps(data).encode()
            request_headers['Content-Type'] = 'application/json'
        connection.request(method, path, body=body, headers=request_headers)
        response = connection.getresponse()
        payload = response.read()
        result = {'status': response.status, 'headers': dict(response.getheaders()), 'raw': payload}
        if 'application/json' in result['headers'].get('Content-Type', ''):
            result['data'] = json.loads(payload)
        connection.close()
        return result

    def login(self, username):
        result = self.request('POST', '/api/login', {'username': username, 'password': f'{username}-test-password'})
        self.assertEqual(result['status'], 200)
        return {'cookie': result['headers']['Set-Cookie'].split(';')[0], 'csrf': result['data']['csrf']}

    def test_static_assets_and_private_source_boundary(self):
        self.assertEqual(self.request('GET', '/')['status'], 200)
        self.assertEqual(self.request('GET', '/assets/app.js')['status'], 200)
        for path in ('/auth.py', '/users.db', '/certs/server.key', '/../auth.py'):
            self.assertEqual(self.request('GET', path)['status'], 404)

    def test_login_cookie_and_wrong_password(self):
        result = self.request('POST', '/api/login', {'username': 'alice', 'password': 'wrong'})
        self.assertEqual(result['status'], 401)
        self.assertEqual(self.request('GET', '/api/files')['status'], 401)
        result = self.request('POST', '/api/login', {'username': 'alice', 'password': 'alice-test-password'})
        cookie = result['headers']['Set-Cookie']
        self.assertIn('HttpOnly', cookie)
        self.assertIn('SameSite=Strict', cookie)

    def test_csrf_and_cross_origin_rejections(self):
        result = self.request('DELETE', '/api/files?name=nope', headers={'Cookie': self.alice['cookie']})
        self.assertEqual(result['status'], 403)
        result = self.request('POST', '/api/login', {'username': 'alice', 'password': 'alice-test-password'},
                              headers={'Origin': 'https://evil.example'})
        self.assertEqual(result['status'], 403)

    def test_binary_roundtrip_no_eof_protocol_and_user_isolation(self):
        payload = bytes(range(256)) + b'EOF.EOF\x00'
        result = self.request('POST', '/api/files?name=binary-test.dat', session=self.alice, raw=payload)
        self.assertEqual(result['status'], 201)
        self.assertEqual(self.request('GET', '/api/download?name=binary-test.dat', session=self.alice)['raw'], payload)
        self.assertEqual(self.request('GET', '/api/download?name=binary-test.dat&username=alice', session=self.bob)['status'], 404)
        result = self.request('GET', '/api/files', session=self.alice)
        self.assertTrue(any(row['name'] == 'binary-test.dat' for row in result['data']['files']))
        self.assertEqual(self.request('DELETE', '/api/files?name=binary-test.dat', session=self.alice)['status'], 200)

    def test_duplicate_upload_and_empty_files(self):
        self.assertEqual(self.request('POST', '/api/files?name=empty.txt', session=self.alice, raw=b'')['status'], 201)
        self.assertEqual(self.request('POST', '/api/files?name=empty.txt', session=self.alice, raw=b'changed')['status'], 409)
        self.assertEqual(self.request('GET', '/api/download?name=empty.txt', session=self.alice)['raw'], b'')
        self.request('DELETE', '/api/files?name=empty.txt', session=self.alice)
        self.assertFalse(list(self.app.user_folder('alice').glob('.upload-*')))

    def test_traversal_symlinks_and_safe_html_preview(self):
        for name in ('../users.db', '/tmp/other', '..', 'a\\b', 'a\x00b', '.upload-hidden'):
            from urllib.parse import quote
            result = self.request('GET', '/api/download?name=' + quote(name, safe=''), session=self.alice)
            self.assertEqual(result['status'], 400)
        symlink = self.app.user_folder('alice') / 'link.txt'
        symlink.symlink_to(self.app.db_path)
        try:
            self.assertEqual(self.request('GET', '/api/download?name=link.txt', session=self.alice)['status'], 403)
        finally:
            symlink.unlink()
        payload = b'<script>alert("never execute")</script>'
        self.request('POST', '/api/files?name=page.html', session=self.alice, raw=payload)
        result = self.request('GET', '/api/preview?name=page.html', session=self.alice)
        self.assertEqual(result['data']['text'], payload.decode())
        self.assertIn('application/json', result['headers']['Content-Type'])
        self.request('DELETE', '/api/files?name=page.html', session=self.alice)

    def test_admin_authorization_is_enforced_by_api(self):
        self.assertEqual(self.request('GET', '/api/admin/status', session=self.bob)['status'], 403)
        self.assertEqual(self.request('POST', '/api/admin/users', {'username': 'hacker', 'password': 'secret'}, session=self.bob)['status'], 403)
        result = self.request('GET', '/api/admin/status', session=self.alice)
        self.assertEqual(result['status'], 200)
        self.assertTrue(any(user['username'] == 'alice' and user['admin'] for user in result['data']['users']))
        self.assertNotIn('password_hash', json.dumps(result['data']))

    def test_account_creation_conflict_and_session_reset(self):
        self.assertEqual(self.request('POST', '/api/admin/users', {'username': 'newclient', 'password': 'first'}, session=self.alice)['status'], 200)
        self.assertFalse(self.app.is_admin('newclient'))
        self.assertEqual(self.request('POST', '/api/admin/users', {'username': 'newclient', 'password': 'second'}, session=self.alice)['status'], 409)
        result = self.request('POST', '/api/admin/users', {'username': 'bob', 'password': 'temporary', 'reset': True}, session=self.alice)
        self.assertEqual(result['status'], 200)
        self.assertEqual(self.request('GET', '/api/files', session=self.bob)['status'], 401)
        self.app.auth.set_password('bob', 'bob-test-password', self.app.db_path)

    def test_password_change_revokes_other_sessions_but_keeps_current(self):
        other = self.login('bob')
        result = self.request('POST', '/api/password',
                              {'current': 'bob-test-password', 'password': 'new-test-password'}, session=self.bob)
        self.assertEqual(result['status'], 200)
        self.assertEqual(self.request('GET', '/api/session', session=self.bob)['status'], 200)
        self.assertEqual(self.request('GET', '/api/session', session=other)['status'], 401)
        self.app.auth.set_password('bob', 'bob-test-password', self.app.db_path)

    def test_upload_size_and_host_limits(self):
        result = self.request('POST', '/api/files?name=too-big.dat', session=self.alice,
                              headers={'Content-Length': str(100 * 1024 * 1024 + 1)}, raw=b'')
        self.assertEqual(result['status'], 413)
        self.assertEqual(self.request('GET', '/', headers={'Host': 'evil.example'})['status'], 403)

    def test_expired_sessions_do_not_authenticate(self):
        token = self.bob['cookie'].split('=', 1)[1]
        with self.app.lock:
            self.app.sessions[self.app.token_key(token)]['expires'] = 0
        self.assertEqual(self.request('GET', '/api/session', session=self.bob)['status'], 401)

    def test_public_origin_validation_keeps_http_mode_private(self):
        self.assertEqual(normalise_public_origin('https://Relay.Example/'), 'https://relay.example')
        for value in ('http://example.com', 'https://*.example.com', 'https://user:pass@example.com',
                      'https://example.com/path', 'https://example.com?query=1', 'https://example.com:8080'):
            with self.subTest(origin=value):
                with self.assertRaises(ValueError):
                    normalise_public_origin(value)
        with self.assertRaises(ValueError):
            WebServer(('127.0.0.1', 0), self.app, public_origin='https://relay.example')

    def test_verified_https_and_secure_cookie(self):
        from setup_tls import generate_certificate
        from tls_transport import create_server_context, create_client_context
        cert, key = generate_certificate(self.root / 'https-test-certs')
        # Reuse the temporary accounts but use a separate in-memory session map.
        secure_app = Application(self.root, secure=True)
        server = WebServer(('127.0.0.1', 0), secure_app, public_origin='https://relay-test.trycloudflare.com')
        server.tls_context = create_server_context(cert, key)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            connection = http.client.HTTPSConnection('127.0.0.1', server.server_port,
                                                    context=create_client_context(cert), timeout=5)
            body = json.dumps({'username': 'alice', 'password': 'alice-test-password'})
            connection.request('POST', '/api/login', body, {
                'Content-Type': 'application/json', 'Host': 'relay-test.trycloudflare.com',
                'Origin': 'https://relay-test.trycloudflare.com'})
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.assertIn('; Secure', response.getheader('Set-Cookie'))
            self.assertTrue(json.loads(response.read())['secure'])
            connection.close()
            # Wrong origins, wildcard lookalikes, alternate ports and spoofed
            # proxy headers must not bypass the original access checks.
            for headers in (
                {'Host': 'relay-test.trycloudflare.com', 'Origin': 'https://evil.example'},
                {'Host': 'other.trycloudflare.com', 'Origin': 'https://other.trycloudflare.com'},
                {'Host': 'relay-test.trycloudflare.com:9999', 'Origin': 'https://relay-test.trycloudflare.com:9999'},
                {'Host': 'evil.example', 'X-Forwarded-Host': 'relay-test.trycloudflare.com'},
            ):
                connection = http.client.HTTPSConnection('127.0.0.1', server.server_port,
                                                        context=create_client_context(cert), timeout=5)
                connection.request('POST', '/api/login', body,
                                   dict(headers, **{'Content-Type': 'application/json'}))
                response = connection.getresponse()
                self.assertEqual(response.status, 403)
                response.read()
                connection.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(3)

    def test_logout_revokes_session(self):
        self.assertEqual(self.request('POST', '/api/logout', session=self.alice)['status'], 200)
        self.assertEqual(self.request('GET', '/api/files', session=self.alice)['status'], 401)

    def test_login_rate_limit(self):
        with self.app.lock:
            self.app.attempts.clear()
        statuses = [self.request('POST', '/api/login', {'username': 'unknown', 'password': 'wrong'})['status'] for _ in range(11)]
        self.assertEqual(statuses[:10], [401] * 10)
        self.assertEqual(statuses[-1], 429)


if __name__ == '__main__':
    unittest.main()
