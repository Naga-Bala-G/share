import unittest
from app import create_app

class AuthTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app('development')
        self.client = self.app.test_client()

    def test_login(self):
        response = self.client.post('/api/auth/login', json={
            'username': 'testuser',
            'password': 'password'
        })
        self.assertEqual(response.status_code, 200)
