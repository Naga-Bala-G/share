import unittest
from app import create_app

class RbacTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app('development')
        self.client = self.app.test_client()

    def test_create_role(self):
        response = self.client.post('/api/rbac/roles', json={
            'roleName': 'admin',
            'permissions': ['read', 'write']
        })
        self.assertEqual(response.status_code, 200)
