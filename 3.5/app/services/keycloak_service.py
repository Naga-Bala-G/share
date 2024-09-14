import requests
import os
from dotenv import load_dotenv

load_dotenv()

class KeycloakService:
    def __init__(self):
        self.keycloak_server = os.getenv('KEYCLOAK_SERVER')
        self.realm = os.getenv('REALM')
        self.client_id = os.getenv('CLIENT_ID')
        self.client_secret = os.getenv('CLIENT_SECRET')
        self.token_url = f'{self.keycloak_server}/realms/{self.realm}/protocol/openid-connect/token'
        self.userinfo_url = f'{self.keycloak_server}/realms/{self.realm}/protocol/openid-connect/userinfo'
        self.roles_url = f'{self.keycloak_server}/admin/realms/{self.realm}/roles'
        self.admin_token = None

    def get_admin_token(self):
        if not self.admin_token:
            response = requests.post(self.token_url, data={
                'grant_type': 'client_credentials',
                'client_id': self.client_id,
                'client_secret': self.client_secret
            })
            response.raise_for_status()
            self.admin_token = response.json().get('access_token')
        return self.admin_token

    def authenticate_user(self, username, password, cloud_provider):
        response = requests.post(self.token_url, data={
            'grant_type': 'password',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'username': username,
            'password': password
        })
        return response

    def get_userinfo(self, token):
        response = requests.get(self.userinfo_url, headers={
            'Authorization': f'Bearer {token}'
        })
        return response

    def refresh_token(self, refresh_token):
        response = requests.post(self.token_url, data={
            'grant_type': 'refresh_token',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'refresh_token': refresh_token
        })
        return response

    def create_or_update_role(self, role_name, permissions, cloud_provider):
        token = self.get_admin_token()
        response = requests.post(self.roles_url, json={
            'name': role_name,
            'description': ','.join(permissions)
        }, headers={
            'Authorization': f'Bearer {token}'
        })
        return response

    def get_roles(self, cloud_provider):
        token = self.get_admin_token()
        response = requests.get(self.roles_url, headers={
            'Authorization': f'Bearer {token}'
        })
        return response

    def assign_role(self, username, role_name, cloud_provider):
        token = self.get_admin_token()
        user_response = requests.get(f'{self.keycloak_server}/admin/realms/{self.realm}/users?username={username}', headers={
            'Authorization': f'Bearer {token}'
        })
        if user_response.status_code == 200:
            user_id = user_response.json()[0]['id']
            role_response = requests.post(f'{self.keycloak_server}/admin/realms/{self.realm}/users/{user_id}/role-mappings/realm', json={
                'roles': [{'name': role_name}]
            }, headers={
                'Authorization': f'Bearer {token}'
            })
            return role_response
        return user_response
