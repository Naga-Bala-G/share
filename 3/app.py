# app.py
from flask import Flask, request, jsonify, abort, render_template, redirect, url_for
import requests

app = Flask(__name__)

# Keycloak configuration
KEYCLOAK_SERVER_URL = 'http://localhost:8080'
REALM_NAME = 'company'
CLIENT_ID = 'myclient'
CLIENT_SECRET = 'OmnK4XgzA5sievSlTLdKuWKM1iDogMRs'
REDIRECT_URI = 'http://localhost:5000/callback'

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not all([username, password]):
        abort(400, description='Missing parameters')

    # Obtain access token
    token_response = requests.post(f'{KEYCLOAK_SERVER_URL}/realms/{REALM_NAME}/protocol/openid-connect/token', data={
        'grant_type': 'password',
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'username': username,
        'password': password,
    })
    
    if token_response.status_code != 200:
        abort(token_response.status_code, description='Authentication failed')

    token_data = token_response.json()
    
    # Return token data
    return jsonify(token_data)

@app.route('/api/auth/user-details', methods=['POST'])
def user_details():
    # Extract the access token from the Authorization header
    auth_header = request.headers.get('Authorization')
    
    if not auth_header:
        abort(400, description='Authorization header is missing')
    
    # Parse the access token from the header
    token_prefix = 'Bearer '
    if not auth_header.startswith(token_prefix):
        abort(400, description='Invalid authorization header format')
    
    access_token = auth_header[len(token_prefix):]
    
    if not access_token:
        abort(400, description='Missing access token')

    # Introspect the access token
    introspect_response = requests.post(f'{KEYCLOAK_SERVER_URL}/realms/{REALM_NAME}/protocol/openid-connect/token/introspect', data={
        'token': access_token,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
    })

    if introspect_response.status_code != 200:
        abort(introspect_response.status_code, description='Token introspection failed')

    introspect_data = introspect_response.json()
    
    # Check if token is active
    if not introspect_data.get('active'):
        abort(401, description='Token is not active or invalid')

    # Return user details
    return jsonify(introspect_data)

@app.route('/api/auth/role-check', methods=['POST'])
def role_check():
    auth_header = request.headers.get('Authorization')
    
    if not auth_header:
        abort(400, description='Authorization header is missing')
    
    token_prefix = 'Bearer '
    if not auth_header.startswith(token_prefix):
        abort(400, description='Invalid authorization header format')
    
    access_token = auth_header[len(token_prefix):]
    
    if not access_token:
        abort(400, description='Missing access token')

    # Introspect the access token
    introspect_response = requests.post(f'{KEYCLOAK_SERVER_URL}/realms/{REALM_NAME}/protocol/openid-connect/token/introspect', data={
        'token': access_token,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
    })

    if introspect_response.status_code != 200:
        abort(introspect_response.status_code, description='Token introspection failed')

    introspect_data = introspect_response.json()
    
    if not introspect_data.get('active'):
        abort(401, description='Token is not active or invalid')
    
    # Check for roles in resource_access
    resource_access = introspect_data.get('resource_access', {})
    
    # Extract roles for 'myclient'
    user_roles = resource_access.get('myclient', {}).get('roles', [])
    
    # Example role check
    if 'executive' in user_roles:
        return jsonify({'message': 'Access granted for admin'})
    elif 'Manager' in user_roles:
        return jsonify({'message': 'Access granted for Manager'})
    elif 'Employee' in user_roles:
        return jsonify({'message': 'Access granted for Employee'})
    else:
        abort(403, description='User does not have the required role')

    return jsonify(introspect_data)

@app.route('/api/auth/refresh', methods=['POST'])
def refresh_token():
    data = request.json
    refresh_token = data.get('refresh_token')

    if not refresh_token:
        abort(400, description='Missing refresh token')

    # Request a new access token using the refresh token
    token_response = requests.post(f'{KEYCLOAK_SERVER_URL}/realms/{REALM_NAME}/protocol/openid-connect/token', data={
        'grant_type': 'refresh_token',
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'refresh_token': refresh_token,
    })

    if token_response.status_code != 200:
        abort(token_response.status_code, description='Token refresh failed')

    token_data = token_response.json()

    # Return new token data
    return jsonify(token_data)


if __name__ == '__main__':
    app.run(debug=True)
