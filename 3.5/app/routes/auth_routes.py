from flask import Blueprint, request, jsonify, abort
from app.services.keycloak_service import KeycloakService

auth_bp = Blueprint('auth', __name__)
keycloak_service = KeycloakService()

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    cloud_provider = data.get('cloudProvider')

    response = keycloak_service.authenticate_user(username, password, cloud_provider)
    if response.status_code == 200:
        return jsonify(response.json())
    else:
        abort(response.status_code, description="Authentication failed")

@auth_bp.route('/userinfo', methods=['GET'])
def userinfo():
    token = request.headers.get('Authorization').replace('Bearer ', '')
    response = keycloak_service.get_userinfo(token)
    if response.status_code == 200:
        return jsonify(response.json())
    else:
        abort(response.status_code, description="Failed to get user info")

@auth_bp.route('/refresh-token', methods=['POST'])
def refresh_token():
    data = request.json
    refresh_token = data.get('refreshToken')
    response = keycloak_service.refresh_token(refresh_token)
    if response.status_code == 200:
        return jsonify(response.json())
    else:
        abort(response.status_code, description="Token refresh failed")
