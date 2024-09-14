from flask import Blueprint, request, jsonify, abort
from app.services.keycloak_service import KeycloakService

rbac_bp = Blueprint('rbac', __name__)
keycloak_service = KeycloakService()

@rbac_bp.route('/roles', methods=['POST'])
def create_or_update_role():
    data = request.json
    role_name = data.get('roleName')
    permissions = data.get('permissions')
    cloud_provider = data.get('cloudProvider')

    response = keycloak_service.create_or_update_role(role_name, permissions, cloud_provider)
    if response.status_code in [200, 201]:
        return jsonify({'status': 'success', 'message': 'Role created/updated successfully'})
    else:
        abort(response.status_code, description="Failed to create/update role")

@rbac_bp.route('/roles', methods=['GET'])
def get_roles():
    cloud_provider = request.args.get('cloudProvider')
    response = keycloak_service.get_roles(cloud_provider)
    if response.status_code == 200:
        return jsonify(response.json())
    else:
        abort(response.status_code, description="Failed to retrieve roles")

@rbac_bp.route('/assign-role', methods=['POST'])
def assign_role():
    data = request.json
    username = data.get('username')
    role_name = data.get('roleName')
    cloud_provider = data.get('cloudProvider')

    response = keycloak_service.assign_role(username, role_name, cloud_provider)
    if response.status_code == 204:
        return jsonify({'status': 'success', 'message': 'Role assigned successfully'})
    else:
        abort(response.status_code, description="Failed to assign role")
