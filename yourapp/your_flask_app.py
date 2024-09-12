from flask import Flask, request, jsonify, send_from_directory
import requests

app = Flask(__name__)

# Keycloak configuration
KEYCLOAK_URL = "http://localhost:8080/realms/myrealm/protocol/openid-connect/token"
CLIENT_ID = "myclient"  # Replace with your actual client ID
CLIENT_SECRET = "UKbpq0cFGgUZukFVXIa3UXbsVh9RqyfD"  # Replace with your actual client secret

@app.route('/api/auth/token', methods=['POST'])
def get_token():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    # Prepare the payload for Keycloak token endpoint
    payload = {
        'grant_type': 'password',
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'username': username,
        'password': password
    }

    # Make the request to Keycloak
    try:
        response = requests.post(KEYCLOAK_URL, data=payload)
        response.raise_for_status()  # Raise an HTTPError for bad responses
    except requests.RequestException as e:
        return jsonify({"error": str(e)}), 500

    # Return the response from Keycloak
    return jsonify(response.json())

@app.route('/')
def serve_login_page():
    return send_from_directory('static', 'login.html')

if __name__ == '__main__':
    app.run(debug=True)
