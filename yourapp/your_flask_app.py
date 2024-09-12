from flask import Flask, request, jsonify, send_from_directory, redirect, url_for, session
import requests

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a secure secret key for session management

# Keycloak configuration
KEYCLOAK_URL = "http://localhost:8080/realms/centific/protocol/openid-connect"
CLIENT_ID = "Balu"
CLIENT_SECRET = "wk0rxCD075nUWStD2JsXF3L4AkWyEkQL"

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
        response = requests.post(f"{KEYCLOAK_URL}/token", data=payload)
        response.raise_for_status()  # Raise an HTTPError for bad responses
    except requests.RequestException as e:
        return jsonify({"error": str(e)}), 500

    tokens = response.json()
    if 'access_token' in tokens:
        # Save the username and tokens in session
        session['username'] = username
        session['refresh_token'] = tokens.get('refresh_token')
        return jsonify(tokens)
    else:
        return jsonify({"error": "Failed to get tokens"}), 401

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    if 'refresh_token' not in session:
        return jsonify({"error": "No session found"}), 400

    refresh_token = session['refresh_token']

    # Prepare the payload for Keycloak logout endpoint
    payload = {
        'grant_type': 'refresh_token',
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'refresh_token': refresh_token
    }

    try:
        response = requests.post(f"{KEYCLOAK_URL}/logout", data=payload)
        response.raise_for_status()
    except requests.RequestException as e:
        return jsonify({"error": str(e)}), 500

    # Clear the session
    session.pop('username', None)
    session.pop('refresh_token', None)

    return jsonify({"message": "Logged out successfully"})

@app.route('/')
def serve_login_page():
    return send_from_directory('static', 'login.html')

@app.route('/dashboard')
def dashboard():
    username = session.get('username')
    if not username:
        return redirect(url_for('serve_login_page'))
    return f"<h1>Hello, {username}!</h1><p>You have successfully logged in.</p><a href='/logout'>Logout</a>"

@app.route('/logout')
def logout_page():
    return send_from_directory('static', 'logout.html')

if __name__ == '__main__':
    app.run(debug=True)
