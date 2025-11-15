# app.py

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
import secrets
import hashlib
import logging
import requests
from config import Config # Make sure you have a config.py file

# --- Basic Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- App Initialization ---
app = Flask(__name__, static_folder='.', static_url_path='')
app.config.from_object(Config)

# --- Extensions ---
CORS(app, origins=['*'])
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# --- Supabase Client Utility ---
class SupabaseClient:
    def __init__(self, url, key):
        self.url = url
        self.key = key
        self.headers = {
            'apikey': self.key,
            'Authorization': f'Bearer {self.key}',
            'Content-Type': 'application/json'
        }

    def _make_request(self, method, endpoint, **kwargs):
        try:
            response = requests.request(method, f"{self.url}/rest/v1/{endpoint}", headers=self.headers, timeout=10, **kwargs)
            response.raise_for_status()
            # No content successful responses (like from DELETE or some PATCH) might not have json
            return response.json() if response.content else {"status": "success"}, None
        except requests.exceptions.HTTPError as e:
            error_message = e.response.json().get('message', 'Request failed')
            logger.error(f"Supabase HTTP error: {error_message}")
            return None, error_message
        except Exception as e:
            logger.error(f"Supabase general exception: {e}")
            return None, str(e)

    def insert(self, table, data):
        return self._make_request('POST', table, json=data)

    def select(self, table, filters=None, single=False):
        params = {}
        if filters:
            for k, v in filters.items():
                params[k] = f"eq.{v}"
        
        headers = self.headers.copy()
        if single:
            headers['Accept'] = 'application/vnd.pgrst.object+json'
        
        try:
            response = requests.get(f"{self.url}/rest/v1/{table}", headers=headers, params=params, timeout=10)
            if response.status_code == 406: # Special case for single=True not found
                return None, None
            response.raise_for_status()
            return response.json(), None
        except requests.exceptions.HTTPError as e:
            error_message = e.response.json().get('message', 'Select failed')
            return None, error_message
        except Exception as e:
            return None, str(e)

    def update(self, table, filters, data_to_update):
        params = {}
        if filters:
            for k, v in filters.items():
                params[k] = f"eq.{v}"
        return self._make_request('PATCH', table, params=params, json=data_to_update)

# --- Initialize Supabase Client ---
supabase = SupabaseClient(Config.SUPABASE_URL, Config.SUPABASE_KEY)
logger.info("✅ Supabase client initialized.")

# --- Utility Functions ---
def generate_secure_token(length=16):
    return f"sk_{secrets.token_hex(length)}"

def hash_password(password):
    # Consistently use sha256 for all password operations
    return hashlib.sha256(password.encode()).hexdigest()

# --- Routes ---
@app.route('/')
def serve_frontend():
    return send_from_directory('.', 'index.html')
    
@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('.', path)

@app.route('/health')
def health():
    return jsonify({"status": "healthy"}), 200
    
@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    if not email or not password: return jsonify({"error": "Email and password are required"}), 400
    if len(password) < 8: return jsonify({"error": "Password must be at least 8 characters long"}), 400
    
    password_hash = hash_password(password)
    secret_key = generate_secure_token()
    
    _, error = supabase.insert('users', {'email': email, 'password_hash': password_hash, 'secret_key': secret_key})
    
    if error:
        if 'unique constraint' in error: return jsonify({"error": "Email already registered"}), 400
        return jsonify({"error": f"Registration failed due to a database error."}), 500
        
    return jsonify({"message": "Registration successful! You can now log in."}), 201

@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    if not email or not password: return jsonify({"error": "Email and password are required"}), 400

    user_data, error = supabase.select('users', filters={'email': email}, single=True)

    if error: return jsonify({"error": "Failed to query user database."}), 500
    if not user_data: return jsonify({"error": "Invalid email or password"}), 401

    password_hash = hash_password(password)
    if user_data.get('password_hash') == password_hash:
        logger.info(f"✅ User logged in: {email}")
        return jsonify({
            "secret_key": user_data.get('secret_key'),
            "credits": user_data.get('credits', 100),
            "spreadsheet_url": user_data.get('spreadsheet_url', '')
        })
    else:
        return jsonify({"error": "Invalid email or password"}), 401
        
@app.route('/save_spreadsheet', methods=['POST'])
def save_spreadsheet():
    data = request.get_json()
    secret_key = data.get('secret_key')
    spreadsheet_url = data.get('spreadsheet_url')

    if not secret_key or not spreadsheet_url:
        return jsonify({"error": "Secret key and spreadsheet URL are required"}), 400
    if not spreadsheet_url.startswith('https://docs.google.com/spreadsheets/'):
        return jsonify({"error": "Invalid Google Sheets URL format."}), 400

    _, error = supabase.update(
        'users', 
        filters={'secret_key': secret_key}, 
        data_to_update={'spreadsheet_url': spreadsheet_url}
    )

    if error: return jsonify({"error": f"Failed to save URL: {error}"}), 500
    return jsonify({"message": "Spreadsheet URL saved successfully"})

# --- Main Execution ---
if __name__ == "__main__":
    port = int(os.environ.get('PORT', 10000))
    app.run(host="0.0.0.0", port=port, debug=False)
