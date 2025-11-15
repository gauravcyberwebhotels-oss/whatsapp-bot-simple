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
from config import Config

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

# --- Supabase Client Utility (Now includes UPDATE) ---
class SupabaseClient:
    def __init__(self, url, key):
        self.url = url
        self.key = key
        self.headers = {
            'apikey': self.key,
            'Authorization': f'Bearer {self.key}',
            'Content-Type': 'application/json'
        }

    def insert(self, table, data):
        try:
            response = requests.post(
                f"{self.url}/rest/v1/{table}", headers=self.headers, json=data, timeout=10
            )
            response.raise_for_status()
            return response.json(), None
        except requests.exceptions.HTTPError as e:
            logger.error(f"Supabase insert HTTP error: {e.response.text}")
            return None, e.response.json().get('message', 'Insert failed')
        except Exception as e:
            logger.error(f"Supabase insert exception: {e}")
            return None, str(e)

    def select(self, table, filters=None, single=False):
        try:
            url = f"{self.url}/rest/v1/{table}"
            if filters:
                filter_str = '&'.join([f"{k}=eq.{v}" for k, v in filters.items()])
                url = f"{url}?{filter_str}"
            
            headers = self.headers.copy()
            if single:
                headers['Accept'] = 'application/vnd.pgrst.object+json'
            
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            return response.json(), None
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404 or e.response.status_code == 406: # 406 is for no result on single=True
                return None, None
            logger.error(f"Supabase select HTTP error: {e.response.text}")
            return None, e.response.json().get('message', 'Select failed')
        except Exception as e:
            logger.error(f"Supabase select exception: {e}")
            return None, str(e)
            
    def update(self, table, filters, data_to_update):
        """Updates rows in a table matching the filters."""
        try:
            filter_str = '&'.join([f"{k}=eq.{v}" for k, v in filters.items()])
            url = f"{self.url}/rest/v1/{table}?{filter_str}"
            
            response = requests.patch(url, headers=self.headers, json=data_to_update, timeout=10)
            response.raise_for_status()
            return response.json(), None
        except requests.exceptions.HTTPError as e:
            logger.error(f"Supabase update HTTP error: {e.response.text}")
            return None, e.response.json().get('message', 'Update failed')
        except Exception as e:
            logger.error(f"Supabase update exception: {e}")
            return None, str(e)


supabase = SupabaseClient(Config.SUPABASE_URL, Config.SUPABASE_KEY)
logger.info("✅ Supabase client initialized with update capabilities.")

def generate_secure_token(length=16):
    return f"sk_{secrets.token_hex(length)}"

@app.route('/')
def serve_frontend():
    return send_from_directory('.', 'index.html')

@app.route('/health')
def health():
    return jsonify({"status": "healthy"}), 200
    
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    if not email or not password: return jsonify({"error": "Email and password are required"}), 400
    if len(password) < 8: return jsonify({"error": "Password must be at least 8 characters long"}), 400
    
    password_hash = hashlib.sha224(password.encode()).hexdigest()
    secret_key = generate_secure_token()
    new_user_data = {'email': email, 'password_hash': password_hash, 'secret_key': secret_key}

    _, error = supabase.insert('users', new_user_data)
    if error:
        if 'unique constraint' in error.lower(): return jsonify({"error": "Email already registered"}), 400
        return jsonify({"error": f"Registration failed: {error}"}), 500
        
    logger.info(f"✅ User registered: {email}")
    return jsonify({"status": "success", "message": "Registration successful! You can now log in."}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    if not email or not password: return jsonify({"error": "Email and password are required"}), 400

    user_data, error = supabase.select('users', filters={'email': email}, single=True)
    if error or not user_data:
        return jsonify({"error": "Invalid email or password"}), 401

    password_hash = hashlib.sha224(password.encode()).hexdigest()
    if user_data.get('password_hash') == password_hash:
        logger.info(f"✅ User logged in: {email}")
        return jsonify({
            "status": "success",
            "message": "Login successful",
            "secret_key": user_data.get('secret_key'),
            "credits": user_data.get('credits', 100),
            "spreadsheet_url": user_data.get('spreadsheet_url', '') # Send spreadsheet URL
        })
    else:
        return jsonify({"error": "Invalid email or password"}), 401
        
@app.route('/save_spreadsheet', methods=['POST'])
def save_spreadsheet():
    """Saves the spreadsheet URL for a user, identified by secret_key."""
    data = request.get_json()
    secret_key = data.get('secret_key')
    spreadsheet_url = data.get('spreadsheet_url')

    if not secret_key or spreadsheet_url is None:
        return jsonify({"error": "Secret key and spreadsheet URL are required"}), 400

    _, error = supabase.update(
        'users', 
        filters={'secret_key': secret_key}, 
        data_to_update={'spreadsheet_url': spreadsheet_url}
    )

    if error:
        return jsonify({"error": f"Failed to save URL: {error}"}), 500
        
    logger.info(f"✅ Spreadsheet URL saved for user.")
    return jsonify({"status": "success", "message": "Spreadsheet URL saved successfully"})

# ... (other routes can remain as placeholders)

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 10000))
    app.run(host="0.0.0.0", port=port, debug=False)
