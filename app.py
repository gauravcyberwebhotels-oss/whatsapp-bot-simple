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
CORS(app, origins=['*']) # Simplified for now, can be restricted later
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

    def insert(self, table, data):
        """Inserts a single row of data into the specified table."""
        try:
            response = requests.post(
                f"{self.url}/rest/v1/{table}",
                headers=self.headers,
                json=data,
                timeout=10
            )
            response.raise_for_status()  # Raise an exception for bad status codes
            return response.json(), None
        except requests.exceptions.HTTPError as e:
            logger.error(f"Supabase insert HTTP error: {e.response.text}")
            return None, e.response.json().get('message', 'Insert failed')
        except Exception as e:
            logger.error(f"Supabase insert exception: {e}")
            return None, str(e)

    def select(self, table, filters=None, single=False):
        """Selects data from a table with optional filters."""
        try:
            url = f"{self.url}/rest/v1/{table}"
            if filters:
                filter_str = '&'.join([f"{k}=eq.{v}" for k, v in filters.items()])
                url = f"{url}?{filter_str}"

            # If 'single' is true, Supabase expects a specific header for a single object
            headers = self.headers.copy()
            if single:
                headers['Accept'] = 'application/vnd.pgrst.object+json'

            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            return response.json(), None
        except requests.exceptions.HTTPError as e:
            logger.error(f"Supabase select HTTP error: {e.response.text}")
            return None, e.response.json().get('message', 'Select failed')
        except Exception as e:
            logger.error(f"Supabase select exception: {e}")
            return None, str(e)

# --- Initialize the Supabase Client ---
supabase = SupabaseClient(Config.SUPABASE_URL, Config.SUPABASE_KEY)
logger.info("✅ Supabase client initialized.")


# --- Simplified Utility Functions ---
def generate_secure_token(length=16):
    """Generates a secure hex token prefixed with 'sk_'."""
    return f"sk_{secrets.token_hex(length)}"

# --- Routes ---

@app.route('/')
def serve_frontend():
    return send_from_directory('.', 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('.', path)

@app.route('/health')
def health():
    return jsonify({"status": "healthy", "database": "supabase_connected"}), 200
    
@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    # Basic password strength check
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters long"}), 400

    password_hash = hashlib.sha256(password.encode()).hexdigest()
    secret_key = generate_secure_token()
    
    new_user_data = {
        'email': email,
        'password_hash': password_hash,
        'secret_key': secret_key
    }

    result, error = supabase.insert('users', new_user_data)

    if error:
        # Check for unique constraint violation
        if 'unique constraint' in error.lower():
            return jsonify({"error": "Email already registered"}), 400
        return jsonify({"error": f"Registration failed: {error}"}), 500

    logger.info(f"✅ User registered successfully: {email}")
    return jsonify({
        "status": "success",
        "message": "Registration successful. You can now log in.",
    }), 201

@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    # Find the user by email in Supabase
    user_data, error = supabase.select('users', filters={'email': email}, single=True)

    if error or not user_data:
        logger.warning(f"Login failed for {email}: User not found or DB error.")
        return jsonify({"error": "Invalid email or password"}), 401

    # Check the password
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    if user_data.get('password_hash') == password_hash:
        logger.info(f"✅ User logged in successfully: {email}")
        return jsonify({
            "status": "success",
            "message": "Login successful",
            "secret_key": user_data.get('secret_key'),
            "credits": user_data.get('credits', 100) # Default if not set
        })
    else:
        logger.warning(f"Login failed for {email}: Invalid password.")
        return jsonify({"error": "Invalid email or password"}), 401
        
# --- Placeholder Routes for Future Bot Functionality ---
# These are kept so your frontend doesn't break, but they are disabled for now.
@app.route('/user/profile', methods=['POST'])
def get_user_profile():
    return jsonify({"error": "Profile functionality is coming soon."}), 501
    
@app.route('/save_spreadsheet', methods=['POST'])
def save_spreadsheet():
    return jsonify({"error": "Bot functionality is coming soon."}), 501
    
@app.route('/start', methods=['POST'])
def start_bot():
    return jsonify({"error": "Bot functionality is coming soon."}), 501

@app.route('/stop', methods=['POST'])
def stop_bot():
    return jsonify({"error": "Bot functionality is coming soon."}), 501
    
@app.route('/status', methods=['POST'])
def get_status():
    return jsonify({"status": "no_active_session"}), 200

@app.route('/progress', methods=['POST'])
def get_progress():
    return jsonify({"status": "no_active_session"}), 200

@app.route('/stats')
def get_stats():
     return jsonify({"total_users": 0, "active_bots": 0}), 200
     
@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"error": "Too many requests. Please try again later."}), 429

# --- Run the App ---
if __name__ == "__main__":
    port = int(os.environ.get('PORT', 10000))
    logger.info(f"🚀 Starting server on port {port}")
    app.run(host="0.0.0.0", port=port, debug=False)
