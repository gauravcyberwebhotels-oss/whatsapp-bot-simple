from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
import secrets
import hashlib
import logging
import requests
import random
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from config import Config

# --- Basic Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- App Initialization ---
app = Flask(__name__, static_folder='.', static_url_path='')
app.config.from_object(Config)

# --- Extensions ---
CORS(app, origins=['*'])
limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])

# --- Supabase Client Class ---
class SupabaseClient:
    def __init__(self, url, key):
        self.url = url
        self.key = key
        self.headers = {'apikey': self.key, 'Authorization': f'Bearer {self.key}', 'Content-Type': 'application/json'}

    def _make_request(self, method, endpoint, **kwargs):
        try:
            response = requests.request(method, f"{self.url}/rest/v1/{endpoint}", headers=self.headers, timeout=10, **kwargs)
            response.raise_for_status()
            return response.json() if response.content else {"status": "success"}, None
        except requests.exceptions.HTTPError as e:
            error_message = e.response.json().get('message', 'Request failed')
            return None, error_message
        except Exception as e:
            return None, str(e)

    def select(self, table, filters=None, single=False):
        params = {k: f"eq.{v}" for k, v in filters.items()} if filters else {}
        headers = self.headers.copy()
        if single: headers['Accept'] = 'application/vnd.pgrst.object+json'
        try:
            response = requests.get(f"{self.url}/rest/v1/{table}", headers=headers, params=params, timeout=10)
            if response.status_code == 406: return None, None # Not found for single
            response.raise_for_status()
            return response.json(), None
        except requests.exceptions.HTTPError as e:
            return None, e.response.json().get('message', 'Select failed')
        except Exception as e:
            return None, str(e)

    def insert(self, table, data):
        return self._make_request('POST', table, json=data)

    def update(self, table, filters, data_to_update):
        url_params = '&'.join([f'{k}=eq.{v}' for k, v in filters.items()])
        return self._make_request('PATCH', f"{table}?{url_params}", json=data_to_update)

    def delete(self, table, filters):
        url_params = '&'.join([f'{k}=eq.{v}' for k, v in filters.items()])
        return self._make_request('DELETE', f"{table}?{url_params}")

# --- Initialize Supabase Client ---
supabase = SupabaseClient(Config.SUPABASE_URL, Config.SUPABASE_KEY)
logger.info("✅ Supabase client initialized.")

# --- Helper Functions ---
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def generate_secure_token(length=16):
    return f"sk_{secrets.token_hex(length)}"

def send_email(to_email, subject, body):
    try:
        msg = MIMEText(body, 'html')
        msg['Subject'] = subject
        msg['From'] = Config.EMAIL_ADDRESS
        msg['To'] = to_email
        with smtplib.SMTP(Config.SMTP_SERVER, Config.SMTP_PORT) as server:
            server.starttls()
            server.login(Config.EMAIL_ADDRESS, Config.EMAIL_PASSWORD)
            server.send_message(msg)
        logger.info(f"✅ Email sent successfully to {to_email}")
        return True
    except Exception as e:
        logger.error(f"❌ FAILED TO SEND EMAIL to {to_email}: {e}")
        return False

# --- Core Routes ---
@app.route('/')
def serve_frontend():
    return send_from_directory('.', 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('.', path)

# --- API Routes ---
@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data received."}), 400
    
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters long."}), 400

    new_user = {'email': email, 'password_hash': hash_password(password), 'secret_key': generate_secure_token()}
    _, error = supabase.insert('users', new_user)
    
    if error:
        if 'unique constraint' in error:
            return jsonify({"error": "Email already registered"}), 400
        return jsonify({"error": "Database registration failed."}), 500
    
    return jsonify({"message": "Registration successful! You can now log in."}), 201

@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data received."}), 400

    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    user_data, error = supabase.select('users', filters={'email': email}, single=True)
    if error or not user_data:
        return jsonify({"error": "Invalid email or password"}), 401

    if user_data.get('password_hash') == hash_password(password):
        logger.info(f"✅ User logged in: {email}")
        return jsonify({
            'secret_key': user_data.get('secret_key'),
            'credits': user_data.get('credits'),
            'spreadsheet_url': user_data.get('spreadsheet_url')
        })
    else:
        logger.warning(f"Failed login for email: {email}")
        return jsonify({"error": "Invalid email or password"}), 401

@app.route('/save_spreadsheet', methods=['POST'])
def save_spreadsheet():
    data = request.get_json()
    secret_key = data.get('secret_key')
    url = data.get('spreadsheet_url')
    
    if not secret_key or not url:
        return jsonify({"error": "Missing required fields"}), 400
        
    _, error = supabase.update('users', filters={'secret_key': secret_key}, data_to_update={'spreadsheet_url': url})
    if error:
        return jsonify({"error": "Failed to save URL"}), 500
        
    return jsonify({"message": "Spreadsheet URL saved successfully"})

@app.route('/forgot_password', methods=['POST'])
@limiter.limit("3 per hour")
def forgot_password():
    data = request.get_json()
    email = data.get('email')
    if not email:
        return jsonify({"error": "Email is required."}), 400
    
    user, _ = supabase.select('users', filters={'email': email}, single=True)
    if not user:
        # Silently succeed to prevent attackers from checking if an email is registered
        return jsonify({"message": "If an account with that email exists, a reset code has been sent."})
    
    reset_code = str(random.randint(100000, 999999))
    expires_at = datetime.utcnow() + timedelta(hours=1)
    
    supabase.insert('password_resets', {'email': email, 'token': reset_code, 'expires_at': expires_at.isoformat()})
    
    email_body = f"<h2>Password Reset</h2><p>Your password reset code is: <b>{reset_code}</b></p><p>This code will expire in one hour.</p>"
    send_email(email, "Your Password Reset Code", email_body)
    
    return jsonify({"message": "If an account with that email exists, a reset code has been sent."})

@app.route('/reset_password', methods=['POST'])
@limiter.limit("5 per hour")
def reset_password():
    data = request.get_json()
    email, code, new_password = data.get('email'), data.get('code'), data.get('new_password')
    
    if not all([email, code, new_password]):
        return jsonify({"error": "All fields are required."}), 400
    if len(new_password) < 8:
        return jsonify({"error": "Password must be at least 8 characters."}), 400

    # Find the most recent, non-expired token
    resets, _ = supabase.select('password_resets', filters={'email': email, 'token': code})
    if not resets or datetime.fromisoformat(resets[0]['expires_at'].replace('Z', '+00:00')) < datetime.utcnow().replace(tzinfo=timedelta(0)):
        return jsonify({"error": "Invalid or expired reset code."}), 400
    
    # Update the user's password in the main 'users' table
    _, error = supabase.update('users', filters={'email': email}, data_to_update={'password_hash': hash_password(new_password)})
    if error:
        return jsonify({"error": "Failed to update password."}), 500
    
    # Invalidate the token by deleting it
    supabase.delete('password_resets', filters={'id': resets[0]['id']})

    return jsonify({"message": "Password has been reset successfully. Please log in."})

# --- Main Execution ---
if __name__ == "__main__":
    port = int(os.environ.get('PORT', 10000))
    app.run(host="0.0.0.0", port=port, debug=False)
