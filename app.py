# app.py (FINAL, CORRECTED VERSION)

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

# --- BOILERPLATE & SETUP (No Changes Here) ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='.', static_url_path='')
app.config.from_object(Config)

CORS(app, origins=['*'])
limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])

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
        except requests.exceptions.HTTPError as e: return None, e.response.json().get('message', 'Request failed')
        except Exception as e: return None, str(e)

    def select(self, table, filters=None, single=False):
        params = {k: f"eq.{v}" for k, v in filters.items()} if filters else {}
        headers = self.headers.copy()
        if single: headers['Accept'] = 'application/vnd.pgrst.object+json'
        try:
            response = requests.get(f"{self.url}/rest/v1/{table}", headers=headers, params=params, timeout=10)
            if response.status_code == 406: return None, None
            response.raise_for_status()
            return response.json(), None
        except requests.exceptions.HTTPError as e: return None, e.response.json().get('message', 'Select failed')
        except Exception as e: return None, str(e)

    def insert(self, table, data): return self._make_request('POST', table, json=data)
    def update(self, table, filters, data): return self._make_request('PATCH', f"{table}?{ '&'.join([f'{k}=eq.{v}' for k,v in filters.items()]) }", json=data)
    def delete(self, table, filters): return self._make_request('DELETE', f"{table}?{ '&'.join([f'{k}=eq.{v}' for k,v in filters.items()]) }")

supabase = SupabaseClient(Config.SUPABASE_URL, Config.SUPABASE_KEY)
logger.info("✅ Supabase client initialized.")

def hash_password(password): return hashlib.sha256(password.encode()).hexdigest()

def send_email(to_email, subject, body):
    try:
        msg = MIMEText(body, 'html')
        msg['Subject'], msg['From'], msg['To'] = subject, Config.EMAIL_ADDRESS, to_email
        with smtplib.SMTP(Config.SMTP_SERVER, Config.SMTP_PORT) as server:
            server.starttls()
            server.login(Config.EMAIL_ADDRESS, Config.EMAIL_PASSWORD)
            server.send_message(msg)
        logger.info(f"✅ Email sent successfully to {to_email}")
        return True
    except Exception as e:
        logger.error(f"❌ FAILED TO SEND EMAIL to {to_email}. Reason: {e}")
        return False

# --- ROUTES (No Changes, except /forgot_password) ---
@app.route('/')
def serve_frontend(): return send_from_directory('.', 'index.html')
@app.route('/<path:path>')
def serve_static(path): return send_from_directory('.', path)

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email, password = data.get('email'), data.get('password')
    if not all([email, password]): return jsonify({"error": "Email and password are required."}), 400
    _, error = supabase.insert('users', {'email': email, 'password_hash': hash_password(password), 'secret_key': secrets.token_hex(16)})
    if error and 'unique constraint' in error: return jsonify({"error": "Email already registered."}), 400
    if error: return jsonify({"error": "Database error during registration."}), 500
    return jsonify({"message": "Registration successful. You can now log in."}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email, password = data.get('email'), data.get('password')
    if not all([email, password]): return jsonify({"error": "Email and password are required."}), 400
    user_data, error = supabase.select('users', filters={'email': email}, single=True)
    if error or not user_data or user_data.get('password_hash') != hash_password(password):
        return jsonify({"error": "Invalid email or password."}), 401
    return jsonify({k: user_data.get(k) for k in ['secret_key', 'credits', 'spreadsheet_url']})

# --- FIX: ROBUST FORGOT PASSWORD LOGIC ---
@app.route('/forgot_password', methods=['POST'])
@limiter.limit("5 per hour") # Slightly increased limit for testing
def forgot_password():
    email = request.get_json().get('email')
    if not email: return jsonify({"error": "Email is required."}), 400

    user, db_error = supabase.select('users', filters={'email': email}, single=True)
    if db_error: return jsonify({"error": "Database error, please try again later."}), 500
    
    # Security: Always return the same message to prevent checking if an email exists.
    # We will only proceed if the user actually exists in the DB.
    if user:
        reset_code, expires_at = str(random.randint(100000, 999999)), datetime.utcnow() + timedelta(hours=1)
        email_body = f"<h2>Password Reset Code</h2><p>Your password reset code is: <b>{reset_code}</b>. It will expire in one hour.</p>"
        
        # We check if the email was sent successfully.
        email_sent = send_email(email, "Your Password Reset Code", email_body)
        
        if not email_sent:
            # If it failed, tell the frontend there was a server error.
            return jsonify({"error": "Could not send the password reset email. Check server logs for details."}), 500

        # Only insert the reset code into the database if the email was successfully sent.
        supabase.insert('password_resets', {'email': email, 'token': reset_code, 'expires_at': expires_at.isoformat()})

    # This is the generic success message.
    return jsonify({"message": "If an account with that email exists, a reset code has been sent."})

@app.route('/reset_password', methods=['POST'])
def reset_password():
    data = request.get_json()
    email, code, new_password = data.get('email'), data.get('code'), data.get('new_password')
    if not all([email, code, new_password]): return jsonify({"error": "All fields are required."}), 400
    
    now_utc = datetime.utcnow().replace(tzinfo=None)
    # Note: Supabase timestamp is often 'YYYY-MM-DDTHH:MM:SS.ffffff+00:00'
    resets, _ = supabase.select('password_resets', filters={'email': email, 'token': code})
    
    if not resets: return jsonify({"error": "Invalid reset code."}), 400

    # Properly parse timezone-aware ISO format from Supabase
    expires_at_str = resets[0]['expires_at'].replace('Z', '+00:00')
    expires_at = datetime.fromisoformat(expires_at_str).replace(tzinfo=None)

    if expires_at < now_utc:
        return jsonify({"error": "Expired reset code."}), 400
    
    _, error = supabase.update('users', filters={'email': email}, data={'password_hash': hash_password(new_password)})
    if error: return jsonify({"error": "Failed to update password."}), 500
    
    supabase.delete('password_resets', filters={'id': resets[0]['id']})
    return jsonify({"message": "Password has been reset successfully. Please log in."})


# A simple health check endpoint
@app.route('/health')
def health_check():
    return jsonify({"status": "healthy"}), 200

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 10000))
    app.run(host="0.0.0.0", port=port)
