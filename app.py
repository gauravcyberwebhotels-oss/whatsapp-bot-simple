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
import random
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from config import Config

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

    def insert(self, table, data): return self._make_request('POST', table, json=data)
    def update(self, table, filters, data_to_update): return self._make_request('PATCH', f"{table}?{ '&'.join([f'{k}=eq.{v}' for k,v in filters.items()]) }", json=data_to_update)
    def delete(self, table, filters): return self._make_request('DELETE', f"{table}?{ '&'.join([f'{k}=eq.{v}' for k,v in filters.items()]) }")

supabase = SupabaseClient(Config.SUPABASE_URL, Config.SUPABASE_KEY)
logger.info("✅ Supabase client initialized.")

def hash_password(password): return hashlib.sha256(password.encode()).hexdigest()
def generate_secure_token(length=16): return f"sk_{secrets.token_hex(length)}"

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
        logger.info(f"✅ Email sent to {to_email}")
        return True
    except Exception as e:
        logger.error(f"❌ Failed to send email to {to_email}: {e}")
        return False

@app.route('/')
def serve_frontend(): return send_from_directory('.', 'index.html')
@app.route('/<path:path>')
def serve_static(path): return send_from_directory('.', path)

@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    data, email, password = request.get_json(), data.get('email'), data.get('password')
    if not email or not password: return jsonify({"error": "Email and password required"}), 400
    
    _, error = supabase.insert('users', {'email': email, 'password_hash': hash_password(password), 'secret_key': generate_secure_token()})
    if error and 'unique constraint' in error: return jsonify({"error": "Email already registered"}), 400
    if error: return jsonify({"error": "Database registration failed."}), 500
    
    return jsonify({"message": "Registration successful! You can now log in."}), 201

@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    data, email, password = request.get_json(), data.get('email'), data.get('password')
    if not email or not password: return jsonify({"error": "Email and password required"}), 400

    user_data, error = supabase.select('users', filters={'email': email}, single=True)
    if error or not user_data: return jsonify({"error": "Invalid email or password"}), 401

    if user_data.get('password_hash') == hash_password(password):
        return jsonify({k: user_data.get(k) for k in ['secret_key', 'credits', 'spreadsheet_url']})
    else:
        return jsonify({"error": "Invalid email or password"}), 401

@app.route('/save_spreadsheet', methods=['POST'])
def save_spreadsheet():
    data = request.get_json()
    secret_key, url = data.get('secret_key'), data.get('spreadsheet_url')
    if not secret_key or not url: return jsonify({"error": "Missing required fields"}), 400

    _, error = supabase.update('users', filters={'secret_key': secret_key}, data_to_update={'spreadsheet_url': url})
    if error: return jsonify({"error": f"Failed to save URL: {error}"}), 500
    return jsonify({"message": "Spreadsheet URL saved successfully"})

@app.route('/forgot_password', methods=['POST'])
@limiter.limit("3 per hour")
def forgot_password():
    email = request.get_json().get('email')
    if not email: return jsonify({"error": "Email is required."}), 400
    
    user, error = supabase.select('users', filters={'email': email}, single=True)
    if not user:
        # Don't reveal if the user exists. Silently succeed.
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
    
    if not all([email, code, new_password]): return jsonify({"error": "All fields are required."}), 400
    if len(new_password) < 8: return jsonify({"error": "Password must be at least 8 characters."}), 400

    # Find the most recent, non-expired token for that email
    resets, _ = supabase.select('password_resets', filters={'email': email, 'token': code})
    if not resets: return jsonify({"error": "Invalid or expired reset code."}), 400
    
    # Check expiration
    reset_record = resets[0]
    if datetime.fromisoformat(reset_record['expires_at'].replace('Z', '+00:00')) < datetime.utcnow().replace(tzinfo=timedelta(0)):
        return jsonify({"error": "Reset code has expired."}), 400
        
    # All checks passed, update the user's password
    _, error = supabase.update('users', filters={'email': email}, data_to_update={'password_hash': hash_password(new_password)})
    if error: return jsonify({"error": "Failed to update password."}), 500

    # Invalidate the used token by deleting it
    supabase.delete('password_resets', filters={'id': reset_record['id']})

    return jsonify({"message": "Password has been reset successfully. Please log in."})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get('PORT', 10000)), debug=False)
