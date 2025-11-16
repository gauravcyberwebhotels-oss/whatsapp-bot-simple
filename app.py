# app.py (Updated and Corrected)

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
import threading
from datetime import datetime, timedelta, timezone
from config import Config
import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException

# --- Essential Startup Checks ---
# Check for required environment variables before the app starts
# This prevents the 401 error by ensuring keys are loaded.
required_vars = ['SUPABASE_URL', 'SUPABASE_KEY', 'BREVO_API_KEY', 'SENDER_EMAIL']
missing_vars = [var for var in required_vars if not getattr(Config, var, None)]
if missing_vars:
    raise ValueError(f"CRITICAL ERROR: Missing environment variables: {', '.join(missing_vars)}. The application cannot start.")

# --- Logging Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- App Initialization ---
app = Flask(__name__, static_folder='.', static_url_path='')
app.config.from_object(Config)
CORS(app, origins=['*']) # Be more specific in production, e.g., ['https://your-frontend-domain.com']
limiter = Limiter(key_func=get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

# --- Refined Supabase Client ---
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
            response = requests.request(method, f"{self.url}/rest/v1/{endpoint}", headers=kwargs.pop('headers', self.headers), timeout=15, **kwargs)
            response.raise_for_status() # Raises HTTPError for bad responses (4xx or 5xx)
            
            # Supabase returns 204 No Content for successful empty responses (e.g., DELETE, minimal INSERT)
            if response.status_code == 204:
                return {"status": "success"}, None

            return response.json(), None
        except requests.exceptions.HTTPError as e:
            # Try to get a specific message from Supabase response, otherwise use the generic error
            error_message = str(e)
            try:
                error_details = e.response.json()
                error_message = error_details.get('message', str(e))
            except (ValueError, AttributeError):
                pass # If response is not JSON or response object is missing
            logger.error(f"HTTP Error {e.response.status_code}: {error_message} for URL: {e.request.url}")
            return None, error_message
        except requests.exceptions.RequestException as e:
            logger.error(f"Request exception: {e}")
            return None, "A network error occurred."

    def select(self, table, filters=None, single=False):
        params = {k: f"eq.{v}" for k, v in filters.items()} if filters else {}
        headers = self.headers.copy()
        if single:
            headers['Accept'] = 'application/vnd.pgrst.object+json'
        return self._make_request('GET', table, params=params, headers=headers)

    def insert(self, table, data):
        # Prefer minimal return to be faster
        headers = self.headers.copy()
        headers['Prefer'] = 'return=minimal'
        return self._make_request('POST', table, json=data, headers=headers)

    def update(self, table, filters, data):
        params = {k: f"eq.{v}" for k, v in filters.items()}
        return self._make_request('PATCH', table, params=params, json=data)

    def delete(self, table, filters):
        params = {k: f"eq.{v}" for k, v in filters.items()}
        return self._make_request('DELETE', table, params=params)

supabase = SupabaseClient(Config.SUPABASE_URL, Config.SUPABASE_KEY)

# --- Helper Functions ---
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def send_email_async(to_email, subject, body):
    def send():
        configuration = sib_api_v3_sdk.Configuration()
        configuration.api_key['api-key'] = Config.BREVO_API_KEY
        api_instance = sib_api_v3_sdk.TransactionalEmailsApi(sib_api_v3_sdk.ApiClient(configuration))
        sender = {"name": "WhatsApp Pro", "email": Config.SENDER_EMAIL}
        to = [{"email": to_email}]
        send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(to=to, sender=sender, subject=subject, html_content=body)
        try:
            api_instance.send_transac_email(send_smtp_email)
            logger.info(f"✅ Email queued for sending to {to_email} via Brevo.")
        except ApiException as e:
            logger.error(f"❌ FAILED TO SEND EMAIL via Brevo. Exception: {e.body}")
    
    # Run the email sending in a background thread
    threading.Thread(target=send, daemon=True).start()
    return True

# --- API Routes ---
@app.route('/')
def serve_frontend():
    return send_from_directory('.', 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('.', path)

@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    data = request.get_json()
    email, password = data.get('email'), data.get('password')
    if not email or not password:
        return jsonify({"error": "Email and password are required."}), 400

    # Check if user already exists
    user_data, err = supabase.select('users', {'email': email}, single=True)
    if err:
        logger.error(f"Register DB check error: {err}")
        return jsonify({"error": "Database error, please try again later."}), 500
    if user_data:
        return jsonify({"error": "This email is already registered."}), 409 # 409 Conflict is more specific

    # Insert new user
    user_payload = {
        'email': email,
        'password_hash': hash_password(password),
        'secret_key': secrets.token_hex(16)
    }
    _, err = supabase.insert('users', user_payload)
    if err:
        logger.error(f"Register insert error: {err}")
        return jsonify({"error": "Registration failed. Please try again."}), 500
    
    logger.info(f"✅ New user registered: {email}")
    return jsonify({"message": "Registration successful. You can now log in."}), 201

@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    data = request.get_json()
    email, password = data.get('email'), data.get('password')
    if not email or not password:
        return jsonify({"error": "Email and password are required."}), 400

    user, err = supabase.select('users', {'email': email}, single=True)
    if err:
        logger.error(f"Login DB error: {err}")
        return jsonify({"error": "Database error, login is unavailable."}), 500
    if not user:
        return jsonify({"error": "Email not found. Please register first."}), 401
    if user.get('password_hash') != hash_password(password):
        return jsonify({"error": "Invalid password."}), 401

    last_login = user.get('last_login_at')
    # Update last login time in the background to not slow down the response
    threading.Thread(target=lambda: supabase.update('users', {'email': email}, {'last_login_at': datetime.now(timezone.utc).isoformat()})).start()

    logger.info(f"✅ User logged in: {email}")
    return jsonify({
        'secret_key': user.get('secret_key'),
        'credits': user.get('credits', 100),
        'spreadsheet_url': user.get('spreadsheet_url', ''),
        'last_login_at': last_login
    })

@app.route('/save_spreadsheet', methods=['POST'])
@limiter.limit("20 per hour") # Allow more frequent saves
def save_spreadsheet():
    data = request.get_json()
    secret_key, spreadsheet_url = data.get('secret_key'), data.get('spreadsheet_url')
    if not secret_key or not spreadsheet_url:
        return jsonify({"error": "A secret key and spreadsheet URL are required."}), 400

    _, err = supabase.update('users', {'secret_key': secret_key}, {'spreadsheet_url': spreadsheet_url})
    if err:
        logger.error(f"Save spreadsheet error: {err}")
        return jsonify({"error": "Failed to save URL. Your session might be invalid."}), 500
    
    logger.info(f"✅ Spreadsheet URL saved for key: {secret_key[:8]}...")
    return jsonify({"message": "Spreadsheet URL saved successfully."})

@app.route('/forgot_password', methods=['POST'])
@limiter.limit("3 per minute")
def forgot_password():
    email = request.get_json().get('email')
    if not email:
        return jsonify({"error": "Email is required"}), 400
        
    user, _ = supabase.select('users', {'email': email}, single=True)
    # Important: Do not reveal if the email exists for security reasons.
    # Always return a success-like message.
    if user:
        reset_code = str(random.randint(100000, 999999))
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=15) # Shorter expiry is safer
        
        # Upsert operation is safer: delete old code, then insert new one
        supabase.delete('password_resets', {'email': email}) # Ignore errors if it doesn't exist
        
        _, err = supabase.insert('password_resets', {
            'email': email,
            'token': reset_code,
            'expires_at': expires_at.isoformat()
        })
        
        if err:
            logger.error(f"Forgot password DB error for {email}: {err}")
            # Even if DB fails, don't tell the user. Just log it.
        else:
            email_body = f"Your password reset code is: <h2>{reset_code}</h2><p>This code expires in 15 minutes.</p>"
            send_email_async(email, "Your Password Reset Code", email_body)
            logger.info(f"✅ Reset code generated for: {email}")

    return jsonify({"message": "If an account with that email exists, a password reset code has been sent."})

@app.route('/reset_password', methods=['POST'])
@limiter.limit("5 per minute")
def reset_password():
    data = request.get_json()
    email, code, new_password = data.get('email'), data.get('code'), data.get('new_password')
    
    if not all([email, code, new_password]) or len(code) != 6 or len(new_password) < 8:
        return jsonify({"error": "Valid email, 6-digit code, and an 8+ character password are required."}), 400

    # Find the matching reset code
    reset_data, err = supabase.select('password_resets', {'email': email, 'token': code}, single=True)
    if err or not reset_data:
        return jsonify({"error": "Invalid or expired reset code."}), 400

    # Check for expiration
    expires_at_str = reset_data['expires_at'].replace('Z', '+00:00') # Ensure timezone compatibility
    expires_at = datetime.fromisoformat(expires_at_str)
    
    if expires_at < datetime.now(timezone.utc):
        supabase.delete('password_resets', {'id': reset_data['id']}) # Clean up expired code
        return jsonify({"error": "This reset code has expired."}), 400

    # Update user's password
    _, err = supabase.update('users', {'email': email}, {'password_hash': hash_password(new_password)})
    if err:
        logger.error(f"Password reset update error for {email}: {err}")
        return jsonify({"error": "Failed to update password."}), 500

    # Clean up the used reset token
    supabase.delete('password_resets', {'email': email})
    
    logger.info(f"✅ Password successfully reset for: {email}")
    return jsonify({"message": "Password has been reset successfully. You can now log in."})

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy"}), 200

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get('PORT', 10000)),
        debug=Config.DEBUG
    )
