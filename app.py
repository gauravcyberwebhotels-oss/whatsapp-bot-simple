# app.py - Final Working Version
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
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='.', static_url_path='')

# Load configuration directly (no separate config.py to avoid issues)
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key')
    SUPABASE_URL = os.environ.get('SUPABASE_URL')
    SUPABASE_KEY = os.environ.get('SUPABASE_KEY')
    BREVO_API_KEY = os.environ.get('BREVO_API_KEY')
    SENDER_EMAIL = os.environ.get('SENDER_EMAIL')
    DEBUG = os.environ.get('DEBUG', 'False').lower() in ('true', '1', 't')

# Validate config
if not all([Config.SUPABASE_URL, Config.SUPABASE_KEY, Config.BREVO_API_KEY, Config.SENDER_EMAIL]):
    logger.error("❌ Missing required environment variables")
else:
    logger.info("✅ All environment variables loaded successfully")

app.config.from_object(Config)
CORS(app, origins=['*'])
limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])

class SupabaseClient:
    def __init__(self, url, key): 
        self.url = url
        self.key = key
        self.headers = {
            'apikey': key, 
            'Authorization': f'Bearer {key}', 
            'Content-Type': 'application/json',
            'Prefer': 'return=representation'
        }
    
    def _make_request(self, method, endpoint, **kwargs):
        try:
            url = f"{self.url}/rest/v1/{endpoint}"
            headers = {**self.headers, **kwargs.pop('headers', {})}
            
            r = requests.request(method, url, headers=headers, timeout=30, **kwargs)
            
            if r.status_code == 204:
                return {"status": "success"}, None
            
            if r.content:
                return r.json(), None
            else:
                return {"status": "success"}, None
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error: {e}")
            return None, str(e)
        except Exception as e: 
            logger.error(f"Unexpected error: {e}")
            return None, str(e)
    
    def select(self, table, filters=None, single=False):
        headers = self.headers.copy()
        params = {}
        
        if filters:
            for key, value in filters.items():
                params[f"{key}"] = f"eq.{value}"
        
        if single:
            headers['Accept'] = 'application/vnd.pgrst.object+json'
        
        return self._make_request('GET', table, params=params, headers=headers)
    
    def insert(self, table, data):
        return self._make_request('POST', table, json=data)
    
    def update(self, table, filters, data):
        filter_query = '&'.join([f'{k}=eq.{v}' for k, v in filters.items()])
        return self._make_request('PATCH', f"{table}?{filter_query}", json=data)
    
    def delete(self, table, filters):
        filter_query = '&'.join([f'{k}=eq.{v}' for k, v in filters.items()])
        return self._make_request('DELETE', f"{table}?{filter_query}")

# Initialize Supabase client
supabase = SupabaseClient(Config.SUPABASE_URL, Config.SUPABASE_KEY) if Config.SUPABASE_URL and Config.SUPABASE_KEY else None

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def send_email_async(to_email, subject, body):
    def send():
        try:
            import sib_api_v3_sdk
            from sib_api_v3_sdk.rest import ApiException
            
            if not Config.BREVO_API_KEY or not Config.SENDER_EMAIL:
                logger.error("Brevo credentials not configured")
                return

            configuration = sib_api_v3_sdk.Configuration()
            configuration.api_key['api-key'] = Config.BREVO_API_KEY
            
            api_instance = sib_api_v3_sdk.TransactionalEmailsApi(sib_api_v3_sdk.ApiClient(configuration))
            
            send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(
                to=[{"email": to_email}],
                sender={"name": "WhatsApp Pro", "email": Config.SENDER_EMAIL},
                subject=subject,
                html_content=body
            )
            
            api_response = api_instance.send_transac_email(send_smtp_email)
            logger.info(f"✅ Email sent to {to_email}")
            
        except ApiException as e:
            logger.error(f"Brevo API error: {e}")
        except Exception as e:
            logger.error(f"Email sending error: {e}")
    
    threading.Thread(target=send, daemon=True).start()

@app.route('/')
def serve_frontend():
    return send_from_directory('.', 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('.', path)

@app.route('/register', methods=['POST'])
def register():
    if not supabase:
        return jsonify({"error": "Service unavailable"}), 503
        
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        password = data.get('password')
        
        if not email or not password:
            return jsonify({"error": "Email and password required"}), 400
        
        if len(password) < 8:
            return jsonify({"error": "Password must be 8+ characters"}), 400

        # Check if user exists
        user, err = supabase.select('users', filters={'email': email}, single=True)
        
        if err:
            return jsonify({"error": "Database error"}), 500
            
        if user:
            return jsonify({"error": "Email already registered"}), 400
        
        # Create user
        user_data = {
            'email': email,
            'password_hash': hash_password(password),
            'secret_key': secrets.token_hex(16),
            'credits': 100,
            'created_at': datetime.utcnow().isoformat()
        }
        
        result, err = supabase.insert('users', user_data)
        
        if err:
            return jsonify({"error": "Registration failed"}), 500
            
        return jsonify({"message": "Registration successful"}), 201
        
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/login', methods=['POST'])
def login():
    if not supabase:
        return jsonify({"error": "Service unavailable"}), 503
        
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        password = data.get('password')
        
        if not email or not password:
            return jsonify({"error": "Email and password required"}), 400
        
        user, err = supabase.select('users', filters={'email': email}, single=True)
        
        if err:
            return jsonify({"error": "Database error"}), 500
            
        if not user:
            return jsonify({"error": "User not registered"}), 401
        
        if user.get('password_hash') != hash_password(password):
            return jsonify({"error": "Invalid credentials"}), 401
        
        # Update last login
        last_login = user.get('last_login_at')
        supabase.update('users', {'email': email}, {
            'last_login_at': datetime.utcnow().isoformat()
        })
        
        return jsonify({
            'secret_key': user.get('secret_key'),
            'credits': user.get('credits', 100),
            'spreadsheet_url': user.get('spreadsheet_url', ''),
            'last_login_at': last_login
        })
        
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/save_spreadsheet', methods=['POST'])
def save_spreadsheet():
    if not supabase:
        return jsonify({"error": "Service unavailable"}), 503
        
    try:
        data = request.get_json()
        secret_key = data.get('secret_key')
        spreadsheet_url = data.get('spreadsheet_url')
        
        if not secret_key:
            return jsonify({"error": "Secret key required"}), 400
            
        result, err = supabase.update('users', {'secret_key': secret_key}, {
            'spreadsheet_url': spreadsheet_url
        })
        
        if err:
            return jsonify({"error": "Failed to save URL"}), 500
            
        return jsonify({"message": "URL saved successfully"})
        
    except Exception as e:
        logger.error(f"Save spreadsheet error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    if not supabase:
        return jsonify({"error": "Service unavailable"}), 503
        
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        
        if not email:
            return jsonify({"error": "Email required"}), 400
        
        # Check if user exists
        user, _ = supabase.select('users', filters={'email': email}, single=True)
        
        # Always return success for security
        if not user:
            return jsonify({"message": "If account exists, reset code sent"})
        
        # Generate reset code
        reset_code = str(random.randint(100000, 999999))
        expires_at = datetime.utcnow() + timedelta(hours=1)
        
        # Clear old codes
        supabase.delete('password_resets', {'email': email})
        
        # Insert new code
        reset_data = {
            'email': email,
            'token': reset_code,
            'expires_at': expires_at.isoformat(),
            'created_at': datetime.utcnow().isoformat()
        }
        
        result, err = supabase.insert('password_resets', reset_data)
        
        if err:
            return jsonify({"error": "Failed to store reset code"}), 500
        
        # Send email
        email_subject = "Password Reset Code - WhatsApp Pro"
        email_body = f"""
        <div style="font-family: Arial, sans-serif;">
            <h2>Password Reset Request</h2>
            <p>Your reset code is:</p>
            <div style="font-size: 32px; font-weight: bold; color: #667eea;">
                {reset_code}
            </div>
            <p>This code expires in 1 hour.</p>
        </div>
        """
        
        send_email_async(email, email_subject, email_body)
        
        return jsonify({"message": "If account exists, reset code sent"})
        
    except Exception as e:
        logger.error(f"Forgot password error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/reset_password', methods=['POST'])
def reset_password():
    if not supabase:
        return jsonify({"error": "Service unavailable"}), 503
        
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        code = data.get('code')
        new_password = data.get('new_password')
        
        if not all([email, code, new_password]):
            return jsonify({"error": "All fields required"}), 400
        
        if len(new_password) < 8:
            return jsonify({"error": "Password must be 8+ characters"}), 400
        
        # Find reset code
        reset_records, err = supabase.select('password_resets', filters={'email': email, 'token': code})
        
        if err or not reset_records:
            return jsonify({"error": "Invalid or expired code"}), 400
        
        reset_record = reset_records[0]
        expires_at = datetime.fromisoformat(reset_record['expires_at'].replace('Z', '+00:00'))
        
        if expires_at < datetime.utcnow():
            supabase.delete('password_resets', {'id': reset_record['id']})
            return jsonify({"error": "Code expired"}), 400
        
        # Update password
        result, err = supabase.update('users', {'email': email}, {
            'password_hash': hash_password(new_password)
        })
        
        if err:
            return jsonify({"error": "Failed to update password"}), 500
        
        # Delete used code
        supabase.delete('password_resets', {'email': email})
        
        return jsonify({"message": "Password reset successfully"})
        
    except Exception as e:
        logger.error(f"Reset password error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        "status": "healthy", 
        "timestamp": datetime.utcnow().isoformat(),
        "supabase": "connected" if supabase else "disconnected"
    })

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 10000))
    app.run(host="0.0.0.0", port=port, debug=Config.DEBUG)
