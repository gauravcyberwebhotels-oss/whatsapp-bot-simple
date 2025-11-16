# app.py - Final Secure Version
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
from config import Config

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='.', static_url_path='')

# Initialize config
try:
    config = Config()
    config.validate()
    app.config.from_object(config)
    logger.info("✅ Configuration loaded successfully")
except ValueError as e:
    logger.error(f"❌ Configuration error: {e}")
    exit(1)

CORS(app, origins=['*'])
limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])

# Security headers
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

class SupabaseClient:
    def __init__(self, url, key): 
        if not url or not key:
            raise ValueError("Supabase URL and Key are required")
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
            
            r = requests.request(
                method, 
                url, 
                headers=headers, 
                timeout=30, 
                **kwargs
            )
            
            if r.status_code == 204:
                return {"status": "success"}, None
            
            if r.content:
                return r.json(), None
            else:
                return {"status": "success"}, None
                
        except requests.exceptions.HTTPError as e:
            error_msg = str(e)
            if e.response.content:
                try:
                    error_data = e.response.json()
                    error_msg = error_data.get('message', error_data.get('error', str(e)))
                except:
                    error_msg = e.response.text
            logger.error(f"HTTP Error {e.response.status_code}: {error_msg}")
            return None, error_msg
        except Exception as e: 
            logger.error(f"Request exception: {e}")
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
try:
    supabase = SupabaseClient(Config.SUPABASE_URL, Config.SUPABASE_KEY)
    logger.info("✅ Supabase client initialized successfully")
except Exception as e:
    logger.error(f"❌ Failed to initialize Supabase client: {e}")
    supabase = None

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def send_email_async(to_email, subject, body):
    """Sends email using the Brevo (Sendinblue) API."""
    def send():
        try:
            # Import here to avoid issues
            import sib_api_v3_sdk
            from sib_api_v3_sdk.rest import ApiException
            
            BREVO_API_KEY = Config.BREVO_API_KEY
            SENDER_EMAIL = Config.SENDER_EMAIL
            
            if not BREVO_API_KEY:
                logger.error("❌ BREVO_API_KEY is not set")
                return
                
            if not SENDER_EMAIL:
                logger.error("❌ SENDER_EMAIL is not set")
                return

            configuration = sib_api_v3_sdk.Configuration()
            configuration.api_key['api-key'] = BREVO_API_KEY
            
            api_instance = sib_api_v3_sdk.TransactionalEmailsApi(sib_api_v3_sdk.ApiClient(configuration))
            
            send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(
                to=[{"email": to_email}],
                sender={"name": "WhatsApp Pro", "email": SENDER_EMAIL},
                subject=subject,
                html_content=body
            )
            
            api_response = api_instance.send_transac_email(send_smtp_email)
            logger.info(f"✅ Email sent to {to_email} via Brevo. Message ID: {api_response.message_id}")
            
        except ApiException as e:
            logger.error(f"❌ FAILED TO SEND EMAIL via Brevo. Exception: {e}")
        except Exception as e:
            logger.error(f"❌ Unexpected error sending email: {e}")
    
    threading.Thread(target=send, daemon=True).start()

@app.route('/')
def serve_frontend():
    return send_from_directory('.', 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('.', path)

@app.route('/register', methods=['POST'])
@limiter.limit("10 per minute")
def register():
    if not supabase:
        return jsonify({"error": "Service temporarily unavailable"}), 503
        
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
            
        email = data.get('email', '').strip().lower()
        password = data.get('password')
        
        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400
        
        if len(password) < 8:
            return jsonify({"error": "Password must be at least 8 characters"}), 400

        # Check if user already exists
        user, err = supabase.select('users', filters={'email': email}, single=True)
        
        if err:
            logger.error(f"Database error checking user: {err}")
            return jsonify({"error": "Database error"}), 500
            
        if user:
            return jsonify({"error": "Email already registered."}), 400
        
        # Create new user
        user_data = {
            'email': email,
            'password_hash': hash_password(password),
            'secret_key': secrets.token_hex(16),
            'credits': 100,
            'created_at': datetime.utcnow().isoformat()
        }
        
        result, err = supabase.insert('users', user_data)
        
        if err:
            logger.error(f"Registration failed: {err}")
            return jsonify({"error": "Registration failed."}), 500
            
        logger.info(f"User registered successfully: {email}")
        return jsonify({"message": "Registration successful. You can now log in."}), 201
        
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    if not supabase:
        return jsonify({"error": "Service temporarily unavailable"}), 503
        
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
            
        email = data.get('email', '').strip().lower()
        password = data.get('password')
        
        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400
        
        # Find user
        user, err = supabase.select('users', filters={'email': email}, single=True)
        
        if err:
            logger.error(f"Database error during login: {err}")
            return jsonify({"error": "Database error"}), 500
            
        if not user:
            return jsonify({"error": "User not registered. Please register first."}), 401
        
        # Verify password
        if user.get('password_hash') != hash_password(password):
            return jsonify({"error": "Invalid email or password."}), 401
        
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
@limiter.limit("10 per minute")
def save_spreadsheet():
    if not supabase:
        return jsonify({"error": "Service temporarily unavailable"}), 503
        
    try:
        data = request.get_json()
        secret_key = data.get('secret_key')
        spreadsheet_url = data.get('spreadsheet_url')
        
        if not secret_key:
            return jsonify({"error": "Secret key is required"}), 400
            
        result, err = supabase.update('users', {'secret_key': secret_key}, {
            'spreadsheet_url': spreadsheet_url
        })
        
        if err:
            logger.error(f"Failed to save spreadsheet URL: {err}")
            return jsonify({"error": "Failed to save URL."}), 500
            
        return jsonify({"message": "Spreadsheet URL saved successfully."})
        
    except Exception as e:
        logger.error(f"Save spreadsheet error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/forgot_password', methods=['POST'])
@limiter.limit("5 per minute")
def forgot_password():
    if not supabase:
        return jsonify({"error": "Service temporarily unavailable"}), 503
        
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
            
        email = data.get('email', '').strip().lower()
        if not email:
            return jsonify({"error": "Email is required"}), 400
        
        # Check if user exists
        user, _ = supabase.select('users', filters={'email': email}, single=True)
        
        # Always return success message for security (don't reveal if email exists)
        if not user:
            logger.info(f"Password reset requested for non-existent email: {email}")
            return jsonify({"message": "If an account exists, a reset code has been sent."})
        
        # Generate reset code
        reset_code = str(random.randint(100000, 999999))
        expires_at = datetime.utcnow() + timedelta(hours=1)
        
        # Delete any existing reset codes for this email
        supabase.delete('password_resets', {'email': email})
        
        # Insert new reset code
        reset_data = {
            'email': email,
            'token': reset_code,
            'expires_at': expires_at.isoformat(),
            'created_at': datetime.utcnow().isoformat()
        }
        
        result, err = supabase.insert('password_resets', reset_data)
        
        if err:
            logger.error(f"Failed to store reset code: {err}")
            return jsonify({"error": "Failed to store reset code."}), 500
        
        # Send email
        email_subject = "Your Password Reset Code - WhatsApp Pro"
        email_body = f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #667eea;">Password Reset Request</h2>
            <p>You requested a password reset for your WhatsApp Pro account.</p>
            <div style="background: #f8f9fa; padding: 20px; border-radius: 10px; text-align: center; margin: 20px 0;">
                <h3 style="color: #333; margin: 0;">Your Reset Code:</h3>
                <div style="font-size: 32px; font-weight: bold; color: #667eea; letter-spacing: 5px; margin: 15px 0;">
                    {reset_code}
                </div>
            </div>
            <p style="color: #666; font-size: 14px;">
                This code will expire in 1 hour. If you didn't request this reset, please ignore this email.
            </p>
        </div>
        """
        
        send_email_async(email, email_subject, email_body)
        logger.info(f"Password reset code sent to: {email}")
        
        return jsonify({"message": "If an account exists, a reset code has been sent."})
        
    except Exception as e:
        logger.error(f"Forgot password error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/reset_password', methods=['POST'])
@limiter.limit("5 per minute")
def reset_password():
    if not supabase:
        return jsonify({"error": "Service temporarily unavailable"}), 503
        
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
            
        email = data.get('email', '').strip().lower()
        code = data.get('code')
        new_password = data.get('new_password')
        
        if not all([email, code, new_password]):
            return jsonify({"error": "All fields are required"}), 400
        
        if len(new_password) < 8:
            return jsonify({"error": "Password must be at least 8 characters"}), 400
        
        # Find reset code
        reset_records, err = supabase.select('password_resets', filters={'email': email, 'token': code})
        
        if err or not reset_records:
            return jsonify({"error": "Invalid or expired reset code."}), 400
        
        reset_record = reset_records[0]
        expires_at = datetime.fromisoformat(reset_record['expires_at'].replace('Z', '+00:00'))
        
        # Check if code expired
        if expires_at < datetime.utcnow():
            supabase.delete('password_resets', {'id': reset_record['id']})
            return jsonify({"error": "Reset code has expired."}), 400
        
        # Update password
        result, err = supabase.update('users', {'email': email}, {
            'password_hash': hash_password(new_password)
        })
        
        if err:
            logger.error(f"Failed to update password: {err}")
            return jsonify({"error": "Failed to update password."}), 500
        
        # Delete used reset code
        supabase.delete('password_resets', {'email': email})
        
        logger.info(f"Password reset successful for: {email}")
        return jsonify({"message": "Password has been reset successfully."})
        
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

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"error": "Rate limit exceeded"}), 429

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 10000))
    debug = Config.DEBUG
    logger.info(f"🚀 Starting server on port {port} (debug: {debug})")
    app.run(host="0.0.0.0", port=port, debug=debug)
