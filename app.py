# app.py (FIXED VERSION - NO EMAIL TIMEOUT)

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
import threading
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
            return None, e.response.json().get('message', 'Request failed')
        except Exception as e: 
            return None, str(e)

    def select(self, table, filters=None, single=False):
        params = {k: f"eq.{v}" for k, v in filters.items()} if filters else {}
        headers = self.headers.copy()
        if single: 
            headers['Accept'] = 'application/vnd.pgrst.object+json'
        try:
            response = requests.get(f"{self.url}/rest/v1/{table}", headers=headers, params=params, timeout=10)
            if response.status_code == 406: 
                return None, None
            response.raise_for_status()
            return response.json(), None
        except requests.exceptions.HTTPError as e: 
            return None, e.response.json().get('message', 'Select failed')
        except Exception as e: 
            return None, str(e)

    def insert(self, table, data): 
        return self._make_request('POST', table, json=data)
    
    def update(self, table, filters, data): 
        filter_str = '&'.join([f'{k}=eq.{v}' for k,v in filters.items()])
        return self._make_request('PATCH', f"{table}?{filter_str}", json=data)
    
    def delete(self, table, filters): 
        filter_str = '&'.join([f'{k}=eq.{v}' for k,v in filters.items()])
        return self._make_request('DELETE', f"{table}?{filter_str}")

supabase = SupabaseClient(Config.SUPABASE_URL, Config.SUPABASE_KEY)
logger.info("✅ Supabase client initialized.")

def hash_password(password): 
    return hashlib.sha256(password.encode()).hexdigest()

def send_email_async(to_email, subject, body):
    """Send email in a separate thread to avoid timeout"""
    def send():
        try:
            msg = MIMEText(body, 'html')
            msg['Subject'] = subject
            msg['From'] = Config.EMAIL_ADDRESS
            msg['To'] = to_email
            
            logger.info(f"Attempting to send email to {to_email} via {Config.SMTP_SERVER}:{Config.SMTP_PORT}")
            
            # Use shorter timeout for SMTP
            server = smtplib.SMTP(Config.SMTP_SERVER, Config.SMTP_PORT, timeout=15)
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(Config.EMAIL_ADDRESS, Config.EMAIL_PASSWORD)
            server.send_message(msg)
            server.quit()
            
            logger.info(f"✅ Email sent successfully to {to_email}")
            return True
        except Exception as e:
            logger.error(f"❌ FAILED TO SEND EMAIL to {to_email}. Error: {str(e)}")
            return False
    
    # Run in background thread
    thread = threading.Thread(target=send)
    thread.daemon = True
    thread.start()
    return True  # Always return True immediately to avoid timeout

@app.route('/')
def serve_frontend(): 
    return send_from_directory('.', 'index.html')

@app.route('/<path:path>')
def serve_static(path): 
    return send_from_directory('.', path)

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    if not all([email, password]):
        return jsonify({"error": "Email and password are required."}), 400
    
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters."}), 400
    
    # Check if user already exists
    existing_user, _ = supabase.select('users', filters={'email': email}, single=True)
    if existing_user:
        return jsonify({"error": "Email already registered."}), 400
    
    # Create new user
    user_data = {
        'email': email, 
        'password_hash': hash_password(password), 
        'secret_key': secrets.token_hex(16),
        'credits': 100
    }
    
    result, error = supabase.insert('users', user_data)
    if error:
        logger.error(f"Registration error: {error}")
        return jsonify({"error": "Database error during registration."}), 500
    
    return jsonify({"message": "Registration successful. You can now log in."}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    if not all([email, password]):
        return jsonify({"error": "Email and password are required."}), 400
    
    user_data, error = supabase.select('users', filters={'email': email}, single=True)
    
    if error or not user_data:
        return jsonify({"error": "Invalid email or password."}), 401
    
    if user_data.get('password_hash') != hash_password(password):
        return jsonify({"error": "Invalid email or password."}), 401
    
    return jsonify({
        'secret_key': user_data.get('secret_key'),
        'credits': user_data.get('credits', 100),
        'spreadsheet_url': user_data.get('spreadsheet_url', '')
    })

@app.route('/save_spreadsheet', methods=['POST'])
def save_spreadsheet():
    data = request.get_json()
    secret_key = data.get('secret_key')
    spreadsheet_url = data.get('spreadsheet_url')
    
    if not secret_key:
        return jsonify({"error": "Authentication required."}), 401
    
    if not spreadsheet_url:
        return jsonify({"error": "Spreadsheet URL is required."}), 400
    
    # Verify user exists
    user_data, error = supabase.select('users', filters={'secret_key': secret_key}, single=True)
    if error or not user_data:
        return jsonify({"error": "Invalid authentication."}), 401
    
    # Update spreadsheet URL
    result, error = supabase.update('users', {'secret_key': secret_key}, {'spreadsheet_url': spreadsheet_url})
    if error:
        return jsonify({"error": "Failed to save spreadsheet URL."}), 500
    
    return jsonify({"message": "Spreadsheet URL saved successfully."})

@app.route('/forgot_password', methods=['POST'])
@limiter.limit("3 per hour")
def forgot_password():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided."}), 400
        
    email = data.get('email')
    if not email:
        return jsonify({"error": "Email is required."}), 400
    
    logger.info(f"Password reset requested for: {email}")
    
    # Check if user exists
    user, _ = supabase.select('users', filters={'email': email}, single=True)
    if not user:
        # Return success even if user doesn't exist for security
        logger.info(f"No user found with email: {email}")
        return jsonify({"message": "If an account with that email exists, a reset code has been sent."})
    
    # Generate reset code
    reset_code = str(random.randint(100000, 999999))
    expires_at = datetime.utcnow() + timedelta(hours=1)
    
    # Create email body
    email_body = f"""
    <h2>Password Reset Code</h2>
    <p>Your password reset code is: <b style="font-size: 18px;">{reset_code}</b></p>
    <p>This code will expire in one hour.</p>
    <p>If you didn't request this reset, please ignore this email.</p>
    """
    
    # Store reset code first (before attempting to send email)
    # Delete any existing reset codes for this email
    supabase.delete('password_resets', {'email': email})
    
    # Store new reset code
    reset_data = {
        'email': email, 
        'token': reset_code, 
        'expires_at': expires_at.isoformat()
    }
    
    result, error = supabase.insert('password_resets', reset_data)
    if error:
        logger.error(f"Failed to store reset token: {error}")
        return jsonify({"error": "Failed to process reset request."}), 500
    
    # Try to send email (but don't wait for it - run in background)
    try:
        send_email_async(email, "Your Password Reset Code", email_body)
        logger.info(f"Reset code generated for {email}: {reset_code}")
        
        # For development/testing, log the code so you can use it
        if Config.DEBUG:
            logger.info(f"DEBUG MODE: Reset code for {email} is {reset_code}")
            
    except Exception as e:
        logger.error(f"Failed to queue email: {e}")
        # Don't return error - the code is still stored and user can request another
    
    return jsonify({
        "message": "If an account exists, a reset code has been sent.",
        "debug_code": reset_code if Config.DEBUG else None  # Only in debug mode
    })

@app.route('/reset_password', methods=['POST'])
def reset_password():
    data = request.get_json()
    email = data.get('email')
    code = data.get('code')
    new_password = data.get('new_password')
    
    if not all([email, code, new_password]):
        return jsonify({"error": "All fields are required."}), 400
    
    if len(new_password) < 8:
        return jsonify({"error": "Password must be at least 8 characters."}), 400
    
    # Find valid reset code
    resets, error = supabase.select('password_resets', filters={'email': email, 'token': code})
    if error or not resets:
        return jsonify({"error": "Invalid or expired reset code."}), 400
    
    reset_record = resets[0]
    expires_at = datetime.fromisoformat(reset_record['expires_at'].replace('Z', '+00:00'))
    
    if expires_at < datetime.utcnow().replace(tzinfo=None):
        supabase.delete('password_resets', {'id': reset_record['id']})
        return jsonify({"error": "Reset code has expired."}), 400
    
    # Update password
    result, error = supabase.update('users', {'email': email}, {'password_hash': hash_password(new_password)})
    if error:
        logger.error(f"Password update failed: {error}")
        return jsonify({"error": "Failed to update password."}), 500
    
    # Delete used reset code
    supabase.delete('password_resets', {'id': reset_record['id']})
    
    logger.info(f"Password reset successful for: {email}")
    return jsonify({"message": "Password has been reset successfully. Please log in."})

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy", "timestamp": datetime.utcnow().isoformat()})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get('PORT', 10000)))
