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
import threading
import ssl # Add this import at the top of your file
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
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
        self.headers = {
            'apikey': self.key, 
            'Authorization': f'Bearer {self.key}', 
            'Content-Type': 'application/json',
            'Prefer': 'return=minimal'
        }

    def _make_request(self, method, endpoint, **kwargs):
        try:
            url = f"{self.url}/rest/v1/{endpoint}"
            logger.info(f"Making {method} request to: {url}")
            
            response = requests.request(
                method, 
                url, 
                headers=self.headers, 
                timeout=30, 
                **kwargs
            )
            
            logger.info(f"Response status: {response.status_code}")
            
            if response.status_code == 204:  # No content
                return {"status": "success"}, None
                
            response.raise_for_status()
            
            if response.content:
                return response.json(), None
            else:
                return {"status": "success"}, None
                
        except requests.exceptions.HTTPError as e:
            error_msg = "Request failed"
            try:
                if e.response.content:
                    error_data = e.response.json()
                    error_msg = error_data.get('message', error_data.get('error', str(e)))
            except:
                error_msg = str(e)
            logger.error(f"HTTP Error {e.response.status_code}: {error_msg}")
            return None, error_msg
            
        except Exception as e:
            logger.error(f"Request exception: {str(e)}")
            return None, str(e)

    def select(self, table, filters=None, single=False):
        try:
            params = {}
            if filters:
                params = {f"{k}": f"eq.{v}" for k, v in filters.items()}
            
            headers = self.headers.copy()
            if single:
                headers['Accept'] = 'application/vnd.pgrst.object+json'
            
            url = f"{self.url}/rest/v1/{table}"
            logger.info(f"SELECT from {table} with params: {params}")
            
            response = requests.get(
                url, 
                headers=headers, 
                params=params, 
                timeout=30
            )
            
            logger.info(f"SELECT response status: {response.status_code}")
            
            response.raise_for_status()
            
            if response.status_code == 200:
                data = response.json()
                if single and isinstance(data, list) and data:
                    return data[0], None
                return data, None
            else:
                return [], None
                
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404 or (e.response.status_code == 406 and single): # 406 for "Not Acceptable" when single returns no rows
                logger.warning(f"No results for select from {table} with filters {filters}")
                return None, None
            error_msg = f"Select failed: {e.response.status_code}"
            logger.error(error_msg)
            return None, error_msg
            
        except Exception as e:
            logger.error(f"Select exception: {str(e)}")
            return None, str(e)


    def insert(self, table, data):
        logger.info(f"INSERT into {table}: { {k: '***' if 'password' in k.lower() or 'token' in k.lower() else v for k, v in data.items()} }")
        return self._make_request('POST', table, json=data)
    
    def update(self, table, filters, data):
        filter_str = '&'.join([f'{k}=eq.{v}' for k,v in filters.items()])
        logger.info(f"UPDATE {table} WHERE {filter_str}: {data}")
        return self._make_request('PATCH', f"{table}?{filter_str}", json=data)
    
    def delete(self, table, filters):
        filter_str = '&'.join([f'{k}=eq.{v}' for k,v in filters.items()])
        logger.info(f"DELETE from {table} WHERE {filter_str}")
        return self._make_request('DELETE', f"{table}?{filter_str}")

supabase = SupabaseClient(Config.SUPABASE_URL, Config.SUPABASE_KEY)
logger.info("✅ Supabase client initialized.")

def hash_password(password): 
    return hashlib.sha256(password.encode()).hexdigest()

# In app.py


def send_email_async(to_email, subject, body):
    """Send email in a separate thread using Port 465 (SMTPS)."""
    def send():
        try:
            msg = MIMEMultipart()
            msg['Subject'] = subject
            msg['From'] = Config.EMAIL_ADDRESS
            msg['To'] = to_email
            msg.attach(MIMEText(body, 'html'))
            
            logger.info(f"🔧 Attempting to send email via SMTPS on Port 465")
            
            # Use a secure SSL context
            context = ssl.create_default_context()

            # Use smtplib.SMTP_SSL for port 465
            with smtplib.SMTP_SSL(Config.SMTP_SERVER, Config.SMTP_PORT, context=context, timeout=30) as server:
                server.login(Config.EMAIL_ADDRESS, Config.EMAIL_PASSWORD)
                logger.info("✅ SMTP_SSL login successful")
                server.send_message(msg)
                logger.info(f"✅ Email sent successfully to {to_email}")
            return True
            
        except Exception as e:
            logger.error(f"❌ FAILED TO SEND EMAIL (Port 465). Error: {str(e)}")
            return False

    thread = threading.Thread(target=send)
    thread.daemon = True
    thread.start()
    return True

@app.route('/')
def serve_frontend(): 
    return send_from_directory('.', 'index.html')

@app.route('/<path:path>')
def serve_static(path): 
    return send_from_directory('.', path)

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        if not all([email, password]):
            return jsonify({"error": "Email and password are required."}), 400
        
        existing_user, error = supabase.select('users', filters={'email': email}, single=True)
        if error:
            return jsonify({"error": "Database error during registration."}), 500
        if existing_user:
            return jsonify({"error": "Email already registered."}), 400
        
        user_data = {
            'email': email, 
            'password_hash': hash_password(password), 
            'secret_key': secrets.token_hex(16),
            'credits': 100,
            'created_at': datetime.utcnow().isoformat()
        }
        
        result, error = supabase.insert('users', user_data)
        if error:
            return jsonify({"error": "Database error during registration."}), 500
        
        return jsonify({"message": "Registration successful. You can now log in."}), 201
    except Exception as e:
        logger.error(f"Registration exception: {str(e)}")
        return jsonify({"error": "Internal server error."}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        if not all([email, password]):
            return jsonify({"error": "Email and password are required."}), 400

        user_data, error = supabase.select('users', filters={'email': email}, single=True)
        if error:
            logger.error(f"Login database error: {error}")
            return jsonify({"error": "Database error."}), 500
        if not user_data:
            return jsonify({"error": "Invalid email or password."}), 401
        if user_data.get('password_hash') != hash_password(password):
            return jsonify({"error": "Invalid email or password."}), 401

        # --- LAST LOGIN LOGIC START ---
        # Get the previous last login time before we update it.
        previous_last_login = user_data.get('last_login_at')
        
        # Now, update the last_login_at to the current time.
        current_time = datetime.utcnow().isoformat()
        supabase.update('users', {'email': email}, {'last_login_at': current_time})
        logger.info(f"User logged in: {email}. Last login updated.")
        # --- LAST LOGIN LOGIC END ---
        
        return jsonify({
            'secret_key': user_data.get('secret_key'),
            'credits': user_data.get('credits', 100),
            'spreadsheet_url': user_data.get('spreadsheet_url', ''),
            'last_login_at': previous_last_login # Send the previous login time
        })
    except Exception as e:
        logger.error(f"Login exception: {str(e)}")
        return jsonify({"error": "Internal server error."}), 500

@app.route('/save_spreadsheet', methods=['POST'])
def save_spreadsheet():
    try:
        data = request.get_json()
        secret_key = data.get('secret_key')
        spreadsheet_url = data.get('spreadsheet_url')
        
        if not secret_key:
            return jsonify({"error": "Authentication required."}), 401
        
        result, error = supabase.update('users', {'secret_key': secret_key}, {'spreadsheet_url': spreadsheet_url})
        if error:
            return jsonify({"error": "Failed to save spreadsheet URL."}), 500
        
        return jsonify({"message": "Spreadsheet URL saved successfully."})
    except Exception as e:
        logger.error(f"Save spreadsheet exception: {str(e)}")
        return jsonify({"error": "Internal server error."}), 500

@app.route('/forgot_password', methods=['POST'])
@limiter.limit("3 per hour")
def forgot_password():
    try:
        email = request.get_json().get('email')
        if not email:
            return jsonify({"error": "Email is required."}), 400
            
        user, error = supabase.select('users', filters={'email': email}, single=True)
        if not user:
            logger.info(f"Password reset for non-existent user: {email}")
            return jsonify({"message": "If an account with that email exists, a reset code has been sent."})

        reset_code = str(random.randint(100000, 999999))
        expires_at = datetime.utcnow() + timedelta(hours=1)
        email_body = f"Your password reset code is: <h1>{reset_code}</h1>. It will expire in one hour."
        
        supabase.delete('password_resets', {'email': email})
        reset_data = {
            'email': email, 
            'token': reset_code, 
            'expires_at': expires_at.isoformat(),
            'created_at': datetime.utcnow().isoformat()
        }
        
        _, error = supabase.insert('password_resets', reset_data)
        if error:
            return jsonify({"error": "Failed to store reset code."}), 500
            
        send_email_async(email, "Your Password Reset Code", email_body)
        return jsonify({"message": "If an account exists, a reset code has been sent to your email."})
    except Exception as e:
        logger.error(f"Forgot password exception: {str(e)}")
        return jsonify({"error": "Internal server error."}), 500

@app.route('/reset_password', methods=['POST'])
def reset_password():
    try:
        data = request.get_json()
        email = data.get('email')
        code = data.get('code')
        new_password = data.get('new_password')
        
        if not all([email, code, new_password]):
            return jsonify({"error": "All fields are required."}), 400
            
        resets, _ = supabase.select('password_resets', filters={'email': email, 'token': code})
        if not resets:
            return jsonify({"error": "Invalid or expired reset code."}), 400
        
        reset_record = resets[0]
        expires_at = datetime.fromisoformat(reset_record['expires_at'].replace('Z', '+00:00'))

        if expires_at < datetime.utcnow():
            supabase.delete('password_resets', {'id': reset_record['id']})
            return jsonify({"error": "Reset code has expired."}), 400

        _, error = supabase.update('users', {'email': email}, {'password_hash': hash_password(new_password)})
        if error:
            return jsonify({"error": "Failed to update password."}), 500

        supabase.delete('password_resets', {'email': email})
        return jsonify({"message": "Password has been reset successfully."})
    except Exception as e:
        logger.error(f"Reset password exception: {str(e)}")
        return jsonify({"error": "Internal server error."}), 500

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy", "timestamp": datetime.utcnow().isoformat()})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get('PORT', 10000)), debug=Config.DEBUG)
