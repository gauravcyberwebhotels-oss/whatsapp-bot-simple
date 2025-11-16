# app.py (FULLY FIXED - ROUTING ORDER + DB ERROR HANDLING)
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
                method, url, headers=self.headers, timeout=30, **kwargs
            )
           
            logger.info(f"Response status: {response.status_code}")
           
            if response.status_code == 204:
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

    def select(self, table, filters=None, single=False, limit=None):
        try:
            params = {}
            if filters:
                params = {f"{k}": f"eq.{v}" for k, v in filters.items()}
            if limit:
                params['limit'] = limit
           
            headers = self.headers.copy()
            if single:
                headers['Accept'] = 'application/vnd.pgrst.object+json'
           
            url = f"{self.url}/rest/v1/{table}"
            logger.info(f"SELECT from {table} with params: {params}")
           
            response = requests.get(url, headers=headers, params=params, timeout=30)
           
            logger.info(f"SELECT response status: {response.status_code}")
           
            if response.status_code == 404:
                logger.warning(f"Table {table} not found or empty - setup issue")
                return [], None
               
            response.raise_for_status()
           
            if response.status_code == 200:
                data = response.json()
                if single and data:
                    return data[0] if isinstance(data, list) else data, None
                return data, None
            else:
                return [], None
               
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                logger.warning(f"Table {table} not found or empty - setup issue")
                return [], None
            error_msg = f"Select failed: {e.response.status_code} - {e.response.text[:200]}"
            logger.error(error_msg)
            return None, error_msg
           
        except Exception as e:
            logger.error(f"Select exception: {str(e)}")
            return None, str(e)

    def insert(self, table, data):
        logger.info(f"INSERT into {table}: {{{', '.join([f'{k}: ***' if 'password' in k.lower() or 'token' in k.lower() else f'{k}: {v}' for k, v in data.items()])}}}")
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

def send_email_async(to_email, subject, body):
    def send():
        try:
            msg = MIMEMultipart()
            msg['Subject'] = subject
            msg['From'] = Config.EMAIL_ADDRESS
            msg['To'] = to_email
            msg.attach(MIMEText(body, 'html'))
           
            logger.info(f"🔧 Sending email to {to_email}")
            server = smtplib.SMTP(Config.SMTP_SERVER, Config.SMTP_PORT, timeout=30)
            server.set_debuglevel(1)
            server.ehlo()
            if server.has_extn('STARTTLS'):
                server.starttls()
                server.ehlo()
                logger.info("✅ TLS established")
            server.login(Config.EMAIL_ADDRESS, Config.EMAIL_PASSWORD)
            logger.info("✅ SMTP login successful")
            server.send_message(msg)
            server.quit()
            logger.info(f"✅ Email sent to {to_email}")
            return True
        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"❌ SMTP Auth Failed: {str(e)} - Check App Password & 2FA")
            return False
        except Exception as e:
            logger.error(f"❌ Email failed: {str(e)}")
            return False
   
    thread = threading.Thread(target=send)
    thread.daemon = True
    thread.start()
    return True

# API ROUTES FIRST
@app.route('/')
def serve_frontend():
    return send_from_directory('.', 'index.html')

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy", "timestamp": datetime.utcnow().isoformat()})

@app.route('/check_tables', methods=['GET'])
def check_tables():
    try:
        users, users_error = supabase.select('users', limit=1)
        password_resets, pr_error = supabase.select('password_resets', limit=1)
       
        return jsonify({
            "users_table_exists": users_error is None,
            "password_resets_table_exists": pr_error is None,
            "users_error": users_error,
            "password_resets_error": pr_error
        })
    except Exception as e:
        logger.error(f"Check tables error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided."}), 400
           
        email = data.get('email')
        password = data.get('password')
       
        if not all([email, password]):
            return jsonify({"error": "Email and password required."}), 400
       
        if len(password) < 8:
            return jsonify({"error": "Password must be at least 8 characters."}), 400
       
        existing_user, error = supabase.select('users', filters={'email': email}, single=True)
        if error:
            logger.error(f"Reg check error: {error}")
            if "404" in str(error).lower() or "not found" in str(error).lower():
                return jsonify({"error": "Database tables not set up. Create 'users' in Supabase."}), 500
            return jsonify({"error": "Database error during registration. Check logs."}), 500
           
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
            logger.error(f"Reg insert error: {error}")
            if "404" in str(error).lower() or "not found" in str(error).lower():
                return jsonify({"error": "Database tables not set up. Create 'users' in Supabase."}), 500
            return jsonify({"error": "Database error during registration. Check logs."}), 500
       
        logger.info(f"New user: {email}")
        return jsonify({"message": "Registration successful. You can now log in."}), 201
    except Exception as e:
        logger.error(f"Reg exception: {str(e)}")
        return jsonify({"error": "Internal server error."}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided."}), 400
           
        email = data.get('email')
        password = data.get('password')
       
        if not all([email, password]):
            return jsonify({"error": "Email and password required."}), 400
       
        user_data, error = supabase.select('users', filters={'email': email}, single=True)
       
        if error:
            logger.error(f"Login DB error: {error}")
            if "404" in str(error).lower() or "not found" in str(error).lower():
                return jsonify({"error": "Database not initialized. Contact support."}), 500
            return jsonify({"error": "Database error."}), 500
           
        if not user_data:
            return jsonify({"error": "Invalid email or password."}), 401
       
        if user_data.get('password_hash') != hash_password(password):
            return jsonify({"error": "Invalid email or password."}), 401
       
        logger.info(f"Login: {email}")
        return jsonify({
            'secret_key': user_data.get('secret_key'),
            'credits': user_data.get('credits', 100),
            'spreadsheet_url': user_data.get('spreadsheet_url', '')
        })
    except Exception as e:
        logger.error(f"Login exception: {str(e)}")
        return jsonify({"error": "Internal server error."}), 500

@app.route('/save_spreadsheet', methods=['POST'])
def save_spreadsheet():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided."}), 400
           
        secret_key = data.get('secret_key')
        spreadsheet_url = data.get('spreadsheet_url')
       
        if not secret_key:
            return jsonify({"error": "Authentication required."}), 401
       
        if not spreadsheet_url:
            return jsonify({"error": "Spreadsheet URL required."}), 400
       
        user_data, error = supabase.select('users', filters={'secret_key': secret_key}, single=True)
        if error:
            logger.error(f"Spreadsheet DB error: {error}")
            if "404" in str(error).lower() or "not found" in str(error).lower():
                return jsonify({"error": "Database not initialized."}), 500
            return jsonify({"error": "Database error."}), 500
           
        if not user_data:
            return jsonify({"error": "Invalid authentication."}), 401
       
        result, error = supabase.update('users', {'secret_key': secret_key}, {'spreadsheet_url': spreadsheet_url})
        if error:
            logger.error(f"Spreadsheet update error: {error}")
            return jsonify({"error": "Failed to save. Check logs."}), 500
       
        logger.info(f"Spreadsheet saved for {user_data.get('email')}")
        return jsonify({"message": "Spreadsheet URL saved."})
    except Exception as e:
        logger.error(f"Spreadsheet exception: {str(e)}")
        return jsonify({"error": "Internal server error."}), 500

@app.route('/forgot_password', methods=['POST'])
@limiter.limit("3 per hour")
def forgot_password():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided."}), 400
           
        email = data.get('email')
        if not email:
            return jsonify({"error": "Email required."}), 400
       
        logger.info(f"Reset requested for: {email}")
       
        user, error = supabase.select('users', filters={'email': email}, single=True)
        if error:
            if "404" in str(error).lower() or "not found" in str(error).lower():
                return jsonify({"error": "Database not initialized."}), 500
            return jsonify({"error": "Database error."}), 500
           
        if not user:
            return jsonify({"message": "If account exists, reset code sent."})
       
        reset_code = str(random.randint(100000, 999999))
        expires_at = datetime.utcnow() + timedelta(hours=1)
       
        email_body = f"""
        <html><body style="font-family: Arial; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px;">
                <h2 style="color: #667eea; text-align: center;">Password Reset Code</h2>
                <p>Hello,</p><p>You requested a password reset.</p>
                <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; text-align: center; margin: 20px 0;">
                    <h3 style="margin: 0; color: #667eea; font-size: 24px; letter-spacing: 2px;">{reset_code}</h3>
                </div>
                <p>Enter this code to reset. Expires in 1 hour.</p><p>If not you, ignore.</p>
                <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
                <p style="font-size: 12px; color: #666;">Automated from WhatsApp Messenger Pro.</p>
            </div>
        </body></html>
        """
       
        supabase.delete('password_resets', {'email': email})
       
        reset_data = {
            'email': email,
            'token': reset_code,
            'expires_at': expires_at.isoformat(),
            'created_at': datetime.utcnow().isoformat()
        }
       
        result, error = supabase.insert('password_resets', reset_data)
        if error:
            logger.error(f"Reset insert error: {error}")
            if "404" in str(error).lower() or "not found" in str(error).lower():
                return jsonify({"error": "Database not initialized."}), 500
            return jsonify({"error": "Failed to store code."}), 500
       
        email_sent = send_email_async(email, "Password Reset Code - WhatsApp Messenger Pro", email_body)
        logger.info(f"Reset code {reset_code} for {email} - sent: {email_sent}")
       
        return jsonify({"message": "If account exists, reset code sent.", "email_sent": email_sent})
    except Exception as e:
        logger.error(f"Forgot exception: {str(e)}")
        return jsonify({"error": "Internal server error."}), 500

@app.route('/reset_password', methods=['POST'])
def reset_password():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided."}), 400
           
        email = data.get('email')
        code = data.get('code')
        new_password = data.get('new_password')
       
        if not all([email, code, new_password]):
            return jsonify({"error": "All fields required."}), 400
       
        if len(new_password) < 8:
            return jsonify({"error": "Password must be 8+ characters."}), 400
       
        resets, error = supabase.select('password_resets', filters={'email': email, 'token': code})
        if error:
            logger.error(f"Reset DB error: {error}")
            if "404" in str(error).lower() or "not found" in str(error).lower():
                return jsonify({"error": "Database not initialized."}), 500
            return jsonify({"error": "Database error."}), 500
           
        if not resets:
            return jsonify({"error": "Invalid/expired code."}), 400
       
        reset_record = resets[0]
        expires_at_str = reset_record['expires_at'].replace('Z', '+00:00')
        expires_at = datetime.fromisoformat(expires_at_str)
       
        if expires_at < datetime.utcnow():
            supabase.delete('password_resets', {'id': reset_record['id']})
            return jsonify({"error": "Code expired. Request new."}), 400
       
        new_hash = hash_password(new_password)
        result, error = supabase.update('users', {'email': email}, {'password_hash': new_hash})
        if error:
            logger.error(f"Reset update error: {error}")
            return jsonify({"error": "Failed to update password."}), 500
       
        supabase.delete('password_resets', {'id': reset_record['id']})
        supabase.delete('password_resets', {'email': email})
       
        logger.info(f"Reset successful for {email}")
        return jsonify({"message": "Password reset. Log in with new password."})
    except Exception as e:
        logger.error(f"Reset exception: {str(e)}")
        return jsonify({"error": "Internal server error."}), 500

@app.route('/test_email', methods=['POST'])
def test_email():
    try:
        data = request.get_json()
        test_email = data.get('email', Config.EMAIL_ADDRESS)
       
        test_body = "<html><body><h2>Test Email</h2><p>SMTP config working!</p></body></html>"
       
        email_sent = send_email_async(test_email, "Test - WhatsApp Messenger Pro", test_body)
       
        return jsonify({
            "message": "Test email sent. Check inbox/logs.",
            "email_sent": email_sent,
            "to_email": test_email
        })
    except Exception as e:
        logger.error(f"Test email error: {str(e)}")
        return jsonify({"error": str(e)}), 500

# STATIC CATCH-ALL LAST
@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('.', path)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get('PORT', 10000)), debug=Config.DEBUG)
