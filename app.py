# app.py (Final Version - Reads directly from environment variables)

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
import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException

# --- Logging Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Directly load variables from the environment ---
# This is a more robust method than using a separate config file.
SUPABASE_URL = os.environ.get('SUPABASE_URL')
SUPABASE_KEY = os.environ.get('SUPABASE_KEY') # This is the public 'anon' key
SUPABASE_SERVICE_KEY = os.environ.get('SUPABASE_SERVICE_KEY') # The secret 'service_role' key
BREVO_API_KEY = os.environ.get('BREVO_API_KEY')
SENDER_EMAIL = os.environ.get('SENDER_EMAIL')

# --- Essential Startup Checks ---
# The application will refuse to start if any secret key is missing.
missing_vars = [
    var for var in 
    ['SUPABASE_URL', 'SUPABASE_KEY', 'SUPABASE_SERVICE_KEY', 'BREVO_API_KEY', 'SENDER_EMAIL'] 
    if not os.environ.get(var)
]
if missing_vars:
    raise ValueError(f"CRITICAL ERROR: The following environment variables are missing: {', '.join(missing_vars)}. The application cannot start.")

# --- App Initialization ---
app = Flask(__name__, static_folder='.', static_url_path='')
CORS(app, origins=['*'])
limiter = Limiter(key_func=get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

# --- Supabase Client Class (no changes needed here) ---
class SupabaseClient:
    def __init__(self, url, key):
        if not url or not key:
            raise ValueError("Supabase URL and Key cannot be empty.")
        self.url = url
        self.key = key
        self.headers = {'apikey': self.key, 'Authorization': f'Bearer {self.key}', 'Content-Type': 'application/json'}

    def _make_request(self, method, endpoint, **kwargs):
        try:
            response = requests.request(method, f"{self.url}/rest/v1/{endpoint}", headers=kwargs.pop('headers', self.headers), timeout=15, **kwargs)
            response.raise_for_status()
            return response.json() if response.content else {"status": "success"}, None
        except requests.exceptions.HTTPError as e:
            error_message = str(e); 
            try: error_message = e.response.json().get('message', str(e))
            except (ValueError, AttributeError): pass
            logger.error(f"HTTP Error {e.response.status_code}: {error_message} for URL: {e.request.url}")
            return None, error_message
        except Exception as e:
            logger.error(f"Request exception: {e}"); return None, "A network error occurred."

    def select(self, t, f=None, s=False): h=self.headers.copy(); p={f"{k}":f"eq.{v}" for k,v in f.items()} if f else{}; S='application/vnd.pgrst.object+json'; h['Accept']=S if s else h.get('Accept'); return self._make_request('GET',t,params=p,headers=h)
    def insert(self, t, d): h=self.headers.copy(); h['Prefer']='return=minimal'; return self._make_request('POST',t,json=d,headers=h)
    def update(self, t, f, d): return self._make_request('PATCH', f"{t}?{'&'.join([f'{k}=eq.{v}'for k,v in f.items()])}", json=d)
    def delete(self, t, f): return self._make_request('DELETE', f"{t}?{'&'.join([f'{k}=eq.{v}'for k,v in f.items()])}")

# --- Initialize TWO clients ---
# 1. A public client using the safe 'anon' key for most operations.
supabase = SupabaseClient(SUPABASE_URL, SUPABASE_KEY)
# 2. A powerful admin client using the secret 'service_role' key ONLY for protected actions.
supabase_admin = SupabaseClient(SUPABASE_URL, SUPABASE_SERVICE_KEY)


# --- Helper Functions ---
def hash_password(password): return hashlib.sha256(password.encode()).hexdigest()

def send_email_async(to_email, subject, body):
    def send():
        configuration = sib_api_v3_sdk.Configuration(); configuration.api_key['api-key'] = BREVO_API_KEY
        api_instance = sib_api_v3_sdk.TransactionalEmailsApi(sib_api_v3_sdk.ApiClient(configuration))
        sender = {"name": "WhatsApp Pro", "email": SENDER_EMAIL}
        to = [{"email": to_email}]; send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(to=to, sender=sender, subject=subject, html_content=body)
        try: api_instance.send_transac_email(send_smtp_email); logger.info(f"✅ Email queued for {to_email}")
        except ApiException as e: logger.error(f"❌ FAILED TO SEND EMAIL: {e.body}")
    threading.Thread(target=send, daemon=True).start()

# --- API Routes ---
@app.route('/')
def serve_frontend(): return send_from_directory('.', 'index.html')
@app.route('/<path:path>')
def serve_static(path): return send_from_directory('.', path)

@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    data = request.get_json(); email, password = data.get('email'), data.get('password')
    if not email or not password: return jsonify({"error": "Email and password required."}), 400
    u, err = supabase.select('users', {'email': email})
    if err: logger.error(f"Register DB error: {err}"); return jsonify({"error": "DB error: Registration unavailable."}), 500
    if u: return jsonify({"error": "Email already registered."}), 409
    _,err = supabase_admin.insert('users',{'email':email,'password_hash':hash_password(p),'secret_key':secrets.token_hex(16)}) # Use admin to insert to bypass RLS
    if err: logger.error(f"Register insert error: {err}"); return jsonify({"error": "Registration failed. Try again."}), 500
    logger.info(f"✅ New user registered: {email}"); return jsonify({"message":"Registration successful. You can now log in."}), 201

@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    data = request.get_json(); email, password = data.get('email'), data.get('password')
    if not email or not password: return jsonify({"error": "Email and password required."}), 400
    user, err = supabase.select('users', {'email': email}, single=True)
    if err: logger.error(f"Login DB error: {err}"); return jsonify({"error":"DB error: Login unavailable."}), 500
    if not user: return jsonify({"error": "Please register first."}), 401
    if user.get('password_hash') != hash_password(password): return jsonify({"error": "Invalid password."}), 401
    ll = user.get('last_login_at')
    # Use admin to ensure last_login can be updated
    threading.Thread(target=lambda: supabase_admin.update('users',{'email':email},{'last_login_at':datetime.utcnow().isoformat()})).start()
    logger.info(f"✅ User logged in: {email}"); return jsonify({'secret_key':user.get('secret_key'),'spreadsheet_url':user.get('spreadsheet_url','')})

@app.route('/save_spreadsheet', methods=['POST'])
@limiter.limit("20 per hour")
def save_spreadsheet():
    d=request.get_json(); sk, su = d.get('secret_key'), d.get('spreadsheet_url')
    if not sk or not su: return jsonify({"error":"Secret key and URL required."}), 400
    # Use admin to ensure URL can be updated against any RLS policies
    _,err=supabase_admin.update('users',{'secret_key':sk},{'spreadsheet_url':su})
    if err: logger.error(f"Save spreadsheet error: {err}"); return jsonify({"error":"Failed to save URL."}), 500
    logger.info(f"✅ Spreadsheet URL saved for key: {sk[:8]}..."); return jsonify({"message":"Spreadsheet URL saved successfully."})

@app.route('/forgot_password', methods=['POST'])
@limiter.limit("3 per minute")
def forgot_password():
    e=request.get_json().get('email')
    if not e: return jsonify({"error":"Email is required"}), 400
    u, _ = supabase.select('users',{'email':e},s=True)
    if u: # Only if user exists, proceed
        rc=str(random.randint(100000,999999)); ex=datetime.utcnow()+timedelta(minutes=15)
        # Use admin client to ensure we can create/delete reset tokens
        supabase_admin.delete('password_resets',{'email':e})
        _,err=supabase_admin.insert('password_resets',{'email':e,'token':rc,'expires_at':ex.isoformat()})
        if err: logger.error(f"Forgot DB error: {err}")
        else: send_email_async(e, "Your Password Reset Code", f"Your reset code is: <h2>{rc}</h2><p>This code expires in 15 minutes.</p>")
    logger.info(f"Password reset initiated for: {e} (If user exists)")
    return jsonify({"message":"If an account exists, a reset code has been sent."})

@app.route('/reset_password', methods=['POST'])
@limiter.limit("5 per minute")
def reset_password():
    d=request.get_json(); e, c, np = d.get('email'), d.get('code'), d.get('new_password')
    if not all([e, c, np]): return jsonify({"error":"Valid email, 6-digit code, and new password required."}), 400
    
    # Verify the code using the public client, as this is a safe 'read' operation
    r, err = supabase.select('password_resets', {'email': e, 'token': c}, single=True)
    if err or not r: return jsonify({"error": "Invalid or expired reset code."}), 400

    ex = datetime.fromisoformat(r['expires_at'].replace('Z','+00:00'))
    if ex < datetime.now(timezone.utc): 
        supabase_admin.delete('password_resets', {'id': r['id']}) # Cleanup with admin
        return jsonify({"error": "Code expired."}), 400
    
    # *** THIS IS THE CRITICAL FIX ***
    # Use the powerful `supabase_admin` client to perform the password update.
    # This will bypass the RLS policy that was blocking the update.
    _, err = supabase_admin.update('users', {'email': e}, {'password_hash': hash_password(np)})
    if err: 
        logger.error(f"Reset update error: {err}"); return jsonify({"error":"Failed to update password."}), 500
    
    # Use the admin client to clean up the used token.
    supabase_admin.delete('password_resets', {'email': e})
    
    logger.info(f"✅ Password reset for: {e}"); return jsonify({"message":"Password has been reset successfully."})

@app.route('/health', methods=['GET'])
def health_check(): return jsonify({"status":"healthy"})

if __name__ == "__main__": app.run(host="0.0.0.0",port=int(os.environ.get('PORT',10000)))
