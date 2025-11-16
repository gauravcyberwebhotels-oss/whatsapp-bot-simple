# app.py (Final Version with Brevo)
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
import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='.', static_url_path='')
app.config.from_object(Config)
CORS(app, origins=['*'])
limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])

class SupabaseClient:
    def __init__(self, url, key): self.url, self.key, self.headers = url, key, {'apikey': key, 'Authorization': f'Bearer {key}', 'Content-Type': 'application/json'}
    def _make_request(self, method, endpoint, **kwargs):
        try:
            r = requests.request(method, f"{self.url}/rest/v1/{endpoint}", headers=kwargs.pop('headers', self.headers), timeout=30, **kwargs)
            r.raise_for_status()
            if r.status_code == 204: return {"status": "success"}, None
            return r.json() if r.content else {"status": "success"}, None
        except requests.exceptions.HTTPError as e:
            msg = e.response.json().get('message', str(e)) if e.response.content else str(e)
            logger.error(f"HTTP Error {e.response.status_code}: {msg}"); return None, msg
        except Exception as e: logger.error(f"Request exception: {e}"); return None, str(e)
    def select(self, t, f=None, s=False): h=self.headers.copy(); p={f"{k}":f"eq.{v}" for k,v in f.items()} if f else{}; S='application/vnd.pgrst.object+json'; h['Accept']=S if s else h.get('Accept'); return self._make_request('GET', t, params=p, headers=h)
    def insert(self, t, d): return self._make_request('POST', t, json=d, headers={'Prefer': 'return=minimal'})
    def update(self, t, f, d): return self._make_request('PATCH', f"{t}?{'&'.join([f'{k}=eq.{v}'for k,v in f.items()])}", json=d)
    def delete(self, t, f): return self._make_request('DELETE', f"{t}?{'&'.join([f'{k}=eq.{v}'for k,v in f.items()])}")

supabase = SupabaseClient(Config.SUPABASE_URL, Config.SUPABASE_KEY)
def hash_password(password): return hashlib.sha256(password.encode()).hexdigest()

def send_email_async(to_email, subject, body):
    """Sends email using the Brevo (Sendinblue) API."""
    def send():
        BREVO_API_KEY = os.environ.get('BREVO_API_KEY')
        SENDER_EMAIL = os.environ.get('SENDER_EMAIL')
        if not BREVO_API_KEY or not SENDER_EMAIL:
            logger.error("❌ BREVO_API_KEY or SENDER_EMAIL is not set.")
            return

        configuration = sib_api_v3_sdk.Configuration(); configuration.api_key['api-key'] = BREVO_API_KEY
        api_instance = sib_api_v3_sdk.TransactionalEmailsApi(sib_api_v3_sdk.ApiClient(configuration))
        send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(to=[{"email": to_email}], sender={"name": "WhatsApp Pro", "email": SENDER_EMAIL}, subject=subject, html_content=body)
        try:
            api_instance.send_transac_email(send_smtp_email)
            logger.info(f"✅ Email sent to {to_email} via Brevo.")
        except ApiException as e:
            logger.error(f"❌ FAILED TO SEND EMAIL via Brevo. Exception: {e}\n")
    threading.Thread(target=send, daemon=True).start()

@app.route('/')
def serve_frontend(): return send_from_directory('.', 'index.html')
@app.route('/<path:path>')
def serve_static(path): return send_from_directory('.', path)
@app.route('/register', methods=['POST'])
def register():
    d=request.get_json(); e,p=d.get('email'),d.get('password')
    u,err=supabase.select('users',f={'email':e},s=True)
    if err and 'Not a valid header' not in err: return jsonify({"error":"DB error"}),500
    if u: return jsonify({"error":"Email already registered."}),400
    _,err=supabase.insert('users',{'email':e,'password_hash':hash_password(p),'secret_key':secrets.token_hex(16)})
    if err: return jsonify({"error":"Registration failed."}),500
    return jsonify({"message":"Registration successful. You can now log in."}),201

@app.route('/login', methods=['POST'])
def login():
    d=request.get_json(); e,p=d.get('email'),d.get('password')
    u,err=supabase.select('users',f={'email':e},s=True)
    if err and 'Not a valid header' not in err: return jsonify({"error":"DB error"}),500
    if not u or u.get('password_hash')!=hash_password(p): return jsonify({"error":"Invalid email or password."}),401
    ll=u.get('last_login_at'); supabase.update('users',{'email':e},{'last_login_at':datetime.utcnow().isoformat()})
    return jsonify({'secret_key':u.get('secret_key'),'credits':u.get('credits',100),'spreadsheet_url':u.get('spreadsheet_url',''),'last_login_at':ll})

@app.route('/save_spreadsheet', methods=['POST'])
def save_spreadsheet():
    d=request.get_json(); sk,su=d.get('secret_key'),d.get('spreadsheet_url')
    _,err=supabase.update('users',{'secret_key':sk},{'spreadsheet_url':su});
    if err: return jsonify({"error":"Failed to save URL."}),500
    return jsonify({"message":"Spreadsheet URL saved successfully."})

@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    e=request.get_json().get('email');
    if not e: return jsonify({"error":"Email is required"}),400
    u, _ = supabase.select('users',f={'email':e},s=True)
    if not u: return jsonify({"message":"If an account exists, a reset code has been sent."})
    rc=str(random.randint(100000,999999)); ex=datetime.utcnow()+timedelta(hours=1)
    supabase.delete('password_resets',{'email':e})
    _,err=supabase.insert('password_resets',{'email':e,'token':rc,'expires_at':ex.isoformat()})
    if err: return jsonify({"error":"Failed to store reset code."}),500
    send_email_async(e, "Your Password Reset Code", f"Your reset code is: <h2>{rc}</h2>")
    return jsonify({"message":"If an account exists, a reset code has been sent."})

@app.route('/reset_password', methods=['POST'])
def reset_password():
    d=request.get_json(); e,c,np=d.get('email'),d.get('code'),d.get('new_password')
    r,err=supabase.select('password_resets',f={'email':e,'token':c})
    if err or not r: return jsonify({"error":"Invalid or expired reset code."}),400
    rr=r[0]; ex=datetime.fromisoformat(rr['expires_at'].replace('Z','+00:00'))
    if ex < datetime.utcnow(): supabase.delete('password_resets',{'id':rr['id']}); return jsonify({"error":"Code expired."}),400
    _,err=supabase.update('users',{'email':e},{'password_hash':hash_password(np)});
    if err: return jsonify({"error":"Failed to update password."}),500
    supabase.delete('password_resets',{'email':e})
    return jsonify({"message":"Password has been reset successfully."})

@app.route('/health', methods=['GET'])
def health_check(): return jsonify({"status":"healthy"})

if __name__ == "__main__": app.run(host="0.0.0.0",port=int(os.environ.get('PORT',10000)),debug=False)
