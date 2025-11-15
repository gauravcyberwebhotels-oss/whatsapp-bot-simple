from flask import Flask, request, jsonify, send_from_directory, render_template_string
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import threading
import time
import os
import subprocess
import json
import random
import requests
import smtplib
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import secrets
import hashlib
import shutil
import re
import atexit
import signal
import psutil
import logging
from logging.handlers import RotatingFileHandler
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from contextlib import contextmanager
from functools import wraps
import jwt
from config import Config
import requests

def save_user_activity_to_supabase(email, activity_type, details=None):
    """Save user activity using direct Supabase API calls"""
    activity_data = {
        'email': email,
        'activity_type': activity_type,
        'details': details or {},
        'timestamp': datetime.now().isoformat(),
        'created_at': datetime.now().isoformat()
    }
    
    headers = {
        'Authorization': f'Bearer {Config.SUPABASE_KEY}',
        'apikey': Config.SUPABASE_KEY,
        'Content-Type': 'application/json'
    }
    
    try:
        response = requests.post(
            f"{Config.SUPABASE_URL}/rest/v1/user_activities",
            headers=headers,
            json=activity_data
        )
        if response.status_code == 201:
            logger.info(f"✅ Activity saved to Supabase for {email}")
            return True
        else:
            logger.error(f"❌ Failed to save activity: {response.status_code}")
            return False
    except Exception as e:
        logger.error(f"❌ Supabase API error: {e}")
        return False

# Enhanced logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler('app.log', maxBytes=10485760, backupCount=5),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='.', static_url_path='')
app.config.from_object(Config)

# Initialize extensions
db = SQLAlchemy(app)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Enhanced CORS configuration
CORS(app, origins=[
    'https://whatsapp-bot-simple.onrender.com',
    'http://localhost:3000',
    'http://localhost:5000',
    'http://localhost:8080',
], supports_credentials=True)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    secret_key = db.Column(db.String(64), nullable=False, unique=True, index=True)
    verified = db.Column(db.Integer, default=0)
    verification_code = db.Column(db.String(6))
    verification_expires = db.Column(db.DateTime)
    spreadsheet_url = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    credits = db.Column(db.Integer, default=100)
    last_login = db.Column(db.DateTime)
    last_activity = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    failed_login_attempts = db.Column(db.Integer, default=0)
    lock_until = db.Column(db.DateTime)

class UserSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    session_id = db.Column(db.String(64), unique=True, nullable=False)
    status = db.Column(db.String(20), default='starting')
    assigned_server = db.Column(db.String(500))
    spreadsheet_url = db.Column(db.String(500))
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    ended_at = db.Column(db.DateTime)
    progress_data = db.Column(db.Text)
    logs = db.Column(db.Text)
    error_message = db.Column(db.Text)

def init_db():
    with app.app_context():
        try:
            db.create_all()
            logger.info("✅ Database initialized successfully")
        except Exception as e:
            logger.error(f"❌ Database initialization failed: {e}")

init_db()

# Session Management
class SessionManager:
    def __init__(self):
        self.sessions = {}
        self.lock = threading.Lock()
        self.start_cleanup_daemon()
    
    def start_cleanup_daemon(self):
        def cleanup_daemon():
            while True:
                try:
                    self.cleanup_expired_sessions()
                    time.sleep(60)
                except Exception as e:
                    logger.error(f"Cleanup daemon error: {e}")
                    time.sleep(30)
        
        threading.Thread(target=cleanup_daemon, daemon=True).start()
    
    def cleanup_expired_sessions(self):
        with self.lock:
            now = datetime.now()
            expired_sessions = []
            for session_id, session in self.sessions.items():
                if session.get('last_activity') and (now - session['last_activity']).total_seconds() > 3600:
                    expired_sessions.append(session_id)
                elif session.get('started_at') and (now - session['started_at']).total_seconds() > 86400:
                    expired_sessions.append(session_id)
            
            for session_id in expired_sessions:
                self.force_stop_session(session_id)
                del self.sessions[session_id]
                logger.info(f"🧹 Cleaned up expired session: {session_id}")
    
    def force_stop_session(self, session_id):
        try:
            session = self.sessions.get(session_id)
            if session and session.get('process'):
                try:
                    session['process'].terminate()
                    time.sleep(2)
                    if session['process'].poll() is None:
                        session['process'].kill()
                except:
                    pass
                
                db_session = UserSession.query.filter_by(session_id=session_id).first()
                if db_session:
                    db_session.status = 'force_stopped'
                    db_session.ended_at = datetime.now()
                    db.session.commit()
        except Exception as e:
            logger.error(f"Error force stopping session {session_id}: {e}")
    
    def add_session(self, session_id, session_data):
        with self.lock:
            session_data['last_activity'] = datetime.now()
            self.sessions[session_id] = session_data
    
    def update_session(self, session_id, updates):
        with self.lock:
            if session_id in self.sessions:
                self.sessions[session_id].update(updates)
                self.sessions[session_id]['last_activity'] = datetime.now()
    
    def get_session(self, session_id):
        with self.lock:
            session = self.sessions.get(session_id)
            if session:
                session['last_activity'] = datetime.now()
            return session
    
    def remove_session(self, session_id):
        with self.lock:
            if session_id in self.sessions:
                del self.sessions[session_id]

session_manager = SessionManager()

# Bot Server Manager
class BotServerManager:
    def __init__(self, servers):
        self.servers = servers
        self.server_status = {server: False for server in servers}
        self.start_health_checks()
    
    def start_health_checks(self):
        def health_check_daemon():
            while True:
                try:
                    self.check_all_servers()
                    time.sleep(30)
                except Exception as e:
                    logger.error(f"Health check daemon error: {e}")
                    time.sleep(60)
        
        threading.Thread(target=health_check_daemon, daemon=True).start()
    
    def check_all_servers(self):
        for server in self.servers:
            try:
                response = requests.get(f"{server}/health", timeout=5)
                self.server_status[server] = response.status_code == 200
            except:
                self.server_status[server] = False
    
    def get_available_server(self):
        available_servers = [server for server, status in self.server_status.items() if status]
        if available_servers:
            return random.choice(available_servers)
        return None
    
    def get_server_stats(self):
        return {
            "total_servers": len(self.servers),
            "online_servers": sum(self.server_status.values()),
            "server_status": self.server_status
        }

bot_server_manager = BotServerManager(Config.BOT_SERVERS)

# Email Manager
class EmailManager:
    def __init__(self, config):
        self.config = config
        self.max_retries = 3
    
    def send_email(self, to_email, subject, body, html=True):
        for attempt in range(self.max_retries):
            try:
                msg = MIMEMultipart()
                msg['From'] = self.config['email']
                msg['To'] = to_email
                msg['Subject'] = subject
                
                if html:
                    msg.attach(MIMEText(body, 'html'))
                else:
                    msg.attach(MIMEText(body, 'plain'))
                
                server = smtplib.SMTP(self.config['smtp_server'], self.config['smtp_port'])
                server.starttls()
                server.login(self.config['email'], self.config['password'])
                server.send_message(msg)
                server.quit()
                
                logger.info(f"✅ Email sent to {to_email}")
                return True
                
            except Exception as e:
                logger.error(f"❌ Email attempt {attempt + 1} failed for {to_email}: {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(2)
        return False

    def send_verification_email(self, email, code):
        subject = "Verify Your WhatsApp Bot Account"
        body = f"""
        <h2>Welcome to WhatsApp Bulk Messenger!</h2>
        <p>Your verification code is: <strong>{code}</strong></p>
        <p>Enter this code in the verification page to activate your account.</p>
        <p><em>This code will expire in 24 hours.</em></p>
        <br>
        <p>Best regards,<br>WhatsApp Bot Team</p>
        """
        return self.send_email(email, subject, body)

    def send_password_reset_email(self, email, code):
        subject = "Reset Your WhatsApp Bot Password"
        body = f"""
        <h2>Password Reset Request</h2>
        <p>Your password reset code is: <strong>{code}</strong></p>
        <p>Enter this code on the password reset page to set a new password.</p>
        <p><em>This code will expire in 1 hour.</em></p>
        <br>
        <p>If you didn't request this reset, please ignore this email.</p>
        <p>Best regards,<br>WhatsApp Bot Team</p>
        """
        return self.send_email(email, subject, body)

EMAIL_CONFIG = {
    'smtp_server': Config.SMTP_SERVER,
    'smtp_port': Config.SMTP_PORT,
    'email': Config.EMAIL_ADDRESS,
    'password': Config.EMAIL_PASSWORD
}

email_manager = EmailManager(EMAIL_CONFIG)

# Utility Functions
def sanitize_input(input_string, max_length=500):
    if not input_string:
        return ""
    sanitized = re.sub(r'[<>&"\'\\]', '', str(input_string))
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
    return sanitized.strip()

def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    return True, "Password is strong"

def generate_secure_token(length=32):
    return secrets.token_hex(length)

# Authentication Decorator
def auth_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            data = request.get_json() or {}
            secret_key = data.get('secret_key')
            
            if not secret_key:
                return jsonify({"error": "Secret key is required"}), 401
            
            if not re.match(r'^sk_[a-f0-9]{32}$', secret_key):
                return jsonify({"error": "Invalid secret key format"}), 401
            
            user = User.query.filter_by(secret_key=secret_key, is_active=True).first()
            if not user:
                return jsonify({"error": "Invalid or inactive account"}), 401
            
            if user.lock_until and user.lock_until > datetime.utcnow():
                return jsonify({"error": "Account temporarily locked. Try again later."}), 423
            
            user.last_activity = datetime.utcnow()
            db.session.commit()
            
            request.user = user
            return f(*args, **kwargs)
            
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return jsonify({"error": "Authentication failed"}), 401
    
    return decorated_function

# Supabase Functions
def save_user_activity_to_supabase(email, activity_type, details=None):
    activity_data = {
        'email': email,
        'activity_type': activity_type,
        'details': details or {},
        'timestamp': datetime.now().isoformat(),
        'created_at': datetime.now().isoformat()
    }
    
    result = supabase_client.insert('user_activities', activity_data)
    
    if result:
        logger.info(f"✅ Activity saved to Supabase for {email}")
        return True
    else:
        logger.error(f"❌ Failed to save activity for {email}")
        return False

def get_user_activities_from_supabase(email):
    result = supabase_client.select('user_activities', {'email': email})
    
    if result and isinstance(result, list):
        sorted_activities = sorted(result, key=lambda x: x.get('timestamp', ''), reverse=True)[:100]
        return sorted_activities
    return []

def get_user_stats_from_supabase(email):
    try:
        activities = get_user_activities_from_supabase(email)
        
        if not activities:
            return {}
        
        activity_counts = {}
        file_uploads = 0
        bot_sessions = 0
        first_seen = None
        last_login = None
        
        for activity in activities:
            activity_type = activity.get('activity_type', '')
            activity_counts[activity_type] = activity_counts.get(activity_type, 0) + 1
            
            if activity_type == 'file_upload':
                file_uploads += 1
            elif activity_type == 'bot_session':
                bot_sessions += 1
            elif activity_type == 'login':
                last_login = activity.get('timestamp')
            
            activity_time = activity.get('timestamp')
            if activity_time:
                if not first_seen or activity_time < first_seen:
                    first_seen = activity_time
        
        return {
            'first_seen': first_seen,
            'last_login': last_login,
            'activity_counts': activity_counts,
            'total_activities': len(activities),
            'files_uploaded': file_uploads,
            'bot_sessions': bot_sessions,
            'status': 'active'
        }
        
    except Exception as e:
        logger.error(f"❌ Error fetching stats from Supabase: {e}")
        return {}

def update_user_activity(email, activity_type, details=None):
    success = save_user_activity_to_supabase(email, activity_type, details)
    
    if not success:
        logger.error(f"⚠️ Failed to save activity to Supabase for {email}")
    
    return success

# Resource Manager
class ResourceManager:
    def __init__(self):
        self.max_concurrent_sessions = 10
        self.session_semaphore = threading.Semaphore(self.max_concurrent_sessions)
    
    def can_start_session(self):
        return self.session_semaphore.acquire(blocking=False)
    
    def release_session(self):
        self.session_semaphore.release()
    
    def get_system_resources(self):
        try:
            memory = psutil.virtual_memory()
            cpu_percent = psutil.cpu_percent(interval=1)
            disk = psutil.disk_usage('/')
            
            return {
                "memory_used_percent": memory.percent,
                "cpu_used_percent": cpu_percent,
                "disk_used_percent": disk.percent,
                "active_sessions": self.max_concurrent_sessions - self.session_semaphore._value,
                "max_sessions": self.max_concurrent_sessions
            }
        except Exception as e:
            logger.error(f"Resource monitoring error: {e}")
            return {}

resource_manager = ResourceManager()

# Keep-alive mechanism
def enhanced_keep_alive():
    while True:
        try:
            resources = resource_manager.get_system_resources()
            logger.info(f"🔄 System status: {resources}")
            time.sleep(300)
        except Exception as e:
            logger.error(f"Keep-alive error: {e}")
            time.sleep(60)

threading.Thread(target=enhanced_keep_alive, daemon=True).start()

# Routes
@app.route('/')
def serve_frontend():
    try:
        return send_from_directory('.', 'index.html')
    except Exception as e:
        logger.error(f"Error serving frontend: {e}")
        return render_template_string('''
            <!DOCTYPE html>
            <html>
            <head><title>WhatsApp Bot</title></head>
            <body>
                <h1>WhatsApp Bulk Messenger</h1>
                <p>System is starting up... Please refresh in a moment.</p>
            </body>
            </html>
        ''')

@app.route('/<path:path>')
def serve_static(path):
    try:
        return send_from_directory('.', path)
    except Exception as e:
        logger.error(f"Error serving static file {path}: {e}")
        return jsonify({"error": "File not found"}), 404

@app.route('/health')
def health():
    try:
        db.session.execute('SELECT 1')
        db_healthy = True
    except:
        db_healthy = False
    
    resources = resource_manager.get_system_resources()
    
    return jsonify({
        "status": "healthy" if db_healthy else "degraded",
        "timestamp": datetime.now().isoformat(),
        "database": "connected" if db_healthy else "disconnected",
        "supabase_connected": supabase_client is not None,
        "system_resources": resources,
        "active_sessions": len(session_manager.sessions),
        "server_stats": bot_server_manager.get_server_stats()
    })

@app.route('/stats')
def get_stats():
    try:
        resources = resource_manager.get_system_resources()
        server_stats = bot_server_manager.get_server_stats()
        
        total_users = User.query.count()
        
        return jsonify({
            "total_users": total_users,
            "active_bots": len(session_manager.sessions),
            "last_updated": datetime.now().isoformat(),
            "system_resources": resources,
            "server_stats": server_stats,
            "supabase_connected": supabase_client is not None
        })
    except Exception as e:
        logger.error(f"Stats endpoint error: {e}")
        return jsonify({"error": "Could not retrieve statistics"}), 500

@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        email = sanitize_input(data.get('email'))
        password = data.get('password')
        
        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400
        
        if not validate_email(email):
            return jsonify({"error": "Invalid email format"}), 400
        
        is_valid_password, password_message = validate_password(password)
        if not is_valid_password:
            return jsonify({"error": password_message}), 400
        
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({"error": "Email already registered"}), 400
        
        secret_key = f"sk_{generate_secure_token(16)}"
        verification_code = f"{random.randint(100000, 999999)}"
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        user = User(
            email=email,
            password_hash=password_hash,
            secret_key=secret_key,
            verification_code=verification_code,
            verification_expires=datetime.utcnow() + timedelta(hours=24)
        )
        db.session.add(user)
        db.session.commit()
        
        update_user_activity(email, "registered", {
            "secret_key": secret_key,
            "verification_code": verification_code
        })
        
        email_sent = email_manager.send_verification_email(email, verification_code)
        
        return jsonify({
            "status": "success",
            "message": "Registration successful. Check your email for verification code.",
            "secret_key": secret_key,
            "email_sent": email_sent
        })
        
    except IntegrityError:
        return jsonify({"error": "Email already registered"}), 400
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return jsonify({"error": "Registration failed. Please try again."}), 500

@app.route('/verify', methods=['POST'])
@limiter.limit("10 per minute")
def verify_email():
    try:
        data = request.get_json()
        email = sanitize_input(data.get('email'))
        code = sanitize_input(data.get('code'))
        
        if not email or not code:
            return jsonify({"error": "Email and verification code are required"}), 400
        
        user = User.query.filter_by(email=email).first()
        
        if not user:
            return jsonify({"error": "Email not found"}), 404
        
        if user.verified:
            return jsonify({"error": "Email already verified"}), 400
        
        if user.verification_expires and user.verification_expires < datetime.utcnow():
            return jsonify({"error": "Verification code expired"}), 400
        
        if user.verification_code == code:
            user.verified = 1
            user.verification_code = None
            user.verification_expires = None
            db.session.commit()
            
            update_user_activity(email, "verified")
            
            return jsonify({
                "status": "success", 
                "message": "Email verified successfully"
            })
        else:
            return jsonify({"error": "Invalid verification code"}), 400
            
    except Exception as e:
        logger.error(f"Verification error: {e}")
        return jsonify({"error": "Verification failed"}), 500

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    try:
        data = request.get_json()
        email = sanitize_input(data.get('email'))
        password = data.get('password')
        
        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400
        
        user = User.query.filter_by(email=email).first()
        
        if not user:
            return jsonify({"error": "Invalid email or password"}), 401
        
        if user.lock_until and user.lock_until > datetime.utcnow():
            return jsonify({"error": "Account temporarily locked. Try again later."}), 423
        
        if not user.is_active:
            return jsonify({"error": "Account deactivated"}), 401
        
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        if user.password_hash == password_hash:
            if not user.verified:
                return jsonify({"error": "Email not verified"}), 401
            
            user.failed_login_attempts = 0
            user.lock_until = None
            user.last_login = datetime.utcnow()
            user.last_activity = datetime.utcnow()
            db.session.commit()
            
            update_user_activity(email, "login", {
                "secret_key": user.secret_key,
                "credits": user.credits
            })
            
            return jsonify({
                "status": "success",
                "message": "Login successful",
                "secret_key": user.secret_key,
                "credits": user.credits
            })
        else:
            user.failed_login_attempts += 1
            
            if user.failed_login_attempts >= 5:
                user.lock_until = datetime.utcnow() + timedelta(minutes=30)
                db.session.commit()
                return jsonify({"error": "Account locked due to too many failed attempts. Try again in 30 minutes."}), 423
            
            db.session.commit()
            return jsonify({"error": "Invalid email or password"}), 401
            
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({"error": "Login failed"}), 500

@app.route('/save_spreadsheet', methods=['POST'])
@auth_required
def save_spreadsheet():
    try:
        data = request.get_json()
        spreadsheet_url = sanitize_input(data.get('spreadsheet_url'), 500)
        
        if not spreadsheet_url:
            return jsonify({"error": "Spreadsheet URL is required"}), 400
        
        if not spreadsheet_url.startswith('https://docs.google.com/spreadsheets/'):
            return jsonify({"error": "Invalid Google Sheets URL"}), 400
        
        user = request.user
        user.spreadsheet_url = spreadsheet_url
        db.session.commit()
        
        update_user_activity(user.email, "file_upload", {
            "file_type": "spreadsheet",
            "url": spreadsheet_url,
            "timestamp": datetime.now().isoformat()
        })
        
        return jsonify({
            "status": "success",
            "message": "Spreadsheet URL saved successfully"
        })
            
    except Exception as e:
        logger.error(f"Save spreadsheet error: {e}")
        return jsonify({"error": "Failed to save spreadsheet"}), 500

@app.route('/start', methods=['POST'])
@auth_required
def start_bot():
    try:
        user = request.user
        
        resources = resource_manager.get_system_resources()
        if resources.get('memory_used_percent', 0) > 90:
            return jsonify({"error": "System resources low. Please try again later."}), 503
        
        if not resource_manager.can_start_session():
            return jsonify({"error": "Maximum concurrent sessions reached. Please try again later."}), 429
        
        if user.credits <= 0:
            resource_manager.release_session()
            return jsonify({"error": "Insufficient credits. Please upgrade your plan."}), 402
        
        if not user.spreadsheet_url:
            resource_manager.release_session()
            return jsonify({"error": "No spreadsheet URL found. Please save your spreadsheet first."}), 400
        
        assigned_server = bot_server_manager.get_available_server()
        if not assigned_server:
            resource_manager.release_session()
            return jsonify({"error": "No bot servers available. Please try again later."}), 503
        
        session_id = f"user_{user.id}_{int(time.time())}_{random.randint(1000, 9999)}"
        
        user.credits -= 1
        db.session.commit()
        
        user_session = UserSession(
            user_id=user.id,
            session_id=session_id,
            assigned_server=assigned_server,
            spreadsheet_url=user.spreadsheet_url,
            progress_data=json.dumps({
                "total_contacts": 0,
                "processed": 0,
                "successful": 0,
                "failed": 0,
                "not_found": 0,
                "current_contact": None,
                "status": "starting"
            })
        )
        db.session.add(user_session)
        db.session.commit()
        
        thread = threading.Thread(
            target=start_user_bot_enhanced, 
            args=(session_id, user.spreadsheet_url, assigned_server, user.email),
            daemon=True
        )
        thread.start()
        
        session_manager.add_session(session_id, {
            'status': 'starting',
            'started_at': datetime.now(),
            'assigned_server': assigned_server,
            'spreadsheet_url': user.spreadsheet_url,
            'user_email': user.email,
            'process': None,
            'thread': thread
        })
        
        update_user_activity(user.email, "bot_session", {
            "session_id": session_id,
            "action": "start",
            "assigned_server": assigned_server,
            "spreadsheet_url": user.spreadsheet_url
        })
        
        return jsonify({
            "status": "success",
            "message": f"Bot started for {user.email}",
            "session_id": session_id,
            "assigned_server": assigned_server,
            "started_at": datetime.now().isoformat(),
            "remaining_credits": user.credits
        })
        
    except Exception as e:
        logger.error(f"Start bot error: {e}")
        resource_manager.release_session()
        return jsonify({"error": "Failed to start bot"}), 500

@app.route('/stop', methods=['POST'])
@auth_required
def stop_bot():
    try:
        user = request.user
        
        active_session_id = None
        for session_id, session in session_manager.sessions.items():
            if session.get('user_email') == user.email and session.get('status') in ['starting', 'running']:
                active_session_id = session_id
                break
        
        if not active_session_id:
            return jsonify({"error": "No active session found"}), 404
        
        session_manager.force_stop_session(active_session_id)
        session_manager.remove_session(active_session_id)
        resource_manager.release_session()
        
        user_session = UserSession.query.filter_by(session_id=active_session_id).first()
        if user_session:
            user_session.status = 'stopped_by_user'
            user_session.ended_at = datetime.now()
            db.session.commit()
        
        update_user_activity(user.email, "bot_session", {
            "session_id": active_session_id,
            "action": "stop",
            "stopped_at": datetime.now().isoformat()
        })
        
        return jsonify({
            "status": "success", 
            "message": f"Bot stopped successfully"
        })
        
    except Exception as e:
        logger.error(f"Stop bot error: {e}")
        return jsonify({"error": "Failed to stop bot"}), 500

@app.route('/status', methods=['POST'])
@auth_required
def get_status():
    try:
        user = request.user
        
        for session_id, session in session_manager.sessions.items():
            if session.get('user_email') == user.email:
                user_session = UserSession.query.filter_by(session_id=session_id).first()
                progress = {}
                if user_session and user_session.progress_data:
                    progress = json.loads(user_session.progress_data)
                
                return jsonify({
                    "status": session['status'],
                    "session_id": session_id,
                    "started_at": session['started_at'].isoformat(),
                    "assigned_server": session['assigned_server'],
                    "progress": progress
                })
        
        return jsonify({"status": "no_active_session"})
        
    except Exception as e:
        logger.error(f"Status error: {e}")
        return jsonify({"error": "Failed to get status"}), 500

@app.route('/user/profile', methods=['POST'])
@auth_required
def get_user_profile():
    try:
        user = request.user
        user_stats = get_user_stats_from_supabase(user.email)
        
        active_sessions = 0
        for session in session_manager.sessions.values():
            if session.get('user_email') == user.email and session.get('status') in ['starting', 'running']:
                active_sessions += 1
        
        return jsonify({
            "email": user.email,
            "verified": bool(user.verified),
            "credits": user.credits,
            "spreadsheet_url": user.spreadsheet_url,
            "joined_date": user.created_at.isoformat() if user.created_at else None,
            "last_login": user.last_login.isoformat() if user.last_login else None,
            "first_seen": user_stats.get("first_seen"),
            "total_activities": user_stats.get("total_activities", 0),
            "files_uploaded": user_stats.get("files_uploaded", 0),
            "bot_sessions": user_stats.get("bot_sessions", 0),
            "active_sessions": active_sessions,
            "activity_counts": user_stats.get("activity_counts", {})
        })
        
    except Exception as e:
        logger.error(f"Profile error: {e}")
        return jsonify({"error": "Failed to get profile"}), 500

@app.route('/progress', methods=['POST'])
@auth_required
def get_progress():
    try:
        user = request.user
        
        for session_id, session in session_manager.sessions.items():
            if session.get('user_email') == user.email:
                user_session = UserSession.query.filter_by(session_id=session_id).first()
                if user_session and user_session.progress_data:
                    progress = json.loads(user_session.progress_data)
                    return jsonify({
                        "status": "success",
                        "progress": progress,
                        "session_status": session['status']
                    })
        
        return jsonify({"status": "no_active_session"})
        
    except Exception as e:
        logger.error(f"Progress error: {e}")
        return jsonify({"error": "Failed to get progress"}), 500

@app.route('/forgot_password', methods=['POST'])
@limiter.limit("3 per hour")
def forgot_password():
    try:
        data = request.get_json()
        email = sanitize_input(data.get('email'))
        
        if not email:
            return jsonify({"error": "Email is required"}), 400
        
        user = User.query.filter_by(email=email, is_active=True).first()
        if user:
            reset_code = f"{random.randint(100000, 999999)}"
            user.verification_code = reset_code
            user.verification_expires = datetime.utcnow() + timedelta(hours=1)
            db.session.commit()
            
            email_sent = email_manager.send_password_reset_email(email, reset_code)
            
            if email_sent:
                return jsonify({
                    "status": "success",
                    "message": "Password reset instructions sent to your email"
                })
            else:
                return jsonify({"error": "Failed to send reset email"}), 500
        else:
            return jsonify({
                "status": "success",
                "message": "If the email exists, reset instructions have been sent"
            })
                
    except Exception as e:
        logger.error(f"Forgot password error: {e}")
        return jsonify({"error": "Password reset failed"}), 500

@app.route('/reset_password', methods=['POST'])
@limiter.limit("5 per hour")
def reset_password():
    try:
        data = request.get_json()
        email = sanitize_input(data.get('email'))
        code = sanitize_input(data.get('code'))
        new_password = data.get('new_password')
        
        if not all([email, code, new_password]):
            return jsonify({"error": "Email, code and new password are required"}), 400
        
        is_valid_password, password_message = validate_password(new_password)
        if not is_valid_password:
            return jsonify({"error": password_message}), 400
        
        user = User.query.filter_by(email=email, is_active=True).first()
        
        if not user:
            return jsonify({"error": "Invalid reset request"}), 400
        
        if user.verification_expires and user.verification_expires < datetime.utcnow():
            return jsonify({"error": "Reset code expired"}), 400
        
        if user.verification_code == code:
            user.password_hash = hashlib.sha256(new_password.encode()).hexdigest()
            user.verification_code = None
            user.verification_expires = None
            user.failed_login_attempts = 0
            user.lock_until = None
            db.session.commit()
            
            update_user_activity(email, "password_reset")
            
            return jsonify({
                "status": "success",
                "message": "Password reset successfully"
            })
        else:
            return jsonify({"error": "Invalid reset code"}), 400
            
    except Exception as e:
        logger.error(f"Reset password error: {e}")
        return jsonify({"error": "Password reset failed"}), 500

# Bot Starter Function
def start_user_bot_enhanced(session_id, spreadsheet_url, assigned_server, email):
    process = None
    user_working_dir = f"/tmp/whatsapp_bot_{session_id}"
    
    try:
        logger.info(f"🚀 Starting enhanced bot for session: {session_id}")
        
        session_manager.update_session(session_id, {'status': 'starting'})
        update_session_progress(session_id, {"status": "starting", "current_contact": "Initializing..."})
        
        os.makedirs(user_working_dir, exist_ok=True)
        
        bot_script = generate_user_bot_script(session_id, spreadsheet_url, user_working_dir, email)
        script_path = os.path.join(user_working_dir, "user_bot.py")
        
        with open(script_path, 'w') as f:
            f.write(bot_script)
        
        if os.path.exists('credentials.json'):
            shutil.copy('credentials.json', os.path.join(user_working_dir, 'credentials.json'))
        
        session_manager.update_session(session_id, {'status': 'running'})
        update_session_progress(session_id, {"status": "running", "current_contact": "Setting up browser..."})
        
        process = subprocess.Popen(['python', script_path], cwd=user_working_dir)
        session_manager.update_session(session_id, {'process': process})
        
        while process.poll() is None:
            time.sleep(5)
            
            session = session_manager.get_session(session_id)
            if not session or session.get('status') in ['stopped', 'force_stopped']:
                process.terminate()
                time.sleep(2)
                if process.poll() is None:
                    process.kill()
                break
        
        exit_code = process.poll()
        
        if exit_code == 0:
            session_manager.update_session(session_id, {'status': 'completed'})
            update_session_progress(session_id, {"status": "completed", "current_contact": "All messages sent successfully!"})
            logger.info(f"✅ Bot completed successfully for session: {session_id}")
        else:
            session_manager.update_session(session_id, {'status': 'failed'})
            update_session_progress(session_id, {"status": "failed", "current_contact": f"Process exited with code {exit_code}"})
            logger.error(f"❌ Bot failed for session: {session_id}, exit code: {exit_code}")
        
        update_user_activity(email, "bot_session", {
            "session_id": session_id,
            "action": "completed" if exit_code == 0 else "failed",
            "exit_code": exit_code,
            "assigned_server": assigned_server
        })
        
    except Exception as e:
        logger.error(f"❌ Critical error in bot starter for {session_id}: {e}")
        
        session_manager.update_session(session_id, {'status': 'error'})
        update_session_progress(session_id, {
            "status": "error", 
            "current_contact": f"System error: {str(e)}"
        })
        
        if process and process.poll() is None:
            try:
                process.terminate()
                time.sleep(2)
                if process.poll() is None:
                    process.kill()
            except:
                pass
        
        update_user_activity(email, "bot_session", {
            "session_id": session_id,
            "action": "error",
            "error": str(e),
            "assigned_server": assigned_server
        })
    
    finally:
        resource_manager.release_session()
        
        try:
            if os.path.exists(user_working_dir):
                shutil.rmtree(user_working_dir, ignore_errors=True)
        except Exception as e:
            logger.error(f"Cleanup error for {session_id}: {e}")

def update_session_progress(session_id, progress_updates):
    try:
        user_session = UserSession.query.filter_by(session_id=session_id).first()
        if user_session:
            current_progress = {}
            if user_session.progress_data:
                current_progress = json.loads(user_session.progress_data)
            
            current_progress.update(progress_updates)
            user_session.progress_data = json.dumps(current_progress)
            db.session.commit()
    except Exception as e:
        logger.error(f"Error updating progress for {session_id}: {e}")

def generate_user_bot_script(user_id, spreadsheet_url, working_dir, email):
    """Generate the bot script - you can include your original bot script here"""
    return f'''
# Bot script for user {user_id}
print("Starting WhatsApp bot for {email}")
print("Spreadsheet URL: {spreadsheet_url}")
# Your original bot script code would go here
'''

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Resource not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"500 Error: {error}")
    return jsonify({"error": "Internal server error"}), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"error": "Rate limit exceeded. Please try again later."}), 429

# Signal handlers for graceful shutdown
def signal_handler(signum, frame):
    logger.info(f"Received signal {signum}, shutting down gracefully...")
    for session_id in list(session_manager.sessions.keys()):
        session_manager.force_stop_session(session_id)
    os._exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# Register cleanup at exit
atexit.register(lambda: [session_manager.force_stop_session(sid) for sid in list(session_manager.sessions.keys())])

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 10000))
    logger.info(f"🚀 Starting production server on port {port}")
    app.run(host="0.0.0.0", port=port, debug=False)
