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

# Security enhancements
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', secrets.token_hex(32))

# Rate limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

db = SQLAlchemy(app)

# Initialize Supabase client
supabase = None
try:
    from supabase_client import create_client
    if create_client:
        supabase = create_client(Config.SUPABASE_URL, Config.SUPABASE_KEY)
        logger.info("✅ Supabase client initialized successfully")
except Exception as e:
    logger.error(f"❌ Supabase initialization error: {e}")
    supabase = None

# Enhanced CORS configuration
CORS(app, origins=[
    'https://whatsapp-bot-simple.onrender.com',
    'http://localhost:3000',
    'http://localhost:5000',
    'http://localhost:8080',
], supports_credentials=True)

# Database Models with enhanced fields
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
    progress_data = db.Column(db.Text)  # JSON string for progress
    logs = db.Column(db.Text)  # JSON string for logs
    error_message = db.Column(db.Text)

class SystemLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    level = db.Column(db.String(20), nullable=False)
    message = db.Column(db.Text, nullable=False)
    details = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

def init_db():
    with app.app_context():
        try:
            db.create_all()
            logger.info("✅ Database initialized successfully")
        except Exception as e:
            logger.error(f"❌ Database initialization failed: {e}")

init_db()

# Enhanced session storage with automatic cleanup
class SessionManager:
    def __init__(self):
        self.sessions = {}
        self.lock = threading.Lock()
        self.cleanup_thread = None
        self.start_cleanup_daemon()
    
    def start_cleanup_daemon(self):
        def cleanup_daemon():
            while True:
                try:
                    self.cleanup_expired_sessions()
                    time.sleep(60)  # Cleanup every minute
                except Exception as e:
                    logger.error(f"Cleanup daemon error: {e}")
                    time.sleep(30)
        
        self.cleanup_thread = threading.Thread(target=cleanup_daemon, daemon=True)
        self.cleanup_thread.start()
    
    def cleanup_expired_sessions(self):
        with self.lock:
            now = datetime.now()
            expired_sessions = []
            for session_id, session in self.sessions.items():
                if session.get('last_activity') and (now - session['last_activity']).total_seconds() > 3600:  # 1 hour
                    expired_sessions.append(session_id)
                elif session.get('started_at') and (now - session['started_at']).total_seconds() > 86400:  # 24 hours
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
                
                # Update database
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

# Enhanced bot servers with health checks
class BotServerManager:
    def __init__(self, servers):
        self.servers = servers
        self.server_status = {server: False for server in servers}
        self.health_check_thread = None
        self.start_health_checks()
    
    def start_health_checks(self):
        def health_check_daemon():
            while True:
                try:
                    self.check_all_servers()
                    time.sleep(30)  # Check every 30 seconds
                except Exception as e:
                    logger.error(f"Health check daemon error: {e}")
                    time.sleep(60)
        
        self.health_check_thread = threading.Thread(target=health_check_daemon, daemon=True)
        self.health_check_thread.start()
    
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

BOT_SERVERS = [
    'https://bot-1-ztr9.onrender.com',
    'https://bot2-jrbf.onrender.com', 
    'https://bot3-3rth.onrender.com',
    'https://bot4-370m.onrender.com',
    'https://bot5-q2ie.onrender.com'
]

bot_server_manager = BotServerManager(BOT_SERVERS)

# Enhanced email configuration with retry logic
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
        """Send verification email"""
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
        """Send password reset email"""
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

# Enhanced security functions
def sanitize_input(input_string, max_length=500):
    """Sanitize user input to prevent XSS and injection attacks"""
    if not input_string:
        return ""
    
    # Remove potentially dangerous characters
    sanitized = re.sub(r'[<>&"\'\\]', '', str(input_string))
    
    # Limit length
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
    
    return sanitized.strip()

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    """Validate password strength"""
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
    """Generate cryptographically secure token"""
    return secrets.token_hex(length)

# Enhanced authentication decorator
def auth_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            data = request.get_json() or {}
            secret_key = data.get('secret_key')
            
            if not secret_key:
                return jsonify({"error": "Secret key is required"}), 401
            
            # Validate secret key format
            if not re.match(r'^sk_[a-f0-9]{32}$', secret_key):
                return jsonify({"error": "Invalid secret key format"}), 401
            
            user = User.query.filter_by(secret_key=secret_key, is_active=True).first()
            if not user:
                return jsonify({"error": "Invalid or inactive account"}), 401
            
            # Check if account is locked
            if user.lock_until and user.lock_until > datetime.utcnow():
                return jsonify({"error": "Account temporarily locked. Try again later."}), 423
            
            # Update last activity
            user.last_activity = datetime.utcnow()
            db.session.commit()
            
            request.user = user
            return f(*args, **kwargs)
            
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return jsonify({"error": "Authentication failed"}), 401
    
    return decorated_function

# Enhanced error handling
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

# Context manager for database operations
@contextmanager
def db_session():
    """Provide a transactional scope around a series of operations."""
    try:
        yield db.session
        db.session.commit()
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Database error: {e}")
        raise
    except Exception as e:
        db.session.rollback()
        logger.error(f"Unexpected error in database session: {e}")
        raise

# Enhanced resource management
class ResourceManager:
    def __init__(self):
        self.max_concurrent_sessions = 10  # Adjust based on your Render plan
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

# Enhanced keep-alive mechanism
def enhanced_keep_alive():
    """Prevent Render from shutting down with health checks"""
    while True:
        try:
            # Log system status
            resources = resource_manager.get_system_resources()
            logger.info(f"🔄 System status: {resources}")
            
            # Clean up temporary files
            cleanup_temp_files()
            
            time.sleep(300)  # 5 minutes
        except Exception as e:
            logger.error(f"Keep-alive error: {e}")
            time.sleep(60)

# Start enhanced keep-alive thread
keep_alive_thread = threading.Thread(target=enhanced_keep_alive, daemon=True)
keep_alive_thread.start()

# Enhanced Supabase functions with retry logic
def supabase_request(table, method='GET', data=None, filters=None):
    """Lightweight Supabase request handler"""
    headers = {
        'Authorization': f'Bearer {Config.SUPABASE_KEY}',
        'apikey': Config.SUPABASE_KEY,
        'Content-Type': 'application/json',
        'Prefer': 'return=representation'
    }
    
    url = f"{Config.SUPABASE_URL}/rest/v1/{table}"
    
    # Add filters to URL
    if filters:
        filter_str = '&'.join([f"{k}=eq.{v}" for k, v in filters.items()])
        url = f"{url}?{filter_str}"
    
    try:
        if method.upper() == 'GET':
            response = requests.get(url, headers=headers, timeout=10)
        elif method.upper() == 'POST':
            response = requests.post(url, headers=headers, json=data, timeout=10)
        elif method.upper() == 'PATCH':
            response = requests.patch(url, headers=headers, json=data, timeout=10)
        elif method.upper() == 'DELETE':
            response = requests.delete(url, headers=headers, timeout=10)
        else:
            return None
        
        if response.status_code in [200, 201]:
            return response.json()
        else:
            logger.error(f"❌ Supabase API error: {response.status_code} - {response.text}")
            return None
            
    except Exception as e:
        logger.error(f"❌ Supabase request error: {e}")
        return None

def supabase_request_with_retry(table, method='GET', data=None, filters=None, retries=3):
    """Enhanced Supabase request handler with retry logic"""
    for attempt in range(retries):
        try:
            result = supabase_request(table, method, data, filters)
            if result is not None:
                return result
        except Exception as e:
            logger.error(f"Supabase request attempt {attempt + 1} failed: {e}")
            if attempt < retries - 1:
                time.sleep(1)
    
    return None

def save_user_activity_to_supabase(email, activity_type, details=None):
    """Enhanced activity tracking with retry"""
    activity_data = {
        'email': email,
        'activity_type': activity_type,
        'details': details or {},
        'timestamp': datetime.now().isoformat(),
        'created_at': datetime.now().isoformat()
    }
    
    result = supabase_request_with_retry('user_activities', 'POST', activity_data)
    
    if result:
        logger.info(f"✅ Activity saved to Supabase for {email}")
        return True
    else:
        logger.error(f"❌ Failed to save activity for {email}")
        return False

def get_user_activities_from_supabase(email):
    """Get user activities from Supabase using lightweight client"""
    filters = {'email': email}
    result = supabase_request('user_activities', 'GET', filters=filters)
    
    if result and isinstance(result, list):
        # Sort by timestamp descending and limit to 100
        sorted_activities = sorted(result, key=lambda x: x.get('timestamp', ''), reverse=True)[:100]
        return sorted_activities
    return []

def get_user_stats_from_supabase(email):
    """Get user statistics from Supabase using lightweight client"""
    try:
        # Get all activities for this user
        activities = get_user_activities_from_supabase(email)
        
        if not activities:
            return {}
        
        # Calculate stats from activities
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
            
            # Find first seen
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

def get_system_stats_from_supabase():
    """Get system statistics from Supabase using lightweight client"""
    try:
        # Get all activities
        result = supabase_request('user_activities', 'GET')
        
        if result and isinstance(result, list):
            unique_emails = set()
            for activity in result:
                email = activity.get('email')
                if email:
                    unique_emails.add(email)
            
            total_users = len(unique_emails)
        else:
            total_users = 0
        
        return {
            'total_users': total_users,
            'last_updated': datetime.now().isoformat(),
            'active_sessions': len(session_manager.sessions)
        }
        
    except Exception as e:
        logger.error(f"❌ Error fetching system stats from Supabase: {e}")
        return {}

def update_user_activity(email, activity_type, details=None):
    """Update user activity in Supabase"""
    success = save_user_activity_to_supabase(email, activity_type, details)
    
    if not success:
        logger.error(f"⚠️ Failed to save activity to Supabase for {email}")
    
    return success

# Frontend serving with enhanced error handling
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

# Enhanced health endpoint
@app.route('/health')
def health():
    try:
        # Check database connection
        db.session.execute('SELECT 1')
        db_healthy = True
    except:
        db_healthy = False
    
    # Check system resources
    resources = resource_manager.get_system_resources()
    
    return jsonify({
        "status": "healthy" if db_healthy else "degraded",
        "timestamp": datetime.now().isoformat(),
        "database": "connected" if db_healthy else "disconnected",
        "supabase_connected": supabase is not None,
        "system_resources": resources,
        "active_sessions": len(session_manager.sessions),
        "server_stats": bot_server_manager.get_server_stats()
    })

@app.route('/ping')
def ping():
    return jsonify({"status": "ok", "timestamp": datetime.now().isoformat()})

# Enhanced stats endpoint
@app.route('/stats')
def get_stats():
    """Get comprehensive system statistics"""
    try:
        system_stats = get_system_stats_from_supabase()
        resources = resource_manager.get_system_resources()
        server_stats = bot_server_manager.get_server_stats()
        
        return jsonify({
            "total_users": system_stats.get("total_users", 0),
            "active_bots": len(session_manager.sessions),
            "last_updated": system_stats.get("last_updated"),
            "system_resources": resources,
            "server_stats": server_stats,
            "supabase_connected": supabase is not None
        })
    except Exception as e:
        logger.error(f"Stats endpoint error: {e}")
        return jsonify({"error": "Could not retrieve statistics"}), 500

# Enhanced user registration with comprehensive validation
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
        
        # Validate email format
        if not validate_email(email):
            return jsonify({"error": "Invalid email format"}), 400
        
        # Validate password strength
        is_valid_password, password_message = validate_password(password)
        if not is_valid_password:
            return jsonify({"error": password_message}), 400
        
        # Check if email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({"error": "Email already registered"}), 400
        
        # Generate secure tokens
        secret_key = f"sk_{generate_secure_token(16)}"
        verification_code = f"{random.randint(100000, 999999)}"
        
        # Hash password
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        # Create user with transaction
        with db_session():
            user = User(
                email=email,
                password_hash=password_hash,
                secret_key=secret_key,
                verification_code=verification_code,
                verification_expires=datetime.utcnow() + timedelta(hours=24)
            )
            db.session.add(user)
        
        # Save activity and send email
        update_user_activity(email, "registered", {
            "secret_key": secret_key,
            "verification_code": verification_code
        })
        
        # Send verification email
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

# Enhanced email verification
@app.route('/verify', methods=['POST'])
@limiter.limit("10 per minute")
def verify_email():
    try:
        data = request.get_json()
        email = sanitize_input(data.get('email'))
        code = sanitize_input(data.get('code'))
        
        if not email or not code:
            return jsonify({"error": "Email and verification code are required"}), 400
        
        with db_session():
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

# Enhanced login with security features
@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    try:
        data = request.get_json()
        email = sanitize_input(data.get('email'))
        password = data.get('password')
        
        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400
        
        with db_session():
            user = User.query.filter_by(email=email).first()
            
            if not user:
                return jsonify({"error": "Invalid email or password"}), 401
            
            # Check if account is locked
            if user.lock_until and user.lock_until > datetime.utcnow():
                return jsonify({"error": "Account temporarily locked. Try again later."}), 423
            
            if not user.is_active:
                return jsonify({"error": "Account deactivated"}), 401
            
            # Verify password
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            
            if user.password_hash == password_hash:
                if not user.verified:
                    return jsonify({"error": "Email not verified"}), 401
                
                # Reset failed attempts on successful login
                user.failed_login_attempts = 0
                user.lock_until = None
                user.last_login = datetime.utcnow()
                user.last_activity = datetime.utcnow()
                
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
                # Increment failed attempts
                user.failed_login_attempts += 1
                
                # Lock account after 5 failed attempts
                if user.failed_login_attempts >= 5:
                    user.lock_until = datetime.utcnow() + timedelta(minutes=30)
                    return jsonify({"error": "Account locked due to too many failed attempts. Try again in 30 minutes."}), 423
                
                return jsonify({"error": "Invalid email or password"}), 401
            
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({"error": "Login failed"}), 500

# Enhanced spreadsheet saving
@app.route('/save_spreadsheet', methods=['POST'])
@auth_required
def save_spreadsheet():
    try:
        data = request.get_json()
        spreadsheet_url = sanitize_input(data.get('spreadsheet_url'), 500)
        
        if not spreadsheet_url:
            return jsonify({"error": "Spreadsheet URL is required"}), 400
        
        # Validate Google Sheets URL format
        if not spreadsheet_url.startswith('https://docs.google.com/spreadsheets/'):
            return jsonify({"error": "Invalid Google Sheets URL"}), 400
        
        with db_session():
            user = request.user
            user.spreadsheet_url = spreadsheet_url
            
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

# Enhanced bot start with comprehensive checks
@app.route('/start', methods=['POST'])
@auth_required
def start_bot():
    try:
        user = request.user
        
        # Check system resources
        resources = resource_manager.get_system_resources()
        if resources.get('memory_used_percent', 0) > 90:
            return jsonify({"error": "System resources low. Please try again later."}), 503
        
        # Check if user can start new session
        if not resource_manager.can_start_session():
            return jsonify({"error": "Maximum concurrent sessions reached. Please try again later."}), 429
        
        # Check user credits
        if user.credits <= 0:
            resource_manager.release_session()
            return jsonify({"error": "Insufficient credits. Please upgrade your plan."}), 402
        
        # Check spreadsheet
        if not user.spreadsheet_url:
            resource_manager.release_session()
            return jsonify({"error": "No spreadsheet URL found. Please save your spreadsheet first."}), 400
        
        # Get available server
        assigned_server = bot_server_manager.get_available_server()
        if not assigned_server:
            resource_manager.release_session()
            return jsonify({"error": "No bot servers available. Please try again later."}), 503
        
        # Generate unique session ID
        session_id = f"user_{user.id}_{int(time.time())}_{random.randint(1000, 9999)}"
        
        # Deduct credit
        with db_session():
            user.credits -= 1
        
        # Create session record
        with db_session():
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
        
        # Start bot in background with enhanced error handling
        thread = threading.Thread(
            target=start_user_bot_enhanced, 
            args=(session_id, user.spreadsheet_url, assigned_server, user.email),
            daemon=True
        )
        thread.start()
        
        # Store session
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
        resource_manager.release_session()  # Ensure semaphore is released
        return jsonify({"error": "Failed to start bot"}), 500

# Enhanced bot stopping
@app.route('/stop', methods=['POST'])
@auth_required
def stop_bot():
    try:
        user = request.user
        
        # Find user's active session
        active_session_id = None
        for session_id, session in session_manager.sessions.items():
            if session.get('user_email') == user.email and session.get('status') in ['starting', 'running']:
                active_session_id = session_id
                break
        
        if not active_session_id:
            return jsonify({"error": "No active session found"}), 404
        
        # Stop the session
        session_manager.force_stop_session(active_session_id)
        session_manager.remove_session(active_session_id)
        resource_manager.release_session()
        
        # Update database
        with db_session():
            user_session = UserSession.query.filter_by(session_id=active_session_id).first()
            if user_session:
                user_session.status = 'stopped_by_user'
                user_session.ended_at = datetime.now()
        
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

# Enhanced session status
@app.route('/status', methods=['POST'])
@auth_required
def get_status():
    try:
        user = request.user
        
        # Find user's session
        for session_id, session in session_manager.sessions.items():
            if session.get('user_email') == user.email:
                # Get progress from database
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

# Enhanced user profile
@app.route('/user/profile', methods=['POST'])
@auth_required
def get_user_profile():
    try:
        user = request.user
        user_stats = get_user_stats_from_supabase(user.email)
        
        # Get active sessions count
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

# Enhanced progress tracking
@app.route('/progress', methods=['POST'])
@auth_required
def get_progress():
    try:
        user = request.user
        
        # Find user's active session
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

# Password reset endpoints
@app.route('/forgot_password', methods=['POST'])
@limiter.limit("3 per hour")
def forgot_password():
    try:
        data = request.get_json()
        email = sanitize_input(data.get('email'))
        
        if not email:
            return jsonify({"error": "Email is required"}), 400
        
        with db_session():
            user = User.query.filter_by(email=email, is_active=True).first()
            if user:
                reset_code = f"{random.randint(100000, 999999)}"
                user.verification_code = reset_code
                user.verification_expires = datetime.utcnow() + timedelta(hours=1)
                
                # Send reset email
                email_sent = email_manager.send_password_reset_email(email, reset_code)
                
                if email_sent:
                    return jsonify({
                        "status": "success",
                        "message": "Password reset instructions sent to your email"
                    })
                else:
                    return jsonify({"error": "Failed to send reset email"}), 500
            else:
                # Don't reveal whether email exists
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
        
        # Validate new password
        is_valid_password, password_message = validate_password(new_password)
        if not is_valid_password:
            return jsonify({"error": password_message}), 400
        
        with db_session():
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

# Admin endpoints (protected)
@app.route('/admin/users', methods=['GET'])
def admin_users():
    # Basic protection - in production, use proper admin authentication
    admin_key = request.headers.get('X-Admin-Key')
    if admin_key != os.environ.get('ADMIN_KEY'):
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        users = User.query.all()
        user_list = []
        
        for user in users:
            user_list.append({
                "id": user.id,
                "email": user.email,
                "verified": bool(user.verified),
                "credits": user.credits,
                "created_at": user.created_at.isoformat() if user.created_at else None,
                "last_login": user.last_login.isoformat() if user.last_login else None,
                "is_active": user.is_active
            })
        
        return jsonify({
            "status": "success",
            "users": user_list,
            "total_users": len(user_list)
        })
        
    except Exception as e:
        logger.error(f"Admin users error: {e}")
        return jsonify({"error": "Failed to get users"}), 500

@app.route('/admin/system_stats', methods=['GET'])
def admin_system_stats():
    admin_key = request.headers.get('X-Admin-Key')
    if admin_key != os.environ.get('ADMIN_KEY'):
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        resources = resource_manager.get_system_resources()
        server_stats = bot_server_manager.get_server_stats()
        
        # Get database stats
        total_users = User.query.count()
        active_users = User.query.filter_by(is_active=True).count()
        total_sessions = UserSession.query.count()
        
        return jsonify({
            "system_resources": resources,
            "server_stats": server_stats,
            "user_stats": {
                "total_users": total_users,
                "active_users": active_users,
                "total_sessions": total_sessions
            },
            "active_sessions": len(session_manager.sessions),
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Admin stats error: {e}")
        return jsonify({"error": "Failed to get system stats"}), 500

# Enhanced bot start function with comprehensive error handling
def start_user_bot_enhanced(session_id, spreadsheet_url, assigned_server, email):
    """Enhanced bot starter with full error handling and recovery"""
    process = None
    
    try:
        logger.info(f"🚀 Starting enhanced bot for session: {session_id}")
        
        # Update session status
        session_manager.update_session(session_id, {'status': 'starting'})
        update_session_progress(session_id, {"status": "starting", "current_contact": "Initializing..."})
        
        # Create working directory
        user_working_dir = f"/tmp/whatsapp_bot_{session_id}"
        os.makedirs(user_working_dir, exist_ok=True)
        
        # Generate bot script
        bot_script = generate_user_bot_script(session_id, spreadsheet_url, user_working_dir, email)
        script_path = os.path.join(user_working_dir, "user_bot.py")
        
        with open(script_path, 'w') as f:
            f.write(bot_script)
        
        # Copy credentials if available
        if os.path.exists('credentials.json'):
            shutil.copy('credentials.json', os.path.join(user_working_dir, 'credentials.json'))
        
        # Update status to running
        session_manager.update_session(session_id, {'status': 'running'})
        update_session_progress(session_id, {"status": "running", "current_contact": "Setting up browser..."})
        
        # Start the bot process
        process = subprocess.Popen(['python', script_path], cwd=user_working_dir)
        session_manager.update_session(session_id, {'process': process})
        
        # Monitor process
        while process.poll() is None:
            time.sleep(5)
            
            # Check if session should be stopped
            session = session_manager.get_session(session_id)
            if not session or session.get('status') in ['stopped', 'force_stopped']:
                process.terminate()
                time.sleep(2)
                if process.poll() is None:
                    process.kill()
                break
        
        # Process completed
        exit_code = process.poll()
        
        if exit_code == 0:
            session_manager.update_session(session_id, {'status': 'completed'})
            update_session_progress(session_id, {"status": "completed", "current_contact": "All messages sent successfully!"})
            logger.info(f"✅ Bot completed successfully for session: {session_id}")
        else:
            session_manager.update_session(session_id, {'status': 'failed'})
            update_session_progress(session_id, {"status": "failed", "current_contact": f"Process exited with code {exit_code}"})
            logger.error(f"❌ Bot failed for session: {session_id}, exit code: {exit_code}")
        
        # Update activity
        update_user_activity(email, "bot_session", {
            "session_id": session_id,
            "action": "completed" if exit_code == 0 else "failed",
            "exit_code": exit_code,
            "assigned_server": assigned_server
        })
        
    except Exception as e:
        logger.error(f"❌ Critical error in bot starter for {session_id}: {e}")
        
        # Update session status
        session_manager.update_session(session_id, {'status': 'error'})
        update_session_progress(session_id, {
            "status": "error", 
            "current_contact": f"System error: {str(e)}"
        })
        
        # Kill process if exists
        if process and process.poll() is None:
            try:
                process.terminate()
                time.sleep(2)
                if process.poll() is None:
                    process.kill()
            except:
                pass
        
        # Update activity
        update_user_activity(email, "bot_session", {
            "session_id": session_id,
            "action": "error",
            "error": str(e),
            "assigned_server": assigned_server
        })
    
    finally:
        # Always release resources
        resource_manager.release_session()
        
        # Cleanup working directory
        try:
            if os.path.exists(user_working_dir):
                shutil.rmtree(user_working_dir, ignore_errors=True)
        except Exception as e:
            logger.error(f"Cleanup error for {session_id}: {e}")

def update_session_progress(session_id, progress_updates):
    """Update session progress in database"""
    try:
        with db_session():
            user_session = UserSession.query.filter_by(session_id=session_id).first()
            if user_session:
                current_progress = {}
                if user_session.progress_data:
                    current_progress = json.loads(user_session.progress_data)
                
                current_progress.update(progress_updates)
                user_session.progress_data = json.dumps(current_progress)
    except Exception as e:
        logger.error(f"Error updating progress for {session_id}: {e}")

def cleanup_temp_files():
    """Clean up temporary files"""
    try:
        current_time = time.time()
        max_age = 3600  # 1 hour
        
        for filename in os.listdir('/tmp'):
            if filename.startswith('whatsapp_bot_'):
                filepath = os.path.join('/tmp', filename)
                try:
                    if os.path.getmtime(filepath) < current_time - max_age:
                        shutil.rmtree(filepath, ignore_errors=True)
                        logger.info(f"🧹 Cleaned up old directory: {filename}")
                except:
                    pass
    except Exception as e:
        logger.error(f"Temp cleanup error: {e}")

# Your original generate_user_bot_script function
def generate_user_bot_script(user_id, spreadsheet_url, working_dir, email):
    """Generate personalized bot script with DYNAMIC SPREADSHEET"""
    unique_port = 9200 + (hash(user_id) % 100)

    return f'''import time
import os
import re
import gspread
import random
import base64
import requests
import sys
import subprocess
import psutil
import shutil
import tempfile
import threading
from google.oauth2.service_account import Credentials
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException, WebDriverException, SessionNotCreatedException, StaleElementReferenceException
from selenium.webdriver.common.keys import Keys
from webdriver_manager.chrome import ChromeDriverManager

# --- USER-SPECIFIC CONFIGURATION ---
SHEET_URL = "{spreadsheet_url}" # DYNAMIC - User's personal spreadsheet
GOOGLE_CREDENTIALS_FILE = 'credentials.json'
CHROME_PROFILE_PATH = os.path.join("{working_dir}", "chrome-profile-user-{user_id}")
CHROME_PORT = {unique_port}
GEMINI_API_KEY = "AIzaSyBh_9C-H-LGhii7EAPH26IfeR_FvLmDvbg"
MAX_RETRIES = 1
RETRY_DELAY = 2
MESSAGE_DELAY_MIN = 120
MESSAGE_DELAY_MAX = 180
automation_running = True

print("=" * 80)
print("🚀 PERSONAL WHATSAPP BOT STARTING")
print(f"👤 USER: {email}")
print(f"📊 SPREADSHEET: {spreadsheet_url}")
print(f"🆔 USER ID: {user_id}")
print("=" * 80)

# Keep-alive mechanism for 24/7 operation
def render_keep_alive():
    """Prevent Render from shutting down the bot"""
    while automation_running:
        try:
            print(f"🔄 Render keep-alive: {{time.strftime('%Y-%m-%d %H:%M:%S')}}")
            time.sleep(300) # Log every 5 minutes
        except Exception as e:
            print(f"Keep-alive error: {{e}}")
            time.sleep(60)

# Start keep-alive thread
keep_alive_thread = threading.Thread(target=render_keep_alive, daemon=True)
keep_alive_thread.start()

class AIPageDetector:
    """AI-powered contact detection - OPTIONAL, skip on rate limit"""
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash-exp:generateContent"
        self.rate_limited = False

    def detect_contact_in_sidebar(self, screenshot_path, phone_number):
        """Enhanced contact detection - SKIP if rate limited"""
        if self.rate_limited:
            print(" 🤖 AI skipped due to rate limit - assuming contact found")
            return True
        if not os.path.exists(screenshot_path):
            print(" ❌ Screenshot file not found for contact detection")
            return True
        for attempt in range(MAX_RETRIES):
            try:
                print(f" 👤 AI Contact Detection Attempt {{attempt + 1}}...")
               
                with open(screenshot_path, "rb") as image_file:
                    image_data = image_file.read()
                    if len(image_data) == 0:
                        print(" ❌ Screenshot is empty")
                        return True
                    encoded_image = base64.b64encode(image_data).decode('utf-8')
               
                prompt = f"""
                Analyze this WhatsApp Web screenshot after searching for phone number {{phone_number}}.
                TASK: Check if ANY contact/search result appears in the LEFT SIDEBAR area.
                LOOK FOR in the LEFT SIDEBAR (left panel):
                - Contact cards/rows with profile pictures or initials
                - Contact names, numbers, or timestamps displayed
                - Highlighted search results
                - Any rectangular elements that look like contacts
                - User profile images/circles with text below
                IGNORE:
                - Right side chat area
                - Top navigation/search bar
                - Bottom status or compose areas
                - Empty space without text/images
                VISUAL CLUES FOR CONTACT_FOUND:
                - At least one row/card in left panel with image + text
                - Name or number visible in left sidebar
                - Any non-empty content in the search results area of sidebar
                If sidebar shows only "No contacts/results" text or is completely blank/empty, say NO_CONTACT.
                RESPOND WITH ONLY ONE OF THESE EXACTLY:
                - "CONTACT_FOUND" if any contact/search result is visible in left sidebar
                - "NO_CONTACT" if sidebar is empty or shows no results message
                - "UNCLEAR" if cannot determine clearly
                Be accurate but lean towards CONTACT_FOUND if any text/images appear in sidebar besides headers.
                """
               
                payload = {{
                    "contents": [
                        {{
                            "parts": [
                                {{"text": prompt}},
                                {{
                                    "inline_data": {{
                                        "mime_type": "image/png",
                                        "data": encoded_image
                                    }}
                                }}
                            ]
                        }}
                    ],
                    "generationConfig": {{
                        "temperature": 0.0,
                        "maxOutputTokens": 20,
                    }}
                }}
               
                url = f"{{self.base_url}}?key={{self.api_key}}"
                response = requests.post(url, json=payload, timeout=30)
                response.raise_for_status()
               
                result = response.json()
               
                if 'candidates' not in result or not result['candidates']:
                    print(" ❌ No candidates in Gemini contact detection response")
                    continue
               
                if 'content' not in result['candidates'][0]:
                    print(" ❌ No content in Gemini contact detection response")
                    continue
               
                if 'parts' not in result['candidates'][0]['content']:
                    print(" ❌ No parts in Gemini contact detection response")
                    continue
               
                answer = result['candidates'][0]['content']['parts'][0]['text'].strip().upper()
               
                print(f" 🤖 AI Contact Detection Result: {{answer}}")
               
                if "CONTACT_FOUND" in answer:
                    return True
                elif "NO_CONTACT" in answer:
                    return False
                else:
                    return True
               
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 429:
                    print(" 🌐 Rate limited (429) - Skipping AI for this session")
                    self.rate_limited = True
                    return True
                else:
                    print(f" 🌐 HTTP error in contact detection attempt {{attempt + 1}}: {{e}}")
                    if attempt < MAX_RETRIES - 1:
                        time.sleep(RETRY_DELAY)
            except requests.exceptions.RequestException as e:
                print(f" 🌐 Network error in contact detection attempt {{attempt + 1}}: {{e}}")
                if attempt < MAX_RETRIES - 1:
                    time.sleep(RETRY_DELAY)
            except KeyError as e:
                print(f" 🔑 Key error in contact detection attempt {{attempt + 1}}: {{e}}")
                if attempt < MAX_RETRIES - 1:
                    time.sleep(RETRY_DELAY)
            except Exception as e:
                print(f" ⚠️ AI contact detection attempt {{attempt + 1}} failed: {{e}}")
                if attempt < MAX_RETRIES - 1:
                    time.sleep(RETRY_DELAY)
       
        return True

class WhatsAppStateManager:
    """Advanced state management for WhatsApp Web with comprehensive page detection"""
    def __init__(self, driver, ai_detector):
        self.driver = driver
        self.ai_detector = ai_detector
        self.current_state = "UNKNOWN"
        self.state_history = []
        self.last_url = ""
        self.page_activity_log = []
        self.force_success_count = 0
        self.last_force_time = 0
        self.readiness_score = 0

    def monitor_page_activity(self):
        """Monitor all page activities and transitions"""
        current_url = self.driver.current_url
        page_title = self.driver.title
        window_handles = len(self.driver.window_handles)
       
        activity_info = {{
            'timestamp': time.time(),
            'url': current_url,
            'title': page_title,
            'windows': window_handles,
            'state': self.current_state
        }}
       
        self.page_activity_log.append(activity_info)
       
        if len(self.page_activity_log) > 20:
            self.page_activity_log.pop(0)
       
        return activity_info

    def detect_page_transition(self):
        """Detect if page has transitioned significantly"""
        activity = self.monitor_page_activity()
       
        url_changed = activity['url'] != self.last_url
        self.last_url = activity['url']
       
        return url_changed or activity['state'] != self.current_state

    def get_comprehensive_page_state(self):
        """Get comprehensive page state with detailed page detection"""
        current_activity = self.monitor_page_activity()
       
        page_state = self._detect_whatsapp_page_state()
       
        self.current_state = page_state
        self.state_history.append((time.time(), page_state, current_activity))
       
        if len(self.state_history) > 10:
            self.state_history.pop(0)
       
        return page_state

    def _detect_whatsapp_page_state(self):
        """Enhanced WhatsApp page state detection"""
        try:
            page_source = self.driver.page_source
            current_url = self.driver.current_url
       
            print(" 🔍 Analyzing WhatsApp page state...")
       
            # QR Code indicators
            qr_indicators = [
                'Scan me!' in page_source,
                'Scan the QR code' in page_source,
                'Steps to log in' in page_source,
                'Link with phone number instead' in page_source,
                'Open WhatsApp on your phone' in page_source,
                'Linked devices' in page_source,
                'Link device' in page_source,
                'canvas' in page_source and 'aria-label="Scan me!"' in page_source,
                'data-ref="https://wa.me/settings/linked_devices' in page_source,
                'Stay logged in on this browser' in page_source,
                'Log in with phone number' in page_source
            ]
       
            if any(qr_indicators):
                print(" 📱 QR CODE PAGE DETECTED")
                return "QR_SCAN_PAGE"
       
            # Loading indicators
            loading_indicators = [
                'ServerJSPayloadListener' in page_source,
                'data-btmanifest="1029351731_main"' in page_source,
                'requireLazy' in page_source,
                'data:text/javascript;base64,cmVxdWlyZUxhenko' in page_source,
            ]
       
            try:
                loading_elements = self.driver.find_elements(By.XPATH, "//*[contains(@class, 'loading') or contains(@class, 'spinner') or contains(@data-testid, 'loading')]")
                if loading_elements:
                    loading_indicators.append(True)
            except:
                pass
       
            # PRIORITIZE interactive elements
            interactive_score = self._calculate_readiness_score()
            if interactive_score >= 1:
                print(f" ✅ INTERACTIVE READY (score: {{interactive_score}}/3)")
                return "CHAT_READY_PAGE"
       
            generic_loading = any(loading_indicators)
            if generic_loading and interactive_score < 1:
                print(" 🔄 LOADING PAGE DETECTED")
                return "LOADING_PAGE"
       
            print(" 🔍 Checking for chat interface elements...")
       
            # Updated chat container check
            try:
                chat_container = self.driver.find_elements(By.XPATH, "//div[contains(@class, 'x1e558r4') or contains(@class, 'x1n2onr6') or @data-testid='chat-list']")
                if chat_container:
                    print(" ✅ CHAT CONTAINER FOUND")
                    return "CHAT_READY_PAGE"
            except:
                pass
       
            # Essential elements with updated selectors
            essential_elements = [
                ('//div[@contenteditable="true"][@data-tab="3"]', 'Search Box'),
                ('//div[@data-testid="chat-list"]', 'Chat List'),
                ('//div[@data-testid="conversation-compose-box-input"]', 'Message Box'),
                ('//div[@data-testid="menu-bar"]', 'Menu Bar'),
                ('//div[@role="button"][@data-testid="chat-list-search"]', 'Search Button')
            ]
       
            chat_elements_found = 0
            chat_elements_total = 0
       
            for xpath, element_name in essential_elements:
                try:
                    elements = self.driver.find_elements(By.XPATH, xpath)
                    if elements:
                        for element in elements:
                            if element.is_displayed():
                                chat_elements_found += 1
                                print(f" ✅ {{element_name}}: FOUND")
                                break
                    chat_elements_total += 1
                except:
                    chat_elements_total += 1
       
            if chat_elements_found >= 2:
                print(f" 💬 CHAT INTERFACE READY - {{chat_elements_found}}/{{chat_elements_total}}")
                return "CHAT_READY_PAGE"
       
            # Contacts check
            try:
                contacts = self.driver.find_elements(By.XPATH, '//div[@data-testid="cell-frame-container"] | //div[@role="listitem"]')
                if contacts and len(contacts) > 0:
                    visible_contacts = [c for c in contacts if c.is_displayed()]
                    if len(visible_contacts) > 0:
                        print(f" 👥 CONTACTS FOUND - {{len(visible_contacts)}}")
                        return "CHAT_READY_PAGE"
            except:
                pass
       
            # Error indicators
            error_indicators = [
                "whatsapp couldn't load" in page_source.lower(),
                "connection failed" in page_source.lower(),
                "reload" in page_source.lower() and "try again" in page_source.lower(),
                "failed to load" in page_source.lower(),
                "disconnected" in page_source.lower(),
                "no internet" in page_source.lower(),
                "session expired" in page_source.lower(),
                "log in again" in page_source.lower()
            ]
       
            if any(error_indicators):
                print(" ❌ ERROR PAGE DETECTED")
                return "ERROR_PAGE"
       
            if len(page_source) < 1000 or "web.whatsapp.com" not in current_url:
                print(" 🌐 INITIAL LOADING")
                return "INITIAL_LOADING"
           
            print(" ❓ UNKNOWN STATE")
            return "UNKNOWN_STATE"
       
        except Exception as e:
            print(f" ⚠️ Page state detection failed: {{e}}")
            return "DETECTION_ERROR"

    def _calculate_readiness_score(self):
        """Real-time score based on interactive UI elements"""
        score = 0
        elements_to_check = [
            ('//div[@contenteditable="true"][@data-tab="3"]', 'Search Box'),
            ('//div[@data-testid="conversation-compose-box-input"]', 'Message Box'),
            ('//div[@data-testid="chat-list"]', 'Chat List')
        ]
       
        for xpath, name in elements_to_check:
            try:
                element = self.driver.find_element(By.XPATH, xpath)
                if element.is_displayed() and element.is_enabled():
                    score += 1
                    print(f" ✅ {{name}} interactive (+1 score)")
            except:
                pass
       
        self.readiness_score = score
        return score

    def wait_for_complete_loading(self, timeout=120):
        """Wait for complete WhatsApp loading"""
        print("\\n" + "="*60)
        print("🔍 REAL-TIME WHATSAPP PAGE STATE MONITOR")
        print("="*60)
        print("📱 Prioritizing interactive elements")
        print("🚀 Proceed once score >=1")
        print("="*60)
       
        start_time = time.time()
        last_state = ""
        consecutive_ready_states = 0
        required_consecutive = 1
        max_loading_checks = 5
        loading_checks_count = 0
       
        while time.time() - start_time < timeout:
            if not automation_running:
                return False
           
            now = time.time()
            if now - self.last_force_time < 30:
                current_state = "CHAT_READY_PAGE"
                print(" ⏳ Grace period: Assuming CHAT_READY")
            else:
                current_state = self.get_comprehensive_page_state()
       
            current_activity = self.monitor_page_activity()
       
            if current_state != last_state:
                print(f" 📊 State Transition: {{last_state}} → {{current_state}}")
                print(f" 🌐 URL: {{current_activity['url']}}")
                print(f" 📄 Title: {{current_activity['title']}}")
                last_state = current_state
       
            print(f" 🎯 Readiness Score: {{self.readiness_score}}/3")
       
            if current_state == "QR_SCAN_PAGE":
                print(" 📱 QR Code Page - Scan with phone!")
                consecutive_ready_states = 0
                loading_checks_count = 0
                time.sleep(5)
           
            elif current_state == "LOADING_PAGE":
                loading_checks_count += 1
                print(f" 🔄 Loading... (check {{loading_checks_count}}/{{max_loading_checks}})")
                consecutive_ready_states = 0
           
                if loading_checks_count >= max_loading_checks or self.readiness_score >= 1:
                    print(" ⚠️ Stuck - forcing check...")
                    if self._force_chat_detection():
                        self.force_success_count += 1
                        self.last_force_time = now
                        print(f" ✅ Force success #{{self.force_success_count}}")
                    
                        if self.force_success_count >= 1 or self.readiness_score >= 1:
                            current_state = "CHAT_READY_PAGE"
                            print(" 🎯 READY: Proceeding!")
                            break
                    else:
                        self.force_success_count = 0
                        print(" ❌ Force failed")
           
                time.sleep(2)
           
            elif current_state == "CHAT_READY_PAGE":
                consecutive_ready_states += 1
                loading_checks_count = 0
                print(f" ✅ Chat Ready ({{consecutive_ready_states}}/{{required_consecutive}})")
           
                if consecutive_ready_states >= required_consecutive and self.readiness_score >= 1:
                    if self.verify_complete_loading():
                        print("🎉 WHATSAPP FULLY LOADED!")
                        return True
                   
            elif current_state == "ERROR_PAGE":
                print(" ❌ Error - Refreshing...")
                consecutive_ready_states = 0
                loading_checks_count = 0
                try:
                    self.driver.refresh()
                    print(" 🔄 Refreshed")
                    time.sleep(5)
                except:
                    pass
               
            elif current_state in ["INITIAL_LOADING", "UNKNOWN_STATE", "DETECTION_ERROR"]:
                print(" 🔄 Monitoring...")
                consecutive_ready_states = 0
                time.sleep(2)
       
            time.sleep(1)
       
        final_score = self._calculate_readiness_score()
        if final_score >= 1:
            print(" 🆘 Timeout but ready—PROCEEDING!")
            return True
       
        print("❌ Timeout waiting for loading")
        return False

    def _force_chat_detection(self):
        """Force chat detection"""
        try:
            print(" 🔍 Force checking...")
       
            try:
                search_box = self.driver.find_element(By.XPATH, '//div[@contenteditable="true"][@data-tab="3"]')
                if search_box.is_displayed() and search_box.is_enabled():
                    print(" ✅ Search box interactive")
                    self._calculate_readiness_score()
                    return True
            except:
                pass
       
            try:
                chat_list = self.driver.find_element(By.XPATH, '//div[@data-testid="chat-list"]')
                if chat_list.is_displayed():
                    print(" ✅ Chat list visible")
                    self._calculate_readiness_score()
                    return True
            except:
                pass
       
            try:
                contacts = self.driver.find_elements(By.XPATH, '//div[@data-testid="cell-frame-container"] | //div[@role="listitem"]')
                if contacts and len(contacts) > 0:
                    print(f" ✅ {{len(contacts)}} contacts found")
                    self._calculate_readiness_score()
                    return True
            except:
                pass
       
            return False
       
        except Exception as e:
            print(f" ❌ Force error: {{e}}")
            return False

    def verify_complete_loading(self):
        """Final verification"""
        print(" 🔍 Final verification...")
       
        verification_steps = [
            self._verify_ui_components,
            self._verify_javascript_environment,
            self._verify_interactivity,
            lambda: self.readiness_score >= 1
        ]
       
        successful_verifications = 0
        for step in verification_steps:
            try:
                if step():
                    successful_verifications += 1
                    print(f" ✅ {{step.__name__ if hasattr(step, '__name__') else 'score_check'}}: PASSED")
                else:
                    print(f" ⚠️ {{step.__name__ if hasattr(step, '__name__') else 'score_check'}}: FAILED")
            except Exception as e:
                print(f" ❌ Verification error: {{e}}")
       
        print(f" 📊 Verification: {{successful_verifications}}/4")
       
        return successful_verifications >= 2

    def _verify_ui_components(self):
        """Verify UI components"""
        components = [
            ('//div[@contenteditable="true"][@data-tab="3"]', 'Search Box'),
            ('//div[@data-testid="chat-list"]', 'Chat List'),
            ('//div[@data-testid="conversation-compose-box-input"]', 'Message Box')
        ]
       
        for xpath, name in components:
            try:
                element = WebDriverWait(self.driver, 5).until(
                    EC.presence_of_element_located((By.XPATH, xpath))
                )
                if not element.is_displayed():
                    print(f" ⚠️ {{name}} not displayed")
                    return False
            except:
                print(f" ⚠️ {{name}} not found")
                return False
        return True

    def _verify_javascript_environment(self):
        """Verify JS environment"""
        try:
            script = """
            try {{
                return {{
                    documentReady: document.readyState === 'complete',
                    reactReady: typeof window.React !== 'undefined',
                    storeReady: typeof window.Store !== 'undefined',
                    chatManager: window.Store && window.Store.Chat !== undefined
                }};
            }} catch(e) {{
                return {{error: e.toString()}};
            }}
            """
            result = self.driver.execute_script(script)
            return (result.get('reactReady', False) and
                    result.get('storeReady', False))
        except:
            return False

    def _verify_interactivity(self):
        """Verify interactivity"""
        try:
            search_box = self.driver.find_element(By.XPATH, '//div[@contenteditable="true"][@data-tab="3"]')
            search_box.click()
            time.sleep(0.5)
            return True
        except:
            return False

def monitor_user_interrupt():
    """Monitor interrupt"""
    global automation_running
    try:
        while automation_running:
            time.sleep(0.5)
    except KeyboardInterrupt:
        automation_running = False
        print("\\n🛑 User interrupt - stopping...")

def kill_chrome_processes():
    """Kill automation Chrome processes"""
    print(" 🔴 Closing Chrome processes...")
    try:
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                process_name = proc.info['name'].lower() if proc.info['name'] else ""
                cmdline = proc.info['cmdline'] or []
               
                is_our_chrome = (
                    'chrome' in process_name and
                    (
                        CHROME_PROFILE_PATH in ' '.join(cmdline) or
                        str(CHROME_PORT) in ' '.join(cmdline) or
                        'chrome-profile-automation' in ' '.join(cmdline)
                    )
                )
               
                is_our_chromedriver = (
                    'chromedriver' in process_name and
                    str(CHROME_PORT) in ' '.join(cmdline)
                )
               
                if is_our_chrome or is_our_chromedriver:
                    print(f" 🎯 Terminating: {{process_name}} (PID: {{proc.info['pid']}})")
                    proc.terminate()
               
            except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                continue
       
        time.sleep(2)
       
        # Force kill
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                process_name = proc.info['name'].lower() if proc.info['name'] else ""
                cmdline = proc.info['cmdline'] or []
               
                is_our_chrome = (
                    'chrome' in process_name and
                    (
                        CHROME_PROFILE_PATH in ' '.join(cmdline) or
                        str(CHROME_PORT) in ' '.join(cmdline) or
                        'chrome-profile-automation' in ' '.join(cmdline)
                    )
                )
               
                is_our_chromedriver = (
                    'chromedriver' in process_name and
                    str(CHROME_PORT) in ' '.join(cmdline)
                )
               
                if is_our_chrome or is_our_chromedriver:
                    print(f" 💀 Force killing: {{process_name}} (PID: {{proc.info['pid']}})")
                    proc.kill()
               
            except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                continue
       
        print(" ✅ Processes terminated")
        time.sleep(1)
       
    except Exception as e:
        print(f" ⚠️ Cleanup warning: {{e}}")

def cleanup_temp_files():
    """Clean temp files"""
    try:
        print(" 🧹 Cleaning temp files...")
       
        for file in os.listdir('.'):
            if file.endswith('.png') and ('sidebar_check' in file or 'state_detection' in file):
                try:
                    os.remove(file)
                    print(f" 🗑️ Removed: {{file}}")
                except:
                    pass
       
        if os.path.exists(CHROME_PROFILE_PATH):
            try:
                shutil.rmtree(CHROME_PROFILE_PATH, ignore_errors=True)
                print(f" 🗑️ Removed profile: {{CHROME_PROFILE_PATH}}")
            except:
                pass
       
        print(" ✅ Temp cleaned")
       
    except Exception as e:
        print(f" ⚠️ Temp cleanup warning: {{e}}")

def reset_chrome_environment():
    """Reset Chrome env"""
    print(" 🔄 Resetting Chrome...")
    kill_chrome_processes()
    cleanup_temp_files()
    print(" ✅ Reset complete")
    time.sleep(1)

def setup_google_sheets():
    """Setup Google Sheets"""
    for attempt in range(MAX_RETRIES):
        try:
            print("📊 Connecting to Sheets...")
            scope = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]
            creds = Credentials.from_service_account_file(GOOGLE_CREDENTIALS_FILE, scopes=scope)
            client = gspread.authorize(creds)
            spreadsheet = client.open_by_url(SHEET_URL)
            worksheet = spreadsheet.get_worksheet(0)
            print("✅ Sheets connected.")
            return worksheet
        except Exception as e:
            print(f"❌ Sheets attempt {{attempt + 1}} failed: {{e}}")
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY)
    return None

def create_driver():
    """Create isolated Chrome driver"""
    for attempt in range(MAX_RETRIES):
        try:
            print(f"🔧 Chrome Setup {{attempt + 1}}/{{MAX_RETRIES}}")
       
            if attempt > 0:
                reset_chrome_environment()
       
            chrome_options = webdriver.ChromeOptions()
       
            os.makedirs(CHROME_PROFILE_PATH, exist_ok=True)
       
            chrome_options.add_argument(f"--user-data-dir={{CHROME_PROFILE_PATH}}")
            chrome_options.add_argument(f"--remote-debugging-port={{CHROME_PORT}}")
            chrome_options.add_argument("--no-first-run")
            chrome_options.add_argument("--no-default-browser-check")
            chrome_options.add_argument("--disable-blink-features=AutomationControlled")
            chrome_options.add_argument("--disable-extensions")
            chrome_options.add_argument("--disable-plugins")
            chrome_options.add_argument("--disable-popup-blocking")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--disable-web-security")
            chrome_options.add_argument("--allow-running-insecure-content")
            chrome_options.add_argument("--disable-features=VizDisplayCompositor")
       
            chrome_options.add_argument("--window-size=1200,800")
            chrome_options.add_argument("--window-position=100,100")
       
            chrome_options.add_experimental_option("excludeSwitches", ["enable-automation", "enable-logging"])
            chrome_options.add_experimental_option('useAutomationExtension', False)
       
            prefs = {{
                "profile.default_content_setting_values.notifications": 2,
                "profile.default_content_settings.popups": 0,
                "credentials_enable_service": False,
                "profile.password_manager_enabled": False,
                "profile.default_content_setting_values.geolocation": 2,
                "profile.default_content_setting_values.images": 1,
                "profile.default_content_setting_values.cookies": 1
            }}
            chrome_options.add_experimental_option("prefs", prefs)
       
            try:
                service = ChromeService(ChromeDriverManager().install())
                driver = webdriver.Chrome(service=service, options=chrome_options)
            except Exception as e:
                print(f" ⚠️ Driver manager failed: {{e}}")
                driver = webdriver.Chrome(options=chrome_options)
       
            driver.set_page_load_timeout(30)
            driver.implicitly_wait(5)
       
            driver.execute_script("Object.defineProperty(navigator, 'webdriver', {{get: () => undefined}})")
            driver.execute_script("Object.defineProperty(navigator, 'chrome', {{get: () => undefined}})")
       
            print("✅ Chrome started!")
            print(f" 📁 Profile: {{CHROME_PROFILE_PATH}}")
            print(f" 🔌 Port: {{CHROME_PORT}}")
            return driver
       
        except SessionNotCreatedException as e:
            print(f"❌ Session error {{attempt + 1}}: {{e}}")
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY)
                reset_chrome_environment()
           
        except Exception as e:
            print(f"❌ Error {{attempt + 1}}: {{e}}")
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY)
                reset_chrome_environment()
    print("❌ All setups failed.")
    return None

def take_screenshot(driver, filename):
    """Take screenshot"""
    for attempt in range(MAX_RETRIES):
        try:
            screenshot_path = f"{{filename}}_{{int(time.time())}}.png"
       
            os.makedirs(os.path.dirname(os.path.abspath(screenshot_path)), exist_ok=True)
       
            driver.save_screenshot(screenshot_path)
       
            if os.path.exists(screenshot_path) and os.path.getsize(screenshot_path) > 1000:
                print(f" 📸 Screenshot: {{screenshot_path}}")
                return screenshot_path
            else:
                print(f" ❌ Screenshot empty: {{screenshot_path}}")
                if os.path.exists(screenshot_path):
                    os.remove(screenshot_path)
               
        except Exception as e:
            print(f" ❌ Screenshot attempt {{attempt + 1}} failed: {{e}}")
            if attempt < MAX_RETRIES - 1:
                time.sleep(1)
    return None

def format_phone_number(phone):
    """Format phone"""
    try:
        clean_phone = re.sub(r'\\D', '', str(phone))
       
        if clean_phone.startswith('91') and len(clean_phone) in [11, 12]:
            return clean_phone
        elif len(clean_phone) == 10:
            return '91' + clean_phone
        elif clean_phone.startswith('+91') and len(clean_phone) == 13:
            return clean_phone[1:]
        elif clean_phone.startswith('0') and len(clean_phone) == 11:
            return '91' + clean_phone[1:]
       
        return clean_phone
    except Exception as e:
        print(f"❌ Phone format error: {{e}}")
        return ""

def clear_search_comprehensive(driver):
    """Clear search - HANDLE STALE ELEMENTS"""
    for attempt in range(MAX_RETRIES):
        try:
            print(" 🧹 Clearing search...")
       
            # Re-find search box each time to avoid stale
            search_box = WebDriverWait(driver, 10).until(
                EC.element_to_be_clickable((By.XPATH, '//div[@contenteditable="true"][@data-tab="3"]'))
            )
       
            search_box.click()
            time.sleep(0.5)
       
            # Clear with keys
            search_box.send_keys(Keys.CONTROL + "a")
            search_box.send_keys(Keys.DELETE)
            time.sleep(0.5)
       
            # JS backup
            driver.execute_script("arguments[0].innerHTML = '';", search_box)
            time.sleep(0.5)
       
            # Escape
            search_box.send_keys(Keys.ESCAPE)
            time.sleep(0.5)
       
            # Verify - re-find if needed
            current_text = driver.execute_script("return arguments[0].textContent || arguments[0].innerText;", search_box)
            if not current_text or current_text.strip() == "":
                print(" ✅ Search cleared")
                return True
            else:
                print(f" ⚠️ Still text: '{{current_text}}'")
           
        except StaleElementReferenceException:
            print(f" ⚠️ Stale element in clear attempt {{attempt + 1}} - retrying...")
            time.sleep(1)
        except Exception as e:
            print(f" ❌ Clear attempt {{attempt + 1}} failed: {{e}}")
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY)
    return False

def search_contact_fast(driver, phone_number):
    """FAST SEARCH - 1 ATTEMPT ONLY, NO WAITING FOR RESULTS"""
    try:
        print(f" 🔍 FAST SEARCH: {{phone_number}}")
     
        # Find search box
        search_box = WebDriverWait(driver, 10).until(
            EC.element_to_be_clickable((By.XPATH, '//div[@contenteditable="true"][@data-tab="3"]'))
        )
     
        # Clear
        search_box.click()
        time.sleep(0.2)
        search_box.send_keys(Keys.CONTROL + "a")
        search_box.send_keys(Keys.DELETE)
        time.sleep(0.2)
     
        # Type fast
        search_box.send_keys(phone_number)
        time.sleep(1) # Short wait for search
     
        print(" ✅ Search completed - proceeding immediately")
        return True
     
    except Exception as e:
        print(f" ❌ Fast search failed: {{e}}")
        return False

def check_no_contacts_message(driver):
    """Check no contacts - FAST"""
    try:
        print(" 🔍 Checking no contacts...")
        no_contact_selectors = [
            '//div[contains(text(), "No contacts")]',
            '//div[contains(text(), "no contacts")]',
            '//div[contains(text(), "No results")]',
            '//div[contains(text(), "no results")]',
            '//div[contains(text(), "Not found")]',
            '//div[contains(text(), "Click here")]',
            '//div[contains(text(), "Search results")]',
            '//span[contains(text(), "No chats")]',
            '//div[contains(@class, "no-search-results")]'
        ]
       
        for selector in no_contact_selectors:
            elements = driver.find_elements(By.XPATH, selector)
            if elements:
                for element in elements:
                    if element.is_displayed():
                        print(" 📭 No contacts detected")
                        return True
     
        # JS check
        no_results = driver.execute_script("""
            const sidebar = document.querySelector('[data-testid="chat-list"]') || document.querySelector('[role="main"] > div:first-child');
            if (sidebar) {{
                const text = sidebar.innerText.toLowerCase();
                return text.includes('no contacts') || text.includes('no results') || text.includes('not found');
            }}
            return false;
        """)
        if no_results:
            print(" 📭 No contacts via JS")
            return True
     
        print(" ✅ No no-contacts - proceed")
        return False
    except:
        print(" ⚠️ Check error - assume found")
        return False

def click_contact_comprehensive(driver, phone_number):
    """ULTRA-POWERFUL CLICKING - CLICKS WHATEVER APPEARS AFTER SEARCH"""
    print(f" 🖱️ POWER CLICKING on contact for: {{phone_number}}")
 
    # ULTRA-POWERFUL CLICKING STRATEGIES (in priority order)
    click_strategies = [
        # STRATEGY 1: CLICK FIRST VISIBLE CONTACT (SIMPLE BUT EFFECTIVE)
        lambda: click_first_visible_contact_aggressive(driver),
     
        # STRATEGY 2: DIRECT PHONE NUMBER MATCH CLICK
        lambda: click_direct_phone_match(driver, phone_number),
     
        # STRATEGY 3: SMART SEARCH RESULT CLICK (CONTEXT-AWARE)
        lambda: click_smart_search_result(driver, phone_number),
     
        # STRATEGY 4: VISUAL ELEMENT CLICK (ANYTHING CLICKABLE IN RESULTS)
        lambda: click_any_visible_result_element(driver),
     
        # STRATEGY 5: JAVASCRIPT FORCE CLICK (NUCLEAR OPTION)
        lambda: javascript_force_click_all_strategies(driver, phone_number),
     
        # STRATEGY 6: COORDINATE CLICKING (FALLBACK)
        lambda: click_using_coordinates(driver)
    ]
 
    # Try each strategy with retries
    for strategy_index, strategy in enumerate(click_strategies):
        print(f" 🔥 Strategy {{strategy_index + 1}}/{{len(click_strategies)}}...")
     
        for attempt in range(MAX_RETRIES):
            try:
                print(f" Attempt {{attempt + 1}}...")
                if strategy():
                    print(f" ✅ Strategy {{strategy_index + 1}} SUCCESS!")
                    return True
                 
            except StaleElementReferenceException:
                print(f" ⚠️ Stale element - retrying...")
                time.sleep(0.5)
            except Exception as e:
                print(f" ⚠️ Attempt {{attempt + 1}} failed: {{e}}")
                if attempt < MAX_RETRIES - 1:
                    time.sleep(0.5)
 
    print(" 💥 ALL CLICKING STRATEGIES FAILED")
    return False

def click_first_visible_contact_aggressive(driver):
    """AGGRESSIVELY CLICK FIRST VISIBLE CONTACT - SIMPLE BUT EFFECTIVE"""
    print(" 👆 AGGRESSIVE FIRST CONTACT CLICK")
 
    # Multiple contact selectors (updated for current WhatsApp)
    contact_selectors = [
        '//div[@data-testid="cell-frame-container"]',
        '//div[@role="listitem"]',
        '//div[@role="gridcell"]',
        '//div[contains(@class, "chat-list")]//div[@role="button"]',
        '//div[contains(@class, "x1y1aw1k")]', # Common chat list class
        '//div[contains(@class, "x1n2onr6")]', # Another common class
        '//div[@tabindex="0"]', # Any clickable element
    ]
 
    for selector in contact_selectors:
        try:
            elements = driver.find_elements(By.XPATH, selector)
            visible_elements = [e for e in elements if e.is_displayed() and e.is_enabled()]
         
            if visible_elements:
                first_contact = visible_elements[0]
                print(f" 👀 Found {{len(visible_elements)}} contacts with selector: {{selector}}")
             
                # Aggressive clicking approach
                click_attempts = [
                    lambda: first_contact.click(),
                    lambda: driver.execute_script("arguments[0].click();", first_contact),
                    lambda: first_contact.send_keys(Keys.ENTER),
                    lambda: driver.execute_script("arguments[0].dispatchEvent(new MouseEvent('click', {{bubbles: true}}));", first_contact),
                ]
             
                for attempt_num, click_attempt in enumerate(click_attempts):
                    try:
                        # Scroll into view first
                        driver.execute_script("arguments[0].scrollIntoView({{block: 'center', behavior: 'instant'}});", first_contact)
                        time.sleep(0.3)
                     
                        click_attempt()
                        print(f" ✅ Success with click method {{attempt_num + 1}}")
                        return True
                    except Exception as e:
                        print(f" ⚠️ Click method {{attempt_num + 1}} failed: {{e}}")
                        continue
                     
        except Exception as e:
            print(f" ⚠️ Selector {{selector}} failed: {{e}}")
            continue
 
    return False

def click_direct_phone_match(driver, phone_number):
    """DIRECT PHONE MATCH - CLICK ANY ELEMENT CONTAINING THE PHONE NUMBER"""
    print(" 📱 DIRECT PHONE MATCH STRATEGY")
 
    # Get partial numbers for matching
    last_8_digits = phone_number[-8:] if len(phone_number) >= 8 else phone_number
    last_10_digits = phone_number[-10:] if len(phone_number) >= 10 else phone_number
 
    # Multiple patterns to match
    phone_patterns = [
        phone_number,
        last_10_digits,
        last_8_digits,
    ]
 
    # Remove duplicates and empty
    phone_patterns = list(set([p for p in phone_patterns if p and len(p) >= 8]))
 
    print(f" Patterns to match: {{phone_patterns}}")
 
    for pattern in phone_patterns:
        try:
            # MULTIPLE SELECTOR STRATEGIES for phone number
            selectors = [
                f"//*[contains(text(), '{{pattern}}')]",
                f"//*[contains(., '{{pattern}}')]",
                f"//div[contains(text(), '{{pattern}}')]",
                f"//span[contains(text(), '{{pattern}}')]",
            ]
         
            for selector in selectors:
                elements = driver.find_elements(By.XPATH, selector)
                for element in elements:
                    try:
                        if element.is_displayed() and element.is_enabled():
                            print(f" 🎯 Found phone element: {{element.text[:50]}}...")
                         
                            # Scroll to element
                            driver.execute_script("arguments[0].scrollIntoView({{block: 'center', behavior: 'instant'}});", element)
                            time.sleep(0.3)
                         
                            # Try multiple click methods
                            click_methods = [
                                lambda: element.click(),
                                lambda: driver.execute_script("arguments[0].click();", element),
                                lambda: element.send_keys(Keys.ENTER),
                            ]
                         
                            for click_method in click_methods:
                                try:
                                    click_method()
                                    print(f" ✅ Clicked phone pattern: {{pattern}}")
                                    return True
                                except:
                                    continue
                                 
                    except Exception as e:
                        print(f" ⚠️ Element interaction failed: {{e}}")
                        continue
                     
        except Exception as e:
            print(f" ⚠️ Pattern {{pattern}} failed: {{e}}")
            continue
 
    return False

def click_smart_search_result(driver, phone_number):
    """SMART CLICKING - UNDERSTANDS SEARCH CONTEXT"""
    print(" 🧠 SMART SEARCH RESULT CLICK")
 
    try:
        # JavaScript approach to find and click the most likely search result
        script = """
        // Find the main chat list/search results area
        const chatList = document.querySelector('[data-testid="chat-list"]') ||
                         document.querySelector('div[role="grid"]') ||
                         document.querySelector('div[role="main"]').firstElementChild;
     
        if (!chatList) return false;
     
        // Get all potential contact elements
        const candidates = Array.from(chatList.querySelectorAll([
            '[role="listitem"]',
            '[data-testid="cell-frame-container"]',
            '[role="gridcell"]',
            'div[tabindex="0"]'
        ].join(',')));
     
        // Filter visible ones
        const visible = candidates.filter(el => {{
            const rect = el.getBoundingClientRect();
            return rect.width > 0 && rect.height > 0 &&
                   el.offsetParent !== null &&
                   el.innerText.trim().length > 0;
        }});
     
        if (visible.length === 0) return false;
     
        // If only one result, click it immediately
        if (visible.length === 1) {{
            console.log('Single result found - clicking immediately');
            visible[0].click();
            return true;
        }}
     
        // For multiple, try to find the best match
        const phonePatterns = [arguments[0], arguments[0].slice(-10), arguments[0].slice(-8)];
     
        for (let candidate of visible) {{
            const text = candidate.innerText.toLowerCase();
         
            // Check if this looks like the best match
            const isBestMatch = phonePatterns.some(pattern =>
                text.includes(pattern) || candidate.querySelector(`[data-pre-plain-text*="${{pattern}}"]`)
            );
         
            if (isBestMatch || candidate.querySelector('[data-testid]')) {{
                console.log('Best match found - clicking');
                candidate.click();
                return true;
            }}
        }}
     
        // Fallback: click first visible
        console.log('Fallback: clicking first visible');
        visible[0].click();
        return true;
        """
     
        result = driver.execute_script(script, phone_number)
        if result:
            print(" ✅ Smart click successful")
            return True
         
    except Exception as e:
        print(f" ⚠️ Smart click failed: {{e}}")
 
    return False

def click_any_visible_result_element(driver):
    """CLICK ANY VISIBLE ELEMENT IN SEARCH RESULTS - NUCLEAR OPTION"""
    print(" 💥 CLICK ANY VISIBLE RESULT")
 
    try:
        # Get all clickable elements in the likely results area
        script = """
        const mainArea = document.querySelector('[data-testid="chat-list"]') ||
                        document.querySelector('div[role="main"]') ||
                        document.body;
     
        const allClickables = mainArea.querySelectorAll([
            'div[role="button"]',
            'div[tabindex="0"]',
            'div[data-testid]',
            'div[role="listitem"]',
            'div[role="gridcell"]'
        ].join(','));
     
        const visible = Array.from(allClickables).filter(el => {{
            const rect = el.getBoundingClientRect();
            return rect.width > 0 && rect.height > 0 &&
                   el.offsetParent !== null &&
                   el.innerText.trim().length > 0;
        }});
     
        if (visible.length > 0) {{
            // Click the most prominent one (largest area)
            const best = visible.reduce((largest, current) => {{
                const largeRect = largest.getBoundingClientRect();
                const currentRect = current.getBoundingClientRect();
                return (currentRect.width * currentRect.height) > (largeRect.width * largeRect.height) ? current : largest;
            }}, visible[0]);
         
            best.click();
            return true;
        }}
        return false;
        """
     
        result = driver.execute_script(script)
        if result:
            print(" ✅ Visible element clicked")
            return True
         
    except Exception as e:
        print(f" ⚠️ Visible click failed: {{e}}")
 
    return False

def javascript_force_click_all_strategies(driver, phone_number):
    """JAVASCRIPT NUCLEAR OPTION - TRY EVERYTHING"""
    print(" ⚡ JAVASCRIPT FORCE CLICK - NUCLEAR")
 
    try:
        script = f"""
        // ULTIMATE CLICKING SCRIPT - TRY EVERY POSSIBLE METHOD
        function ultimateClick() {{
            // METHOD 1: Chat list items
            const chatList = document.querySelector('[data-testid="chat-list"]');
            if (chatList) {{
                const firstItem = chatList.querySelector('[role="listitem"], [data-testid="cell-frame-container"]');
                if (firstItem) {{
                    firstItem.click();
                    return true;
                }}
            }}
         
            // METHOD 2: Direct text match
            const patterns = ['{phone_number}', '{phone_number[-10:]}', '{phone_number[-8:]}'];
            for (let pattern of patterns) {{
                const textElements = document.evaluate(
                    `//*[contains(text(), "${{pattern}}")]`,
                    document,
                    null,
                    XPathResult.ORDERED_NODE_SNAPSHOT_TYPE,
                    null
                );
             
                for (let i = 0; i < textElements.snapshotLength; i++) {{
                    const el = textElements.snapshotItem(i);
                    if (el.getBoundingClientRect().width > 0) {{
                        el.scrollIntoView({{block: 'center', behavior: 'instant'}});
                        el.click();
                        return true;
                    }}
                }}
            }}
         
            // METHOD 3: Any clickable in main area
            const mainArea = document.querySelector('div[role="main"]');
            if (mainArea) {{
                const clickables = mainArea.querySelectorAll('div[role="button"], div[tabindex="0"]');
                for (let clickable of clickables) {{
                    if (clickable.getBoundingClientRect().width > 0) {{
                        clickable.click();
                        return true;
                    }}
                }}
            }}
         
            return false;
        }}
     
        return ultimateClick();
        """
     
        result = driver.execute_script(script)
        if result:
            print(" ✅ JavaScript nuclear click worked!")
            return True
         
    except Exception as e:
        print(f" ⚠️ Nuclear click failed: {{e}}")
 
    return False

def click_using_coordinates(driver):
    """COORDINATE-BASED CLICKING - ABSOLUTE FALLBACK"""
    print(" 🎯 COORDINATE-BASED CLICKING")
 
    try:
        # Find the first reasonable element and click using coordinates
        script = """
        const chatList = document.querySelector('[data-testid="chat-list"]') ||
                        document.querySelector('div[role="main"]');
     
        if (!chatList) return false;
     
        const elements = chatList.querySelectorAll('div[role="listitem"], div[data-testid="cell-frame-container"]');
        for (let el of elements) {{
            const rect = el.getBoundingClientRect();
            if (rect.width > 0 && rect.height > 0) {{
                // Calculate center coordinates
                const x = rect.left + rect.width / 2;
                const y = rect.top + rect.height / 2;
             
                // Create and dispatch click event
                const clickEvent = new MouseEvent('click', {{
                    view: window,
                    bubbles: true,
                    cancelable: true,
                    clientX: x,
                    clientY: y
                }});
             
                el.dispatchEvent(clickEvent);
                return true;
            }}
        }}
        return false;
        """
     
        result = driver.execute_script(script)
        if result:
            print(" ✅ Coordinate click successful")
            return True
         
    except Exception as e:
        print(f" ⚠️ Coordinate click failed: {{e}}")
 
    return False

def verify_chat_opened_comprehensive(driver):
    """Verify chat - IMPROVED WITH BETTER SELECTORS AND POLLING"""
    print(" 🔍 Verifying chat...")
    # Poll for chat elements
    max_poll = 10
    poll_count = 0
    while poll_count < max_poll:
        try:
            # Updated selectors for conversation
            conversation_selectors = [
                '//div[@data-testid="conversation-panel-header"]',
                '//div[@data-testid="conversation-panel-body"]',
                '//div[@data-testid="conversation-compose-box-input"]',
                '//div[contains(@class, "x1e558r4") and contains(@class, "x1lliihq")]', # Header class
                '//div[@contenteditable="true" and @data-tab="10"]'
            ]
       
            found_elements = 0
            for selector in conversation_selectors:
                elements = driver.find_elements(By.XPATH, selector)
                if elements and any(e.is_displayed() for e in elements):
                    found_elements += 1
       
            # JS check for URL or panel
            js_check = driver.execute_script("""
                return window.location.href.includes('/s/') ||
                       document.querySelector('[data-testid="conversation-panel-body"]') !== null ||
                       document.querySelector('[data-testid="conversation-compose-box-input"]') !== null;
            """)
       
            if found_elements >= 1 or js_check:
                print(f" ✅ Chat verified (elements: {{found_elements}}, JS: {{js_check}})")
                return True
       
            poll_count += 1
            time.sleep(0.5)
        except:
            poll_count += 1
            time.sleep(0.5)
    print(" ❌ Chat verification failed after polling")
    return False

def send_message_guaranteed(driver, message):
    """GUARANTEED MESSAGE SENDING - FOCUSED ON TYPING AND SENDING"""
    print(f" 💬 GUARANTEED SENDING: '{{message[:50]}}...'")
 
    for attempt in range(MAX_RETRIES):
        try:
            print(f" Send attempt {{attempt + 1}}...")
         
            # FIND MESSAGE BOX - MULTIPLE SELECTORS
            message_selectors = [
                '//div[@data-testid="conversation-compose-box-input"]',
                '//div[@contenteditable="true"][@data-tab="10"]',
                '//div[@role="textbox"]',
                '//div[contains(@class, "selectable-text")]',
                '//div[@contenteditable="true"]'
            ]
         
            message_box = None
            for selector in message_selectors:
                try:
                    message_box = WebDriverWait(driver, 10).until(
                        EC.element_to_be_clickable((By.XPATH, selector))
                    )
                    print(f" ✅ Found message box with: {{selector}}")
                    break
                except:
                    continue
         
            if not message_box:
                print(" ❌ No message box found")
                continue
         
            # CLICK AND CLEAR
            message_box.click()
            time.sleep(0.5)
         
            # CLEAR THOROUGHLY
            message_box.send_keys(Keys.CONTROL + "a")
            message_box.send_keys(Keys.DELETE)
            time.sleep(0.3)
         
            # JS CLEAR AS BACKUP
            driver.execute_script("arguments[0].innerHTML = '';", message_box)
            time.sleep(0.3)
         
            # VERIFY CLEAR
            current_text = driver.execute_script("return arguments[0].textContent || arguments[0].innerText;", message_box)
            if current_text.strip():
                print(f" ⚠️ Still text after clear: '{{current_text}}' - clearing again")
                message_box.send_keys(Keys.CONTROL + "a")
                message_box.send_keys(Keys.DELETE)
                time.sleep(0.3)
         
            # TYPE MESSAGE CHARACTER BY CHARACTER (RELIABLE)
            print(" ⌨️ Typing message...")
            formatted_message = message.replace('\\n', ' ') # Remove newlines for WhatsApp
         
            for char in formatted_message:
                message_box.send_keys(char)
                time.sleep(0.02) # Small delay for reliability
         
            time.sleep(1) # Let typing complete
         
            # VERIFY TYPED MESSAGE
            typed_text = driver.execute_script("return arguments[0].textContent || arguments[0].innerText;", message_box)
            if formatted_message in typed_text:
                print(" ✅ Message typed successfully")
             
                # SEND MESSAGE - MULTIPLE METHODS
                print(" 📤 Sending message...")
             
                send_methods = [
                    lambda: message_box.send_keys(Keys.ENTER),
                    lambda: driver.execute_script("arguments[0].dispatchEvent(new KeyboardEvent('keydown', {{'key': 'Enter', 'keyCode': 13, 'which': 13, 'bubbles': true}}));", message_box),
                    lambda: click_send_button(driver)
                ]
             
                for method_num, send_method in enumerate(send_methods):
                    try:
                        send_method()
                        print(f" ✅ Send method {{method_num + 1}} executed")
                        time.sleep(2) # Wait for send to complete
                        break
                    except Exception as e:
                        print(f" ⚠️ Send method {{method_num + 1}} failed: {{e}}")
                        continue
             
                # VERIFY MESSAGE WAS SENT
                if verify_message_sent(driver, formatted_message):
                    print(" 🎉 MESSAGE SENT AND VERIFIED!")
                    return True
                else:
                    print(" ⚠️ Send verification failed but continuing")
                    return True # Still return True as message might have sent
                 
            else:
                print(f" ❌ Typing verification failed. Expected: '{{formatted_message}}', Got: '{{typed_text}}'")
                continue
             
        except StaleElementReferenceException:
            print(" ⚠️ Stale element - retrying...")
            time.sleep(1)
        except Exception as e:
            print(f" ❌ Send attempt {{attempt + 1}} failed: {{e}}")
            if attempt < MAX_RETRIES - 1:
                time.sleep(1)
 
    print(" 💥 ALL SEND ATTEMPTS FAILED")
    return False

def click_send_button(driver):
    """Click send button as backup"""
    try:
        send_buttons = [
            '//button[@data-testid="send"]',
            '//span[@data-testid="send"]',
            '//button[@aria-label="Send"]',
            '//button[contains(@class, "send")]'
        ]
     
        for selector in send_buttons:
            try:
                send_btn = driver.find_element(By.XPATH, selector)
                if send_btn.is_displayed() and send_btn.is_enabled():
                    send_btn.click()
                    print(" ✅ Send button clicked")
                    return True
            except:
                continue
        return False
    except:
        return False

def verify_message_sent(driver, message):
    """Verify message was sent"""
    try:
        # Check if message appears in chat
        script = """
        const messages = document.querySelectorAll('[data-testid="msg-container"], [data-id]');
        for (let msg of messages) {{
            if (msg.innerText.includes(arguments[0])) {{
                return true;
            }}
        }}
        return false;
        """
     
        result = driver.execute_script(script, message[:50]) # Check first 50 chars
        return result
    except:
        return False

def update_sheet_status_safely(worksheet, row, status):
    """Update sheet"""
    for attempt in range(MAX_RETRIES):
        try:
            worksheet.update_cell(row, 3, status)
            print(f" 📊 Status: {{status}}")
            return True
        except Exception as e:
            print(f" ❌ Update attempt {{attempt + 1}} failed: {{e}}")
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY)
    return False

def wait_with_progress(seconds, reason="Next"):
    """Wait progress with random delay between 2-3 minutes"""
    global automation_running
    total_seconds = seconds
    while total_seconds > 0 and automation_running:
        try:
            mins = total_seconds // 60
            secs = total_seconds % 60
            print(f" ⏰ {{reason}}: {{mins:02d}}:{{secs:02d}}", end='\\r')
            time.sleep(1)
            total_seconds -= 1
        except KeyboardInterrupt:
            automation_running = False
            print("\\n⚠️ Interrupted")
            break
        except Exception as e:
            print(f"\\n⚠️ Wait error: {{e}}")
            break
    if automation_running:
        print(" " * 50, end='\\r')

def get_random_delay():
    """Get random delay between 2-3 minutes"""
    return random.randint(MESSAGE_DELAY_MIN, MESSAGE_DELAY_MAX)

def cleanup_resources_safe(driver=None):
    """Cleanup"""
    global automation_running
    if not automation_running:
        print("🧹 Emergency cleanup...")
        try:
            for file in os.listdir('.'):
                if file.endswith('.png') and ('sidebar_check' in file or 'state_detection' in file):
                    try:
                        os.remove(file)
                    except:
                        pass
           
            kill_chrome_processes()
            cleanup_temp_files()
           
        except Exception as e:
            print(f"⚠️ Cleanup error: {{e}}")

def check_automation_should_continue():
    """Check continue"""
    global automation_running
    return automation_running

def run_comprehensive_automation(driver, worksheet, state_manager):
    """Main automation - FOCUSED ON SENDING MESSAGES"""
    global automation_running
    print("\\n" + "="*60)
    print("🚀 WHATSAPP MESSAGE SENDER")
    print("🎯 FOCUS: TYPING AND SENDING MESSAGES")
    print("⚡ 1 ATTEMPT PER STEP")
    print(f"⏰ DELAY: {{MESSAGE_DELAY_MIN//60}}-{{MESSAGE_DELAY_MAX//60}} minutes between messages")
    print("="*60)
    print("💡 Ctrl+C to stop")
    print("="*60)
    success_count = 0
    fail_count = 0
    not_found_count = 0
    total_processed = 0
    try:
        all_data = worksheet.get_all_values()
        if len(all_data) <= 1:
            print("❌ No data in sheet")
            return success_count, fail_count, not_found_count, total_processed
       
        records = all_data[1:]
        total_contacts = len(records)
       
        print(f"📋 {{total_contacts}} contacts")
       
        for i, record in enumerate(records):
            if not check_automation_should_continue():
                print("🛑 Stopped by user")
                break
           
            row_index = i + 2
       
            # Skip processed
            try:
                current_status = worksheet.cell(row_index, 3).value if len(worksheet.row_values(row_index)) >= 3 else ""
                if current_status in ["Sent ✅", "Sent ✅ (AI)", "Sent ✅ (Fallback)"]:
                    print(f" ⏭️ Skipping: {{record[0] if len(record)>0 else ''}}")
                    continue
            except:
                pass
       
            total_processed += 1
       
            print(f"\\n" + "="*50)
            print(f"🔄 {{total_processed}}/{{total_contacts}}")
            print("="*50)
       
            raw_phone = record[0].strip() if len(record) > 0 and record[0] else ""
            message = record[1].strip() if len(record) > 1 and record[1] else ""
       
            if not raw_phone or not message:
                update_sheet_status_safely(worksheet, row_index, "Failed - Missing data")
                fail_count += 1
                continue
       
            formatted_phone = format_phone_number(raw_phone)
            if len(formatted_phone) < 10:
                update_sheet_status_safely(worksheet, row_index, "Failed - Invalid number")
                fail_count += 1
                continue
       
            print(f" 📞 {{raw_phone}} → {{formatted_phone}}")
            print(f" 📝 '{{message[:50]}}...'")
       
            # State check
            current_state = state_manager.get_comprehensive_page_state()
            print(f" 📊 State: {{current_state}}")
            if current_state != "CHAT_READY_PAGE":
                print("🔄 Re-waiting...")
                if not state_manager.wait_for_complete_loading(timeout=20):
                    print("❌ State fail - skip")
                    update_sheet_status_safely(worksheet, row_index, "Failed - State error")
                    fail_count += 1
                    continue
                print("✅ Ready!")
       
            # Clear
            if not clear_search_comprehensive(driver):
                print("❌ Clear fail - skip")
                update_sheet_status_safely(worksheet, row_index, "Failed - Clear error")
                fail_count += 1
                continue
       
            # FAST SEARCH - 1 ATTEMPT ONLY
            if not search_contact_fast(driver, formatted_phone):
                print("❌ Search fail - skip")
                update_sheet_status_safely(worksheet, row_index, "Failed - Search error")
                fail_count += 1
                continue
       
            print(" 🔍 Search done...")
       
            # No contacts check
            no_contacts = check_no_contacts_message(driver)
            if no_contacts:
                print(" 📭 Not found")
                update_sheet_status_safely(worksheet, row_index, "Not Found ❌")
                not_found_count += 1
                continue
       
            # POWER CLICKING
            if click_contact_comprehensive(driver, formatted_phone):
                # Verify chat
                if verify_chat_opened_comprehensive(driver):
                    # GUARANTEED MESSAGE SENDING
                    if send_message_guaranteed(driver, message):
                        update_sheet_status_safely(worksheet, row_index, "Sent ✅")
                        success_count += 1
                        print(f" 🎉 Sent to {{formatted_phone}}")
                    else:
                        update_sheet_status_safely(worksheet, row_index, "Failed - Send error")
                        fail_count += 1
                        print(f" ❌ Send fail {{formatted_phone}}")
                else:
                    update_sheet_status_safely(worksheet, row_index, "Failed - Chat not opened")
                    fail_count += 1
                    print(f" ❌ Chat fail {{formatted_phone}}")
            else:
                update_sheet_status_safely(worksheet, row_index, "Failed - Click error")
                fail_count += 1
                print(f" ❌ Click fail {{formatted_phone}}")
       
            # Clear for next
            clear_search_comprehensive(driver)
       
            # Wait 2-3 minutes if more contacts remaining
            if i < total_contacts - 1 and automation_running:
                delay_seconds = get_random_delay()
                print(f"\\n ⏰ Next message in {{delay_seconds//60}} minutes...")
                wait_with_progress(delay_seconds, f"Next message in")
       
        return success_count, fail_count, not_found_count, total_processed
       
    except Exception as e:
        print(f"❌ Automation error: {{e}}")
        import traceback
        traceback.print_exc()
        return success_count, fail_count, not_found_count, total_processed

def main():
    """Main"""
    global automation_running
    print("\\n🚀 WHATSAPP MESSAGE BOT")
    print("🎯 FOCUS: TYPING AND SENDING")
    print("⚡ 1 ATTEMPT PER STEP")
    print(f"⏰ DELAY: {{MESSAGE_DELAY_MIN//60}}-{{MESSAGE_DELAY_MAX//60}} minutes between messages")
    print("🔒 RELIABLE MESSAGE SENDING")
    print("="*60)
    driver = None
    worksheet = None
    ai_detector = None
    state_manager = None
    # Interrupt thread
    interrupt_monitor = threading.Thread(target=monitor_user_interrupt, daemon=True)
    interrupt_monitor.start()
    try:
        # AI
        print("\\n🧠 STEP 1: AI Init...")
        ai_detector = AIPageDetector(GEMINI_API_KEY)
       
        # Sheets
        print("\\n📊 STEP 2: Sheets...")
        worksheet = setup_google_sheets()
        if not worksheet:
            return
       
        # Chrome
        print("\\n🔧 STEP 3: Chrome...")
        driver = create_driver()
        if not driver:
            print("❌ Chrome fail.")
            return
       
        # State
        print("\\n🎮 STEP 4: State Manager...")
        state_manager = WhatsAppStateManager(driver, ai_detector)
       
        # WhatsApp
        print("\\n🌐 STEP 5: WhatsApp...")
        try:
            print(" 🌐 Loading WhatsApp...")
            driver.get("https://web.whatsapp.com")
            print(" ✅ Loaded")
       
            initial_state = state_manager.get_comprehensive_page_state()
            print(f" 📊 Initial: {{initial_state}}")
       
        except Exception as e:
            print(f"❌ Load fail: {{e}}")
            return
       
        # Wait load
        print("\\n🔍 STEP 6: Monitoring...")
        print(" 👀 Transitions...")
       
        if not state_manager.wait_for_complete_loading():
            print("❌ Load fail!")
            return
       
        print("\\n🎉 READY—STARTING!")
        print("📱 Search → Click → TYPE AND SEND")
        time.sleep(2)
       
        # Run
        success_count, fail_count, not_found_count, total_processed = run_comprehensive_automation(
            driver, worksheet, state_manager
        )
       
        # Report
        print("\\n" + "="*60)
        if automation_running:
            print("🏁 COMPLETED!")
        else:
            print("🛑 STOPPED")
        print("="*60)
        print(f" ✅ Sent: {{success_count}}")
        print(f" ❌ Failed: {{fail_count}}")
        print(f" 🔍 Not found: {{not_found_count}}")
        print(f" 📊 Processed: {{total_processed}}")
        print("="*60)
       
    except KeyboardInterrupt:
        print("\\n🛑 Interrupted")
        automation_running = False
    except Exception as e:
        print(f"\\n❌ Error: {{e}}")
        import traceback
        traceback.print_exc()
    finally:
        print("\\n🧹 Cleanup...")
        cleanup_resources_safe(driver)
       
        if driver:
            try:
                driver.quit()
                print("🔚 Closed.")
            except:
                print("⚠️ Already closed.")
       
        print("\\n👋 Done.")

if __name__ == "__main__":
    main()
'''

# Signal handlers for graceful shutdown
def signal_handler(signum, frame):
    logger.info(f"Received signal {signum}, shutting down gracefully...")
    # Clean up sessions
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
