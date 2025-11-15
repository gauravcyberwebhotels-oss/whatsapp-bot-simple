# config.py

import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Flask
    SECRET_KEY = os.environ.get('SECRET_KEY', 'a_default_secret_key_for_development')
    
    # Supabase Configuration - IMPORTANT: Make sure these are set in your Render environment
    SUPABASE_URL = os.environ.get('SUPABASE_URL', 'https://dakroxgamegsqbwqpcah.supabase.co')
    SUPABASE_KEY = os.environ.get('SUPABASE_KEY', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRha3JveGdhbWVnc3Fid3FwY2FoIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjMxODU1NDgsImV4cCI6MjA3ODc2MTU0OH0.5UIGJfWkUtV3j7bNq7hyZ4gCk5DPx03iDPLRNlm9Wcs')
    
    # Email Configuration (kept for future use, but not for verification)
    SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
    SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
    EMAIL_ADDRESS = os.environ.get('EMAIL_ADDRESS', 'youremail@gmail.com')
    EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD', 'your_app_password')
    
    # Bot Servers (kept for future use)
    BOT_SERVERS = [
        'https://bot-1-ztr9.onrender.com',
        'https://bot2-jrbf.onrender.com', 
        'https://bot3-3rth.onrender.com',
        'https://bot4-370m.onrender.com',
        'https://bot5-q2ie.onrender.com'
    ]
