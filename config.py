# config.py

import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Flask
    SECRET_KEY = os.environ.get('SECRET_KEY', 'a_default_secret_key_for_development')
    
    # Supabase Configuration
    SUPABASE_URL = os.environ.get('SUPABASE_URL', 'https://dakroxgamegsqbwqpcah.supabase.co')
    SUPABASE_KEY = os.environ.get('SUPABASE_KEY', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRha3JveGdhbWVnc3Fid3FwY2FoIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjMxODU1NDgsImV4cCI6MjA3ODc2MTU0OH0.5UIGJfWkUtV3j7bNq7hyZ4gCk5DPx03iDPLRNlm9Wcs')
    
    # Email Configuration
    SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
    SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
    EMAIL_ADDRESS = os.environ.get('EMAIL_ADDRESS', 'gauravcyberwebhotels@gmail.com')
    EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD', 'mdyd lhin edma qxis')
    
    # Debug settings
    DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'
