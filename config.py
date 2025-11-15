# config.py

import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Flask
    SECRET_KEY = os.environ.get('SECRET_KEY', 'a_default_secret_key_for_development')
    
    # Supabase Configuration
    SUPABASE_URL = os.environ.get('SUPABASE_URL', 'https://dakroxgamegsqbwqpcah.supabase.co')
    SUPABASE_KEY = os.environ.get('SUPABASE_KEY', 'your-public-anon-key-here')
    
    # --- NEW: EMAIL CONFIGURATION FOR PASSWORD RESETS ---
    SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
    SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
    # This is the email address that will send the password reset link
    EMAIL_ADDRESS = os.environ.get('EMAIL_ADDRESS', 'gauravcyberwebhotels@gmail.com')
    # This is the "App Password" you generate from your Google Account security settings
    EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD', 'mdyd lhin edma qxis')
