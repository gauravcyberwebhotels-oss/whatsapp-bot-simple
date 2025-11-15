import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Flask
    SECRET_KEY = os.environ.get('SECRET_KEY', 'a605e8a61862c381e124448307639e38481f295e3d5753d13b68ff723bc50ffe')
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'c693bc92f011e86ac876e035bcd84e19d0c42cd046dd3ddbcf042050bc45473d')
    
    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///users.db').replace('postgres://', 'postgresql://')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Supabase Configuration
    SUPABASE_URL = os.environ.get('SUPABASE_URL', 'https://dakroxgamegsqbwqpcah.supabase.co')
    SUPABASE_KEY = os.environ.get('SUPABASE_KEY', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRha3JveGdhbWVnc3Fid3FwY2FoIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjMxODU1NDgsImV4cCI6MjA3ODc2MTU0OH0.5UIGJfWkUtV3j7bNq7hyZ4gCk5DPx03iDPLRNlm9Wcs')
    
    # Email Configuration
    SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
    SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
    EMAIL_ADDRESS = os.environ.get('EMAIL_ADDRESS', 'gauravcyberwebhotels@gmail.com')
    EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD', 'mdyd lhin edma qxis')
    
    # Bot Servers
    BOT_SERVERS = [
        'https://bot-1-ztr9.onrender.com',
        'https://bot2-jrbf.onrender.com', 
        'https://bot3-3rth.onrender.com',
        'https://bot4-370m.onrender.com',
        'https://bot5-q2ie.onrender.com'
    ]
    
    # Rate Limiting
    RATELIMIT_STORAGE_URI = "memory://"
