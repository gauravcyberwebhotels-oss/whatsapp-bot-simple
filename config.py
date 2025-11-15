import os
class Config:
    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///users.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
   
    # Supabase Configuration
    SUPABASE_URL = os.environ.get('SUPABASE_URL', 'https://dakroxgamegsqbwqpcah.supabase.co')
    SUPABASE_KEY = os.environ.get('SUPABASE_KEY', 'sbp_841029a97bc68581c577e1a92dcb723f589d1b02')
   
    # Email Configuration
    SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
    SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
    EMAIL_ADDRESS = os.environ.get('EMAIL_ADDRESS', 'gauravcyberwebhotels@gmail.com')
    EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD', 'mdyd lhin edma qxis')
   
    # Bot Servers - Updated to your Render URLs
    BOT_SERVERS = [
        'https://bot-1-ztr9.onrender.com',
        'https://bot2-jrbf.onrender.com',
        'https://bot3-3rth.onrender.com',
        'https://bot4-370m.onrender.com',
        'https://bot5-q2ie.onrender.com'
    ]
   
    SECRET_KEY = os.environ.get('SECRET_KEY', '4f6d8a3c9e2b1f7a8d5c0e9b2a7f4d8c1e6a9b3d8f2c5e7a1b9d4f6c8e3a2b7f')
