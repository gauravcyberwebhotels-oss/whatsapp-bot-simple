import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///users.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Email configuration
    SMTP_SERVER = 'smtp.gmail.com'
    SMTP_PORT = 587
    EMAIL_ADDRESS = 'gauravcyberwebhotels@gmail.com'
    EMAIL_PASSWORD = 'mdyd lhin edma qxis'  # Use App Password

    # Bot configuration
    BOT_SERVERS = [
        'https://bot-1-ztr9.onrender.com',
        'https://bot2-jrbf.onrender.com',
        'https://bot3-3rth.onrender.com',
        'https://bot4-370m.onrender.com',
        'https://bot5-q2ie.onrender.com'
    ]

    # WhatsApp configuration
    MESSAGE_DELAY_MIN = 120 # 2 minutes
    MESSAGE_DELAY_MAX = 180 # 3 minutes
    MAX_RETRIES = 3

    # AI configuration
    GEMINI_API_KEY = "AIzaSyBh_9C-H-LGhii7EAPH26IfeR_FvLmDvbg"
