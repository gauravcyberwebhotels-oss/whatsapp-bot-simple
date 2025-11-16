import os
from dotenv import load_dotenv
# Load environment variables from a .env file if it exists (for local development)
load_dotenv()
class Config:
    """
    This class reads all your secret keys and settings from the environment.
    It does NOT import from any other part of the application.
    """
    # Flask Secret Key
    SECRET_KEY = os.environ.get('SECRET_KEY', 'a-very-secret-key-for-dev')
    # Supabase Configuration
    SUPABASE_URL = os.environ.get('SUPABASE_URL')
    SUPABASE_KEY = os.environ.get('SUPABASE_KEY')
  
    # Brevo API Key for sending emails
    BREVO_API_KEY = os.environ.get('BREVO_API_KEY')
    SENDER_EMAIL = os.environ.get('SENDER_EMAIL')
  
    # Flask Debug settings (should be False in production)
    DEBUG = os.environ.get('DEBUG', 'False').lower() in ('true', '1', 't')
