# config.py - Final Secure Version
import os

class Config:
    """
    Configuration class - ALL credentials from environment variables only
    """
    # Flask Secret Key
    SECRET_KEY = os.environ.get('SECRET_KEY')
    
    # Supabase Configuration
    SUPABASE_URL = os.environ.get('SUPABASE_URL')
    SUPABASE_KEY = os.environ.get('SUPABASE_KEY')
    
    # Brevo Configuration
    BREVO_API_KEY = os.environ.get('BREVO_API_KEY')
    SENDER_EMAIL = os.environ.get('SENDER_EMAIL')
    
    # Flask Debug settings
    DEBUG = os.environ.get('DEBUG', 'False').lower() in ('true', '1', 't')
    
    def validate(self):
        """Validate that all required environment variables are set"""
        required_vars = ['SECRET_KEY', 'SUPABASE_URL', 'SUPABASE_KEY', 'BREVO_API_KEY', 'SENDER_EMAIL']
        missing = [var for var in required_vars if not getattr(self, var)]
        
        if missing:
            raise ValueError(f"Missing required environment variables: {', '.join(missing)}")
