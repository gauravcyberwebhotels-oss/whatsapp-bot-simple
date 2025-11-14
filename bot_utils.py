import time
import random
from datetime import datetime

def get_random_delay():
    """Get random delay between 2-3 minutes"""
    return random.randint(120, 180)

def format_timestamp():
    """Get current timestamp"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def validate_phone_number(phone):
    """Validate and format phone number"""
    import re
    clean_phone = re.sub(r'\D', '', str(phone))
   
    if clean_phone.startswith('91') and len(clean_phone) in [11, 12]:
        return clean_phone
    elif len(clean_phone) == 10:
        return '91' + clean_phone
    elif clean_phone.startswith('+91') and len(clean_phone) == 13:
        return clean_phone[1:]
    elif clean_phone.startswith('0') and len(clean_phone) == 11:
        return '91' + clean_phone[1:]
   
    return clean_phone

def log_activity(message, level="INFO"):
    """Log activity with timestamp"""
    timestamp = format_timestamp()
    print(f"[{timestamp}] [{level}] {message}")