import requests
import logging
from config import Config

logger = logging.getLogger(__name__)

class SupabaseClient:
    def __init__(self):
        self.url = Config.SUPABASE_URL
        self.key = Config.SUPABASE_KEY
        self.headers = {
            'Authorization': f'Bearer {self.key}',
            'apikey': self.key,
            'Content-Type': 'application/json'
        }
    
    def insert(self, table, data):
        """Insert data into Supabase table"""
        try:
            response = requests.post(
                f"{self.url}/rest/v1/{table}",
                headers=self.headers,
                json=data,
                timeout=10
            )
            if response.status_code in [200, 201]:
                return response.json()
            else:
                logger.error(f"Supabase insert error: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            logger.error(f"Supabase insert exception: {e}")
            return None
    
    def select(self, table, filters=None):
        """Select data from Supabase table"""
        try:
            url = f"{self.url}/rest/v1/{table}"
            if filters:
                filter_str = '&'.join([f"{k}=eq.{v}" for k, v in filters.items()])
                url = f"{url}?{filter_str}"
            
            response = requests.get(url, headers=self.headers, timeout=10)
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Supabase select error: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            logger.error(f"Supabase select exception: {e}")
            return None
    
    def update(self, table, filters, data):
        """Update data in Supabase table"""
        try:
            filter_str = '&'.join([f"{k}=eq.{v}" for k, v in filters.items()])
            url = f"{self.url}/rest/v1/{table}?{filter_str}"
            
            response = requests.patch(url, headers=self.headers, json=data, timeout=10)
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Supabase update error: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            logger.error(f"Supabase update exception: {e}")
            return None
    
    def delete(self, table, filters):
        """Delete data from Supabase table"""
        try:
            filter_str = '&'.join([f"{k}=eq.{v}" for k, v in filters.items()])
            url = f"{self.url}/rest/v1/{table}?{filter_str}"
            
            response = requests.delete(url, headers=self.headers, timeout=10)
            if response.status_code == 204:
                return True
            else:
                logger.error(f"Supabase delete error: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            logger.error(f"Supabase delete exception: {e}")
            return False

# Global Supabase client instance
supabase_client = SupabaseClient()

def create_client(url, key):
    """Factory function to create Supabase client"""
    return SupabaseClient()
