"""
Click Protection - Rate Limiting Modülü

API çağrıları için rate limiting kontrolü.
"""

import time
from collections import deque
from datetime import datetime

class RateLimiter:
    """API çağrıları için rate limiting"""
    
    def __init__(self, max_calls=4, time_window=60):
        """
        Args:
            max_calls: Zaman penceresi içinde izin verilen maksimum çağrı sayısı
            time_window: Zaman penceresi (saniye)
        """
        self.max_calls = max_calls
        self.time_window = time_window
        self.calls = deque()
    
    def can_make_request(self):
        """İstek yapılabilir mi kontrol et"""
        now = datetime.now()
        
        # Eski çağrıları temizle
        while self.calls and (now - self.calls[0]).total_seconds() > self.time_window:
            self.calls.popleft()
        
        # Limit kontrolü
        if len(self.calls) < self.max_calls:
            return True, 0
        
        # Ne kadar beklemeli
        wait_time = self.time_window - (now - self.calls[0]).total_seconds()
        return False, max(0, wait_time)
    
    def record_request(self):
        """İsteği kaydet"""
        self.calls.append(datetime.now())
    
    def wait_if_needed(self):
        """Gerekirse bekle"""
        can_make, wait_time = self.can_make_request()
        if not can_make and wait_time > 0:
            time.sleep(wait_time)
        self.record_request()

