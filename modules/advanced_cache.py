"""
Click Protection - Gelişmiş Cache Modülü

Analiz sonuçlarını cache'ler ve daha hızlı analiz sağlar.
"""

import json
import os
import hashlib
from datetime import datetime, timedelta


class AdvancedCache:
    """Gelişmiş cache yöneticisi"""
    
    def __init__(self, cache_dir, cache_duration_hours=24):
        self.cache_dir = cache_dir
        self.cache_duration = timedelta(hours=cache_duration_hours)
        os.makedirs(cache_dir, exist_ok=True)
    
    def get_cache_key(self, url_or_ip):
        """URL/IP için cache anahtarı oluştur"""
        return hashlib.md5(url_or_ip.encode('utf-8')).hexdigest()
    
    def get_cached_result(self, url_or_ip):
        """
        Cache'den sonuç getir.
        
        Args:
            url_or_ip: Cache'den getirilecek URL/IP
        
        Returns:
            dict veya None: Cache'de varsa sonuç, yoksa None
        """
        cache_key = self.get_cache_key(url_or_ip)
        cache_file = os.path.join(self.cache_dir, f"{cache_key}.json")
        
        if not os.path.exists(cache_file):
            return None
        
        try:
            with open(cache_file, 'r', encoding='utf-8') as f:
                cache_data = json.load(f)
            
            # Cache süresi kontrolü
            cached_time = datetime.fromisoformat(cache_data.get('timestamp', ''))
            if datetime.now() - cached_time > self.cache_duration:
                # Cache süresi dolmuş, dosyayı sil
                os.remove(cache_file)
                return None
            
            return cache_data.get('result')
            
        except Exception:
            return None
    
    def cache_result(self, url_or_ip, result):
        """
        Sonucu cache'le.
        
        Args:
            url_or_ip: Cache'lenecek URL/IP
            result: Cache'lenecek sonuç
        """
        cache_key = self.get_cache_key(url_or_ip)
        cache_file = os.path.join(self.cache_dir, f"{cache_key}.json")
        
        try:
            cache_data = {
                'url_or_ip': url_or_ip,
                'timestamp': datetime.now().isoformat(),
                'result': result
            }
            
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(cache_data, f, ensure_ascii=False, indent=2)
                
        except Exception:
            pass  # Cache hatası kritik değil
    
    def clear_old_cache(self):
        """Süresi dolmuş cache'leri temizle"""
        try:
            for filename in os.listdir(self.cache_dir):
                if filename.endswith('.json'):
                    filepath = os.path.join(self.cache_dir, filename)
                    try:
                        with open(filepath, 'r', encoding='utf-8') as f:
                            cache_data = json.load(f)
                        
                        cached_time = datetime.fromisoformat(cache_data.get('timestamp', ''))
                        if datetime.now() - cached_time > self.cache_duration:
                            os.remove(filepath)
                    except:
                        # Hatalı cache dosyasını sil
                        try:
                            os.remove(filepath)
                        except:
                            pass
        except Exception:
            pass
    
    def clear_all_cache(self):
        """Tüm cache'i temizle"""
        try:
            for filename in os.listdir(self.cache_dir):
                if filename.endswith('.json'):
                    try:
                        os.remove(os.path.join(self.cache_dir, filename))
                    except:
                        pass
        except Exception:
            pass

