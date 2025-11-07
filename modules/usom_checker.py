"""
Click Protection - USOM (Ulusal Siber Olaylara Müdahale Merkezi) Kontrol Modülü

USOM zararlı bağlantılar listesini kontrol eder.
"""

import requests
import os
from datetime import datetime, timedelta
import threading

class USOMChecker:
    """USOM zararlı bağlantı kontrolü"""
    
    def __init__(self, cache_dir=None):
        self.usom_txt_url = "https://www.usom.gov.tr/adres/zararli-baglanti-adresleri.txt"
        self.usom_api_url = "https://www.usom.gov.tr/api/adres"
        
        # Script dizinini bul
        if cache_dir is None:
            import sys
            if getattr(sys, 'frozen', False):
                script_dir = os.path.dirname(sys.executable)
            else:
                script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            cache_dir = os.path.join(script_dir, "data", "cache")
        
        self.cache_dir = cache_dir
        self.cache_file = os.path.join(cache_dir, "usom_cache.txt")
        self.cache_expiry_hours = 24  # Cache 24 saat geçerli
        self.usom_domains = set()
        self.lock = threading.Lock()
        
        # Cache klasörünü oluştur
        os.makedirs(cache_dir, exist_ok=True)
        
        # Cache'den yükle veya güncelle
        self._load_or_update_cache()
    
    def _load_or_update_cache(self):
        """Cache'den yükle veya güncelle"""
        try:
            # Cache dosyası var mı ve geçerli mi kontrol et
            if os.path.exists(self.cache_file):
                cache_age = datetime.now() - datetime.fromtimestamp(os.path.getmtime(self.cache_file))
                if cache_age < timedelta(hours=self.cache_expiry_hours):
                    # Cache geçerli, yükle
                    with open(self.cache_file, 'r', encoding='utf-8') as f:
                        self.usom_domains = set(line.strip().lower() for line in f if line.strip())
                    return
            
            # Cache yok veya eski, güncelle
            self._update_cache()
        except Exception as e:
            print(f"USOM cache yükleme hatası: {e}")
            # Hata durumunda boş set kullan
            self.usom_domains = set()
    
    def _update_cache(self):
        """USOM listesini güncelle"""
        try:
            # User-Agent ekle (bazı siteler bot isteklerini reddediyor)
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            # TXT dosyasını indir
            response = requests.get(self.usom_txt_url, timeout=15, headers=headers)
            if response.status_code == 200:
                domains = set()
                lines = response.text.split('\n')
                
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Satırdan domain'i çıkar (tab, boşluk veya virgül ile ayrılmış olabilir)
                    parts = line.replace('\t', ' ').replace(',', ' ').split()
                    if parts:
                        domain = parts[0].lower().strip()
                        # Geçersiz karakterleri temizle
                        domain = domain.split('?')[0].split('#')[0].split('|')[0]
                        # Sadece geçerli domain formatlarını ekle
                        if domain and '.' in domain and len(domain) > 3:
                            # www. ile başlıyorsa kaldır
                            if domain.startswith('www.'):
                                domain = domain[4:]
                            domains.add(domain)
                
                self.usom_domains = domains
                
                # Cache'e kaydet
                os.makedirs(os.path.dirname(self.cache_file), exist_ok=True)
                with open(self.cache_file, 'w', encoding='utf-8') as f:
                    for domain in sorted(domains):
                        f.write(domain + '\n')
                
                print(f"USOM listesi güncellendi: {len(domains)} domain yüklendi")
                return True
            else:
                print(f"USOM liste indirme hatası: HTTP {response.status_code}")
                return False
        except Exception as e:
            print(f"USOM güncelleme hatası: {e}")
            return False
    
    def check_domain(self, domain_or_url):
        """Domain veya URL'yi USOM listesinde kontrol et"""
        try:
            from urllib.parse import urlparse
            
            # Domain'i çıkar
            if '://' in domain_or_url:
                parsed = urlparse(domain_or_url)
                domain = parsed.hostname or domain_or_url
            else:
                domain = domain_or_url.split('/')[0].split(':')[0].split('?')[0].split('#')[0]
            
            if not domain:
                return False, None
            
            domain = domain.lower().strip()
            
            # www. ile başlıyorsa kaldır
            if domain.startswith('www.'):
                domain = domain[4:]
            
            # Port numarasını kaldır
            if ':' in domain:
                domain = domain.split(':')[0]
            
            if not domain or len(domain) < 3:
                return False, None
            
            # Tam eşleşme kontrolü
            if domain in self.usom_domains:
                return True, f"USOM zararlı bağlantılar listesinde bulundu: {domain}"
            
            # Subdomain kontrolü - tüm olası kombinasyonları kontrol et
            # Örnek: subdomain.example.com -> example.com, com
            parts = domain.split('.')
            for i in range(len(parts)):
                check_domain = '.'.join(parts[i:])
                if check_domain and check_domain in self.usom_domains:
                    return True, f"USOM listesinde bulundu (domain: {check_domain})"
            
            # Ters kontrol - USOM listesindeki domain'lerin bu domain'in alt domain'i olup olmadığını kontrol et
            # Örnek: evil.example.com ve example.com USOM listesindeyse
            for usom_domain in self.usom_domains:
                # Tam eşleşme (zaten kontrol edildi, ama yine de kontrol et)
                if domain == usom_domain:
                    return True, f"USOM listesinde bulundu (domain: {usom_domain})"
                # Subdomain kontrolü: domain.usom_domain veya domain == usom_domain
                if domain.endswith('.' + usom_domain):
                    return True, f"USOM listesinde bulundu (subdomain: {usom_domain})"
                # Eşleşme kontrolü: domain içinde usom_domain geçiyorsa
                if usom_domain in domain and len(usom_domain) > 5:  # En az 5 karakter uzunluğunda domain'ler için
                    # Daha kesin kontrol: domain'in sonunda veya noktadan sonra usom_domain geçiyorsa
                    if domain.endswith(usom_domain) or '.' + usom_domain in domain:
                        return True, f"USOM listesinde bulundu (domain: {usom_domain})"
            
            return False, None
        except Exception as e:
            import traceback
            print(f"USOM kontrol hatası: {e}")
            traceback.print_exc()
            return False, f"USOM kontrol hatası: {e}"
    
    def force_update(self):
        """Cache'i zorla güncelle"""
        return self._update_cache()

# Global instance
usom_checker = None

def get_usom_checker():
    """USOM checker instance'ını al"""
    global usom_checker
    if usom_checker is None:
        usom_checker = USOMChecker()
    return usom_checker

