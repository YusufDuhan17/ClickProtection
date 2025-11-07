"""
Click Protection - URL/IP Güvenlik Analiz Aracı
Copyright (C) 2024  Yusuf Duhan Şahin

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import re
import requests
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk, simpledialog
from urllib.parse import urlparse, parse_qs
from datetime import datetime
from whois.parser import PywhoisError
import whois
import Levenshtein
import tldextract
import ipaddress
import base64
import ssl
import socket
import configparser
import os
import sys
import idna
import threading
import webbrowser

# Görüntü işleme için Pillow kütüphanesini içe aktarın
from PIL import Image, ImageTk

# Güvenlik modülleri
try:
    from modules.security import SecureConfig
    SECURITY_AVAILABLE = True
except ImportError:
    SECURITY_AVAILABLE = False

try:
    from modules.utils import is_valid_url, normalize_url, sanitize_filename, is_ip_address as utils_is_ip_address
    UTILS_AVAILABLE = True
except ImportError:
    UTILS_AVAILABLE = False

try:
    from modules.logger import logger
    LOGGER_AVAILABLE = True
except ImportError:
    LOGGER_AVAILABLE = False
    # Basit logger fallback
    class DummyLogger:
        def debug(self, msg): pass
        def info(self, msg): pass
        def warning(self, msg): pass
        def error(self, msg, exc_info=False): pass
        def critical(self, msg, exc_info=False): pass
    logger = DummyLogger()

try:
    from modules.rate_limiter import RateLimiter
    RATE_LIMITER_AVAILABLE = True
except ImportError:
    RATE_LIMITER_AVAILABLE = False

try:
    from modules.usom_checker import get_usom_checker
    USOM_AVAILABLE = True
except ImportError:
    USOM_AVAILABLE = False

try:
    from modules.export import ExportManager
    EXPORT_AVAILABLE = True
except ImportError:
    EXPORT_AVAILABLE = False
    ExportManager = None

try:
    from modules.ip_reputation import IPReputationChecker
    IP_REPUTATION_AVAILABLE = True
except ImportError:
    IP_REPUTATION_AVAILABLE = False
    IPReputationChecker = None

try:
    from modules.certificate_transparency import CertificateTransparencyChecker
    CT_AVAILABLE = True
except ImportError:
    CT_AVAILABLE = False
    CertificateTransparencyChecker = None

try:
    from modules.advanced_cache import AdvancedCache
    CACHE_AVAILABLE = True
except ImportError:
    CACHE_AVAILABLE = False
    AdvancedCache = None

try:
    from modules.ml_scorer import MLScorer
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    MLScorer = None 

class URLAnalyzerApp:
    def __init__(self, master):
        self.master = master
        master.title("Click Protection - URL/IP Güvenlik Analiz Aracı")
        master.geometry("850x780")
        master.resizable(False, False)
        
        # Script dizinini doğru bul (EXE veya Python script için)
        if getattr(sys, 'frozen', False):
            # PyInstaller ile oluşturulmuş EXE
            exe_path = sys.executable
            exe_dir = os.path.dirname(exe_path)
            
            # Eğer masaüstündeyse, proje klasörünü bul
            desktop_paths = [
                os.path.join(os.path.expanduser("~"), "Desktop"),
                os.path.join(os.path.expanduser("~"), "Masaüstü")
            ]
            
            is_on_desktop = any(desktop in exe_path for desktop in desktop_paths)
            
            if is_on_desktop:
                # Masaüstündeki EXE'den proje klasörünü bul
                # Tüm olası proje klasörlerini kontrol et
                base_dirs = [
                    os.path.join(os.path.expanduser("~"), "Desktop"),
                    os.path.join(os.path.expanduser("~"), "Masaüstü")
                ]
                
                possible_dirs = []
                for base in base_dirs:
                    # "Yaptığım çalışmalar" klasörünü ara
                    works_dir = os.path.join(base, "Yaptığım çalışmalar", "ClickProtection", "Click_Protection")
                    if os.path.exists(works_dir):
                        possible_dirs.append(works_dir)
                    # Doğrudan "ClickProtection" klasörünü ara
                    click_dir = os.path.join(base, "ClickProtection", "Click_Protection")
                    if os.path.exists(click_dir):
                        possible_dirs.append(click_dir)
                
                # data klasörünü içeren ilk dizini bul
                found = False
                for dir_path in possible_dirs:
                    data_path = os.path.join(dir_path, "data")
                    if os.path.exists(data_path) or os.path.exists(dir_path):
                        self.script_dir = dir_path
                        found = True
                        # data klasörü yoksa oluştur
                        if not os.path.exists(data_path):
                            os.makedirs(data_path, exist_ok=True)
                        break
                
                if not found:
                    # Proje klasörü bulunamadıysa, masaüstünde data klasörü oluşturma
                    # Bunun yerine kullanıcının belgeler klasöründe oluştur
                    docs_dir = os.path.join(os.path.expanduser("~"), "Documents", "ClickProtection")
                    data_dir = os.path.join(docs_dir, "data")
                    os.makedirs(data_dir, exist_ok=True)
                    self.script_dir = docs_dir
            else:
                # Masaüstünde değilse, EXE'nin bulunduğu klasörü kullan
                self.script_dir = exe_dir
        else:
            # Normal Python script
            self.script_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Data klasörünü script dizininde oluştur (yoksa)
        data_dir = os.path.join(self.script_dir, 'data')
        try:
            os.makedirs(data_dir, exist_ok=True)
        except:
            pass
        
        # Çalışma dizinini script dizinine ayarla (masaüstünde data klasörü oluşmasını önlemek için)
        try:
            original_cwd = os.getcwd()
            os.chdir(self.script_dir)
            # Çalışma dizinini değiştirdikten sonra tekrar kontrol et
            if os.getcwd() != self.script_dir:
                # Eğer chdir çalışmadıysa, environment variable ile dene
                os.environ['PWD'] = self.script_dir
        except Exception as e:
            logger.warning(f"Çalışma dizini değiştirilemedi: {e}")
            # Fallback: environment variable
            try:
                os.environ['PWD'] = self.script_dir
            except:
                pass

        # Logoyu pencere simgesi olarak ayarla
        try:
            logo_path = os.path.join(self.script_dir, "assets", "CLICKPROLOGO.png")
            if os.path.exists(logo_path):
                icon_image = Image.open(logo_path)
                photo = ImageTk.PhotoImage(icon_image)
                self.master.iconphoto(True, photo)
                self.logo_image = photo  # Referansı tut
        except Exception as e:
            logger.warning(f"Logo yüklenirken hata: {e}", exc_info=True)

        # Modern renk paleti - HD ve canlı renkler
        self.primary_bg = "#FFFFFF"  # Beyaz arka plan (daha net)
        self.dark_blue_bg = "#1E3A8A"  # Modern mavi header
        self.text_color_dark = "#111827"  # Çok koyu siyah (daha net okunur)
        self.text_color_light = "#374151"  # Koyu gri metin (daha net)
        self.button_color = "#2563EB"  # Canlı mavi buton
        self.button_hover_color = "#1D4ED8"  # Hover efekti
        self.button_text_color = "#FFFFFF"
        self.result_box_bg = "#FFFFFF"  # Beyaz sonuç kutusu
        self.white_color = "#FFFFFF" 
        self.dark_gray_detail = "#4B5563"  # Daha koyu (daha net)
        self.light_green = "#059669"  # Daha canlı yeşil
        self.accent_purple = "#7C3AED"  # Daha canlı mor
        self.card_bg = "#FFFFFF"  # Card arka planı
        self.card_border = "#D1D5DB"  # Daha belirgin border  # Card kenarlık 

        master.config(bg=self.primary_bg) 

        # Güvenlik modülleri başlatma
        if SECURITY_AVAILABLE:
            try:
                self.secure_config = SecureConfig()
                logger.info("Güvenlik modülü başarıyla yüklendi")
            except Exception as e:
                logger.error(f"Güvenlik modülü yüklenirken hata: {e}", exc_info=True)
                self.secure_config = None
        else:
            self.secure_config = None
            logger.warning("Güvenlik modülü bulunamadı, API anahtarları şifrelenmeden saklanacak")

        # Rate limiter başlatma
        if RATE_LIMITER_AVAILABLE:
            self.rate_limiter = RateLimiter(max_calls=4, time_window=60)
            logger.info("Rate limiter başlatıldı")
        else:
            self.rate_limiter = None
            logger.warning("Rate limiter modülü bulunamadı")

        # USOM checker başlatma
        if USOM_AVAILABLE:
            try:
                self.usom_checker = get_usom_checker()
                logger.info("USOM checker başlatıldı")
            except Exception as e:
                logger.error(f"USOM checker başlatma hatası: {e}", exc_info=True)
                self.usom_checker = None
        else:
            self.usom_checker = None
            logger.warning("USOM checker modülü bulunamadı")

        self.config = configparser.ConfigParser()
        self.config_path = self._get_config_path()
        self._load_config()

        self.suspicious_keywords = [k.strip().lower() for k in self.config['AnalysisSettings']['suspicious_keywords'].split(',') if k.strip()]
        self.suspicious_extensions = [e.strip().lower() for e in self.config['AnalysisSettings']['suspicious_extensions'].split(',') if e.strip()]
        
        # Dosya yollarını config'den al ve data klasörüne göre ayarla
        blacklist_file_config = self.config['Files']['blacklist_file']
        real_domains_file_config = self.config['Files']['real_domains_file']
        
        # Eğer config'de data/ prefix'i yoksa ekle
        if not blacklist_file_config.startswith('data/'):
            blacklist_file_config = os.path.join('data', blacklist_file_config)
        if not real_domains_file_config.startswith('data/'):
            real_domains_file_config = os.path.join('data', real_domains_file_config)
        
        # Dosya adlarını sanitize et (path traversal koruması)
        if UTILS_AVAILABLE:
            self.blacklist_file = sanitize_filename(os.path.basename(blacklist_file_config))
            self.real_domains_file = sanitize_filename(os.path.basename(real_domains_file_config))
        else:
            self.blacklist_file = os.path.basename(blacklist_file_config)
            self.real_domains_file = os.path.basename(real_domains_file_config)
        
        # Tam yolu oluştur (script_dir kullan)
        self.blacklist_file = os.path.join(self.script_dir, 'data', self.blacklist_file)
        self.real_domains_file = os.path.join(self.script_dir, 'data', self.real_domains_file)
        
        # Config dosyasında olmayan ayarların varsayılan değerlerle yüklenmesi sağlanıyor
        self.levenshtein_threshold = int(self.config['AnalysisSettings'].get('levenshtein_threshold', '1'))
        self.path_length_threshold = int(self.config['AnalysisSettings'].get('path_length_threshold', '50'))
        self.encoded_char_threshold = int(self.config['AnalysisSettings'].get('encoded_char_threshold', '5'))
        self.risk_threshold_safe = int(self.config['RiskThresholds'].get('safe', '20'))
        self.risk_threshold_suspicious = int(self.config['RiskThresholds'].get('suspicious', '60'))

        # API anahtarlarını güvenli şekilde yükle
        self.vt_api_key = self._load_api_key_safely('virustotal')
        self.abuseipdb_api_key = self._load_api_key_safely('abuseipdb')

        # Cache yöneticisi
        if CACHE_AVAILABLE:
            cache_dir = os.path.join(self.script_dir, 'data', 'cache', 'analysis')
            self.advanced_cache = AdvancedCache(cache_dir, cache_duration_hours=24)
            # Eski cache'leri temizle
            self.advanced_cache.clear_old_cache()
        else:
            self.advanced_cache = None

        # ML Scorer
        if ML_AVAILABLE:
            ml_dir = os.path.join(self.script_dir, 'data', 'ml')
            self.ml_scorer = MLScorer(ml_dir)
        else:
            self.ml_scorer = None

        # IP Reputation Checker
        if IP_REPUTATION_AVAILABLE:
            self.ip_reputation_checker = IPReputationChecker(self.abuseipdb_api_key)
        else:
            self.ip_reputation_checker = None

        # Certificate Transparency Checker
        if CT_AVAILABLE:
            self.ct_checker = CertificateTransparencyChecker()
        else:
            self.ct_checker = None

        self.analysis_running = False 
        self.history = [] 
        self.MAX_HISTORY_SIZE = 10 
        self.last_analyzed_url = ""
        self.last_analysis_data = None  # Son analiz sonuçlarını saklamak için
        
        # Export manager
        if EXPORT_AVAILABLE:
            self.export_manager = ExportManager(self.script_dir)
        else:
            self.export_manager = None
        
        logger.info("URLAnalyzerApp başlatıldı") 

        self._create_widgets()
        self._load_history() 

        self.issue_details = {
            "ip_in_url": {"text": "URL'de doğrudan IP adresi kullanımı, meşru sitelerde nadiren görülür ve genellikle şüpheli amaçlar için kullanılır.", "score": 20},
            "at_symbol": {"text": "URL'de '@' sembolü, kullanıcı adı ve şifre gizleme veya gerçek domaini maskeleme amacıyla kullanılabilir.", "score": 20},
            "multiple_subdomains": {"text": "Çok fazla subdomain, URL'yi karmaşıklaştırarak gerçek alan adını gizlemeye çalışabilir.", "score": 10},
            "suspicious_keywords": {"text": "URL'de 'login', 'free', 'update' gibi şüpheli anahtar kelimeler, oltalama girişimlerinde sıkça görülür.", "score": 10},
            "suspicious_extensions": {"text": "URL'nin tehlikeli dosya uzantılarıyla bitmesi (örn. .exe, .scr), kötü amaçlı yazılım indirme riskini gösterir.", "score": 40},
            "suspicious_parameters": {"text": "URL'deki izleme parametreleri (örn. utm_source), oltalama kampanyalarında izleme veya yönlendirme için kullanılabilir.", "score": 15},
            "long_path": {"text": "URL yolu çok uzun. Bu, zararlı veya karmaşık bir yapıya işaret edebilir.", "score": 10},
            "encoded_path_query": {"text": "URL yolunda veya sorgu parametrelerinde kodlanmış (encoded) karakterler tespit edildi. Bu, gizli kötü amaçlı kod veya veri taşımak için kullanılabilir.", "score": 15},
            "obfuscated_parameters": {"text": "URL sorgu parametreleri şifrelenmiş veya anlaşılması zor karakterler içeriyor. Bu, kötü amaçlı aktiviteyi gizlemeye çalışıyor olabilir.", "score": 20},
            "domain_age_new": {"text": "Domain çok yeni oluşturulmuş. Yeni domainler genellikle kötü amaçlı faaliyetler için kullanılır ve kısa ömürlü olabilir.", "score": 50},
            "domain_age_young": {"text": "Domain yaşı genç. Yeni domainler riskli olabilir ancak henüz erken aşamada.", "score": 30},
            "domain_age_moderate": {"text": "Domain yaşı orta seviyede. Dikkatli olmakta fayda var.", "score": 10},
            "domain_age_unknown": {"text": "Domain oluşturulma tarihi bulunamadı. WHOIS bilgileri gizlenmiş olabilir, bu da şüpheli bir durumdur.", "score": 20},
            "whois_error": {"text": "WHOIS sorgusu yapılamadı veya domain bulunamadı. Bu durum, alan adının gizlenmeye çalışıldığını veya mevcut olmadığını gösterebilir.", "score": 10},
            "similar_domain": {"text": "URL, bilinen meşru bir alan adına çok benziyor (typosquatting). Bu, kullanıcıları kandırmak için yapılan bir oltalama girişimi olabilir.", "score": 30},
            "punycode_detected": {"text": "Punycode (IDN) kullanımı tespit edildi. Gerçek alan adını taklit etmek için benzer görünen karakterler kullanılmış olabilir.", "score": 25},
            "ssl_expired": {"text": "SSL sertifikasının süresi dolmuş. Güvenli bağlantı sağlanamaz, bu da sitenin bakımsız veya kötü amaçlı olduğunu gösterebilir.", "score": 30},
            "ssl_soon_expire": {"text": "SSL sertifikası yakında sona erecek. Sitenin güncel olmadığını veya yenilenmesinin ihmal edildiğini gösterebilir.", "score": 10},
            "ssl_error": {"text": "SSL sertifikasında hata oluştu. Güvenli bağlantı kurulamadı veya sertifika geçersiz.", "score": 15},
            "ssl_timeout": {"text": "SSL sertifika kontrolü zaman aşımına uğradı. Sunucu yanıt vermiyor veya bağlantı sorunları var.", "score": 10},
            "ssl_connection_error": {"text": "SSL sertifika kontrolü bağlantı hatası. Ağ veya sunucu tarafında bir sorun olabilir.", "score": 10},
            "ssl_ip_address": {"text": "IP adresleri için doğrudan SSL sertifikası kontrolü genellikle geçerli değildir, çünkü sertifikalar genellikle alan adları için verilir.", "score": 10},
            "http_status_redirect": {"text": "URL yönlendirme yapıyor. Aşırı veya şüpheli yönlendirmeler kötü amaçlı olabilir.", "score": 10},
            "http_status_forbidden": {"text": "Erişim yasaklandı (403). Sitenin erişime kapalı olması veya kısıtlı olması şüpheli olabilir.", "score": 15},
            "http_status_not_found": {"text": "Sayfa bulunamadı (404). Bu, kötü amaçlı bir sitenin kaldırıldığını veya URL'nin yanlış olduğunu gösterebilir.", "score": 20},
            "http_status_server_error": {"text": "Sunucu hatası (5xx). Sunucunun düzgün çalışmadığını veya kötü amaçlı bir sunucu olduğunu gösterebilir.", "score": 30},
            "http_status_unknown": {"text": "Bilinmeyen HTTP durum kodu. Sunucudan anormal bir yanıt alındı.", "score": 20},
            "http_status_connection_error": {"text": "HTTP durumu alınamadı (Bağlantı/İstek hatası). URL'ye erişilemiyor.", "score": 10},
            "virustotal_malicious": {"text": "VirusTotal kötü amaçlı içerik buldu. Çeşitli güvenlik motorları bu URL'yi tehlikeli olarak işaretledi.", "score": 40},
            "virustotal_no_record": {"text": "VirusTotal'da URL kaydı bulunamadı. Bu yeni veya nadir bir URL olabilir, bu da riskli olabileceği anlamına gelir.", "score": 20},
            "virustotal_api_error": {"text": "VirusTotal API hatası. API anahtarınız geçersiz veya kullanım limitiniz aşılmış olabilir.", "score": 10},
            "usom_malicious": {"text": "Bu URL/USOM (Ulusal Siber Olaylara Müdahale Merkezi) zararlı bağlantılar listesinde bulunuyor. Resmi olarak zararlı olarak işaretlenmiş.", "score": 60},
            "usom_error": {"text": "USOM kontrolü yapılamadı. İnternet bağlantınızı kontrol edin.", "score": 0},
            "url_shortener": {"text": "URL kısaltma servisi kullanılıyor. Gerçek hedef URL görünmüyor, bu riskli olabilir.", "score": 15},
            "non_standard_port": {"text": "Standart olmayan port numarası kullanılıyor. Bu şüpheli olabilir.", "score": 10},
            "blacklisted_domain_ip": {"text": "Bu domain/IP, yerel kara listenizde bulunuyor. Daha önce kötü amaçlı olarak işaretlenmiş demektir.", "score": 50},
            "safelisted_domain_ip": {"text": "Bu domain/IP, yerel güvenli listelerinizde bulunuyor. Güvenli kabul edilmektedir.", "score": 0}, 
        }

    def _get_config_path(self):
        return os.path.join(self.script_dir, 'data', 'config.ini')

    def _load_api_key_safely(self, api_type='virustotal'):
        """API anahtarını güvenli şekilde yükle (şifreli veya düz metin)"""
        try:
            encrypted_key = self.config['API_Keys'].get(f'{api_type}_api_key_encrypted', '')
            if encrypted_key and self.secure_config:
                try:
                    decrypted = self.secure_config.decrypt(encrypted_key)
                    logger.info("API anahtarı şifreli formattan başarıyla yüklendi")
                    return decrypted
                except Exception as e:
                    logger.warning(f"Şifreli API anahtarı çözülemedi: {e}")
            
            # Fallback: düz metin API anahtarı (eski format)
            plain_key = self.config['API_Keys'].get(f'{api_type}_api_key', '')
            if plain_key:
                logger.warning("API anahtarı düz metin olarak yüklendi. Güvenlik için şifreleme önerilir.")
            return plain_key
        except Exception as e:
            logger.error(f"API anahtarı yüklenirken hata: {e}", exc_info=True)
            return ''

    def _save_api_key_safely(self, api_key, api_type='virustotal'):
        """API anahtarını güvenli şekilde kaydet (şifrele)"""
        try:
            if api_key and self.secure_config:
                encrypted = self.secure_config.encrypt(api_key)
                self.config['API_Keys'][f'{api_type}_api_key_encrypted'] = encrypted
                # Eski düz metin anahtarı sil
                if f'{api_type}_api_key' in self.config['API_Keys']:
                    del self.config['API_Keys'][f'{api_type}_api_key']
                logger.info(f"{api_type} API anahtarı şifrelenerek kaydedildi")
            elif api_key:
                # Şifreleme yoksa düz metin kaydet (uyarı ile)
                self.config['API_Keys'][f'{api_type}_api_key'] = api_key
                logger.warning(f"{api_type} API anahtarı düz metin olarak kaydedildi (güvenlik modülü yok)")
            else:
                # API anahtarını sil
                if f'{api_type}_api_key' in self.config['API_Keys']:
                    del self.config['API_Keys'][f'{api_type}_api_key']
                if f'{api_type}_api_key_encrypted' in self.config['API_Keys']:
                    del self.config['API_Keys'][f'{api_type}_api_key_encrypted']
        except Exception as e:
            logger.error(f"API anahtarı kaydedilirken hata: {e}", exc_info=True)

    def _load_config(self):
        if not os.path.exists(self.config_path):
            self.config['API_Keys'] = {'virustotal_api_key': ''}
            self.config['AnalysisSettings'] = {
                'suspicious_keywords': "login,free,update,verify,account,secure,paypal,bank,click,download",
                'suspicious_extensions': ".exe,.bat,.scr,.zip,.rar,.msi",
                'levenshtein_threshold': '1',
                'path_length_threshold': '50', 
                'encoded_char_threshold': '5' 
            }
            self.config['Files'] = {
                'blacklist_file': 'data/blacklist.txt',
                'real_domains_file': 'data/real_domains.txt',
                'history_file': 'data/history.txt' 
            }
            self.config['RiskThresholds'] = {
                'safe': '20',
                'suspicious': '60'
            }
            try:
                with open(self.config_path, 'w') as configfile:
                    self.config.write(configfile)
            except IOError as e:
                messagebox.showerror("Hata", f"Config dosyası oluşturulurken hata: {e}\nLütfen uygulama klasörünün yazma izinlerini kontrol edin.")
        else:
            self.config.read(self.config_path)
        
        # Yeni ayarları yükle
        self.path_length_threshold = int(self.config['AnalysisSettings'].get('path_length_threshold', '50'))
        self.encoded_char_threshold = int(self.config['AnalysisSettings'].get('encoded_char_threshold', '5'))


    def _save_config(self):
        try:
            # Dosya izinlerini kontrol et ve ayarla
            with open(self.config_path, 'w') as configfile:
                self.config.write(configfile)
            
            # Güvenlik: Dosya izinlerini kısıtla (sadece sahip okuyabilsin)
            try:
                os.chmod(self.config_path, 0o600)
            except Exception:
                pass  # Windows'ta chmod çalışmayabilir
            
            logger.debug("Config dosyası başarıyla kaydedildi")
            return True
        except Exception as e:
            error_msg = "Ayarlar kaydedilirken bir hata oluştu."
            logger.error(f"Config kaydetme hatası: {e}", exc_info=True)
            messagebox.showerror("Hata", error_msg)
            return False

    def _create_widgets(self):
        # Modern header - Logo ile
        # Kompakt header - Daha modern görünüm
        header_frame = tk.Frame(self.master, bg=self.dark_blue_bg, relief=tk.FLAT)
        header_frame.pack(fill=tk.X, pady=(0, 8))
        
        title_frame = tk.Frame(header_frame, bg=self.dark_blue_bg)
        title_frame.pack(pady=6)
        
        # Logo görseli ekle - Daha küçük
        try:
            logo_path = os.path.join(self.script_dir, "assets", "CLICKPROLOGO.png")
            if os.path.exists(logo_path):
                logo_img = Image.open(logo_path)
                logo_img = logo_img.resize((28, 28), Image.Resampling.LANCZOS)  # 40'tan 28'e
                logo_photo = ImageTk.PhotoImage(logo_img)
                logo_label = tk.Label(title_frame, image=logo_photo, bg=self.dark_blue_bg)
                logo_label.image = logo_photo  # Referansı tut
                logo_label.pack(side=tk.LEFT, padx=(0, 8))
        except:
            pass
        
        title_text_frame = tk.Frame(title_frame, bg=self.dark_blue_bg)
        title_text_frame.pack(side=tk.LEFT)
        
        tk.Label(title_text_frame, text="CLICK PROTECTION", 
                font=("Segoe UI", 14, "bold"),  # 20'den 14'e
                fg=self.white_color, bg=self.dark_blue_bg).pack()
        
        tk.Label(title_text_frame, text="URL ve IP Güvenlik Analiz Aracı", 
                font=("Segoe UI", 8),  # 9'dan 8'e
                fg="#93C5FD", bg=self.dark_blue_bg).pack()

        # API Key girişi - Card tasarımı (YUKARI TAŞINDI) - Kompakt
        api_card = tk.Frame(self.master, bg=self.card_bg, relief=tk.FLAT, bd=1, highlightbackground=self.card_border, highlightthickness=1)
        api_card.pack(fill=tk.X, padx=15, pady=(0, 8))
        
        tk.Label(api_card, text="🔑 VirusTotal API Key (Opsiyonel)", 
                font=("Segoe UI", 10, "bold"),  # 11'den 10'a
                fg=self.text_color_dark, bg=self.card_bg,
                anchor="w").pack(fill=tk.X, padx=12, pady=(8, 4))
        
        self.api_entry = tk.Entry(api_card, width=70, show="*", 
                                 fg="#111827", 
                                 bg="#FFFFFF", 
                                 insertbackground="#111827",
                                 font=("Segoe UI", 11),
                                 relief=tk.FLAT,
                                 bd=8,
                                 highlightthickness=2,
                                 highlightcolor=self.button_color,
                                 highlightbackground="#D1D5DB")
        self.api_entry.pack(fill=tk.X, padx=12, pady=(0, 8))

        self.remember_api_var = tk.BooleanVar(value=bool(self.vt_api_key))
        if self.remember_api_var.get():
            self.api_entry.insert(0, self.vt_api_key)
            self.api_entry.config(state='disabled')
        else:
            self.api_entry.insert(0, "")

        # API seçenekleri
        api_options_frame = tk.Frame(api_card, bg=self.card_bg)
        api_options_frame.pack(fill=tk.X, padx=12, pady=(0, 10))
        
        self.remember_api_check = tk.Checkbutton(api_options_frame, 
                                                 text="API anahtarını kaydet", 
                                                 variable=self.remember_api_var, 
                                                 command=self._toggle_api_entry_state,
                                                 font=("Segoe UI", 9),
                                                 fg=self.text_color_light,
                                                 bg=self.card_bg,
                                                 activebackground=self.card_bg,
                                                 selectcolor=self.card_bg)
        self.remember_api_check.pack(side=tk.LEFT)
        
        tk.Button(api_options_frame, text="🔑 API Anahtarı Al", 
                 command=self._open_virustotal_apikey_page, 
                 bg="#10B981", 
                 fg=self.button_text_color, 
                 font=("Segoe UI", 9),
                 relief=tk.FLAT,
                 padx=12,
                 pady=4,
                 cursor="hand2",
                 activebackground="#059669").pack(side=tk.LEFT, padx=(10, 0))

        # URL girişi - Card tasarımı (AŞAĞI TAŞINDI, Kontrol Et butonu yanında)
        url_card = tk.Frame(self.master, bg=self.card_bg, relief=tk.FLAT, bd=1, highlightbackground=self.card_border, highlightthickness=1)
        url_card.pack(fill=tk.X, padx=15, pady=(0, 8))
        
        url_header_frame = tk.Frame(url_card, bg=self.card_bg)
        url_header_frame.pack(fill=tk.X, padx=12, pady=(8, 4))
        
        tk.Label(url_header_frame, text="🔗 URL veya IP Adresi", 
                font=("Segoe UI", 10, "bold"),  # 11'den 10'a
                fg=self.text_color_dark, bg=self.card_bg,
                anchor="w").pack(side=tk.LEFT)
        
        # Ana kontrol butonu - Küçük ve URL input'unun yanında
        self.check_button = tk.Button(url_header_frame, text="🔍 Kontrol Et", 
                                      command=self._start_analysis_thread, 
                                      font=("Segoe UI", 10, "bold"),
                                      bg=self.button_color, 
                                      fg=self.button_text_color,
                                      relief=tk.FLAT,
                                      padx=20,
                                      pady=6,
                                      cursor="hand2",
                                      activebackground=self.button_hover_color)
        self.check_button.pack(side=tk.RIGHT, padx=(10, 0))
        
        self.url_entry = tk.Entry(url_card, width=70, 
                                 fg="#111827",  # Çok koyu siyah (daha net)
                                 bg="#FFFFFF",  # Beyaz arka plan (daha net)
                                 insertbackground="#111827",
                                 font=("Segoe UI", 11),  # Daha büyük font
                                 relief=tk.FLAT,
                                 bd=8,
                                 highlightthickness=2,
                                 highlightcolor=self.button_color,
                                 highlightbackground="#D1D5DB")
        self.url_entry.pack(fill=tk.X, padx=12, pady=(0, 10))

        # Sonuç kutusu - Card tasarımı
        result_card = tk.Frame(self.master, bg=self.card_bg, relief=tk.FLAT, bd=1, highlightbackground=self.card_border, highlightthickness=1)
        result_card.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 8))
        
        tk.Label(result_card, text="📊 Analiz Sonuçları", 
                font=("Segoe UI", 10, "bold"),  # 11'den 10'a
                fg=self.text_color_dark, bg=self.card_bg,
                anchor="w").pack(fill=tk.X, padx=12, pady=(8, 4))
        
        self.result_box = scrolledtext.ScrolledText(result_card, width=80, height=12, 
                                                    state='disabled', 
                                                    fg="#111827",  # Çok koyu siyah (daha net)
                                                    bg="#FFFFFF",  # Beyaz arka plan (daha net)
                                                    insertbackground="#111827",
                                                    font=("Segoe UI", 10),  # Daha büyük ve net font
                                                    wrap=tk.WORD,
                                                    relief=tk.FLAT,
                                                    bd=0,
                                                    padx=15,
                                                    pady=12)
        self.result_box.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 10))

        # Risk göstergesi ve progress bar - Card içinde
        risk_card = tk.Frame(self.master, bg=self.card_bg, relief=tk.FLAT, bd=1, highlightbackground=self.card_border, highlightthickness=1)
        risk_card.pack(fill=tk.X, padx=15, pady=(0, 8))
        
        risk_inner = tk.Frame(risk_card, bg=self.card_bg)
        risk_inner.pack(padx=15, pady=10)
        
        self.risk_label = tk.Label(risk_inner, text="0% - Bilgi Yok", 
                                   font=("Segoe UI", 14, "bold"),  # 16'dan 14'e
                                   bg=self.card_bg, fg=self.text_color_dark)
        self.risk_label.pack(pady=(0, 6))

        # Progress bar
        s = ttk.Style()
        s.theme_use('default')
        s.configure("risk.Horizontal.TProgressbar", 
                   background=self.button_color, 
                   troughcolor="#E5E7EB", 
                   bordercolor="#E5E7EB",
                   thickness=18)  # 20'den 18'e
        self.risk_bar = ttk.Progressbar(risk_inner, length=350, mode="determinate", 
                                        maximum=100, style="risk.Horizontal.TProgressbar")
        self.risk_bar.pack(pady=(0, 12))  # Butonlara daha fazla boşluk

        # Yardımcı butonlar - Risk card'ın içinde - Daha belirgin
        helper_frame = tk.Frame(risk_inner, bg=self.card_bg)
        helper_frame.pack(pady=(0, 8))  # Alt padding eklendi
        
        self.open_in_browser_button = tk.Button(helper_frame, text="🌐 Tarayıcıda Aç", 
                                               command=self._open_url_in_browser, 
                                               font=("Segoe UI", 10, "bold"),  # 9'dan 10'a, bold eklendi
                                               bg=self.button_color, 
                                               fg=self.button_text_color,
                                               relief=tk.FLAT,
                                               state=tk.DISABLED,
                                               padx=20,
                                               pady=8,  # 6'dan 8'e
                                               cursor="hand2",
                                               activebackground=self.button_hover_color,
                                               bd=0,
                                               highlightthickness=2,
                                               highlightbackground=self.button_color)
        self.open_in_browser_button.pack(side=tk.LEFT, padx=6)
        
        self.export_results_button = tk.Button(helper_frame, text="💾 Sonuçları Dışa Aktar", 
                                            command=self._export_results, 
                                            font=("Segoe UI", 10, "bold"),
                                            bg="#10B981", 
                                            fg=self.button_text_color,
                                            relief=tk.FLAT,
                                            state=tk.DISABLED,
                                            padx=22,
                                            pady=8,
                                            cursor="hand2",
                                            activebackground="#059669",
                                            bd=0,
                                            highlightthickness=2,
                                            highlightbackground="#10B981")
        self.export_results_button.pack(side=tk.LEFT, padx=6)
        
        # Loading animasyonu için label
        self.loading_label = tk.Label(helper_frame, text="", 
                                      font=("Segoe UI", 10, "bold"),  # Bold eklendi
                                      bg=self.card_bg,
                                      fg=self.button_color)
        self.loading_label.pack(side=tk.LEFT, padx=12)
        self.loading_dots = 0
        self.loading_animation_id = None
        
        # Alt boşluk ekle - Butonların görünürlüğünü artır
        bottom_spacer = tk.Frame(self.master, bg=self.primary_bg, height=15)
        bottom_spacer.pack(fill=tk.X) 
        
        # Modern menü çubuğu
        menubar = tk.Menu(self.master, bg=self.white_color, fg=self.text_color_dark, 
                         activebackground=self.button_color, activeforeground=self.button_text_color,
                         font=("Segoe UI", 9))
        self.master.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=0, bg=self.white_color, fg=self.text_color_dark,
                           activebackground=self.button_color, activeforeground=self.button_text_color,
                           font=("Segoe UI", 9))
        menubar.add_cascade(label="📁 Dosya", menu=file_menu)
        file_menu.add_command(label="📜 Geçmişi Görüntüle", command=self._show_history_window)
        file_menu.add_separator()
        export_menu = tk.Menu(file_menu, tearoff=0, bg=self.white_color, fg=self.text_color_dark,
                             activebackground=self.button_color, activeforeground=self.button_text_color,
                             font=("Segoe UI", 9))
        file_menu.add_cascade(label="💾 Sonuçları Dışa Aktar", menu=export_menu)
        export_menu.add_command(label="📄 PDF Olarak Kaydet", command=lambda: self._export_results('pdf'))
        export_menu.add_command(label="📊 CSV Olarak Kaydet", command=lambda: self._export_results('csv'))
        export_menu.add_command(label="📋 JSON Olarak Kaydet", command=lambda: self._export_results('json'))
        file_menu.add_separator()
        file_menu.add_command(label="🚪 Çıkış", command=self.master.quit)

        settings_menu = tk.Menu(menubar, tearoff=0, bg=self.white_color, fg=self.text_color_dark,
                               activebackground=self.button_color, activeforeground=self.button_text_color,
                               font=("Segoe UI", 9))
        menubar.add_cascade(label="⚙️ Ayarlar", menu=settings_menu)
        settings_menu.add_command(label="🔧 Ayarları Düzenle", command=self._open_settings_window)
        settings_menu.add_command(label="🚫 Kara Liste", command=lambda: self._edit_list_file(self.blacklist_file, "Kara Liste"))
        settings_menu.add_command(label="✅ Güvenli Domainler", command=lambda: self._edit_list_file(self.real_domains_file, "Güvenli Domainler")) 

    def _toggle_api_entry_state(self):
        if self.remember_api_var.get():
            if self.api_entry.get().strip():
                api_key = self.api_entry.get().strip()
                self.api_entry.config(state='disabled', show="") 
                self.vt_api_key = api_key
                self._save_api_key_safely(api_key)
                self._save_config()
                logger.info("API anahtarı kaydedildi")
            else:
                self.api_entry.config(state='normal', show="*")
                messagebox.showinfo("Bilgi", "API anahtarını kaydetmek için lütfen bir anahtar girin.")
        else:
            self.api_entry.config(state='normal', show="*")
            self._save_api_key_safely('')  # API anahtarını sil
            self._save_config()
            self.vt_api_key = ''
            self.api_entry.delete(0, tk.END)
            logger.info("API anahtarı silindi")

    def _open_virustotal_apikey_page(self):
        """VirusTotal'ın API anahtarı alım sayfasına yönlendirir."""
        url = "https://www.virustotal.com/gui/my-apikey"
        try:
            webbrowser.open_new_tab(url)
            messagebox.showinfo("Bilgi", "VirusTotal'ın ücretsiz API anahtarı alım sayfası tarayıcınızda açıldı. Lütfen adımları takip ederek bir anahtar alın ve uygulamaya yapıştırın.")
        except Exception as e:
            messagebox.showerror("Tarayıcı Hatası", f"VirusTotal sayfası tarayıcıda açılamadı: {e}")

    def _open_settings_window(self):
        settings_window = tk.Toplevel(self.master)
        settings_window.title("Uygulama Ayarları")
        settings_window.geometry("400x500") 
        settings_window.config(bg=self.primary_bg)

        tk.Label(settings_window, text="Şüpheli Anahtar Kelimeler (virgülle ayırın):", bg=self.primary_bg, fg=self.text_color_dark).pack(pady=5)
        self.settings_keywords_entry = tk.Entry(settings_window, width=50, bg=self.result_box_bg, fg=self.text_color_light, insertbackground=self.text_color_light)
        self.settings_keywords_entry.insert(0, ",".join(self.suspicious_keywords))
        self.settings_keywords_entry.pack()

        tk.Label(settings_window, text="Şüpheli Dosya Uzantıları (virgülle ayırın):", bg=self.primary_bg, fg=self.text_color_dark).pack(pady=5)
        self.settings_extensions_entry = tk.Entry(settings_window, width=50, bg=self.result_box_bg, fg=self.text_color_light, insertbackground=self.text_color_light)
        self.settings_extensions_entry.insert(0, ",".join(self.suspicious_extensions))
        self.settings_extensions_entry.pack()

        tk.Label(settings_window, text="Levenshtein Benzerlik Eşiği (0-10 arası):", bg=self.primary_bg, fg=self.text_color_dark).pack(pady=5)
        self.settings_levenshtein_entry = tk.Entry(settings_window, width=10, bg=self.result_box_bg, fg=self.text_color_light, insertbackground=self.text_color_light)
        self.settings_levenshtein_entry.insert(0, str(self.levenshtein_threshold))
        self.settings_levenshtein_entry.pack()

        tk.Label(settings_window, text="Yol Uzunluğu Eşiği (karakter sayısı):", bg=self.primary_bg, fg=self.text_color_dark).pack(pady=5)
        self.settings_path_length_entry = tk.Entry(settings_window, width=10, bg=self.result_box_bg, fg=self.text_color_light, insertbackground=self.text_color_light)
        self.settings_path_length_entry.insert(0, str(self.path_length_threshold))
        self.settings_path_length_entry.pack()

        tk.Label(settings_window, text="Kodlanmış Karakter Eşiği (%):", bg=self.primary_bg, fg=self.text_color_dark).pack(pady=5)
        self.settings_encoded_char_entry = tk.Entry(settings_window, width=10, bg=self.result_box_bg, fg=self.text_color_light, insertbackground=self.text_color_light)
        self.settings_encoded_char_entry.insert(0, str(self.encoded_char_threshold))
        self.settings_encoded_char_entry.pack()

        tk.Label(settings_window, text="Güvenli Risk Eşiği (%):", bg=self.primary_bg, fg=self.text_color_dark).pack(pady=5)
        self.settings_safe_threshold_entry = tk.Entry(settings_window, width=10, bg=self.result_box_bg, fg=self.text_color_light, insertbackground=self.text_color_light)
        self.settings_safe_threshold_entry.insert(0, str(self.risk_threshold_safe))
        self.settings_safe_threshold_entry.pack()

        tk.Label(settings_window, text="Şüpheli Risk Eşiği (%):", bg=self.primary_bg, fg=self.text_color_dark).pack(pady=5)
        self.settings_suspicious_threshold_entry = tk.Entry(settings_window, width=10, bg=self.result_box_bg, fg=self.text_color_light, insertbackground=self.text_color_light)
        self.settings_suspicious_threshold_entry.insert(0, str(self.risk_threshold_suspicious))
        self.settings_suspicious_threshold_entry.pack()

        tk.Button(settings_window, text="Ayarları Kaydet", command=lambda: self._save_settings(settings_window), bg=self.button_color, fg=self.button_text_color).pack(pady=10)

    def _save_settings(self, window):
        try:
            self.suspicious_keywords = [k.strip().lower() for k in self.settings_keywords_entry.get().split(',') if k.strip()]
            self.suspicious_extensions = [e.strip().lower() for e in self.settings_extensions_entry.get().split(',') if e.strip()]
            self.levenshtein_threshold = int(self.settings_levenshtein_entry.get())
            self.path_length_threshold = int(self.settings_path_length_entry.get())
            self.encoded_char_threshold = int(self.settings_encoded_char_entry.get())
            self.risk_threshold_safe = int(self.settings_safe_threshold_entry.get())
            self.risk_threshold_suspicious = int(self.settings_suspicious_threshold_entry.get())

            if not (0 <= self.levenshtein_threshold <= 10):
                raise ValueError("Levenshtein eşiği 0 ile 10 arasında olmalı.")
            if not (0 <= self.path_length_threshold <= 1000): 
                raise ValueError("Yol uzunluğu eşiği 0 ile 1000 arasında olmalı.")
            if not (0 <= self.encoded_char_threshold <= 100): 
                raise ValueError("Kodlanmış karakter eşiği 0 ile 100 arasında olmalı.")
            if not (0 <= self.risk_threshold_safe <= 100 and 0 <= self.risk_threshold_suspicious <= 100):
                raise ValueError("Risk eşikleri 0 ile 100 arasında olmalı.")
            if self.risk_threshold_safe >= self.risk_threshold_suspicious:
                raise ValueError("Güvenli eşik, şüpheli eşikten küçük olmalı.")

            self.config['AnalysisSettings']['suspicious_keywords'] = ",".join(self.suspicious_keywords)
            self.config['AnalysisSettings']['suspicious_extensions'] = ",".join(self.suspicious_extensions)
            self.config['AnalysisSettings']['levenshtein_threshold'] = str(self.levenshtein_threshold)
            self.config['AnalysisSettings']['path_length_threshold'] = str(self.path_length_threshold)
            self.config['AnalysisSettings']['encoded_char_threshold'] = str(self.encoded_char_threshold)
            self.config['RiskThresholds']['safe'] = str(self.risk_threshold_safe)
            self.config['RiskThresholds']['suspicious'] = str(self.risk_threshold_suspicious)

            self._save_config()
            messagebox.showinfo("Başarılı", "Ayarlar başarıyla kaydedildi.")
            window.destroy()
        except ValueError as ve:
            messagebox.showerror("Hata", f"Geçersiz ayar değeri: {ve}")
        except Exception as e:
            messagebox.showerror("Hata", f"Ayarlar kaydedilirken bir hata oluştu: {e}")

    def _start_analysis_thread(self):
        if self.analysis_running:
            messagebox.showinfo("Bilgi", "Analiz zaten devam ediyor, lütfen bekleyin.")
            return

        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Hata", "Lütfen bir URL veya IP girin.")
            return

        # Input validation - URL/IP kontrolü
        if UTILS_AVAILABLE:
            if not is_valid_url(url):
                messagebox.showerror("Hata", "Geçersiz URL veya IP adresi formatı. Lütfen geçerli bir URL veya IP adresi girin.")
                logger.warning(f"Geçersiz URL girişi: {url[:50]}...")
                return
        else:
            # Basit kontrol
            if len(url) > 2048:  # URL uzunluk limiti
                messagebox.showerror("Hata", "URL çok uzun. Maksimum 2048 karakter olmalıdır.")
                return

        current_api_input = self.api_entry.get().strip()
        if self.remember_api_var.get():
            if current_api_input:
                self.vt_api_key = current_api_input
                self._save_api_key_safely(current_api_input)
                self._save_config()
                self.api_entry.config(state='disabled')
            else:
                messagebox.showwarning("Uyarı", "API anahtarını kaydetmek için lütfen bir anahtar girin.")
                self.api_entry.config(state='normal')
                return
        else:
            self.vt_api_key = current_api_input
            self._save_api_key_safely('')  # Kaydetme seçilmediyse sil
            self._save_config()
        
        logger.info(f"Analiz başlatıldı: {url[:50]}...")

        self.result_box.config(state='normal')
        self.result_box.delete("1.0", tk.END)
        self.risk_bar["value"] = 0
        self.risk_label.config(text="Yükleniyor...", fg="#3B82F6")
        self.check_button.config(state=tk.DISABLED, text="Analiz Ediliyor...")
        self.open_in_browser_button.config(state=tk.DISABLED)
        self.export_results_button.config(state=tk.DISABLED)
        self.analysis_running = True
        self.last_analyzed_url = "" 
        self.last_results_text = ""
        
        # Loading animasyonunu başlat
        self._start_loading_animation() 

        analysis_thread = threading.Thread(target=self._run_analysis_in_thread, args=(url,))
        analysis_thread.start()

    def _run_analysis_in_thread(self, url):
        try:
            # URL normalizasyonu
            if UTILS_AVAILABLE:
                normalized_url = normalize_url(url)
            else:
                normalized_url = url
                if self._is_ip_address(url) and not urlparse(url).scheme:
                    normalized_url = "http://" + url
                elif not urlparse(url).scheme:
                    normalized_url = "http://" + url
                
            parsed_url = urlparse(normalized_url)
            if not parsed_url.hostname and not self._is_ip_address(normalized_url):
                error_msg = "Geçersiz URL veya IP adresi formatı."
                logger.warning(f"Geçersiz URL formatı: {url[:50]}...")
                self.master.after(0, lambda: messagebox.showerror("Hata", error_msg))
                self.master.after(0, self._reset_analysis_state)
                return

            issues, vt_analysis_data, domain, score, status, color, subdomains = self._analyze_url(normalized_url)

            self.master.after(0, self._update_gui_with_results, url, issues, vt_analysis_data, domain, score, status, color)
            self.master.after(0, self._add_to_history, url, score, status)
            self.master.after(0, self._update_open_in_browser_button, url, status, score) 

        except Exception as e:
            error_msg = "Analiz sırasında bir hata oluştu. Lütfen tekrar deneyin."
            logger.error(f"Analiz hatası: {e}", exc_info=True)
            self.master.after(0, lambda: messagebox.showerror("Hata", error_msg))
            self.master.after(0, lambda: self.result_box.insert(tk.END, error_msg, "red"))
            self.master.after(0, lambda: self.result_box.config(state='disabled'))
        finally:
            self.master.after(0, self._reset_analysis_state)

    def _update_gui_with_results(self, original_url, issues, vt_analysis_data, domain, score, status, color):
        self.result_box.config(state='normal')
        self.result_box.delete("1.0", tk.END)
        self.result_box.insert(tk.END, f"Analiz Edilen URL/IP: {original_url}\n\n", "bold")
        self.result_box.tag_config("bold", font=("Segoe UI", 11, "bold"), foreground="#111827")

        for i, (line, detail_key) in enumerate(issues):
            tag = ""
            if line.startswith("🔴"): tag = "red"
            elif line.startswith("🟠"): tag = "orange"
            elif line.startswith("🟡"): tag = "yellow"
            elif line.startswith("🟢"): tag = "green_status"
            elif line.startswith("ℹ️"): tag = "info"
            elif line.startswith("🚫"): tag = "dark_red"
            elif line.startswith("✅"): tag = "green_status" 
            elif line.startswith("🔎"): tag = "purple"
            elif line.startswith("⚠️"): tag = "warning"
            
            self.result_box.insert(tk.END, line + "\n", tag)
            
            if detail_key and self.issue_details.get(detail_key):
                details = self.issue_details[detail_key]["text"]
                self.result_box.insert(tk.END, f"    (i) Detay: {details}\n", "info_detail")
                self.result_box.tag_config("info_detail", foreground="#4B5563", font=("Segoe UI", 9, "italic"))

        # Daha net ve canlı renkler
        self.result_box.tag_config("red", foreground="#DC2626", font=("Segoe UI", 10))
        self.result_box.tag_config("dark_red", foreground="#991B1B", font=("Segoe UI", 10, "bold"))
        self.result_box.tag_config("orange", foreground="#EA580C", font=("Segoe UI", 10))
        self.result_box.tag_config("yellow", foreground="#D97706", font=("Segoe UI", 10))
        self.result_box.tag_config("green_status", foreground="#059669", font=("Segoe UI", 10))
        self.result_box.tag_config("info", foreground="#2563EB", font=("Segoe UI", 10))
        self.result_box.tag_config("purple", foreground="#7C3AED", font=("Segoe UI", 10))
        self.result_box.tag_config("warning", foreground="#B45309", font=("Segoe UI", 10))

        self.result_box.insert(tk.END, "\n")
        
        self.result_box.insert(tk.END, "\n🔎 VirusTotal Sonucu:\n", "purple")
        if isinstance(vt_analysis_data, dict):
            self.result_box.insert(tk.END, f"Tarama Sonucu: {vt_analysis_data.get('malicious', 0)} Zararlı, {vt_analysis_data.get('suspicious', 0)} Şüpheli, {vt_analysis_data.get('harmless', 0)} Temiz, {vt_analysis_data.get('undetected', 0)} Tespit Edilmemiş.\n", "vt_result")
            self.result_box.insert(tk.END, f"Toplam Motor Taraması: {vt_analysis_data.get('total_scans', 0)}\n", "vt_result")
            if vt_analysis_data.get('engines_detected'):
                self.result_box.insert(tk.END, "Tespit Eden Motorlar (ilk 5):\n", "vt_header")
                for engine_detail in vt_analysis_data['engines_detected']:
                    self.result_box.insert(tk.END, f"    - {engine_detail}\n", "vt_detail")
                if vt_analysis_data.get('more_engines_count', 0) > 0:
                    self.result_box.insert(tk.END, f"    ... ve diğer {vt_analysis_data['more_engines_count']} motor.\n", "vt_detail")
            else:
                self.result_box.insert(tk.END, "✅ Herhangi bir zararlı veya şüpheli bulgu tespit edilmedi.\n", "green_status")
        else:
            self.result_box.insert(tk.END, f"{vt_analysis_data}\n", "info")
        
        # VirusTotal sonuçları için tag'ler
        self.result_box.tag_config("vt_result", foreground="#111827", font=("Segoe UI", 10))
        self.result_box.tag_config("vt_header", foreground="#7C3AED", font=("Segoe UI", 10, "bold"))
        self.result_box.tag_config("vt_detail", foreground="#4B5563", font=("Segoe UI", 9))

        # Risk göstergesini güncelle
        self.risk_label.config(text=f"{score}% - {status}", fg=color, font=("Segoe UI", 14, "bold"))
        self.risk_bar["value"] = score
        
        # Progress bar rengini risk durumuna göre ayarla
        if score <= self.risk_threshold_safe:
            bar_color = self.light_green
        elif score <= self.risk_threshold_suspicious:
            bar_color = "orange"
        else:
            bar_color = "red"
        
        s = ttk.Style()
        s.configure("risk.Horizontal.TProgressbar", 
                   background=bar_color, 
                   troughcolor="#E5E7EB", 
                   bordercolor="#E5E7EB")
        
        self.result_box.config(state='disabled')
        
        # Export butonunu aktif et
        if hasattr(self, 'export_results_button'):
            self.export_results_button.config(state=tk.NORMAL)
        
        # Loading animasyonunu durdur
        self._stop_loading_animation()
        
        # Analiz sonuçlarını kaydet (export için)
        self.last_analysis_data = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'url': original_url,
            'domain': domain,
            'risk_score': score,
            'risk_status': status,
            'issues': issues,
            'virustotal': vt_analysis_data if isinstance(vt_analysis_data, dict) else {},
            'issue_details': {key: self.issue_details[key] for key in self.issue_details if any(key == issue[1] for issue in issues)}
        }

    def _reset_analysis_state(self):
        self.analysis_running = False
        self._stop_loading_animation()
        self.check_button.config(state=tk.NORMAL, text="Kontrol Et")
        if hasattr(self, 'export_results_button'):
            self.export_results_button.config(state=tk.NORMAL if self.last_analysis_data else tk.DISABLED)
    
    def _start_loading_animation(self):
        """Loading animasyonunu başlat"""
        if hasattr(self, 'loading_animation_id') and self.loading_animation_id:
            self.master.after_cancel(self.loading_animation_id)
        
        self.loading_dots = 0
        self._animate_loading()
    
    def _animate_loading(self):
        """Loading animasyonunu güncelle"""
        if not self.analysis_running:
            if hasattr(self, 'loading_label'):
                self.loading_label.config(text="")
            return
        
        dots = "." * (self.loading_dots % 4)
        if hasattr(self, 'loading_label'):
            self.loading_label.config(text=f"Analiz ediliyor{dots}", fg="#2563EB", font=("Segoe UI", 10, "bold"))
        self.loading_dots += 1
        self.loading_animation_id = self.master.after(500, self._animate_loading)
    
    def _stop_loading_animation(self):
        """Loading animasyonunu durdur"""
        if hasattr(self, 'loading_animation_id') and self.loading_animation_id:
            self.master.after_cancel(self.loading_animation_id)
            self.loading_animation_id = None
        if hasattr(self, 'loading_label'):
            self.loading_label.config(text="")

    def _update_open_in_browser_button(self, url, status, score):
        # Sadece güvenli bağlantılarda (score <= 20) butonu aktif et
        if status == "Güvenli ✅" and score <= 20 and not self._is_ip_address(url):
            self.open_in_browser_button.config(state=tk.NORMAL)
            self.last_analyzed_url = url
            self.last_risk_score = score
        else:
            self.open_in_browser_button.config(state=tk.DISABLED)
            self.last_analyzed_url = ""
            self.last_risk_score = 100

    def _open_url_in_browser(self):
        if hasattr(self, 'last_risk_score') and self.last_risk_score > 20:
            messagebox.showwarning("Güvenlik Uyarısı", 
                                 f"Bu URL güvenli olarak değerlendirilmedi (Risk skoru: {self.last_risk_score}%).\n"
                                 "Güvenli olmayan bağlantıları tarayıcıda açmanız önerilmez.")
            return
        
        if self.last_analyzed_url:
            try:
                webbrowser.open_new_tab(self.last_analyzed_url)
            except Exception as e:
                messagebox.showerror("Tarayıcı Hatası", f"URL tarayıcıda açılamadı: {e}")
        else:
            messagebox.showwarning("Uyarı", "Tarayıcıda açılacak bir URL bulunmuyor veya bu bağlantı güvenli değil.")

    def _export_results(self, format_type=None):
        """Analiz sonuçlarını dışa aktar"""
        if not self.export_manager:
            messagebox.showerror("Hata", "Export modülü yüklenemedi. Lütfen reportlab kütüphanesini yükleyin.")
            return
        
        if not self.last_analysis_data:
            messagebox.showwarning("Uyarı", "Dışa aktarılacak analiz sonucu bulunamadı. Lütfen önce bir URL analiz edin.")
            return
        
        # Format seçilmediyse kullanıcıdan sor
        if format_type is None:
            format_type = self._ask_export_format()
            if not format_type:
                return
        
        try:
            filepath = self.export_manager.export_results(self.last_analysis_data, format_type)
            if filepath:
                messagebox.showinfo("Başarılı", f"Rapor başarıyla kaydedildi!\n\n{filepath}")
                # Dosyayı açmak isteyip istemediğini sor
                if messagebox.askyesno("Dosyayı Aç", "Rapor dosyasını şimdi açmak ister misiniz?"):
                    os.startfile(filepath)  # Windows için
            else:
                messagebox.showerror("Hata", "Rapor kaydedilemedi. Lütfen tekrar deneyin.")
        except Exception as e:
            logger.error(f"Export hatası: {e}", exc_info=True)
            messagebox.showerror("Hata", f"Rapor kaydedilirken bir hata oluştu: {e}")
    
    def _ask_export_format(self):
        """Kullanıcıdan export formatı seçmesini iste"""
        from tkinter import simpledialog
        
        format_choice = simpledialog.askstring(
            "Format Seçin",
            "Lütfen export formatını seçin:\n1 - PDF\n2 - CSV\n3 - JSON",
            initialvalue="1"
        )
        
        if format_choice == "1":
            return "pdf"
        elif format_choice == "2":
            return "csv"
        elif format_choice == "3":
            return "json"
        else:
            return None
    

    def _extract_main_domain(self, url):
        if self._is_ip_address(url) and not urlparse(url).scheme:
            url = "http://" + url
        
        ext = tldextract.extract(url)
        if ext.domain and ext.suffix:
            return ext.domain + "." + ext.suffix
        elif self._is_ip_address(url):
            return urlparse(url).hostname if urlparse(url).hostname else url
        else: 
            return urlparse(url).hostname if urlparse(url).hostname else url


    def _extract_subdomains(self, url):
        ext = tldextract.extract(url).subdomain
        return ext.split(".") if ext else []

    def _is_ip_address(self, url_or_host):
        try:
            if "://" in url_or_host:
                host = urlparse(url_or_host).hostname
            else:
                host = url_or_host
            if not host: 
                host = url_or_host 
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def _check_at_symbol(self, url):
        return "@" in url

    def _check_multiple_subdomains(self, url):
        sub = tldextract.extract(url).subdomain
        if sub:
            parts = [p for p in sub.split(".") if p and p.lower() != "www"]
            return len(parts) > 1
        return False

    def _check_keywords(self, url):
        try:
            with open(self.blacklist_file, "r") as f:
                blacklist_from_file = [line.strip().lower() for line in f if line.strip()]
        except FileNotFoundError:
            blacklist_from_file = []
            
        all_suspicious_items = self.suspicious_keywords + blacklist_from_file
        return any(keyword in url.lower() for keyword in all_suspicious_items)

    def _check_extensions(self, url):
        return any(url.lower().endswith(ext) for ext in self.suspicious_extensions)

    def _check_url_shortener(self, url):
        """URL kısaltma servisi kontrolü"""
        shortener_domains = [
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'buff.ly',
            'short.link', 'rebrand.ly', 'cutt.ly', 'is.gd', 'v.gd', 'tiny.cc',
            'shorturl.at', 'shorte.st', 'adf.ly', 'bc.vc', 'ouo.io'
        ]
        parsed = urlparse(url)
        domain = parsed.hostname or ''
        return any(shortener in domain.lower() for shortener in shortener_domains)

    def _check_port_number(self, url):
        """Port numarası kontrolü"""
        parsed = urlparse(url)
        if parsed.port:
            # Standart olmayan portlar şüpheli olabilir
            standard_ports = [80, 443, 8080, 8443]
            if parsed.port not in standard_ports:
                return True, parsed.port
        return False, None

    def _load_domains_from_file(self, filename):
        normalized_domains = set()
        try:
            # Path traversal koruması
            if UTILS_AVAILABLE:
                safe_filename = sanitize_filename(os.path.basename(filename))
            else:
                safe_filename = os.path.basename(filename)
            
            # Dosya data klasöründe olmalı
            full_path = os.path.join(script_dir, 'data', safe_filename)
            
            # Güvenlik: Dosya yolunun script dizininde olduğundan emin ol
            script_dir_real = os.path.realpath(script_dir)
            full_path_real = os.path.realpath(full_path)
            data_dir_real = os.path.realpath(os.path.join(self.script_dir, 'data'))
            if not full_path_real.startswith(data_dir_real):
                logger.error(f"Path traversal denemesi tespit edildi: {filename}")
                return list(normalized_domains)
            
            with open(full_path, "r", encoding='utf-8') as f:
                for line in f:
                    stripped_line = line.strip().lower()
                    if stripped_line:
                        if self._is_ip_address(stripped_line):
                            normalized_domains.add(stripped_line) 
                        else:
                            extracted_info = tldextract.extract(stripped_line)
                            if extracted_info.domain and extracted_info.suffix:
                                normalized_domains.add(f"{extracted_info.domain}.{extracted_info.suffix}")
                            elif extracted_info.domain: 
                                normalized_domains.add(extracted_info.domain)
        except FileNotFoundError:
            logger.debug(f"Dosya bulunamadı: {filename}")
            pass
        except Exception as e:
            logger.error(f"Dosya okuma hatası ({filename}): {e}", exc_info=True)
        return list(normalized_domains)

    def _save_domains_to_file(self, filename, domains):
        try:
            # Path traversal koruması
            if UTILS_AVAILABLE:
                safe_filename = sanitize_filename(os.path.basename(filename))
            else:
                safe_filename = os.path.basename(filename)
            
            # Dosya data klasöründe olmalı
            full_path = os.path.join(script_dir, 'data', safe_filename)
            
            # Güvenlik: Dosya yolunun script dizininde olduğundan emin ol
            script_dir_real = os.path.realpath(script_dir)
            full_path_real = os.path.realpath(full_path)
            data_dir_real = os.path.realpath(os.path.join(self.script_dir, 'data'))
            if not full_path_real.startswith(data_dir_real):
                logger.error(f"Path traversal denemesi tespit edildi: {filename}")
                raise ValueError("Geçersiz dosya yolu")
            
            with open(full_path, "w", encoding='utf-8') as f:
                for d in domains:
                    f.write(d + "\n")
            logger.debug(f"Dosya kaydedildi: {filename}")
        except Exception as e:
            logger.error(f"Dosya kaydetme hatası ({filename}): {e}", exc_info=True)
            raise

    def _is_similar_domain(self, domain, legit_domains):
        """
        Gelişmiş domain benzerlik kontrolü - phishing tespiti için
        Levenshtein distance, karakter değişimleri, TLD manipülasyonları kontrol eder
        """
        if not domain or not legit_domains:
            return False, None
        
        # Domain'i normalize et (küçük harf, www kaldır)
        domain_clean = domain.lower().replace('www.', '').strip()
        
        # Domain'in ana kısmını ve TLD'sini ayır
        domain_parts = domain_clean.split('.')
        if len(domain_parts) < 2:
            return False, None
        
        domain_main = '.'.join(domain_parts[:-1])  # TLD hariç
        domain_tld = domain_parts[-1]
        
        best_match = None
        best_score = float('inf')
        best_legit = None
        dynamic_threshold = self.levenshtein_threshold  # Varsayılan değer
        
        for legit in legit_domains:
            if not legit or legit.strip() == '':
                continue
            
            # Yorum satırlarını atla
            if legit.strip().startswith('#'):
                continue
            
            legit_clean = legit.lower().replace('www.', '').strip()
            
            # Tam eşleşme varsa atla
            if domain_clean == legit_clean:
                continue
            
            # Legit domain'in ana kısmını ve TLD'sini ayır
            legit_parts = legit_clean.split('.')
            if len(legit_parts) < 2:
                continue
            
            legit_main = '.'.join(legit_parts[:-1])
            legit_tld = legit_parts[-1]
            
            # 1. Ana domain kısmı benzerlik kontrolü (TLD olmadan)
            main_dist = Levenshtein.distance(domain_main, legit_main)
            
            # Domain uzunluğuna göre dinamik threshold
            max_len = max(len(domain_main), len(legit_main))
            if max_len <= 5:
                current_threshold = max(1, self.levenshtein_threshold)
            elif max_len <= 10:
                current_threshold = max(2, self.levenshtein_threshold)
            else:
                # Uzun domainler için daha toleranslı (ama yine de dikkatli)
                current_threshold = max(2, min(3, self.levenshtein_threshold + 1))
            
            # 2. TLD değişikliği kontrolü (phishing için yaygın)
            tld_changed = domain_tld != legit_tld
            
            # 3. Karakter değişimleri kontrolü (o->0, i->l, a->@, vb.)
            char_similarity = self._check_character_similarity(domain_main, legit_main)
            
            # 4. Homoglyph (benzer görünen karakterler) kontrolü
            homoglyph_score = self._check_homoglyphs(domain_main, legit_main)
            
            # 5. Subdomain manipülasyonu kontrolü
            subdomain_manipulation = self._check_subdomain_manipulation(domain_clean, legit_clean)
            
            # Skorlama sistemi
            similarity_score = main_dist
            
            # TLD değişikliği varsa ekstra şüpheli
            if tld_changed and main_dist <= current_threshold + 1:
                similarity_score = main_dist - 0.5  # Daha şüpheli
            
            # Karakter benzerliği yüksekse ekstra puan
            if char_similarity > 0.7:
                similarity_score = similarity_score - 0.3
            
            # Homoglyph tespit edildiyse çok şüpheli
            if homoglyph_score > 0:
                similarity_score = similarity_score - 0.5
            
            # Subdomain manipülasyonu varsa şüpheli
            if subdomain_manipulation:
                similarity_score = similarity_score - 0.2
            
            # En iyi eşleşmeyi bul
            if similarity_score < best_score:
                best_score = similarity_score
                best_match = main_dist
                best_legit = legit_clean
        
        # Eşik değerini kontrol et (en son kullanılan threshold ile)
        if best_match is not None:
            # En iyi eşleşme için threshold'u tekrar hesapla
            if best_legit:
                best_parts = best_legit.split('.')
                if len(best_parts) >= 2:
                    best_main = '.'.join(best_parts[:-1])
                    max_len = max(len(domain_main), len(best_main))
                    if max_len <= 5:
                        final_threshold = max(1, self.levenshtein_threshold)
                    elif max_len <= 10:
                        final_threshold = max(2, self.levenshtein_threshold)
                    else:
                        final_threshold = max(2, min(3, self.levenshtein_threshold + 1))
                    
                    if best_match <= final_threshold:
                        return True, best_legit
        
        return False, None
    
    def _check_character_similarity(self, domain1, domain2):
        """
        Karakter benzerliği kontrolü (o->0, i->l, a->@ gibi yaygın değişimler)
        """
        if len(domain1) != len(domain2):
            return 0.0
        
        similar_chars = {
            'o': '0', '0': 'o',
            'i': 'l', 'l': 'i', '1': 'i', 'i': '1',
            'a': '@', '@': 'a',
            's': '5', '5': 's',
            'e': '3', '3': 'e',
            'g': '9', '9': 'g',
            'z': '2', '2': 'z',
        }
        
        similar_count = 0
        for c1, c2 in zip(domain1, domain2):
            if c1 == c2:
                similar_count += 1
            elif c1.lower() in similar_chars and similar_chars[c1.lower()] == c2.lower():
                similar_count += 0.5
            elif c2.lower() in similar_chars and similar_chars[c2.lower()] == c1.lower():
                similar_count += 0.5
        
        return similar_count / len(domain1) if domain1 else 0.0
    
    def _check_homoglyphs(self, domain1, domain2):
        """
        Homoglyph (benzer görünen karakterler) kontrolü
        Örnek: а (Kiril) vs a (Latin), о (Kiril) vs o (Latin)
        """
        # Yaygın homoglyph çiftleri
        homoglyph_pairs = [
            ('а', 'a'), ('е', 'e'), ('о', 'o'), ('р', 'p'), ('с', 'c'),
            ('у', 'y'), ('х', 'x'), ('м', 'm'), ('н', 'n'), ('к', 'k'),
            ('А', 'A'), ('Е', 'E'), ('О', 'O'), ('Р', 'P'), ('С', 'C'),
            ('У', 'Y'), ('Х', 'X'), ('М', 'M'), ('Н', 'H'), ('К', 'K'),
        ]
        
        if len(domain1) != len(domain2):
            return 0
        
        homoglyph_count = 0
        for c1, c2 in zip(domain1, domain2):
            if c1 == c2:
                continue
            for h1, h2 in homoglyph_pairs:
                if (c1 == h1 and c2 == h2) or (c1 == h2 and c2 == h1):
                    homoglyph_count += 1
                    break
        
        return homoglyph_count
    
    def _check_subdomain_manipulation(self, domain, legit):
        """
        Subdomain manipülasyonu kontrolü
        Örnek: paypal.com vs paypal-security.com, microsoft.com vs microsoft-verify.com
        """
        try:
            # Legit domain'in ana kısmını al
            legit_parts = legit.split('.')
            if len(legit_parts) < 2:
                return False
            
            legit_main = legit_parts[-2]  # Son ikinci kısım (TLD'den önceki)
            if not legit_main or len(legit_main) < 3:
                return False
            
            # Domain'de legit domain'in ana kısmı geçiyor mu?
            domain_parts = domain.split('.')
            if len(domain_parts) < 2:
                return False
            
            # Subdomain'lerde legit domain geçiyor mu?
            # Örnek: security-paypal.com, paypal-security.com
            for part in domain_parts[:-2]:  # TLD ve ana domain hariç
                if not part:
                    continue
                part_lower = part.lower()
                legit_main_lower = legit_main.lower()
                
                # Legit domain ana kısmı subdomain'de geçiyor mu?
                if legit_main_lower in part_lower and part_lower != legit_main_lower:
                    # Örnek: paypal-security.com'da "paypal" geçiyor
                    # Ama paypal.com'un kendi subdomain'i değil (security.paypal.com olmalı)
                    return True
            
            # Ana domain kısmında manipülasyon var mı?
            domain_main = domain_parts[-2]
            if not domain_main:
                return False
            
            domain_main_lower = domain_main.lower()
            legit_main_lower = legit_main.lower()
            
            # Legit domain ana kısmı domain'de geçiyor ama tam eşleşmiyor mu?
            if legit_main_lower in domain_main_lower and domain_main_lower != legit_main_lower:
                # Örnek: paypal-verify.com vs paypal.com
                # paypal-verify.com'da "paypal" geçiyor ama tam eşleşmiyor
                if len(domain_main_lower) > len(legit_main_lower) + 2:  # En az 2 karakter eklenmiş
                    # Ama çok kısa eklemeler normal olabilir (paypal-tr.com gibi)
                    # Sadece şüpheli eklemeleri yakala (-security, -verify, -update, vb.)
                    suspicious_suffixes = ['-security', '-verify', '-update', '-login', '-account', 
                                          '-secure', '-confirm', '-validate', '-support', '-help']
                    for suffix in suspicious_suffixes:
                        if domain_main_lower.endswith(suffix):
                            return True
                    
                    # Eğer domain legit'ten çok uzunsa şüpheli
                    if len(domain_main_lower) > len(legit_main_lower) + 5:
                        return True
            
            return False
        except Exception as e:
            logger.debug(f"Subdomain manipülasyon kontrolü hatası: {e}")
            return False

    def _is_blacklisted(self, domain_or_ip):
        blacklist = self._load_domains_from_file(self.blacklist_file)
        return domain_or_ip in blacklist

    def _is_safelisted(self, domain_or_ip):
        safelist = self._load_domains_from_file(self.real_domains_file)
        if domain_or_ip in safelist:
            return True

        if not self._is_ip_address(domain_or_ip):
            main_domain = self._extract_main_domain(domain_or_ip)
            if main_domain in safelist:
                return True
        return False

    def _check_ssl_cert(self, domain_or_ip):
        try:
            ctx = ssl.create_default_context()
            host_to_connect = domain_or_ip

            if self._is_ip_address(domain_or_ip):
                return "⚠️ IP adresleri için doğrudan SSL sertifikası kontrolü genellikle geçerli değildir.", 10, "ssl_ip_address"
            
            try:
                if domain_or_ip.startswith("xn--"):
                    host_to_connect = idna.decode(domain_or_ip)
            except idna.IDNAError:
                pass 

            with socket.create_connection((host_to_connect, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host_to_connect) as ssock:
                    cert = ssock.getpeercert()
                    expire_date_str = cert.get('notAfter')
                    if not expire_date_str:
                        return "🟠 SSL Sertifikası son kullanma tarihi bulunamadı.", 10, "ssl_error"
                    
                    expire_date = datetime.strptime(expire_date_str, '%b %d %H:%M:%S %Y %Z')
                    days_left = (expire_date - datetime.utcnow()).days
                    if days_left < 0:
                        return f"🔴 SSL Sertifikası süresi dolmuş! ({expire_date.date()})", 30, "ssl_expired"
                    elif days_left < 30:
                        return f"🟠 SSL Sertifikası yakında sona erecek ({days_left} gün kaldı)", 10, "ssl_soon_expire"
                    else:
                        return f"🟢 SSL Sertifikası geçerli, son kullanma: {expire_date.date()}", 0, None
        except ssl.SSLError as e:
            return f"⚠️ SSL sertifika hatası: {e}", 15, "ssl_error"
        except socket.timeout:
            return "⚠️ SSL sertifika kontrolü zaman aşımına uğradı.", 10, "ssl_timeout"
        except (socket.error, ConnectionRefusedError, OSError) as e:
            return f"⚠️ SSL sertifika kontrolü bağlantı hatası: {e}", 10, "ssl_connection_error"
        except Exception as e:
            return f"⚠️ SSL sertifika kontrolü yapılamadı (Genel hata: {e})", 10, "ssl_error"

    def _whois_socket_query(self, domain):
        """Socket ile doğrudan WHOIS sorgusu yap (alternatif yöntem)"""
        try:
            # TLD'ye göre WHOIS sunucusu belirle
            tld = domain.split('.')[-1].upper()
            whois_servers = {
                'COM': 'whois.verisign-grs.com',
                'NET': 'whois.verisign-grs.com',
                'ORG': 'whois.pir.org',
                'INFO': 'whois.afilias.net',
                'BIZ': 'whois.neulevel.biz',
                'US': 'whois.nic.us',
                'UK': 'whois.nic.uk',
                'DE': 'whois.denic.de',
                'FR': 'whois.afnic.fr',
                'IT': 'whois.nic.it',
                'ES': 'whois.nic.es',
                'NL': 'whois.domain-registry.nl',
                'BE': 'whois.dns.be',
                'AU': 'whois.aunic.net',
                'CA': 'whois.cira.ca',
                'JP': 'whois.jprs.jp',
                'CN': 'whois.cnnic.net.cn',
                'RU': 'whois.tcinet.ru',
                'BR': 'whois.registro.br',
                'MX': 'whois.mx',
                'IN': 'whois.inregistry.net',
                'TR': 'whois.nic.tr',
            }
            
            # Varsayılan olarak genel WHOIS sunucusu
            whois_server = whois_servers.get(tld, 'whois.iana.org')
            
            def query_whois_server(server, query_domain):
                """Belirli bir WHOIS sunucusuna sorgu gönder"""
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(8)
                try:
                    sock.connect((server, 43))
                    sock.sendall((query_domain + '\r\n').encode('utf-8'))
                    
                    response = b''
                    while True:
                        data = sock.recv(4096)
                        if not data:
                            break
                        response += data
                        if len(response) > 65536:  # Maksimum yanıt boyutu
                            break
                    
                    return response.decode('utf-8', errors='ignore')
                finally:
                    sock.close()
            
            # İlk sorguyu yap
            whois_text = query_whois_server(whois_server, domain)
            
            # Referans kontrolü (IANA referansı varsa takip et)
            if 'refer:' in whois_text.lower() or 'whois server:' in whois_text.lower():
                refer_match = re.search(r'(?:refer:|whois server:)\s*([^\s\n]+)', whois_text, re.IGNORECASE)
                if refer_match:
                    refer_server = refer_match.group(1).strip()
                    if refer_server and refer_server != whois_server:
                        logger.debug(f"WHOIS referans bulundu: {refer_server}, tekrar sorgulanıyor")
                        try:
                            whois_text = query_whois_server(refer_server, domain)
                        except:
                            pass  # Referans sunucusuna bağlanamazsa ilk yanıtı kullan
            
            # Creation date'i parse et
            creation_date = None
            date_patterns = [
                r'Creation Date:\s*(\d{4}-\d{2}-\d{2}(?:\s+\d{2}:\d{2}:\d{2})?)',
                r'Created:\s*(\d{4}-\d{2}-\d{2}(?:\s+\d{2}:\d{2}:\d{2})?)',
                r'Registered:\s*(\d{4}-\d{2}-\d{2}(?:\s+\d{2}:\d{2}:\d{2})?)',
                r'Registration Date:\s*(\d{4}-\d{2}-\d{2}(?:\s+\d{2}:\d{2}:\d{2})?)',
                r'created:\s*(\d{4}-\d{2}-\d{2}(?:\s+\d{2}:\d{2}:\d{2})?)',
                r'Creation Date:\s*(\d{2}-\w{3}-\d{4})',
                r'Created:\s*(\d{2}-\w{3}-\d{4})',
                r'Registered:\s*(\d{2}-\w{3}-\d{4})',
                r'Registration Date:\s*(\d{2}-\w{3}-\d{4})',
                r'Creation Date:\s*(\d{4}/\d{2}/\d{2})',
                r'Created:\s*(\d{4}/\d{2}/\d{2})',
                r'Registered:\s*(\d{4}/\d{2}/\d{2})',
            ]
            
            for pattern in date_patterns:
                match = re.search(pattern, whois_text, re.IGNORECASE)
                if match:
                    date_str = match.group(1).strip()
                    try:
                        # YYYY-MM-DD formatı
                        if '-' in date_str and len(date_str.split('-')[0]) == 4:
                            if ' ' in date_str:
                                creation_date = datetime.strptime(date_str.split()[0], '%Y-%m-%d')
                            else:
                                creation_date = datetime.strptime(date_str, '%Y-%m-%d')
                        # DD-MMM-YYYY formatı
                        elif '-' in date_str and len(date_str.split('-')[0]) == 2:
                            creation_date = datetime.strptime(date_str, '%d-%b-%Y')
                        # YYYY/MM/DD formatı
                        elif '/' in date_str:
                            creation_date = datetime.strptime(date_str, '%Y/%m/%d')
                        if creation_date:
                            break
                    except ValueError:
                        continue
            
            return creation_date
                
        except socket.timeout:
            logger.debug(f"WHOIS socket sorgusu zaman aşımı: {domain}")
            return None
        except Exception as e:
            logger.debug(f"WHOIS socket sorgusu hatası: {e}")
            return None

    def _check_domain_age(self, domain):
        """Domain yaşını WHOIS ile kontrol et"""
        try:
            # İnternet bağlantısı kontrolü
            try:
                import socket
                socket.create_connection(("8.8.8.8", 53), timeout=3)
            except OSError:
                logger.warning("İnternet bağlantısı yok, WHOIS sorgusu atlandı")
                return "ℹ️ İnternet bağlantısı kontrol edilemedi, WHOIS sorgusu atlandı.", 0, "whois_error"
            
            # Domain'i temizle (www, http/https kaldır)
            clean_domain = domain.replace('www.', '').replace('http://', '').replace('https://', '').split('/')[0]
            clean_domain = clean_domain.split(':')[0].split('?')[0]
            
            logger.debug(f"WHOIS sorgusu başlatılıyor: {clean_domain}")
            
            info = None
            creation_date = None
            
            # python-whois kütüphanesi ile sorgu - timeout ile
            try:
                # Timeout için threading kullan
                import threading
                whois_result = [None]
                whois_exception = [None]
                
                def whois_query():
                    try:
                        whois_result[0] = whois.whois(clean_domain)
                    except Exception as e:
                        whois_exception[0] = e
                
                thread = threading.Thread(target=whois_query)
                thread.daemon = True
                thread.start()
                thread.join(timeout=10)  # 10 saniye timeout
                
                if thread.is_alive():
                    logger.warning(f"WHOIS sorgusu zaman aşımına uğradı: {clean_domain}")
                    # Zaman aşımı durumunda alternatif yöntem dene
                    info = None
                elif whois_exception[0]:
                    raise whois_exception[0]
                else:
                    info = whois_result[0]
                    logger.debug(f"WHOIS yanıtı alındı: {type(info)}")
                    
            except PywhoisError as e:
                logger.warning(f"PywhoisError: {e}, alternatif yöntem deneniyor")
                info = None
            except Exception as whois_error:
                error_msg = str(whois_error).lower()
                logger.warning(f"WHOIS sorgu hatası: {whois_error}")
                # Bazı hatalar normal olabilir (domain gizlenmiş, kayıtlı değil vb.)
                if 'no whois server' in error_msg or 'no match' in error_msg or 'not found' in error_msg:
                    return "ℹ️ WHOIS bilgileri alınamadı. Domain gizlenmiş olabilir veya kayıtlı değil.", 5, "whois_error"
                info = None
            
            # Alternatif yöntem: Socket ile doğrudan WHOIS sorgusu
            if not info:
                try:
                    logger.debug(f"Alternatif WHOIS yöntemi deneniyor: {clean_domain}")
                    creation_date = self._whois_socket_query(clean_domain)
                    if creation_date:
                        logger.info(f"Alternatif yöntemle domain yaşı bulundu: {clean_domain}")
                        age = (datetime.now() - creation_date).days
                        if age < 100:
                            return f"🔴 Bu domain {age} gün önce oluşturulmuş! Çok yeni ve çok riskli.", 50, "domain_age_new"
                        elif age < 300:
                            return f"🟠 Bu domain {age} gün önce oluşturulmuş! Riskli olabilir.", 30, "domain_age_young"
                        elif age < 500:
                            return f"🟡 Bu domain {age} gün önce oluşturulmuş! Dikkat etmekte fayda var.", 10, "domain_age_moderate"
                        else:
                            return f"🟢 Domain yaşı {age} gün – Güvenli domain yaşı.", 0, None
                except Exception as alt_error:
                    logger.debug(f"Alternatif WHOIS yöntemi başarısız: {alt_error}")
            
            if not info:
                return "ℹ️ WHOIS sorgusu yapılamadı. Domain yaşı kontrol edilemedi.", 0, "whois_error"
            
            # Creation date'i al - farklı formatları dene
            if hasattr(info, 'creation_date'):
                creation_date = info.creation_date
            elif isinstance(info, dict):
                creation_date = info.get('creation_date') or info.get('created') or info.get('registration_date')
            
            # List ise ilk elemanı al
            if isinstance(creation_date, list):
                creation_date = min([d for d in creation_date if d]) if creation_date else None
            
            if not creation_date:
                logger.debug(f"Domain {clean_domain} için creation_date bulunamadı, whois bilgisi: {str(info)[:200]}")
                return "ℹ️ Domain oluşturulma tarihi bulunamadı. WHOIS bilgileri gizlenmiş olabilir.", 5, "domain_age_unknown"
            
            # Tarih formatını düzelt
            if not isinstance(creation_date, datetime):
                date_formats = [
                    '%Y-%m-%d %H:%M:%S', '%Y-%m-%d', '%d-%b-%Y', '%Y%m%d', 
                    '%Y.%m.%d', '%d/%m/%Y', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%dT%H:%M:%SZ',
                    '%d.%m.%Y', '%m/%d/%Y', '%b %d %Y', '%d %b %Y'
                ]
                parsed = False
                date_str = str(creation_date).split(".")[0].split("+")[0].strip()
                for fmt in date_formats:
                    try:
                        creation_date = datetime.strptime(date_str, fmt)
                        parsed = True
                        break
                    except ValueError:
                        continue
                if not parsed:
                    logger.warning(f"Domain {clean_domain} için tarih formatı tanınamadı: {date_str}")
                    return "ℹ️ Domain oluşturulma tarihi formatı tanınamadı.", 5, "domain_age_unknown"

            age = (datetime.now() - creation_date).days
            logger.info(f"Domain {clean_domain} yaşı: {age} gün")

            if age < 100:
                return f"🔴 Bu domain {age} gün önce oluşturulmuş! Çok yeni ve çok riskli.", 50, "domain_age_new"
            elif age < 300:
                return f"🟠 Bu domain {age} gün önce oluşturulmuş! Riskli olabilir.", 30, "domain_age_young"
            elif age < 500:
                return f"🟡 Bu domain {age} gün önce oluşturulmuş! Dikkat etmekte fayda var.", 10, "domain_age_moderate"
            else:
                return f"🟢 Domain yaşı {age} gün – Güvenli domain yaşı.", 0, None
                
        except Exception as e:
            logger.error(f"WHOIS genel hatası: {e}", exc_info=True)
            # Kullanıcıya teknik detay göstermek yerine bilgilendirici mesaj
            return "ℹ️ WHOIS sorgusu yapılamadı. Domain yaşı kontrol edilemedi.", 0, "whois_error"

    def _check_dns_records(self, domain):
        """
        DNS kayıt kontrolü - MX, SPF, DMARC kayıtlarını kontrol eder
        Email güvenliği ve phishing tespiti için önemli
        """
        try:
            if self._is_ip_address(domain):
                return [], 0
            
            issues = []
            score = 0
            
            # Domain'i temizle
            clean_domain = domain.replace('www.', '').split('/')[0].split(':')[0]
            
            # DNS sorguları için socket kullan
            try:
                # MX kayıt kontrolü
                try:
                    import socket
                    mx_records = socket.getaddrinfo(clean_domain, None, socket.AF_INET)
                    # MX kayıtları genellikle email sunucularını gösterir
                except:
                    pass
                
                # SPF ve DMARC kontrolü için TXT kayıtlarını kontrol et
                # Not: Tam DNS sorgusu için dnspython gerekir, ama basit kontrol yapabiliriz
                # Bu özellik için kullanıcıya bilgi verelim
                
            except Exception as e:
                logger.debug(f"DNS kayıt kontrolü hatası: {e}")
            
            # Şimdilik bilgilendirici mesaj
            # Gelecekte dnspython ile genişletilebilir
            return issues, score
            
        except Exception as e:
            logger.debug(f"DNS kontrolü genel hatası: {e}")
            return [], 0
    
    def _check_url_redirects(self, url):
        """
        URL redirect zincirini takip eder - phishing için önemli
        """
        try:
            redirects = []
            max_redirects = 10
            current_url = url
            
            for i in range(max_redirects):
                try:
                    response = requests.head(current_url, timeout=5, allow_redirects=False, verify=True)
                    
                    if response.status_code in [301, 302, 303, 307, 308]:
                        redirect_url = response.headers.get('Location', '')
                        if redirect_url:
                            # Relatif URL'leri mutlak URL'ye çevir
                            if redirect_url.startswith('/'):
                                parsed = urlparse(current_url)
                                redirect_url = f"{parsed.scheme}://{parsed.netloc}{redirect_url}"
                            elif not redirect_url.startswith('http'):
                                parsed = urlparse(current_url)
                                redirect_url = f"{parsed.scheme}://{parsed.netloc}/{redirect_url}"
                            
                            redirects.append((current_url, redirect_url, response.status_code))
                            current_url = redirect_url
                        else:
                            break
                    else:
                        break
                except requests.exceptions.RequestException:
                    break
                except Exception:
                    break
            
            if len(redirects) > 3:
                return True, redirects, f"🟠 Çok fazla yönlendirme tespit edildi ({len(redirects)} adım). Şüpheli olabilir.", 15
            elif len(redirects) > 0:
                # Son yönlendirmeyi kontrol et
                final_url = redirects[-1][1]
                final_domain = urlparse(final_url).netloc
                original_domain = urlparse(url).netloc
                
                # Farklı domain'e yönlendirme varsa şüpheli
                if final_domain != original_domain and final_domain:
                    return True, redirects, f"🟡 URL farklı bir domain'e yönlendiriyor: {original_domain} → {final_domain}", 10
                else:
                    return True, redirects, f"ℹ️ {len(redirects)} yönlendirme adımı tespit edildi.", 0
            else:
                return False, [], None, 0
                
        except Exception as e:
            logger.debug(f"URL redirect kontrolü hatası: {e}")
            return False, [], None, 0

    def _check_http_status(self, url_or_ip):
        HTTP_STATUS_DETAILS = {
            100: "100 Continue: Devam etmek için sunucunun cevabını bekleyin.",
            101: "101 Switching Protocols: Protokol değiştiriliyor.",
            200: "200 OK: Sayfa başarıyla yüklendi.",
            201: "201 Created: Kaynak başarıyla oluşturuldu.",
            202: "202 Accepted: İstek kabul edildi, ancak işlem henüz tamamlanmadı.",
            204: "204 No Content: İstek başarıyla işlendi, ancak döndürülecek içerik yok.",
            301: "301 Moved Permanently: Kalıcı yönlendirme.",
            302: "302 Found: Geçici yönlendirme.",
            303: "303 See Other: Diğer bir URL'ye yönlendirme.",
            304: "304 Not Modified: Kaynak değişmedi.",
            307: "307 Temporary Redirect: Geçici yönlendirme.",
            308: "308 Permanent Redirect: Kalıcı yönlendirme.",
            400: "400 Bad Request: İstemci tarafından gönderilen istekte hata var.",
            401: "401 Unauthorized: Kimlik doğrulaması gereklidir.",
            403: "403 Forbidden: Sunucu isteği anladı ancak yetki verilmedi.",
            404: "404 Not Found: İstenen sayfa bulunamadı.",
            405: "405 Method Not Allowed: Kullanılan HTTP metodu desteklenmiyor.",
            406: "406 Not Acceptable: Sunucu, istemcinin talep ettiği biçimde yanıt üretemez.",
            408: "408 Request Timeout: İstek zaman aşımına uğradı.",
            409: "409 Conflict: İstek bir sunucu çakışması nedeniyle tamamlanamadı.",
            410: "410 Gone: Kaynak kalıcı olarak kaldırıldı.",
            429: "429 Too Many Requests: Çok fazla istek gönderildi, geçici olarak engellendi.",
            500: "500 Internal Server Error: Sunucuda hata oluştu.",
            501: "501 Not Implemented: Sunucu isteği yerine getiremez.",
            502: "502 Bad Gateway: Ağ geçidi sunucusu geçersiz bir yanıt aldı.",
            503: "503 Service Unavailable: Sunucu şu anda hizmet veremiyor.",
            504: "504 Gateway Timeout: Ağ geçidi sunucusu zaman aşımına uğradı.",
        }
        
        try_urls = []
        parsed_url_scheme = urlparse(url_or_ip).scheme
        
        if not parsed_url_scheme: 
            try_urls.append("https://" + url_or_ip)
            try_urls.append("http://" + url_or_ip)
        else: 
            try_urls.append(url_or_ip)

        for attempt_url in try_urls:
            try:
                response = requests.head(attempt_url, timeout=5, allow_redirects=True, verify=True)  
                status_code = response.status_code
                description = HTTP_STATUS_DETAILS.get(status_code, "Durum açıklaması bulunamadı.")

                if 200 <= status_code < 300: 
                    return f"📡 HTTP durum kodu: {status_code} (OK)\nℹ️ Açıklama: {description}", 0, None
                elif 300 <= status_code < 400: 
                    return f"🟡 HTTP durum kodu: {status_code} (Yönlendirme)\nℹ️ Açıklama: {description}", 10, "http_status_redirect"
                elif status_code == 403:
                    return f"🟠 HTTP durum kodu: 403 (Erişim yasaklandı)\nℹ️ Açıklama: {description}", 15, "http_status_forbidden"
                elif status_code == 404:
                    return f"🔴 HTTP durum kodu: 404 (Sayfa bulunamadı)\nℹ️ Açıklama: {description}", 20, "http_status_not_found"
                elif 500 <= status_code < 600: 
                    return f"🔴 HTTP durum kodu: {status_code} (Sunucu hatası)\nℹ️ Açıklama: {description}", 30, "http_status_server_error"
                else: 
                    return f"🟠 HTTP durum kodu: {status_code} (Bilinmeyen durum)\nℹ️ Açıklama: {description}", 20, "http_status_unknown"
            except requests.exceptions.SSLError:
                continue
            except requests.exceptions.RequestException:
                continue
            except Exception:
                continue
            
        return f"🔴 HTTP durumu alınamadı (Bağlantı/İstek hatası). URL'ye erişilemiyor.", 10, "http_status_connection_error"

    def _check_suspicious_parameters(self, url):
        return bool(re.search(r"[?&](tm_campaign=|ap_id=|aaid=|gclid=|utm_source=|utm_medium=|utm_campaign=|utm_term=|utm_content=)", url))

    def _check_punycode(self, domain):
        try:
            if domain.startswith("xn--"):
                decoded_domain = idna.decode(domain)
                return True, f"🔴 Punycode (IDN) kullanımı tespit edildi: '{domain}' -> '{decoded_domain}'", "punycode_detected"
            return False, None, None
        except idna.IDNAError as e:
            return False, f"⚠️ Punycode çözülürken hata: {e}", None

    def _check_path_and_query_anomalies(self, url):
        parsed = urlparse(url)
        issues = []
        total_score = 0

        path = parsed.path
        if len(path) > self.path_length_threshold:
            issues.append(("🟠 URL yolu çok uzun. (+10)", "long_path"))
            total_score += 10

        encoded_chars = re.findall(r"%[0-9a-fA-F]{2}", path + parsed.query)
        if len(path + parsed.query) > 0:
            percentage_encoded = (len(encoded_chars) / len(path + parsed.query)) * 100
            if percentage_encoded > self.encoded_char_threshold:
                issues.append(("🟠 URL yolu veya sorgu parametrelerinde yüksek oranda kodlanmış karakter var. (+15)", "encoded_path_query"))
                total_score += 15

        query_params = parse_qs(parsed.query)
        for key, values in query_params.items():
            for value in values:
                decoded_value = requests.utils.unquote(value) 
                if re.search(r"[^a-zA-Z0-9\-\._~]", decoded_value) and len(decoded_value) > 10: 
                    issues.append(("🔴 Sorgu parametrelerinde şifrelenmiş/anlamsız değerler var. (+20)", "obfuscated_parameters"))
                    total_score += 20
                    break 
            if "obfuscated_parameters" in [issue[1] for issue in issues]:
                break 

        return issues, total_score

    def _virus_total_scan(self, target):
        if not self.vt_api_key:
            return "ℹ️ VirusTotal API Key girilmedi veya yapılandırma dosyasından yüklenemedi.\n" \
                   "Lütfen bir API anahtarı girin ve kaydetmeyi deneyin."

        # Rate limiting kontrolü
        if self.rate_limiter:
            try:
                self.rate_limiter.wait_if_needed()
                logger.debug("Rate limiter kontrolü geçildi")
            except Exception as e:
                logger.warning(f"Rate limiter hatası: {e}")

        headers = {"x-apikey": self.vt_api_key}
        result_data = {
            "status": "error",
            "message": "",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "total_scans": 0,
            "engines_detected": [],
            "more_engines_count": 0
        }

        try:
            parsed = urlparse(target)
            
            vt_url = ""
            resource_type = ""

            if self._is_ip_address(target):
                vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
                resource_type = "IP Adresi"
            elif not parsed.scheme: 
                url_to_encode = "http://" + target
                encoded = base64.urlsafe_b64encode(url_to_encode.encode()).decode().strip("=")
                vt_url = f"https://www.virustotal.com/api/v3/urls/{encoded}"
                resource_type = "URL"
            else: 
                encoded = base64.urlsafe_b64encode(target.encode()).decode().strip("=")
                vt_url = f"https://www.virustotal.com/api/v3/urls/{encoded}"
                resource_type = "URL"
            
            logger.debug(f"VirusTotal API çağrısı: {resource_type}")
            r = requests.get(vt_url, headers=headers, timeout=15)

            if r.status_code == 200:
                data = r.json().get("data", {})
                if not data:
                    result_data["status"] = "warning"
                    result_data["message"] = f"⚠️ VirusTotal'da {resource_type} için veri bulunamadı."
                    return result_data

                attributes = data.get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                
                result_data["malicious"] = stats.get("malicious", 0)
                result_data["suspicious"] = stats.get("suspicious", 0)
                result_data["harmless"] = stats.get("harmless", 0)
                result_data["undetected"] = stats.get("undetected", 0)
                result_data["total_scans"] = result_data["malicious"] + result_data["suspicious"] + result_data["harmless"] + result_data["undetected"]
                
                analysis_results = attributes.get("last_analysis_results", {})
                all_engines_detected = []
                for engine, result in analysis_results.items():
                    if result["category"] in ["malicious", "suspicious"]:
                        all_engines_detected.append(f"{engine}: {result['result']} ({result['category']})")
                
                result_data["engines_detected"] = all_engines_detected[:5]
                result_data["more_engines_count"] = len(all_engines_detected) - len(result_data["engines_detected"])

                if result_data["malicious"] > 0 or result_data["suspicious"] > 0:
                    result_data["status"] = "malicious"
                    result_data["message"] = "🚫 VirusTotal kötü amaçlı/şüpheli içerik buldu."
                else:
                    result_data["status"] = "harmless"
                    result_data["message"] = "✅ VirusTotal: Herhangi bir zararlı veya şüpheli bulgu tespit edilmedi."
                return result_data

            elif r.status_code == 401:
                result_data["message"] = "⚠️ VirusTotal API anahtarı geçersiz veya yetkisiz."
            elif r.status_code == 403:
                result_data["message"] = "⚠️ VirusTotal erişim engellendi (403 Forbidden). API çağrı limitinizi kontrol edin."
            elif r.status_code == 404:
                result_data["message"] = f"⚠️ VirusTotal'da '{target}' için kayıt bulunamadı. Bu yeni veya nadir bir {resource_type} olabilir."
            elif r.status_code == 429:
                result_data["message"] = "⚠️ VirusTotal API çağrı limiti aşıldı (429 Too Many Requests). Lütfen bekleyin."
            else:
                result_data["message"] = f"⚠️ VirusTotal API hatası: {r.status_code} - {r.text}"

        except requests.exceptions.Timeout:
            result_data["message"] = "⚠️ VirusTotal isteği zaman aşımına uğradı (15 saniye)."
        except requests.exceptions.ConnectionError:
            result_data["message"] = "⚠️ VirusTotal bağlantı hatası. İnternet bağlantınızı kontrol edin."
        except Exception as e:
            result_data["message"] = f"⚠️ VirusTotal isteği başarısız: {e}"
            
        return result_data

    def _analyze_url(self, url):
        # Cache kontrolü
        if self.advanced_cache:
            cached_result = self.advanced_cache.get_cached_result(url)
            if cached_result:
                logger.info(f"Cache'den sonuç yüklendi: {url}")
                return (cached_result['issues'], cached_result['vt_data'], 
                       cached_result['domain'], cached_result['score'], 
                       cached_result['status'], cached_result['color'], 
                       cached_result['subs'])
        
        is_ip = self._is_ip_address(url)
        domain = ""
        subs = []

        if not is_ip:
            domain = self._extract_main_domain(url).lower()
            subs = self._extract_subdomains(url)

        total_score = 0
        issues = []
        
        # Güvenli liste kontrolü - Bonus puan için
        is_safelisted = self._is_safelisted(domain if not is_ip else url)
        
        legit_domains = self._load_domains_from_file(self.real_domains_file)

        if not is_ip and self._is_blacklisted(domain):
            issues.append(("🔴 Bu domain kara listede yer alıyor! (+50)", "blacklisted_domain_ip"))
            total_score += 50
        elif is_ip and self._is_blacklisted(url):
            issues.append(("🔴 Bu IP adresi kara listede yer alıyor! (+50)", "blacklisted_domain_ip"))
            total_score += 50

        if is_ip:
            issues.append(("🔴 URL doğrudan bir IP adresi. (+20)", "ip_in_url"))
            total_score += 20
        elif self._is_ip_address(urlparse(url).hostname):
            issues.append(("🔴 URL hostname kısmında bir IP adresi içeriyor. (+20)", "ip_in_url"))
            total_score += 20
            
        if self._check_at_symbol(url):
            issues.append(("🔴 '@' karakteri içeriyor (Kullanıcı adı/şifre gizleme girişimi olabilir). (+20)", "at_symbol"))
            total_score += 20
        if not is_ip and self._check_multiple_subdomains(url):
            issues.append(("🟠 Çok fazla subdomain var. (+10)", "multiple_subdomains"))
            total_score += 10
        if self._check_keywords(url):
            issues.append(("🟠 URL şüpheli kelimeler içeriyor. (+10)", "suspicious_keywords"))
            total_score += 10
        if self._check_extensions(url):
            issues.append(("🔴 URL tehlikeli dosya uzantısı içeriyor. (+40)", "suspicious_extensions"))
            total_score += 40
        if self._check_suspicious_parameters(url):
            issues.append(("🟠 URL'de şüpheli takip parametreleri tespit edildi. (+15)", "suspicious_parameters"))
            total_score += 15
        
        # URL kısaltma servisi kontrolü
        if self._check_url_shortener(url):
            issues.append(("🟠 URL kısaltma servisi kullanılıyor. Gerçek hedef görünmüyor. (+15)", "url_shortener"))
            total_score += 15
        
        # Port numarası kontrolü
        has_non_standard_port, port_num = self._check_port_number(url)
        if has_non_standard_port:
            issues.append((f"🟠 Standart olmayan port numarası kullanılıyor: {port_num} (+10)", "non_standard_port"))
            total_score += 10
        
        path_query_issues, path_query_score = self._check_path_and_query_anomalies(url)
        issues.extend(path_query_issues)
        total_score += path_query_score

        if not is_ip:
            age_result, age_score, age_detail_key = self._check_domain_age(domain)
            issues.append((f"{age_result} (+{age_score})", age_detail_key))
            total_score += age_score

            similar, legit_match = self._is_similar_domain(domain, legit_domains)
            if similar:
                issues.append((f"🔴 Phishing benzeri domain tespit edildi (typosquatting): '{domain}' ↔ '{legit_match}' (+30)", "similar_domain"))
                total_score += 30
            
            punycode_detected, punycode_message, punycode_detail_key = self._check_punycode(domain)
            if punycode_detected:
                issues.append((punycode_message + " (+25)", punycode_detail_key)) 
                total_score += 25

            ssl_result, ssl_score, ssl_detail_key = self._check_ssl_cert(domain)
            issues.append((f"{ssl_result} (+{ssl_score})", ssl_detail_key))
            total_score += ssl_score
        else: 
            ssl_result, ssl_score, ssl_detail_key = self._check_ssl_cert(url)
            issues.append((f"{ssl_result} (+{ssl_score})", ssl_detail_key))
            total_score += ssl_score
            issues.append(("ℹ️ IP adresi olduğu için Domain Yaşı ve Benzer Domain kontrolü atlandı.", None))

        http_result, http_score, http_detail_key = self._check_http_status(url)
        issues.append((f"{http_result} (+{http_score})", http_detail_key))
        total_score += http_score

        # URL redirect kontrolü - Phishing tespiti için önemli
        if not is_ip:
            has_redirects, redirect_chain, redirect_message, redirect_score = self._check_url_redirects(url)
            if has_redirects and redirect_message:
                issues.append((f"{redirect_message} (+{redirect_score})", "url_redirects"))
                total_score += redirect_score
                # Redirect zincirini detay olarak sakla
                if redirect_chain and len(redirect_chain) > 0:
                    redirect_details = "\n".join([f"  {i+1}. {r[0]} → {r[1]} ({r[2]})" for i, r in enumerate(redirect_chain)])
                    issues.append((f"ℹ️ Yönlendirme zinciri:\n{redirect_details}", None))
        
        # IP Reputation kontrolü
        if is_ip and self.ip_reputation_checker:
            try:
                ip_reputation = self.ip_reputation_checker.check_ip_reputation(url)
                if ip_reputation.get('risk_level') == 'high':
                    issues.append((f"🔴 IP adresi yüksek risk seviyesinde (AbuseIPDB: {ip_reputation.get('abuseipdb', {}).get('abuse_confidence_score', 0)}%) (+{ip_reputation.get('risk_score', 0)})", "ip_reputation_high"))
                    total_score += ip_reputation.get('risk_score', 0)
                elif ip_reputation.get('risk_level') == 'medium':
                    issues.append((f"🟠 IP adresi orta risk seviyesinde (AbuseIPDB: {ip_reputation.get('abuseipdb', {}).get('abuse_confidence_score', 0)}%) (+{ip_reputation.get('risk_score', 0)})", "ip_reputation_medium"))
                    total_score += ip_reputation.get('risk_score', 0)
                elif ip_reputation.get('geo_location'):
                    geo = ip_reputation['geo_location']
                    issues.append((f"ℹ️ IP Coğrafi Konum: {geo.get('country', 'Unknown')}, {geo.get('city', 'Unknown')}", None))
            except Exception as e:
                logger.debug(f"IP reputation kontrolü hatası: {e}")
        
        # Certificate Transparency kontrolü
        if not is_ip and self.ct_checker:
            try:
                ct_result = self.ct_checker.check_certificate_history(domain)
                if ct_result.get('risk_score', 0) > 0:
                    issues.append((f"🟠 Sertifika geçmişi şüpheli: {ct_result.get('total_certs', 0)} sertifika, {len(ct_result.get('suspicious_certs', []))} şüpheli (+{ct_result.get('risk_score', 0)})", "cert_transparency"))
                    total_score += ct_result.get('risk_score', 0)
                elif ct_result.get('total_certs', 0) > 0:
                    issues.append((f"ℹ️ Sertifika geçmişi: {ct_result.get('total_certs', 0)} sertifika kaydı bulundu", None))
            except Exception as e:
                logger.debug(f"Certificate Transparency kontrolü hatası: {e}")

        # USOM kontrolü (Türkiye için önemli) - Domain ve URL ile kontrol et
        if not is_ip and self.usom_checker:
            try:
                # Önce domain ile kontrol et
                usom_found, usom_message = self.usom_checker.check_domain(domain)
                
                # Domain bulunamadıysa, www. olmadan tekrar dene
                if not usom_found and domain.startswith('www.'):
                    usom_found, usom_message = self.usom_checker.check_domain(domain[4:])
                
                # Hala bulunamadıysa tam URL ile de dene
                if not usom_found:
                    usom_found, usom_message = self.usom_checker.check_domain(url)
                
                if usom_found:
                    issues.append((f"🚫 USOM (Ulusal Siber Olaylara Müdahale Merkezi) zararlı bağlantılar listesinde bulundu! (+60)\nℹ️ {usom_message}\n🌐 Kaynak: https://www.usom.gov.tr/adres", "usom_malicious"))
                    total_score += 60
                    logger.warning(f"USOM zararlı bağlantı tespit edildi: {domain} - {usom_message}")
            except Exception as e:
                logger.error(f"USOM kontrol hatası: {e}", exc_info=True)
                issues.append(("⚠️ USOM kontrolü yapılamadı.", "usom_error"))

        vt_analysis_data = self._virus_total_scan(url)
        
        if isinstance(vt_analysis_data, dict):
            if vt_analysis_data.get('status') == "malicious":
                issues.append(("🚫 VirusTotal kötü amaçlı içerik buldu. (+40)", "virustotal_malicious"))
                total_score += 40
            elif vt_analysis_data.get('status') == "warning" and "kayıt bulunamadı" in vt_analysis_data.get('message', ''):
                issues.append(("⚠️ VirusTotal kaydı bulunamadı (Yeni/nadir olabilir). (+20)", "virustotal_no_record"))
                total_score += 20
            elif vt_analysis_data.get('status') == "error":
                issues.append((f"⚠️ VirusTotal hatası: {vt_analysis_data.get('message', 'Bilinmeyen hata')}", "virustotal_api_error"))
                total_score += 10
        else:
            issues.append((vt_analysis_data, "virustotal_api_error"))

        # ML Scorer ile skoru iyileştir
        if self.ml_scorer:
            ml_score = self.ml_scorer.calculate_risk_score(issues, total_score)
            # ML skorunu %30 ağırlıkla ekle (eski skor %70)
            total_score = int(total_score * 0.7 + ml_score * 0.3)
        
        # Güvenli listedeki domainler için -20 bonus puan
        if is_safelisted:
            bonus_score = 20
            total_score = max(0, total_score - bonus_score)
            issues.append(("✅ Bu URL güvenli domainler listenizde bulunuyor. Risk puanı -20 düşürüldü.", "safelisted_domain_ip"))
        
        total_score = max(0, min(100, total_score))

        if total_score <= self.risk_threshold_safe:
            status = "Güvenli ✅"
            color = self.light_green
        elif total_score <= self.risk_threshold_suspicious:
            status = "Şüpheli ⚠️"
            color = "orange"
        else:
            status = "Tehlikeli 🚫"
            color = "red"

        # Sonuçları cache'le
        result = (issues, vt_analysis_data, domain, total_score, status, color, subs)
        if self.advanced_cache:
            cache_data = {
                'issues': issues,
                'vt_data': vt_analysis_data,
                'domain': domain,
                'score': total_score,
                'status': status,
                'color': color,
                'subs': subs
            }
            self.advanced_cache.cache_result(url, cache_data)

        return result

    def _edit_list_file(self, filename, title):
        def save_changes():
            items_to_save = listbox.get(0, tk.END)
            try:
                self._save_domains_to_file(filename, items_to_save)
                messagebox.showinfo("Başarılı", f"{title} başarıyla kaydedildi.")
                edit_window.destroy()
            except Exception as e:
                messagebox.showerror("Hata", f"Dosya kaydedilirken hata oluştu: {e}")

        def add_item():
            new_item = entry.get().strip().lower() 
            if new_item:
                normalized_new_item = ""
                if self._is_ip_address(new_item):
                    normalized_new_item = new_item
                else:
                    extracted_info = tldextract.extract(new_item)
                    if extracted_info.domain and extracted_info.suffix:
                        normalized_new_item = f"{extracted_info.domain}.{extracted_info.suffix}"
                    elif extracted_info.domain:
                        normalized_new_item = extracted_info.domain
                
                if normalized_new_item and normalized_new_item not in listbox.get(0, tk.END):
                    listbox.insert(tk.END, normalized_new_item)
                    entry.delete(0, tk.END)
                elif not normalized_new_item and not self._is_ip_address(new_item):
                    messagebox.showwarning("Uyarı", "Geçerli bir domain veya IP adresi girin.")
                else:
                    messagebox.showwarning("Uyarı", "Bu öğe zaten listede mevcut.")
            else:
                messagebox.showwarning("Uyarı", "Boş giriş eklenemez.")


        def delete_selected():
            selected_indices = listbox.curselection()
            if not selected_indices:
                messagebox.showwarning("Uyarı", "Silmek için bir öğe seçin.")
                return
            for index in reversed(selected_indices):
                listbox.delete(index)

        items = self._load_domains_from_file(filename) 

        edit_window = tk.Toplevel(self.master)
        edit_window.title(title)
        edit_window.geometry("450x450")
        edit_window.config(bg=self.primary_bg)

        listbox = tk.Listbox(edit_window, selectmode=tk.EXTENDED, width=60, bg=self.result_box_bg, fg=self.text_color_light, selectbackground=self.button_color, selectforeground=self.button_text_color)
        listbox.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)
        for item in items:
            listbox.insert(tk.END, item)

        entry_frame = tk.Frame(edit_window, bg=self.primary_bg)
        entry_frame.pack(fill=tk.X, padx=10)

        entry = tk.Entry(entry_frame, bg=self.result_box_bg, fg=self.text_color_light, insertbackground=self.text_color_light)
        entry.pack(side=tk.LEFT, expand=True, fill=tk.X, pady=5)

        add_btn = tk.Button(entry_frame, text="Ekle", command=add_item, bg=self.button_color, fg=self.button_text_color)
        add_btn.pack(side=tk.LEFT, padx=5)

        btn_frame = tk.Frame(edit_window, bg=self.primary_bg)
        btn_frame.pack(fill=tk.X, padx=10, pady=5)

        delete_btn = tk.Button(btn_frame, text="Seçiliyi Sil", command=delete_selected, bg=self.button_color, fg=self.button_text_color)
        delete_btn.pack(side=tk.LEFT)

        save_btn = tk.Button(btn_frame, text="Kaydet", command=save_changes, bg=self.button_color, fg=self.button_text_color)
        save_btn.pack(side=tk.RIGHT)

    def _load_generic_list_from_file(self, filename):
        items = []
        try:
            # Path traversal koruması
            if UTILS_AVAILABLE:
                safe_filename = sanitize_filename(os.path.basename(filename))
            else:
                safe_filename = os.path.basename(filename)
            
            # Dosya data klasöründe olmalı
            full_path = os.path.join(self.script_dir, 'data', safe_filename)
            
            # Güvenlik kontrolü
            script_dir_real = os.path.realpath(self.script_dir)
            full_path_real = os.path.realpath(full_path)
            data_dir_real = os.path.realpath(os.path.join(self.script_dir, 'data'))
            if not full_path_real.startswith(data_dir_real):
                logger.error(f"Path traversal denemesi tespit edildi: {filename}")
                return items
            
            with open(full_path, "r", encoding='utf-8') as f:
                items = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            logger.debug(f"Dosya bulunamadı: {filename}")
            pass
        except Exception as e:
            logger.error(f"Dosya okuma hatası ({filename}): {e}", exc_info=True)
            messagebox.showwarning("Dosya Okuma Hatası", "Dosya okunurken bir hata oluştu.")
            pass
        return items

    def _load_history(self):
        history_file_path = self.config['Files']['history_file']
        script_dir = os.path.dirname(__file__)
        
        # Path traversal koruması ve data klasörüne göre ayarla
        if UTILS_AVAILABLE:
            safe_filename = sanitize_filename(os.path.basename(history_file_path))
        else:
            safe_filename = os.path.basename(history_file_path)
        
        # Dosya data klasöründe olmalı
        full_path = os.path.join(self.script_dir, 'data', safe_filename)
        
        # Güvenlik kontrolü
        script_dir_real = os.path.realpath(self.script_dir)
        full_path_real = os.path.realpath(full_path)
        data_dir_real = os.path.realpath(os.path.join(self.script_dir, 'data'))
        if not full_path_real.startswith(data_dir_real):
            logger.error(f"Path traversal denemesi tespit edildi: {history_file_path}")
            self.history = []
            return

        if not os.path.exists(full_path):
            try:
                with open(full_path, 'w', encoding='utf-8') as f:
                    pass
                self.history = [] 
                logger.info(f"Geçmiş dosyası oluşturuldu: {history_file_path}")
                return 
            except Exception as e:
                logger.error(f"Geçmiş dosyası oluşturma hatası: {e}", exc_info=True)
                messagebox.showwarning("Geçmiş Dosyası Oluşturma Hatası", "Geçmiş dosyası oluşturulurken bir hata oluştu.")
                self.history = [] 
                return

        try:
            with open(full_path, 'r', encoding='utf-8') as f:
                self.history = [] 
                for line in f:
                    parts = line.strip().split(';')
                    if len(parts) == 3:
                        try:
                            self.history.append({'url': parts[0], 'score': int(parts[1]), 'status': parts[2]})
                        except ValueError:
                            logger.warning(f"Geçersiz geçmiş kaydı atlandı: {line.strip()}")
                    else:
                        logger.warning(f"Geçersiz formatta geçmiş kaydı atlandı: {line.strip()}")
        except Exception as e:
            logger.error(f"Geçmiş yükleme hatası: {e}", exc_info=True)
            messagebox.showwarning("Geçmiş Yükleme Hatası", "Geçmiş dosyası yüklenirken bir hata oluştu.")
            self.history = [] 

    def _save_history(self):
        history_file_path = self.config['Files']['history_file']
        
        # Path traversal koruması ve data klasörüne göre ayarla
        if UTILS_AVAILABLE:
            safe_filename = sanitize_filename(os.path.basename(history_file_path))
        else:
            safe_filename = os.path.basename(history_file_path)
        
        # Dosya data klasöründe olmalı
        full_path = os.path.join(self.script_dir, 'data', safe_filename)
        
        # Güvenlik kontrolü
        script_dir_real = os.path.realpath(self.script_dir)
        full_path_real = os.path.realpath(full_path)
        data_dir_real = os.path.realpath(os.path.join(self.script_dir, 'data'))
        if not full_path_real.startswith(data_dir_real):
            logger.error(f"Path traversal denemesi tespit edildi: {history_file_path}")
            return
        
        try:
            with open(full_path, 'w', encoding='utf-8') as f:
                for entry in self.history:
                    f.write(f"{entry['url']};{entry['score']};{entry['status']}\n")
            logger.debug("Geçmiş başarıyla kaydedildi")
        except Exception as e:
            logger.error(f"Geçmiş kaydetme hatası: {e}", exc_info=True)
            messagebox.showwarning("Geçmiş Kaydetme Hatası", "Geçmiş dosyası kaydedilirken bir hata oluştu.")

    def _add_to_history(self, url, score, status):
        for i, entry in enumerate(self.history):
            if entry['url'] == url:
                del self.history[i]
                break
            
        self.history.insert(0, {'url': url, 'score': score, 'status': status})
        
        if len(self.history) > self.MAX_HISTORY_SIZE:
            self.history = self.history[:self.MAX_HISTORY_SIZE]
            
        self._save_history()

    def _show_history_window(self):
        history_window = tk.Toplevel(self.master)
        history_window.title("Son Aramalar Geçmişi")
        history_window.geometry("600x400")
        history_window.config(bg=self.primary_bg)

        tk.Label(history_window, text="Son Analiz Edilen URL'ler:", font=("Arial", 12, "bold"), bg=self.primary_bg, fg=self.text_color_dark).pack(pady=5)

        history_listbox = tk.Listbox(history_window, width=80, height=15, bg=self.result_box_bg, fg=self.text_color_light, selectbackground=self.button_color, selectforeground=self.button_text_color)
        history_listbox.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)

        if not self.history:
            history_listbox.insert(tk.END, "Geçmişte kayıt bulunamadı.")
        else:
            for entry in self.history:
                history_listbox.insert(tk.END, f"[{entry['status']}] {entry['url']} (Risk: {entry['score']}%)")
        
        def load_selected_from_history():
            selected_indices = history_listbox.curselection()
            if selected_indices:
                selected_index = selected_indices[0]
                selected_url = self.history[selected_index]['url']
                self.url_entry.delete(0, tk.END)
                self.url_entry.insert(0, selected_url)
                history_window.destroy()
                self._start_analysis_thread()

        load_button = tk.Button(history_window, text="Seçili URL'yi Yükle ve Kontrol Et", command=load_selected_from_history, bg=self.button_color, fg=self.button_text_color)
        load_button.pack(pady=5)

        def delete_selected_from_history():
            selected_indices = history_listbox.curselection()
            if not selected_indices:
                messagebox.showwarning("Uyarı", "Silmek için geçmişten bir öğe seçin.", parent=history_window)
                return

            if messagebox.askyesno("Seçiliyi Sil", "Seçili öğeyi geçmişten silmek istediğinizden emin misiniz?", parent=history_window):
                for index in sorted(selected_indices, reverse=True):
                    del self.history[index]
                    history_listbox.delete(index)
                self._save_history()
                messagebox.showinfo("Başarılı", "Seçili öğe başarıyla silindi.", parent=history_window)
                if not self.history:
                    history_listbox.insert(tk.END, "Geçmişte kayıt bulunamadı.")

        delete_selected_button = tk.Button(history_window, text="Seçiliyi Geçmişten Sil", command=delete_selected_from_history, bg=self.button_color, fg=self.button_text_color)
        delete_selected_button.pack(pady=5)

        def clear_history_confirm():
            if messagebox.askyesno("Geçmişi Temizle", "Tüm geçmişi temizlemek istediğinizden emin misiniz?", parent=history_window):
                self.history = []
                self._save_history()
                history_listbox.delete(0, tk.END)
                history_listbox.insert(tk.END, "Geçmiş temizlendi.")

        clear_all_button = tk.Button(history_window, text="Tüm Geçmişi Temizle", command=clear_history_confirm, bg=self.button_color, fg=self.button_text_color)
        clear_all_button.pack(pady=5)

if __name__ == "__main__":
    root = tk.Tk()
    app = URLAnalyzerApp(root)
    root.mainloop()