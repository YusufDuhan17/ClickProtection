"""
Click Protection - Güvenlik Modülü

API anahtarı şifreleme için yardımcı fonksiyonlar.
"""

import base64
import os
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

class SecureConfig:
    """Güvenli yapılandırma yönetimi"""
    
    def __init__(self, key_file=".secret_key"):
        self.key_file = key_file
        self.key = self._get_or_create_key()
    
    def _get_key_directory(self):
        """Anahtar dosyası için uygun dizin bul"""
        # PyInstaller EXE modunda mı kontrol et
        if getattr(sys, 'frozen', False):
            # EXE modunda - AppData'ya kaydet (her zaman yazılabilir)
            appdata = os.getenv('APPDATA', os.path.expanduser("~"))
            key_dir = os.path.join(appdata, "ClickProtection")
            os.makedirs(key_dir, exist_ok=True)
        else:
            # Python script modunda - modules klasörüne kaydet
            script_dir = os.path.dirname(__file__)
            key_dir = script_dir
        
        return key_dir
    
    def _get_or_create_key(self):
        """Şifreleme anahtarı al veya oluştur"""
        key_dir = self._get_key_directory()
        key_path = os.path.join(key_dir, self.key_file)
        
        if os.path.exists(key_path):
            try:
                with open(key_path, 'rb') as f:
                    return f.read()
            except Exception:
                pass
        
        # Yeni anahtar oluştur
        key = get_random_bytes(32)  # AES-256 için 32 byte
        try:
            with open(key_path, 'wb') as f:
                f.write(key)
            # Dosya izinlerini kısıtla (sadece sahip okuyabilsin)
            # Windows'ta chmod çalışmayabilir, o yüzden try-except içinde
            try:
                os.chmod(key_path, 0o600)
            except (AttributeError, OSError):
                pass  # Windows'ta chmod desteklenmeyebilir
        except Exception:
            pass
        
        return key
    
    def encrypt(self, plaintext):
        """Metni şifrele"""
        try:
            cipher = AES.new(self.key, AES.MODE_CBC)
            ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
            return base64.b64encode(cipher.iv + ciphertext).decode('utf-8')
        except Exception as e:
            return plaintext  # Şifreleme başarısız olursa düz metin döndür
    
    def decrypt(self, ciphertext):
        """Şifreli metni çöz"""
        try:
            data = base64.b64decode(ciphertext.encode('utf-8'))
            iv = data[:16]
            ciphertext = data[16:]
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
            return plaintext.decode('utf-8')
        except Exception:
            return ciphertext  # Çözme başarısız olursa düz metin döndür

# Not: Bu modül opsiyonel olarak kullanılabilir
# Şu an için config.ini'de düz metin saklanıyor
# Gelecekte bu modül entegre edilebilir

