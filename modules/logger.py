"""
Click Protection - URL/IP Güvenlik Analiz Aracı

Bu modül loglama işlevselliği sağlar.
"""

import logging
import os
import sys
from datetime import datetime

class AppLogger:
    """Uygulama için loglama sınıfı"""
    
    def __init__(self, log_file="click_protection.log"):
        self.log_file = log_file
        self._setup_logger()
    
    def _get_log_directory(self):
        """Log dosyası için uygun dizin bul"""
        # PyInstaller EXE modunda mı kontrol et
        if getattr(sys, 'frozen', False):
            # EXE modunda - AppData'ya kaydet (her zaman yazılabilir)
            appdata = os.getenv('APPDATA', os.path.expanduser("~"))
            log_dir = os.path.join(appdata, "ClickProtection")
            os.makedirs(log_dir, exist_ok=True)
        else:
            # Python script modunda - modules klasörüne kaydet
            script_dir = os.path.dirname(__file__)
            log_dir = script_dir
        
        return log_dir
    
    def _setup_logger(self):
        """Logger yapılandırması"""
        # Logger oluştur
        self.logger = logging.getLogger('ClickProtection')
        self.logger.setLevel(logging.DEBUG)
        
        # Handler yoksa ekle
        if not self.logger.handlers:
            # Konsol handler (her zaman ekle)
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)
            
            # Formatter
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)
            
            # Dosya handler (hata olursa atla)
            try:
                log_dir = self._get_log_directory()
                log_path = os.path.join(log_dir, self.log_file)
                
                # Klasörü oluştur (yoksa)
                os.makedirs(log_dir, exist_ok=True)
                
                # Dosya handler oluştur
                file_handler = logging.FileHandler(log_path, encoding='utf-8')
                file_handler.setLevel(logging.DEBUG)
                file_handler.setFormatter(formatter)
                self.logger.addHandler(file_handler)
            except Exception as e:
                # Log dosyası oluşturulamazsa, sadece konsola yaz
                # Bu durum EXE modunda geçici klasörlerde yazma izni olmadığında olabilir
                pass
    
    def debug(self, message):
        """Debug seviyesinde log"""
        self.logger.debug(message)
    
    def info(self, message):
        """Info seviyesinde log"""
        self.logger.info(message)
    
    def warning(self, message):
        """Warning seviyesinde log"""
        self.logger.warning(message)
    
    def error(self, message, exc_info=False):
        """Error seviyesinde log"""
        self.logger.error(message, exc_info=exc_info)
    
    def critical(self, message, exc_info=False):
        """Critical seviyesinde log"""
        self.logger.critical(message, exc_info=exc_info)

# Global logger instance
logger = AppLogger()

