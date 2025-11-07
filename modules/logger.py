"""
Click Protection - URL/IP Güvenlik Analiz Aracı

Bu modül loglama işlevselliği sağlar.
"""

import logging
import os
from datetime import datetime

class AppLogger:
    """Uygulama için loglama sınıfı"""
    
    def __init__(self, log_file="click_protection.log"):
        self.log_file = log_file
        self._setup_logger()
    
    def _setup_logger(self):
        """Logger yapılandırması"""
        script_dir = os.path.dirname(__file__)
        log_path = os.path.join(script_dir, self.log_file)
        
        # Logger oluştur
        self.logger = logging.getLogger('ClickProtection')
        self.logger.setLevel(logging.DEBUG)
        
        # Handler yoksa ekle
        if not self.logger.handlers:
            # Dosya handler
            file_handler = logging.FileHandler(log_path, encoding='utf-8')
            file_handler.setLevel(logging.DEBUG)
            
            # Konsol handler
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)
            
            # Formatter
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            
            file_handler.setFormatter(formatter)
            console_handler.setFormatter(formatter)
            
            self.logger.addHandler(file_handler)
            self.logger.addHandler(console_handler)
    
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

