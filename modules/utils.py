"""
Click Protection - Yardımcı Fonksiyonlar

Bu modül yardımcı fonksiyonlar içerir.
"""

import re
import ipaddress
from urllib.parse import urlparse
import tldextract

def is_valid_url(url):
    """
    URL'nin geçerli olup olmadığını kontrol eder.
    
    Args:
        url (str): Kontrol edilecek URL
        
    Returns:
        bool: URL geçerliyse True, değilse False
    """
    if not url or not isinstance(url, str):
        return False
    
    url = url.strip()
    if not url:
        return False
    
    # Temel URL format kontrolü
    try:
        result = urlparse(url)
        # Scheme varsa geçerli olmalı
        if result.scheme and result.scheme not in ['http', 'https', 'ftp']:
            return False
        # Hostname veya IP adresi olmalı
        if result.netloc or result.path:
            return True
        # Scheme yoksa, hostname/IP kontrolü yap
        if not result.scheme:
            # IP adresi kontrolü
            try:
                ipaddress.ip_address(url.split('/')[0].split(':')[0])
                return True
            except ValueError:
                pass
            # Domain kontrolü
            ext = tldextract.extract(url)
            if ext.domain and ext.suffix:
                return True
        return False
    except Exception:
        return False

def normalize_url(url):
    """
    URL'yi normalize eder (scheme ekler, temizler).
    
    Args:
        url (str): Normalize edilecek URL
        
    Returns:
        str: Normalize edilmiş URL
    """
    if not url:
        return ""
    
    url = url.strip()
    
    # Scheme kontrolü
    parsed = urlparse(url)
    if not parsed.scheme:
        # IP adresi kontrolü
        try:
            ipaddress.ip_address(url.split('/')[0].split(':')[0])
            return "http://" + url
        except ValueError:
            return "http://" + url
    
    return url

def extract_domain_from_url(url):
    """
    URL'den domain çıkarır.
    
    Args:
        url (str): URL
        
    Returns:
        str: Domain veya boş string
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or parsed.netloc
        if hostname:
            ext = tldextract.extract(hostname)
            if ext.domain and ext.suffix:
                return f"{ext.domain}.{ext.suffix}"
            return hostname
        return ""
    except Exception:
        return ""

def is_ip_address(value):
    """
    Değerin IP adresi olup olmadığını kontrol eder.
    
    Args:
        value (str): Kontrol edilecek değer
        
    Returns:
        bool: IP adresiyse True, değilse False
    """
    try:
        if "://" in value:
            host = urlparse(value).hostname
        else:
            host = value.split('/')[0].split(':')[0]
        
        if not host:
            host = value
        
        ipaddress.ip_address(host)
        return True
    except (ValueError, AttributeError):
        return False

def sanitize_filename(filename):
    """
    Dosya adından geçersiz karakterleri temizler.
    
    Args:
        filename (str): Temizlenecek dosya adı
        
    Returns:
        str: Temizlenmiş dosya adı
    """
    # Windows'ta geçersiz karakterler
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    return filename[:255]  # Maksimum dosya adı uzunluğu

