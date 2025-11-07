"""
Click Protection - Certificate Transparency Log Modülü

SSL sertifika geçmişini ve şüpheli sertifikaları kontrol eder.
"""

import requests
import json
from datetime import datetime, timedelta


class CertificateTransparencyChecker:
    """Certificate Transparency Log kontrolü"""
    
    def __init__(self):
        self.crt_sh_url = "https://crt.sh"
    
    def check_certificate_history(self, domain):
        """
        Domain için sertifika geçmişini kontrol eder.
        
        Args:
            domain: Kontrol edilecek domain
        
        Returns:
            dict: Sertifika geçmişi bilgileri
        """
        result = {
            'domain': domain,
            'total_certs': 0,
            'recent_certs': 0,
            'suspicious_certs': [],
            'first_seen': None,
            'last_seen': None,
            'risk_score': 0
        }
        
        try:
            # crt.sh API kullanarak sertifika geçmişini al
            params = {
                'q': domain,
                'output': 'json'
            }
            
            response = requests.get(f"{self.crt_sh_url}/", params=params, timeout=10)
            
            if response.status_code == 200:
                try:
                    certs = response.json()
                    if isinstance(certs, list) and len(certs) > 0:
                        result['total_certs'] = len(certs)
                        
                        # Son 30 gün içindeki sertifikaları say
                        thirty_days_ago = datetime.now() - timedelta(days=30)
                        recent_count = 0
                        
                        first_seen_dates = []
                        last_seen_dates = []
                        
                        for cert in certs:
                            # Sertifika tarihlerini parse et
                            not_before = cert.get('not_before')
                            not_after = cert.get('not_after')
                            
                            if not_before:
                                try:
                                    cert_date = datetime.strptime(not_before, '%Y-%m-%dT%H:%M:%S')
                                    first_seen_dates.append(cert_date)
                                    if cert_date >= thirty_days_ago:
                                        recent_count += 1
                                except:
                                    pass
                            
                            if not_after:
                                try:
                                    cert_date = datetime.strptime(not_after, '%Y-%m-%dT%H:%M:%S')
                                    last_seen_dates.append(cert_date)
                                except:
                                    pass
                            
                            # Şüpheli sertifikaları tespit et
                            # Çok kısa süreli sertifikalar şüpheli olabilir
                            if not_before and not_after:
                                try:
                                    not_before_date = datetime.strptime(not_before, '%Y-%m-%dT%H:%M:%S')
                                    not_after_date = datetime.strptime(not_after, '%Y-%m-%dT%H:%M:%S')
                                    cert_duration = (not_after_date - not_before_date).days
                                    
                                    if cert_duration < 30:  # 30 günden kısa sertifikalar şüpheli
                                        result['suspicious_certs'].append({
                                            'not_before': not_before,
                                            'not_after': not_after,
                                            'duration_days': cert_duration,
                                            'issuer': cert.get('issuer_name', 'Unknown')
                                        })
                                except:
                                    pass
                        
                        if first_seen_dates:
                            result['first_seen'] = min(first_seen_dates).isoformat()
                        if last_seen_dates:
                            result['last_seen'] = max(last_seen_dates).isoformat()
                        
                        result['recent_certs'] = recent_count
                        
                        # Risk skoru hesapla
                        if recent_count > 5:
                            result['risk_score'] += 20  # Çok fazla yeni sertifika
                        if len(result['suspicious_certs']) > 0:
                            result['risk_score'] += 15  # Şüpheli sertifikalar
                        if result['total_certs'] == 0:
                            result['risk_score'] += 10  # Hiç sertifika yok
                            
                except json.JSONDecodeError:
                    result['error'] = "Sertifika geçmişi parse edilemedi"
            else:
                result['error'] = f"API hatası: {response.status_code}"
                
        except requests.exceptions.RequestException as e:
            result['error'] = f"Bağlantı hatası: {str(e)}"
        except Exception as e:
            result['error'] = f"Hata: {str(e)}"
        
        return result

