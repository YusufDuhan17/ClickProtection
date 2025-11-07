"""
Click Protection - IP Reputation Modülü

IP adreslerinin itibar kontrolü için AbuseIPDB ve coğrafi konum bilgisi sağlar.
"""

import requests
import json
import socket
import ipaddress
from datetime import datetime


class IPReputationChecker:
    """IP reputation kontrolü"""
    
    def __init__(self, abuseipdb_api_key=None):
        self.abuseipdb_api_key = abuseipdb_api_key
        self.abuseipdb_url = "https://api.abuseipdb.com/api/v2/check"
    
    def check_ip_reputation(self, ip_address):
        """
        IP adresinin itibarını kontrol eder.
        
        Args:
            ip_address: Kontrol edilecek IP adresi
        
        Returns:
            dict: IP reputation bilgileri
        """
        result = {
            'ip': ip_address,
            'is_private': False,
            'is_valid': False,
            'abuseipdb': None,
            'geo_location': None,
            'risk_score': 0,
            'risk_level': 'unknown'
        }
        
        try:
            # IP adresinin geçerli olup olmadığını kontrol et
            ip_obj = ipaddress.ip_address(ip_address)
            result['is_valid'] = True
            result['is_private'] = ip_obj.is_private
            
            # Private IP'ler için kontrol yapma
            if result['is_private']:
                result['risk_level'] = 'safe'
                result['message'] = "Private IP adresi (yerel ağ)"
                return result
            
            # AbuseIPDB kontrolü
            if self.abuseipdb_api_key:
                abuse_data = self._check_abuseipdb(ip_address)
                result['abuseipdb'] = abuse_data
                
                if abuse_data:
                    abuse_score = abuse_data.get('abuse_confidence_score', 0)
                    if abuse_score >= 75:
                        result['risk_score'] += 50
                        result['risk_level'] = 'high'
                    elif abuse_score >= 50:
                        result['risk_score'] += 30
                        result['risk_level'] = 'medium'
                    elif abuse_score >= 25:
                        result['risk_score'] += 10
                        result['risk_level'] = 'low'
                    else:
                        result['risk_level'] = 'safe'
            
            # Coğrafi konum bilgisi (basit IP geolocation)
            geo_data = self._get_geo_location(ip_address)
            result['geo_location'] = geo_data
            
        except ValueError:
            result['message'] = "Geçersiz IP adresi formatı"
        except Exception as e:
            result['message'] = f"Hata: {str(e)}"
        
        return result
    
    def _check_abuseipdb(self, ip_address):
        """AbuseIPDB API ile IP kontrolü"""
        if not self.abuseipdb_api_key:
            return None
        
        try:
            headers = {
                'Key': self.abuseipdb_api_key,
                'Accept': 'application/json'
            }
            
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            
            response = requests.get(self.abuseipdb_url, headers=headers, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'abuse_confidence_score': data.get('data', {}).get('abuseConfidencePercentage', 0),
                    'is_public': data.get('data', {}).get('isPublic', False),
                    'is_whitelisted': data.get('data', {}).get('isWhitelisted', False),
                    'usage_type': data.get('data', {}).get('usageType', 'Unknown'),
                    'isp': data.get('data', {}).get('isp', 'Unknown'),
                    'domain': data.get('data', {}).get('domain', 'Unknown'),
                    'country': data.get('data', {}).get('countryCode', 'Unknown'),
                    'reports': data.get('data', {}).get('numReports', 0)
                }
            elif response.status_code == 429:
                return {'error': 'Rate limit exceeded'}
            else:
                return None
                
        except requests.exceptions.RequestException:
            return None
        except Exception as e:
            return {'error': str(e)}
    
    def _get_geo_location(self, ip_address):
        """Basit IP geolocation (ipapi.co kullanarak - ücretsiz)"""
        try:
            # Ücretsiz servis kullan (rate limit var ama basit kullanım için yeterli)
            response = requests.get(f"https://ipapi.co/{ip_address}/json/", timeout=5)
            if response.status_code == 200:
                data = response.json()
                return {
                    'country': data.get('country_name', 'Unknown'),
                    'country_code': data.get('country_code', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'region': data.get('region', 'Unknown'),
                    'isp': data.get('org', 'Unknown'),
                    'timezone': data.get('timezone', 'Unknown')
                }
        except:
            pass
        
        return None

