"""
Click Protection - Machine Learning Skorlama Modülü

Öğrenen algoritma ile daha doğru risk skorlaması yapar.
"""

import json
import os
from datetime import datetime


class MLScorer:
    """Machine Learning tabanlı skorlama"""
    
    def __init__(self, model_dir):
        self.model_dir = model_dir
        os.makedirs(model_dir, exist_ok=True)
        self.weights_file = os.path.join(model_dir, "ml_weights.json")
        self.weights = self._load_weights()
    
    def _load_weights(self):
        """ML ağırlıklarını yükle"""
        default_weights = {
            'domain_age_new': 0.8,
            'domain_age_young': 0.5,
            'domain_age_moderate': 0.2,
            'similar_domain': 0.7,
            'punycode_detected': 0.6,
            'ssl_expired': 0.9,
            'ssl_error': 0.3,
            'suspicious_extensions': 0.85,
            'suspicious_keywords': 0.4,
            'url_shortener': 0.5,
            'url_redirects': 0.6,
            'blacklisted': 0.95,
            'usom_malicious': 0.95,
            'virustotal_malicious': 0.9,
            'ip_in_url': 0.6,
            'multiple_subdomains': 0.3,
            'base_risk': 0.1
        }
        
        if os.path.exists(self.weights_file):
            try:
                with open(self.weights_file, 'r', encoding='utf-8') as f:
                    loaded_weights = json.load(f)
                    # Yeni ağırlıkları ekle, eski ağırlıkları koru
                    default_weights.update(loaded_weights)
            except:
                pass
        
        return default_weights
    
    def _save_weights(self):
        """ML ağırlıklarını kaydet"""
        try:
            with open(self.weights_file, 'w', encoding='utf-8') as f:
                json.dump(self.weights, f, ensure_ascii=False, indent=2)
        except:
            pass
    
    def calculate_risk_score(self, issues, base_score):
        """
        ML tabanlı risk skoru hesapla.
        
        Args:
            issues: Tespit edilen sorunlar listesi
            base_score: Temel risk skoru
        
        Returns:
            float: ML ile hesaplanmış risk skoru
        """
        ml_score = 0.0
        max_score = 100.0
        
        # Her sorun için ağırlıklı skor hesapla
        for issue_text, detail_key in issues:
            if detail_key and detail_key in self.weights:
                weight = self.weights[detail_key]
                # Ağırlığı skora ekle
                ml_score += weight * 10  # Her ağırlık 10 puan değerinde
        
        # Temel risk skorunu da ekle
        ml_score += base_score * self.weights.get('base_risk', 0.1)
        
        # Maksimum değeri aşmamasını sağla
        ml_score = min(ml_score, max_score)
        
        return ml_score
    
    def adjust_weights(self, feature_key, adjustment_factor):
        """
        ML ağırlıklarını ayarla (öğrenme).
        
        Args:
            feature_key: Ayarlanacak özellik anahtarı
            adjustment_factor: Ayar faktörü (0.9 - 1.1 arası)
        """
        if feature_key in self.weights:
            self.weights[feature_key] *= adjustment_factor
            # Değerleri 0-1 aralığında tut
            self.weights[feature_key] = max(0.0, min(1.0, self.weights[feature_key]))
            self._save_weights()
    
    def get_feature_importance(self):
        """Özellik önem sıralamasını getir"""
        return sorted(self.weights.items(), key=lambda x: x[1], reverse=True)

