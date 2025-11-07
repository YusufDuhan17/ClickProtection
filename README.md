# Click Protection - URL/IP Güvenlik Analiz Aracı

<div align="center">

![Click Protection](assets/CLICKPROLOGO.png)

**🛡️ Profesyonel URL ve IP Adresi Güvenlik Analiz Aracı**

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-GPL--3.0-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](https://www.microsoft.com/windows)
[![AI](https://img.shields.io/badge/AI-ML%20Powered-purple.svg)](https://scikit-learn.org/)

[Özellikler](#-özellikler) • [Kurulum](#-kurulum) • [Kullanım](#-kullanım) • [Katkıda Bulunma](#-katkıda-bulunma)

</div>

---

## 📋 Proje Hakkında

**Click Protection**, siber güvenlik alanında kapsamlı bir URL ve IP adresi analiz aracıdır. Bu proje, **yapay zeka desteği** ile geliştirilmiş ve modern güvenlik teknolojilerini kullanarak phishing, kötü amaçlı yazılım ve diğer siber tehditleri tespit etmek için tasarlanmıştır.

### 🌟 Öne Çıkan Özellikler

- ✅ **USOM Entegrasyonu**: Türkiye'nin resmi siber güvenlik kurumu USOM zararlı bağlantılar listesi ile entegre
- ✅ **VirusTotal Desteği**: 70+ antivirüs motoru ile çoklu tarama
- ✅ **Machine Learning Skorlama**: Öğrenen algoritma ile daha doğru risk tespiti
- ✅ **IP Reputation Kontrolü**: AbuseIPDB entegrasyonu ile IP itibar analizi
- ✅ **Certificate Transparency**: SSL sertifika geçmişi ve şüpheli sertifika tespiti
- ✅ **Gelişmiş Cache**: 24 saatlik akıllı cache sistemi
- ✅ **Çoklu Export**: PDF, CSV, JSON formatlarında rapor oluşturma
- ✅ **Güvenli API Yönetimi**: AES-256 şifreleme ile API anahtarı koruması
- ✅ **Modern GUI**: Kullanıcı dostu ve profesyonel arayüz
- ✅ **30+ Güvenlik Kontrolü**: Kapsamlı analiz ve risk skorlaması

---

## 🚀 Özellikler

### 🔍 Kapsamlı Analiz Özellikleri

- **URL/IP Format Kontrolü**: Geçerli URL ve IP adresi doğrulama ve normalizasyon
- **Domain Yaşı Analizi**: WHOIS sorguları ile domain oluşturulma tarihi kontrolü (alternatif yöntemlerle)
- **SSL Sertifika Kontrolü**: SSL sertifikası geçerliliği, süresi ve güvenlik kontrolü
- **HTTP Durum Kontrolü**: HTTP durum kodları analizi ve yönlendirme takibi
- **Typosquatting Tespiti**: Gelişmiş Levenshtein algoritması ile benzer domain tespiti
- **Punycode Tespiti**: IDN domain kontrolü ve homoglyph tespiti
- **URL Redirect Takibi**: Yönlendirme zinciri analizi ve farklı domain tespiti
- **Subdomain Manipülasyonu**: Şüpheli subdomain eklemeleri tespiti

### 🛡️ Güvenlik Kontrolleri

- **USOM Kontrolü**: Türkiye'nin resmi zararlı bağlantılar listesi (otomatik güncelleme)
- **VirusTotal Entegrasyonu**: 70+ antivirüs motoru ile gerçek zamanlı tehdit kontrolü
- **AbuseIPDB Entegrasyonu**: IP adreslerinin itibar kontrolü ve coğrafi konum bilgisi
- **Certificate Transparency Log**: SSL sertifika geçmişi ve şüpheli sertifika tespiti
- **Kara Liste Kontrolü**: Yerel zararlı domain/IP listesi
- **Güvenli Domain Listesi**: 200+ güvenilir domain (bankalar, e-ticaret, vb.)
- **URL Kısaltma Tespiti**: Kısaltma servisi kullanımı kontrolü
- **Port Numarası Kontrolü**: Standart olmayan port tespiti

### 🤖 AI & Machine Learning Özellikleri

- **ML Skorlama Sistemi**: Öğrenen algoritma ile risk skorlaması
- **Dinamik Ağırlık Sistemi**: Özellik önem analizi ve adaptif skorlama
- **Yanlış Pozitif Azaltma**: Gelişmiş algoritma ile daha doğru tespit
- **Akıllı Cache**: 24 saatlik cache ile hızlı analiz
- **Gelişmiş Phishing Tespiti**: Karakter benzerliği, homoglyph ve TLD manipülasyonu kontrolü

### 💾 Export & Raporlama

- **PDF Raporu**: Detaylı, profesyonel PDF formatında analiz raporu
- **CSV Export**: Veri analizi için CSV formatında export
- **JSON Export**: API uyumlu JSON formatında çıktı
- **Analiz Geçmişi**: Son analizleri görüntüleme ve yönetme

### ⚙️ Gelişmiş Özellikler

- **Risk Skorlama**: 0-100 arası detaylı risk puanı (ML destekli)
- **Yapılandırılabilir Ayarlar**: Şüpheli kelimeler, eşikler, Levenshtein threshold
- **Rate Limiting**: API çağrı limitlerini koruma
- **Güvenli Loglama**: Detaylı log kayıtları (hassas bilgi koruması)
- **Multi-threading**: Asenkron analiz ile hızlı sonuç

### 🔒 Güvenlik Özellikleri

- **AES-256 Şifreleme**: API anahtarları güvenli şifreleme ile saklanır
- **Input Validation**: Tüm kullanıcı girişleri kontrol edilir ve sanitize edilir
- **Path Traversal Koruması**: Dosya erişimleri güvenli şekilde yönetilir
- **XSS Koruması**: Cross-site scripting saldırılarına karşı koruma
- **SQL Injection Koruması**: Veritabanı saldırılarına karşı koruma
- **Rate Limiting**: API abuse'ü önleme

---

## 📦 Kurulum

### ⭐ Yöntem 1: Otomatik Kurulum (Önerilen)

1. **GitHub'dan indirin**: 
   - Projeyi ZIP olarak indirin veya `git clone` ile klonlayın
   ```bash
   git clone https://github.com/YusufDuhan17/ClickProtection.git
   cd ClickProtection/Click_Protection
   ```

2. **ZIP'i çıkarın**: İndirdiğiniz ZIP dosyasını bir klasöre çıkarın

3. **Kurulum.bat çalıştırın**: 
   - `Kurulum.bat` dosyasına çift tıklayın
   - ⚠️ **Not**: Eğer `.bat` dosyası çalışmazsa, `install.py` dosyasına sağ tıklayıp "Python ile Aç" seçeneğini kullanın

4. **Kurulum tamamlandıktan sonra**: 
   - `dist/ClickProtection.exe` dosyasını çalıştırarak uygulamayı başlatın
   - Veya masaüstünden `ClickProtection.exe` ile başlatın

### 🔧 Yöntem 2: Manuel Kurulum

#### Gereksinimler

- Python 3.8 veya üzeri
- pip (Python paket yöneticisi)
- İnternet bağlantısı (paket indirme için)

#### Adımlar

1. **Python'u kontrol edin**:
   ```bash
   python --version
   # veya
   python3 --version
   ```

2. **Projeyi klonlayın veya indirin**:
   ```bash
   git clone https://github.com/YusufDuhan17/ClickProtection.git
   cd ClickProtection/Click_Protection
   ```

3. **Sanal ortam oluşturun** (önerilen):
   ```bash
   python -m venv venv
   
   # Windows
   venv\Scripts\activate
   
   # Linux/macOS
   source venv/bin/activate
   ```

4. **Gerekli paketleri yükleyin**:
   ```bash
   pip install -r requirements.txt
   ```

5. **Uygulamayı çalıştırın**:
   ```bash
   python Click_Protection.py
   ```

### 📋 Gerekli Python Paketleri

```
requests>=2.31.0
python-whois>=0.8.0
python-Levenshtein>=0.21.1
tldextract>=5.0.0
Pillow>=10.0.0
pycryptodome>=3.19.0
reportlab>=4.0.0
scikit-learn>=1.3.0
```

---

## 📖 Kullanım

### Temel Kullanım

1. **Uygulamayı başlatın**: 
   - `ClickProtection.exe` (Windows) veya `python Click_Protection.py`

2. **URL veya IP girin**: 
   - Analiz etmek istediğiniz URL veya IP adresini girin
   - Örnek: `https://example.com` veya `192.168.1.1`

3. **VirusTotal API Key** (Opsiyonel): 
   - Daha detaylı analiz için VirusTotal API anahtarınızı girin
   - Ücretsiz API anahtarı: [VirusTotal API Key](https://www.virustotal.com/gui/my-apikey)

4. **AbuseIPDB API Key** (Opsiyonel): 
   - IP reputation kontrolü için AbuseIPDB API anahtarınızı girin
   - Ücretsiz API anahtarı: [AbuseIPDB Pricing](https://www.abuseipdb.com/pricing)

5. **Kontrol Et**: 
   - "Kontrol Et" butonuna tıklayın
   - Analiz otomatik olarak başlar

6. **Sonuçları İncele**: 
   - Risk skoru ve detaylı analiz sonuçlarını görüntüleyin
   - Her bulgu için detaylı açıklamalar görüntülenir

### Gelişmiş Özellikler

- **Sonuçları Dışa Aktar**: 
  - PDF, CSV veya JSON formatında rapor oluşturun
  - Menüden "Dosya > Sonuçları Dışa Aktar" seçeneğini kullanın

- **Güvenli Domainler Listesi**: 
  - Bilinen güvenli domainleri listeye ekleyin
  - Güvenli listedeki domainler için -20 risk puanı bonusu alın
  - Menüden "Ayarlar > Güvenli Domainler" seçeneğini kullanın

- **Kara Liste Yönetimi**: 
  - Zararlı domain/IP'leri kara listeye ekleyin
  - Menüden "Ayarlar > Kara Liste" seçeneğini kullanın

- **Ayarları Özelleştirin**: 
  - Levenshtein eşiği, risk eşikleri vb. ayarlayın
  - Menüden "Ayarlar > Ayarları Düzenle" seçeneğini kullanın

---

## 📊 Analiz Kriterleri

Uygulama 30+ farklı güvenlik kriterine göre analiz yapar ve 0-100 arası risk skoru verir:

| Kontrol | Risk Puanı | Açıklama |
|---------|-----------|----------|
| 🚫 USOM Zararlı Liste | +60 | Türkiye'nin resmi zararlı bağlantılar listesi |
| 🦠 VirusTotal Zararlı | +40 | 70+ antivirüs motoru tespiti |
| 🔴 Kara Liste | +50 | Yerel zararlı domain/IP listesi |
| 🆕 Yeni Domain (<100 gün) | +50 | Çok yeni domainler riskli |
| 🔒 SSL Sertifikası Süresi Dolmuş | +30 | Güvenli bağlantı yok |
| 🎯 Typosquatting (ML) | +30 | Benzer domain tespiti (ML destekli) |
| 🌐 Punycode Kullanımı | +25 | IDN domain kontrolü |
| 📜 Certificate Transparency | +20 | Şüpheli sertifika geçmişi |
| 🌍 IP Reputation (Yüksek) | +50 | AbuseIPDB yüksek risk skoru |
| 🌍 IP Reputation (Orta) | +30 | AbuseIPDB orta risk skoru |
| 📎 Tehlikeli Dosya Uzantısı | +40 | .exe, .bat, .scr vb. |
| 🔗 URL Kısaltma Servisi | +15 | Gerçek hedef görünmüyor |
| 🔄 URL Redirect (Farklı Domain) | +10 | Farklı domain'e yönlendirme |
| 🔌 Standart Olmayan Port | +10 | Şüpheli port kullanımı |
| 🔴 IP Adresi Kullanımı | +20 | Doğrudan IP adresi |
| 🟠 Çok Fazla Subdomain | +10 | Subdomain manipülasyonu |
| 🟠 Şüpheli Kelimeler | +10 | login, free, update vb. |
| 🟠 Şüpheli Parametreler | +15 | utm_source, gclid vb. |
| ✅ Güvenli Domain Bonusu | **-20** | Güvenli listedeki domainler için bonus |

**Risk Skorları:**
- 🟢 **0-20%**: Güvenli ✅ - Bu URL/IP güvenli görünüyor
- 🟠 **21-60%**: Şüpheli ⚠️ - Dikkatli olun, ek kontroller yapın
- 🔴 **61-100%**: Tehlikeli 🚫 - Bu URL/IP'ye erişmeyin!

---

## 🛠️ Proje Yapısı

```
Click_Protection/
├── Click_Protection.py          # Ana uygulama
├── install.py                    # Kurulum scripti
├── Kurulum.bat                   # Windows kurulum scripti
├── Click_Protection.spec         # PyInstaller spec dosyası
├── requirements.txt              # Python bağımlılıkları
├── README.md                     # Bu dosya
├── LICENSE                       # GPL-3.0 lisansı
├── COPYRIGHT_NOTICE.txt          # Telif hakkı bildirimi
├── LICENSE_INFO.md               # Lisans açıklaması
│
├── modules/                      # Yardımcı modüller
│   ├── logger.py                 # Loglama modülü
│   ├── security.py               # Güvenlik modülü (şifreleme)
│   ├── utils.py                  # Yardımcı fonksiyonlar
│   ├── rate_limiter.py           # Rate limiting
│   ├── usom_checker.py           # USOM kontrol modülü
│   ├── export.py                 # Export modülü (PDF, CSV, JSON)
│   ├── ip_reputation.py          # IP reputation kontrolü
│   ├── certificate_transparency.py # CT log kontrolü
│   ├── advanced_cache.py         # Gelişmiş cache sistemi
│   └── ml_scorer.py              # ML skorlama sistemi
│
├── data/                         # Veri dosyaları
│   ├── blacklist.txt             # Kara liste
│   ├── real_domains.txt          # Güvenli domainler (200+)
│   ├── cache/                    # Cache klasörü
│   ├── reports/                  # Export raporları
│   └── ml/                       # ML model dosyaları
│
├── assets/                       # Görseller
│   ├── CLICKPROLOGO.ico          # Uygulama ikonu
│   └── CLICKPROLOGO.png          # Logo
│
└── docs/                         # Dokümantasyon
    ├── README.md                 # Detaylı dokümantasyon
    └── LICENSE                   # Lisans dosyası (kopya)
```

---

## 🔒 Güvenlik

### Güvenlik Özellikleri

- ✅ **AES-256 Şifreleme**: API anahtarları AES-256 ile şifrelenerek saklanır
- ✅ **Input Validation**: Tüm kullanıcı girişleri kontrol edilir ve sanitize edilir
- ✅ **Path Traversal Koruması**: Dosya erişimleri güvenli şekilde yönetilir
- ✅ **Rate Limiting**: API çağrı limitlerini korur ve abuse'ü önler
- ✅ **Güvenli Loglama**: Hassas bilgiler (API anahtarları, şifreler) loglanmaz
- ✅ **XSS Koruması**: Cross-site scripting saldırılarına karşı koruma
- ✅ **SQL Injection Koruması**: Veritabanı saldırılarına karşı koruma

### Güvenlik Uyarıları

- ⚠️ Bu araç **%100 doğruluk garantisi vermez**
- ⚠️ Sonuçlar **yalnızca bilgilendirme amaçlıdır**
- ⚠️ Kritik güvenlik kararları için **ek araştırma yapın**
- ⚠️ VirusTotal API **limitlerine dikkat edin** (ücretsiz: 4 istek/dakika)
- ⚠️ USOM listesi **güncel olmayabilir** (cache 24 saat)

---

## 📝 Gereksinimler

### Sistem Gereksinimleri

- **Python**: 3.8 veya üzeri (manuel kurulum için)
- **İşletim Sistemi**: Windows 10/11 (önerilen), Linux, macOS
- **İnternet Bağlantısı**: USOM, VirusTotal ve diğer servisler için gerekli
- **Disk Alanı**: ~100 MB (kurulum + cache için)
- **RAM**: Minimum 512 MB (önerilen: 1 GB+)

---

## 🎯 Kullanım Senaryoları

- ✅ **E-posta Güvenliği**: E-posta'da gelen şüpheli linkleri kontrol etme
- ✅ **Sosyal Medya**: Sosyal medyada paylaşılan URL'leri analiz etme
- ✅ **İndirme Güvenliği**: İndirme linklerinin güvenliğini kontrol etme
- ✅ **IP Analizi**: IP adreslerinin güvenlik durumunu öğrenme
- ✅ **Phishing Tespiti**: Phishing saldırılarını tespit etme
- ✅ **Domain Analizi**: Domain yaşı, SSL sertifikası ve güvenlik durumu kontrolü
- ✅ **Raporlama**: Güvenlik raporları oluşturma (PDF, CSV, JSON)

---

## 📞 Destek ve İletişim

- 📧 **E-posta**: sahinyusufduhan@gmail.com
- https://www.linkedin.com/in/yusuf-duhan-sahin-a2b406352/
---

## 📄 Lisans

Bu proje **GNU General Public License v3.0 (GPL-3.0)** altında lisanslanmıştır.

**Telif Hakkı:** Copyright (C) 2024 Yusuf Duhan Şahin

Detaylar için [LICENSE](LICENSE) dosyasına bakın.

### Lisans Koruması

- ✅ Bu proje GPL-3.0 lisansı altında korunmaktadır
- ✅ Kodun açık kaynak olarak kalması garanti edilir
- ✅ Değiştirilmiş versiyonların da açık kaynak olması zorunludur
- ✅ Telif hakkı ihlali durumunda yasal işlem başlatılabilir
- ✅ Lisans ihlali yapanların hakları otomatik olarak sona erer

Detaylı bilgi için [LICENSE_INFO.md](LICENSE_INFO.md) dosyasına bakın.

---

## 🙏 Teşekkürler

- [VirusTotal](https://www.virustotal.com/) - API desteği için
- [USOM](https://www.usom.gov.tr/) - Zararlı bağlantılar listesi için
- [AbuseIPDB](https://www.abuseipdb.com/) - IP reputation servisi için
- [crt.sh](https://crt.sh/) - Certificate Transparency log için
- Tüm katkıda bulunanlar ve açık kaynak topluluğu

---

## 🔄 Önceden siteye yüklediğimden farkları var tabiki;

**Yeni Özellikler:**
- ✅ Machine Learning skorlama sistemi
- ✅ IP Reputation kontrolü (AbuseIPDB)
- ✅ Certificate Transparency log analizi
- ✅ Gelişmiş cache mekanizması (24 saat)
- ✅ Çoklu format export (PDF, CSV, JSON)
- ✅ URL redirect zinciri takibi
- ✅ Gelişmiş phishing tespiti (homoglyph, karakter benzerliği)
- ✅ Coğrafi konum bilgisi
- ✅ Güvenli domain bonusu (-20 risk puanı)

**İyileştirmeler:**
- ✅ WHOIS sorgusu alternatif yöntemlerle iyileştirildi
- ✅ Levenshtein algoritması geliştirildi
- ✅ 200+ güvenli domain eklendi
- ✅ Performans optimizasyonları
- ✅ UI/UX iyileştirmeleri
- ✅ PDF export Türkçe karakter desteği
- ✅ Modern ve kompakt GUI tasarımı

### v1.1

- ✅ USOM entegrasyonu eklendi
- ✅ URL kısaltma servisi kontrolü
- ✅ Port numarası kontrolü
- ✅ Sonuçları kopyalama özelliği
- ✅ Güvenlik iyileştirmeleri
- ✅ Proje yapısı organize edildi
- ✅ Kurulum scripti eklendi

### v1.0

- İlk stabil sürüm
- Temel URL/IP analiz özellikleri
- VirusTotal entegrasyonu
- GUI arayüzü

---

## 👨‍💻 Geliştirici

Bu proje, **Bilişim Güvenliği 2. sınıf öğrencisi** tarafından, yapay zeka desteği ile geliştirilmiştir.

**İlgi Alanları:**
- 🔒 Siber Güvenlik
- 🎯 Penetrasyon Testleri
- 🔍 Sistem Analizleri
- 🌐 Ağ Analizi
- 💻 Web Geliştirme

---

<div align="center">

**⭐ Bu projeyi beğendiyseniz yıldız vermeyi unutmayın! ⭐**

Made with ❤️ for secure internet usage

**🛡️ Güvenli internet kullanımı için geliştirilmiştir**

</div>


