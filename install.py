"""
Click Protection - Kurulum Scripti

Bu script uygulamayı kurar ve gerekli kontrolleri yapar.
"""

import os
import sys
import subprocess
import shutil
import time
import threading
from pathlib import Path

# Windows'ta konsol kodlamasını UTF-8 yap
if sys.platform == 'win32':
    try:
        import codecs
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
        sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')
    except:
        pass

class Installer:
    """Kurulum yöneticisi"""
    
    def __init__(self):
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        self.python_exe = sys.executable
        self.required_packages = [
            'requests',
            'python-whois',
            'python-Levenshtein',
            'tldextract',
            'Pillow',
            'pycryptodome'
        ]
        
    def print_step(self, message):
        """Adım mesajı yazdır"""
        print(f"\n{'='*60}")
        print(f"  {message}")
        print(f"{'='*60}\n")
    
    def check_python(self):
        """Python versiyonunu kontrol et"""
        self.print_step("Python Versiyonu Kontrol Ediliyor...")
        version = sys.version_info
        print(f"Python {version.major}.{version.minor}.{version.micro} tespit edildi")
        
        if version.major < 3 or (version.major == 3 and version.minor < 8):
            print("❌ HATA: Python 3.8 veya üzeri gerekli!")
            print("Lütfen Python'u güncelleyin: https://www.python.org/downloads/")
            return False
        
        print("✅ Python versiyonu uygun")
        return True
    
    def check_pip(self):
        """pip'in yüklü olup olmadığını kontrol et"""
        self.print_step("pip Kontrol Ediliyor...")
        try:
            subprocess.run([self.python_exe, '-m', 'pip', '--version'], 
                         check=True, capture_output=True)
            print("✅ pip yüklü")
            return True
        except:
            print("❌ HATA: pip bulunamadı!")
            print("Lütfen pip'i yükleyin veya Python'u yeniden yükleyin.")
            return False
    
    def check_packages(self):
        """Gerekli paketlerin yüklü olup olmadığını kontrol et"""
        self.print_step("Paketler Kontrol Ediliyor...")
        missing_packages = []
        
        for package in self.required_packages:
            # Paket adını normalize et
            import_name = package.replace('-', '_').replace('python-', '')
            if package == 'python-whois':
                import_name = 'whois'
            elif package == 'python-Levenshtein':
                import_name = 'Levenshtein'
            elif package == 'Pillow':
                import_name = 'PIL'
            elif package == 'pycryptodome':
                import_name = 'Crypto'
            
            try:
                __import__(import_name)
                print(f"✅ {package} yüklü")
            except ImportError:
                print(f"❌ {package} bulunamadı")
                missing_packages.append(package)
        
        return missing_packages
    
    def install_packages(self, packages):
        """Paketleri yükle"""
        if not packages:
            return True
        
        self.print_step(f"{len(packages)} Paket Yükleniyor...")
        print("📦 Paketler yükleniyor, lütfen bekleyin...\n")
        
        try:
            # requirements.txt varsa onu kullan
            requirements_file = os.path.join(self.script_dir, 'requirements.txt')
            if os.path.exists(requirements_file):
                print("📄 requirements.txt dosyası kullanılıyor...")
                print("="*60)
                print("🔄 Güvenli paketler yükleniyor...")
                print("💡 Bu işlem birkaç dakika sürebilir, lütfen bekleyin.")
                print("="*60 + "\n")
                
                # Çıktıyı gizle, sadece ilerleme göster
                import time
                process = subprocess.Popen(
                    [self.python_exe, '-m', 'pip', 'install', '-r', requirements_file, '--quiet', '--disable-pip-version-check'],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                # İlerleme göstergesi
                dots = 0
                while process.poll() is None:
                    dots = (dots + 1) % 4
                    print(f"\r{' ' * 50}\r🔄 Yükleniyor{'.' * dots}", end='', flush=True)
                    time.sleep(0.5)
                
                process.wait()
                print("\r" + " " * 50 + "\r", end='')  # Satırı temizle
                
                if process.returncode == 0:
                    print("✅ Tüm paketler başarıyla yüklendi!")
                    return True
                else:
                    print(f"❌ Paket yükleme hatası (Kod: {process.returncode})")
                    return False
            else:
                # Tek tek yükle (sessiz mod)
                for i, package in enumerate(packages, 1):
                    print(f"📦 [{i}/{len(packages)}] {package} yükleniyor...", end=' ', flush=True)
                    result = subprocess.run([self.python_exe, '-m', 'pip', 'install', package, '--quiet', '--disable-pip-version-check'],
                                         capture_output=True, text=True)
                    if result.returncode == 0:
                        print("✅")
                    else:
                        print("❌")
            
            return True
        except subprocess.CalledProcessError as e:
            print(f"\n❌ HATA: Paket yükleme başarısız: {e}")
            if e.stdout:
                print("Çıktı:", e.stdout)
            if e.stderr:
                print("Hata:", e.stderr)
            return False
    
    def check_files(self):
        """Gerekli dosyaların mevcut olup olmadığını kontrol et"""
        self.print_step("Dosyalar Kontrol Ediliyor...")
        
        required_files = [
            'Click_Protection.py',
            'requirements.txt',
            'modules/logger.py',
            'modules/security.py',
            'modules/utils.py',
            'modules/rate_limiter.py',
            'modules/usom_checker.py',
            'data/config.ini',
            'assets/CLICKPROLOGO.png'
        ]
        
        missing_files = []
        for file_path in required_files:
            full_path = os.path.join(self.script_dir, file_path)
            if os.path.exists(full_path):
                print(f"✅ {file_path}")
            else:
                print(f"❌ {file_path} bulunamadı")
                missing_files.append(file_path)
        
        return len(missing_files) == 0
    
    def check_pyinstaller(self):
        """PyInstaller'ın yüklü olup olmadığını kontrol et"""
        try:
            subprocess.run([self.python_exe, '-m', 'PyInstaller', '--version'], 
                         check=True, capture_output=True)
            return True
        except:
            return False
    
    def build_exe(self):
        """EXE dosyası oluştur"""
        self.print_step("EXE Dosyası Oluşturuluyor...")
        
        # PyInstaller kontrolü
        if not self.check_pyinstaller():
            print("⚠️ PyInstaller bulunamadı. Yükleniyor...")
            try:
                print("📦 PyInstaller yükleniyor, lütfen bekleyin...")
                subprocess.run([self.python_exe, '-m', 'pip', 'install', 'pyinstaller'],
                             check=True)
                print("✅ PyInstaller yüklendi")
            except Exception as e:
                print(f"❌ PyInstaller yüklenemedi: {e}")
                return False
        
        # EXE dosyası zaten var mı kontrol et (onefile modu için)
        exe_path = os.path.join(self.script_dir, 'dist', 'ClickProtection.exe')
        if os.path.exists(exe_path):
            response = input("\n⚠️ EXE dosyası zaten mevcut. Yeniden oluşturmak ister misiniz? (E/H): ")
            if not response.upper().strip().startswith('E'):
                print("✅ Mevcut EXE dosyası kullanılacak")
                return True
        
        # Spec dosyası kontrolü
        spec_file = os.path.join(self.script_dir, 'Click_Protection.spec')
        if not os.path.exists(spec_file):
            print(f"❌ Spec dosyası bulunamadı: {spec_file}")
            return False
        
        print("\n" + "="*60)
        print("  EXE DOSYASI OLUŞTURULUYOR")
        print("="*60)
        print("\n⚠️ ÖNEMLİ: Bu işlem 2-5 dakika sürebilir!")
        print("📝 PyInstaller şu adımları gerçekleştiriyor:")
        print("   1. Modülleri analiz ediyor...")
        print("   2. Bağımlılıkları topluyor...")
        print("   3. EXE dosyasını oluşturuyor...")
        print("\n💡 İpucu: Bu süreçte bilgisayarınız biraz yavaşlayabilir.")
        print("="*60 + "\n")
        
        input("Devam etmek için Enter'a basın...")
        
        try:
            # PyInstaller'ı çalıştır - çıktıyı gizle, animasyon göster
            print("\n🔄 PyInstaller başlatılıyor...")
            print("💡 Bu işlem 2-5 dakika sürebilir, lütfen bekleyin...\n")
            
            # Türkçe karakter içermeyen build ve dist klasörleri oluştur
            import tempfile
            temp_build_dir = os.path.join(tempfile.gettempdir(), 'ClickProtection_build')
            dist_dir = os.path.join(self.script_dir, 'dist')
            
            # Build klasörünü oluştur
            os.makedirs(temp_build_dir, exist_ok=True)
            os.makedirs(dist_dir, exist_ok=True)
            
            # Hata log dosyası
            error_log = os.path.join(self.script_dir, 'pyinstaller_error.log')
            
            # PyInstaller'ı arka planda çalıştır (çıktıyı gizle)
            creation_flags = 0
            if sys.platform == 'win32':
                creation_flags = subprocess.CREATE_NO_WINDOW
            
            # PyInstaller komutu - workpath ve distpath parametreleri ile
            pyinstaller_cmd = [
                self.python_exe, '-m', 'PyInstaller',
                '--clean', '--noconfirm',
                '--workpath', temp_build_dir,
                '--distpath', dist_dir,
                spec_file
            ]
            
            # Çıktıyı log dosyasına yönlendir (hata ayıklama için)
            with open(error_log, 'w', encoding='utf-8') as log_file:
                process = subprocess.Popen(
                    pyinstaller_cmd,
                    cwd=self.script_dir,
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    creationflags=creation_flags
                )
                
                # Animasyonlu ilerleme göstergesi
                steps = [
                    "Modülleri analiz ediyor",
                    "Bağımlılıkları topluyor", 
                    "Dosyaları paketliyor",
                    "EXE dosyasını oluşturuyor"
                ]
                step_idx = 0
                dots = 0
                start_time = time.time()
                last_step_change = start_time
                
                # Animasyon döngüsü - process bitene kadar
                while process.poll() is None:
                    elapsed = int(time.time() - start_time)
                    current_step = steps[step_idx % len(steps)]
                    dots = (dots + 1) % 4
                    
                    # Her 10 saniyede bir adım değiştir
                    if time.time() - last_step_change >= 10:
                        step_idx = (step_idx + 1) % len(steps)
                        last_step_change = time.time()
                    
                    # Zamanı dakika:saniye formatında göster
                    mins = elapsed // 60
                    secs = elapsed % 60
                    time_str = f"{mins}:{secs:02d}" if mins > 0 else f"{secs}s"
                    
                    print(f"\r{' ' * 80}\r🔄 {current_step}{'.' * dots} [{time_str}]", end='', flush=True)
                    time.sleep(0.5)
                
                # Process tamamlanmasını bekle
                return_code = process.wait()
            
            
            print("\r" + " " * 80 + "\r", end='')  # Satırı temizle
            
            print("\n" + "="*60)
            print("PYINSTALLER TAMAMLANDI")
            print("="*60 + "\n")
            
            if return_code == 0:
                if os.path.exists(exe_path):
                    print(f"✅ EXE dosyası başarıyla oluşturuldu!")
                    print(f"📁 Konum: {exe_path}")
                    return True
                else:
                    print("⚠️ PyInstaller tamamlandı ancak EXE dosyası bulunamadı")
                    print("📁 Kontrol edin: dist/ClickProtection/ klasörü")
                    return False
            else:
                print(f"❌ EXE oluşturma hatası (Kod: {return_code})")
                print("💡 PyInstaller bir hata ile sonlandı.")
                # Hata logunu göster
                if os.path.exists(error_log):
                    print(f"\n📋 Hata detayları için log dosyasına bakın: {error_log}")
                    # Son 10 satırı göster
                    try:
                        with open(error_log, 'r', encoding='utf-8') as f:
                            lines = f.readlines()
                            if lines:
                                print("\n⚠️ Son hata satırları:")
                                for line in lines[-10:]:
                                    print(f"   {line.rstrip()}")
                    except:
                        pass
                return False
        except Exception as e:
            print(f"\n❌ EXE oluşturma hatası: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def create_desktop_shortcut(self):
        """Masaüstü kısayolu oluştur ve EXE'yi kopyala"""
        self.print_step("Masaüstü Kısayolu Oluşturuluyor...")
        
        try:
            desktop = os.path.join(os.path.expanduser("~"), "Desktop")
            if not os.path.exists(desktop):
                desktop = os.path.join(os.path.expanduser("~"), "Masaüstü")
            
            if not os.path.exists(desktop):
                print("⚠️ Masaüstü klasörü bulunamadı, kısayol oluşturulamadı")
                return False
            
            # EXE dosyası yolunu kontrol et (onefile modu için)
            exe_path = os.path.join(self.script_dir, 'dist', 'ClickProtection.exe')
            desktop_exe = os.path.join(desktop, 'ClickProtection.exe')
            
            if os.path.exists(exe_path):
                # EXE'yi masaüstüne kopyala
                print(f"📁 EXE dosyası masaüstüne kopyalanıyor...")
                try:
                    import shutil
                    shutil.copy2(exe_path, desktop_exe)
                    print(f"✅ EXE dosyası masaüstüne kopyalandı: {desktop_exe}")
                    print(f"💡 Artık masaüstündeki 'ClickProtection.exe' dosyasını çift tıklayarak çalıştırabilirsiniz!")
                    return True
                except Exception as e:
                    print(f"❌ EXE kopyalama hatası: {e}")
                    return False
            else:
                print("⚠️ EXE dosyası bulunamadı!")
                print(f"📁 Kontrol edin: {exe_path}")
                return False
        except Exception as e:
            print(f"⚠️ Kısayol oluşturulamadı: {e}")
            return False
    
    def run(self):
        """Kurulumu çalıştır"""
        print("\n" + "="*60)
        print("  CLICK PROTECTION - KURULUM")
        print("="*60 + "\n")
        
        # 1. Python kontrolü
        if not self.check_python():
            input("\nKurulum durduruldu. Devam etmek için Enter'a basın...")
            return False
        
        # 2. pip kontrolü
        if not self.check_pip():
            input("\nKurulum durduruldu. Devam etmek için Enter'a basın...")
            return False
        
        # 3. Dosya kontrolü
        if not self.check_files():
            print("\n⚠️ Bazı dosyalar eksik görünüyor, ancak kurulum devam ediyor...")
        
        # 4. Paket kontrolü ve yükleme
        missing = self.check_packages()
        if missing:
            print(f"\n⚠️ {len(missing)} paket eksik bulundu:")
            for pkg in missing:
                print(f"   - {pkg}")
            response = input(f"\n❓ Bu eksik paketleri yüklemek ister misiniz? (E/H): ")
            if response.upper().strip().startswith('E'):
                if not self.install_packages(missing):
                    print("\n❌ Paket yükleme başarısız!")
                    input("\nKurulum durduruldu. Devam etmek için Enter'a basın...")
                    return False
            else:
                print("⚠️ Eksik paketler yüklenmedi. Uygulama çalışmayabilir.")
                response2 = input("Yine de devam etmek istiyor musunuz? (E/H): ")
                if not response2.upper().strip().startswith('E'):
                    print("Kurulum iptal edildi.")
                    input("\nÇıkmak için Enter'a basın...")
                    return False
        else:
            print("\n✅ Tüm paketler zaten yüklü! Tekrar yükleme yapılmıyor.")
        
        # 5. EXE dosyası oluştur
        print("\n" + "="*60)
        print("  SONRAKI ADIM: EXE DOSYASI OLUŞTURMA")
        print("="*60)
        response = input("\n❓ EXE dosyası oluşturmak istiyor musunuz? (E/H): ")
        if response.upper().strip().startswith('E'):
            exe_created = self.build_exe()
        else:
            print("⚠️ EXE oluşturma atlandı. Uygulamayı Python ile çalıştırabilirsiniz.")
            exe_created = False
        
        # 6. Masaüstü kısayolu
        print("\n" + "="*60)
        print("  SONRAKI ADIM: MASAUSTU KISAYOLU")
        print("="*60)
        response = input("\n❓ Masaüstü kısayolu oluşturmak istiyor musunuz? (E/H): ")
        if response.upper().strip().startswith('E'):
            self.create_desktop_shortcut()
        else:
            print("⚠️ Masaüstü kısayolu oluşturulmadı.")
        
        # Masaüstü yolunu al (başlatma için)
        desktop = os.path.join(os.path.expanduser("~"), "Desktop")
        if not os.path.exists(desktop):
            desktop = os.path.join(os.path.expanduser("~"), "Masaüstü")
        
        # 7. Başarı mesajı
        self.print_step("KURULUM TAMAMLANDI!")
        print("✅ Click Protection başarıyla kuruldu!")
        print(f"\n📁 Kurulum Dizini: {self.script_dir}")
        
        # EXE dosyası yolu (onefile modu için)
        exe_path = os.path.join(self.script_dir, 'dist', 'ClickProtection.exe')
        
        print("\n" + "="*60)
        print("  UYGULAMAYI BAŞLATMA")
        print("="*60)
        print("\n🚀 Uygulamayı başlatmak için seçenekleriniz:")
        if exe_created and os.path.exists(exe_path):
            desktop_exe = os.path.join(desktop, 'ClickProtection.exe')
            if os.path.exists(desktop_exe):
                print(f"\n   ⭐ ÖNERİLEN: Masaüstündeki 'ClickProtection.exe' dosyasını çift tıklayın")
            else:
                print(f"\n   ⭐ ÖNERİLEN: '{exe_path}' dosyasını çift tıklayın")
                print(f"   VEYA: Masaüstüne kopyalayıp oradan çalıştırın")
        else:
            print(f"\n   1. '{self.script_dir}' klasöründeki 'Click_Protection.py' dosyasını çalıştırın")
            print(f"   2. VEYA şu komutu çalıştırın:")
            print(f"      python \"{os.path.join(self.script_dir, 'Click_Protection.py')}\"")
        
        response = input("\n❓ Şimdi uygulamayı başlatmak ister misiniz? (E/H): ")
        if response.upper().strip().startswith('E'):
            try:
                desktop_exe = os.path.join(desktop, 'ClickProtection.exe')
                if exe_created and os.path.exists(desktop_exe):
                    print(f"\n🚀 Masaüstündeki EXE dosyası başlatılıyor: {desktop_exe}")
                    subprocess.Popen([desktop_exe])
                    print("✅ Uygulama başlatıldı!")
                elif exe_created and os.path.exists(exe_path):
                    print(f"\n🚀 EXE dosyası başlatılıyor: {exe_path}")
                    subprocess.Popen([exe_path])
                    print("✅ Uygulama başlatıldı!")
                else:
                    print(f"\n🚀 Python scripti başlatılıyor...")
                    subprocess.Popen([self.python_exe, os.path.join(self.script_dir, 'Click_Protection.py')])
                    print("✅ Uygulama başlatıldı!")
            except Exception as e:
                print(f"\n❌ Uygulama başlatılamadı: {e}")
                print("💡 Lütfen manuel olarak başlatmayı deneyin.")
        
        print("\n" + "="*60)
        print("  KURULUM TAMAMLANDI")
        print("="*60)
        print("\n✅ Tüm işlemler tamamlandı!")
        print("💡 İyi kullanımlar!")
        
        input("\n\nÇıkmak için Enter'a basın...")
        return True

if __name__ == "__main__":
    try:
        installer = Installer()
        installer.run()
    except KeyboardInterrupt:
        print("\n\n⚠️ Kurulum kullanıcı tarafından iptal edildi.")
        input("\nÇıkmak için Enter'a basın...")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Beklenmeyen bir hata oluştu: {e}")
        import traceback
        traceback.print_exc()
        input("\nÇıkmak için Enter'a basın...")
        sys.exit(1)

