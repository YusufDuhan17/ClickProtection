@echo off
chcp 65001 >nul
title Click Protection - Kurulum
color 0A

echo.
echo ============================================================
echo   CLICK PROTECTION - KURULUM
echo ============================================================
echo.

REM Python'un yüklü olup olmadığını kontrol et
python --version >nul 2>&1
if errorlevel 1 (
    echo [HATA] Python bulunamadı!
    echo.
    echo Lutfen Python'u yukleyin: https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

REM install.py dosyasını çalıştır
python "%~dp0install.py"

REM Hata durumunda bekle
if errorlevel 1 (
    echo.
    echo [HATA] Kurulum sirasinda bir hata olustu!
    pause
    exit /b 1
)

exit /b 0

