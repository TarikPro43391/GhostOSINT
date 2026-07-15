@echo off
title Ghost OSINT Framework v0.1.5 - Kurulum ve Baslatici
color 0A
cd /d "%~dp0"

echo ================================================================
echo   GHOST OSINT FRAMEWORK v0.1.5 (Alpha) - Kurulum ve Baslatici
echo   by TarikPro43391
echo ================================================================
echo.

REM --- Python kurulu mu kontrol et ---
python --version >nul 2>&1
if errorlevel 1 (
    echo [HATA] Python bulunamadi. Lutfen Python 3 kurun ve PATH'e ekleyin.
    echo https://www.python.org/downloads/
    pause
    exit /b 1
)

echo [OK] Python bulundu.
echo ================================================================
echo Gerekli Python kutuphaneleri kontrol ediliyor/kuruluyor...
echo (requests, phonenumbers, dnspython, Pillow, opencv, xhtml2pdf, playwright)
echo.

REM -q (sessiz mod) kaldirildi, boylece kullanici kurulumu ve olasi hatalari gorebilir.
python -m pip install --disable-pip-version-check requests phonenumbers dnspython pillow opencv-python xhtml2pdf playwright

echo.
echo [OK] Kutuphane kurulumu tamamlandi.
echo ================================================================
echo Playwright icin gerekli tarayici (Chromium) kuruluyor.
echo Bu islem internet hiziniza bagli olarak biraz surebilir...
echo.
python -m playwright install --with-deps chromium

echo.
echo ================================================================
echo   Ghost OSINT baslatiliyor...
echo ================================================================
echo.

python "GhostOSINT.py"

if errorlevel 1 (
    echo.
    echo [HATA] Program bir hata ile kapandi. Yukaridaki mesaji kontrol et.
    pause
)

exit /b 0
