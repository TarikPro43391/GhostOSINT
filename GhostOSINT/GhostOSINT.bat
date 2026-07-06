@echo off
title Ghost OSINT Framework v0.1.1 - Baslatici
color 0A
cd /d "%~dp0"

echo ================================================================
echo   GHOST OSINT FRAMEWORK v0.1.1 (Alpha) - Baslatici
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
echo.
echo Gerekli kutuphaneler kontrol ediliyor / kuruluyor...
echo (Internet yoksa veya zaten kuruluysa bu adim hizlica gecer)
echo.

python -m pip install --disable-pip-version-check -q requests phonenumbers dnspython pillow opencv-python

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
