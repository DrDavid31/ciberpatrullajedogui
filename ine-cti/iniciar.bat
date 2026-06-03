@echo off
chcp 65001 > nul
echo.
echo  ═══════════════════════════════════════════════════════
echo   DOGUI CIBERPATRULLAJE v3.1
echo   Centro de inteligencia, monitoreo y respuesta digital
echo  ═══════════════════════════════════════════════════════
echo.

:: Verificar Python
python --version > nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python no encontrado.
    echo         Descargalo desde https://python.org
    pause
    exit /b 1
)

echo [OK] Python encontrado
echo [..] Instalando dependencias...
pip install -r requirements.txt -q

if %errorlevel% neq 0 (
    echo [ERROR] Fallo la instalacion de dependencias
    pause
    exit /b 1
)

echo [OK] Dependencias instaladas
echo.
echo  Iniciando servidor...
echo  Abre tu navegador en: http://localhost:5000
echo  Presiona Ctrl+C para detener
echo.
start "" http://localhost:5000
python app.py
pause
