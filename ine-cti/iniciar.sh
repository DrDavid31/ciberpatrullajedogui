#!/bin/bash
# ═══════════════════════════════════════════════
#  Dogui Ciberpatrullaje — Script de instalación
# ═══════════════════════════════════════════════

echo ""
echo "  DOGUI CIBERPATRULLAJE"
echo ""
echo "  v3.2 — Centro de inteligencia, monitoreo y respuesta digital"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Verificar Python
if ! command -v python3 &>/dev/null; then
    echo "[ERROR] Python 3 no encontrado. Instálalo desde https://python.org"
    exit 1
fi

PY=$(python3 --version 2>&1)
echo "[OK] $PY encontrado"

# Verificar pip
if ! command -v pip3 &>/dev/null && ! python3 -m pip --version &>/dev/null; then
    echo "[ERROR] pip no encontrado. Instala pip antes de continuar."
    exit 1
fi

echo "[OK] pip disponible"
echo ""
echo "[...] Instalando dependencias..."
pip3 install -r requirements.txt -q

if [ $? -ne 0 ]; then
    echo "[ERROR] Falló la instalación de dependencias"
    exit 1
fi

echo "[OK] Dependencias instaladas"
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Iniciando servidor Dogui Ciberpatrullaje..."
echo "  URL: http://localhost:5000"
echo "  Presiona Ctrl+C para detener"
echo "═══════════════════════════════════════════════════════════════"
echo ""

python3 app.py
