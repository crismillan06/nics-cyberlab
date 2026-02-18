#!/usr/bin/env bash
# =============================================
# Script para cargar entorno y cargar varibles
# =============================================

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="${BASE_DIR}/deploy"

echo "🔹 Activando entorno virtual de OpenStack..."
step_start=$(date +%s)

if [[ -d "${DEPLOY_DIR}/openstack_venv" ]]; then
    source "${DEPLOY_DIR}/openstack_venv/bin/activate"
    echo "[✔] Entorno virtual 'openstack_venv' activado correctamente."
else
    echo "[✖] No se encontró el entorno 'openstack_venv'."
    exit 1
fi

step_end=$(date +%s)
echo "-------------------------------------------"
sleep 1

# ===== Cargar variables de entorno OpenStack =====
if [[ -f "${BASE_DIR}/admin-openrc.sh" ]]; then
    echo "[+] Cargando variables del entorno OpenStack (admin-openrc.sh)..."
    source "${BASE_DIR}/admin-openrc.sh"
    echo "[✔] Variables cargadas correctamente."
    echo "-------------------------------------------"
    sleep 1
else
    echo "[✖] No se encontró 'admin-openrc.sh'."
    exit 1
fi
