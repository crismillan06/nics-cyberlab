#!/usr/bin/env bash
# ==================================================
# Stage 01 | Escenario base NICS CyberLab
# Caldera + Snort + Wazuh + Integraciones
# ==================================================

set -e

# ======================================
# DIRECTORIOS BASE
# ======================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

INST_DIR="${BASE_DIR}/inst"
LOG_DIR="${BASE_DIR}/log"

# ======================================
# LOGGING
# ======================================
LOG_FILE="${LOG_DIR}/stage01.log"
mkdir -p "${LOG_DIR}"

if [[ -f "${LOG_FILE}" ]]; then
    mv "${LOG_FILE}" "${LOG_FILE}-$(date +%Y%m%d-%H%M).bak"
fi

exec > >(tee -a "${LOG_FILE}") 2>&1
exec 3>>"${LOG_FILE}"

# ======================================
# FUNCIONES
# ======================================
timer() {
    local start=$1
    local end=$(date +%s)
    local diff=$((end - start))
    printf "%02d min %02d seg\n" $((diff / 60)) $((diff % 60))
}

log_block() {
    echo "" >&3
    echo "============================================================" >&3
    echo "$1" >&3
    echo "$(date '+%Y-%m-%d | %H:%M:%S')" >&3
    echo "============================================================" >&3
    echo "" >&3
}

overall_start=$(date +%s)

# ======================================
# INICIO
# ======================================
log_block "INICIO STAGE 01 | EscENARIO BASE"
echo "🚀 Lanzando Stage 01 - Escenario base..."

# ======================================
# PASO 1 | ENTORNO OPENSTACK
# ======================================
log_block "PASO 1 | Activación entorno OpenStack"

if [[ -d "${BASE_DIR}/deploy/openstack_venv" ]]; then
    source "${BASE_DIR}/deploy/openstack_venv/bin/activate"
    echo "[✔] Entorno virtual OpenStack activado."
else
    echo "[✖] No se encontró openstack_venv."
    exit 1
fi

if [[ -f "${BASE_DIR}/admin-openrc.sh" ]]; then
    source "${BASE_DIR}/admin-openrc.sh"
    echo "[✔] admin-openrc cargado."
else
    echo "[✖] No se encontró admin-openrc.sh."
    exit 1
fi

# ======================================
# PASO 2 | DESPLIEGUE BASE (PARALELO)
# ======================================
log_block "PASO 2 | Despliegue herramientas base (paralelo)"
step_start=$(date +%s)

bash "${INST_DIR}/op+caldera.sh" &
PID_CALDERA=$!

bash "${INST_DIR}/op+snort.sh" &
PID_SNORT=$!

bash "${INST_DIR}/op+wazuh.sh" &
PID_WAZUH=$!

echo "[⚙️] Caldera  PID: ${PID_CALDERA}"
echo "[⚙️] Snort    PID: ${PID_SNORT}"
echo "[⚙️] Wazuh    PID: ${PID_WAZUH}"

echo "⏳ Esperando finalización de herramientas base..."
wait ${PID_CALDERA}
wait ${PID_SNORT}
wait ${PID_WAZUH}

echo "[✔] Herramientas base desplegadas en: $(timer $step_start)"
echo "------------------------------------------------------------"

# ======================================
# PASO 3 | INTEGRACIONES (SECUENCIAL)
# ======================================
log_block "PASO 3 | Integraciones"

step_start=$(date +%s)

bash "${INST_DIR}/op+wazuh-snort.sh"
echo "[✔] Integración Wazuh + Snort completada."

bash "${INST_DIR}/op+snort-caldera.sh"
echo "[✔] Integración Snort + Caldera completada."

echo "[✔] Integraciones finalizadas en: $(timer $step_start)"
echo "------------------------------------------------------------"

# ======================================
# FIN
# ======================================
deactivate 2>/dev/null || true

log_block "FIN STAGE 01"

echo "[⏱] Tiempo total Stage 01: $(timer $overall_start)"
echo "[📜] Log completo: ${LOG_FILE}"
