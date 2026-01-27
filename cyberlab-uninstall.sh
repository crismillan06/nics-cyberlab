#!/bin/bash
# ==================================================
# Script de desinstalación automática de NICS | CyberLab
# ==================================================

set -e

# ======================================
# DIRECTORIOS BASE (ROBUSTO)
# ======================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="${SCRIPT_DIR}"

UNDEPLOY_DIR="${BASE_DIR}/undeploy"
LOG_DIR="${BASE_DIR}/log"

# ======================================
# SECCIÓN DE CONFIGURACION DE LOS LOGS
# ======================================
LOG_FILE="${LOG_DIR}/cyberlab-uninstall.log"

mkdir -p "${LOG_DIR}"

if [[ -f "${LOG_FILE}" ]]; then
    mv "${LOG_FILE}" "${LOG_FILE}-$(date +%Y%m%d-%H%M).bak"
fi

exec > >(tee -a "${LOG_FILE}") 2>&1
exec 3>>"${LOG_FILE}"

# ===========================
# FUNCIONES
# ===========================
timer() {
    local start_time=$1
    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - start_time))
    printf "%02d min %02d seg\n" $((duration / 60)) $((duration % 60))
}

log_block() {
    echo "" >&3
    echo "============================================================" >&3
    echo "$1" >&3
    echo "$(date '+%Y-%m-%d | %H:%M:%S')" >&3
    echo "============================================================" >&3
    echo "" >&3
}

require_script() {
    local f="$1"
    if [[ ! -f "$f" ]]; then
        echo "[✖] No se encontró el script requerido: $f" >&3
        return 1
    fi
    return 0
}

# Ejecuta un paso sin abortar todo el uninstall si falla.
# Mantiene set -e global pero hace best-effort por paso.
run_step() {
    local title="$1"
    shift

    log_block "$title"
    local step_start
    step_start=$(date +%s)

    set +e
    "$@"
    local rc=$?
    set -e

    if [[ $rc -eq 0 ]]; then
        echo "[✔] Paso completado en: $(timer $step_start)" >&3
    else
        echo "[!] Paso terminó con errores (rc=$rc) en: $(timer $step_start)" >&3
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    echo "------------------------------------------------------------" >&3
    return 0
}

# Wrapper para ejecutar scripts desde la raíz del repo (importante para scripts con rutas relativas)
run_from_root() {
    local script_path="$1"
    shift || true
    bash -c "cd '${BASE_DIR}' && bash '${script_path}' $*"
}

# ===========================
# INICIO
# ===========================
FAIL_COUNT=0
overall_start=$(date +%s)

log_block "INICIO DE LA DESINSTALACIÓN DE NICS | CyberLab"
echo "Iniciando desinstalación completa de NICS | CyberLab..."
echo "[i] Base     : ${BASE_DIR}"
echo "[i] Undeploy : ${UNDEPLOY_DIR}"
echo "[i] Log      : ${LOG_FILE}"
echo "------------------------------------------------------------"

# ===========================
# PASO 0 | Detener Dashboard (best-effort)
# ===========================
run_step "PASO 0 | Detener Dashboard (best-effort)" bash -c "
  # Intento conservador: matar solo si el proceso referencia start_dashboard.sh
  pkill -f \"${BASE_DIR}/gui/start_dashboard.sh\" >/dev/null 2>&1 || true
  pkill -f \"start_dashboard.sh\" >/dev/null 2>&1 || true
  exit 0
"

# ===========================
# PASO 1 | Eliminar recursos OpenStack base del laboratorio
# ===========================
if require_script "${UNDEPLOY_DIR}/openstack-resources-uninstall.sh"; then
  run_step "PASO 1 | Eliminación de recursos OpenStack (imágenes, flavors, redes, SG, keypair, artefactos)" \
    bash "${UNDEPLOY_DIR}/openstack-resources-uninstall.sh"
else
  echo "[✖] Falta ${UNDEPLOY_DIR}/openstack-resources-uninstall.sh (no puedo continuar de forma fiable)." >&3
  exit 1
fi

# ===========================
# PASO 2 | Reglas de red / iptables (uplinkbridge)
# ===========================
if require_script "${UNDEPLOY_DIR}/uplinkbridge-uninstall.sh"; then
  run_step "PASO 2 | Eliminación de reglas de red / iptables (uplinkbridge)" \
    sudo bash "${UNDEPLOY_DIR}/uplinkbridge-uninstall.sh"
else
  echo "[ℹ] No se ejecuta PASO 2 (script no encontrado)." >&3
  echo "------------------------------------------------------------" >&3
fi

# ===========================
# PASO 3 | Eliminar credenciales / OpenRC
# ===========================
if require_script "${UNDEPLOY_DIR}/admin-openrc_uninstall.sh"; then
  # IMPORTANTE: este script borra admin-openrc.sh por ruta relativa -> forzar ejecución desde BASE_DIR
  run_step "PASO 3 | Eliminación de credenciales (admin-openrc.sh + cleanup)" \
    bash -c "cd '${BASE_DIR}' && bash '${UNDEPLOY_DIR}/admin-openrc_uninstall.sh'"
else
  echo "[ℹ] No se ejecuta PASO 3 (script no encontrado)." >&3
  echo "------------------------------------------------------------" >&3
fi

# ===========================
# PASO 4 | Desinstalar OpenStack
# ===========================
if require_script "${UNDEPLOY_DIR}/openstack-uninstall.sh"; then
  run_step "PASO 4 | Desinstalación de OpenStack" \
    sudo bash "${UNDEPLOY_DIR}/openstack-uninstall.sh"
else
  echo "[ℹ] No se ejecuta PASO 4 (script no encontrado)." >&3
  echo "------------------------------------------------------------" >&3
fi

# Desactivar venv si estuviera activo
deactivate 2>/dev/null || true

# ===========================
# FIN
# ===========================
log_block "FIN DEL PROCESO"
echo "[⏱] Tiempo total de desinstalación: $(timer $overall_start)"
echo "[📜] Log completo registrado en: ${LOG_FILE}"

if [[ "${FAIL_COUNT}" -gt 0 ]]; then
  echo "[!] Finalizado con ${FAIL_COUNT} paso(s) con errores. Revisa el log."
  exit 2
fi

echo "[✔] Desinstalación completada correctamente."
exit 0
