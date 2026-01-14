#!/bin/bash
# ==========================================================
# Script: level-01.sh
# Ubicación: ./lab/level-01.sh
#
# Descripción:
#   Ejecuta el escenario "Level" desplegando e integrando:
#     1) inst/op+snort.sh
#     2) inst/op+wazuh.sh
#     3) inst/op+caldera.sh
#     4) inst/op+snort-caldera.sh
#     5) inst/op+wazuh-snort.sh
#
# Requisitos:
#   - Guarda TODA la salida en: ./log/level.log (append)
#   - Separa escenarios con:
#       #################### LEVEL 01 ####################
#       #################### LEVEL 02 ####################
#   - Instala nmap en caldera-server
#   - Asegura readiness de Caldera (puerto 8888 accesible desde snort)
#   - Muestra al final credenciales/URLs y tiempo total
# ==========================================================

set -euo pipefail

# ======================================
# DIRECTORIOS BASE (ROBUSTO)
# ======================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

INST_DIR="${BASE_DIR}/inst"
LOG_DIR="${BASE_DIR}/log"
LOG_FILE="${LOG_DIR}/level.log"

# ======================================
# FUNCIONES
# ======================================
timer() {
  local start_time=$1
  local end_time
  end_time=$(date +%s)
  local duration=$((end_time - start_time))
  printf "%02d min %02d seg\n" $((duration / 60)) $((duration % 60))
}

format_time_long() {
  local total=$1
  echo "$((total/60)) minutos y $((total%60)) segundos"
}

die() {
  echo "[✖] $*" >&2
  exit 1
}

require_file() {
  [[ -f "$1" ]] || die "No se encontró el fichero: $1"
}

next_level_number() {
  if [[ ! -f "${LOG_FILE}" ]]; then
    echo "01"
    return 0
  fi
  local last
  last="$(grep -Eo 'LEVEL[[:space:]]+[0-9]+' "${LOG_FILE}" 2>/dev/null | awk '{print $2}' | tail -n 1 || true)"
  if [[ -z "${last}" ]]; then
    echo "01"
    return 0
  fi
  printf "%02d" $((10#${last} + 1))
}

log_block() {
  echo ""
  echo "============================================================"
  echo "$1"
  echo "$(date '+%Y-%m-%d | %H:%M:%S')"
  echo "============================================================"
  echo ""
}

run_script() {
  local script="$1"
  require_file "$script"
  log_block "EJECUTANDO: $(basename "$script")"
  # Ejecutar SIEMPRE desde la raíz del proyecto para que $PWD de los scripts sea correcto
  ( cd "$BASE_DIR" && bash "$script" )
  echo "------------------------------------------------------------"
}

extract_ips_from_addresses() {
  local server="$1"
  local addrs
  addrs="$(openstack server show "$server" -f value -c addresses 2>/dev/null || true)"
  [[ -n "$addrs" ]] || return 1
  echo "$addrs" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | awk '!seen[$0]++'
}

ip_in_cidr() {
  local ip="$1" cidr="$2"
  python3 - <<PY
import ipaddress
ip = ipaddress.ip_address("$ip")
net = ipaddress.ip_network("$cidr", strict=False)
print("1" if ip in net else "0")
PY
}

resolve_private_and_external_ip() {
  local server="$1" private_cidr="$2"
  local ips ip priv="" ext=""

  ips="$(extract_ips_from_addresses "$server" || true)"
  [[ -n "${ips}" ]] || return 1

  while read -r ip; do
    [[ -z "$ip" ]] && continue
    if [[ "$(ip_in_cidr "$ip" "$private_cidr")" == "1" ]]; then
      priv="$ip"
    else
      ext="$ip"
    fi
  done <<<"$ips"

  [[ -n "$priv" ]] || return 1
  echo "$priv $ext"
}

ensure_floating_ip_if_missing() {
  local server="$1" private_cidr="$2" network_external="$3"
  local ips ip has_external=0

  ips="$(extract_ips_from_addresses "$server" || true)"
  if [[ -n "${ips:-}" ]]; then
    while read -r ip; do
      [[ -z "$ip" ]] && continue
      if [[ "$(ip_in_cidr "$ip" "$private_cidr")" == "0" ]]; then
        has_external=1
        break
      fi
    done <<<"$ips"
  fi

  (( has_external )) && return 0

  echo "[!] '$server' no tiene IP externa. Asignando Floating IP..."
  local free_fip
  free_fip="$(openstack floating ip list -f value -c "Floating IP Address" -c "Fixed IP Address" \
    | awk '$2=="None"{print $1; exit}' || true)"

  if [[ -z "$free_fip" ]]; then
    free_fip="$(openstack floating ip create "$network_external" -f value -c floating_ip_address)" \
      || die "No se pudo crear Floating IP en $network_external"
  fi

  ssh-keygen -f "$HOME/.ssh/known_hosts" -R "$free_fip" >/dev/null 2>&1 || true
  openstack server add floating ip "$server" "$free_fip" || die "No se pudo asociar Floating IP $free_fip a $server"
  echo "[✔] Floating IP asignada a '$server': $free_fip"
}

wait_ssh() {
  local host="$1"
  local ssh_user="$2"
  local ssh_key="$3"
  local timeout="${4:-300}"
  local start now
  start=$(date +%s)
  echo "[+] Esperando SSH en $host ..."
  until ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -i "$ssh_key" "$ssh_user@$host" "echo ok" >/dev/null 2>&1; do
    sleep 5; echo -n "."
    now=$(date +%s)
    if (( now - start > timeout )); then
      echo ""
      die "Timeout SSH a $host"
    fi
  done
  echo ""
  echo "[✔] SSH disponible en $host"
}

ensure_sg_rule() {
  local sg="$1" proto="$2" port="$3" cidr="$4"
  local err

  err="$(openstack security group rule create \
      --ingress --protocol "$proto" --dst-port "${port}:${port}" --remote-ip "$cidr" \
      "$sg" 2>&1 >/dev/null || true)"

  if [[ -z "$err" ]]; then
    echo "[✔] Regla creada en SG '$sg': $proto/$port desde $cidr"
    return 0
  fi
  if echo "$err" | grep -qiE "already exists|ConflictException|409"; then
    echo "[✔] Regla ya existía en SG '$sg': $proto/$port desde $cidr"
    return 0
  fi
  die "No se pudo crear la regla SG ($proto/$port desde $cidr) en '$sg'. Error: $err"
}

extract_cloud_init_password() {
  local f="$1"
  [[ -f "$f" ]] || return 0

  local p
  p="$(grep -E '^[[:space:]]*password:[[:space:]]*' "$f" 2>/dev/null | head -n1 | sed -E 's/^[[:space:]]*password:[[:space:]]*//')" || true
  if [[ -n "${p:-}" ]]; then
    echo "$p"
    return 0
  fi

  p="$(grep -E '^[[:space:]]*-[[:space:]]*"?[A-Za-z0-9._-]+:[^"]+' "$f" 2>/dev/null \
      | head -n1 \
      | sed -E 's/^[[:space:]]*-[[:space:]]*"?//; s/"$//')" || true
  if [[ -n "${p:-}" ]]; then
    echo "${p#*:}"
    return 0
  fi

  p="$(awk '
    BEGIN{inlist=0}
    /chpasswd:/{inlist=1}
    inlist && /debian:/{print; exit}
  ' "$f" 2>/dev/null | sed -E 's/^[[:space:]]*debian:[[:space:]]*//')" || true
  [[ -n "${p:-}" ]] && echo "$p" || true
}

# ======================================
# PREPARACIÓN LOGS
# ======================================
mkdir -p "${LOG_DIR}"

LEVEL_NUM="$(next_level_number)"

# Encabezado del escenario (append al log)
{
  echo ""
  echo "#################### LEVEL ${LEVEL_NUM} ####################"
  echo "$(date '+%Y-%m-%d | %H:%M:%S')"
  echo ""
} >> "${LOG_FILE}"

# Redirección global: todo a pantalla y append al log
exec > >(tee -a "${LOG_FILE}") 2>&1

overall_start=$(date +%s)

echo "============================================================"
echo " INICIO ESCENARIO | LEVEL ${LEVEL_NUM}"
echo "============================================================"
echo "[i] Proyecto : ${BASE_DIR}"
echo "[i] Inst     : ${INST_DIR}"
echo "[i] Log      : ${LOG_FILE}"
echo "------------------------------------------------------------"

# ======================================
# EJECUCIÓN EN ORDEN
# ======================================
run_script "${INST_DIR}/op+snort.sh"
run_script "${INST_DIR}/op+wazuh.sh"
run_script "${INST_DIR}/op+caldera.sh"

# ======================================
# POST | INSTALAR NMAP EN CALDERA
# ======================================
log_block "POST | Instalación de Nmap en caldera-server"

VENV_DIR="${BASE_DIR}/deploy/openstack_venv"
OPENRC_FILE="${BASE_DIR}/admin-openrc.sh"
KEY_NAME="my_key"
SSH_USER="debian"
SSH_KEY_PATH="${BASE_DIR}/deploy/keys/${KEY_NAME}.pem"
USERDATA_FILE="${BASE_DIR}/deploy/cloud-init/set-password.yml"

SUBNET_PRIVATE="subnet_net_private_01"
NETWORK_EXTERNAL="net_external_01"
SEC_GROUP="sg_basic"

[[ -d "$VENV_DIR" ]] || die "No se encontró el entorno '$VENV_DIR'."
# shellcheck disable=SC1090
source "$VENV_DIR/bin/activate"

require_file "$OPENRC_FILE"
# shellcheck disable=SC1090
source "$OPENRC_FILE"

require_file "$SSH_KEY_PATH"

PRIVATE_CIDR="$(openstack subnet show "$SUBNET_PRIVATE" -f value -c cidr 2>/dev/null)" \
  || die "No se pudo obtener el CIDR de $SUBNET_PRIVATE"
echo "[✔] CIDR privado: $PRIVATE_CIDR"

ensure_floating_ip_if_missing "caldera-server" "$PRIVATE_CIDR" "$NETWORK_EXTERNAL"

read -r CALDERA_PRIV CALDERA_EXT < <(resolve_private_and_external_ip "caldera-server" "$PRIVATE_CIDR") \
  || die "No pude resolver IPs para caldera-server"

CALDERA_SSH_IP="${CALDERA_EXT:-$CALDERA_PRIV}"
echo "[✔] caldera-server: private=${CALDERA_PRIV} | external=${CALDERA_EXT:-N/A} | ssh=${CALDERA_SSH_IP}"

wait_ssh "$CALDERA_SSH_IP" "$SSH_USER" "$SSH_KEY_PATH" 300

ssh -o StrictHostKeyChecking=no -i "$SSH_KEY_PATH" "$SSH_USER@$CALDERA_SSH_IP" <<'EOF'
set -e
sudo apt-get update -y
sudo apt-get install -y nmap
echo "[✔] nmap instalado correctamente en caldera-server"
EOF

echo "------------------------------------------------------------"

# ======================================
# PRECHECK | CALDERA READY + SG 8888
# ======================================
log_block "PRECHECK | Caldera listo y accesible desde snort-server (TCP/8888)"

CALDERA_PORT="8888"
SNORT_INSTANCE="snort-server"
CALDERA_INSTANCE="caldera-server"

# Abrir 8888/TCP en SG para tráfico interno (idempotente)
ensure_sg_rule "$SEC_GROUP" tcp "$CALDERA_PORT" "$PRIVATE_CIDR"

# Resolver IP privada de Caldera y SSH IP de Snort
read -r CALDERA_PRIV CALDERA_EXT < <(resolve_private_and_external_ip "$CALDERA_INSTANCE" "$PRIVATE_CIDR") \
  || die "No pude resolver IPs para $CALDERA_INSTANCE"
read -r SNORT_PRIV SNORT_EXT < <(resolve_private_and_external_ip "$SNORT_INSTANCE" "$PRIVATE_CIDR") \
  || die "No pude resolver IPs para $SNORT_INSTANCE"

SNORT_SSH_IP="${SNORT_EXT:-$SNORT_PRIV}"
CALDERA_URL_PRIV="http://${CALDERA_PRIV}:${CALDERA_PORT}"

echo "[i] snort-server: private=${SNORT_PRIV} | external=${SNORT_EXT:-N/A} | ssh=${SNORT_SSH_IP}"
echo "[i] caldera-server URL (priv): ${CALDERA_URL_PRIV}"

wait_ssh "$SNORT_SSH_IP" "$SSH_USER" "$SSH_KEY_PATH" 300

echo "[+] Esperando a que Caldera responda desde snort-server..."
READY=0
for _ in $(seq 1 60); do   # 60 intentos x 5s = 5 min
  if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -i "$SSH_KEY_PATH" \
      "$SSH_USER@$SNORT_SSH_IP" \
      "curl -fsS --connect-timeout 3 --max-time 5 '$CALDERA_URL_PRIV' >/dev/null"; then
    READY=1
    break
  fi
  sleep 5
  echo -n "."
done
echo ""

if [[ "$READY" -ne 1 ]]; then
  echo "[!] Caldera aún no responde en ${CALDERA_URL_PRIV} desde snort-server."
  echo "[!] Diagnóstico rápido (caldera-server): puerto 8888 y log"

  # Re-evaluar ssh caldera por si cambió
  ensure_floating_ip_if_missing "caldera-server" "$PRIVATE_CIDR" "$NETWORK_EXTERNAL"
  read -r _CAL_PRIV _CAL_EXT < <(resolve_private_and_external_ip "caldera-server" "$PRIVATE_CIDR") || true
  _CAL_SSH="${_CAL_EXT:-$_CAL_PRIV}"

  wait_ssh "$_CAL_SSH" "$SSH_USER" "$SSH_KEY_PATH" 60 || true
  ssh -o StrictHostKeyChecking=no -i "$SSH_KEY_PATH" "$SSH_USER@$_CAL_SSH" \
    "ss -ltnp | grep ':8888' || true; tail -n 80 ~/caldera/caldera.log 2>/dev/null || true" || true

  die "Caldera no está accesible desde snort-server. No ejecuto op+snort-caldera.sh."
fi

echo "[✔] Caldera responde desde snort-server. Continuando con integración..."
echo "------------------------------------------------------------"

# ======================================
# INTEGRACIONES
# ======================================
run_script "${INST_DIR}/op+snort-caldera.sh"
run_script "${INST_DIR}/op+wazuh-snort.sh"

# ======================================
# RESUMEN FINAL (CONSOLIDADO)
# ======================================
log_block "RESUMEN FINAL | LEVEL ${LEVEL_NUM}"

# Asegurar floating IPs por si cambió algo
ensure_floating_ip_if_missing "snort-server" "$PRIVATE_CIDR" "$NETWORK_EXTERNAL"
ensure_floating_ip_if_missing "wazuh-manager" "$PRIVATE_CIDR" "$NETWORK_EXTERNAL"
ensure_floating_ip_if_missing "caldera-server" "$PRIVATE_CIDR" "$NETWORK_EXTERNAL"

read -r SNORT_PRIV SNORT_EXT < <(resolve_private_and_external_ip "snort-server" "$PRIVATE_CIDR") \
  || die "No pude resolver IPs para snort-server"
read -r WAZUH_PRIV WAZUH_EXT < <(resolve_private_and_external_ip "wazuh-manager" "$PRIVATE_CIDR") \
  || die "No pude resolver IPs para wazuh-manager"
read -r CALDERA_PRIV CALDERA_EXT < <(resolve_private_and_external_ip "caldera-server" "$PRIVATE_CIDR") \
  || die "No pude resolver IPs para caldera-server"

SNORT_SSH_IP="${SNORT_EXT:-$SNORT_PRIV}"
WAZUH_SSH_IP="${WAZUH_EXT:-$WAZUH_PRIV}"
CALDERA_SSH_IP="${CALDERA_EXT:-$CALDERA_PRIV}"

# Credenciales Wazuh (admin) desde fichero generado por el instalador
WAZUH_ADMIN_PASS="$(ssh -o StrictHostKeyChecking=no -i "$SSH_KEY_PATH" "$SSH_USER@$WAZUH_SSH_IP" \
  'cat /tmp/wazuh-admin-password 2>/dev/null || true' | tr -d '\r' || true)"
[[ -z "${WAZUH_ADMIN_PASS:-}" ]] && WAZUH_ADMIN_PASS="<NO_DETECTADA_EN_SCRIPT>"

# Caldera creds por defecto (según tu script)
CALDERA_URL="http://${CALDERA_SSH_IP}:8888"
CALDERA_USER="admin"
CALDERA_PASS="admin"

# Snort: no dashboard; acceso por SSH (usuario/clave)
SNORT_USER="debian"
SNORT_PASS="$(extract_cloud_init_password "$USERDATA_FILE" || true)"
[[ -z "${SNORT_PASS:-}" ]] && SNORT_PASS="<SSH_POR_CLAVE (password no detectada)>"

# Wazuh Dashboard
WAZUH_URL="https://${WAZUH_SSH_IP}"
WAZUH_USER="admin"

# Tiempo total
overall_end=$(date +%s)
overall_duration=$((overall_end - overall_start))

echo "==================== ACCESOS Y CREDENCIALES ===================="
echo
echo "-------------------- [WAZUH MANAGER] ---------------------------"
echo "Instancia      : wazuh-manager"
echo "Dashboard URL  : ${WAZUH_URL}"
echo "Usuario        : ${WAZUH_USER}"
echo "Password       : ${WAZUH_ADMIN_PASS}"
echo "SSH            : ssh -i ${SSH_KEY_PATH} ${SSH_USER}@${WAZUH_SSH_IP}"
echo
echo "-------------------- [SNORT SERVER] ----------------------------"
echo "Instancia      : snort-server"
echo "Dashboard URL  : (no aplica; Snort es CLI)"
echo "Usuario (SSH)  : ${SNORT_USER}"
echo "Password       : ${SNORT_PASS}"
echo "SSH            : ssh -i ${SSH_KEY_PATH} ${SSH_USER}@${SNORT_SSH_IP}"
echo "Snort (captura): sudo snort -i ens3 -c /etc/snort/snort.lua -A alert_fast -k none -l /var/log/snort"
echo "Alertas        : sudo tail -f /var/log/snort/alert_fast.txt"
echo
echo "-------------------- [MITRE CALDERA] ---------------------------"
echo "Instancia      : caldera-server"
echo "Dashboard URL  : ${CALDERA_URL}"
echo "Usuario        : ${CALDERA_USER}"
echo "Password       : ${CALDERA_PASS}"
echo "SSH            : ssh -i ${SSH_KEY_PATH} ${SSH_USER}@${CALDERA_SSH_IP}"
echo "Nota           : nmap instalado en caldera-server"
echo
echo "==============================================================="
echo "[⏱] Tiempo total de ejecución: $(format_time_long "$overall_duration")"
echo "[📜] Puedes revisar el log en: ${LOG_FILE}"
echo "==============================================================="

# Desactivar venv si estaba activo
deactivate 2>/dev/null || true

exit 0
