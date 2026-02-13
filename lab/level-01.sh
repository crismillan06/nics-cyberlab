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
#   - Instala nmap en caldera-server
#   - Asegura readiness de Caldera (puerto 8888 accesible desde snort)
#   - Muestra al final credenciales/URLs y tiempo total
# ==========================================================

set -euo pipefail

# ======================================
# DIRECTORIOS BASE
# ======================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

INST_DIR="${BASE_DIR}/inst"
LOG_DIR="${BASE_DIR}/log"
LOG_FILE="${LOG_DIR}/level.log"

# ======================================
# FUNCIONES
# ======================================
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

  (
    cd "$BASE_DIR"
    stdbuf -oL -eL bash "$script" 2>&1 | while IFS= read -r line; do
      echo "[$(date '+%H:%M:%S')][${script##*/}] $line"
    done
  )
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

  echo "[+] Esperando SSH en $host (user=$ssh_user) ..."
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

# ==========================================================
# PASSWORD/USUARIO según imagen + password-os.yml
# ==========================================================
server_image_name() {
  local server="$1"
  openstack server show "$server" -f value -c image 2>/dev/null | awk '{print $1}'
}

os_id_from_image() {
  local img="$1"
  case "$img" in
    ubuntu-*) echo "ubuntu" ;;
    debian-*) echo "debian" ;;
    kali-*)   echo "kali" ;;
    *)        echo "unknown" ;;
  esac
}

ssh_user_from_os() {
  local os="$1"
  case "$os" in
    ubuntu) echo "ubuntu" ;;
    debian) echo "debian" ;;
    kali)   echo "kali" ;;
    *)      echo "debian" ;; # fallback típico
  esac
}

extract_password_from_password_os_yml() {
  local f="$1" os="$2"
  [[ -f "$f" ]] || return 0

  # Caso 1: YAML clásico con password:
  local p=""
  p="$(grep -E '^[[:space:]]*password:[[:space:]]*' "$f" 2>/dev/null | head -n1 | sed -E 's/^[[:space:]]*password:[[:space:]]*//')" || true
  [[ -n "${p:-}" ]] && echo "$p" && return 0

  # Caso 2: YAML centralizado con "case ... PASS="xxx""
  awk -v os="$os" '
    $0 ~ "^[[:space:]]*"os"\\)" {
      if (match($0, /PASS="([^"]+)"/, a)) { print a[1]; exit }
    }
  ' "$f" 2>/dev/null || true
}

password_for_server_from_userdata() {
  local server="$1" userdata="$2"
  local img os p
  img="$(server_image_name "$server")"
  os="$(os_id_from_image "$img")"
  p="$(extract_password_from_password_os_yml "$userdata" "$os")"

  if [[ -z "${p:-}" ]]; then
    case "$os" in
      ubuntu) p="ubuntu123" ;;
      debian) p="debian123" ;;
      kali)   p="kali123" ;;
      *)      p="<DESCONOCIDA>" ;;
    esac
  fi
  echo "$p"
}

ssh_user_for_server() {
  local server="$1"
  local img os
  img="$(server_image_name "$server")"
  os="$(os_id_from_image "$img")"
  ssh_user_from_os "$os"
}

# ======================================
# PREPARACIÓN LOGS
# ======================================
mkdir -p "${LOG_DIR}"
LEVEL_NUM="01"

{
  echo ""
  echo "#################### LEVEL ${LEVEL_NUM} ####################"
  echo "$(date '+%Y-%m-%d | %H:%M:%S')"
  echo ""
} >> "${LOG_FILE}"

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
# VARIABLES DE OPENSTACK / SSH / RED
# ======================================
VENV_DIR="${BASE_DIR}/deploy/openstack_venv"
OPENRC_FILE="${BASE_DIR}/admin-openrc.sh"
KEY_NAME="my_key"
SSH_KEY_PATH="${BASE_DIR}/deploy/keys/${KEY_NAME}.pem"

USERDATA_FILE="${BASE_DIR}/deploy/cloud-init/passwd-os.yml"

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
require_file "$USERDATA_FILE"

PRIVATE_CIDR="$(openstack subnet show "$SUBNET_PRIVATE" -f value -c cidr 2>/dev/null)" \
  || die "No se pudo obtener el CIDR de $SUBNET_PRIVATE"
echo "[✔] CIDR privado: $PRIVATE_CIDR"

# ======================================
# EJECUCIÓN EN PARALELO
# ======================================
echo "[i] Lanzando instancias en paralelo con intervalos escalonados..."

(run_script "${INST_DIR}/op+snort.sh") &
PID_SNORT=$!

(
  sleep 180
  run_script "${INST_DIR}/op+wazuh.sh"
) &
PID_WAZUH=$!

(
  sleep 300
  run_script "${INST_DIR}/op+caldera.sh"
) &
PID_CALDERA=$!

wait $PID_SNORT
wait $PID_WAZUH
wait $PID_CALDERA

echo "[✔] Todas las instancias levantadas y SSH disponible."

# ======================================
# POST | Instalación de Nmap + Hydra + SecLists en Caldera
# ======================================
ensure_floating_ip_if_missing "caldera-server" "$PRIVATE_CIDR" "$NETWORK_EXTERNAL"

read -r CALDERA_PRIV CALDERA_EXT < <(resolve_private_and_external_ip "caldera-server" "$PRIVATE_CIDR") \
  || die "No pude resolver IPs para caldera-server"

CALDERA_SSH_IP="${CALDERA_EXT:-$CALDERA_PRIV}"
CALDERA_SSH_USER="$(ssh_user_for_server "caldera-server")"

echo "[✔] caldera-server: private=${CALDERA_PRIV} | external=${CALDERA_EXT:-N/A} | ssh=${CALDERA_SSH_USER}@${CALDERA_SSH_IP}"
wait_ssh "$CALDERA_SSH_IP" "$CALDERA_SSH_USER" "$SSH_KEY_PATH" 300

ssh -o StrictHostKeyChecking=no -i "$SSH_KEY_PATH" "$CALDERA_SSH_USER@$CALDERA_SSH_IP" <<'EOF'
set -euo pipefail

WORDLIST_OFFICIAL="/snap/seclists/current/Passwords/Common-Credentials/Pwdb_top-10000000.txt"
OUTDIR="${HOME}/wordlists"

log()  { echo -e "[+] $*"; }
ok()   { echo -e "[✔] $*"; }
warn() { echo -e "[!] $*"; }
err()  { echo -e "[✖] $*" >&2; }

need_cmd() { command -v "$1" >/dev/null 2>&1; }

log "Actualizando índices APT..."
sudo apt-get update -y

# --- Ubuntu: asegurar 'universe' (Hydra suele estar ahí) ---
if [[ -r /etc/os-release ]]; then
  . /etc/os-release
  if [[ "${ID:-}" == "ubuntu" ]]; then
    if ! grep -RhsE '^[[:space:]]*deb .* universe' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null | grep -q universe; then
      warn "Repositorio 'universe' no detectado. Intentando habilitarlo..."
      sudo apt-get install -y software-properties-common
      sudo add-apt-repository -y universe
      sudo apt-get update -y
      ok "Repositorio 'universe' habilitado."
    else
      ok "Repositorio 'universe' ya estaba habilitado."
    fi
  fi
fi

# --- Instalar herramientas (tipo nmap) ---
log "Instalando herramientas base (nmap, hydra, snapd)..."
sudo apt-get install -y nmap hydra snapd

ok "nmap:  $(command -v nmap)"
ok "hydra: $(command -v hydra)"

# --- Asegurar snapd activo ---
if need_cmd systemctl; then
  sudo systemctl enable --now snapd >/dev/null 2>&1 || true
  sudo systemctl enable --now snapd.socket >/dev/null 2>&1 || true
fi

if ! need_cmd snap; then
  err "snap no está disponible tras instalar snapd. Revisa snapd/systemd en la imagen."
  exit 1
fi
ok "snap:  $(command -v snap)"

# --- Instalar SecLists vía snap ---
if snap list 2>/dev/null | awk '{print $1}' | grep -qx seclists; then
  ok "SecLists (snap) ya está instalado."
else
  log "Instalando SecLists vía snap..."
  sudo snap install seclists
  ok "SecLists instalado."
fi

# --- Validar wordlist oficial ---
log "Verificando wordlist oficial..."
if [[ -f "${WORDLIST_OFFICIAL}" ]]; then
  ok "Wordlist oficial encontrada: ${WORDLIST_OFFICIAL}"
else
  warn "No se encontró en la ruta esperada: ${WORDLIST_OFFICIAL}"
  log "Buscando alternativa dentro del snap..."
  ALT="$(sudo find /snap/seclists -type f -name 'Pwdb_top-10000000.txt' 2>/dev/null | head -n 1 || true)"
  if [[ -n "${ALT}" && -f "${ALT}" ]]; then
    ok "Encontrada alternativa: ${ALT}"
    WORDLIST_OFFICIAL="${ALT}"
  else
    err "No se pudo localizar 'Pwdb_top-10000000.txt' dentro de /snap/seclists."
    err "Revisa que el snap seclists esté correctamente instalado."
    exit 1
  fi
fi

# --- Preparar directorio y subsets TOP ---
log "Preparando directorio de wordlists: ${OUTDIR}"
mkdir -p "${OUTDIR}"

TARGET_LINK="${OUTDIR}/Pwdb_top-10000000.txt"
if [[ -L "${TARGET_LINK}" || -f "${TARGET_LINK}" ]]; then
  ok "Wordlist local ya existe: ${TARGET_LINK}"
else
  ln -s "${WORDLIST_OFFICIAL}" "${TARGET_LINK}" 2>/dev/null || cp "${WORDLIST_OFFICIAL}" "${TARGET_LINK}"
  ok "Wordlist preparada en: ${TARGET_LINK}"
fi

log "Generando subsets TOP (1k / 10k / 100k)..."
head -n 1000   "${TARGET_LINK}" > "${OUTDIR}/pwdb_top_1k.txt"
head -n 10000  "${TARGET_LINK}" > "${OUTDIR}/pwdb_top_10k.txt"
head -n 100000 "${TARGET_LINK}" > "${OUTDIR}/pwdb_top_100k.txt"
ok "Subsets creados en ${OUTDIR}"

# --- Resumen remoto ---
echo
echo "================== RESUMEN CALDERA =================="
ok "nmap:               $(command -v nmap)"
ok "hydra:              $(command -v hydra)"
ok "seclists (snap):     $(snap list 2>/dev/null | awk '$1=="seclists"{print $1" "$2" "$3}' || echo 'instalado')"
ok "wordlist oficial:    ${WORDLIST_OFFICIAL}"
ok "wordlist alumno:     ${TARGET_LINK}"
echo "Subsets:"
ls -lh "${OUTDIR}/pwdb_top_1k.txt" "${OUTDIR}/pwdb_top_10k.txt" "${OUTDIR}/pwdb_top_100k.txt" 2>/dev/null || true
echo "======================================================"
EOF

echo "[✔] nmap + hydra + seclists instalados y wordlists preparadas en caldera-server"

# ======================================
# PRECHECK | Caldera listo + SG 8888
# ======================================
CALDERA_PORT="8888"
SNORT_INSTANCE="snort-server"
CALDERA_INSTANCE="caldera-server"

ensure_sg_rule "$SEC_GROUP" tcp "$CALDERA_PORT" "$PRIVATE_CIDR"

read -r CALDERA_PRIV CALDERA_EXT < <(resolve_private_and_external_ip "$CALDERA_INSTANCE" "$PRIVATE_CIDR") \
  || die "No pude resolver IPs para $CALDERA_INSTANCE"
read -r SNORT_PRIV SNORT_EXT < <(resolve_private_and_external_ip "$SNORT_INSTANCE" "$PRIVATE_CIDR") \
  || die "No pude resolver IPs para $SNORT_INSTANCE"

SNORT_SSH_IP="${SNORT_EXT:-$SNORT_PRIV}"
SNORT_SSH_USER="$(ssh_user_for_server "snort-server")"
CALDERA_URL_PRIV="http://${CALDERA_PRIV}:${CALDERA_PORT}"

wait_ssh "$SNORT_SSH_IP" "$SNORT_SSH_USER" "$SSH_KEY_PATH" 300

READY=0
for _ in $(seq 1 60); do
  if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -i "$SSH_KEY_PATH" \
      "$SNORT_SSH_USER@$SNORT_SSH_IP" \
      "curl -fsS --connect-timeout 3 --max-time 5 '$CALDERA_URL_PRIV' >/dev/null"; then
    READY=1
    break
  fi
  sleep 5
done

[[ "$READY" -eq 1 ]] || die "Caldera no está accesible desde snort-server."

# ======================================
# INTEGRACIONES
# ======================================
run_script "${INST_DIR}/op+snort-caldera.sh"
run_script "${INST_DIR}/op+wazuh-snort.sh"

# ======================================
# RESUMEN FINAL
# ======================================
log_block "RESUMEN FINAL | LEVEL ${LEVEL_NUM}"

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

SNORT_SSH_USER="$(ssh_user_for_server "snort-server")"
WAZUH_SSH_USER="$(ssh_user_for_server "wazuh-manager")"
CALDERA_SSH_USER="$(ssh_user_for_server "caldera-server")"

WAZUH_SSH_PASS="$(password_for_server_from_userdata "wazuh-manager" "$USERDATA_FILE")"
CALDERA_SSH_PASS="$(password_for_server_from_userdata "caldera-server" "$USERDATA_FILE")"

# Wazuh dashboard
WAZUH_ADMIN_PASS="$(ssh -o StrictHostKeyChecking=no -i "$SSH_KEY_PATH" "$WAZUH_SSH_USER@$WAZUH_SSH_IP" \
  'cat /tmp/wazuh-admin-password 2>/dev/null || true' | tr -d '\r' || true)"
[[ -z "${WAZUH_ADMIN_PASS:-}" ]] && WAZUH_ADMIN_PASS="<NO_DETECTADA_EN_SCRIPT>"

WAZUH_URL="https://${WAZUH_SSH_IP}"
WAZUH_USER="admin"

# Caldera dashboard (por defecto)
CALDERA_URL="http://${CALDERA_SSH_IP}:8888"
CALDERA_USER="admin"
CALDERA_PASS="admin"

overall_end=$(date +%s)
overall_duration=$((overall_end - overall_start))

echo "==================== ACCESOS Y CREDENCIALES ===================="
echo
echo "-------------------- [WAZUH MANAGER] ---------------------------"
echo "Instancia           : wazuh-manager"
echo "Dashboard URL       : ${WAZUH_URL}"
echo "Usuario (dashboard) : ${WAZUH_USER}"
echo "Password (dashboard): ${WAZUH_ADMIN_PASS}"
echo "SSH                 : ssh -i ${SSH_KEY_PATH} ${WAZUH_SSH_USER}@${WAZUH_SSH_IP}"
echo "Usuario (SSH)       : ${WAZUH_SSH_USER}"
echo "Password (SSH)      : ${WAZUH_SSH_PASS}"
echo
echo "-------------------- [SNORT SERVER] ----------------------------"
echo "Instancia           : snort-server"
echo "Dashboard URL       : (no aplica; Snort es CLI)"
echo "SSH                 : ssh -i ${SSH_KEY_PATH} ${SNORT_SSH_USER}@${SNORT_SSH_IP}"
echo "Usuario (SSH)       : ${SNORT_SSH_USER}"
echo "Password (SSH)      : ¿?"
echo "Snort (captura)     : sudo snort -i ens3 -c /etc/snort/snort.lua -A alert_fast -k none -l /var/log/snort"
echo "Alertas             : sudo tail -f /var/log/snort/alert_fast.txt"
echo
echo "-------------------- [MITRE CALDERA] ---------------------------"
echo "Instancia           : caldera-server"
echo "Dashboard URL       : ${CALDERA_URL}"
echo "Usuario (dashboard) : ${CALDERA_USER}"
echo "Password (dashboard): ${CALDERA_PASS}"
echo "SSH                 : ssh -i ${SSH_KEY_PATH} ${CALDERA_SSH_USER}@${CALDERA_SSH_IP}"
echo "Usuario (SSH)       : ${CALDERA_SSH_USER}"
echo "Password (SSH)      : ${CALDERA_SSH_PASS}"
echo "Nota                : nmap + hydra + seclists instalados en caldera-server (wordlists en ~/wordlists)"
echo
echo "==============================================================="
echo "[⏱] Tiempo total de ejecución: $(format_time_long "$overall_duration")"
echo "[📜] Puedes revisar el log en: ${LOG_FILE}"
echo "==============================================================="

deactivate 2>/dev/null || true
exit 0
