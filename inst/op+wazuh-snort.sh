#!/bin/bash
set -euo pipefail

SCRIPT_START=$(date +%s)
format_time() { local total=$1; echo "$((total/60)) minutos y $((total%60)) segundos"; }

log() { echo "$*" >&2; }
die() { log "[✖] $*"; exit 1; }
require_file() { [[ -f "$1" ]] || die "No se encontró el fichero: $1"; }

# --------------------------
# Config (override por env)
# --------------------------
VENV_DIR="${VENV_DIR:-deploy/openstack_venv}"
OPENRC_FILE="${OPENRC_FILE:-admin-openrc.sh}"

MANAGER_INSTANCE="${MANAGER_INSTANCE:-wazuh-manager}"
SNORT_INSTANCE="${SNORT_INSTANCE:-snort-server}"

KEY_NAME="${KEY_NAME:-my_key}"
SEC_GROUP="${SEC_GROUP:-sg_basic}"

SUBNET_PRIVATE="${SUBNET_PRIVATE:-subnet_net_private_01}"
NETWORK_EXTERNAL="${NETWORK_EXTERNAL:-net_external_01}"

SSH_USER="${SSH_USER:-debian}"
SSH_KEY_PATH="${SSH_KEY_PATH:-$PWD/deploy/keys/${KEY_NAME}.pem}"
KNOWN_HOSTS_FILE="${KNOWN_HOSTS_FILE:-$HOME/.ssh/known_hosts}"

SNORT_IFACE="${SNORT_IFACE:-ens3}"
SNORT_LOG_FILE="${SNORT_LOG_FILE:-/var/log/snort/alert_fast.txt}"
# OJO: con -A alert_fast normalmente corresponde a snort-fast
WAZUH_LOG_FORMAT="${WAZUH_LOG_FORMAT:-snort-fast}"

WAZUH_PORT_DATA="${WAZUH_PORT_DATA:-1514}"
WAZUH_PORT_ENROLL="${WAZUH_PORT_ENROLL:-1515}"

# --------------------------
# Helpers OpenStack / SSH
# --------------------------
wait_active() {
  local server="$1"
  local status
  status="$(openstack server show "$server" -f value -c status 2>/dev/null || true)"
  [[ -n "$status" ]] || die "No existe la instancia '$server' (o no se pudo consultar)."

  if [[ "$status" != "ACTIVE" ]]; then
    log "[!] '$server' está en estado $status. Arrancando..."
    openstack server start "$server" >/dev/null || die "No se pudo arrancar '$server'"
    log "[+] Esperando a que '$server' esté ACTIVE..."
    until [[ "$(openstack server show "$server" -f value -c status)" == "ACTIVE" ]]; do
      sleep 5; log -n "."
    done
    log ""
    log "[✔] '$server' ACTIVE"
  else
    log "[✔] '$server' ACTIVE"
  fi
}

wait_ssh() {
  local host="$1"
  local timeout="${2:-300}"
  local start now
  start=$(date +%s)
  log "[+] Esperando SSH en $host ..."
  until ssh -o StrictHostKeyChecking=no -i "$SSH_KEY_PATH" "$SSH_USER@$host" "echo ok" >/dev/null 2>&1; do
    sleep 5; log -n "."
    now=$(date +%s)
    if (( now - start > timeout )); then
      log ""
      die "Timeout SSH a $host"
    fi
  done
  log ""
  log "[✔] SSH disponible en $host"
}

extract_ips_from_addresses() {
  local server="$1"
  local addrs ips
  addrs="$(openstack server show "$server" -f value -c addresses 2>/dev/null || true)"
  [[ -n "$addrs" ]] || return 1
  ips="$(echo "$addrs" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | awk '!seen[$0]++')"
  [[ -n "$ips" ]] || return 1
  echo "$ips"
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

ensure_floating_if_missing() {
  local server="$1" private_cidr="$2"
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

  log "[!] '$server' no tiene IP externa (fuera de $private_cidr). Asignando Floating IP..."
  local free_fip
  free_fip="$(openstack floating ip list -f value -c "Floating IP Address" -c "Fixed IP Address" \
    | awk '$2=="None"{print $1; exit}')"
  if [[ -z "$free_fip" ]]; then
    free_fip="$(openstack floating ip create "$NETWORK_EXTERNAL" -f value -c floating_ip_address)" \
      || die "No se pudo crear Floating IP en $NETWORK_EXTERNAL"
  fi

  ssh-keygen -f "$KNOWN_HOSTS_FILE" -R "$free_fip" >/dev/null 2>&1 || true
  openstack server add floating ip "$server" "$free_fip" || die "No se pudo asociar Floating IP $free_fip a $server"
  log "[✔] Floating IP asignada a '$server': $free_fip"
}

resolve_private_and_ssh_ip() {
  local server="$1" private_cidr="$2"
  local ips ip priv="" ssh=""

  ips="$(extract_ips_from_addresses "$server")" || die "No pude extraer IPs de '$server'"

  while read -r ip; do
    [[ -z "$ip" ]] && continue
    if [[ "$(ip_in_cidr "$ip" "$private_cidr")" == "1" ]]; then
      priv="$ip"
    else
      ssh="$ip"
    fi
  done <<<"$ips"

  [[ -n "$priv" ]] || die "No encontré IP privada de '$server' dentro de $private_cidr"
  [[ -n "$ssh"  ]] || die "No encontré IP externa/SSH de '$server' (fuera de $private_cidr)"
  echo "$priv $ssh"
}

ensure_sg_rule() {
  local proto="$1" port="$2" cidr="$3"
  local err
  err="$(openstack security group rule create \
      --ingress --protocol "$proto" --dst-port "${port}:${port}" --remote-ip "$cidr" \
      "$SEC_GROUP" 2>&1 >/dev/null || true)"

  if [[ -z "$err" ]]; then log "[✔] Regla creada: $proto/$port desde $cidr"; return 0; fi
  if echo "$err" | grep -qiE "already exists|ConflictException|409"; then
    log "[✔] Regla ya existía: $proto/$port desde $cidr"; return 0
  fi
  die "No se pudo crear la regla SG ($proto/$port desde $cidr). Error: $err"
}

ssh_run() {
  local host="$1"; shift
  ssh -o StrictHostKeyChecking=no -i "$SSH_KEY_PATH" "$SSH_USER@$host" "$@"
}

# --------------------------
# Inicio
# --------------------------
echo "============================================="
echo " Integración Snort -> Wazuh (OpenStack)"
echo "============================================="

log "[+] Activando entorno virtual OpenStack..."
[[ -d "$VENV_DIR" ]] || die "No se encontró el entorno '$VENV_DIR'."
# shellcheck disable=SC1090
source "$VENV_DIR/bin/activate"

log "[+] Cargando variables OpenStack..."
require_file "$OPENRC_FILE"
# shellcheck disable=SC1090
source "$OPENRC_FILE"
require_file "$SSH_KEY_PATH"

log "[+] Verificando subred privada..."
PRIVATE_CIDR="$(openstack subnet show "$SUBNET_PRIVATE" -f value -c cidr 2>/dev/null)" \
  || die "No se pudo obtener el CIDR de $SUBNET_PRIVATE"
log "[✔] CIDR privado: $PRIVATE_CIDR"

log "[+] Asegurando reglas de red para Wazuh (SG: $SEC_GROUP)..."
ensure_sg_rule tcp "$WAZUH_PORT_DATA" "$PRIVATE_CIDR"
ensure_sg_rule udp "$WAZUH_PORT_DATA" "$PRIVATE_CIDR"
ensure_sg_rule tcp "$WAZUH_PORT_ENROLL" "$PRIVATE_CIDR"

log "[+] Asegurando instancias ACTIVE..."
wait_active "$MANAGER_INSTANCE"
wait_active "$SNORT_INSTANCE"

log "[+] Asegurando IP externa (Floating) si falta..."
ensure_floating_if_missing "$MANAGER_INSTANCE" "$PRIVATE_CIDR"
ensure_floating_if_missing "$SNORT_INSTANCE" "$PRIVATE_CIDR"

log "[+] Resolviendo IPs (privada y SSH) por CIDR..."
read -r MANAGER_PRIV MANAGER_SSH < <(resolve_private_and_ssh_ip "$MANAGER_INSTANCE" "$PRIVATE_CIDR")
read -r SNORT_PRIV   SNORT_SSH   < <(resolve_private_and_ssh_ip "$SNORT_INSTANCE" "$PRIVATE_CIDR")

log "    - $MANAGER_INSTANCE: private=$MANAGER_PRIV ssh=$MANAGER_SSH"
log "    - $SNORT_INSTANCE  : private=$SNORT_PRIV ssh=$SNORT_SSH"

wait_ssh "$MANAGER_SSH" 300
wait_ssh "$SNORT_SSH" 300

log "[+] Detectando versión del Wazuh Manager..."
MANAGER_WAZUH_VERSION="$(ssh_run "$MANAGER_SSH" "dpkg-query -W -f='\${Version}\n' wazuh-manager 2>/dev/null || true" | tr -d '\r')"
[[ -n "${MANAGER_WAZUH_VERSION:-}" ]] || die "No pude detectar la versión de wazuh-manager"
log "[✔] Wazuh Manager version: $MANAGER_WAZUH_VERSION"
TARGET_AGENT_VERSION="$MANAGER_WAZUH_VERSION"

# --------------------------
# Obtener/crear agente en manager y key line
# --------------------------
AGENT_NAME="$SNORT_INSTANCE"
log "[+] Preparando agente '$AGENT_NAME' en Wazuh Manager..."

get_agent_line() {
  ssh_run "$MANAGER_SSH" "sudo awk -v name='$AGENT_NAME' '\$2==name {print; exit}' /var/ossec/etc/client.keys 2>/dev/null || true"
}

AGENT_KEY_LINE="$(get_agent_line)"
if [[ -z "${AGENT_KEY_LINE:-}" ]]; then
  log "[!] No existe entrada para '$AGENT_NAME' en client.keys. Creando agente..."
  ssh_run "$MANAGER_SSH" "printf 'A\n%s\nany\ny\nQ\n' '$AGENT_NAME' | sudo /var/ossec/bin/manage_agents >/dev/null" \
    || die "No se pudo crear el agente."
  AGENT_KEY_LINE="$(get_agent_line)"
fi
[[ -n "${AGENT_KEY_LINE:-}" ]] || die "No se pudo obtener la línea del agente desde client.keys"

AGENT_ID="$(echo "$AGENT_KEY_LINE" | awk '{print $1}')"
log "[✔] Agente en manager: ID=$AGENT_ID, Name=$AGENT_NAME"
AGENT_KEY_B64="$(printf '%s' "$AGENT_KEY_LINE" | base64 | tr -d '\n')"

# --------------------------
# Configurar snort-server (clave + NO enrollment + localfile correcto)
# --------------------------
log "[+] Instalando/configurando Wazuh Agent en '$SNORT_INSTANCE' (version=$TARGET_AGENT_VERSION) e integrando logs de Snort..."

ssh_run "$SNORT_SSH" bash -s -- \
  "$MANAGER_PRIV" "$AGENT_KEY_B64" "$SNORT_LOG_FILE" "$WAZUH_LOG_FORMAT" "$TARGET_AGENT_VERSION" "$AGENT_NAME" <<'REMOTE'
set -euo pipefail
MANAGER_IP="$1"
KEY_B64="$2"
SNORT_LOG_FILE="$3"
WAZUH_LOG_FORMAT="$4"
TARGET_VER="$5"
AGENT_NAME="$6"
export DEBIAN_FRONTEND=noninteractive

echo "[remote] Preparando Snort log..."
sudo mkdir -p "$(dirname "$SNORT_LOG_FILE")"
sudo touch "$SNORT_LOG_FILE"
sudo chmod 755 "$(dirname "$SNORT_LOG_FILE")"
sudo chmod 644 "$SNORT_LOG_FILE" || true

echo "[remote] Preparando APT + repo Wazuh..."
sudo rm -f /etc/apt/sources.list.d/wazuh.list || true
sudo rm -f /usr/share/keyrings/wazuh.gpg || true
sudo apt-get update -o Acquire::Retries=3
sudo apt-get install -y curl gnupg ca-certificates apt-transport-https

curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
sudo chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  | sudo tee /etc/apt/sources.list.d/wazuh.list >/dev/null
sudo apt-get update -o Acquire::Retries=3

echo "[remote] Forzando wazuh-agent=$TARGET_VER (no interactivo)..."
sudo apt-mark unhold wazuh-agent 2>/dev/null || true
sudo apt-get install -y --allow-downgrades \
  -o Dpkg::Options::="--force-confnew" \
  -o Dpkg::Options::="--force-confdef" \
  "wazuh-agent=$TARGET_VER"
sudo apt-mark hold wazuh-agent >/dev/null

echo "[remote] Parando wazuh-agent..."
sudo systemctl stop wazuh-agent >/dev/null 2>&1 || true

echo "[remote] ESCRIBIENDO /var/ossec/etc/client.keys con la key del manager..."
KEY_LINE="$(echo "$KEY_B64" | base64 -d)"
printf '%s\n' "$KEY_LINE" | sudo tee /var/ossec/etc/client.keys >/dev/null

if getent group wazuh >/dev/null; then
  sudo chown root:wazuh /var/ossec/etc/client.keys
else
  sudo chown root:root /var/ossec/etc/client.keys
fi
sudo chmod 640 /var/ossec/etc/client.keys

echo "[remote] Reescribiendo bloque <client> (1514/tcp) y desactivando enrollment (GLOBAL)..."
sudo cp -p /var/ossec/etc/ossec.conf "/var/ossec/etc/ossec.conf.bak.$(date +%F_%H%M%S)"

# 1) Eliminar TODOS los bloques enrollment existentes (si hubiera más de uno)
sudo perl -0777 -i -pe 's/<enrollment>.*?<\/enrollment>\s*//sg' /var/ossec/etc/ossec.conf

# 2) Reemplazar el primer <client> completo por uno controlado
sudo perl -0777 -i -pe "s#<client>.*?</client>#<client>\n  <server>\n    <address>${MANAGER_IP}</address>\n    <port>1514</port>\n    <protocol>tcp</protocol>\n  </server>\n  <enrollment>\n    <enabled>no</enabled>\n  </enrollment>\n</client>#s" /var/ossec/etc/ossec.conf

echo "[remote] Eliminando localfile duplicados hacia $SNORT_LOG_FILE..."
sudo perl -0777 -i -pe "s#\\s*<localfile>\\s*.*?<location>\\Q${SNORT_LOG_FILE}\\E</location>\\s*</localfile>\\s*##sg" /var/ossec/etc/ossec.conf

LOCALFILE_BLOCK="  <localfile>\n    <log_format>${WAZUH_LOG_FORMAT}</log_format>\n    <location>${SNORT_LOG_FILE}</location>\n  </localfile>\n"

echo "[remote] Insertando localfile en <!-- Log analysis -->..."
if sudo grep -q "<!--[[:space:]]*Log analysis[[:space:]]*-->" /var/ossec/etc/ossec.conf; then
  sudo perl -0777 -i -pe "s#(<!--[[:space:]]*Log analysis[[:space:]]*-->\\s*)#\$1${LOCALFILE_BLOCK}#s" /var/ossec/etc/ossec.conf
else
  sudo perl -0777 -i -pe "s#</ossec_config>#${LOCALFILE_BLOCK}</ossec_config>#s" /var/ossec/etc/ossec.conf
fi

echo "[remote] Reiniciando wazuh-agent..."
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent >/dev/null
sudo systemctl restart wazuh-agent

echo "[remote] Últimas líneas ossec.log (debería NO aparecer 'Requesting a key from server'):"
sudo tail -n 60 /var/ossec/logs/ossec.log || true

if sudo tail -n 200 /var/ossec/logs/ossec.log | grep -q "Requesting a key from server"; then
  echo "[remote][ERROR] El agente sigue intentando enrollment (1515). Dump client.keys y bloque client:"
  echo "--- client.keys ---"
  sudo cat /var/ossec/etc/client.keys || true
  echo "--- ossec.conf client/enrollment ---"
  sudo awk 'BEGIN{p=0} /<client>/{p=1} p{print} /<\/client>/{p=0}' /var/ossec/etc/ossec.conf || true
  exit 31
fi
REMOTE

# --------------------------
# Esperar conexión (manager)
# --------------------------
log "[+] Esperando a que el agente esté ACTIVE (agent_control -lc)..."
CONNECTED=0
for _ in $(seq 1 40); do
  if ssh_run "$MANAGER_SSH" "sudo /var/ossec/bin/agent_control -lc | grep -q \"Name: ${AGENT_NAME}\""; then
    CONNECTED=1
    break
  fi
  sleep 3
done

if [[ "$CONNECTED" -ne 1 ]]; then
  log "[!] Sigue sin conectar. Dump diagnóstico:"
  ssh_run "$MANAGER_SSH" "sudo /var/ossec/bin/agent_control -l || true; echo '--- ossec.log (authd/remoted) ---'; sudo tail -n 160 /var/ossec/logs/ossec.log | egrep -i 'authd|remoted|reject|error|key|${AGENT_NAME}' || true" || true
  die "El agente no ha conectado todavía."
fi

log "[✔] Agente conectado detectado en el manager."

# --------------------------
# AÑADIR REGLAS EN WAZUH MANAGER (ICMP + SCAN)
# --------------------------
log "[+] Instalando reglas locales en Wazuh Manager (ICMP + Nmap SYN scan)..."
ssh_run "$MANAGER_SSH" bash -s <<'MANAGER_RULES'
set -euo pipefail
RULE_FILE="/var/ossec/etc/rules/snort_local_rules.xml"

sudo tee "$RULE_FILE" >/dev/null <<'EOF'
#<group name="local,snort,network,scan,">
  <rule id="600001" level="7">
    <match>Intento ICMPv4 detectado</match>
    <description>Snort ICMP detection</description>
  </rule>

  #<rule id="600010" level="8">
    #<match>Nmap TCP SYN scan</match>
    #<description>Snort scan activity detected</description>
  #</rule>
#</group>
EOF

sudo chown root:wazuh "$RULE_FILE" 2>/dev/null || sudo chown root:root "$RULE_FILE"
sudo chmod 640 "$RULE_FILE" || true

# Reinicio para cargar reglas
sudo systemctl restart wazuh-manager

# Comprobación rápida: que no haya errores de carga recientes en ossec.log
sudo tail -n 80 /var/ossec/logs/ossec.log | egrep -i 'rule|decoder|error|failed|xml|syntax' || true
MANAGER_RULES
log "[✔] Reglas de Snort instaladas en el manager."

echo "[✔] Integración completada: Snort ($SNORT_INSTANCE) -> Wazuh ($MANAGER_INSTANCE)"

SCRIPT_END=$(date +%s)
echo "===================================================="
echo "[⏱] Tiempo TOTAL del script: $(format_time $((SCRIPT_END-SCRIPT_START)))"
echo "===================================================="
echo

echo "Comprobación:"
echo
echo "Terminal 1 (snort)  # Snort capturando tráfico:"
echo "sudo snort -i $SNORT_IFACE -c /etc/snort/snort.lua -A alert_fast -k none -l /var/log/snort"
echo
echo "Terminal 2 (snort)  # Visualización de logs:"
echo "sudo tail -f $SNORT_LOG_FILE"
echo
echo "Wazuh: ☰ → Threat Intelligence → Threat Hunting → agente → Events"
