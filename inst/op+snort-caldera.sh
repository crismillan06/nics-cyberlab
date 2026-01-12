#!/bin/bash
# =========================================================
#  Descripción: Integra Caldera (agente Sandcat)
#  en la instancia snort-server (Debian 12)
# =========================================================

# ===== Timer global =====
SCRIPT_START=$(date +%s)
format_time() { local total=$1; echo "$((total/60)) minutos y $((total%60)) segundos"; }

echo "===================================================="
echo " Integración Caldera ➜ snort-server (agente)"
echo "===================================================="

# =========================
# ENTORNO / RUTAS PROYECTO
# =========================
# Igual que op+snort.sh y op+wazuh.sh: se asume que ejecutas este script desde
# /home/nics/nics-cyberlab
PROJECT_DIR="$PWD"

VENV_DIR="deploy/openstack_venv"
OPENRC_FILE="admin-openrc.sh"

echo "[i] Directorio del proyecto: $PROJECT_DIR"

# ===== Activar entorno virtual =====
echo "🔹 Activando entorno virtual de OpenStack..."
if [[ -d "$VENV_DIR" ]]; then
    # shellcheck disable=SC1091
    source "$VENV_DIR/bin/activate"
    echo "[✔] Entorno virtual activado correctamente: $VENV_DIR"
else
    echo "[✖] No se encontró el entorno '$VENV_DIR'. Ejecuta primero deploy/openstack-resources.sh"
    exit 1
fi
echo "-------------------------------------------"
sleep 1

# ===== Cargar variables de entorno OpenStack =====
if [[ -f "$OPENRC_FILE" ]]; then
    echo "[+] Cargando variables del entorno OpenStack ($OPENRC_FILE)..."
    # shellcheck disable=SC1091
    source "$OPENRC_FILE"
    echo "[✔] Credenciales OpenStack cargadas para $OS_USERNAME"
    echo "-------------------------------------------"
    sleep 1
else
    echo "[✖] No se encontró '$OPENRC_FILE'. Ejecuta primero deploy/openstack-resources.sh"
    exit 1
fi

# =========================
# CONFIGURACIÓN GENERAL
# =========================
SNORT_INSTANCE_NAME="snort-server"
CALDERA_INSTANCE_NAME="caldera-server"

SSH_USER="debian"
KEY_NAME="my_key"
SSH_KEY_PATH="$PROJECT_DIR/deploy/keys/${KEY_NAME}.pem"
KNOWN_HOSTS_FILE="$HOME/.ssh/known_hosts"

AGENT_DIR="/opt/caldera"
AGENT_PATH="$AGENT_DIR/caldera-agent"
SERVICE_PATH="/etc/systemd/system/caldera-agent.service"
CALDERA_PORT="8888"
CALDERA_GROUP="red"   # grupo del agente en Caldera

echo "[✔] Keypair privado: $SSH_KEY_PATH"

# =========================
# COMPROBACIONES BÁSICAS
# =========================
echo "🔹 Verificando requisitos básicos..."

if ! command -v openstack >/dev/null 2>&1; then
    echo "[✖] No se encuentra el comando 'openstack'. Revisa tu entorno."
    exit 1
fi

if [[ ! -f "$SSH_KEY_PATH" ]]; then
    echo "[✖] No se encuentra la clave privada SSH: $SSH_KEY_PATH"
    exit 1
fi

SNORT_EXISTS=$(openstack server list -f value -c Name | grep -w "$SNORT_INSTANCE_NAME" || true)
if [[ -z "$SNORT_EXISTS" ]]; then
    echo "[✖] No se ha encontrado la instancia de Snort: '$SNORT_INSTANCE_NAME'"
    echo "    Asegúrate de haber ejecutado inst/op+snort.sh antes."
    exit 1
fi

CALDERA_EXISTS=$(openstack server list -f value -c Name | grep -w "$CALDERA_INSTANCE_NAME" || true)
if [[ -z "$CALDERA_EXISTS" ]]; then
    echo "[✖] No se ha encontrado la instancia de Caldera: '$CALDERA_INSTANCE_NAME'"
    echo "    Asegúrate de haber ejecutado inst/op+caldera.sh antes."
    exit 1
fi

echo "[✔] Instancias de Snort y Caldera detectadas."
echo "-------------------------------------------"

# ===============================
# FUNCIONES PARA SACAR IPs
# ===============================
get_private_ip_from_addresses() {
    local server_name="$1"
    local addrs
    addrs=$(openstack server show "$server_name" -f value -c addresses)
    # Primera IP = IP fija privada (net_private_01)
    echo "$addrs" | grep -oE '([0-9]+\.){3}[0-9]+' | head -n1
}

get_floating_ip_for_fixed_ip() {
    local fixed_ip="$1"
    # Buscamos en las Floating IPs aquella cuyo "Fixed IP Address" coincide con la IP privada
    openstack floating ip list -f value -c "Floating IP Address" -c "Fixed IP Address" \
        | awk -v ip="$fixed_ip" '$2==ip {print $1; exit}'
}

# --- SNORT ---
SNORT_PRIVATE_IP=$(get_private_ip_from_addresses "$SNORT_INSTANCE_NAME")
SNORT_FLOATING_IP=$(get_floating_ip_for_fixed_ip "$SNORT_PRIVATE_IP")

# --- CALDERA ---
CALDERA_PRIVATE_IP=$(get_private_ip_from_addresses "$CALDERA_INSTANCE_NAME")
CALDERA_FLOATING_IP=$(get_floating_ip_for_fixed_ip "$CALDERA_PRIVATE_IP")

if [[ -z "$SNORT_PRIVATE_IP" ]]; then
    echo "[✖] No se ha podido determinar la IP privada de '$SNORT_INSTANCE_NAME'."
    openstack server show "$SNORT_INSTANCE_NAME" -f value -c addresses
    exit 1
fi

if [[ -z "$CALDERA_PRIVATE_IP" ]]; then
    echo "[✖] No se ha podido determinar la IP privada de '$CALDERA_INSTANCE_NAME'."
    openstack server show "$CALDERA_INSTANCE_NAME" -f value -c addresses
    exit 1
fi

# Usaremos SIEMPRE la IP PRIVADA de Caldera para que el agente se conecte desde la red interna
CALDERA_URL="http://$CALDERA_PRIVATE_IP:$CALDERA_PORT"

echo "[✔] SNORT   - IP privada: $SNORT_PRIVATE_IP    | IP flotante: ${SNORT_FLOATING_IP:-N/A}"
echo "[✔] CALDERA - IP privada: $CALDERA_PRIVATE_IP  | IP flotante: ${CALDERA_FLOATING_IP:-N/A}"
echo "[✔] URL Caldera usada por el agente: $CALDERA_URL"
echo "-------------------------------------------"

# =========================
# ESPERA SSH A SNORT
# =========================
# Para SSH usamos la flotante si existe; si no, la privada (igual que harías tú a mano)
TARGET_SSH_IP="${SNORT_FLOATING_IP:-$SNORT_PRIVATE_IP}"

echo "[+] Comprobando conexión SSH con snort-server ($TARGET_SSH_IP)..."
SSH_TIMEOUT=300   # damos margen generoso
SSH_START=$(date +%s)

ssh-keygen -f "$KNOWN_HOSTS_FILE" -R "$TARGET_SSH_IP" >/dev/null 2>&1 || true

until ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -i "$SSH_KEY_PATH" \
          "$SSH_USER@$TARGET_SSH_IP" "echo ok" >/dev/null 2>&1; do
    sleep 5; echo -n "."
    NOW=$(date +%s)
    if (( NOW - SSH_START > SSH_TIMEOUT )); then
        echo
        echo "[✖] Timeout al intentar conectar por SSH con Snort ($TARGET_SSH_IP)"
        echo "    Prueba manualmente con:"
        echo "    ssh -i $SSH_KEY_PATH $SSH_USER@$TARGET_SSH_IP"
        exit 1
    fi
done

echo
echo "[✔] SSH disponible en snort-server ($TARGET_SSH_IP)"
echo "-------------------------------------------"

# ===========================================
# INSTALAR / CONFIGURAR AGENTE CALDERA EN SNORT
# ===========================================
echo "🔹 Instalando / actualizando agente Caldera en snort-server..."

ssh -o StrictHostKeyChecking=no -i "$SSH_KEY_PATH" "$SSH_USER@$TARGET_SSH_IP" <<EOF
set -e

CALDERA_URL="$CALDERA_URL"
AGENT_DIR="$AGENT_DIR"
AGENT_PATH="$AGENT_PATH"
SERVICE_PATH="$SERVICE_PATH"
CALDERA_GROUP="$CALDERA_GROUP"

echo "[+] Actualizando paquetes base..."
sudo apt-get update -y

echo "[+] Instalando curl (si no está ya)..."
sudo apt-get install -y curl

echo "[+] Probando conectividad HTTP con Caldera en \$CALDERA_URL..."
if curl -s --connect-timeout 5 "\$CALDERA_URL" >/dev/null 2>&1; then
  echo "[✔] Caldera responde en \$CALDERA_URL"
else
  echo "[!] No se ha podido contactar con \$CALDERA_URL ahora mismo."
  echo "    El agente igualmente intentará reconectar periódicamente."
fi

echo "[+] Creando directorio para el agente: \$AGENT_DIR"
sudo mkdir -p "\$AGENT_DIR"

echo "[+] Descargando/actualizando agente Sandcat desde Caldera..."
sudo curl -s -X POST -H "file:sandcat.go" -H "platform:linux" "\$CALDERA_URL/file/download" -o "\$AGENT_PATH"
sudo chmod +x "\$AGENT_PATH"

echo "[+] Creando/actualizando servicio systemd para el agente..."

sudo tee "\$SERVICE_PATH" >/dev/null <<EOSVC
[Unit]
Description=Caldera Sandcat Agent (snort-server)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=\$AGENT_PATH -server \$CALDERA_URL -group \$CALDERA_GROUP -v
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOSVC

echo "[+] Recargando systemd y habilitando el servicio..."
sudo systemctl daemon-reload
sudo systemctl enable caldera-agent.service >/dev/null 2>&1 || true
sudo systemctl restart caldera-agent.service

echo "[+] Estado del servicio caldera-agent:"
sudo systemctl status caldera-agent.service --no-pager | head -n 15 || true

EOF

# =========================
# TIEMPO TOTAL SCRIPT
# =========================
SCRIPT_END=$(date +%s)

echo "-------------------------------------------"
echo "[✔] Agente Caldera desplegado en snort-server."
echo "[✔] Conectando contra: $CALDERA_URL  (grupo: $CALDERA_GROUP)"
echo "===================================================="
echo "[⏱] Tiempo TOTAL del script: $(format_time $((SCRIPT_END-SCRIPT_START)))"
echo "===================================================="

echo
echo "Resumen:"
echo "  - Instancia Snort : $SNORT_INSTANCE_NAME  (SSH: $SSH_USER@${SNORT_FLOATING_IP:-$SNORT_PRIVATE_IP})"
echo "  - Servidor Caldera: $CALDERA_INSTANCE_NAME (URL interna: $CALDERA_URL)"
echo
echo "Comprobaciones recomendadas en snort-server:"
echo
echo "  ssh -i $SSH_KEY_PATH $SSH_USER@${SNORT_FLOATING_IP:-$SNORT_PRIVATE_IP}"
echo "  sudo systemctl status caldera-agent.service"
echo "  sudo journalctl -u caldera-agent.service -f"
echo
echo "En la GUI de Caldera deberías ver el nuevo agente (grupo '$CALDERA_GROUP') conectado."
