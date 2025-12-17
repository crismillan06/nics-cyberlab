#!/bin/bash
# ==========================================
#  Descripción: Despliega una instancia
#  Debian 12 en OpenStack e instala Snort 3
# ==========================================

# ===== Timer global del script =====
SCRIPT_START=$(date +%s)

# Convertir segundos → "X minutos y Y segundos"
format_time() {
    local total=$1
    local minutes=$((total / 60))
    local seconds=$((total % 60))
    echo "${minutes} minutos y ${seconds} segundos"
}

echo "============================================="
echo "    Despliega una instancia en OpenStack:    "
echo "             Debian 12 + Snort 3             "
echo "============================================="

# ===== Activar entorno virtual =====
echo "🔹 Activando entorno virtual de OpenStack..."
step_start=$(date +%s)
if [[ -d "openstack-installer/openstack_venv" ]]; then
    source openstack-installer/openstack_venv/bin/activate
    echo "[✔] Entorno virtual 'openstack_venv' activado correctamente."
else
    echo "[✖] No se encontró el entorno 'openstack_venv'. Ejecuta primero openstack-recursos.sh"
    exit 1
fi
step_end=$(date +%s)
echo "-------------------------------------------"
sleep 1

# ===== Cargar variables de entorno OpenStack =====
if [[ -f "admin-openrc.sh" ]]; then
    echo "[+] Cargando variables del entorno OpenStack (admin-openrc.sh)..."
    source admin-openrc.sh
    echo "[✔] Variables cargadas correctamente."
    echo "-------------------------------------------"
    sleep 1
else
    echo "[✖] No se encontró 'admin-openrc.sh'. Ejecuta primero openstack-recursos.sh"
    exit 1
fi

# =========================
# CONFIGURACIÓN GENERAL
# =========================
IMAGE_NAME="debian-12"
FLAVOR="S_2CPU_4GB"
KEY_NAME="my_key"
SEC_GROUP="sg_basic"

NETWORK_PRIVATE="net_private_01"
SUBNET_PRIVATE="subnet_net_private_01"
NETWORK_EXTERNAL="net_external_01"
ROUTER_NAME="router_private_01"

INSTANCE_NAME="snort-server"
SSH_USER="debian"
SSH_KEY_PATH="$HOME/nics-cyberlab-A/my_key.pem"
USERDATA_FILE="$HOME/nics-cyberlab-A/set-password.yml"
KNOWN_HOSTS_FILE="$HOME/.ssh/known_hosts"

# =========================
# VERIFICACIÓN DE RECURSOS
# =========================
echo "🔹 Verificando recursos necesarios..."

if ! openstack image list -f value -c Name | grep -qw "$IMAGE_NAME"; then
    echo "[!] Falta la imagen '$IMAGE_NAME'. Ejecuta openstack-recursos.sh"; exit 1
fi
if ! openstack flavor list -f value -c Name | grep -qw "$FLAVOR"; then
    echo "[!] Falta el flavor '$FLAVOR'. Ejecuta openstack-recursos.sh"; exit 1
fi
if ! openstack keypair list -f value -c Name | grep -qw "$KEY_NAME"; then
    echo "[!] Falta el keypair '$KEY_NAME'. Ejecuta openstack-recursos.sh"; exit 1
fi
if [[ ! -f "$SSH_KEY_PATH" ]]; then
    echo "[!] No se encuentra la clave privada '$SSH_KEY_PATH'."; exit 1
fi
if ! openstack security group list -f value -c Name | grep -qw "$SEC_GROUP"; then
    echo "[!] Falta el grupo de seguridad '$SEC_GROUP'. Ejecuta openstack-recursos.sh"; exit 1
fi
if ! openstack network list -f value -c Name | grep -qw "$NETWORK_PRIVATE"; then
    echo "[!] Falta la red privada '$NETWORK_PRIVATE'."; exit 1
fi
if ! openstack subnet list -f value -c Name | grep -qw "$SUBNET_PRIVATE"; then
    echo "[!] Falta la subred privada '$SUBNET_PRIVATE'."; exit 1
fi
if ! openstack router list -f value -c Name | grep -qw "$ROUTER_NAME"; then
    echo "[!] Falta el router '$ROUTER_NAME'."; exit 1
fi
if [[ ! -f "$USERDATA_FILE" ]]; then
    echo "[!] No se encuentra '$USERDATA_FILE'."; exit 1
fi

echo "[✔] Todos los recursos necesarios existen."
echo "-------------------------------------------"

# =========================
# ELIMINAR INSTANCIA PREVIA
# =========================
EXISTING=$(openstack server list -f value -c Name | grep -w "$INSTANCE_NAME")
if [[ -n "$EXISTING" ]]; then
    echo "[!] Existe una instancia '$INSTANCE_NAME'. Eliminando..."
    for s in $EXISTING; do openstack server delete "$s"; done

    until ! openstack server list -f value -c Name | grep -qw "$INSTANCE_NAME"; do
        sleep 5
        echo -n "."
    done
    echo
    echo "[✔] Instancia '$INSTANCE_NAME' eliminada."
fi

# =========================
# CREACIÓN DE LA INSTANCIA
# =========================
echo "🔹 Creando instancia '$INSTANCE_NAME'..."
openstack server create \
  --image "$IMAGE_NAME" \
  --flavor "$FLAVOR" \
  --key-name "$KEY_NAME" \
  --security-group "$SEC_GROUP" \
  --network "$NETWORK_PRIVATE" \
  --user-data "$USERDATA_FILE" \
  "$INSTANCE_NAME"

echo "[+] Esperando que la instancia esté ACTIVE..."
until [[ "$(openstack server show "$INSTANCE_NAME" -f value -c status)" == "ACTIVE" ]]; do
    sleep 5
    echo -n "."
done
echo
echo "[✔] Instancia '$INSTANCE_NAME' activa."

# =========================
# IP FLOTANTE
# =========================
FLOATING_IP=$(openstack floating ip list -f value -c "Floating IP Address" -c "Fixed IP Address" | awk '$2=="None"{print $1; exit}')
if [[ -z "$FLOATING_IP" ]]; then
    FLOATING_IP=$(openstack floating ip create "$NETWORK_EXTERNAL" -f value -c floating_ip_address)
fi

ssh-keygen -f "$KNOWN_HOSTS_FILE" -R "$FLOATING_IP" >/dev/null 2>&1
openstack server add floating ip "$INSTANCE_NAME" "$FLOATING_IP"

# =========================
# ESPERA SSH (1 MINUTO)
# =========================
echo "[+] Esperando conexión SSH (Puede tardar un momentito)..."
SSH_TIMEOUT=60
SSH_START=$(date +%s)

until ssh -o StrictHostKeyChecking=no -i "$SSH_KEY_PATH" $SSH_USER@"$FLOATING_IP" "echo ok" >/dev/null 2>&1; do
    sleep 5
    echo -n "."
    NOW=$(date +%s)
    if (( NOW - SSH_START > SSH_TIMEOUT )); then
        echo
        echo "[✖] Timeout al intentar conectar por SSH"
        exit 1
    fi
done

echo
echo "[✔] SSH disponible en $FLOATING_IP"

# ===============================
# INSTALACIÓN DE SNORT 3 (TIMER)
# ===============================
INSTALL_START=$(date +%s)

ssh -o StrictHostKeyChecking=no -i "$SSH_KEY_PATH" $SSH_USER@"$FLOATING_IP" <<'EOF'
set -e

sudo apt update
sudo apt upgrade -y
sudo apt autoremove --purge -y
sudo apt autoclean -y

sudo apt install -y build-essential cmake pkg-config autoconf automake libtool bison flex git
sudo apt install -y libpcap-dev libpcre3 libpcre3-dev libpcre2-dev libdumbnet-dev \
    zlib1g-dev liblzma-dev openssl libssl-dev libluajit-5.1-dev luajit libtirpc-dev libnghttp2-dev libhwloc-dev

cd /tmp
git clone https://github.com/snort3/libdaq.git
cd libdaq
sudo ./bootstrap
sudo ./configure
sudo make -j$(nproc)
sudo make install
sudo ldconfig

cd /tmp
git clone https://github.com/snort3/snort3.git
cd snort3
sudo ./configure_cmake.sh --prefix=/usr/local/snort3
cd build
sudo make -j$(nproc)
sudo make install
sudo ldconfig
sudo ln -sf /usr/local/snort3/bin/snort /usr/local/bin/snort

sudo mkdir -p /etc/snort/rules
sudo cp -r /usr/local/snort3/etc/snort/* /etc/snort/

sudo tee /etc/snort/snort.lua > /dev/null <<'EOL'
RULE_PATH = "/etc/snort/rules"
LOCAL_RULES = RULE_PATH .. "/local.rules"
daq = { modules = { { name = "afpacket" } } }
ips = { enable_builtin_rules = false, include = { LOCAL_RULES } }
alert_fast = { file = true }
outputs = { alert_fast }
EOL

sudo tee /etc/snort/rules/local.rules > /dev/null <<'EOL'
alert icmp any any -> any any (msg:"Intento ICMPv4 detectado"; sid:1000010; rev:1;)
EOL

sudo mkdir -p /var/log/snort
sudo touch /var/log/snort/alert_fast.txt
sudo chmod -R 755 /var/log/snort
sudo chown -R debian:debian /var/log/snort
sudo ip link set ens3 promisc on
EOF

INSTALL_END=$(date +%s)
INSTALL_TIME=$((INSTALL_END - INSTALL_START))

echo "[✔] Snort 3 instalado y configurado."
echo "[⏱] Tiempo de instalación de Snort: $(format_time $INSTALL_TIME)"
echo "[✔] IP flotante asignada: $FLOATING_IP"

# ========================================
# TIEMPO TOTAL DEL SCRIPT
# ========================================
SCRIPT_END=$(date +%s)
SCRIPT_TIME=$((SCRIPT_END - SCRIPT_START))

echo "===================================================="
echo "[⏱] Tiempo TOTAL del script: $(format_time $SCRIPT_TIME)"
echo "===================================================="

echo "Acceso SSH:"
echo "[➜] ssh -i $SSH_KEY_PATH $SSH_USER@$FLOATING_IP"
echo "-----------------------------------------------"

echo "Terminal 1 – Snort capturando tráfico:"
echo "[➜] sudo snort -i ens3 -c /etc/snort/snort.lua -A alert_fast -k none -l /var/log/snort"
echo
echo "Terminal 2 – Visualización en tiempo real de alertas:"
echo "[➜] sudo tail -f /var/log/snort/alert_fast.txt"
echo
echo "Terminal 3 – Cliente externo (prueba ICMP):"
echo "[➜] ping -c 4 <IP_tarjeta_snort>"
