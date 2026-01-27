#!/bin/bash
# ==========================================
# Despliega una instancia Debian 12 + Snort 3
# ==========================================

# ===== Timer global =====
SCRIPT_START=$(date +%s)
format_time() { local total=$1; echo "$((total/60)) minutos y $((total%60)) segundos"; }

echo "============================================="
echo "    Despliega una instancia en OpenStack:    "
echo "             Debian 12 + Snort 3             "
echo "============================================="

# ===== Activar entorno virtual =====
VENV_DIR="deploy/openstack_venv"
echo "🔹 Activando entorno virtual de OpenStack..."
if [[ -d "$VENV_DIR" ]]; then
    source "$VENV_DIR/bin/activate"
    echo "[✔] Entorno virtual activado correctamente: $VENV_DIR"
else
    echo "[✖] No se encontró el entorno '$VENV_DIR'. Ejecuta primero deploy/openstack-resources.sh"
    exit 1
fi
echo "-------------------------------------------"
sleep 1

# ===== Cargar variables de entorno OpenStack =====
OPENRC_FILE="admin-openrc.sh"
if [[ -f "$OPENRC_FILE" ]]; then
    echo "[+] Cargando variables del entorno OpenStack ($OPENRC_FILE)..."
    source "$OPENRC_FILE"
    echo "[✔] Variables cargadas correctamente."
    echo "-------------------------------------------"
    sleep 1
else
    echo "[✖] No se encontró '$OPENRC_FILE'. Ejecuta primero deploy/openstack-resources.sh"
    exit 1
fi

# =========================
# CONFIGURACIÓN GENERAL
# =========================
IMAGE_NAME="debian-12"
FLAVOR="T_1CPU_2GB"
KEY_NAME="my_key"
SEC_GROUP="sg_basic"

NETWORK_PRIVATE="net_private_01"
SUBNET_PRIVATE="subnet_net_private_01"
NETWORK_EXTERNAL="net_external_01"
ROUTER_NAME="router_private_01"

INSTANCE_NAME="snort-server"
SSH_USER="debian"
SSH_KEY_PATH="$PWD/deploy/keys/${KEY_NAME}.pem"
USERDATA_FILE="$PWD/deploy/cloud-init/set-password.yml"
KNOWN_HOSTS_FILE="$HOME/.ssh/known_hosts"

echo "[✔] Keypair privado: $SSH_KEY_PATH"
echo "[✔] Cloud-init: $USERDATA_FILE"

# =========================
# VERIFICACIÓN DE RECURSOS
# =========================
echo "🔹 Verificando recursos necesarios..."

for res in \
    "openstack image list -f value -c Name|grep -qw $IMAGE_NAME:'Imagen $IMAGE_NAME'" \
    "openstack flavor list -f value -c Name|grep -qw $FLAVOR:'Flavor $FLAVOR'" \
    "openstack keypair list -f value -c Name|grep -qw $KEY_NAME:'Keypair $KEY_NAME'" \
    "openstack security group list -f value -c Name|grep -qw $SEC_GROUP:'Grupo de seguridad $SEC_GROUP'" \
    "openstack network list -f value -c Name|grep -qw $NETWORK_PRIVATE:'Red privada $NETWORK_PRIVATE'" \
    "openstack subnet list -f value -c Name|grep -qw $SUBNET_PRIVATE:'Subred privada $SUBNET_PRIVATE'" \
    "openstack router list -f value -c Name|grep -qw $ROUTER_NAME:'Router $ROUTER_NAME'" \
    "[[ -f $SSH_KEY_PATH ]]:'Clave privada $SSH_KEY_PATH'" \
    "[[ -f $USERDATA_FILE ]]:'Cloud-init $USERDATA_FILE'"
do
    cmd=$(echo $res | cut -d: -f1)
    msg=$(echo $res | cut -d: -f2)
    eval $cmd
    if [[ $? -ne 0 ]]; then
        echo "[✖] Falta recurso: $msg. Ejecuta deploy/openstack-resources.sh"
        exit 1
    else
        echo "[✔] Recurso existente: $msg"
    fi
done
echo "-------------------------------------------"

# =========================
# ELIMINAR INSTANCIA PREVIA
# =========================
EXISTING=$(openstack server list -f value -c Name | grep -w "$INSTANCE_NAME")
if [[ -n "$EXISTING" ]]; then
    echo "[!] Existe instancia '$INSTANCE_NAME'. Eliminando..."
    for s in $EXISTING; do openstack server delete "$s"; done
    until ! openstack server list -f value -c Name | grep -qw "$INSTANCE_NAME"; do
        sleep 5; echo -n "."
    done
    echo; echo "[✔] Instancia '$INSTANCE_NAME' eliminada."
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
    sleep 5; echo -n "."
done
echo; echo "[✔] Instancia '$INSTANCE_NAME' activa."

# =========================
# IP FLOTANTE
# =========================
FLOATING_IP=$(openstack floating ip list -f value -c "Floating IP Address" -c "Fixed IP Address" | awk '$2=="None"{print $1; exit}')
if [[ -z "$FLOATING_IP" ]]; then
    FLOATING_IP=$(openstack floating ip create "$NETWORK_EXTERNAL" -f value -c floating_ip_address)
fi
ssh-keygen -f "$KNOWN_HOSTS_FILE" -R "$FLOATING_IP" >/dev/null 2>&1
openstack server add floating ip "$INSTANCE_NAME" "$FLOATING_IP"

echo "[✔] IP flotante asignada: $FLOATING_IP"

# =========================
# ESPERA SSH
# =========================
echo "[+] Esperando conexión SSH..."
SSH_TIMEOUT=120
SSH_START=$(date +%s)
until ssh -o StrictHostKeyChecking=no -i "$SSH_KEY_PATH" $SSH_USER@"$FLOATING_IP" "echo ok" >/dev/null 2>&1; do
    sleep 5; echo -n "."
    NOW=$(date +%s)
    if (( NOW - SSH_START > SSH_TIMEOUT )); then
        echo; echo "[✖] Timeout al intentar conectar por SSH"; exit 1
    fi
done
echo; echo "[✔] SSH disponible en $FLOATING_IP"

# =========================
# INSTALACIÓN SNORT 3
# =========================
INSTALL_START=$(date +%s)
ssh -o StrictHostKeyChecking=no -i "$SSH_KEY_PATH" $SSH_USER@"$FLOATING_IP" <<'EOF'
set -e
sudo apt update && sudo apt upgrade -y && sudo apt autoremove --purge -y && sudo apt autoclean -y
sudo apt install -y build-essential cmake pkg-config autoconf automake libtool bison flex git \
    libpcap-dev libpcre3 libpcre3-dev libpcre2-dev libdumbnet-dev zlib1g-dev liblzma-dev \
    openssl libssl-dev libluajit-5.1-dev luajit libtirpc-dev libnghttp2-dev libhwloc-dev

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

# === Reglas locales (ICMP + Nmap SYN scan) ===
sudo tee /etc/snort/rules/local.rules > /dev/null <<'EOL'
alert icmp any any -> any any (msg:"Intento ICMPv4 detectado"; sid:1000010; rev:1;)
#alert tcp any any -> any any (msg:"Nmap TCP SYN scan"; flow:stateless; flags:S; detection_filter:track by_src, count 5, seconds 20; sid:1000011; rev:2;)
EOL

sudo mkdir -p /var/log/snort
sudo touch /var/log/snort/alert_fast.txt
sudo chmod -R 755 /var/log/snort
sudo chown -R debian:debian /var/log/snort
sudo ip link set ens3 promisc on
EOF
INSTALL_END=$(date +%s)
echo "[✔] Snort 3 instalado."
echo "[⏱] Tiempo de instalación: $(format_time $((INSTALL_END-INSTALL_START)))"

# =========================
# TIEMPO TOTAL SCRIPT
# =========================
SCRIPT_END=$(date +%s)
echo "===================================================="
echo "[⏱] Tiempo TOTAL del script: $(format_time $((SCRIPT_END-SCRIPT_START)))"
echo "===================================================="

echo "Acceso SSH:"
echo "[➜] ssh -i $SSH_KEY_PATH $SSH_USER@$FLOATING_IP"
echo "-----------------------------------------------"
echo "Terminal 1 – Snort capturando tráfico:"
echo "[➜] sudo snort -i ens3 -c /etc/snort/snort.lua -A alert_fast -k none -l /var/log/snort"
echo "Terminal 2 – Visualización en tiempo real de alertas:"
echo "[➜] sudo tail -f /var/log/snort/alert_fast.txt"
echo "Terminal 3 – Cliente externo (prueba ICMP):"
echo "[➜] ping -c 4 <IP_tarjeta_snort>"
