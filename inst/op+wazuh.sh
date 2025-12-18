#!/bin/bash
# ==========================================
# Despliega una instancia Debian 12 + Wazuh Manager
# ==========================================

# ===== Timer global =====
SCRIPT_START=$(date +%s)
format_time() { local total=$1; echo "$((total/60)) minutos y $((total%60)) segundos"; }

echo "============================================="
echo "    Despliega una instancia en OpenStack:    "
echo "           Debian 12 + Wazuh Manager         "
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
FLAVOR="S_2CPU_4GB"
KEY_NAME="my_key"
SEC_GROUP="sg_basic"

NETWORK_PRIVATE="net_private_01"
SUBNET_PRIVATE="subnet_net_private_01"
NETWORK_EXTERNAL="net_external_01"
ROUTER_NAME="router_private_01"

INSTANCE_NAME="wazuh-manager"
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
SSH_TIMEOUT=300  # 5 minutos
SSH_START=$(date +%s)

# Esperar a que cloud-init termine
until ssh -o StrictHostKeyChecking=no -i "$SSH_KEY_PATH" $SSH_USER@"$FLOATING_IP" "test -f /var/lib/cloud/instance/boot-finished" >/dev/null 2>&1; do
    sleep 5; echo -n "."
    NOW=$(date +%s)
    if (( NOW - SSH_START > SSH_TIMEOUT )); then
        echo; echo "[✖] Timeout: cloud-init no ha terminado, SSH no disponible"; exit 1
    fi
done

# Intentar conexión SSH real
until ssh -o StrictHostKeyChecking=no -i "$SSH_KEY_PATH" $SSH_USER@"$FLOATING_IP" "echo ok" >/dev/null 2>&1; do
    sleep 5; echo -n "."
    NOW=$(date +%s)
    if (( NOW - SSH_START > SSH_TIMEOUT )); then
        echo; echo "[✖] Timeout al intentar conectar por SSH"; exit 1
    fi
done

echo; echo "[✔] SSH disponible en $FLOATING_IP"

# =========================
# INSTALACIÓN WAZUH
# =========================
INSTALL_START=$(date +%s)
ssh -o StrictHostKeyChecking=no -i "$SSH_KEY_PATH" $SSH_USER@"$FLOATING_IP" <<'EOF'
set -e
export DEBIAN_FRONTEND=noninteractive

echo "[+] Actualizando sistema..."
sudo apt-get update -o Acquire::Retries=3

sleep 10 # Evitar cuelgue

sudo apt-get upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"

sleep 10 # Evitar cuelgue

echo "[+] Instalando dependencias..."
sudo apt-get install -y curl net-tools gnupg lsb-release apt-transport-https

echo "[+] Descargando Wazuh..."
cd "$HOME"
sudo curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh
sudo chmod +x wazuh-install.sh

echo "[+] Ejecutando instalación automática..."
sudo bash ./wazuh-install.sh -a

echo "[+] Esperando 15 segundos para que Wazuh Manager arranque..."
sleep 15

# Extraer contraseña admin
if [[ -f wazuh-install-files.tar ]]; then
    sudo tar -axf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt -O \
        | grep -P "'admin'" -A 1 \
        | tail -n 1 \
        | awk -F"'" '{print $2}' \
        | sudo tee /tmp/wazuh-admin-password >/dev/null || true
else
    echo "[!] No se encontró 'wazuh-install-files.tar', no se puede extraer la contraseña automáticamente."
fi

echo "[+] Comprobando estado servicio wazuh-manager..."
sudo systemctl is-active --quiet wazuh-manager && echo "[✔] wazuh-manager activo" || sudo systemctl status wazuh-manager.service --no-pager

echo "[+] Comprobando puerto 1515..."
sudo netstat -tuln | grep 1515 || echo "[!] puerto 1515 no encontrado."
EOF

# ===== Recuperar contraseña admin desde la instancia =====
ADMIN_PASSWORD=$(ssh -o StrictHostKeyChecking=no -i "$SSH_KEY_PATH" $SSH_USER@"$FLOATING_IP" 'sudo cat /tmp/wazuh-admin-password 2>/dev/null || true')

INSTALL_END=$(date +%s)
echo "[✔] Wazuh Manager instalado."
echo "[⏱] Tiempo de instalación: $(format_time $((INSTALL_END-INSTALL_START)))"

if [[ -z "$ADMIN_PASSWORD" ]]; then
    ADMIN_PASSWORD="<NO_DETECTADA_EN_SCRIPT>"
    echo "[!] No se pudo obtener la contraseña de 'admin'. Ejecuta manualmente dentro de la instancia."
fi

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
echo "Acceso Wazuh Dashboard:"
echo "  URL      : https://$FLOATING_IP"
echo "  Usuario  : admin"
echo "  Password : $ADMIN_PASSWORD"
echo ""
