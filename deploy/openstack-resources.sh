#!/bin/bash
# ==============================================
# Despliegue de parámetros para OpenStack
# Objetivo: Comprobar y crear recursos mínimos
# ==============================================

# --------- RUTAS BASE --------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

IMG_DIR="${SCRIPT_DIR}/img"
KEYS_DIR="${SCRIPT_DIR}/keys"
CLOUDINIT_DIR="${SCRIPT_DIR}/cloud-init"
VENV_DIR="${SCRIPT_DIR}/openstack_venv"

mkdir -p "$IMG_DIR" "$KEYS_DIR" "$CLOUDINIT_DIR"

# --------- CONFIGURACIÓN BÁSICA ---------------

echo "🔹 Activando primero el entorno virtual de OpenStack..."
if [[ -d "$VENV_DIR" ]]; then
  source "$VENV_DIR/bin/activate"
  echo "[✔] Entorno virtual activado correctamente."
else
  echo "[✖] No se encontró el entorno virtual."
  exit 1
fi
echo "-------------------------------------------"
sleep 1

echo "🔹 Cargando variables del entorno OpenStack..."
if [[ -f "${BASE_DIR}/admin-openrc.sh" ]]; then
  source "${BASE_DIR}/admin-openrc.sh"
  echo "[✔] Variables cargadas correctamente."
else
  echo "[✖] No se encontró admin-openrc.sh"
  exit 1
fi
echo "-------------------------------------------"
sleep 1

# --------- DEFINICIÓN DE RECURSOS -------------

declare -A FLAVORS_DEF=(
  [T_1CPU_2GB]="--ram 2048 --vcpus 1 --disk 20"
  [S_2CPU_4GB]="--ram 4096 --vcpus 2 --disk 40"
  [M_4CPU_8GB]="--ram 8192 --vcpus 4 --disk 80"
  [L_6CPU_12GB]="--ram 12288 --vcpus 6 --disk 120"
)

UBUNTU_IMG="${IMG_DIR}/ubuntu-22.04.5-jammy.qcow2"
DEBIAN_IMG="${IMG_DIR}/debian-12-generic.qcow2"
KALI_IMG_RAW="${IMG_DIR}/disk.raw"
KALI_IMG_QCOW2="${IMG_DIR}/kali-linux-2025.2.qcow2"
KALI_TAR="${IMG_DIR}/kali-linux-2025.2-cloud-genericcloud-amd64.tar.xz"

NETWORK_EXT_NAME="net_external_01"
SUBNET_EXT_NAME="subnet_net_external_01"
EXT_SUBNET_RANGE="10.0.2.0/24"
EXT_GATEWAY_IP="10.0.2.1"

NETWORK_PRIV="net_private_01"
SUBNET_PRIV="subnet_net_private_01"
PRIV_SUBNET_RANGE="192.168.100.0/24"
PRIV_GATEWAY_IP="192.168.100.1"

ROUTER_PRIV="router_private_01"
USE_EXTERNAL_NET=1

SEC_GROUP="sg_basic"
RULES_TCP=(21 22 25 53 80 443 1514 1515 2222 5601 7443 8022 8834 8888 17443)
RULES_UDP=(1514 1515)

KEYPAIR="my_key"
KEYPAIR_PRIV_FILE="${KEYS_DIR}/${KEYPAIR}.pem"
KEYPAIR_PUB_FILE="${KEYS_DIR}/${KEYPAIR}.pem.pub"

PASS_FILE="${CLOUDINIT_DIR}/set-password.yml"

# --------- FUNCIONES --------------------------

die() { echo "[✖] $*" >&2; exit 1; }
run_or_die() { "$@" &>/dev/null || die "Error ejecutando: $*"; }
find_existing_external_net() {
  openstack network list --external -f value -c Name 2>/dev/null
}

echo "🔹 Iniciando comprobación de recursos en OpenStack..."
echo "-------------------------------------------"

# ==============================================
# FLAVORS
# ==============================================
echo "🔹 Comprobando flavors..."

for flavor in "${!FLAVORS_DEF[@]}"; do
  if openstack flavor show "$flavor" &>/dev/null; then
    echo "[✔] Flavor existente: $flavor"
  else
    echo "[+] Creando flavor: $flavor"
    run_or_die openstack flavor create "$flavor" ${FLAVORS_DEF[$flavor]}
    echo "[✔] Flavor creado correctamente: $flavor"
  fi
done
echo "-------------------------------------------"

# ==============================================
# IMÁGENES
# ==============================================
echo "🔹 Comprobando imágenes..."

IMG_LIST=("ubuntu-22.04" "debian-12" "kali-linux")

for img in "${IMG_LIST[@]}"; do
  if openstack image show "$img" &>/dev/null; then
    echo "[✔] Imagen existente: $img"
    continue
  fi

  echo "[+] Preparando imagen: $img"

  case "$img" in
    ubuntu-22.04)
      [ -f "$UBUNTU_IMG" ] || run_or_die wget -q \
        https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img \
        -O "$UBUNTU_IMG"
      FILE="$UBUNTU_IMG"
      ;;
    debian-12)
      [ -f "$DEBIAN_IMG" ] || run_or_die wget -q \
        https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2 \
        -O "$DEBIAN_IMG"
      FILE="$DEBIAN_IMG"
      ;;
    kali-linux)
      if [ ! -f "$KALI_IMG_QCOW2" ]; then
        run_or_die wget -q \
          https://kali.download/cloud-images/kali-2025.2/kali-linux-2025.2-cloud-genericcloud-amd64.tar.xz \
          -O "$KALI_TAR"
        run_or_die tar -xf "$KALI_TAR" -C "$IMG_DIR"
        command -v qemu-img >/dev/null || sudo apt install -y qemu-utils &>/dev/null
        run_or_die qemu-img convert -f raw -O qcow2 "$KALI_IMG_RAW" "$KALI_IMG_QCOW2"
      fi
      FILE="$KALI_IMG_QCOW2"
      ;;
  esac

  echo "[+] Subiendo imagen a OpenStack: $img"
  run_or_die openstack image create "$img" \
    --file "$FILE" \
    --disk-format qcow2 \
    --container-format bare

  echo "[✔] Imagen creada correctamente: $img"
done
echo "-------------------------------------------"

# ==============================================
# RED EXTERNA
# ==============================================
echo "🔹 Comprobando red externa..."

NETWORK_EXT_ID=""

if openstack network show "$NETWORK_EXT_NAME" &>/dev/null; then
  NETWORK_EXT_ID=$(openstack network show "$NETWORK_EXT_NAME" -f value -c id)
  echo "[✔] Red externa existente: $NETWORK_EXT_NAME"
else
  echo "[+] Creando red externa: $NETWORK_EXT_NAME"
  if openstack network create "$NETWORK_EXT_NAME" \
      --external --provider-network-type flat \
      --provider-physical-network physnet1 &>/dev/null; then
    NETWORK_EXT_ID=$(openstack network show "$NETWORK_EXT_NAME" -f value -c id)
    echo "[✔] Red externa creada correctamente: $NETWORK_EXT_NAME"
  else
    echo "[!] No se pudo crear red externa, buscando existente..."
    EXISTING_EXT_NETS=$(find_existing_external_net)
    if [ -z "$EXISTING_EXT_NETS" ]; then
      USE_EXTERNAL_NET=0
      echo "[!] No hay redes externas disponibles"
    else
      NETWORK_EXT_NAME=$(echo "$EXISTING_EXT_NETS" | head -n1)
      NETWORK_EXT_ID=$(openstack network show "$NETWORK_EXT_NAME" -f value -c id)
      echo "[✔] Usando red externa existente: $NETWORK_EXT_NAME"
    fi
  fi
fi

if [ "$USE_EXTERNAL_NET" -eq 1 ]; then
  if openstack subnet show "$SUBNET_EXT_NAME" &>/dev/null; then
    echo "[✔] Subred externa existente: $SUBNET_EXT_NAME"
  else
    echo "[+] Creando subred externa: $SUBNET_EXT_NAME"
    run_or_die openstack subnet create "$SUBNET_EXT_NAME" \
      --network "$NETWORK_EXT_ID" \
      --subnet-range "$EXT_SUBNET_RANGE" \
      --gateway "$EXT_GATEWAY_IP" \
      --dns-nameserver 8.8.8.8
    echo "[✔] Subred externa creada correctamente"
  fi
fi
echo "-------------------------------------------"

# ==============================================
# RED PRIVADA + ROUTER
# ==============================================
echo "🔹 Comprobando red privada y router..."

if openstack network show "$NETWORK_PRIV" &>/dev/null; then
  echo "[✔] Red privada existente: $NETWORK_PRIV"
else
  echo "[+] Creando red privada: $NETWORK_PRIV"
  run_or_die openstack network create "$NETWORK_PRIV"
  echo "[✔] Red privada creada correctamente"
fi

if openstack subnet show "$SUBNET_PRIV" &>/dev/null; then
  echo "[✔] Subred privada existente: $SUBNET_PRIV"
else
  echo "[+] Creando subred privada: $SUBNET_PRIV"
  run_or_die openstack subnet create "$SUBNET_PRIV" \
    --network "$NETWORK_PRIV" \
    --subnet-range "$PRIV_SUBNET_RANGE" \
    --gateway "$PRIV_GATEWAY_IP" \
    --dns-nameserver 8.8.8.8
  echo "[✔] Subred privada creada correctamente"
fi

if openstack router show "$ROUTER_PRIV" &>/dev/null; then
  echo "[✔] Router existente: $ROUTER_PRIV"
else
  echo "[+] Creando router: $ROUTER_PRIV"
  run_or_die openstack router create "$ROUTER_PRIV"
  echo "[✔] Router creado correctamente"
fi

[ "$USE_EXTERNAL_NET" -eq 1 ] && \
  openstack router set "$ROUTER_PRIV" --external-gateway "$NETWORK_EXT_ID" &>/dev/null

openstack router add subnet "$ROUTER_PRIV" "$SUBNET_PRIV" 2>/dev/null || true
echo "-------------------------------------------"

# ==============================================
# SECURITY GROUP
# ==============================================
echo "🔹 Comprobando security group..."

if openstack security group show "$SEC_GROUP" &>/dev/null; then
    echo "[✔] Grupo existente: $SEC_GROUP"
else
    echo "[+] Creando security group $SEC_GROUP..."
    run_or_die openstack security group create "$SEC_GROUP"
fi

echo "[+] Configurando reglas de seguridad..."

add_rule() {
  local proto=$1
  local port=$2

  # Comprobamos si ya existe la regla
  if ! openstack security group rule list "$SEC_GROUP" -f value \
       -c "IP Protocol" -c "Port Range" | grep -qE "^$proto\s+$port:$port$"; then
    echo "[+] Añadiendo regla $proto para puerto $port..."
    run_or_die openstack security group rule create --proto "$proto" --dst-port "$port" "$SEC_GROUP"
    echo "[✔] Regla $proto aplicada: $port"
  else
    echo "[✔] Regla $proto existente: $port"
  fi
}

# TCP
for p in "${RULES_TCP[@]}"; do
  add_rule tcp "$p"
done

# UDP
for p in "${RULES_UDP[@]}"; do
  add_rule udp "$p"
done

# ICMP
if ! openstack security group rule list "$SEC_GROUP" -f value -c "IP Protocol" | grep -q "^icmp$"; then
  echo "[+] Añadiendo regla ICMP..."
  run_or_die openstack security group rule create --proto icmp "$SEC_GROUP"
  echo "[✔] Regla ICMP aplicada"
else
  echo "[✔] Regla ICMP existente"
fi

# ==============================================
# KEYPAIR
# ==============================================
echo "🔹 Gestionando keypair (.pem)..."

if openstack keypair show "$KEYPAIR" &>/dev/null; then
    echo "[!] Keypair '$KEYPAIR' ya existe. Eliminando..."
    openstack keypair delete "$KEYPAIR"
fi

if [[ -f "$KEYPAIR_PRIV_FILE" ]]; then rm -f "$KEYPAIR_PRIV_FILE"; fi
if [[ -f "$KEYPAIR_PUB_FILE" ]]; then rm -f "$KEYPAIR_PUB_FILE"; fi

echo "[+] Generando nuevo par de claves..."
ssh-keygen -t rsa -b 4096 -m PEM \
    -f "$KEYPAIR_PRIV_FILE" -N "" -C "key for OpenStack"

chmod 400 "$KEYPAIR_PRIV_FILE"
chmod 644 "$KEYPAIR_PUB_FILE"

openstack keypair create --public-key "$KEYPAIR_PUB_FILE" "$KEYPAIR" &>/dev/null
echo "[✔] Keypair creado correctamente:"
echo "    Privada: $KEYPAIR_PRIV_FILE"
echo "    Pública: $KEYPAIR_PUB_FILE"
echo "-------------------------------------------"

# ==============================================
# CLOUD-INIT
# ==============================================
echo "🔹 Comprobando cloud-init..."

if [ ! -f "$PASS_FILE" ]; then
  echo "[+] Creando fichero cloud-init..."
  cat > "$PASS_FILE" <<EOF
#cloud-config
password: nics2025!
chpasswd: { expire: False }
ssh_pwauth: True
EOF
  echo "[✔] Fichero cloud-init generado en: $PASS_FILE"
else
  echo "[✔] Fichero cloud-init existente en: $PASS_FILE"
fi
echo "-------------------------------------------"

# ==============================================
# FINAL
# ==============================================
echo
echo "[✔] Comprobación y creación de recursos completada."
echo "Ejemplo de lanzamiento:"
echo
echo "openstack server create \\"
echo "  --flavor T_1CPU_2GB \\"
echo "  --image ubuntu-22.04 \\"
echo "  --network $NETWORK_PRIV \\"
echo "  --security-group $SEC_GROUP \\"
echo "  --key-name $KEYPAIR \\"
echo "  --user-data $PASS_FILE \\"
echo "  mi_instancia_01"
