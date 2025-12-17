#!/bin/bash
# ==============================================
# Despliegue de parámetros para OpenStack
# Objetivo: Comprobar y crear recursos mínimos
# para poder lanzar una instancia
# ==============================================

# --------- RUTAS BASE (NUEVO) -----------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

IMG_DIR="${SCRIPT_DIR}/img"
KEYS_DIR="${SCRIPT_DIR}/keys"
CLOUDINIT_DIR="${SCRIPT_DIR}/cloud-init"

mkdir -p "$IMG_DIR" "$KEYS_DIR" "$CLOUDINIT_DIR"

# --------- CONFIGURACIÓN BÁSICA ---------------

# ===== Activar entorno virtual =====
echo "🔹 Activando primero el entorno virtual de OpenStack..."
step_start=$(date +%s)
if [[ -d "${SCRIPT_DIR}/openstack_venv" ]]; then
    source "${SCRIPT_DIR}/openstack_venv/bin/activate"
    echo "[✔] Entorno virtual 'openstack_venv' activado correctamente."
else
    echo "[✖] No se encontró el entorno 'openstack_venv'. Ejecuta primero openstack-installer.sh"
    exit 1
fi
step_end=$(date +%s)
echo "-------------------------------------------"
sleep 1

# ===== Cargar variables de entorno OpenStack =====
if [[ -f "${BASE_DIR}/admin-openrc.sh" ]]; then
    echo "[+] Cargando variables del entorno OpenStack (admin-openrc.sh)..."
    source "${BASE_DIR}/admin-openrc.sh"
    echo "[✔] Variables cargadas correctamente."
    echo "-------------------------------------------"
    sleep 1
else
    echo "[✖] No se encontró 'admin-openrc.sh'."
    exit 1
fi

# ===== Carpeta IMG para descargas =====
echo "🔹 Verificando carpeta para imágenes..."
echo "[✔] Carpeta de trabajo: $IMG_DIR"
echo "-------------------------------------------"
sleep 1

# Flavors y sus recursos
declare -A FLAVORS_DEF=(
  [T_1CPU_2GB]="--ram 2048  --vcpus 1 --disk 20"
  [S_2CPU_4GB]="--ram 4096  --vcpus 2 --disk 40"
  [M_4CPU_8GB]="--ram 8192  --vcpus 4 --disk 80"
  [L_6CPU_12GB]="--ram 12288 --vcpus 6 --disk 120"
)

# Imágenes
UBUNTU_IMG="${IMG_DIR}/ubuntu-22.04.5-jammy.qcow2"
DEBIAN_IMG="${IMG_DIR}/debian-12-generic.qcow2"
KALI_IMG_RAW="${IMG_DIR}/disk.raw"
KALI_IMG_QCOW2="${IMG_DIR}/kali-linux-2025.2.qcow2"
KALI_TAR="${IMG_DIR}/kali-linux-2025.2-cloud-genericcloud-amd64.tar.xz"

# Redes
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

# Seguridad
SEC_GROUP="sg_basic"
RULES_TCP=(21 22 25 53 80 443 1514 1515 2222 5601 7443 8022 8834 8888 17443)
RULES_UDP=(1514 1515)

# Claves
KEYPAIR="my_key"
KEYPAIR_PRIV_FILE="${KEYS_DIR}/${KEYPAIR}.pem"
KEYPAIR_PUB_FILE="${KEYS_DIR}/${KEYPAIR}.pem.pub"

PASS_FILE="${CLOUDINIT_DIR}/set-password.yml"

# --------- FUNCIONES AUXILIARES -------------

die() {
  echo "[✖] $*" >&2
  exit 1
}

run_or_die() {
  "$@" || die "Error ejecutando: $*"
}

find_existing_external_net() {
  openstack network list --external -f value -c Name || return 1
}

echo "🔹 Iniciando comprobación de recursos en OpenStack..."

# ==============================================
# FLAVORS
# ==============================================
echo "🔹 Comprobando flavors..."
for flavor in "${!FLAVORS_DEF[@]}"; do
  if openstack flavor show "$flavor" &>/dev/null; then
    echo "[✔] Flavor existente: $flavor"
  else
    echo "[+] Creando flavor: $flavor (${FLAVORS_DEF[$flavor]})"
    run_or_die openstack flavor create "$flavor" ${FLAVORS_DEF[$flavor]}
  fi
done

# ==============================================
# IMÁGENES
# ==============================================
echo "🔹 Comprobando y creando imágenes (Ubuntu + Debian + Kali)..."

IMG_LIST=("ubuntu-22.04" "debian-12" "kali-linux")

for img_name in "${IMG_LIST[@]}"; do
  if openstack image show "$img_name" &>/dev/null; then
    echo "[✔] Imagen existente en OpenStack: $img_name"
    continue
  fi

  case "$img_name" in
    "ubuntu-22.04")
      if [ ! -f "$UBUNTU_IMG" ]; then
        echo "[+] Descargando Ubuntu 22.04.5..."
        run_or_die wget -c \
          https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img \
          -O "$UBUNTU_IMG"
      fi
      IMG_FILE="$UBUNTU_IMG"
      ;;
    "debian-12")
      if [ ! -f "$DEBIAN_IMG" ]; then
        echo "[+] Descargando Debian 12..."
        run_or_die wget -c \
          https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2 \
          -O "$DEBIAN_IMG"
      fi
      IMG_FILE="$DEBIAN_IMG"
      ;;
    "kali-linux")
      if [ ! -f "$KALI_IMG_QCOW2" ]; then
        echo "[+] Descargando Kali Linux 2025.2..."
        run_or_die wget -c \
          https://kali.download/cloud-images/kali-2025.2/kali-linux-2025.2-cloud-genericcloud-amd64.tar.xz \
          -O "$KALI_TAR"

        echo "[+] Extrayendo disk.raw..."
        run_or_die tar -xvf "$KALI_TAR" -C "$IMG_DIR"

        if ! command -v qemu-img &>/dev/null; then
          echo "[!] 'qemu-img' no está instalado. Instalando..."
          sudo apt update && sudo apt install -y qemu-utils
        fi

        echo "[+] Convirtiendo disk.raw a QCOW2..."
        run_or_die qemu-img convert -f raw -O qcow2 "$KALI_IMG_RAW" "$KALI_IMG_QCOW2"
      fi
      IMG_FILE="$KALI_IMG_QCOW2"
      ;;
  esac

  echo "[+] Creando imagen en OpenStack: $img_name"
  run_or_die openstack image create "$img_name" \
    --file "$IMG_FILE" \
    --disk-format qcow2 \
    --container-format bare
done

# ==============================================
# KEYPAIR
# ==============================================
echo "🔹 Gestionando keypair (.pem)..."

if openstack keypair show "$KEYPAIR" &>/dev/null; then
    echo "[!] Keypair '$KEYPAIR' ya existe. Eliminando..."
    openstack keypair delete "$KEYPAIR"
fi

rm -f "$KEYPAIR_PRIV_FILE" "$KEYPAIR_PUB_FILE"

echo "[+] Generando nuevo par de claves..."
ssh-keygen -t rsa -b 4096 -m PEM \
    -f "$KEYPAIR_PRIV_FILE" -N "" -C "key for OpenStack"

chmod 400 "$KEYPAIR_PRIV_FILE"
chmod 644 "$KEYPAIR_PUB_FILE"

openstack keypair create --public-key "$KEYPAIR_PUB_FILE" "$KEYPAIR"

# ==============================================
# CLOUD-INIT
# ==============================================
if [ ! -f "$PASS_FILE" ]; then
  echo "[+] Creando fichero cloud-init por defecto..."
  cat > "$PASS_FILE" << EOF
#cloud-config
password: nics2025!
chpasswd: { expire: False }
ssh_pwauth: True
EOF
fi

echo
echo "[✔] Comprobación y creación de recursos completada."
echo "Ejemplo para lanzar una instancia:"
echo "[➜] openstack server create \\"
echo "      --flavor T_1CPU_2GB \\"
echo "      --image ubuntu-22.04 \\"
echo "      --network $NETWORK_PRIV \\"
echo "      --security-group $SEC_GROUP \\"
echo "      --key-name $KEYPAIR \\"
echo "      --user-data $PASS_FILE \\"
echo "      mi_instancia_01"
