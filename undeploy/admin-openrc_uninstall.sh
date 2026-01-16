#!/usr/bin/env bash
# ======================================================
# Uninstall / Cleanup admin-openrc.sh
# ======================================================

set -euo pipefail

OPENRC_FILE="admin-openrc.sh"
TMP_JSON="/tmp/clouds.json"
KOLLA_CLOUDS="/etc/kolla/clouds.yaml"

echo "==============================================="
echo "  Uninstall admin-openrc.sh (OpenStack cleanup)"
echo "==============================================="

# ------------------------------------------------------
# 1️⃣ Limpiar variables de entorno OpenStack
# ------------------------------------------------------
echo "[+] Limpiando variables de entorno OS_* ..."

unset OS_AUTH_TYPE || true
unset OS_AUTH_URL || true
unset OS_USERNAME || true
unset OS_PASSWORD || true
unset OS_USER_DOMAIN_NAME || true
unset OS_PROJECT_NAME || true
unset OS_PROJECT_DOMAIN_NAME || true
unset OS_REGION_NAME || true
unset OS_INTERFACE || true
unset OS_IDENTITY_API_VERSION || true
unset OS_APPLICATION_CREDENTIAL_ID || true
unset OS_APPLICATION_CREDENTIAL_SECRET || true
unset OS_APPLICATION_CREDENTIAL_NAME || true

echo "[✔] Variables de entorno eliminadas"

# ------------------------------------------------------
# 2️⃣ Eliminar archivo admin-openrc.sh
# ------------------------------------------------------
if [[ -f "$OPENRC_FILE" ]]; then
  rm -f "$OPENRC_FILE"
  echo "[✔] Eliminado $OPENRC_FILE"
else
  echo "[ℹ] $OPENRC_FILE no existe"
fi

# ------------------------------------------------------
# 3️⃣ Eliminar archivo temporal
# ------------------------------------------------------
if [[ -f "$TMP_JSON" ]]; then
  sudo rm -f "$TMP_JSON"
  echo "[✔] Eliminado $TMP_JSON"
else
  echo "[ℹ] $TMP_JSON no existe"
fi

# ------------------------------------------------------
# 4️⃣ Restaurar permisos de clouds.yaml (opcional)
# ------------------------------------------------------
if [[ -f "$KOLLA_CLOUDS" ]]; then
  echo "[+] Restaurando permisos seguros en $KOLLA_CLOUDS"
  sudo chown root:root "$KOLLA_CLOUDS"
  sudo chmod 600 "$KOLLA_CLOUDS"
  echo "[✔] Permisos restaurados"
else
  echo "[ℹ] $KOLLA_CLOUDS no existe"
fi

# ------------------------------------------------------
# 5️⃣ Desinstalar dependencias (SIN preguntar)
# ------------------------------------------------------
echo "[+] Desinstalando jq y yq ..."
sudo apt purge -y jq yq
sudo apt autoremove -y
echo "[✔] jq y yq desinstalados"

echo ""
echo "[✔] Uninstall completado correctamente"
