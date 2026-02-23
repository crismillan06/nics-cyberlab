#!/usr/bin/env bash
# ==========================================================
# NICS | CyberLab — Preflight Check (OpenStack / Kolla)
#   Reglas:
#     - FAIL  = "sin esto NO funciona"
#     - WARN  = "recomendado / mejor tenerlo"
#   Además:
#     - Si falta algo y el instalador NO lo instala => FAIL (no WARN)
#     - Cada WARN/FAIL arreglable imprime "haz esto"
# ==========================================================
set -euo pipefail

NO_COLOR=0
DO_FIX=0
ASSUME_YES=0

MIN_CPU=8
REC_CPU=16
MIN_RAM_GB=16
REC_RAM_GB=32
MIN_DISK_GB=120
REC_DISK_GB=240

CRIT_PORTS_REGEX=":(80|443|5000|8000|8004|8080|8888|9696|8774|3306|5672)\b"

# -------------------------------------------------------------------
# Qué instala tu script de instalación (ajústalo a la realidad)
# - Si algo falta y está en esta lista => WARN (porque se instalará)
# - Si algo falta y NO está en esta lista => FAIL (instálalo tú)
#
# Puedes sobrescribir sin editar:
#   INSTALLER_INSTALLS_CSV="python3,git,curl,wget,docker" sudo bash preflight-check.sh
# -------------------------------------------------------------------
INSTALLER_INSTALLS_CSV="${INSTALLER_INSTALLS_CSV:-python3,git,curl,wget}"
INSTALLER_INSTALLS_CSV="${INSTALLER_INSTALLS_CSV// /}"
IFS=',' read -r -a INSTALLER_INSTALLS <<< "$INSTALLER_INSTALLS_CSV"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --fix) DO_FIX=1; shift ;;
    --yes|-y) ASSUME_YES=1; shift ;;
    --no-color) NO_COLOR=1; shift ;;
    -h|--help)
      cat <<'EOF'
Uso:
  sudo bash preflight-check.sh [--fix] [--yes|-y] [--no-color]

Opciones:
  --fix        Aplica correcciones seguras (módulos, sysctl, locale UTF-8, opcionalmente ufw/unattended/AppArmor)
  --yes|-y     No preguntar (asume "sí" cuando el fix es razonable)
  --no-color   Desactiva colores

Config (env):
  INSTALLER_INSTALLS_CSV="python3,git,curl,wget"   # comandos que tu instalador SI instalará
EOF
      exit 0
      ;;
    *) echo "[X] Opción desconocida: $1" >&2; exit 1 ;;
  esac
done

# ----------------------------------------------------------
# Root check ANTES de tocar el log
# ----------------------------------------------------------
if [[ "${EUID}" -ne 0 ]]; then
  echo "[✖] Ejecuta como root (sudo)." >&2
  echo "    → Solución: sudo bash preflight-check.sh" >&2
  exit 1
fi

# ----------------------------------------------------------
# Log de cambios:
# - Si existe, lo borra (como pediste)
# - Luego lo crea de nuevo y valida que existe
# ----------------------------------------------------------
LOG_CHANGES="/var/tmp/preflight-changes.log"

if [[ -e "$LOG_CHANGES" ]]; then
  # Comando pedido (con fallback por si sudo no está disponible en el entorno)
  sudo rm -f /var/tmp/preflight-changes.log 2>/dev/null || rm -f /var/tmp/preflight-changes.log
fi

: > "$LOG_CHANGES" 2>/dev/null || {
  echo "[✖] No se pudo crear el log de cambios en $LOG_CHANGES" >&2
  echo "    → Solución: sudo rm -f /var/tmp/preflight-changes.log && sudo chown root:root /var/tmp && sudo chmod 1777 /var/tmp" >&2
  exit 1
}

if [[ ! -f "$LOG_CHANGES" ]]; then
  echo "[✖] El log de cambios no se ha creado correctamente: $LOG_CHANGES" >&2
  echo "    → Solución: revisa permisos de /var/tmp (debe ser 1777) y vuelve a ejecutar." >&2
  exit 1
fi

if [[ "$NO_COLOR" -eq 1 ]]; then
  C_GRN=""; C_YEL=""; C_RED=""; C_BLU=""; C_RST=""
else
  C_GRN=$'\e[32m'; C_YEL=$'\e[33m'; C_RED=$'\e[31m'; C_BLU=$'\e[34m'; C_RST=$'\e[0m'
fi

OK=0; WARN=0; FAIL=0
ok()    { ((++OK));   echo "${C_GRN}[✔]${C_RST} $*"; }
warn()  { ((++WARN)); echo "${C_YEL}[!]${C_RST} $*"; }
fail()  { ((++FAIL)); echo "${C_RED}[✖]${C_RST} $*"; }
info()  { echo "${C_BLU}[*]${C_RST} $*"; }
hint()  { echo "    ${C_BLU}→${C_RST} $*"; }

ask_yes_no() {
  local prompt="$1"
  if [[ "$ASSUME_YES" -eq 1 ]]; then
    return 0
  fi
  read -r -p "$prompt [S/N]: " opt
  [[ "$opt" =~ ^[sS]$ ]]
}

add_revert_cmd() { echo "$*" >> "$LOG_CHANGES"; }
need_cmd() { command -v "$1" >/dev/null 2>&1; }

in_list() {
  local needle="$1"; shift
  local x
  for x in "$@"; do
    [[ "$x" == "$needle" ]] && return 0
  done
  return 1
}

installer_installs() { in_list "$1" "${INSTALLER_INSTALLS[@]}"; }

# Missing command:
# - Si el instalador lo instalará => WARN (y digo cómo instalarlo ya si quieres)
# - Si NO lo instalará => FAIL (y digo cómo instalarlo)
missing_cmd() {
  local cmd="$1" pkg="$2" why="$3"
  if installer_installs "$cmd"; then
    warn "Falta '${cmd}' (${why}) — tu instalador lo instalará."
    hint "Si quieres arreglarlo YA: sudo apt-get update && sudo apt-get install -y ${pkg}"
  else
    fail "Falta '${cmd}' (${why}) — sin esto NO va a funcionar."
    hint "Solución: sudo apt-get update && sudo apt-get install -y ${pkg}"
  fi
}

echo "============================================================"
echo " NICS | CyberLab — Preflight Check (OpenStack / Kolla)"
echo "============================================================"
info "Modo: fix=${DO_FIX} | yes=${ASSUME_YES} | color=$((1-NO_COLOR))"
info "Reversión: $LOG_CHANGES"
info "Instalador instala (INSTALLER_INSTALLS_CSV): ${INSTALLER_INSTALLS_CSV:-<vacío>}"
echo

# ----------------------------
# Root (ya validado arriba)
# ----------------------------
ok "Ejecución como root."

# ----------------------------
# OS (REQUERIDO: Ubuntu 24.x)
# ----------------------------
if [[ -r /etc/os-release ]]; then
  . /etc/os-release
  info "SO: ${PRETTY_NAME:-unknown}"

  # Acepta Ubuntu 24.x (VERSION_ID suele ser 24.04 aunque PRETTY_NAME ponga 24.04.1 LTS)
  if [[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" =~ ^24(\.|$) ]]; then
    ok "SO compatible: Ubuntu ${VERSION_ID} (requerido Ubuntu 24.x)."
  else
    fail "SO NO compatible para este laboratorio. Requerido: Ubuntu 24.x"
    hint "Detectado: ${PRETTY_NAME:-ID=${ID:-unknown} VERSION_ID=${VERSION_ID:-unknown}}"
    hint "Solución: usa una VM con Ubuntu 24.04 LTS (recomendado) y vuelve a ejecutar el preflight."
    exit 2
  fi
else
  fail "No se pudo leer /etc/os-release."
  hint "Solución: asegúrate de estar en un Linux estándar (no initramfs/imagen recortada)."
  exit 2
fi

# ----------------------------
# Comandos base para que el propio preflight funcione
# ----------------------------
need_cmd ss    || missing_cmd "ss" "iproute2" "necesario para comprobar puertos/servicios"
need_cmd ping  || missing_cmd "ping" "iputils-ping" "necesario para comprobar conectividad"
need_cmd getent || missing_cmd "getent" "libc-bin" "necesario para comprobar DNS"

# ----------------------------
# UTF-8 / Locale (recomendado)
# ----------------------------
UTF_OK=0
CHARMAP="$(locale charmap 2>/dev/null || true)"
LANG_NOW="$(locale | awk -F= '/^LANG=/{print $2}' | tr -d '"')"

if [[ "$CHARMAP" == "UTF-8" ]]; then
  ok "Locale/charset OK: $(locale charmap) (LANG=${LANG_NOW:-N/A})"
  UTF_OK=1
else
  warn "Tu charset actual NO es UTF-8 (locale charmap -> ${CHARMAP:-N/A})."
  hint "Solución Ubuntu/Debian: sudo locale-gen es_ES.UTF-8 && sudo update-locale LANG=es_ES.UTF-8"
  hint "Luego: cierra sesión y vuelve a entrar (o abre una shell nueva)."
  if [[ "$DO_FIX" -eq 1 ]] && ask_yes_no "¿Configurar UTF-8 (es_ES.UTF-8) como LANG del sistema?"; then
    PREV_LANG="${LANG_NOW:-}"
    if need_cmd locale-gen; then locale-gen es_ES.UTF-8 >/dev/null 2>&1 || true; fi
    if need_cmd update-locale; then update-locale LANG=es_ES.UTF-8 >/dev/null 2>&1 || true; fi
    add_revert_cmd "update-locale LANG='${PREV_LANG}' >/dev/null 2>&1 || true"
    ok "Locale actualizado a es_ES.UTF-8 (re-login para aplicar al 100%)."
  fi
fi

# ----------------------------
# Virtualización (recomendado)
# ----------------------------
if grep -Eq '(vmx|svm)' /proc/cpuinfo 2>/dev/null; then
  ok "CPU soporta virtualización (vmx/svm)."
else
  warn "No detecto vmx/svm (virtualización HW)."
  hint "Si es una VM (VMware/VirtualBox/Proxmox): habilita VT-x/AMD-V y (si aplica) 'nested virtualization'."
fi

if [[ -e /dev/kvm ]]; then
  ok "/dev/kvm presente (KVM disponible)."
else
  warn "/dev/kvm no presente."
  hint "En VM: habilita virtualización anidada. En host: instala/activa KVM (paquetes qemu-kvm, libvirt, etc.)."
fi

# ----------------------------
# CPU / RAM / Disco (mínimos = FAIL)
# ----------------------------
CPU="$(nproc)"
if (( CPU >= REC_CPU )); then
  ok "CPU: ${CPU} vCPU (recomendado ≥ ${REC_CPU})."
elif (( CPU >= MIN_CPU )); then
  warn "CPU: ${CPU} vCPU (mínimo OK ≥ ${MIN_CPU}, recomendado ≥ ${REC_CPU})."
else
  fail "CPU: ${CPU} vCPU (insuficiente; mínimo ${MIN_CPU})."
  hint "Solución: asigna ≥ ${MIN_CPU} vCPU a la máquina (ideal ≥ ${REC_CPU})."
fi

RAM_GB="$(free -g | awk '/Mem:/ {print $2}')"
if (( RAM_GB >= REC_RAM_GB )); then
  ok "RAM: ${RAM_GB} GB (recomendado ≥ ${REC_RAM_GB})."
elif (( RAM_GB >= MIN_RAM_GB )); then
  warn "RAM: ${RAM_GB} GB (mínimo OK ≥ ${MIN_RAM_GB}, recomendado ≥ ${REC_RAM_GB})."
else
  fail "RAM: ${RAM_GB} GB (insuficiente; mínimo ${MIN_RAM_GB})."
  hint "Solución: asigna ≥ ${MIN_RAM_GB} GB RAM (ideal ≥ ${REC_RAM_GB})."
fi

DISK_GB="$(df -BG / | awk 'NR==2 {gsub("G","",$4); print $4}')"
if (( DISK_GB >= REC_DISK_GB )); then
  ok "Disco libre (/): ${DISK_GB} GB (recomendado ≥ ${REC_DISK_GB})."
elif (( DISK_GB >= MIN_DISK_GB )); then
  warn "Disco libre (/): ${DISK_GB} GB (mínimo OK ≥ ${MIN_DISK_GB}, recomendado ≥ ${REC_DISK_GB})."
else
  fail "Disco libre (/): ${DISK_GB} GB (insuficiente; mínimo ${MIN_DISK_GB})."
  hint "Solución: amplía disco o libera espacio hasta ≥ ${MIN_DISK_GB} GB (ideal ≥ ${REC_DISK_GB} GB)."
  hint "Tip rápido: sudo du -xh /var | sort -h | tail -n 20"
fi

# ----------------------------
# Red: DNS + Internet (DNS e Internet = FAIL)
# ----------------------------
if need_cmd getent; then
  if getent hosts one.one.one.one >/dev/null 2>&1; then
    ok "Resolver DNS funciona (getent hosts)."
  else
    fail "Problema de DNS (getent hosts falla) — sin DNS el despliegue suele romperse (apt, pulls, etc.)."
    hint "Solución (rápida): edita /etc/resolv.conf y deja por ejemplo:"
    hint "  nameserver 1.1.1.1"
    hint "  nameserver 8.8.8.8"
    hint "Luego (si aplica): sudo systemctl restart systemd-resolved || true"
    hint "Verifica: getent hosts google.com"
  fi
fi

if need_cmd ping; then
  if ping -c2 -W2 1.1.1.1 &>/dev/null; then
    ok "Conectividad IP a Internet OK (ping 1.1.1.1)."
  else
    fail "Sin conectividad IP a Internet (ping 1.1.1.1 falla)."
    hint "Solución: revisa gateway/NAT/enlace. Comandos útiles:"
    hint "  ip a"
    hint "  ip r"
    hint "  ping -c2 -W2 <TU_GATEWAY>"
    hint "En VM: verifica que la NIC esté conectada y que haya NAT/bridge real."
  fi

  if ping -c2 -W2 google.com &>/dev/null; then
    ok "Conectividad + DNS OK (ping google.com)."
  else
    warn "ping google.com falla (puede ser DNS o ICMP bloqueado)."
    hint "Solución: prueba DNS sin ICMP: getent hosts google.com"
    hint "Y prueba HTTP: curl -I https://google.com (si curl está)."
  fi
fi

# ----------------------------
# Hora / NTP (recomendado)
# ----------------------------
if need_cmd timedatectl; then
  if timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -qi yes; then
    ok "Reloj sincronizado (NTP)."
  else
    warn "Reloj NO sincronizado. Recomendado activar NTP."
    hint "Solución 1 (systemd): sudo timedatectl set-ntp true"
    hint "Solución 2 (chrony): sudo apt-get update && sudo apt-get install -y chrony && sudo systemctl enable --now chrony"
  fi
else
  warn "timedatectl no disponible."
  hint "Solución: instala systemd/timedatectl (en Ubuntu/Debian debería venir por defecto)."
fi

# ----------------------------
# unattended-upgrades / ufw (recomendaciones operativas)
# ----------------------------
if need_cmd systemctl; then
  if systemctl is-active --quiet unattended-upgrades; then
    warn "unattended-upgrades activo (puede interferir con apt durante despliegues)."
    hint "Solución: sudo systemctl stop unattended-upgrades && sudo systemctl disable unattended-upgrades"
    if [[ "$DO_FIX" -eq 1 ]] && ask_yes_no "¿Desactivar unattended-upgrades?"; then
      systemctl stop unattended-upgrades || true
      systemctl disable unattended-upgrades || true
      add_revert_cmd "systemctl enable unattended-upgrades || true"
      add_revert_cmd "systemctl start unattended-upgrades || true"
      ok "unattended-upgrades desactivado."
    fi
  else
    ok "unattended-upgrades inactivo."
  fi

  if systemctl is-active --quiet ufw; then
    warn "UFW activo (puede bloquear tráfico de OpenStack/OVS)."
    hint "Solución: sudo systemctl stop ufw && sudo systemctl disable ufw"
    if [[ "$DO_FIX" -eq 1 ]] && ask_yes_no "¿Desactivar UFW?"; then
      systemctl stop ufw || true
      systemctl disable ufw || true
      add_revert_cmd "systemctl enable ufw || true"
      add_revert_cmd "systemctl start ufw || true"
      ok "UFW desactivado."
    fi
  else
    ok "UFW inactivo."
  fi
else
  warn "systemctl no disponible (no puedo validar servicios)."
  hint "Si esto NO es un contenedor/entorno mínimo, revisa que systemd esté funcionando."
fi

# ----------------------------
# AppArmor (normal en Ubuntu; warn informativo)
# ----------------------------
if need_cmd systemctl && systemctl is-active --quiet apparmor; then
  warn "AppArmor activo (normal en Ubuntu)."
  hint "Si ves 'permission denied' en contenedores y quieres aislar causa (lab):"
  hint "  sudo systemctl stop apparmor && sudo systemctl disable apparmor"
  if [[ "$DO_FIX" -eq 1 ]] && ask_yes_no "¿Parar y deshabilitar AppArmor (solo lab/diagnóstico)?"; then
    systemctl stop apparmor || true
    systemctl disable apparmor || true
    add_revert_cmd "systemctl enable apparmor || true"
    add_revert_cmd "systemctl start apparmor || true"
    ok "AppArmor desactivado (diagnóstico)."
  fi
else
  ok "AppArmor inactivo o no detectado."
fi

# ----------------------------
# Módulos kernel requeridos (FAIL si faltan)
# ----------------------------
for mod in br_netfilter overlay; do
  if lsmod | awk '{print $1}' | grep -qx "$mod"; then
    ok "Módulo cargado: $mod"
  else
    fail "Módulo NO cargado: $mod (requerido para redes/containers)."
    hint "Solución: sudo modprobe $mod"
    hint "Persistencia: echo '$mod' | sudo tee /etc/modules-load.d/nics-cyberlab-${mod}.conf >/dev/null"
    if [[ "$DO_FIX" -eq 1 ]]; then
      modprobe "$mod" && ok "Cargado ahora: $mod" || fail "No pude cargar módulo: $mod"
      if [[ -d /etc/modules-load.d ]]; then
        echo "$mod" > "/etc/modules-load.d/nics-cyberlab-${mod}.conf"
        add_revert_cmd "rm -f /etc/modules-load.d/nics-cyberlab-${mod}.conf"
        ok "Persistencia de módulo en /etc/modules-load.d/."
      fi
    else
      hint "Auto-fix: vuelve a ejecutar con --fix"
    fi
  fi
done

# ----------------------------
# Sysctl requerido (FAIL si no cumple)
# ----------------------------
apply_sysctl_persist() {
  local key="$1" value="$2" required="$3"
  local current
  current="$(sysctl -n "$key" 2>/dev/null || echo "")"
  if [[ "$current" == "$value" ]]; then
    ok "sysctl $key=$value"
    return 0
  fi

  if [[ "$required" -eq 1 ]]; then
    fail "sysctl $key actual=${current:-N/A}, requerido=$value"
  else
    warn "sysctl $key actual=${current:-N/A}, recomendado=$value"
  fi

  hint "Solución: sudo sysctl -w ${key}=${value}"
  hint "Persistencia: crea/edita /etc/sysctl.d/99-nics-cyberlab.conf con '${key} = ${value}'"
  if [[ "$DO_FIX" -eq 1 ]]; then
    sysctl -w "$key=$value" >/dev/null
    ok "Aplicado: sysctl $key=$value"

    local f="/etc/sysctl.d/99-nics-cyberlab.conf"
    if [[ -f "$f" ]]; then
      if grep -qE "^\s*${key}\s*=" "$f"; then
        sed -i -E "s|^\s*${key}\s*=.*|${key} = ${value}|g" "$f"
      else
        echo "${key} = ${value}" >> "$f"
      fi
    else
      cat > "$f" <<EOF
# NICS | CyberLab sysctl
${key} = ${value}
EOF
      add_revert_cmd "rm -f $f"
    fi

    add_revert_cmd "sysctl -w ${key}=${current:-0} >/dev/null 2>&1 || true"
    ok "Persistencia: $f"
  else
    hint "Auto-fix: vuelve a ejecutar con --fix"
  fi
}

apply_sysctl_persist net.ipv4.ip_forward 1 1

BR_SYSCTL_FILE="/proc/sys/net/bridge/bridge-nf-call-iptables"
if [[ -e "$BR_SYSCTL_FILE" ]]; then
  apply_sysctl_persist net.bridge.bridge-nf-call-iptables 1 0
else
  warn "net.bridge.bridge-nf-call-iptables no disponible en /proc."
  hint "Si quieres forzarlo: asegúrate de tener br_netfilter cargado (modprobe br_netfilter)."
fi

# ----------------------------
# Docker (requerido para Kolla)
# ----------------------------
if need_cmd docker; then
  ok "Docker instalado: $(docker --version 2>/dev/null || echo 'ok')"
  if need_cmd systemctl; then
    if systemctl is-active --quiet docker; then
      ok "Servicio Docker activo."
    else
      if installer_installs docker; then
        warn "Servicio Docker NO activo — tu instalador lo debería activar."
      else
        fail "Servicio Docker NO activo — sin Docker corriendo, Kolla no funciona."
      fi
      hint "Solución: sudo systemctl enable --now docker"
      if [[ "$DO_FIX" -eq 1 ]]; then
        systemctl enable --now docker || true
        add_revert_cmd "systemctl disable docker || true"
        add_revert_cmd "systemctl stop docker || true"
        ok "Docker activado."
      else
        hint "Auto-fix: vuelve a ejecutar con --fix"
      fi
    fi
  else
    warn "No hay systemctl: no puedo comprobar/levantar el servicio Docker."
    hint "Si estás en un entorno sin systemd, asegúrate de arrancar dockerd manualmente."
  fi
else
  missing_cmd "docker" "docker.io" "Kolla necesita Docker"
  hint "Tras instalar: sudo systemctl enable --now docker"
  hint "Verifica: docker run --rm hello-world"
fi

# ----------------------------
# Dependencias básicas (requeridas para operar/instalar)
# ----------------------------
declare -A CMD_PKG=(
  [python3]="python3"
  [git]="git"
  [curl]="curl"
  [wget]="wget"
)

for c in python3 git curl wget; do
  if need_cmd "$c"; then
    ok "Dependencia OK: $c"
  else
    missing_cmd "$c" "${CMD_PKG[$c]}" "dependencia base"
  fi
done

if [[ -x "deploy/openstack_venv/bin/openstack" ]]; then
  ok "Detectado OpenStack CLI en venv (deploy/openstack_venv)."
else
  info "OpenStack CLI (venv) no detectado aún — normal si no has ejecutado cyberlab.sh."
fi

# ----------------------------
# Puertos críticos (host) — warn (posible conflicto)
# ----------------------------
info "Puertos relevantes ocupados en el host (si aparece algo, revísalo):"
if ss -tulpn 2>/dev/null | grep -Eq "$CRIT_PORTS_REGEX"; then
  ss -tulpn | grep -E "$CRIT_PORTS_REGEX" || true
  warn "Hay puertos relevantes ocupados. Puede ser normal o un conflicto."
  hint "Solución: identifica el proceso (PID/servicio) y para lo que estorbe:"
  hint "  sudo ss -tulpn | grep -E '$CRIT_PORTS_REGEX'"
  hint "  sudo systemctl stop <servicio>  (o)  sudo kill <PID>"
else
  ok "No se detectan puertos críticos ocupados (lista básica)."
fi

# ----------------------------
# Resumen
# ----------------------------
echo
echo "============================================================"
echo " Preflight terminado"
echo "------------------------------------------------------------"
echo " OK   : $OK"
echo " WARN : $WARN"
echo " FAIL : $FAIL"
echo "------------------------------------------------------------"
echo " Cambios realizados (si aplica): $LOG_CHANGES"
echo " Revertir cambios: sudo bash $LOG_CHANGES"
echo "============================================================"

if (( FAIL > 0 )); then
  exit 2
fi
exit 0
