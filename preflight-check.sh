#!/usr/bin/env bash
# ==========================================================
# NICS | CyberLab — Preflight Check (OpenStack / Kolla)
# ==========================================================
set -euo pipefail

LOG_CHANGES="/var/tmp/preflight-changes.log"
: > "$LOG_CHANGES"

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
EOF
      exit 0
      ;;
    *) echo "[X] Opción desconocida: $1" >&2; exit 1 ;;
  esac
done

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

echo "============================================================"
echo " NICS | CyberLab — Preflight Check (OpenStack / Kolla)"
echo "============================================================"
info "Modo: fix=${DO_FIX} | yes=${ASSUME_YES} | color=$((1-NO_COLOR))"
info "Reversión: $LOG_CHANGES"
echo

# ----------------------------
# Root
# ----------------------------
if [[ "${EUID}" -ne 0 ]]; then
  fail "Ejecuta como root (sudo)."
  exit 1
else
  ok "Ejecución como root."
fi

# ----------------------------
# OS
# ----------------------------
if [[ -r /etc/os-release ]]; then
  . /etc/os-release
  info "SO: ${PRETTY_NAME:-unknown}"
  case "${ID:-}" in
    ubuntu|debian) ok "SO compatible (${ID})." ;;
    *) warn "SO no validado para Kolla en este script (ID=${ID})." ;;
  esac
else
  fail "No se pudo leer /etc/os-release."
fi

# ----------------------------
# UTF-8 / Locale
# ----------------------------
UTF_OK=0
CHARMAP="$(locale charmap 2>/dev/null || true)"
LANG_NOW="$(locale | awk -F= '/^LANG=/{print $2}' | tr -d '"')"

if [[ "$CHARMAP" == "UTF-8" ]]; then
  ok "Locale/charset OK: $(locale charmap) (LANG=${LANG_NOW:-N/A})"
  UTF_OK=1
else
  warn "Tu charset actual NO es UTF-8 (locale charmap -> ${CHARMAP:-N/A})."
  info "Esto puede hacer que símbolos tipo [✔] o ⏱︎ se vean mal en terminal/logs."
  info "Fix típico Ubuntu: locale-gen es_ES.UTF-8 && update-locale LANG=es_ES.UTF-8"
  if [[ "$DO_FIX" -eq 1 ]] && ask_yes_no "¿Configurar UTF-8 (es_ES.UTF-8) como LANG del sistema?"; then
    PREV_LANG="${LANG_NOW:-}"
    # Generar locale si hace falta
    if need_cmd locale-gen; then
      locale-gen es_ES.UTF-8 >/dev/null 2>&1 || true
    fi
    if need_cmd update-locale; then
      update-locale LANG=es_ES.UTF-8 >/dev/null 2>&1 || true
    fi
    add_revert_cmd "update-locale LANG='${PREV_LANG}' >/dev/null 2>&1 || true"
    ok "Locale actualizado a es_ES.UTF-8 (re-login o nueva shell para aplicar al 100%)."
  fi
fi

# ----------------------------
# Virtualización (KVM)
# ----------------------------
if egrep -q '(vmx|svm)' /proc/cpuinfo 2>/dev/null; then
  ok "CPU soporta virtualización (vmx/svm)."
else
  warn "No detecto vmx/svm. En VMware, revisa 'nested virtualization' (AMD-V/VT-x)."
fi

if [[ -e /dev/kvm ]]; then
  ok "/dev/kvm presente (KVM disponible)."
else
  warn "/dev/kvm no presente. En VM, habilita virtualización anidada; en host, instala/activa KVM."
fi

# ----------------------------
# CPU / RAM / Disco
# ----------------------------
CPU="$(nproc)"
if (( CPU >= REC_CPU )); then ok "CPU: ${CPU} vCPU (recomendado ≥ ${REC_CPU})."
elif (( CPU >= MIN_CPU )); then warn "CPU: ${CPU} vCPU (mínimo OK ≥ ${MIN_CPU}, recomendado ≥ ${REC_CPU})."
else fail "CPU: ${CPU} vCPU (insuficiente; mínimo ${MIN_CPU})."; fi

RAM_GB="$(free -g | awk '/Mem:/ {print $2}')"
if (( RAM_GB >= REC_RAM_GB )); then ok "RAM: ${RAM_GB} GB (recomendado ≥ ${REC_RAM_GB})."
elif (( RAM_GB >= MIN_RAM_GB )); then warn "RAM: ${RAM_GB} GB (mínimo OK ≥ ${MIN_RAM_GB}, recomendado ≥ ${REC_RAM_GB})."
else fail "RAM: ${RAM_GB} GB (insuficiente; mínimo ${MIN_RAM_GB})."; fi

DISK_GB="$(df -BG / | awk 'NR==2 {gsub("G","",$4); print $4}')"
if (( DISK_GB >= REC_DISK_GB )); then ok "Disco libre (/): ${DISK_GB} GB (recomendado ≥ ${REC_DISK_GB})."
elif (( DISK_GB >= MIN_DISK_GB )); then warn "Disco libre (/): ${DISK_GB} GB (mínimo OK ≥ ${MIN_DISK_GB}, recomendado ≥ ${REC_DISK_GB})."
else fail "Disco libre (/): ${DISK_GB} GB (insuficiente; mínimo ${MIN_DISK_GB})."; fi

# ----------------------------
# Red: DNS + Internet
# ----------------------------
if getent hosts one.one.one.one >/dev/null 2>&1; then
  ok "Resolver DNS funciona (getent hosts)."
else
  warn "Posible problema de DNS (getent hosts falla). Revisa /etc/resolv.conf."
fi

if ping -c2 -W2 1.1.1.1 &>/dev/null; then
  ok "Conectividad IP a Internet OK (ping 1.1.1.1)."
else
  fail "Sin conectividad IP a Internet (ping 1.1.1.1 falla)."
fi

if ping -c2 -W2 google.com &>/dev/null; then
  ok "Conectividad + DNS OK (ping google.com)."
else
  warn "Conectividad DNS/ICMP puede fallar (ping google.com falla)."
fi

# ----------------------------
# Hora / NTP
# ----------------------------
if need_cmd timedatectl; then
  if timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -qi yes; then
    ok "Reloj sincronizado (NTP)."
  else
    warn "Reloj NO sincronizado. Recomendado activar NTP (chrony/systemd-timesyncd)."
  fi
else
  warn "timedatectl no disponible."
fi

# ----------------------------
# unattended-upgrades / ufw
# ----------------------------
if need_cmd systemctl; then
  if systemctl is-active --quiet unattended-upgrades; then
    warn "unattended-upgrades activo (puede interferir con apt durante despliegues)."
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
    info "En laboratorio suele desactivarse para evitar bloqueos de redes/bridges."
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
fi

# ----------------------------
# AppArmor (explicación + fix opcional)
# ----------------------------
if need_cmd systemctl && systemctl is-active --quiet apparmor; then
  warn "AppArmor activo (normal en Ubuntu)."
  info "¿Qué significa? Aplica perfiles MAC. Normalmente NO rompe Kolla, pero si ves 'permission denied' en contenedores, puede influir."
  info "Recomendación: déjalo activo salvo que estés depurando un fallo real."
  if [[ "$DO_FIX" -eq 1 ]] && ask_yes_no "¿Parar y deshabilitar AppArmor (solo para laboratorio/diagnóstico)?"; then
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
# Módulos kernel requeridos
# ----------------------------
for mod in br_netfilter overlay; do
  if lsmod | awk '{print $1}' | grep -qx "$mod"; then
    ok "Módulo cargado: $mod"
  else
    warn "Módulo NO cargado: $mod"
    if [[ "$DO_FIX" -eq 1 ]]; then
      modprobe "$mod" && ok "Cargado ahora: $mod" || fail "No pude cargar módulo: $mod"
      if [[ -d /etc/modules-load.d ]]; then
        echo "$mod" > "/etc/modules-load.d/nics-cyberlab-${mod}.conf"
        add_revert_cmd "rm -f /etc/modules-load.d/nics-cyberlab-${mod}.conf"
        ok "Persistencia de módulo en /etc/modules-load.d/."
      fi
    fi
  fi
done

# ----------------------------
# Sysctl requerido (y persistente)
# ----------------------------
apply_sysctl_persist() {
  local key="$1" value="$2"
  local current
  current="$(sysctl -n "$key" 2>/dev/null || echo "")"
  if [[ "$current" == "$value" ]]; then
    ok "sysctl $key=$value"
    return 0
  fi

  warn "sysctl $key actual=${current:-N/A}, recomendado=$value"
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
  fi
}

apply_sysctl_persist net.ipv4.ip_forward 1

# Bridge sysctl: comprobar existencia REAL (no solo sysctl -a)
BR_SYSCTL_FILE="/proc/sys/net/bridge/bridge-nf-call-iptables"
if [[ -e "$BR_SYSCTL_FILE" ]]; then
  # Si existe, entonces sysctl funciona
  apply_sysctl_persist net.bridge.bridge-nf-call-iptables 1
else
  warn "net.bridge.bridge-nf-call-iptables no disponible en /proc."
  info "Esto puede pasar por kernel/build o porque el subsistema bridge no expone esos sysctl."
  info "Si br_netfilter está cargado (lo está), normalmente NO bloquea el lab; solo afecta a filtrado iptables sobre bridges Linux."
fi

# ----------------------------
# Docker
# ----------------------------
if need_cmd docker; then
  ok "Docker instalado: $(docker --version 2>/dev/null || echo 'ok')"
  if need_cmd systemctl; then
    if systemctl is-active --quiet docker; then
      ok "Servicio Docker activo."
    else
      warn "Servicio Docker NO activo."
      if [[ "$DO_FIX" -eq 1 ]]; then
        systemctl enable --now docker || true
        add_revert_cmd "systemctl disable docker || true"
        add_revert_cmd "systemctl stop docker || true"
        ok "Docker activado."
      fi
    fi
  fi
else
  warn "Docker NO instalado (Kolla lo necesita). Paquete típico: docker.io"
fi

# ----------------------------
# Dependencias básicas
# ----------------------------
declare -a NEED_CMDS=(python3 git curl wget)
for c in "${NEED_CMDS[@]}"; do
  if need_cmd "$c"; then ok "Dependencia OK: $c"
  else warn "Dependencia faltante: $c"
  fi
done

if [[ -x "deploy/openstack_venv/bin/openstack" ]]; then
  ok "Detectado OpenStack CLI en venv (deploy/openstack_venv)."
else
  info "OpenStack CLI (venv) no detectado aún — normal si no has ejecutado cyberlab.sh."
fi

# ----------------------------
# Puertos críticos (host)
# ----------------------------
info "Puertos relevantes ocupados en el host (si aparece algo, revísalo):"
if ss -tulpn 2>/dev/null | egrep -q "$CRIT_PORTS_REGEX"; then
  ss -tulpn | egrep "$CRIT_PORTS_REGEX" || true
  warn "Hay puertos relevantes ocupados. Puede ser normal (p.ej. 80/443) o un conflicto."
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
