#!/bin/bash
set -euo pipefail

SERVICE_NAME="uplinkbridge.service"
SCRIPT_DST="/usr/local/sbin/setup-veth.sh"
SERVICE_DST="/etc/systemd/system/$SERVICE_NAME"

log(){ printf "[%s] %s\n" "$(date '+%F %T')" "$*"; }

run_best_effort(){
  set +e
  "$@"
  local rc=$?
  set -e
  if [[ $rc -ne 0 ]]; then
    log "WARN: command failed (rc=$rc): $*"
  fi
  return 0
}

need_root(){
  if [[ "${EUID}" -ne 0 ]]; then
    echo "[✖] Ejecuta este script como root"
    exit 1
  fi
}

default_iface(){
  local iface=""
  iface="$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}' || true)"
  [[ -n "${iface}" ]] && { echo "$iface"; return 0; }
  iface="$(ip route 2>/dev/null | awk '/default/ {print $5; exit}' || true)"
  echo "${iface}"
}

delete_iface(){
  local ifname="$1"
  if ip link show "$ifname" >/dev/null 2>&1; then
    run_best_effort ip link set "$ifname" down
    run_best_effort ip link del "$ifname"
  fi
}

get_ipv4_32_list(){
  local iface="$1"
  ip -4 addr show dev "$iface" scope global 2>/dev/null | awk '/inet / {print $2}' | grep '/32' || true
}

remove_ipv4_32_runtime(){
  local iface="$1"
  local ips32
  ips32="$(get_ipv4_32_list "$iface")"
  if [[ -z "${ips32}" ]]; then
    log "No hay IPs /32 en ${iface}."
    return 0
  fi

  log "Eliminando IPs /32 (runtime) en ${iface}:"
  while read -r cidr; do
    [[ -z "${cidr}" ]] && continue
    log "  - ip addr del ${cidr} dev ${iface}"
    run_best_effort ip addr del "${cidr}" dev "${iface}"
  done <<< "${ips32}"
}

remove_ipv4_32_persistence_netplan(){
  local stamp="$1"
  # Limpieza best-effort de /32 en netplan
  if compgen -G "/etc/netplan/*.yaml" >/dev/null; then
    for f in /etc/netplan/*.yaml; do
      [[ -f "$f" ]] || continue
      if grep -q "/32" "$f" 2>/dev/null; then
        cp -a "$f" "${f}.bak-${stamp}"
        # Elimina entradas /32 tanto si están en listas multilínea como en listas inline [a,b,c]
        run_best_effort sed -i -E '
          s/(, *[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/32)//g;
          s/([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/32, *)//g;
          /\/32/d
        ' "$f"
      fi
    done
    run_best_effort netplan generate
    run_best_effort netplan apply
  fi
}

remove_ipv4_32_persistence_nm(){
  local iface="$1"
  local stamp="$2"

  if ! command -v nmcli >/dev/null 2>&1; then
    return 0
  fi
  if ! systemctl is-active --quiet NetworkManager 2>/dev/null; then
    return 0
  fi

  local conn
  conn="$(nmcli -g GENERAL.CONNECTION dev show "$iface" 2>/dev/null || true)"
  [[ -z "${conn}" || "${conn}" == "--" ]] && return 0

  # Backups de perfiles NM
  if compgen -G "/etc/NetworkManager/system-connections/*.nmconnection" >/dev/null; then
    for f in /etc/NetworkManager/system-connections/*.nmconnection; do
      [[ -f "$f" ]] || continue
      if grep -q "/32" "$f" 2>/dev/null; then
        cp -a "$f" "${f}.bak-${stamp}"
      fi
    done
  fi

  local ips32
  ips32="$(get_ipv4_32_list "$iface")"
  if [[ -z "${ips32}" ]]; then
    # Aun así, si quedaron persistidas pero no activas, las quitamos del perfil
    ips32="$(nmcli -g ipv4.addresses con show "$conn" 2>/dev/null | tr ',' '\n' | grep '/32' || true)"
  fi

  if [[ -n "${ips32}" ]]; then
    log "Eliminando IPs /32 del perfil NetworkManager: ${conn}"
    while read -r cidr; do
      [[ -z "${cidr}" ]] && continue
      run_best_effort nmcli con mod "$conn" -ipv4.addresses "$cidr"
    done <<< "${ips32}"
    run_best_effort nmcli con reload
    # Reaplicar sin tumbar si es posible
    run_best_effort nmcli dev reapply "$iface"
    # Si no reapply, hacer down/up (puede cortar)
    run_best_effort nmcli con down "$conn"
    run_best_effort nmcli con up "$conn"
  fi
}

stop_keepalived(){
  # Keepalived puede dejar VIPs /32
  log "Parando keepalived si existe (best-effort)..."
  run_best_effort systemctl stop keepalived
  run_best_effort systemctl disable keepalived
  run_best_effort pkill -TERM -x keepalived
  run_best_effort pkill -KILL -x keepalived
}

ovs_is_installed(){
  dpkg -s openvswitch-switch >/dev/null 2>&1
}

ensure_ovs_tools(){
  if command -v ovs-vsctl >/dev/null 2>&1; then
    return 0
  fi
  log "No existe ovs-vsctl. Instalando openvswitch-switch temporalmente para borrar bridges..."
  run_best_effort apt-get update -y
  run_best_effort apt-get install -y openvswitch-switch openvswitch-common
}

start_ovs_if_possible(){
  # En Ubuntu puede existir openvswitch-switch o unidades separadas
  run_best_effort systemctl start openvswitch-switch
  run_best_effort systemctl start ovsdb-server
  run_best_effort systemctl start ovs-vswitchd

  # Si existe ovs-ctl, úsalo como fallback
  if [[ -x /usr/share/openvswitch/scripts/ovs-ctl ]]; then
    run_best_effort /usr/share/openvswitch/scripts/ovs-ctl start
  fi
}

stop_ovs_processes(){
  run_best_effort systemctl stop openvswitch-switch
  run_best_effort systemctl stop ovs-vswitchd
  run_best_effort systemctl stop ovsdb-server
  run_best_effort pkill -TERM -x ovs-vswitchd
  run_best_effort pkill -TERM -x ovsdb-server
  sleep 1
  run_best_effort pkill -KILL -x ovs-vswitchd
  run_best_effort pkill -KILL -x ovsdb-server
}

remove_ovs_bridges_hard(){
  log "Eliminando bridges OVS (hard): br-ex/br-int/br-tun + ovs-system..."

  # Intento determinista con ovs-vsctl si está disponible
  if command -v ovs-vsctl >/dev/null 2>&1; then
    run_best_effort ovs-vsctl --if-exists del-br br-ex
    run_best_effort ovs-vsctl --if-exists del-br br-int
    run_best_effort ovs-vsctl --if-exists del-br br-tun
  fi

  # Fallback por ip (a veces no basta, pero ayuda)
  delete_iface br-ex
  delete_iface br-int
  delete_iface br-tun

  # ovs-system normalmente se va cuando no hay datapath; se intenta
  delete_iface ovs-system

  # Limpieza de ficheros OVS
  run_best_effort rm -rf /run/openvswitch
  run_best_effort rm -rf /etc/openvswitch
  run_best_effort rm -rf /var/lib/openvswitch
}

unload_ovs_modules(){
  log "Intentando descargar módulos OVS..."
  if command -v modprobe >/dev/null 2>&1; then
    for m in vport_vxlan vport_geneve vport_gre vport_stt vport_lisp openvswitch; do
      run_best_effort modprobe -r "$m"
    done
  fi
}

purge_ovs_if_temp_installed(){
  local was_installed="$1"
  if [[ "$was_installed" -eq 0 ]]; then
    log "Purgando openvswitch (se instaló solo para limpiar)..."
    run_best_effort apt-get purge -y openvswitch-switch openvswitch-common
    run_best_effort apt-get autoremove -y
  fi
}

cleanup_uplinkbridge(){
  log "Eliminando servicio uplinkbridge + veth/bridge..."
  run_best_effort systemctl stop "$SERVICE_NAME"
  run_best_effort systemctl disable "$SERVICE_NAME"
  run_best_effort rm -f "$SERVICE_DST"
  run_best_effort systemctl daemon-reload

  run_best_effort ip link del veth0
  run_best_effort ip link del veth1
  run_best_effort ip link set uplinkbridge down
  delete_iface uplinkbridge
  run_best_effort brctl delbr uplinkbridge

  log "Restaurando iptables (solo reglas conocidas)..."
  run_best_effort iptables -t nat -D POSTROUTING -s 10.0.2.0/24 -j MASQUERADE
  run_best_effort iptables -t nat -D POSTROUTING -s 192.168.250.0/24 -j MASQUERADE
  run_best_effort iptables -D FORWARD -s 10.0.2.0/24 -j ACCEPT
  run_best_effort iptables -D FORWARD -s 192.168.250.0/24 -j ACCEPT

  log "Restaurando forwarding IPv4..."
  run_best_effort sysctl -w net.ipv4.conf.all.forwarding=0
  run_best_effort sed -i '/^net.ipv4.conf.all.forwarding=1/d' /etc/sysctl.conf
  run_best_effort sysctl -p

  run_best_effort rm -f "$SCRIPT_DST"
}

# ============================================================
# MAIN
# ============================================================
need_root

echo "=============================================="
echo " Limpieza HARD: uplinkbridge + OVS + VIPs /32 (host como antes)"
echo "=============================================="

STAMP="$(date +%Y%m%d-%H%M%S)"
IFACE="$(default_iface)"

cleanup_uplinkbridge

# 1) Quitar VIPs /32 (y evitar que vuelvan)
if [[ -n "${IFACE}" ]]; then
  stop_keepalived
  remove_ipv4_32_runtime "${IFACE}"

  # Si siguen, hay persistencia: netplan/NM
  if [[ -n "$(get_ipv4_32_list "${IFACE}")" ]]; then
    log "Persisten /32 tras borrado runtime; limpiando persistencia (netplan/NM)..."
    remove_ipv4_32_persistence_netplan "${STAMP}"
    remove_ipv4_32_persistence_nm "${IFACE}" "${STAMP}"
    remove_ipv4_32_runtime "${IFACE}"
  fi
else
  log "No se detectó interfaz por defecto; no se limpian /32."
fi

# 2) Borrar OVS bridges de forma determinista
NEED_OVS=0
for br in ovs-system br-ex br-int br-tun; do
  if ip link show "$br" >/dev/null 2>&1; then
    NEED_OVS=1
    break
  fi
done

if [[ "$NEED_OVS" -eq 1 ]]; then
  WAS_OVS_INSTALLED=0
  if ovs_is_installed; then WAS_OVS_INSTALLED=1; fi

  ensure_ovs_tools
  start_ovs_if_possible
  remove_ovs_bridges_hard
  stop_ovs_processes
  unload_ovs_modules
  # Reintento final tras unload
  remove_ovs_bridges_hard
  purge_ovs_if_temp_installed "$WAS_OVS_INSTALLED"
fi

# 3) Informe final
log "Estado final: interfaces residuales objetivo (si quedan):"
run_best_effort sh -c "ip -o link show | awk -F': ' '{print \$2}' | cut -d'@' -f1 | egrep '^(ovs-system|br-ex|br-int|br-tun)$' || true"

if [[ -n "${IFACE}" ]]; then
  log "IPs actuales en ${IFACE} (debería quedar sin /32):"
  run_best_effort ip -4 addr show dev "${IFACE}"
fi

if ip link show ovs-system >/dev/null 2>&1 || ip link show br-ex >/dev/null 2>&1 || ip link show br-int >/dev/null 2>&1 || ip link show br-tun >/dev/null 2>&1; then
  log "NOTA: si aún quedan, el kernel mantiene el datapath. En ese caso, un reinicio los elimina al 100%."
fi

echo "=============================================="
echo " ✔ Finalizado"
echo "=============================================="
