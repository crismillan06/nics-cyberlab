#!/bin/bash
# ============================================================
# Safe uninstall: OpenStack(Kolla) + Docker + venv + configs
# - Does NOT purge system python on Ubuntu 24.04
# - Removes Docker repo in BOTH formats: docker.list and docker.sources
# - Removes Docker keyrings: docker.gpg and docker.asc
# - Cleans /run/docker/netns mounts best-effort
# - NEW: stops/disables (and optionally masks) host libvirt sockets/services
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# venv suele vivir en deploy/ o openstack-installer/ según tu árbol
VENV_CANDIDATES=(
  "${PROJECT_ROOT}/openstack-installer/openstack_venv"
  "${PROJECT_ROOT}/deploy/openstack_venv"
)

INVENTORY="/etc/kolla/ansible/inventory/all-in-one"

MODE="safe"  # safe | purge-build-deps | no-apt
MASK_LIBVIRT=1  # por defecto, enmascara sockets para evitar socket-activation

while [[ $# -gt 0 ]]; do
  case "$1" in
    --safe) MODE="safe"; shift ;;
    --purge-build-deps) MODE="purge-build-deps"; shift ;;
    --no-apt) MODE="no-apt"; shift ;;
    --no-mask-libvirt) MASK_LIBVIRT=0; shift ;;
    *) shift ;;
  esac
done

log(){ printf "[%s] %s\n" "$(date '+%F %T')" "$*"; }

# Best-effort runner: never trips set -e
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
    log "Ejecuta como root: sudo $0 [--safe|--purge-build-deps|--no-apt] [--no-mask-libvirt]"
    exit 1
  fi
}

need_root

ORIG_USER="${SUDO_USER:-root}"
ORIG_HOME="$(getent passwd "${ORIG_USER}" | cut -d: -f6)"
COLL_BASE="${ORIG_HOME}/.ansible/collections/ansible_collections"

log "Mode: ${MODE}"

log "1) Activating venv (if present) to access kolla-ansible..."
FOUND_VENV=""
for v in "${VENV_CANDIDATES[@]}"; do
  if [[ -d "$v" ]]; then
    FOUND_VENV="$v"
    break
  fi
done

if [[ -n "${FOUND_VENV}" ]]; then
  # shellcheck disable=SC1090
  source "${FOUND_VENV}/bin/activate" || true
  export PATH="${FOUND_VENV}/bin:${PATH}"
else
  log "   - No venv found (ok)."
fi

log "2) kolla-ansible stop/destroy (if possible)..."
if command -v kolla-ansible >/dev/null 2>&1 && [[ -f "${INVENTORY}" ]]; then
  run_best_effort kolla-ansible -i "${INVENTORY}" stop
  run_best_effort kolla-ansible -i "${INVENTORY}" destroy --yes-i-really-really-mean-it
  run_best_effort kolla-ansible -i "${INVENTORY}" destroy
else
  log "   - kolla-ansible or inventory not found; skipping destroy."
fi

# ============================================================
# NEW: limpiar libvirt del host para que NO bloquee Kolla
# ============================================================
log "2.5) Stopping/disabling host libvirt (to avoid Kolla precheck failures)..."
LIBVIRT_UNITS=(libvirtd virtqemud virtlogd virtlockd)

for u in "${LIBVIRT_UNITS[@]}"; do
  run_best_effort systemctl stop "${u}.service" "${u}.socket"
  run_best_effort systemctl disable "${u}.service" "${u}.socket"
done

if [[ "${MASK_LIBVIRT}" -eq 1 ]]; then
  for u in "${LIBVIRT_UNITS[@]}"; do
    run_best_effort systemctl mask "${u}.service" "${u}.socket"
  done
fi

# Limpieza de sockets runtime (var/run suele ser symlink a /run)
run_best_effort rm -f /run/libvirt/libvirt-sock /run/libvirt/libvirt-sock-ro
run_best_effort rm -f /var/run/libvirt/libvirt-sock /var/run/libvirt/libvirt-sock-ro

log "3) Docker cleanup (containers/volumes/networks/images related to kolla)..."
if command -v docker >/dev/null 2>&1; then
  run_best_effort docker ps -aq --filter "label=kolla_version" | xargs -r docker rm -f
  run_best_effort docker ps -aq --filter "name=kolla"         | xargs -r docker rm -f

  run_best_effort docker volume ls -q --filter "name=kolla"   | xargs -r docker volume rm -f
  run_best_effort docker network ls -q --filter "name=kolla"  | xargs -r docker network rm

  run_best_effort docker image ls --format '{{.Repository}}:{{.Tag}}' | \
    awk '/(openstack\.kolla|\/kolla|^kolla)/{print $0}' | xargs -r docker image rm -f
else
  log "   - docker binary not found (ok)."
fi

log "4) Removing /etc/kolla..."
run_best_effort rm -rf /etc/kolla

log "5) Removing Ansible collections installed by the installer..."
run_best_effort rm -rf "${COLL_BASE}/openstack/cloud" \
                      "${COLL_BASE}/community/docker" \
                      "${COLL_BASE}/community/general" \
                      "${COLL_BASE}/ansible/posix"

MODPROBE_FILE="${COLL_BASE}/ansible/posix/plugins/modules/modprobe.py"
if [[ -f "${MODPROBE_FILE}" ]] && grep -q "cmd = \['modprobe'\]" "${MODPROBE_FILE}" 2>/dev/null; then
  run_best_effort rm -f "${MODPROBE_FILE}"
fi

log "6) Removing venv (if found)..."
if [[ -n "${FOUND_VENV}" ]]; then
  run_best_effort rm -rf "${FOUND_VENV}"
fi

log "7) Removing requirements.txt created by the installer (signature-based)..."
for f in \
  "${PROJECT_ROOT}/requirements.txt" \
  "${PROJECT_ROOT}/deploy/requirements.txt" \
  "${PROJECT_ROOT}/openstack-installer/requirements.txt" \
  "$(pwd)/requirements.txt" \
  "${ORIG_HOME}/requirements.txt"; do
  if [[ -f "$f" ]] && grep -q "kolla-ansible @ git+https://opendev.org/openstack/kolla-ansible@master" "$f" 2>/dev/null; then
    run_best_effort rm -f "$f"
  fi
done

log "8) Removing user from docker group (if present)..."
if getent group docker >/dev/null 2>&1; then
  run_best_effort gpasswd -d "${ORIG_USER}" docker
fi

log "9) Stopping/disabling Docker service..."
run_best_effort systemctl disable --now docker
run_best_effort systemctl disable --now containerd

if [[ "${MODE}" == "no-apt" ]]; then
  log "10) --no-apt: skipping apt changes."
  log "[✓] Completed (no-apt)."
  exit 0
fi

# PATCH: remove Docker repo in BOTH formats + BOTH key types
log "10) Removing Docker repo entries (docker.list/docker.sources) and keyrings (docker.gpg/docker.asc)..."
run_best_effort rm -f /etc/apt/sources.list.d/docker.list
run_best_effort rm -f /etc/apt/sources.list.d/docker.sources
run_best_effort rm -f /etc/apt/keyrings/docker.gpg
run_best_effort rm -f /etc/apt/keyrings/docker.asc

run_best_effort apt-get update -y

log "11) Purging Docker packages (and related extras)..."
run_best_effort apt-get purge -y \
  docker-ce docker-ce-cli containerd.io docker-compose-plugin \
  docker-buildx-plugin docker-ce-rootless-extras \
  slirp4netns libslirp0 pigz

run_best_effort apt-get autoremove -y

log "12) Removing Docker data directories (to leave host clean)..."
# Clean netns mounts to avoid "resource busy"
if [[ -d /run/docker/netns ]]; then
  for ns in /run/docker/netns/*; do
    [[ -e "$ns" ]] || continue
    run_best_effort umount -l "$ns"
  done
fi

run_best_effort rm -rf /etc/docker
run_best_effort rm -rf /var/lib/docker /var/lib/containerd
run_best_effort rm -rf /run/docker /run/containerd
run_best_effort rm -f /var/run/docker.sock

if [[ "${MODE}" == "purge-build-deps" ]]; then
  log "13) Purging build/devel deps installed for the lab (NOT system python)..."
  # Do NOT remove python3/python3.12 on Ubuntu 24.04
  run_best_effort apt-get purge -y \
    python3.12-dev \
    libffi-dev libssl-dev gcc \
    cmake pkg-config build-essential \
    libdbus-1-dev libglib2.0-dev \
    bridge-utils iptables
  run_best_effort apt-get autoremove -y
else
  log "13) Safe mode: keeping base tooling (python/git/build deps)."
fi

log "[✓] OpenStack/Kolla/Docker uninstall completed (mode=${MODE})."

if [[ "${MASK_LIBVIRT}" -eq 1 ]]; then
  log "NOTE: libvirt units were masked. To revert later:"
  log "  sudo systemctl unmask libvirtd.{service,socket} virtqemud.{service,socket} virtlogd.{service,socket} virtlockd.{service,socket}"
fi
