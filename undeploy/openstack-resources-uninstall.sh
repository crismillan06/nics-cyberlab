#!/usr/bin/env bash
set -euo pipefail

# ======================================================
# Reverse uninstall of deploy/openstack-resources.sh
# - Removes OpenStack resources created by that script
# - Removes local artifacts under ./deploy/{img,keys,cloud-init}
# - Purges qemu-utils (best-effort) because install may have installed it
# - Works outside venv: locates an openstack CLI from common venv locations
# ======================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

DEPLOY_DIR="${PROJECT_ROOT}/deploy"

# Local artifacts created by install script
IMG_DIR="${DEPLOY_DIR}/img"
KEYS_DIR="${DEPLOY_DIR}/keys"
CLOUDINIT_DIR="${DEPLOY_DIR}/cloud-init"
PASS_FILE="${CLOUDINIT_DIR}/set-password.yml"

# OpenRC expected by install script
OPENRC_DEFAULT="${PROJECT_ROOT}/admin-openrc.sh"

# Resources created by install script (fixed names)
FLAVORS_CREATED=(T_1CPU_2GB S_2CPU_4GB M_4CPU_8GB L_6CPU_12GB)
IMAGES_CREATED=(ubuntu-22.04 debian-12 kali-linux)

NETWORK_EXT_NAME="net_external_01"
SUBNET_EXT_NAME="subnet_net_external_01"

NETWORK_PRIV="net_private_01"
SUBNET_PRIV="subnet_net_private_01"
ROUTER_PRIV="router_private_01"

SEC_GROUP="sg_basic"
KEYPAIR="my_key"

log(){ printf "[%s] %s\n" "$(date '+%F %T')" "$*"; }

# Best-effort runner: does not abort the whole script under set -e
run_best_effort() {
  set +e
  "$@"
  local rc=$?
  set -e
  if [[ $rc -ne 0 ]]; then
    log "WARN: command failed (rc=$rc): $*"
  fi
  return 0
}

# ------------------------------------------------------
# 0) Load OpenRC
# ------------------------------------------------------
FOUND_OPENRC=""
CANDIDATES=()

# allow override via env var OPENRC_PATH if desired
[[ -n "${OPENRC_PATH:-}" ]] && CANDIDATES+=("${OPENRC_PATH}")
CANDIDATES+=(
  "${OPENRC_DEFAULT}"
  "$(pwd)/admin-openrc.sh"
  "/etc/kolla/admin-openrc.sh"
)

for f in "${CANDIDATES[@]}"; do
  if [[ -n "${f}" && -f "${f}" ]]; then
    FOUND_OPENRC="${f}"
    break
  fi
done

if [[ -z "${FOUND_OPENRC}" ]]; then
  log "ERROR: admin-openrc.sh not found; cannot authenticate to OpenStack."
  log "Tried:"
  printf " - %s\n" "${CANDIDATES[@]}"
  exit 1
fi

log "Using OpenRC: ${FOUND_OPENRC}"
set +u
# shellcheck disable=SC1090
source "${FOUND_OPENRC}"
set -u

# ------------------------------------------------------
# 1) Locate openstack CLI (works outside venv)
# ------------------------------------------------------
OPENSTACK_BIN=""

if command -v openstack >/dev/null 2>&1; then
  OPENSTACK_BIN="$(command -v openstack)"
fi

if [[ -z "${OPENSTACK_BIN}" ]]; then
  VENV_CANDIDATES=(
    "${DEPLOY_DIR}/openstack_venv"
    "${PROJECT_ROOT}/openstack_venv"
    "${PROJECT_ROOT}/openstack-installer/openstack_venv"
  )
  for v in "${VENV_CANDIDATES[@]}"; do
    if [[ -x "${v}/bin/openstack" ]]; then
      OPENSTACK_BIN="${v}/bin/openstack"
      break
    fi
  done
fi

if [[ -z "${OPENSTACK_BIN}" ]]; then
  log "ERROR: 'openstack' CLI not found."
  log "Looked for: openstack in PATH, and these venvs:"
  log "  - ${DEPLOY_DIR}/openstack_venv/bin/openstack"
  log "  - ${PROJECT_ROOT}/openstack_venv/bin/openstack"
  log "  - ${PROJECT_ROOT}/openstack-installer/openstack_venv/bin/openstack"
  exit 1
fi

OS(){ "${OPENSTACK_BIN}" "$@"; }

log "Using OpenStack CLI: ${OPENSTACK_BIN}"

# ------------------------------------------------------
# Helpers to get IDs safely
# ------------------------------------------------------
get_id_by_show() {
  # usage: get_id_by_show <resource> <name>
  # returns empty if not found
  local rtype="$1" name="$2"
  OS "${rtype}" show "${name}" -f value -c id 2>/dev/null || true
}

# Ports that belong to a specific network
list_ports_on_network() {
  local net="$1"
  OS port list --network "${net}" -f value -c ID 2>/dev/null || true
}

# Ports that belong to a specific subnet (best-effort across client versions)
list_ports_on_subnet() {
  local subnet_id="$1"
  # Many openstackclient versions support: --fixed-ip subnet=<id>
  local out
  out="$(OS port list --fixed-ip "subnet=${subnet_id}" -f value -c ID 2>/dev/null || true)"
  if [[ -n "${out}" ]]; then
    printf "%s\n" "${out}"
    return 0
  fi
  # Fallback: parse "Fixed IP Addresses" column (best-effort)
  OS port list -f value -c ID -c "Fixed IP Addresses" 2>/dev/null | awk -v sid="${subnet_id}" '$0 ~ sid {print $1}' || true
}

# ------------------------------------------------------
# 2) Identify & delete instances that depend on this stack (best-effort, targeted)
# Criteria:
# - addresses contain net_private_01
# - OR security_groups contains sg_basic
# - OR key_name equals my_key
# ------------------------------------------------------
log "1) Deleting servers tied to this stack (net=${NETWORK_PRIV}, sg=${SEC_GROUP}, key=${KEYPAIR})..."

while read -r sid; do
  [[ -z "${sid:-}" ]] && continue

  addr="$(OS server show "${sid}" -f value -c addresses 2>/dev/null || true)"
  sgs="$(OS server show "${sid}" -f value -c security_groups 2>/dev/null || true)"
  key="$(OS server show "${sid}" -f value -c key_name 2>/dev/null || true)"
  name="$(OS server show "${sid}" -f value -c name 2>/dev/null || true)"

  if echo "${addr}" | grep -q "${NETWORK_PRIV}"; then
    match=1
  elif echo "${sgs}" | grep -q "${SEC_GROUP}"; then
    match=1
  elif [[ "${key}" == "${KEYPAIR}" ]]; then
    match=1
  else
    match=0
  fi

  if [[ "${match}" -eq 1 ]]; then
    log "  - Deleting server: ${name:-unknown} (${sid})"
    run_best_effort OS server delete "${sid}"
  fi
done < <(OS server list -f value -c ID 2>/dev/null || true)

# ------------------------------------------------------
# 3) Floating IPs associated to our ports (private network and external subnet)
# ------------------------------------------------------
log "2) Deleting floating IPs tied to this stack (best-effort)..."

PRIV_NET_ID="$(get_id_by_show network "${NETWORK_PRIV}")"
EXT_SUBNET_ID="$(get_id_by_show subnet "${SUBNET_EXT_NAME}")"

PORTS_TO_CLEAN=()

if [[ -n "${PRIV_NET_ID}" ]]; then
  while read -r pid; do
    [[ -n "${pid:-}" ]] && PORTS_TO_CLEAN+=("${pid}")
  done < <(list_ports_on_network "${NETWORK_PRIV}")
fi

if [[ -n "${EXT_SUBNET_ID}" ]]; then
  while read -r pid; do
    [[ -n "${pid:-}" ]] && PORTS_TO_CLEAN+=("${pid}")
  done < <(list_ports_on_subnet "${EXT_SUBNET_ID}")
fi

# Make port list unique
unique_ports() {
  printf "%s\n" "$@" | awk 'NF{seen[$0]=1} END{for (p in seen) print p}'
}

PORTS_TO_CLEAN_UNIQ="$(unique_ports "${PORTS_TO_CLEAN[@]:-}")"

# Delete floating IPs whose Port is in our port set
if [[ -n "${PORTS_TO_CLEAN_UNIQ}" ]]; then
  while read -r fid faddr fport; do
    [[ -z "${fid:-}" ]] && continue
    [[ -z "${fport:-}" ]] && continue
    if echo "${PORTS_TO_CLEAN_UNIQ}" | grep -qx "${fport}"; then
      log "  - Deleting floating IP: ${faddr} (${fid}) port=${fport}"
      run_best_effort OS floating ip delete "${fid}"
    fi
  done < <(OS floating ip list -f value -c ID -c "Floating IP Address" -c Port 2>/dev/null || true)
fi

# ------------------------------------------------------
# 4) Router / Networks / Subnets (reverse order)
# ------------------------------------------------------
log "3) Deleting router/networks/subnets created by install script (best-effort)..."

# Router: detach subnet + unset external gateway + delete
if OS router show "${ROUTER_PRIV}" >/dev/null 2>&1; then
  run_best_effort OS router remove subnet "${ROUTER_PRIV}" "${SUBNET_PRIV}"
  run_best_effort OS router unset "${ROUTER_PRIV}" --external-gateway
  run_best_effort OS router delete "${ROUTER_PRIV}"
fi

# Clean residual ports on private network (safe in context of uninstall)
if OS network show "${NETWORK_PRIV}" >/dev/null 2>&1; then
  log "  - Deleting residual ports on ${NETWORK_PRIV} (best-effort)..."
  while read -r pid; do
    [[ -z "${pid:-}" ]] && continue
    run_best_effort OS port delete "${pid}"
  done < <(list_ports_on_network "${NETWORK_PRIV}")
fi

# Delete private subnet/network
run_best_effort OS subnet delete "${SUBNET_PRIV}"
run_best_effort OS network delete "${NETWORK_PRIV}"

# External subnet: delete ports on that subnet only (to avoid wiping reused external nets)
if OS subnet show "${SUBNET_EXT_NAME}" >/dev/null 2>&1; then
  EXT_SUBNET_ID="$(get_id_by_show subnet "${SUBNET_EXT_NAME}")"
  if [[ -n "${EXT_SUBNET_ID}" ]]; then
    log "  - Deleting residual ports on subnet ${SUBNET_EXT_NAME} (best-effort)..."
    while read -r pid; do
      [[ -z "${pid:-}" ]] && continue
      run_best_effort OS port delete "${pid}"
    done < <(list_ports_on_subnet "${EXT_SUBNET_ID}")
  fi
fi

# Delete external subnet by fixed name (created by install script even when reusing ext net)
run_best_effort OS subnet delete "${SUBNET_EXT_NAME}"

# Delete external network ONLY if it is the one named net_external_01 (created by install script)
# (If install re-used another external net, we do NOT touch it.)
run_best_effort OS network delete "${NETWORK_EXT_NAME}"

# ------------------------------------------------------
# 5) Security group + Keypair
# ------------------------------------------------------
log "4) Deleting security group and keypair created by install script (best-effort)..."
run_best_effort OS security group delete "${SEC_GROUP}"
run_best_effort OS keypair delete "${KEYPAIR}"

# ------------------------------------------------------
# 6) Images
# ------------------------------------------------------
log "5) Deleting images created by install script (best-effort)..."
for img in "${IMAGES_CREATED[@]}"; do
  run_best_effort OS image delete "${img}"
done

# ------------------------------------------------------
# 7) Flavors
# ------------------------------------------------------
log "6) Deleting flavors created by install script (best-effort)..."
for flv in "${FLAVORS_CREATED[@]}"; do
  run_best_effort OS flavor delete "${flv}"
done

# ------------------------------------------------------
# 8) Local cleanup (deploy/img, deploy/keys, deploy/cloud-init)
# ------------------------------------------------------
log "7) Removing local artifacts created by install script..."

run_best_effort rm -f "${PASS_FILE}"

# Remove images/downloads/conversion artifacts
run_best_effort rm -f \
  "${IMG_DIR}/ubuntu-22.04.5-jammy.qcow2" \
  "${IMG_DIR}/debian-12-generic.qcow2" \
  "${IMG_DIR}/disk.raw" \
  "${IMG_DIR}/kali-linux-2025.2.qcow2" \
  "${IMG_DIR}/kali-linux-2025.2-cloud-genericcloud-amd64.tar.xz"

# If there are any other leftover artifacts in those dirs, remove them as well
if [[ -d "${IMG_DIR}" ]]; then
  run_best_effort rm -f "${IMG_DIR}"/*
  run_best_effort rmdir "${IMG_DIR}"
fi

if [[ -d "${KEYS_DIR}" ]]; then
  run_best_effort rm -f "${KEYS_DIR}"/*
  run_best_effort rmdir "${KEYS_DIR}"
fi

if [[ -d "${CLOUDINIT_DIR}" ]]; then
  run_best_effort rm -f "${CLOUDINIT_DIR}"/*
  run_best_effort rmdir "${CLOUDINIT_DIR}"
fi

# ------------------------------------------------------
# 9) Purge qemu-utils (installed by install script if missing)
# ------------------------------------------------------
log "8) Purging qemu-utils (best-effort, uses sudo)..."
run_best_effort sudo apt-get purge -y qemu-utils
run_best_effort sudo apt-get autoremove -y

log "[✓] Reverse uninstall completed (best-effort)."
log "Verify with:"
log "  ${OPENSTACK_BIN} image list"
log "  ${OPENSTACK_BIN} flavor list"
log "  ${OPENSTACK_BIN} network list"
log "  ${OPENSTACK_BIN} subnet list"
log "  ${OPENSTACK_BIN} router list"
log "  ${OPENSTACK_BIN} security group list"
log "  ${OPENSTACK_BIN} keypair list"
