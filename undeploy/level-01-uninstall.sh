#!/usr/bin/env bash
set -euo pipefail

# ==========================================================
# Reverse uninstall for: lab/level-01.sh
# - Best-effort: does not abort on individual failures
# - Works outside venv: locates OpenStack CLI from common venvs/PATH
# - Removes what Level-01 touches:
#   * Runs component uninstall scripts if present (reverse order)
#   * Deletes servers: snort-server, wazuh-manager, caldera-server
#   * Deletes floating IPs attached to those servers
#   * Deletes attached volumes/snapshots (best-effort)
#   * Removes SG rule tcp/8888 from sg_basic with remote-ip == private CIDR (best-effort)
# ==========================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

INST_DIR="${BASE_DIR}/inst"
UNDEPLOY_DIR="${BASE_DIR}/undeploy"

OPENRC_DEFAULT="${BASE_DIR}/admin-openrc.sh"

# Servers referenced by level-01.sh
STACK_SERVERS=( "snort-server" "wazuh-manager" "caldera-server" )

# Resources referenced by level-01.sh
SEC_GROUP="sg_basic"
SUBNET_PRIVATE="subnet_net_private_01"
CALDERA_PORT="8888"

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

die(){
  log "ERROR: $*"
  exit 1
}

# ----------------------------------------------------------
# 0) Load OpenRC
# ----------------------------------------------------------
FOUND_OPENRC=""
CANDIDATES=()
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

[[ -n "${FOUND_OPENRC}" ]] || die "admin-openrc.sh not found. Tried: ${CANDIDATES[*]}"

log "Using OpenRC: ${FOUND_OPENRC}"
set +u
# shellcheck disable=SC1090
source "${FOUND_OPENRC}"
set -u

# ----------------------------------------------------------
# 1) Locate openstack CLI (outside venv compatible)
# ----------------------------------------------------------
OPENSTACK_BIN=""

if command -v openstack >/dev/null 2>&1; then
  OPENSTACK_BIN="$(command -v openstack)"
fi

if [[ -z "${OPENSTACK_BIN}" ]]; then
  VENV_CANDIDATES=(
    "${BASE_DIR}/deploy/openstack_venv"
    "${BASE_DIR}/openstack_venv"
    "${BASE_DIR}/openstack-installer/openstack_venv"
  )
  for v in "${VENV_CANDIDATES[@]}"; do
    if [[ -x "${v}/bin/openstack" ]]; then
      OPENSTACK_BIN="${v}/bin/openstack"
      break
    fi
  done
fi

[[ -n "${OPENSTACK_BIN}" ]] || die "'openstack' CLI not found in PATH or known venvs."

OS(){ "${OPENSTACK_BIN}" "$@"; }

log "Using OpenStack CLI: ${OPENSTACK_BIN}"

# ----------------------------------------------------------
# 2) Try to run component uninstall scripts (reverse order)
# ----------------------------------------------------------
# level-01 runs:
#   inst/op+snort.sh
#   inst/op+wazuh.sh
#   inst/op+caldera.sh
#   inst/op+snort-caldera.sh
#   inst/op+wazuh-snort.sh
#
# We'll attempt uninstall variants in reverse order.
INSTALL_SCRIPTS=(
  "${INST_DIR}/op+wazuh-snort.sh"
  "${INST_DIR}/op+snort-caldera.sh"
  "${INST_DIR}/op+caldera.sh"
  "${INST_DIR}/op+wazuh.sh"
  "${INST_DIR}/op+snort.sh"
)

find_uninstall_variant() {
  local install_path="$1"
  local base_name
  base_name="$(basename "${install_path}")"     # e.g., op+snort.sh
  local stem="${base_name%.sh}"                # e.g., op+snort

  local candidates=(
    "${INST_DIR}/${stem}_uninstall.sh"
    "${INST_DIR}/${stem}-uninstall.sh"
    "${UNDEPLOY_DIR}/${stem}_uninstall.sh"
    "${UNDEPLOY_DIR}/${stem}-uninstall.sh"
    "${UNDEPLOY_DIR}/${stem}.uninstall.sh"
  )

  local c
  for c in "${candidates[@]}"; do
    if [[ -f "${c}" ]]; then
      echo "${c}"
      return 0
    fi
  done

  return 1
}

log "0) Component uninstall phase (best-effort, reverse order)..."
for s in "${INSTALL_SCRIPTS[@]}"; do
  if u="$(find_uninstall_variant "${s}" 2>/dev/null || true)"; then
    if [[ -n "${u}" && -f "${u}" ]]; then
      log "  - Running: ${u}"
      run_best_effort bash -c "cd '${BASE_DIR}' && bash '${u}'"
    fi
  else
    log "  - No uninstall script found for: $(basename "${s}") (skipping)"
  fi
done

# ----------------------------------------------------------
# 3) Resolve private CIDR (needed to remove SG rule added by level-01)
# ----------------------------------------------------------
PRIVATE_CIDR=""
PRIVATE_CIDR="$(OS subnet show "${SUBNET_PRIVATE}" -f value -c cidr 2>/dev/null || true)"
if [[ -n "${PRIVATE_CIDR}" ]]; then
  log "Detected private CIDR from ${SUBNET_PRIVATE}: ${PRIVATE_CIDR}"
else
  log "WARN: Could not resolve CIDR from ${SUBNET_PRIVATE}. SG rule cleanup will be best-effort without CIDR match."
fi

# ----------------------------------------------------------
# Helpers: get server id, ports, floating IPs
# ----------------------------------------------------------
get_server_id() {
  local name="$1"
  OS server show "${name}" -f value -c id 2>/dev/null || true
}

list_ports_for_server() {
  local sid="$1"
  OS port list --device-id "${sid}" -f value -c ID 2>/dev/null || true
}

list_fips_all() {
  # ID, Floating IP Address, Port
  OS floating ip list -f value -c ID -c "Floating IP Address" -c Port 2>/dev/null || true
}

wait_server_gone() {
  local sid="$1"
  for _ in $(seq 1 90); do
    if ! OS server show "${sid}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 3
  done
  log "WARN: server ${sid} still present after waiting."
  return 0
}

# ----------------------------------------------------------
# 4) Delete floating IPs attached to our servers
# ----------------------------------------------------------
log "1) Deleting floating IPs attached to level servers (best-effort)..."

declare -a SERVER_IDS=()

for name in "${STACK_SERVERS[@]}"; do
  sid="$(get_server_id "${name}")"
  if [[ -z "${sid}" ]]; then
    log "  - Server not found: ${name} (skipping)"
    continue
  fi

  SERVER_IDS+=( "${sid}" )

  # Collect ports for that server
  ports="$(list_ports_for_server "${sid}")"
  if [[ -z "${ports}" ]]; then
    log "  - No ports found for server ${name} (${sid})"
    continue
  fi

  # For each port, delete any floating IPs associated
  while read -r pid; do
    [[ -z "${pid}" ]] && continue
    while read -r fid faddr fport; do
      [[ -z "${fid:-}" ]] && continue
      [[ -z "${fport:-}" ]] && continue
      if [[ "${fport}" == "${pid}" ]]; then
        log "    - Deleting floating IP: ${faddr} (${fid}) [port=${pid} server=${name}]"
        # Clean known_hosts entry best-effort (local)
        run_best_effort ssh-keygen -f "$HOME/.ssh/known_hosts" -R "${faddr}" >/dev/null 2>&1
        run_best_effort OS floating ip delete "${fid}"
      fi
    done < <(list_fips_all)
  done <<< "${ports}"
done

# ----------------------------------------------------------
# 5) Delete servers
# ----------------------------------------------------------
log "2) Deleting servers: ${STACK_SERVERS[*]} (best-effort)..."

for name in "${STACK_SERVERS[@]}"; do
  sid="$(get_server_id "${name}")"
  if [[ -z "${sid}" ]]; then
    log "  - Server not found: ${name} (skipping)"
    continue
  fi

  log "  - Deleting server: ${name} (${sid})"
  run_best_effort OS server delete "${sid}"
  run_best_effort wait_server_gone "${sid}"
done

# ----------------------------------------------------------
# 6) Delete volumes/snapshots attached to those servers (best-effort)
# ----------------------------------------------------------
log "3) Deleting snapshots/volumes attached to deleted servers (best-effort)..."

# If we didn't capture ids earlier (e.g., server vanished fast), still try by names
if [[ "${#SERVER_IDS[@]}" -eq 0 ]]; then
  for name in "${STACK_SERVERS[@]}"; do
    sid="$(get_server_id "${name}")"
    [[ -n "${sid}" ]] && SERVER_IDS+=( "${sid}" )
  done
fi

# Find volumes whose Attachments mention any server id
for sid in "${SERVER_IDS[@]}"; do
  [[ -z "${sid}" ]] && continue

  vol_ids="$(OS volume list -f value -c ID -c Attachments 2>/dev/null | awk -v s="${sid}" '$0 ~ s {print $1}' || true)"
  if [[ -z "${vol_ids}" ]]; then
    continue
  fi

  while read -r vid; do
    [[ -z "${vid}" ]] && continue

    # Delete snapshots for this volume (if any)
    snap_ids="$(OS volume snapshot list -f value -c ID -c Volume 2>/dev/null | awk -v v="${vid}" '$2==v {print $1}' || true)"
    if [[ -n "${snap_ids}" ]]; then
      while read -r snid; do
        [[ -z "${snid}" ]] && continue
        log "  - Deleting snapshot: ${snid} (volume=${vid})"
        run_best_effort OS volume snapshot delete "${snid}"
      done <<< "${snap_ids}"
    fi

    log "  - Deleting volume: ${vid} (was attached to server=${sid})"
    run_best_effort OS volume delete "${vid}"
  done <<< "${vol_ids}"
done

# ----------------------------------------------------------
# 7) Remove the extra SG rule created by level-01: tcp/8888 from PRIVATE_CIDR in sg_basic
# ----------------------------------------------------------
log "4) Removing SG rule added by level-01 (tcp/${CALDERA_PORT} from private CIDR) (best-effort)..."

if OS security group show "${SEC_GROUP}" >/dev/null 2>&1; then
  rules_json="$(OS security group rule list "${SEC_GROUP}" -f json 2>/dev/null || true)"
  if [[ -n "${rules_json}" ]]; then
    # Use python to robustly parse json and select matching rule IDs
    ids_to_delete="$(python3 - <<PY
import json, sys

raw = sys.stdin.read().strip()
if not raw:
    sys.exit(0)

try:
    data = json.loads(raw)
except Exception:
    sys.exit(0)

PORT = int("${CALDERA_PORT}")
CIDR = "${PRIVATE_CIDR}"

def get(d, *keys):
    for k in keys:
        if k in d and d[k] is not None:
            return d[k]
    return None

out = []
for r in data:
    proto = get(r, "IP Protocol", "Protocol", "protocol")
    direction = get(r, "Direction", "direction")
    remote = get(r, "Remote IP Prefix", "Remote IP", "remote_ip_prefix")
    prmin = get(r, "Port Range Min", "Port Range", "port_range_min")
    prmax = get(r, "Port Range Max", "port_range_max")

    # Normalize
    if isinstance(proto, str):
        proto_n = proto.strip().lower()
    else:
        proto_n = str(proto).strip().lower() if proto is not None else ""

    dir_n = str(direction).strip().lower() if direction is not None else ""

    # Port range may come as "8888:8888"
    if isinstance(prmin, str) and ":" in prmin and prmax is None:
        try:
            a,b = prmin.split(":",1)
            prmin_i = int(a); prmax_i = int(b)
        except Exception:
            prmin_i = prmax_i = None
    else:
        try:
            prmin_i = int(prmin) if prmin is not None else None
        except Exception:
            prmin_i = None
        try:
            prmax_i = int(prmax) if prmax is not None else prmin_i
        except Exception:
            prmax_i = prmin_i

    # Match: ingress tcp 8888 and (if CIDR known) remote==CIDR
    if proto_n != "tcp":
        continue
    if dir_n and dir_n != "ingress":
        continue
    if prmin_i != PORT or prmax_i != PORT:
        continue
    if CIDR:
        if str(remote).strip() != CIDR:
            continue

    rid = get(r, "ID", "Id", "id")
    if rid:
        out.append(rid)

for rid in out:
    print(rid)
PY
<<< "${rules_json}")"

    if [[ -n "${ids_to_delete}" ]]; then
      while read -r rid; do
        [[ -z "${rid}" ]] && continue
        log "  - Deleting SG rule: ${rid} (sg=${SEC_GROUP})"
        run_best_effort OS security group rule delete "${rid}"
      done <<< "${ids_to_delete}"
    else
      log "  - No matching SG rules found to delete."
    fi
  else
    log "  - Could not retrieve SG rules as JSON; skipping SG rule deletion."
  fi
else
  log "  - Security group not found: ${SEC_GROUP} (skipping)"
fi

log "[OK] Level-01 reverse uninstall completed (best-effort)."
log "Verify:"
log "  ${OPENSTACK_BIN} server list"
log "  ${OPENSTACK_BIN} floating ip list"
log "  ${OPENSTACK_BIN} security group rule list ${SEC_GROUP}"
