#!/usr/bin/env bash
set -euo pipefail

# ==========================================================
# purge-all-instances.sh
# Elimina TODAS las instancias (servers) del ámbito elegido.
# - Independiente: localiza openstack CLI (PATH / venvs típicos)
# - Carga OpenRC de rutas comunes
# - Borra FIPs asociados a los puertos de cada instancia
# - Borra instancias y espera a que desaparezcan
# - (Opcional por defecto) Borra snapshots y volúmenes asociados (best-effort)
#
# USO:
#   bash purge-all-instances.sh --force [--all-projects] [--no-purge-volumes] [--purge-orphan-fips]
# ==========================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

OPENRC_DEFAULT="${BASE_DIR}/admin-openrc.sh"

FORCE=0
ALL_PROJECTS=0
PURGE_VOLUMES=1
PURGE_ORPHAN_FIPS=0

usage() {
  cat <<EOF
Usage:
  bash $0 --force [options]

Options:
  --force               REQUIRED. Ejecuta la purga masiva (sin prompts).
  --all-projects         Borra instancias en TODOS los proyectos (admin). MUY PELIGROSO.
  --no-purge-volumes      No borrar snapshots/volúmenes asociados (solo borra instancias y FIPs).
  --purge-orphan-fips     Borra también Floating IPs huérfanas (Port=None).
  -h, --help              Muestra esta ayuda.

Notas:
- Este script es destructivo. Con --all-projects puede arrasar el cloud.
- Requiere credenciales válidas (OpenRC) y openstack CLI.
EOF
}

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

die(){ log "ERROR: $*"; exit 1; }

# ----------------------------------------------------------
# Parse args
# ----------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --force) FORCE=1; shift ;;
    --all-projects) ALL_PROJECTS=1; shift ;;
    --no-purge-volumes) PURGE_VOLUMES=0; shift ;;
    --purge-orphan-fips) PURGE_ORPHAN_FIPS=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) log "WARN: ignoring unknown option: $1"; shift ;;
  esac
done

[[ "${FORCE}" -eq 1 ]] || { usage; exit 2; }

# ----------------------------------------------------------
# 1) Load OpenRC
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

[[ -n "${FOUND_OPENRC}" ]] || die "admin-openrc.sh no encontrado. Probados: ${CANDIDATES[*]}"

log "Using OpenRC: ${FOUND_OPENRC}"
set +u
# shellcheck disable=SC1090
source "${FOUND_OPENRC}"
set -u

# ----------------------------------------------------------
# 2) Locate openstack CLI (outside venv compatible)
# ----------------------------------------------------------
OPENSTACK_BIN=""

if command -v openstack >/dev/null 2>&1; then
  OPENSTACK_BIN="$(command -v openstack)"
else
  VENV_CANDIDATES=(
    "${BASE_DIR}/deploy/openstack_venv"
    "${BASE_DIR}/openstack_venv"
    "${BASE_DIR}/openstack-installer/openstack_venv"
    "${BASE_DIR}/deploy/openstack_venv"  # redundante a propósito
  )
  for v in "${VENV_CANDIDATES[@]}"; do
    if [[ -x "${v}/bin/openstack" ]]; then
      OPENSTACK_BIN="${v}/bin/openstack"
      break
    fi
  done
fi

# Si no hay CLI, intentamos instalar (best-effort) para que sea "independiente"
if [[ -z "${OPENSTACK_BIN}" ]]; then
  if command -v apt-get >/dev/null 2>&1; then
    log "OpenStack CLI no encontrado. Intentando instalar python3-openstackclient (requiere sudo)..."
    run_best_effort sudo apt-get update -y
    run_best_effort sudo apt-get install -y python3-openstackclient
    if command -v openstack >/dev/null 2>&1; then
      OPENSTACK_BIN="$(command -v openstack)"
    fi
  fi
fi

[[ -n "${OPENSTACK_BIN}" ]] || die "'openstack' CLI no disponible (PATH/venv/apt)."

OS(){ "${OPENSTACK_BIN}" "$@"; }
log "Using OpenStack CLI: ${OPENSTACK_BIN}"

SCOPE_DESC="$([[ "${ALL_PROJECTS}" -eq 1 ]] && echo "ALL_PROJECTS" || echo "CURRENT_PROJECT")"
log "Scope: ${SCOPE_DESC}"

# ----------------------------------------------------------
# Helpers
# ----------------------------------------------------------
server_list_cmd() {
  if [[ "${ALL_PROJECTS}" -eq 1 ]]; then
    OS server list --all-projects -f value -c ID -c Name 2>/dev/null || true
  else
    OS server list -f value -c ID -c Name 2>/dev/null || true
  fi
}

volume_list_cmd() {
  if [[ "${ALL_PROJECTS}" -eq 1 ]]; then
    OS volume list --all-projects -f value -c ID -c Name -c Status -c Attachments 2>/dev/null || true
  else
    OS volume list -f value -c ID -c Name -c Status -c Attachments 2>/dev/null || true
  fi
}

snapshot_list_cmd() {
  if [[ "${ALL_PROJECTS}" -eq 1 ]]; then
    OS volume snapshot list --all-projects -f value -c ID -c Name -c Status -c Volume 2>/dev/null || true
  else
    OS volume snapshot list -f value -c ID -c Name -c Status -c Volume 2>/dev/null || true
  fi
}

wait_gone_server() {
  local sid="$1"
  for _ in $(seq 1 90); do
    if ! OS server show "${sid}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 3
  done
  log "WARN: server ${sid} sigue existiendo tras esperar."
  return 0
}

ports_for_server() {
  local sid="$1"
  OS port list --device-id "${sid}" -f value -c ID 2>/dev/null || true
}

fip_list_cmd() {
  # ID, Floating IP, Port
  if [[ "${ALL_PROJECTS}" -eq 1 ]]; then
    OS floating ip list --all-projects -f value -c ID -c "Floating IP Address" -c Port 2>/dev/null || true
  else
    OS floating ip list -f value -c ID -c "Floating IP Address" -c Port 2>/dev/null || true
  fi
}

# ----------------------------------------------------------
# 3) Build server set
# ----------------------------------------------------------
mapfile -t SERVERS < <(server_list_cmd)

if [[ "${#SERVERS[@]}" -eq 0 ]]; then
  log "No hay instancias que borrar en el ámbito ${SCOPE_DESC}."
  if [[ "${PURGE_ORPHAN_FIPS}" -eq 1 ]]; then
    log "Purga de orphan FIPs solicitada; continuando..."
  else
    exit 0
  fi
fi

log "Encontradas ${#SERVERS[@]} instancias en ${SCOPE_DESC}."

# ----------------------------------------------------------
# 4) Delete Floating IPs attached to servers (by port match)
# ----------------------------------------------------------
log "1) Eliminando Floating IPs asociadas a instancias (best-effort)..."

# Cache FIPs once (may change, but good enough)
FIPS_RAW="$(fip_list_cmd)"
# For speed, store in a temp file
TMP_FIPS="$(mktemp)"
printf "%s\n" "${FIPS_RAW}" > "${TMP_FIPS}"

# Also collect server IDs for later volume cleanup
TMP_SERVER_IDS="$(mktemp)"

while read -r sid sname; do
  [[ -z "${sid:-}" ]] && continue
  printf "%s\n" "${sid}" >> "${TMP_SERVER_IDS}"

  ports="$(ports_for_server "${sid}")"
  [[ -n "${ports}" ]] || continue

  while read -r pid; do
    [[ -z "${pid:-}" ]] && continue
    # Match lines where port column equals pid
    while read -r fid faddr fport; do
      [[ -z "${fid:-}" ]] && continue
      [[ -z "${fport:-}" ]] && continue
      if [[ "${fport}" == "${pid}" ]]; then
        log "  - Deleting FIP ${faddr} (${fid}) [server=${sname} port=${pid}]"
        run_best_effort ssh-keygen -f "$HOME/.ssh/known_hosts" -R "${faddr}" >/dev/null 2>&1
        run_best_effort OS floating ip delete "${fid}"
      fi
    done < <(awk -v p="${pid}" '$3==p {print $0}' "${TMP_FIPS}" 2>/dev/null || true)
  done <<< "${ports}"

done <<< "$(printf "%s\n" "${SERVERS[@]}")"

# Orphan FIPs (Port=None) if requested
if [[ "${PURGE_ORPHAN_FIPS}" -eq 1 ]]; then
  log "1b) Eliminando Floating IPs huérfanas (Port=None) (best-effort)..."
  while read -r fid faddr fport; do
    [[ -z "${fid:-}" ]] && continue
    if [[ "${fport:-}" == "None" || -z "${fport:-}" ]]; then
      log "  - Deleting orphan FIP ${faddr} (${fid})"
      run_best_effort ssh-keygen -f "$HOME/.ssh/known_hosts" -R "${faddr}" >/dev/null 2>&1
      run_best_effort OS floating ip delete "${fid}"
    fi
  done < <(fip_list_cmd)
fi

# ----------------------------------------------------------
# 5) Delete all servers
# ----------------------------------------------------------
log "2) Eliminando TODAS las instancias (best-effort)..."

while read -r sid sname; do
  [[ -z "${sid:-}" ]] && continue
  log "  - Deleting server: ${sname} (${sid})"
  run_best_effort OS server delete "${sid}"
done <<< "$(printf "%s\n" "${SERVERS[@]}")"

log "2b) Esperando a que desaparezcan (best-effort)..."
while read -r sid; do
  [[ -z "${sid:-}" ]] && continue
  run_best_effort wait_gone_server "${sid}"
done < "${TMP_SERVER_IDS}"

# ----------------------------------------------------------
# 6) Purge volumes/snapshots associated to those servers (optional)
# ----------------------------------------------------------
if [[ "${PURGE_VOLUMES}" -eq 1 ]]; then
  log "3) Purga de snapshots/volúmenes asociados (best-effort)..."

  # Build a set of server IDs for matching in attachments
  SERVER_IDS_SET="$(awk 'NF{seen[$0]=1} END{for (k in seen) print k}' "${TMP_SERVER_IDS}")"

  # Map: volume_id -> server_id referenced in attachments
  # openstack volume list returns a field "Attachments" which usually contains server_id
  while read -r vid vname vstatus vattach; do
    [[ -z "${vid:-}" ]] && continue
    match=0
    while read -r sid; do
      [[ -z "${sid:-}" ]] && continue
      if echo "${vattach}" | grep -q "${sid}"; then
        match=1
        break
      fi
    done <<< "${SERVER_IDS_SET}"

    [[ "${match}" -eq 1 ]] || continue

    # Delete snapshots for this volume
    while read -r snid snname snstatus svol; do
      [[ -z "${snid:-}" ]] && continue
      if [[ "${svol:-}" == "${vid}" ]]; then
        log "  - Deleting snapshot: ${snname} (${snid}) volume=${vid}"
        run_best_effort OS volume snapshot delete "${snid}"
      fi
    done < <(snapshot_list_cmd)

    log "  - Deleting volume: ${vname} (${vid}) status=${vstatus}"
    run_best_effort OS volume delete "${vid}"

  done < <(volume_list_cmd)

else
  log "3) Skipping volume purge (--no-purge-volumes)."
fi

# ----------------------------------------------------------
# Cleanup temp files
# ----------------------------------------------------------
rm -f "${TMP_FIPS}" "${TMP_SERVER_IDS}" 2>/dev/null || true

log "[OK] Purga de instancias completada (best-effort)."
log "Verifica con:"
log "  ${OPENSTACK_BIN} server list $([[ ${ALL_PROJECTS} -eq 1 ]] && echo '--all-projects' || true)"
log "  ${OPENSTACK_BIN} floating ip list $([[ ${ALL_PROJECTS} -eq 1 ]] && echo '--all-projects' || true)"
if [[ "${PURGE_VOLUMES}" -eq 1 ]]; then
  log "  ${OPENSTACK_BIN} volume list $([[ ${ALL_PROJECTS} -eq 1 ]] && echo '--all-projects' || true)"
  log "  ${OPENSTACK_BIN} volume snapshot list $([[ ${ALL_PROJECTS} -eq 1 ]] && echo '--all-projects' || true)"
fi
