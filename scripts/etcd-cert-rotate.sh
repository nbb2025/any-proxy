#!/usr/bin/env bash
# etcd-cert-rotate.sh
#
# Usage:
#   scripts/etcd-cert-rotate.sh \
#       --inventory configs/etcd-nodes.csv \
#       --ca-dir deploy/pki/ca \
#       --output-dir deploy/pki/out \
#       --client-out configs/etcd-client \
#       --restart-cmd "sudo systemctl restart etcd"
#
# Requirements:
#   - bash, openssl, scp, ssh
#   - inventory CSV columns: name,host,ssh_user,ssh_port,data_dir,alt_names
#     alt_names separated by semicolon (;) e.g. "10.0.0.1;etcd-1.local"
#
# Behaviour:
#   - ensures CA exists (creates if missing)
#   - generates new server cert/key for each node (backup kept with timestamp)
#   - optionally generates client certs (PEM bundle + key)
#   - uploads certs via scp, swaps atomically on remote, optional restart
#   - keeps timestamped archive under output directory

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

INVENTORY=""
CA_DIR="${ROOT_DIR}/deploy/pki/ca"
OUTPUT_DIR="${ROOT_DIR}/deploy/pki/out"
CLIENT_OUT=""
RESTART_CMD=""
TMP_REMOTE_DIR="/tmp/etcd-cert-rotate"
ROTATE_TS="$(date +%Y%m%d%H%M%S)"
START_PORT=22

usage() {
  cat <<'EOF'
Usage: etcd-cert-rotate.sh [options]

Options:
  --inventory PATH        CSV file listing etcd nodes (required)
  --ca-dir PATH           Directory to store CA material (default: deploy/pki/ca)
  --output-dir PATH       Directory to stage generated certs (default: deploy/pki/out)
  --client-out PATH       Directory to write client cert/key bundle (optional)
  --restart-cmd CMD       Remote command to restart etcd after deploy (optional)
  --tmp-remote DIR        Remote staging directory (default: /tmp/etcd-cert-rotate)
  --timestamp VALUE       Override rotation timestamp (default: current datetime)
  -h, --help              Show this message

Inventory CSV columns (header required):
  name,host,ssh_user,ssh_port,data_dir,alt_names
    - ssh_port optional (defaults to 22)
    - alt_names optional semicolon-delimited list of SAN entries (IPs/hosts)

Example:
  scripts/etcd-cert-rotate.sh --inventory configs/etcd-nodes.csv \
      --client-out configs/etcd-client \
      --restart-cmd "sudo systemctl restart etcd"
EOF
}

log() {
  printf '[%s] %s\n' "$(date +'%Y-%m-%d %H:%M:%S')" "$*" >&2
}

fatal() {
  log "ERROR: $*"
  exit 1
}

ensure_dir() {
  local dir="$1"
  mkdir -p "${dir}"
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --inventory)
        INVENTORY="$2"; shift 2;;
      --ca-dir)
        CA_DIR="$2"; shift 2;;
      --output-dir)
        OUTPUT_DIR="$2"; shift 2;;
      --client-out)
        CLIENT_OUT="$2"; shift 2;;
      --restart-cmd)
        RESTART_CMD="$2"; shift 2;;
      --tmp-remote)
        TMP_REMOTE_DIR="$2"; shift 2;;
      --timestamp)
        ROTATE_TS="$2"; shift 2;;
      -h|--help)
        usage; exit 0;;
      *)
        fatal "Unknown argument: $1";;
    esac
  done

  [[ -z "${INVENTORY}" ]] && fatal "--inventory is required"
  [[ -f "${INVENTORY}" ]] || fatal "Inventory ${INVENTORY} not found"
  ensure_dir "${CA_DIR}"
  ensure_dir "${OUTPUT_DIR}"
  if [[ -n "${CLIENT_OUT}" ]]; then
    ensure_dir "${CLIENT_OUT}"
  fi
}

ensure_ca() {
  local ca_key="${CA_DIR}/ca.key"
  local ca_crt="${CA_DIR}/ca.crt"
  if [[ -f "${ca_key}" && -f "${ca_crt}" ]]; then
    log "Found existing CA at ${CA_DIR}"
    return
  fi
  log "Generating new CA in ${CA_DIR}"
  openssl genrsa -out "${ca_key}" 4096
  openssl req -x509 -new -nodes -key "${ca_key}" \
    -sha256 -days 1825 \
    -subj "/CN=any-proxy-etcd-ca" \
    -out "${ca_crt}"
}

build_san_block() {
  local host="$1"
  local altnames="$2"
  local san_list=()

  if [[ -n "${host}" ]]; then
    san_list+=("DNS:${host}")
  fi

  IFS=';' read -ra extras <<< "${altnames}"
  for entry in "${extras[@]}"; do
    entry="$(echo "${entry}" | xargs)"
    [[ -z "${entry}" ]] && continue
    if [[ "${entry}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      san_list+=("IP:${entry}")
    else
      san_list+=("DNS:${entry}")
    fi
  done

  if [[ ${#san_list[@]} -eq 0 ]]; then
    san_list=("DNS:${host}")
  fi

  printf '%s' "$(IFS=,; echo "${san_list[*]}")"
}

generate_server_cert() {
  local name="$1"
  local host="$2"
  local san="$3"
  local out_dir="${OUTPUT_DIR}/${ROTATE_TS}/${name}"

  ensure_dir "${out_dir}"

  local csr_conf="${out_dir}/csr.cnf"
  cat > "${csr_conf}" <<EOF
[ req ]
default_bits       = 4096
distinguished_name = req_distinguished_name
req_extensions     = v3_req
prompt             = no

[ req_distinguished_name ]
CN = ${name}

[ v3_req ]
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = ${san}
EOF

  openssl genrsa -out "${out_dir}/server.key" 4096
  openssl req -new -key "${out_dir}/server.key" -out "${out_dir}/server.csr" \
    -config "${csr_conf}"
  openssl x509 -req -in "${out_dir}/server.csr" \
    -CA "${CA_DIR}/ca.crt" -CAkey "${CA_DIR}/ca.key" \
    -CAcreateserial \
    -out "${out_dir}/server.crt" \
    -days 825 -sha256 \
    -extensions v3_req -extfile "${csr_conf}"

  rm -f "${out_dir}/server.csr" "${csr_conf}"
  log "Generated server certificate for ${name}"
}

generate_client_bundle() {
  local client_dir="${CLIENT_OUT}/${ROTATE_TS}"
  ensure_dir "${client_dir}"
  local csr_conf="${client_dir}/client.cnf"
  cat > "${csr_conf}" <<EOF
[ req ]
default_bits       = 4096
distinguished_name = req_distinguished_name
req_extensions     = v3_req
prompt             = no

[ req_distinguished_name ]
CN = any-proxy-control-plane

[ v3_req ]
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

  openssl genrsa -out "${client_dir}/client.key" 4096
  openssl req -new -key "${client_dir}/client.key" -out "${client_dir}/client.csr" \
    -config "${csr_conf}"
  openssl x509 -req -in "${client_dir}/client.csr" \
    -CA "${CA_DIR}/ca.crt" -CAkey "${CA_DIR}/ca.key" \
    -CAcreateserial \
    -out "${client_dir}/client.crt" \
    -days 365 -sha256 \
    -extensions v3_req -extfile "${csr_conf}"

  rm -f "${client_dir}/client.csr" "${csr_conf}"
  cat "${client_dir}/client.crt" "${client_dir}/client.key" > "${client_dir}/client.pem"
  cp "${CA_DIR}/ca.crt" "${client_dir}/ca.crt"
  log "Generated client bundle at ${client_dir}"
}

deploy_to_node() {
  local name="$1"
  local host="$2"
  local user="$3"
  local port="$4"
  local data_dir="$5"
  local out_dir="${OUTPUT_DIR}/${ROTATE_TS}/${name}"

  [[ -d "${out_dir}" ]] || fatal "Missing output directory for ${name}"

  local scp_opts=(-P "${port}")
  local ssh_opts=(-p "${port}")
  local remote="${user}@${host}"

  log "Uploading new certs to ${name} (${host})"
  ssh "${ssh_opts[@]}" "${remote}" "sudo mkdir -p '${TMP_REMOTE_DIR}'"
  scp "${scp_opts[@]}" "${CA_DIR}/ca.crt" "${out_dir}/server.crt" "${out_dir}/server.key" "${remote}:${TMP_REMOTE_DIR}/"

  local remote_backup="${data_dir}/backup-${ROTATE_TS}"
  local remote_cmds="
set -e
sudo mkdir -p '${data_dir}'
if [ -f '${data_dir}/server.crt' ]; then
  sudo mkdir -p '${remote_backup}'
  sudo cp '${data_dir}/server.crt' '${remote_backup}/server.crt'
  sudo cp '${data_dir}/server.key' '${remote_backup}/server.key'
fi
sudo cp '${TMP_REMOTE_DIR}/server.crt' '${data_dir}/server.crt'
sudo cp '${TMP_REMOTE_DIR}/server.key' '${data_dir}/server.key'
sudo cp '${TMP_REMOTE_DIR}/ca.crt' '${data_dir}/ca.crt'
sudo chmod 600 '${data_dir}/server.key'
sudo rm -rf '${TMP_REMOTE_DIR}'
"
  if [[ -n "${RESTART_CMD}" ]]; then
    remote_cmds+="
${RESTART_CMD}
"
  fi

  ssh "${ssh_opts[@]}" "${remote}" "${remote_cmds}"
  log "Deployed certificates to ${name}"
}

process_inventory() {
  local header_processed=0
  while IFS=, read -r name host user port data_dir alt_names; do
    # Skip header
    if [[ ${header_processed} -eq 0 ]]; then
      header_processed=1
      continue
    fi
    name="$(echo "${name}" | xargs)"
    [[ -z "${name}" ]] && continue
    host="$(echo "${host}" | xargs)"
    user="$(echo "${user}" | xargs)"
    port="$(echo "${port}" | xargs)"
    data_dir="$(echo "${data_dir}" | xargs)"
    alt_names="$(echo "${alt_names}" | tr -d '\r')"

    [[ -z "${host}" || -z "${user}" || -z "${data_dir}" ]] && fatal "Incomplete inventory row for ${name}"
    [[ -z "${port}" ]] && port="${START_PORT}"

    local san="$(build_san_block "${host}" "${alt_names}")"
    generate_server_cert "${name}" "${host}" "${san}"
    deploy_to_node "${name}" "${host}" "${user}" "${port}" "${data_dir}"
  done < "${INVENTORY}"
}

main() {
  parse_args "$@"
  ensure_ca
  process_inventory
  if [[ -n "${CLIENT_OUT}" ]]; then
    generate_client_bundle
  fi
  log "Rotation completed. Artifacts stored under ${OUTPUT_DIR}/${ROTATE_TS}"
}

main "$@"
