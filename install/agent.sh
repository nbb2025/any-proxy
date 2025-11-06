#!/usr/bin/env bash

set -euo pipefail

# Only Linux/amd64 environments are supported.
if [[ "$(uname -s)" != "Linux" ]] || [[ "$(uname -m)" != "x86_64" ]]; then
  echo "[anyproxy-install] only Linux amd64 is supported by this script" >&2
  exit 1
fi

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[anyproxy-install] missing dependency: $1" >&2
    exit 1
  fi
}

for bin in curl tar install systemctl jq; do
  require_cmd "$bin"
done

ensure_systemctl_service() {
  local service=$1
  if command -v systemctl >/dev/null 2>&1; then
    systemctl enable --now "$service" >/dev/null 2>&1 || true
  fi
}

install_openresty() {
  if command -v openresty >/dev/null 2>&1; then
    ensure_systemctl_service openresty
    return
  fi

  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y
    apt-get install -y curl gnupg ca-certificates lsb-release
    local release
    release=$(lsb_release -cs 2>/dev/null || (source /etc/os-release && echo "${UBUNTU_CODENAME:-${VERSION_CODENAME:-focal}}"))
    local distro
    distro=$(source /etc/os-release && echo "${ID:-ubuntu}")
    case "$distro" in
      ubuntu|debian) ;;
      *) distro="ubuntu" ;;
    esac
    local keyring="/usr/share/keyrings/openresty-archive-keyring.gpg"
    mkdir -p /usr/share/keyrings
    curl -fsSL https://openresty.org/package/pubkey.gpg | gpg --dearmor -o "$keyring"
    cat <<EOF >/etc/apt/sources.list.d/openresty.list
deb [signed-by=${keyring}] https://openresty.org/package/${distro} ${release} main
EOF
    apt-get update -y
    apt-get install -y openresty
  elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
    local pkgmgr
    if command -v dnf >/dev/null 2>&1; then
      pkgmgr="dnf"
    else
      pkgmgr="yum"
    fi
    if [[ ! -f /etc/yum.repos.d/openresty.repo ]]; then
      cat <<'EOF' >/etc/yum.repos.d/openresty.repo
[openresty]
name=Official OpenResty Repository
baseurl=https://openresty.org/package/centos/$releasever/$basearch
gpgcheck=1
repo_gpgcheck=0
gpgkey=https://openresty.org/package/pubkey.gpg
enabled=1
EOF
    fi
    $pkgmgr install -y openresty
  else
    echo "[anyproxy-install] unsupported package manager: unable to install openresty automatically" >&2
    exit 1
  fi

  ensure_systemctl_service openresty
}

install_haproxy_pkg() {
  if command -v haproxy >/dev/null 2>&1; then
    ensure_systemctl_service haproxy
    return
  fi

  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y
    apt-get install -y haproxy
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y haproxy
  elif command -v yum >/dev/null 2>&1; then
    yum install -y haproxy
  else
    echo "[anyproxy-install] unsupported package manager: unable to install haproxy automatically" >&2
    exit 1
  fi

  ensure_systemctl_service haproxy
}

CONTROL_PLANE_URL="${ANYPROXY_CONTROL_PLANE:-}"
NODE_TYPE="${ANYPROXY_NODE_TYPE:-}"
NODE_ID="${ANYPROXY_NODE_ID:-}"
TOKEN="${ANYPROXY_TOKEN:-}"
VERSION="${ANYPROXY_VERSION:-latest}"
RELOAD_CMD="${ANYPROXY_RELOAD_CMD:-nginx -s reload}"
OUTPUT_PATH="${ANYPROXY_OUTPUT_PATH:-}"
STREAM_OUTPUT_PATH="${ANYPROXY_STREAM_OUTPUT_PATH:-}"
CERT_DIR="${ANYPROXY_CERT_DIR:-}"
CLIENT_CA_DIR="${ANYPROXY_CLIENT_CA_DIR:-}"
AGENT_AUTH_TOKEN="${ANYPROXY_AGENT_TOKEN:-}"
NODE_NAME="${ANYPROXY_NODE_NAME:-}"
NODE_CATEGORY="${ANYPROXY_NODE_CATEGORY:-}"
NODE_GROUP_ID="${ANYPROXY_NODE_GROUP_ID:-}"

usage() {
  cat <<'EOF'
Usage: agent.sh --control-plane URL --type edge|tunnel --node NODE_ID --token TOKEN [--version VERSION] [--reload CMD] [--output PATH] [--stream-output PATH] [--node-name NAME] [--node-category KIND] [--group-id ID] [--cert-dir PATH] [--client-ca-dir PATH] [--agent-token TOKEN]

Environment overrides:
  ANYPROXY_CONTROL_PLANE default control plane URL
  ANYPROXY_NODE_TYPE     default node type (edge/tunnel)
  ANYPROXY_NODE_ID       default node ID
  ANYPROXY_TOKEN         default token string
  ANYPROXY_VERSION       default version to install (fallback: latest)
  ANYPROXY_RELOAD_CMD    reload command for nginx/openresty (fallback: "nginx -s reload")
  ANYPROXY_OUTPUT_PATH   default HTTP config output path
  ANYPROXY_STREAM_OUTPUT_PATH default stream config output path
  ANYPROXY_CERT_DIR      default certificate directory passed to agent
  ANYPROXY_CLIENT_CA_DIR client CA bundle directory passed to agent
  ANYPROXY_AGENT_TOKEN   optional bearer token supplied to agent via -auth-token
  ANYPROXY_NODE_NAME     default node display name passed to agent
  ANYPROXY_NODE_CATEGORY default node category hint (cdn/tunnel)
  ANYPROXY_NODE_GROUP_ID default node group identifier
EOF
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --control-plane)
      CONTROL_PLANE_URL=${2:-}
      shift 2
      ;;
    --type)
      NODE_TYPE=${2:-}
      shift 2
      ;;
    --node)
      NODE_ID=${2:-}
      shift 2
      ;;
    --token)
      TOKEN=${2:-}
      shift 2
      ;;
    --version)
      VERSION=${2:-}
      shift 2
      ;;
    --reload)
      RELOAD_CMD=${2:-}
      shift 2
      ;;
    --output)
      OUTPUT_PATH=${2:-}
      shift 2
      ;;
    --stream-output)
      STREAM_OUTPUT_PATH=${2:-}
      shift 2
      ;;
    --cert-dir)
      CERT_DIR=${2:-}
      shift 2
      ;;
    --client-ca-dir)
      CLIENT_CA_DIR=${2:-}
      shift 2
      ;;
    --agent-token)
      AGENT_AUTH_TOKEN=${2:-}
      shift 2
      ;;
    --node-name)
      NODE_NAME=${2:-}
      shift 2
      ;;
    --node-category)
      NODE_CATEGORY=${2:-}
      shift 2
      ;;
    --group-id)
      NODE_GROUP_ID=${2:-}
      shift 2
      ;;
    -h|--help)
      usage
      ;;
    *)
      echo "[anyproxy-install] unknown argument: $1" >&2
      usage
      ;;
  esac
done

if [[ -z $CONTROL_PLANE_URL || -z $NODE_TYPE || -z $NODE_ID || -z $TOKEN ]]; then
  echo "[anyproxy-install] missing required arguments" >&2
  usage
fi

if [[ "$NODE_TYPE" != "edge" && "$NODE_TYPE" != "tunnel" ]]; then
  echo "[anyproxy-install] --type must be either edge or tunnel" >&2
  exit 1
fi

NODE_NAME="$(echo "${NODE_NAME}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
NODE_CATEGORY="$(echo "${NODE_CATEGORY}" | tr '[:upper:]' '[:lower:]')"
case "$NODE_CATEGORY" in
  cdn|tunnel|"") ;;
  *)
    NODE_CATEGORY=""
    ;;
esac

CONTROL_PLANE_URL=${CONTROL_PLANE_URL%/}

TOKEN_URL="${CONTROL_PLANE_URL}/install/tokens/${TOKEN}.json"
echo "[anyproxy-install] validating token against ${TOKEN_URL}"

TOKEN_FILE=$(mktemp)
cleanup() {
  rm -f "$TOKEN_FILE"
}
trap cleanup EXIT

if ! curl -fsSL "$TOKEN_URL" -o "$TOKEN_FILE"; then
  echo "[anyproxy-install] failed to fetch token metadata" >&2
  exit 1
fi

EXPIRES_AT=$(jq -r '.expiresAt // empty' "$TOKEN_FILE")
TOKEN_TYPE=$(jq -r '.type // empty' "$TOKEN_FILE")
TOKEN_NODE=$(jq -r '.node // empty' "$TOKEN_FILE")

if [[ -z $EXPIRES_AT || -z $TOKEN_TYPE || -z $TOKEN_NODE ]]; then
  echo "[anyproxy-install] token metadata missing fields" >&2
  exit 1
fi

CURRENT_TS=$(date -u +%s)
if (( CURRENT_TS > EXPIRES_AT )); then
  echo "[anyproxy-install] token has expired" >&2
  exit 1
fi
if [[ "$TOKEN_TYPE" != "$NODE_TYPE" || "$TOKEN_NODE" != "$NODE_ID" ]]; then
  echo "[anyproxy-install] token does not match requested node/type" >&2
  exit 1
fi

if [[ "$NODE_TYPE" == "edge" ]]; then
  install_openresty
  install_haproxy_pkg
else
  install_haproxy_pkg
fi

TMPDIR=$(mktemp -d)
trap 'cleanup; rm -rf "$TMPDIR"' EXIT

download_agent() {
  local agent_type=$1
  local archive="${TMPDIR}/${agent_type}.tar.gz"
  local url="${CONTROL_PLANE_URL}/install/binaries/${VERSION}/${agent_type}_linux_amd64.tar.gz"
  echo "[anyproxy-install] downloading ${agent_type} agent ${VERSION} from ${url}"
  if ! curl -fsSL "$url" -o "$archive"; then
    echo "[anyproxy-install] failed to download ${agent_type} agent bundle" >&2
    exit 1
  fi
  if ! tar -xzf "$archive" -C "$TMPDIR"; then
    echo "[anyproxy-install] failed to extract ${agent_type} agent bundle" >&2
    exit 1
  fi
  if [[ ! -x "${TMPDIR}/${agent_type}-agent" ]]; then
    echo "[anyproxy-install] agent bundle missing executable ${agent_type}-agent" >&2
    exit 1
  fi
}

write_service() {
  local service_path=$1
  local description=$2
  shift 2
  local exec_cmd=$1
  shift
  local -a exec_args=("$@")

  {
    echo "[Unit]"
    echo "Description=${description}"
    echo "After=network-online.target"
    echo "Wants=network-online.target"
    echo
    echo "[Service]"
    printf "ExecStart=%s" "${exec_cmd}"
    for arg in "${exec_args[@]}"; do
      printf " \\\\\n  %s" "$arg"
    done
    echo
    echo "Restart=always"
    echo "RestartSec=5"
    echo
    echo "[Install]"
    echo "WantedBy=multi-user.target"
  } >"$service_path"
}

SERVICES=()

if [[ "$NODE_TYPE" == "edge" ]]; then
  download_agent "edge"
  download_agent "tunnel"

  EDGE_INSTALL_PATH="/usr/local/bin/anyproxy-edge"
  TUNNEL_INSTALL_PATH="/usr/local/bin/anyproxy-tunnel"
  echo "[anyproxy-install] installing binaries to ${EDGE_INSTALL_PATH} and ${TUNNEL_INSTALL_PATH}"
  install -m 0755 "${TMPDIR}/edge-agent" "$EDGE_INSTALL_PATH"
  install -m 0755 "${TMPDIR}/tunnel-agent" "$TUNNEL_INSTALL_PATH"

  EDGE_DEFAULT_OUTPUT="/etc/nginx/conf.d/anyproxy-${NODE_ID}.conf"
  EDGE_OUTPUT_PATH=${OUTPUT_PATH:-$EDGE_DEFAULT_OUTPUT}
  mkdir -p "$(dirname "$EDGE_OUTPUT_PATH")"

  TUNNEL_DEFAULT_OUTPUT="/etc/nginx/stream.d/anyproxy-${NODE_ID}.conf"
  TUNNEL_OUTPUT_PATH=${STREAM_OUTPUT_PATH:-$TUNNEL_DEFAULT_OUTPUT}
  mkdir -p "$(dirname "$TUNNEL_OUTPUT_PATH")"

  EDGE_EXEC_ARGS=(
    "-control-plane" "${CONTROL_PLANE_URL}"
    "-node-id" "${NODE_ID}"
    "-output" "${EDGE_OUTPUT_PATH}"
  )
  if [[ -n $NODE_NAME ]]; then
    EDGE_EXEC_ARGS+=("-node-name" "${NODE_NAME}")
  fi
  if [[ -n $NODE_CATEGORY ]]; then
    EDGE_EXEC_ARGS+=("-node-category" "${NODE_CATEGORY}")
  fi
  if [[ -n $NODE_GROUP_ID ]]; then
    EDGE_EXEC_ARGS+=("-group-id" "${NODE_GROUP_ID}")
  fi
  if [[ -n $AGENT_AUTH_TOKEN ]]; then
    EDGE_EXEC_ARGS+=("-auth-token" "${AGENT_AUTH_TOKEN}")
  fi
  if [[ -n $CERT_DIR ]]; then
    EDGE_EXEC_ARGS+=("-cert-dir" "${CERT_DIR}")
  fi
  if [[ -n $CLIENT_CA_DIR ]]; then
    EDGE_EXEC_ARGS+=("-client-ca-dir" "${CLIENT_CA_DIR}")
  fi
  EDGE_EXEC_ARGS+=("-reload" "${RELOAD_CMD}")

  EDGE_SERVICE_NAME="anyproxy-edge-${NODE_ID}.service"
  EDGE_SERVICE_PATH="/etc/systemd/system/${EDGE_SERVICE_NAME}"
  write_service "$EDGE_SERVICE_PATH" "AnyProxy edge agent (${NODE_ID})" "$EDGE_INSTALL_PATH" "${EDGE_EXEC_ARGS[@]}"
  echo "[anyproxy-install] systemd unit written to ${EDGE_SERVICE_PATH}"
  SERVICES+=("$EDGE_SERVICE_NAME")

  TUNNEL_EXEC_ARGS=(
    "-control-plane" "${CONTROL_PLANE_URL}"
    "-node-id" "${NODE_ID}"
    "-output" "${TUNNEL_OUTPUT_PATH}"
  )
  if [[ -n $NODE_NAME ]]; then
    TUNNEL_EXEC_ARGS+=("-node-name" "${NODE_NAME}")
  fi
  if [[ -n $NODE_CATEGORY ]]; then
    TUNNEL_EXEC_ARGS+=("-node-category" "${NODE_CATEGORY}")
  fi
  if [[ -n $NODE_GROUP_ID ]]; then
    TUNNEL_EXEC_ARGS+=("-group-id" "${NODE_GROUP_ID}")
  fi
  if [[ -n $NODE_NAME ]]; then
    TUNNEL_EXEC_ARGS+=("-node-name" "${NODE_NAME}")
  fi
  if [[ -n $NODE_CATEGORY ]]; then
    TUNNEL_EXEC_ARGS+=("-node-category" "${NODE_CATEGORY}")
  fi
  if [[ -n $NODE_GROUP_ID ]]; then
    TUNNEL_EXEC_ARGS+=("-group-id" "${NODE_GROUP_ID}")
  fi
  if [[ -n $AGENT_AUTH_TOKEN ]]; then
    TUNNEL_EXEC_ARGS+=("-auth-token" "${AGENT_AUTH_TOKEN}")
  fi
  TUNNEL_EXEC_ARGS+=("-reload" "${RELOAD_CMD}")

  TUNNEL_SERVICE_NAME="anyproxy-tunnel-${NODE_ID}.service"
  TUNNEL_SERVICE_PATH="/etc/systemd/system/${TUNNEL_SERVICE_NAME}"
  write_service "$TUNNEL_SERVICE_PATH" "AnyProxy tunnel agent (${NODE_ID})" "$TUNNEL_INSTALL_PATH" "${TUNNEL_EXEC_ARGS[@]}"
  echo "[anyproxy-install] systemd unit written to ${TUNNEL_SERVICE_PATH}"
  SERVICES+=("$TUNNEL_SERVICE_NAME")

  systemctl daemon-reload
  for svc in "${SERVICES[@]}"; do
    systemctl enable --now "$svc"
    systemctl status "$svc" --no-pager
  done

  echo "[anyproxy-install] installation complete."
  echo "[anyproxy-install] HTTP config renders to ${EDGE_OUTPUT_PATH}"
  echo "[anyproxy-install] Stream config renders to ${TUNNEL_OUTPUT_PATH}"
elif [[ "$NODE_TYPE" == "tunnel" ]]; then
  download_agent "tunnel"

  TUNNEL_INSTALL_PATH="/usr/local/bin/anyproxy-tunnel"
  echo "[anyproxy-install] installing binary to ${TUNNEL_INSTALL_PATH}"
  install -m 0755 "${TMPDIR}/tunnel-agent" "$TUNNEL_INSTALL_PATH"

  TUNNEL_DEFAULT_OUTPUT="/etc/nginx/stream.d/anyproxy-${NODE_ID}.conf"
  TUNNEL_OUTPUT_PATH=${STREAM_OUTPUT_PATH:-${OUTPUT_PATH:-$TUNNEL_DEFAULT_OUTPUT}}
  mkdir -p "$(dirname "$TUNNEL_OUTPUT_PATH")"

  TUNNEL_EXEC_ARGS=(
    "-control-plane" "${CONTROL_PLANE_URL}"
    "-node-id" "${NODE_ID}"
    "-output" "${TUNNEL_OUTPUT_PATH}"
  )
  if [[ -n $AGENT_AUTH_TOKEN ]]; then
    TUNNEL_EXEC_ARGS+=("-auth-token" "${AGENT_AUTH_TOKEN}")
  fi
  TUNNEL_EXEC_ARGS+=("-reload" "${RELOAD_CMD}")

  TUNNEL_SERVICE_NAME="anyproxy-tunnel-${NODE_ID}.service"
  TUNNEL_SERVICE_PATH="/etc/systemd/system/${TUNNEL_SERVICE_NAME}"
  write_service "$TUNNEL_SERVICE_PATH" "AnyProxy tunnel agent (${NODE_ID})" "$TUNNEL_INSTALL_PATH" "${TUNNEL_EXEC_ARGS[@]}"
  echo "[anyproxy-install] systemd unit written to ${TUNNEL_SERVICE_PATH}"

  systemctl daemon-reload
  systemctl enable --now "$TUNNEL_SERVICE_NAME"
  systemctl status "$TUNNEL_SERVICE_NAME" --no-pager

  echo "[anyproxy-install] installation complete. Stream config renders to ${TUNNEL_OUTPUT_PATH}"
else
  echo "[anyproxy-install] unsupported node type: ${NODE_TYPE}" >&2
  exit 1
fi
