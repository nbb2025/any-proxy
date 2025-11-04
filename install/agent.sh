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

CONTROL_PLANE_URL="${ANYPROXY_CONTROL_PLANE:-}"
NODE_TYPE="${ANYPROXY_NODE_TYPE:-}"
NODE_ID="${ANYPROXY_NODE_ID:-}"
TOKEN="${ANYPROXY_TOKEN:-}"
VERSION="${ANYPROXY_VERSION:-latest}"
RELOAD_CMD="${ANYPROXY_RELOAD_CMD:-nginx -s reload}"
OUTPUT_PATH="${ANYPROXY_OUTPUT_PATH:-}"
CERT_DIR="${ANYPROXY_CERT_DIR:-}"
CLIENT_CA_DIR="${ANYPROXY_CLIENT_CA_DIR:-}"
AGENT_AUTH_TOKEN="${ANYPROXY_AGENT_TOKEN:-}"

usage() {
  cat <<'EOF'
Usage: agent.sh --control-plane URL --type edge|tunnel --node NODE_ID --token TOKEN [--version VERSION] [--reload CMD] [--output PATH] [--cert-dir PATH] [--client-ca-dir PATH] [--agent-token TOKEN]

Environment overrides:
  ANYPROXY_CONTROL_PLANE default control plane URL
  ANYPROXY_NODE_TYPE     default node type (edge/tunnel)
  ANYPROXY_NODE_ID       default node ID
  ANYPROXY_TOKEN         default token string
  ANYPROXY_VERSION       default version to install (fallback: latest)
  ANYPROXY_RELOAD_CMD    reload command for nginx/openresty (fallback: "nginx -s reload")
  ANYPROXY_OUTPUT_PATH   default config output path
  ANYPROXY_CERT_DIR      default certificate directory passed to agent
  ANYPROXY_CLIENT_CA_DIR client CA bundle directory passed to agent
  ANYPROXY_AGENT_TOKEN   optional bearer token supplied to agent via -auth-token
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

BINARIES_URL="${CONTROL_PLANE_URL}/install/binaries/${VERSION}/${NODE_TYPE}_linux_amd64.tar.gz"
echo "[anyproxy-install] downloading ${NODE_TYPE} agent ${VERSION} from ${BINARIES_URL}"

TMPDIR=$(mktemp -d)
trap 'cleanup; rm -rf "$TMPDIR"' EXIT

if ! curl -fsSL "$BINARIES_URL" -o "${TMPDIR}/agent.tar.gz"; then
  echo "[anyproxy-install] failed to download agent bundle" >&2
  exit 1
fi

tar -xzf "${TMPDIR}/agent.tar.gz" -C "$TMPDIR"

AGENT_BIN="${TMPDIR}/${NODE_TYPE}-agent"
if [[ ! -x $AGENT_BIN ]]; then
  echo "[anyproxy-install] agent bundle missing executable ${NODE_TYPE}-agent" >&2
  exit 1
fi

INSTALL_PATH="/usr/local/bin/anyproxy-${NODE_TYPE}"
echo "[anyproxy-install] installing binary to ${INSTALL_PATH}"
install -m 0755 "$AGENT_BIN" "$INSTALL_PATH"

case "$NODE_TYPE" in
  edge)
    DEFAULT_OUTPUT="/etc/nginx/conf.d/anyproxy-${NODE_ID}.conf"
    OUTPUT_DIR=$(dirname "${OUTPUT_PATH:-$DEFAULT_OUTPUT}")
    ;;
  tunnel)
    DEFAULT_OUTPUT="/etc/nginx/stream.d/anyproxy-${NODE_ID}.conf"
    OUTPUT_DIR=$(dirname "${OUTPUT_PATH:-$DEFAULT_OUTPUT}")
    ;;
esac

mkdir -p "$OUTPUT_DIR"
AGENT_OUTPUT_PATH=${OUTPUT_PATH:-$DEFAULT_OUTPUT}

SERVICE_NAME="anyproxy-${NODE_TYPE}-${NODE_ID}.service"
SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}"

EXEC_CMD="${INSTALL_PATH}"
EXEC_ARGS=(
  "-control-plane" "${CONTROL_PLANE_URL}"
  "-node-id" "${NODE_ID}"
  "-output" "${AGENT_OUTPUT_PATH}"
)
if [[ -n $AGENT_AUTH_TOKEN ]]; then
  EXEC_ARGS+=("-auth-token" "${AGENT_AUTH_TOKEN}")
fi
if [[ -n $CERT_DIR ]]; then
  EXEC_ARGS+=("-cert-dir" "${CERT_DIR}")
fi
if [[ -n $CLIENT_CA_DIR ]]; then
  EXEC_ARGS+=("-client-ca-dir" "${CLIENT_CA_DIR}")
fi
EXEC_ARGS+=("-reload" "${RELOAD_CMD}")

{
  echo "[Unit]"
  echo "Description=AnyProxy ${NODE_TYPE} agent (${NODE_ID})"
  echo "After=network-online.target"
  echo "Wants=network-online.target"
  echo
  echo "[Service]"
  printf "ExecStart=%s" "${EXEC_CMD}"
  for arg in "${EXEC_ARGS[@]}"; do
    printf " \\\\\n  %s" "$arg"
  done
  echo
  echo "Restart=always"
  echo "RestartSec=5"
  echo
  echo "[Install]"
  echo "WantedBy=multi-user.target"
} >"$SERVICE_PATH"

echo "[anyproxy-install] systemd unit written to ${SERVICE_PATH}"

systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME"
systemctl status "$SERVICE_NAME" --no-pager

echo "[anyproxy-install] installation complete. Config renders to ${AGENT_OUTPUT_PATH}"
