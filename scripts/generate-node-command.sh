#!/usr/bin/env bash

set -euo pipefail

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[anyproxy-command] missing dependency: $1" >&2
    exit 1
  fi
}

escape() {
  printf %q "$1"
}

CONTROL_PLANE_URL="${CONTROL_PLANE_URL:-}"
NODE_TYPE=""
NODE_ID=""
NODE_NAME="${ANYPROXY_NODE_NAME:-}"
NODE_GROUP="${ANYPROXY_NODE_GROUP_ID:-}"
NODE_CATEGORY="${ANYPROXY_NODE_CATEGORY:-}"
VERSION="${ANYPROXY_VERSION:-latest}"
RELOAD_CMD="${ANYPROXY_RELOAD_CMD:-}"
OUTPUT_PATH="${ANYPROXY_OUTPUT_PATH:-}"
STREAM_OUTPUT_PATH="${ANYPROXY_STREAM_OUTPUT_PATH:-}"
OUTPUT_FORMAT="${ANYPROXY_OUTPUT_FMT:-text}"
AGENT_TOKEN="${ANYPROXY_AGENT_TOKEN:-}"
AGENT_KEY="${ANYPROXY_AGENT_KEY:-}"
TUNNEL_GROUP="${ANYPROXY_TUNNEL_GROUP_ID:-}"
HAPROXY_RELOAD="${ANYPROXY_HAPROXY_RELOAD_CMD:-}"
CERT_DIR="${ANYPROXY_CERT_DIR:-}"
CLIENT_CA_DIR="${ANYPROXY_CLIENT_CA_DIR:-}"

usage() {
  cat <<'EOF'
Usage: generate-node-command.sh --type edge|tunnel [--node NODE_ID] [options]

Options:
  --control-plane URL   Base URL where edge-install.sh is hosted (default: env CONTROL_PLANE_URL)
  --version VERSION     Agent version tag (default: env ANYPROXY_VERSION or "latest")
  --reload CMD          Override reload command passed to installer (default: env ANYPROXY_RELOAD_CMD)
  --output PATH         Override agent --output path passed to installer
  --stream-output PATH  Override stream config output path (edge installs only; default stream.d)
  --node-name NAME      Optional friendly display name for the node
  --node-group ID       Optional node group identifier to apply on registration
  --node-category KIND  Optional category hint (cdn|tunnel)
  --cert-dir PATH       Override agent certificate directory (default: env ANYPROXY_CERT_DIR)
  --client-ca-dir PATH  Override agent client CA directory (default: env ANYPROXY_CLIENT_CA_DIR or cert dir)
  --agent-token TOKEN   Embed control-plane bearer token for agents (default: env ANYPROXY_AGENT_TOKEN)
  --agent-key KEY       (tunnel nodes) Provide tunnel-agent key issued by control plane (default: env ANYPROXY_AGENT_KEY)
  --tunnel-group ID     (tunnel nodes) Override tunnel group identifier (default: env ANYPROXY_TUNNEL_GROUP_ID)
  --haproxy-reload CMD  Override haproxy reload command (edge nodes; default: env ANYPROXY_HAPROXY_RELOAD_CMD)
  --format text|env     Output style (default: text; env for machine parsing)

Environment:
  CONTROL_PLANE_URL     Default control plane / install base URL
  ANYPROXY_VERSION      Default agent version
  ANYPROXY_RELOAD_CMD   Default reload command
  ANYPROXY_OUTPUT_PATH  Default HTTP output path override
  ANYPROXY_STREAM_OUTPUT_PATH Default stream output path override
  ANYPROXY_OUTPUT_FMT   Default format (text/env)
  ANYPROXY_CERT_DIR      Default certificate directory
  ANYPROXY_CLIENT_CA_DIR Default client CA directory
  ANYPROXY_AGENT_TOKEN   Default agent bearer token
  ANYPROXY_NODE_NAME     Default node display name
  ANYPROXY_NODE_GROUP_ID Default node group identifier
  ANYPROXY_NODE_CATEGORY Default node category hint
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
    --format)
      OUTPUT_FORMAT=${2:-}
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
    --node-name)
      NODE_NAME=${2:-}
      shift 2
      ;;
    --node-group)
      NODE_GROUP=${2:-}
      shift 2
      ;;
    --node-category)
      NODE_CATEGORY=${2:-}
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
      AGENT_TOKEN=${2:-}
      shift 2
      ;;
    --agent-key)
      AGENT_KEY=${2:-}
      shift 2
      ;;
    --tunnel-group)
      TUNNEL_GROUP=${2:-}
      shift 2
      ;;
    --haproxy-reload)
      HAPROXY_RELOAD=${2:-}
      shift 2
      ;;
    -h|--help)
      usage
      ;;
    *)
      echo "[anyproxy-command] unknown argument: $1" >&2
      usage
      ;;
  esac
done

if [[ -z $NODE_TYPE ]]; then
  echo "[anyproxy-command] --type is required" >&2
  usage
fi

if [[ "$NODE_TYPE" != "edge" && "$NODE_TYPE" != "tunnel" ]]; then
  echo "[anyproxy-command] --type must be edge or tunnel" >&2
  exit 1
fi

if [[ "$NODE_TYPE" == "tunnel" && -z $AGENT_KEY ]]; then
  echo "[anyproxy-command] --agent-key (or ANYPROXY_AGENT_KEY) is required for tunnel nodes" >&2
  exit 1
fi

NODE_CATEGORY=$(echo "${NODE_CATEGORY,,}")
case "$NODE_CATEGORY" in
  cdn|tunnel|"") ;;
  *)
    NODE_CATEGORY=""
    ;;
esac

case "$OUTPUT_FORMAT" in
  text|env) ;;
  *)
    echo "[anyproxy-command] unsupported format: ${OUTPUT_FORMAT}" >&2
    exit 1
    ;;
esac

CONTROL_PLANE_URL=${CONTROL_PLANE_URL%/}
INSTALL_URL="${CONTROL_PLANE_URL}/install/edge-install.sh"

CMD="curl -fsSL ${INSTALL_URL} | sudo"
CMD+=" ANYPROXY_CONTROL_PLANE=$(escape "${CONTROL_PLANE_URL}")"
CMD+=" ANYPROXY_NODE_TYPE=$(escape "${NODE_TYPE}")"

if [[ -n $NODE_ID ]]; then
  CMD+=" ANYPROXY_NODE_ID=$(escape "${NODE_ID}")"
fi

if [[ -n $VERSION ]]; then
  CMD+=" ANYPROXY_VERSION=$(escape "${VERSION}")"
fi
if [[ -n $RELOAD_CMD ]]; then
  CMD+=" ANYPROXY_RELOAD_CMD=$(escape "${RELOAD_CMD}")"
fi
if [[ -n $OUTPUT_PATH ]]; then
  CMD+=" ANYPROXY_OUTPUT_PATH=$(escape "${OUTPUT_PATH}")"
fi
if [[ -n $STREAM_OUTPUT_PATH ]]; then
  CMD+=" ANYPROXY_STREAM_OUTPUT_PATH=$(escape "${STREAM_OUTPUT_PATH}")"
fi
if [[ -n $NODE_NAME ]]; then
  CMD+=" ANYPROXY_NODE_NAME=$(escape "${NODE_NAME}")"
fi
if [[ -n $NODE_GROUP ]]; then
  CMD+=" ANYPROXY_NODE_GROUP_ID=$(escape "${NODE_GROUP}")"
fi
if [[ -n $TUNNEL_GROUP ]]; then
  CMD+=" ANYPROXY_TUNNEL_GROUP_ID=$(escape "${TUNNEL_GROUP}")"
fi
if [[ -n $NODE_CATEGORY ]]; then
  CMD+=" ANYPROXY_NODE_CATEGORY=$(escape "${NODE_CATEGORY}")"
fi
if [[ -n $CERT_DIR ]]; then
  CMD+=" ANYPROXY_CERT_DIR=$(escape "${CERT_DIR}")"
fi
if [[ -n $CLIENT_CA_DIR ]]; then
  CMD+=" ANYPROXY_CLIENT_CA_DIR=$(escape "${CLIENT_CA_DIR}")"
fi
if [[ -n $AGENT_TOKEN ]]; then
  CMD+=" ANYPROXY_AGENT_TOKEN=$(escape "${AGENT_TOKEN}")"
fi
if [[ -n $AGENT_KEY ]]; then
  CMD+=" ANYPROXY_AGENT_KEY=$(escape "${AGENT_KEY}")"
fi
if [[ -n $HAPROXY_RELOAD ]]; then
  CMD+=" ANYPROXY_HAPROXY_RELOAD_CMD=$(escape "${HAPROXY_RELOAD}")"
fi

CMD+=" bash"

if [[ "$OUTPUT_FORMAT" == "env" ]]; then
  {
    printf 'COMMAND=%s\n' "$CMD"
    printf 'CONTROL_PLANE_URL=%s\n' "$CONTROL_PLANE_URL"
    printf 'NODE_TYPE=%s\n' "$NODE_TYPE"
    printf 'NODE_ID=%s\n' "$NODE_ID"
    printf 'VERSION=%s\n' "$VERSION"
    printf 'RELOAD_CMD=%s\n' "$RELOAD_CMD"
    printf 'OUTPUT_PATH=%s\n' "$OUTPUT_PATH"
    printf 'STREAM_OUTPUT_PATH=%s\n' "$STREAM_OUTPUT_PATH"
    printf 'NODE_NAME=%s\n' "$NODE_NAME"
    printf 'NODE_GROUP_ID=%s\n' "$NODE_GROUP"
    printf 'NODE_CATEGORY=%s\n' "$NODE_CATEGORY"
    printf 'CERT_DIR=%s\n' "$CERT_DIR"
    printf 'CLIENT_CA_DIR=%s\n' "$CLIENT_CA_DIR"
    printf 'AGENT_TOKEN=%s\n' "$AGENT_TOKEN"
}
exit 0
fi

if [[ "$NODE_TYPE" == "edge" ]]; then
  echo "在目标边缘节点执行以下命令（将同步部署 HTTP + 隧道 Agent）："
else
  echo "在目标 ${NODE_TYPE} 节点执行以下命令："
fi
if [[ -n $NODE_NAME ]]; then
  echo "[anyproxy-command] 节点名称：${NODE_NAME}"
fi
if [[ -n $NODE_CATEGORY ]]; then
  echo "[anyproxy-command] 节点用途：${NODE_CATEGORY}"
fi
if [[ -z $NODE_ID ]]; then
  echo "[anyproxy-command] 节点 ID 将在首次安装时自动生成"
else
  echo "[anyproxy-command] 指定节点 ID：${NODE_ID}"
fi
echo
echo "$CMD"
