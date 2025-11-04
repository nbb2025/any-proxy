#!/usr/bin/env bash

set -euo pipefail

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[anyproxy-token] missing dependency: $1" >&2
    exit 1
  fi
}

escape() {
  printf %q "$1"
}

if command -v openssl >/dev/null 2>&1; then
  generate_token() {
    openssl rand -hex 16
  }
else
  require_cmd hexdump
  generate_token() {
    hexdump -vn16 -e '16/1 "%02x"' /dev/urandom
  }
fi

CONTROL_PLANE_URL="${CONTROL_PLANE_URL:-https://anyproxy.weekeasy.com}"
NODE_TYPE=""
NODE_ID=""
TTL_MINUTES=30
TOKENS_DIR="${ANYPROXY_TOKENS_DIR:-/opt/anyproxy/install/tokens}"
VERSION="${ANYPROXY_VERSION:-latest}"
RELOAD_CMD="${ANYPROXY_RELOAD_CMD:-}"
OUTPUT_PATH="${ANYPROXY_OUTPUT_PATH:-}"
OUTPUT_FORMAT="${ANYPROXY_OUTPUT_FMT:-text}"

usage() {
  cat <<'EOF'
Usage: generate-node-command.sh --type edge|tunnel --node NODE_ID [options]

Options:
  --control-plane URL   Base URL where agent.sh/token is hosted (default: env CONTROL_PLANE_URL or https://anyproxy.weekeasy.com)
  --ttl-min MINUTES     Token validity window in minutes (default: 30)
  --tokens-dir PATH     Directory to store token json files (default: /opt/anyproxy/install/tokens or env ANYPROXY_TOKENS_DIR)
  --version VERSION     Agent version tag (default: env ANYPROXY_VERSION or "latest")
  --reload CMD          Override reload command passed to installer (default: env ANYPROXY_RELOAD_CMD)
  --output PATH         Override agent --output path passed to installer
  --format text|env     Output style (default: text; env for machine parsing)

Environment:
  CONTROL_PLANE_URL     Default control plane / install base URL
  ANYPROXY_TOKENS_DIR   Storage directory for generated token files
  ANYPROXY_VERSION      Default agent version
  ANYPROXY_RELOAD_CMD   Default reload command
  ANYPROXY_OUTPUT_PATH  Default output path override
  ANYPROXY_OUTPUT_FMT   Default format (text/env)
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
    --ttl-min)
      TTL_MINUTES=${2:-}
      shift 2
      ;;
    --tokens-dir)
      TOKENS_DIR=${2:-}
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
    -h|--help)
      usage
      ;;
    *)
      echo "[anyproxy-token] unknown argument: $1" >&2
      usage
      ;;
  esac
done

if [[ -z $NODE_TYPE || -z $NODE_ID ]]; then
  echo "[anyproxy-token] --type and --node are required" >&2
  usage
fi

if [[ "$NODE_TYPE" != "edge" && "$NODE_TYPE" != "tunnel" ]]; then
  echo "[anyproxy-token] --type must be edge or tunnel" >&2
  exit 1
fi

case "$OUTPUT_FORMAT" in
  text|env) ;;
  *)
    echo "[anyproxy-token] unsupported format: ${OUTPUT_FORMAT}" >&2
    exit 1
    ;;
esac

require_cmd date
require_cmd mkdir
require_cmd cat

TOKEN=$(generate_token)
NOW_TS=$(date -u +%s)
TTL_SECONDS=$((TTL_MINUTES * 60))
EXP_TS=$((NOW_TS + TTL_SECONDS))

mkdir -p "$TOKENS_DIR"

TOKEN_PATH="${TOKENS_DIR%/}/${TOKEN}.json"
cat >"$TOKEN_PATH" <<EOF
{"token":"${TOKEN}","type":"${NODE_TYPE}","node":"${NODE_ID}","expiresAt":${EXP_TS},"issuedAt":${NOW_TS}}
EOF

CONTROL_PLANE_URL=${CONTROL_PLANE_URL%/}
INSTALL_URL="${CONTROL_PLANE_URL}/install/agent.sh"

CMD="curl -fsSL ${INSTALL_URL} | sudo"
CMD+=" ANYPROXY_CONTROL_PLANE=$(escape "${CONTROL_PLANE_URL}")"
CMD+=" ANYPROXY_NODE_TYPE=$(escape "${NODE_TYPE}")"
CMD+=" ANYPROXY_NODE_ID=$(escape "${NODE_ID}")"
CMD+=" ANYPROXY_TOKEN=$(escape "${TOKEN}")"

if [[ -n $VERSION ]]; then
  CMD+=" ANYPROXY_VERSION=$(escape "${VERSION}")"
fi
if [[ -n $RELOAD_CMD ]]; then
  CMD+=" ANYPROXY_RELOAD_CMD=$(escape "${RELOAD_CMD}")"
fi
if [[ -n $OUTPUT_PATH ]]; then
  CMD+=" ANYPROXY_OUTPUT_PATH=$(escape "${OUTPUT_PATH}")"
fi

CMD+=" bash"

if [[ "$OUTPUT_FORMAT" == "env" ]]; then
  {
    printf 'COMMAND=%s\n' "$CMD"
    printf 'TOKEN=%s\n' "$TOKEN"
    printf 'TOKEN_PATH=%s\n' "$TOKEN_PATH"
    printf 'EXPIRES_AT=%s\n' "$EXP_TS"
    printf 'EXPIRES_AT_ISO=%s\n' "$(date -u -d "@${EXP_TS}" +%Y-%m-%dT%H:%M:%SZ)"
    printf 'CONTROL_PLANE_URL=%s\n' "$CONTROL_PLANE_URL"
    printf 'NODE_TYPE=%s\n' "$NODE_TYPE"
    printf 'NODE_ID=%s\n' "$NODE_ID"
    printf 'VERSION=%s\n' "$VERSION"
    printf 'RELOAD_CMD=%s\n' "$RELOAD_CMD"
    printf 'OUTPUT_PATH=%s\n' "$OUTPUT_PATH"
  }
  exit 0
fi

echo "[anyproxy-token] token written to ${TOKEN_PATH}"
echo
echo "在目标 ${NODE_TYPE} 节点执行以下命令："
echo
echo "$CMD"
echo
echo "[anyproxy-token] token 将于 $(date -u -d "@${EXP_TS}") 过期"
