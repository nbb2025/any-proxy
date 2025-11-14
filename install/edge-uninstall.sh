#!/usr/bin/env bash

set -euo pipefail

log_info() {
  echo "[anyproxy-uninstall] $*"
}

log_error() {
  echo "[anyproxy-uninstall] ERROR: $*" >&2
}

die() {
  log_error "$1"
  exit "${2:-1}"
}

ensure_root() {
  if [[ $EUID -ne 0 ]]; then
    die "请使用 root 权限运行本脚本（例如通过 sudo）"
  fi
}

ensure_root

if [[ "$(uname -s)" != "Linux" ]]; then
  die "仅支持在 Linux 系统上卸载节点"
fi

NODE_TYPE="${ANYPROXY_NODE_TYPE:-}"
NODE_ID="$(echo "${ANYPROXY_NODE_ID:-}" | tr -d '[:space:]')"
OUTPUT_PATH="${ANYPROXY_OUTPUT_PATH:-}"
STREAM_OUTPUT_PATH="${ANYPROXY_STREAM_OUTPUT_PATH:-}"
PURGE_CONFIG="${ANYPROXY_PURGE_CONFIG:-0}"
EDGECTL_BIN_PATH="/usr/local/bin/edgectl"
EDGECTL_STATE_FILE="/etc/anyproxy/edgectl.env"

usage() {
  cat <<'EOF'
Usage: edge-uninstall.sh --type edge|tunnel --node NODE_ID [options]

Options:
  --type TYPE            节点类型：edge 或 tunnel（也可通过 ANYPROXY_NODE_TYPE 设置）
  --node NODE_ID         节点 ID（也可通过 ANYPROXY_NODE_ID 设置）
  --output PATH          Edge 节点 HTTP 配置路径（默认 /etc/nginx/conf.d/anyproxy-<NODE_ID>.conf）
  --stream-output PATH   Edge 节点 stream/HAProxy 配置路径
  --purge-config         同时删除渲染产物（等价于 ANYPROXY_PURGE_CONFIG=1）

Environment:
  ANYPROXY_NODE_TYPE        默认节点类型
  ANYPROXY_NODE_ID          默认节点 ID
  ANYPROXY_OUTPUT_PATH      默认 HTTP 配置路径
  ANYPROXY_STREAM_OUTPUT_PATH 默认 stream 配置路径
  ANYPROXY_PURGE_CONFIG     设为 1 时删除配置文件
EOF
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --type)
      NODE_TYPE=${2:-}
      shift 2
      ;;
    --node)
      NODE_ID=${2:-}
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
    --purge-config)
      PURGE_CONFIG=1
      shift
      ;;
    -h|--help)
      usage
      ;;
    *)
      usage
      ;;
  esac
done

if [[ -z $NODE_TYPE || -z $NODE_ID ]]; then
  usage
fi

NODE_TYPE=$(echo "$NODE_TYPE" | tr '[:upper:]' '[:lower:]')
case "$NODE_TYPE" in
  edge|tunnel) ;;
  *)
    die "节点类型必须是 edge 或 tunnel"
    ;;
esac

EDGE_STATUS_FILE="${ANYPROXY_STATUS_FILE:-/var/lib/anyproxy/edge-status-${NODE_ID}.env}"

trim() {
  local value=${1:-}
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

cleanup_service() {
  local service_name=$1
  if [[ -z "$service_name" ]]; then
    return
  fi
  if systemctl list-unit-files "$service_name" >/dev/null 2>&1 || systemctl status "$service_name" >/dev/null 2>&1; then
    log_info "停止并删除 systemd 服务 ${service_name}"
    systemctl stop "$service_name" >/dev/null 2>&1 || true
    systemctl disable "$service_name" >/dev/null 2>&1 || true
    rm -f "/etc/systemd/system/${service_name}"
    rm -rf "/etc/systemd/system/${service_name}.d"
  fi
}

cleanup_binary() {
  local path=$1
  if [[ -n "$path" && -e "$path" ]]; then
    log_info "删除二进制文件 ${path}"
    rm -f "$path"
  fi
}

remove_config_file() {
  local path=$1
  if [[ "$PURGE_CONFIG" != "1" ]]; then
    return
  fi
  if [[ -n "$path" ]]; then
    path=$(trim "$path")
  fi
  if [[ -n "$path" && -e "$path" ]]; then
    log_info "删除渲染产物 ${path}"
    rm -f "$path"
  fi
}

complete_cleanup() {
  systemctl daemon-reload >/dev/null 2>&1 || true
}

remove_edgectl_assets() {
  if [[ -f "$EDGECTL_STATE_FILE" ]]; then
    log_info "删除 edgectl 状态文件 ${EDGECTL_STATE_FILE}"
    rm -f "$EDGECTL_STATE_FILE"
  fi
  if [[ -f "$EDGECTL_BIN_PATH" ]]; then
    log_info "删除 edgectl 命令 ${EDGECTL_BIN_PATH}"
    rm -f "$EDGECTL_BIN_PATH"
  fi
  if [[ -f "$EDGE_STATUS_FILE" ]]; then
    log_info "删除 edge 状态文件 ${EDGE_STATUS_FILE}"
    rm -f "$EDGE_STATUS_FILE"
  fi
}

if [[ "$NODE_TYPE" == "edge" ]]; then
  EDGE_SERVICE="anyproxy-edge-${NODE_ID}.service"
  LEGACY_EDGE_SERVICE="anyproxy-edge.service"
  EDGE_BINARY="/usr/local/bin/anyproxy-edge"
  DEFAULT_OUTPUT="/etc/nginx/conf.d/anyproxy-${NODE_ID}.conf"
  DEFAULT_STREAM="/etc/haproxy/haproxy.cfg"

  OUTPUT_PATH=${OUTPUT_PATH:-$DEFAULT_OUTPUT}
  STREAM_OUTPUT_PATH=${STREAM_OUTPUT_PATH:-$DEFAULT_STREAM}
  EDGE_KEY_PATH="$(dirname "$OUTPUT_PATH")/.anyproxy-node.key"

  cleanup_service "$EDGE_SERVICE"
  cleanup_service "$LEGACY_EDGE_SERVICE"
  cleanup_binary "$EDGE_BINARY"
  remove_config_file "$OUTPUT_PATH"
  remove_config_file "$STREAM_OUTPUT_PATH"
  if [[ "$PURGE_CONFIG" == "1" ]]; then
    remove_config_file "$EDGE_KEY_PATH"
  fi

  log_info "Edge 节点 ${NODE_ID} 已卸载"
  remove_edgectl_assets
elif [[ "$NODE_TYPE" == "tunnel" ]]; then
  TUNNEL_SERVICE="anyproxy-tunnel-${NODE_ID}.service"
  LEGACY_TUNNEL_SERVICE="anyproxy-tunnel.service"
  TUNNEL_BINARY="/usr/local/bin/anyproxy-tunnel"
  DEFAULT_TUNNEL_OUTPUT="/etc/nginx/stream.d/anyproxy-${NODE_ID}.conf"

  OUTPUT_PATH=${OUTPUT_PATH:-$DEFAULT_TUNNEL_OUTPUT}

  cleanup_service "$TUNNEL_SERVICE"
  cleanup_service "$LEGACY_TUNNEL_SERVICE"
  cleanup_binary "$TUNNEL_BINARY"
  remove_config_file "$OUTPUT_PATH"

  log_info "隧道节点 ${NODE_ID} 已卸载"
fi

complete_cleanup

log_info "卸载完成，可根据需要删除残留日志或临时文件。"
