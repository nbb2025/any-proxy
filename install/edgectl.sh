#!/usr/bin/env bash

set -euo pipefail

STATE_FILE="/etc/anyproxy/edgectl.env"
EDGECTL_BIN_DEFAULT="/usr/local/bin/edgectl"
STATUS_FILE=""
STATUS_AGENT_VERSION=""
STATUS_DESIRED_VERSION=""
STATUS_LAST_CONTACT=""
STATUS_CONFIG_VERSION=""

log() {
  echo "[edgectl] $*"
}

log_err() {
  echo "[edgectl] ERROR: $*" >&2
}

die() {
  log_err "$1"
  exit "${2:-1}"
}

require_root() {
  if [[ $EUID -ne 0 ]]; then
    die "请以 root 权限运行（可使用 sudo edgectl ...）"
  fi
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    die "缺少依赖：$1"
  fi
}

ensure_state_file() {
  if [[ ! -f $STATE_FILE ]]; then
    die "未找到状态文件 ${STATE_FILE}，请重新执行安装脚本"
  fi
}

load_state() {
  ensure_state_file
  # shellcheck disable=SC1090
  source "$STATE_FILE"
  SERVICE_NAME=${EDGE_STATE_SERVICE_NAME:-"anyproxy-edge-${ANYPROXY_NODE_ID:-unknown}.service"}
  INSTALL_URL=${EDGE_STATE_INSTALL_URL:-"${ANYPROXY_CONTROL_PLANE%/}/install/edge-install.sh"}
  UNINSTALL_URL=${EDGE_STATE_UNINSTALL_URL:-"${ANYPROXY_CONTROL_PLANE%/}/install/edge-uninstall.sh"}
  EDGECTL_BIN=${EDGE_STATE_BIN_PATH:-$EDGECTL_BIN_DEFAULT}
  STATUS_FILE=${EDGE_STATE_STATUS_FILE:-${ANYPROXY_STATUS_FILE:-}}
  if [[ -z $STATUS_FILE && -n ${ANYPROXY_NODE_ID:-} ]]; then
    STATUS_FILE="/var/lib/anyproxy/edge-status-${ANYPROXY_NODE_ID}.env"
  fi
}

load_status_env() {
  STATUS_AGENT_VERSION=${ANYPROXY_AGENT_VERSION:-}
  STATUS_DESIRED_VERSION=""
  STATUS_LAST_CONTACT=""
  STATUS_CONFIG_VERSION=""
  if [[ -n $STATUS_FILE && -f $STATUS_FILE ]]; then
    # shellcheck disable=SC1090
    source "$STATUS_FILE"
    STATUS_AGENT_VERSION=${EDGE_STATUS_AGENT_VERSION:-$STATUS_AGENT_VERSION}
    STATUS_DESIRED_VERSION=${EDGE_STATUS_DESIRED_VERSION:-$STATUS_DESIRED_VERSION}
    STATUS_LAST_CONTACT=${EDGE_STATUS_LAST_CONTACT:-$STATUS_LAST_CONTACT}
    STATUS_CONFIG_VERSION=${EDGE_STATUS_CONFIG_VERSION:-$STATUS_CONFIG_VERSION}
  fi
}

download_script() {
  local url=$1
  local out
  out=$(mktemp)
  if ! curl -fsSL "$url" -o "$out"; then
    rm -f "$out"
    die "下载脚本失败：$url"
  fi
  chmod +x "$out"
  echo "$out"
}

run_install() {
  local target_version=$1
  load_state
  local script
  script=$(download_script "$INSTALL_URL")
  log "开始升级 edge-agent（version=${target_version:-auto}）"
  if [[ -n $target_version ]]; then
    export ANYPROXY_VERSION="$target_version"
  else
    unset ANYPROXY_VERSION
  fi
  if [[ -n $STATUS_FILE ]]; then
    export ANYPROXY_STATUS_FILE="$STATUS_FILE"
  fi
  bash "$script" --type edge --node "${ANYPROXY_NODE_ID}"
  rm -f "$script"
  log "edge-agent 升级完成"
}

run_uninstall() {
  local purge_flag=$1
  load_state
  local script
  script=$(download_script "$UNINSTALL_URL")
  if [[ $purge_flag == "1" ]]; then
    export ANYPROXY_PURGE_CONFIG=1
  fi
  if [[ -n $STATUS_FILE ]]; then
    export ANYPROXY_STATUS_FILE="$STATUS_FILE"
  fi
  bash "$script" --type edge --node "${ANYPROXY_NODE_ID}"
  rm -f "$script"
  log "edge-agent 已卸载"
  cleanup_edgectl_files
}

cleanup_edgectl_files() {
  rm -f "$STATE_FILE"
  local bin_path=${EDGE_STATE_BIN_PATH:-$EDGECTL_BIN_DEFAULT}
  if [[ -x $bin_path || -f $bin_path ]]; then
    log "移除 ${bin_path}"
    rm -f "$bin_path"
  fi
  if [[ -n $STATUS_FILE && -f $STATUS_FILE ]]; then
    log "移除状态文件 ${STATUS_FILE}"
    rm -f "$STATUS_FILE"
  fi
}

handle_upgrade() {
  require_cmd curl
  local version_arg=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --version|-v)
        version_arg=${2:-}
        shift 2
        ;;
      *)
        usage
        ;;
    esac
  done
  load_state
  local desired_version="${version_arg:-${ANYPROXY_VERSION:-}}"
  run_install "$desired_version"
}

handle_restart() {
  load_state
  systemctl restart "$SERVICE_NAME"
  log "已重启 ${SERVICE_NAME}"
}

handle_start() {
  load_state
  systemctl start "$SERVICE_NAME"
  log "已启动 ${SERVICE_NAME}"
}

handle_stop() {
  load_state
  systemctl stop "$SERVICE_NAME"
  log "已停止 ${SERVICE_NAME}"
}

handle_info() {
  load_state
  load_status_env
  local active substate
  active=$(systemctl show "$SERVICE_NAME" -p ActiveState --value 2>/dev/null || true)
  substate=$(systemctl show "$SERVICE_NAME" -p SubState --value 2>/dev/null || true)
  active=${active:-unknown}
  substate=${substate:-unknown}
  echo "节点 ID: ${ANYPROXY_NODE_ID:-未知}"
  echo "Agent 版本: ${STATUS_AGENT_VERSION:-未知}"
  echo "主控 URL: ${ANYPROXY_CONTROL_PLANE:-未知}"
  echo "目标版本: ${STATUS_DESIRED_VERSION:-未设置}"
  echo "最后通讯: ${STATUS_LAST_CONTACT:-未知}"
  if [[ -n $STATUS_CONFIG_VERSION ]]; then
    echo "配置版本: ${STATUS_CONFIG_VERSION}"
  else
    echo "配置版本: 未知"
  fi
  echo "服务状态: ${active}/${substate}"
  if [[ -n $STATUS_FILE ]]; then
    echo "状态文件: ${STATUS_FILE}"
  fi
}

handle_uninstall() {
  require_cmd curl
  local purge=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --purge-config)
        purge=1
        shift
        ;;
      *)
        usage
        ;;
    esac
  done
  run_uninstall "$purge"
}

usage() {
  cat <<'EOF'
用法：edgectl <命令> [选项]

命令：
  upgrade [--version vX.Y.Z]   重新执行安装并升级 edge-agent（默认沿用上次版本）
  start                        启动 edge-agent systemd 服务
  restart                      重启 edge-agent systemd 服务
  stop                         停止 edge-agent systemd 服务
  info                         查看服务状态、版本、主控 URL、上次通讯及配置版本
  uninstall [--purge-config]   卸载 edge-agent，并可选择删除渲染产物
EOF
  exit 1
}

main() {
  require_root
  require_cmd systemctl
  local cmd=${1:-}
  if [[ -z $cmd ]]; then
    usage
  fi
  shift || true
  case "$cmd" in
    upgrade)
      handle_upgrade "$@"
      ;;
    start)
      handle_start "$@"
      ;;
    restart)
      handle_restart "$@"
      ;;
    stop)
      handle_stop "$@"
      ;;
    info)
      handle_info "$@"
      ;;
    uninstall)
      handle_uninstall "$@"
      ;;
    *)
      usage
      ;;
  esac
}

main "$@"
