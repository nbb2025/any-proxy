#!/usr/bin/env bash

set -euo pipefail

log_info() {
  echo "[anyproxy-install] $*"
}

log_warn() {
  echo "[anyproxy-install] WARN: $*" >&2
}

log_error() {
  echo "[anyproxy-install] ERROR: $*" >&2
}

die() {
  log_error "$1"
  exit "${2:-1}"
}

ensure_root() {
  if [[ $EUID -ne 0 ]]; then
    die "please run this script as root (e.g. prefix with sudo)"
  fi
}

MIN_KERNEL="5.10.0"
MIN_GLIBC="2.34"
MIN_CPU_CORES=1
MIN_MEMORY_MB=2048
MIN_DISK_GB=20

PKG_MANAGER=""
PKG_UPDATE_CMD=""
PKG_INSTALL_CMD=""
PKG_CHECK_CMD=""
SKIP_REQUIREMENTS="${ANYPROXY_IGNORE_REQUIREMENTS:-0}"
PKG_UPDATE_DONE=""
EDGECTL_BIN_PATH="/usr/local/bin/edgectl"
EDGECTL_STATE_FILE="/etc/anyproxy/edgectl.env"

ensure_root

if [[ "$(uname -s)" != "Linux" ]]; then
  die "unsupported operating system: $(uname -s)"
fi

extend_path() {
  case ":$PATH:" in
    *:/sbin:* ) ;;
    *) PATH="$PATH:/sbin:/usr/sbin"; export PATH ;;
  esac
}

extend_path

version_ge() {
  local current=$1
  local required=$2
  if [[ "$current" == "$required" ]]; then
    return 0
  fi
  local sorted
  sorted=$(printf '%s\n%s\n' "$current" "$required" | sort -V | tail -n1)
  [[ "$sorted" == "$current" ]]
}

OS_ID=""
OS_VERSION_ID=""
OS_NAME=""
OS_LIKE=""
ARCH="$(uname -m)"

detect_distribution() {
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID=${ID:-}
    OS_VERSION_ID=${VERSION_ID:-}
    OS_NAME=${PRETTY_NAME:-$NAME}
    OS_LIKE=${ID_LIKE:-}
  fi

  if [[ -z $OS_ID || -z $OS_VERSION_ID ]]; then
    die "unable to detect Linux distribution via /etc/os-release"
  fi
}

require_architecture() {
  case "$ARCH" in
    x86_64|amd64) ;;
    *)
      die "unsupported CPU architecture '${ARCH}' (supported: x86_64)"
      ;;
  esac
}

enforce_supported_distribution() {
  local major="${OS_VERSION_ID%%.*}"
  case "$OS_ID" in
    debian)
      if ! version_ge "$OS_VERSION_ID" "12"; then
        die "Debian $OS_VERSION_ID is not supported; please use Debian 12 or newer"
      fi
      ;;
    ubuntu)
      if ! version_ge "$OS_VERSION_ID" "22.04"; then
        die "Ubuntu $OS_VERSION_ID is not supported; please use Ubuntu 22.04 or newer"
      fi
      ;;
    rhel|centos|centos_stream|ol|rocky|almalinux)
      if [[ "$major" -lt 9 ]]; then
        die "RHEL/CentOS/AlmaLinux/Rocky $OS_VERSION_ID not supported; please use version 9 or newer"
      fi
      ;;
    fedora)
      if ! version_ge "$OS_VERSION_ID" "40"; then
        die "Fedora $OS_VERSION_ID not supported; please use Fedora 40 or newer"
      fi
      ;;
    "fedora-coreos")
      if ! version_ge "$OS_VERSION_ID" "42"; then
        die "Fedora CoreOS $OS_VERSION_ID not supported; please use 42 or newer"
      fi
      ;;
    amzn)
      if ! version_ge "$OS_VERSION_ID" "2023"; then
        die "Amazon Linux $OS_VERSION_ID not supported; please use Amazon Linux 2023 or newer"
      fi
      ;;
    sles|suse|opensuse-leap|opensuse-tumbleweed)
      if ! version_ge "$OS_VERSION_ID" "15.6"; then
        die "SUSE/OpenSUSE $OS_VERSION_ID not supported; please use 15.6 or newer"
      fi
      ;;
    *)
      die "unsupported Linux distribution '$OS_ID'"
      ;;
  esac
}

setup_package_manager() {
  if command -v apt-get >/dev/null 2>&1; then
    PKG_MANAGER="apt"
    PKG_UPDATE_CMD="apt-get update -y"
    PKG_INSTALL_CMD="DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends"
    PKG_CHECK_CMD="dpkg -s"
  elif command -v dnf >/dev/null 2>&1; then
    PKG_MANAGER="dnf"
    PKG_UPDATE_CMD="dnf makecache -y"
    PKG_INSTALL_CMD="dnf install -y"
    PKG_CHECK_CMD="dnf list installed"
  elif command -v yum >/dev/null 2>&1; then
    PKG_MANAGER="yum"
    PKG_UPDATE_CMD="yum makecache -y"
    PKG_INSTALL_CMD="yum install -y"
    PKG_CHECK_CMD="yum list installed"
  elif command -v zypper >/dev/null 2>&1; then
    PKG_MANAGER="zypper"
    PKG_UPDATE_CMD="zypper -n ref"
    PKG_INSTALL_CMD="zypper -n install --allow-unsigned-rpm"
    PKG_CHECK_CMD="zypper se -i"
  else
    die "unable to determine package manager for distribution '$OS_ID'"
  fi
}

pkg_update_once() {
  if [[ -n "${PKG_UPDATE_DONE:-}" ]]; then
    return
  fi
  log_info "refreshing package metadata via ${PKG_MANAGER}"
  eval "$PKG_UPDATE_CMD" >/dev/null 2>&1 || log_warn "package metadata refresh failed; continuing anyway"
  PKG_UPDATE_DONE=1
}

pkg_installed() {
  local pkg=$1
  case "$PKG_MANAGER" in
    apt)
      dpkg -s "$pkg" >/dev/null 2>&1
      ;;
    dnf|yum)
      eval "$PKG_CHECK_CMD $pkg" >/dev/null 2>&1
      ;;
    zypper)
      zypper se -i "$pkg" >/dev/null 2>&1
      ;;
    *)
      return 1
      ;;
  esac
}

pkg_install() {
  local pkg=$1
  if pkg_installed "$pkg"; then
    return
  fi
  pkg_update_once
  log_info "installing missing dependency package '${pkg}'"
  if ! eval "$PKG_INSTALL_CMD $pkg" >/dev/null 2>&1; then
    die "failed to install required package '${pkg}'"
  fi
}

ensure_command_or_install() {
  local command_name=$1
  local deb_pkg=$2
  local rpm_pkg=${3:-$2}
  if command -v "$command_name" >/dev/null 2>&1; then
    return
  fi
  case "$PKG_MANAGER" in
    apt)
      [[ -n "$deb_pkg" ]] && pkg_install "$deb_pkg"
      ;;
    dnf|yum|zypper)
      [[ -n "$rpm_pkg" ]] && pkg_install "$rpm_pkg"
      ;;
  esac
  if ! command -v "$command_name" >/dev/null 2>&1; then
    die "missing required command '${command_name}' even after attempting installation"
  fi
}

ensure_base_dependencies() {
  ensure_command_or_install "curl" "curl"
  ensure_command_or_install "tar" "tar"
  ensure_command_or_install "gzip" "gzip"
  ensure_command_or_install "gpg" "gnupg" "gnupg2"
  ensure_command_or_install "lsb_release" "lsb-release" "redhat-lsb-core"
  ensure_command_or_install "install" "coreutils"
  pkg_install "ca-certificates"
  if ! command -v systemctl >/dev/null 2>&1; then
    die "systemctl is required but not available; ensure systemd is installed and active"
  fi
}

check_kernel_version() {
  local kernel
  kernel=$(uname -r | cut -d- -f1)
  if ! version_ge "$kernel" "$MIN_KERNEL"; then
    die "kernel version ${kernel} detected; requires ${MIN_KERNEL} or newer"
  fi
}

check_glibc_version() {
  if ! command -v ldd >/dev/null 2>&1; then
    die "'ldd' command not found; glibc tooling missing"
  fi
  local glibc_version
  glibc_version=$(ldd --version | head -n1 | awk '{print $NF}')
  if [[ -z "$glibc_version" ]]; then
    die "unable to determine glibc version"
  fi
  if ! version_ge "$glibc_version" "$MIN_GLIBC"; then
    die "glibc ${glibc_version} detected; requires ${MIN_GLIBC} or newer"
  fi
}

get_root_available_kb() {
  local kb=""
  if kb=$(df --output=avail / 2>/dev/null | tail -n1 | tr -d ' '); then
    :
  else
    kb=""
  fi
  if [[ -z "$kb" ]]; then
    if kb=$(df -Pk / 2>/dev/null | awk 'NR==2 {print $4}'); then
      :
    else
      kb=""
    fi
  fi
  printf '%s\n' "$kb"
}

check_resource_baseline() {
  local cpu_count mem_kb mem_mb disk_kb disk_gb
  if command -v nproc >/dev/null 2>&1; then
    cpu_count=$(nproc)
  else
    cpu_count=$(grep -c '^processor' /proc/cpuinfo || echo 1)
  fi
  if (( cpu_count < MIN_CPU_CORES )); then
    die "system has ${cpu_count} CPU core(s); requires at least ${MIN_CPU_CORES}"
  fi

  mem_kb=$(grep -i '^MemTotal:' /proc/meminfo | awk '{print $2}')
  mem_mb=$(( mem_kb / 1024 ))
  if (( mem_mb < MIN_MEMORY_MB )); then
    die "system memory ${mem_mb}MB is below required ${MIN_MEMORY_MB}MB"
  fi

  disk_kb=$(get_root_available_kb)
  if [[ -z "$disk_kb" ]]; then
    die "unable to determine available disk space on root filesystem"
  fi
  disk_gb=$(( disk_kb / 1024 / 1024 ))
  if (( disk_gb < MIN_DISK_GB )); then
    die "root filesystem free space ${disk_gb}GB is below required ${MIN_DISK_GB}GB"
  fi
}

detect_distribution
setup_package_manager
ensure_base_dependencies

log_info "detected distribution: ${OS_NAME} (${OS_ID} ${OS_VERSION_ID})"
log_info "using package manager: ${PKG_MANAGER}"

if [[ "$SKIP_REQUIREMENTS" == "1" ]]; then
  log_warn "ANYPROXY_IGNORE_REQUIREMENTS=1 set; skipping OS/kernel/resource checks"
else
  require_architecture
  enforce_supported_distribution
  check_kernel_version
  check_glibc_version
  check_resource_baseline
fi

ensure_systemctl_service() {
  local service=$1
  if command -v systemctl >/dev/null 2>&1; then
    systemctl enable --now "$service" >/dev/null 2>&1 || true
  fi
}

resolve_openresty_repo_release() {
  local distro=$1
  local release=$2
  local lowered
  lowered=$(echo "${release}" | tr '[:upper:]' '[:lower:]')
  case "$distro" in
    debian)
      case "$lowered" in
        bookworm|bullseye|buster) echo "$lowered"; return ;;
        trixie|testing|sid) echo "bookworm"; return ;;
      esac
      ;;
    ubuntu)
      case "$lowered" in
        jammy|focal|bionic) echo "$lowered"; return ;;
        noble|mantic|lunar|kinetic|impish|hirsute|groovy|eoan) echo "jammy"; return ;;
      esac
      ;;
  esac
  echo ""
}

install_openresty() {
  if command -v openresty >/dev/null 2>&1; then
    ensure_systemctl_service openresty
    return
  fi

  if command -v apt-get >/dev/null 2>&1; then
    local openresty_list="/etc/apt/sources.list.d/openresty.list"
    if [[ -f "$openresty_list" ]]; then
      echo "[anyproxy-install] removing stale OpenResty apt source ${openresty_list}"
      rm -f "$openresty_list"
    fi
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
    local normalized_release
    normalized_release=$(echo "${release}" | tr '[:upper:]' '[:lower:]')
    local repo_release
    repo_release=$(resolve_openresty_repo_release "$distro" "$normalized_release")
    if [[ -z "$repo_release" ]]; then
      echo "[anyproxy-install] unsupported ${distro} release '${release}' for OpenResty repository" >&2
      echo "[anyproxy-install] please install openresty manually and re-run this script" >&2
      exit 1
    fi
    if [[ "$repo_release" != "$normalized_release" ]]; then
      echo "[anyproxy-install] falling back to OpenResty '${repo_release}' packages for ${distro} '${release}'" >&2
    fi
    local keyring="/usr/share/keyrings/openresty-archive-keyring.gpg"
    mkdir -p /usr/share/keyrings
    if [[ -f "$keyring" ]]; then
      rm -f "$keyring"
    fi
    curl -fsSL https://openresty.org/package/pubkey.gpg | gpg --dearmor --batch --yes -o "$keyring"
    cat <<EOF >/etc/apt/sources.list.d/openresty.list
deb [signed-by=${keyring}] https://openresty.org/package/${distro} ${repo_release} openresty
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
VERSION="${ANYPROXY_VERSION:-latest}"
RELOAD_CMD="${ANYPROXY_RELOAD_CMD:-nginx -s reload}"
OUTPUT_PATH="${ANYPROXY_OUTPUT_PATH:-}"
STREAM_OUTPUT_PATH="${ANYPROXY_STREAM_OUTPUT_PATH:-}"
HAPROXY_RELOAD_CMD="${ANYPROXY_HAPROXY_RELOAD_CMD:-systemctl reload haproxy}"
CERT_DIR="${ANYPROXY_CERT_DIR:-}"
CLIENT_CA_DIR="${ANYPROXY_CLIENT_CA_DIR:-}"
AGENT_AUTH_TOKEN="${ANYPROXY_AGENT_TOKEN:-}"
NODE_NAME="${ANYPROXY_NODE_NAME:-}"
NODE_CATEGORY="${ANYPROXY_NODE_CATEGORY:-}"
NODE_GROUP_ID="${ANYPROXY_NODE_GROUP_ID:-}"
AGENT_VERSION="${ANYPROXY_AGENT_VERSION:-}"
AGENT_KEY="${ANYPROXY_AGENT_KEY:-}"
AGENT_KEY_FILE="${ANYPROXY_AGENT_KEY_FILE:-}"
TUNNEL_GROUP_ID="${ANYPROXY_TUNNEL_GROUP_ID:-}"
EDGE_CANDIDATES_RAW="${ANYPROXY_EDGE_CANDIDATES:-}"

usage() {
  cat <<'EOF'
Usage: edge-install.sh --control-plane URL --type edge|tunnel [--node NODE_ID] [--version VERSION] [--reload CMD] [--output PATH] [--stream-output PATH] [--node-name NAME] [--node-category KIND] [--group-id ID] [--cert-dir PATH] [--client-ca-dir PATH] [--agent-token TOKEN]

Environment overrides:
  ANYPROXY_CONTROL_PLANE default control plane URL
  ANYPROXY_NODE_TYPE     default node type (edge/tunnel)
  ANYPROXY_NODE_ID       default node ID
  ANYPROXY_VERSION       default version to install (fallback: latest)
  ANYPROXY_RELOAD_CMD    reload command for nginx/openresty (fallback: "nginx -s reload")
  ANYPROXY_OUTPUT_PATH   default HTTP config output path
  ANYPROXY_STREAM_OUTPUT_PATH default stream config output path
  ANYPROXY_HAPROXY_RELOAD_CMD reload command for haproxy (fallback: "systemctl reload haproxy")
  ANYPROXY_CERT_DIR      default certificate directory passed to agent
  ANYPROXY_CLIENT_CA_DIR client CA bundle directory passed to agent
  ANYPROXY_AGENT_VERSION optional agent semantic version override reported to control plane (default: auto-detect)
  ANYPROXY_AGENT_TOKEN   optional bearer token supplied to agent via -auth-token
  ANYPROXY_NODE_NAME     default node display name passed to agent
  ANYPROXY_NODE_CATEGORY default node category hint (cdn/tunnel)
  ANYPROXY_NODE_GROUP_ID default node group identifier
  ANYPROXY_STATUS_FILE   edge-agent 状态文件路径（默认 /var/lib/anyproxy/edge-status-<NODE_ID>.env）
  ANYPROXY_AGENT_KEY     tunnel nodes: agent key issued by control plane
  ANYPROXY_AGENT_KEY_FILE tunnel nodes: path to agent key file
  ANYPROXY_TUNNEL_GROUP_ID tunnel nodes: override tunnel group id
  ANYPROXY_EDGE_CANDIDATES tunnel nodes: comma separated edge candidates (host:port)
  ANYPROXY_IGNORE_REQUIREMENTS set to 1 to skip OS/CPU/memory/disk checks (NOT recommended)
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
    --agent-key)
      AGENT_KEY=${2:-}
      shift 2
      ;;
    --agent-key-file)
      AGENT_KEY_FILE=${2:-}
      shift 2
      ;;
    --edge)
      EDGE_CANDIDATES_RAW+="${EDGE_CANDIDATES_RAW:+,}${2:-}"
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
    --tunnel-group)
      TUNNEL_GROUP_ID=${2:-}
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

generate_node_id() {
  if command -v uuidgen >/dev/null 2>&1; then
    printf "node-%s\n" "$(uuidgen | tr 'A-Z' 'a-z')"
    return
  fi
  if [[ -r /proc/sys/kernel/random/uuid ]]; then
    printf "node-%s\n" "$(tr 'A-Z' 'a-z' </proc/sys/kernel/random/uuid)"
    return
  fi
  local ts random_hex
  ts=$(date +%s)
  if command -v od >/dev/null 2>&1; then
    random_hex=$(od -An -N4 -tx4 /dev/urandom 2>/dev/null | tr -d ' ')
  fi
  random_hex=${random_hex:-$RANDOM}
  printf "node-%s-%s\n" "$ts" "$random_hex"
}

NODE_ID="$(echo "${NODE_ID}" | tr -d '[:space:]')"

if [[ -z $CONTROL_PLANE_URL || -z $NODE_TYPE ]]; then
  echo "[anyproxy-install] missing required arguments" >&2
  usage
fi

if [[ -z $NODE_ID ]]; then
  NODE_ID=$(generate_node_id)
  echo "[anyproxy-install] generated node id: ${NODE_ID}"
fi

EDGE_STATUS_FILE="${ANYPROXY_STATUS_FILE:-/var/lib/anyproxy/edge-status-${NODE_ID}.env}"
mkdir -p "$(dirname "$EDGE_STATUS_FILE")"

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

EDGE_CANDIDATES=()
if [[ -n $EDGE_CANDIDATES_RAW ]]; then
  IFS=',' read -ra EDGE_CANDIDATES <<<"${EDGE_CANDIDATES_RAW}"
fi

if [[ -z $TUNNEL_GROUP_ID ]]; then
  TUNNEL_GROUP_ID=$NODE_GROUP_ID
fi

if [[ "$NODE_TYPE" == "edge" ]]; then
  install_openresty
  install_haproxy_pkg
fi

TMPDIR=$(mktemp -d)
cleanup() {
  rm -rf "$TMPDIR"
}
trap cleanup EXIT

quote_var() {
  local key=$1
  local value=${2-}
  printf 'export %s=%q\n' "$key" "$value"
}

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
      printf " \\\\\n  %q" "$arg"
    done
    echo
    echo "Restart=always"
    echo "RestartSec=5"
    echo
    echo "[Install]"
    echo "WantedBy=multi-user.target"
  } >"$service_path"
}

install_edgectl_cli() {
  local url="${CONTROL_PLANE_URL}/install/edgectl.sh"
  if ! curl -fsSL "$url" -o "$EDGECTL_BIN_PATH"; then
    log_warn "下载 edgectl 失败：${url}"
    return
  fi
  chmod 0755 "$EDGECTL_BIN_PATH"
  log_info "edgectl 安装到 ${EDGECTL_BIN_PATH}"
}

write_edgectl_state() {
  local state_dir
  state_dir=$(dirname "$EDGECTL_STATE_FILE")
  mkdir -p "$state_dir"
  local install_url="${CONTROL_PLANE_URL}/install/edge-install.sh"
  local uninstall_url="${CONTROL_PLANE_URL}/install/edge-uninstall.sh"
  {
    echo "# 自动生成，请勿手动修改"
    quote_var "ANYPROXY_CONTROL_PLANE" "$CONTROL_PLANE_URL"
    quote_var "ANYPROXY_NODE_TYPE" "$NODE_TYPE"
    quote_var "ANYPROXY_NODE_ID" "$NODE_ID"
    quote_var "ANYPROXY_NODE_NAME" "$NODE_NAME"
    quote_var "ANYPROXY_NODE_CATEGORY" "$NODE_CATEGORY"
    quote_var "ANYPROXY_NODE_GROUP_ID" "$NODE_GROUP_ID"
    quote_var "ANYPROXY_VERSION" "$VERSION"
    quote_var "ANYPROXY_RELOAD_CMD" "$RELOAD_CMD"
    quote_var "ANYPROXY_OUTPUT_PATH" "$OUTPUT_PATH"
    quote_var "ANYPROXY_STREAM_OUTPUT_PATH" "$STREAM_OUTPUT_PATH"
    quote_var "ANYPROXY_HAPROXY_RELOAD_CMD" "$HAPROXY_RELOAD_CMD"
    quote_var "ANYPROXY_CERT_DIR" "$CERT_DIR"
    quote_var "ANYPROXY_CLIENT_CA_DIR" "$CLIENT_CA_DIR"
    quote_var "ANYPROXY_AGENT_TOKEN" "$AGENT_AUTH_TOKEN"
    quote_var "ANYPROXY_AGENT_VERSION" "$AGENT_VERSION"
    quote_var "ANYPROXY_EDGE_CANDIDATES" "$EDGE_CANDIDATES_RAW"
    quote_var "ANYPROXY_STATUS_FILE" "$EDGE_STATUS_FILE"
    quote_var "EDGE_STATE_SERVICE_NAME" "$EDGE_SERVICE_NAME"
    quote_var "EDGE_STATE_INSTALL_URL" "$install_url"
    quote_var "EDGE_STATE_UNINSTALL_URL" "$uninstall_url"
    quote_var "EDGE_STATE_BIN_PATH" "$EDGECTL_BIN_PATH"
    quote_var "EDGE_STATE_STATUS_FILE" "$EDGE_STATUS_FILE"
  } >"$EDGECTL_STATE_FILE"
  chmod 600 "$EDGECTL_STATE_FILE"
  log_info "edgectl 状态写入 ${EDGECTL_STATE_FILE}"
}

cleanup_service_unit() {
  local service_name=$1
  local service_path="/etc/systemd/system/${service_name}"

  if [[ -z "$service_name" ]]; then
    return
  fi

  if systemctl list-unit-files "${service_name}" >/dev/null 2>&1 || [[ -f "$service_path" ]]; then
    log_info "stopping and removing legacy unit ${service_name}"
    systemctl stop "${service_name}" >/dev/null 2>&1 || true
    systemctl disable "${service_name}" >/dev/null 2>&1 || true
    rm -f "${service_path}"
    rm -rf "${service_path}.d"
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl reset-failed "${service_name}" >/dev/null 2>&1 || true
  fi
}

cleanup_binary_artifact() {
  local binary_path=$1
  if [[ -n "$binary_path" && -e "$binary_path" ]]; then
    log_info "removing legacy binary ${binary_path}"
    rm -f "$binary_path"
  fi
}

SERVICES=()

if [[ "$NODE_TYPE" == "edge" ]]; then
  EDGE_SERVICE_NAME="anyproxy-edge-${NODE_ID}.service"
  EDGE_INSTALL_PATH="/usr/local/bin/anyproxy-edge"
  cleanup_service_unit "$EDGE_SERVICE_NAME"
  cleanup_service_unit "anyproxy-edge.service"
  cleanup_binary_artifact "$EDGE_INSTALL_PATH"

  download_agent "edge"

  echo "[anyproxy-install] installing binary to ${EDGE_INSTALL_PATH}"
  install -m 0755 "${TMPDIR}/edge-agent" "$EDGE_INSTALL_PATH"

  EDGE_DEFAULT_OUTPUT="/etc/nginx/conf.d/anyproxy-${NODE_ID}.conf"
  EDGE_OUTPUT_PATH=${OUTPUT_PATH:-$EDGE_DEFAULT_OUTPUT}
  mkdir -p "$(dirname "$EDGE_OUTPUT_PATH")"
  EDGE_KEY_PATH="/etc/anyproxy/.anyproxy-node.key"

  if [[ -n $AGENT_AUTH_TOKEN && -f $EDGE_KEY_PATH ]]; then
    log_info "removing stale node key ${EDGE_KEY_PATH} before issuing new key"
    rm -f "$EDGE_KEY_PATH"
  fi

  STREAM_DEFAULT_OUTPUT="/etc/haproxy/haproxy.cfg"
  STREAM_OUTPUT_PATH=${STREAM_OUTPUT_PATH:-$STREAM_DEFAULT_OUTPUT}
  mkdir -p "$(dirname "$STREAM_OUTPUT_PATH")"

  EDGE_EXEC_ARGS=(
    "-control-plane" "${CONTROL_PLANE_URL}"
    "-node-id" "${NODE_ID}"
    "-output" "${EDGE_OUTPUT_PATH}"
    "-stream-output" "${STREAM_OUTPUT_PATH}"
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
  if [[ -n $AGENT_VERSION ]]; then
    EDGE_EXEC_ARGS+=("-agent-version" "${AGENT_VERSION}")
  fi
  EDGE_EXEC_ARGS+=("-node-key-path" "${EDGE_KEY_PATH}")
  EDGE_EXEC_ARGS+=("-status-file" "${EDGE_STATUS_FILE}")
  EDGE_EXEC_ARGS+=("-reload" "${RELOAD_CMD}")
  if [[ -n $HAPROXY_RELOAD_CMD ]]; then
    EDGE_EXEC_ARGS+=("-haproxy-reload" "${HAPROXY_RELOAD_CMD}")
  fi

  EDGE_SERVICE_PATH="/etc/systemd/system/${EDGE_SERVICE_NAME}"
  write_service "$EDGE_SERVICE_PATH" "AnyProxy edge agent (${NODE_ID})" "$EDGE_INSTALL_PATH" "${EDGE_EXEC_ARGS[@]}"
  echo "[anyproxy-install] systemd unit written to ${EDGE_SERVICE_PATH}"
  SERVICES+=("$EDGE_SERVICE_NAME")

  systemctl daemon-reload
  for svc in "${SERVICES[@]}"; do
    systemctl enable --now "$svc"
    systemctl status "$svc" --no-pager
  done

  echo "[anyproxy-install] installation complete."
  echo "[anyproxy-install] HTTP config renders to ${EDGE_OUTPUT_PATH}"
  echo "[anyproxy-install] Stream config renders to ${STREAM_OUTPUT_PATH}"

  install_edgectl_cli
  write_edgectl_state
elif [[ "$NODE_TYPE" == "tunnel" ]]; then
  TUNNEL_SERVICE_NAME="anyproxy-tunnel-${NODE_ID}.service"
  TUNNEL_INSTALL_PATH="/usr/local/bin/anyproxy-tunnel"
  cleanup_service_unit "$TUNNEL_SERVICE_NAME"
  cleanup_service_unit "anyproxy-tunnel.service"
  cleanup_binary_artifact "$TUNNEL_INSTALL_PATH"

  download_agent "tunnel"

  echo "[anyproxy-install] installing binary to ${TUNNEL_INSTALL_PATH}"
  install -m 0755 "${TMPDIR}/tunnel-agent" "$TUNNEL_INSTALL_PATH"

  if [[ -z $AGENT_KEY && -z $AGENT_KEY_FILE ]]; then
    echo "[anyproxy-install] ANYPROXY_AGENT_KEY or --agent-key is required for tunnel nodes" >&2
    exit 1
  fi

  KEY_FILE_PATH="$AGENT_KEY_FILE"
  if [[ -z $KEY_FILE_PATH ]]; then
    KEY_FILE_PATH="/etc/anyproxy/tunnel-agent.key"
    mkdir -p "$(dirname "$KEY_FILE_PATH")"
    printf '%s\n' "$AGENT_KEY" >"$KEY_FILE_PATH"
    chmod 600 "$KEY_FILE_PATH"
  fi

  TUNNEL_EXEC_ARGS=(
    "-control-plane" "${CONTROL_PLANE_URL}"
    "-node-id" "${NODE_ID}"
    "-agent-key-file" "${KEY_FILE_PATH}"
  )
  if [[ -n $TUNNEL_GROUP_ID ]]; then
    TUNNEL_EXEC_ARGS+=("-group-id" "${TUNNEL_GROUP_ID}")
  fi
  for edge in "${EDGE_CANDIDATES[@]}"; do
    edge="$(echo "$edge" | xargs)"
    if [[ -z $edge ]]; then
      continue
    fi
    TUNNEL_EXEC_ARGS+=("-edge" "$edge")
  done

  TUNNEL_SERVICE_PATH="/etc/systemd/system/${TUNNEL_SERVICE_NAME}"
  write_service "$TUNNEL_SERVICE_PATH" "AnyProxy tunnel agent (${NODE_ID})" "$TUNNEL_INSTALL_PATH" "${TUNNEL_EXEC_ARGS[@]}"
  echo "[anyproxy-install] systemd unit written to ${TUNNEL_SERVICE_PATH}"

  systemctl daemon-reload
  systemctl enable --now "$TUNNEL_SERVICE_NAME"
  systemctl status "$TUNNEL_SERVICE_NAME" --no-pager

  echo "[anyproxy-install] installation complete. Tunnel client running"
else
  echo "[anyproxy-install] unsupported node type: ${NODE_TYPE}" >&2
  exit 1
fi
