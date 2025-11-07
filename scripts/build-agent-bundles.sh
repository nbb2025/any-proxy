#!/usr/bin/env bash

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <version> [output-dir]" >&2
  exit 1
fi

VERSION="$1"
OUTPUT_DIR="${2:-install/binaries/${VERSION}}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${ROOT_DIR}/${OUTPUT_DIR}"

build_agent() {
  local agent=$1
  local bin="${TMP_DIR}/${agent}-agent"
  echo "[build-agent-bundles] building ${agent} agent for linux/amd64"
  (cd "${ROOT_DIR}" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "${bin}" "./cmd/${agent}-agent")
  local archive="${ROOT_DIR}/${OUTPUT_DIR}/${agent}_linux_amd64.tar.gz"
  tar -czf "${archive}" -C "${TMP_DIR}" "${agent}-agent"
  sha256sum "${archive}" > "${archive}.sha256"
  echo "[build-agent-bundles] wrote ${archive} (+ .sha256)"
}

build_agent "edge"
build_agent "tunnel"

echo "[build-agent-bundles] bundles ready under ${OUTPUT_DIR}"
