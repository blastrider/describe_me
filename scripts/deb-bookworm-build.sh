#!/usr/bin/env bash
set -euo pipefail

if ! command -v docker >/dev/null 2>&1 && ! command -v podman >/dev/null 2>&1; then
  echo "This helper requires docker or podman. Please install one of them."
  exit 1
fi

ENGINE=${CONTAINER_ENGINE:-}
if [[ -z "${ENGINE}" ]]; then
  if command -v docker >/dev/null 2>&1; then
    ENGINE=docker
  else
    ENGINE=podman
  fi
fi

IMAGE=${DEB_BUILD_IMAGE:-"debian:12"}
PROJECT_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"
TARGET_DIR="${PROJECT_ROOT}/target"

echo "[deb] Building describe_me .deb inside ${IMAGE} using ${ENGINE}"

"${ENGINE}" run --rm -t \
  -v "${PROJECT_ROOT}:/workspace" \
  -w /workspace \
  -e CARGO_TARGET_DIR=/workspace/target \
  "${IMAGE}" \
  bash -c '
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y --no-install-recommends curl ca-certificates build-essential pkg-config git
    if ! command -v cargo >/dev/null 2>&1; then
      curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
    fi
    source "$HOME/.cargo/env"
    if ! command -v cargo-deb >/dev/null 2>&1; then
      cargo install --locked cargo-deb
    fi
    cargo build --release --features "cli web config systemd net"
    if [ -d plugin-examples/certificates ]; then
      cargo build --release --manifest-path plugin-examples/certificates/Cargo.toml
    fi
    cargo deb --features "cli web config systemd net" --no-build
  '

echo "[deb] Artifacts available under ${TARGET_DIR}/debian/"
