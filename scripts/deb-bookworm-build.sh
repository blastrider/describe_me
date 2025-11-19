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
DEB_FEATURES=${DEB_FEATURES:-"cli web config systemd net journald"}
HOST_UID=$(id -u)
HOST_GID=$(id -g)
HOST_USER_NAME=$(id -un 2>/dev/null || echo builder)
HOST_GROUP_NAME=$(id -gn 2>/dev/null || echo builder)

read -r -d '' CONTAINER_SCRIPT <<'EOF' || true
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends curl ca-certificates build-essential pkg-config git

HOST_UID="${HOST_UID:-0}"
HOST_GID="${HOST_GID:-0}"
HOST_USER_NAME="${HOST_USER_NAME:-builduser}"
HOST_GROUP_NAME="${HOST_GROUP_NAME:-builduser}"
DEB_FEATURES="${DEB_FEATURES:-cli web config systemd net journald}"

BUILD_USER="root"
BUILD_HOME="/root"

if [ "${HOST_UID}" -ne 0 ]; then
  if getent group "${HOST_GID}" >/dev/null 2>&1; then
    HOST_GROUP_NAME="$(getent group "${HOST_GID}" | cut -d: -f1)"
  else
    if getent group "${HOST_GROUP_NAME}" >/dev/null 2>&1; then
      HOST_GROUP_NAME="host-${HOST_GID}"
    fi
    groupadd --gid "${HOST_GID}" "${HOST_GROUP_NAME}"
  fi

  if getent passwd "${HOST_UID}" >/dev/null 2>&1; then
    HOST_USER_NAME="$(getent passwd "${HOST_UID}" | cut -d: -f1)"
  else
    if id -u "${HOST_USER_NAME}" >/dev/null 2>&1; then
      HOST_USER_NAME="host-${HOST_UID}"
    fi
    useradd --uid "${HOST_UID}" --gid "${HOST_GID}" --create-home --shell /bin/bash "${HOST_USER_NAME}"
  fi

  BUILD_USER="${HOST_USER_NAME}"
  BUILD_HOME="$(getent passwd "${HOST_UID}" | cut -d: -f6)"
fi

cat >/tmp/build.sh <<'BUILD_SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
cd /workspace
export HOME="${BUILD_HOME}"
export USER="${BUILD_USER_NAME}"
export CARGO_HOME="${HOME}/.cargo"
export RUSTUP_HOME="${HOME}/.rustup"
export CARGO_TARGET_DIR=/workspace/target
mkdir -p "${CARGO_HOME}" "${RUSTUP_HOME}" "${CARGO_TARGET_DIR}"

if [ ! -f "${CARGO_HOME}/bin/cargo" ]; then
  curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
fi

# shellcheck disable=SC1091
source "${CARGO_HOME}/env"

if ! command -v cargo-deb >/dev/null 2>&1; then
  cargo install --locked cargo-deb
fi

cargo build --release --features "${DEB_FEATURES}"

if [ -d plugin-examples/certificates ]; then
  cargo build --release --manifest-path plugin-examples/certificates/Cargo.toml
fi

cargo deb --features "${DEB_FEATURES}" --no-build
BUILD_SCRIPT
chmod +x /tmp/build.sh

if [ "${BUILD_USER}" = "root" ]; then
  BUILD_HOME="${BUILD_HOME}" BUILD_USER_NAME="${BUILD_USER}" DEB_FEATURES="${DEB_FEATURES}" bash /tmp/build.sh
else
  mkdir -p /workspace/target
  chown -R "${HOST_UID}:${HOST_GID}" /workspace/target || true
  runuser -u "${BUILD_USER}" -- env BUILD_HOME="${BUILD_HOME}" BUILD_USER_NAME="${BUILD_USER}" DEB_FEATURES="${DEB_FEATURES}" bash /tmp/build.sh
fi
EOF

echo "[deb] Building describe_me .deb inside ${IMAGE} using ${ENGINE}"

"${ENGINE}" run --rm -t \
  -v "${PROJECT_ROOT}:/workspace" \
  -w /workspace \
  -e CARGO_TARGET_DIR=/workspace/target \
  -e HOST_UID="${HOST_UID}" \
  -e HOST_GID="${HOST_GID}" \
  -e HOST_USER_NAME="${HOST_USER_NAME}" \
  -e HOST_GROUP_NAME="${HOST_GROUP_NAME}" \
  -e DEB_FEATURES="${DEB_FEATURES}" \
  "${IMAGE}" \
  bash -c "${CONTAINER_SCRIPT}"

chown -R "${HOST_UID}:${HOST_GID}" "${TARGET_DIR}" || true

echo "[deb] Artifacts available under ${TARGET_DIR}/debian/"
