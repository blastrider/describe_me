#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPEC_FILE="${ROOT_DIR}/packaging/rpm/describe_me.spec"
TOPDIR="${ROOT_DIR}/target/rpmbuild-fedora"
RPM_FEATURES="${RPM_FEATURES:-cli web config systemd net journald}"
HOST_UID="${HOST_UID:-0}"
HOST_GID="${HOST_GID:-0}"
TARBALL_NAME=
TARBALL_PATH=

echo "[deps] installing build tooling"
dnf -y install rpm-build rpmdevtools git gcc make rust cargo systemd-rpm-macros gzip tar

VERSION="$(awk -F '\"' '/^version = /{print $2; exit}' "${ROOT_DIR}/Cargo.toml")"
if [ -z "${VERSION}" ]; then
  echo "Unable to detect version from Cargo.toml" >&2
  exit 1
fi
TARBALL_NAME="describe-me-${VERSION}.tar.gz"
TARBALL_PATH="${TOPDIR}/SOURCES/${TARBALL_NAME}"

git config --global --add safe.directory "${ROOT_DIR}"

echo "[prep] staging sources for describe-me ${VERSION}"
rm -rf "${TOPDIR}"
mkdir -p "${TOPDIR}"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
(
  cd "${ROOT_DIR}"
  tar --exclude-vcs --exclude='./target' --exclude='./.git' \
    --transform "s,^./,describe-me-${VERSION}/," \
    -czf "${TARBALL_PATH}" .
)
if [ ! -f "${TARBALL_PATH}" ]; then
  echo "Tarball ${TARBALL_PATH} not found after git archive" >&2
  exit 1
fi

echo "[build] rpmbuild -ba (features: ${RPM_FEATURES})"
rpmbuild -ba "${SPEC_FILE}" \
  --define "_topdir ${TOPDIR}" \
  --define "_sourcedir ${TOPDIR}/SOURCES" \
  --define "_srcrpmdir ${TOPDIR}/SRPMS" \
  --define "_rpmdir ${TOPDIR}/RPMS" \
  --define "cargo_features ${RPM_FEATURES}" \
  --define "project_version ${VERSION}"

if [ "$(id -u)" -eq 0 ]; then
  chown -R "${HOST_UID}:${HOST_GID}" "${TOPDIR}"
fi

echo "[done] RPMs are in ${TOPDIR}/RPMS"
