#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2026 Nero Duality, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Reproduce Release workflow package jobs locally with Docker/Podman.
#
# Usage:
#   bash .github/scripts/run-local-release-packages.sh --quick
#   bash .github/scripts/run-local-release-packages.sh --native
#   bash .github/scripts/run-local-release-packages.sh --cross armhf
#   bash .github/scripts/run-local-release-packages.sh --all
#
set -euo pipefail

usage() {
  cat <<'EOF'
Build Release-style .deb / .rpm packages locally (same script as GitHub Actions).

Usage:
  bash .github/scripts/run-local-release-packages.sh MODE [options]

Modes (pick one):
  --quick            Native amd64 .deb only (fast smoke; ~Release deb amd64)
  --native           Native amd64 deb + rpm (host/container amd64)
  --cross ARCH       One cross arch, deb + rpm (armhf|ppc64el|riscv64|s390x)
  --all-cross        All four cross arches, deb + rpm
  --all              Native amd64 deb+rpm + all cross deb+rpm (slow)

Options:
  --format FMT       deb, rpm, or both (default: both except --quick uses deb)
  --arch ARCH        With --native: amd64 only locally (arm64 needs arm64 runner)
  -h, --help         Help

Environment:
  CONTAINER_ENGINE              docker (default) or podman
  CI_PLATFORM                   Unset: linux/amd64 on x86_64, else linux/$host (e.g. arm64 on Pi).
                                Empty (CI_PLATFORM=): native pull. Set to override.
  PCSC_FIDO_LOCAL_CI_KEEP_BUILDS  Set to 1 to keep build/release-* trees

Examples:
  bash .github/scripts/run-local-release-packages.sh --quick
  bash .github/scripts/run-local-release-packages.sh --cross riscv64
  bash .github/scripts/run-local-release-packages.sh --native --format rpm

Artifacts land in dist/ (and build/release-*). Cross builds use debian:trixie
containers, matching .github/workflows/release.yml.

Native amd64 RPM files use the .x86_64.rpm suffix (not .amd64.rpm). --quick builds
amd64 .deb only; use --native or --release-arch amd64 for amd64 deb + rpm.

EOF
}

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=helper-cross-targets.sh
source "${SCRIPT_DIR}/helper-cross-targets.sh"
# shellcheck source=helper-container-bind-mount.sh
source "${SCRIPT_DIR}/helper-container-bind-mount.sh"

MODE=""
FORMAT=""
NATIVE_ARCH=amd64
CROSS_ARCH=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --quick)
      MODE=quick
      FORMAT=deb
      ;;
    --native)
      MODE=native
      ;;
    --cross)
      MODE=cross
      CROSS_ARCH="${2:-}"
      [[ -n ${CROSS_ARCH} ]] || {
        printf 'error: --cross requires an architecture\n' >&2
        exit 2
      }
      shift
      ;;
    --all-cross)
      MODE=all-cross
      ;;
    --all)
      MODE=all
      ;;
    --format)
      FORMAT="${2:-}"
      shift
      ;;
    --arch)
      NATIVE_ARCH="${2:-}"
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      printf 'error: unknown option %q\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

if [[ -z ${MODE} ]]; then
  usage >&2
  exit 2
fi

if [[ -z ${FORMAT} ]]; then
  FORMAT=both
fi

case "${FORMAT}" in
  deb | rpm | both) ;;
  *)
    printf 'error: unsupported format: %s\n' "${FORMAT}" >&2
    exit 2
    ;;
esac

ENGINE="${CONTAINER_ENGINE:-docker}"
if ! command -v "${ENGINE}" >/dev/null 2>&1; then
  printf 'error: %s not found (install or set CONTAINER_ENGINE)\n' "${ENGINE}" >&2
  exit 1
fi

# dist/ is append-only across invocations unless cleared here — avoids stale artifacts
# in the summary when running e.g. --release-arch riscv64 after --all-release.
PCSC_FIDO_RELEASE_BUILT=()
pcsc_fido_record_release_artifact() {
  local f base
  for f in "$@"; do
    [[ -f ${f} ]] || continue
    base="$(basename "${f}")"
    PCSC_FIDO_RELEASE_BUILT+=("${base}")
  done
}

PLATFORM_ARGS=()
pcsc_fido_load_ci_platform_args

chown_outputs() {
  pcsc_fido_restore_bind_mount_ownership build dist
}

run_native_package() {
  local arch="$1"
  local fmt="$2"
  local dist_before dist_after artifact
  if [[ ${arch} != amd64 ]]; then
    printf 'error: local native release builds support amd64 only (got %s)\n' "${arch}" >&2
    printf 'hint: arm64 release packages need an arm64 runner/CI; use --cross for other ports\n' >&2
    exit 2
  fi

  printf '\n── Release packages: native %s %s (debian:trixie-slim) ──\n' "${arch}" "${fmt}"
  dist_before="$(mktemp)"
  find "${REPO_ROOT}/dist" -maxdepth 1 -type f \( -name '*.deb' -o -name '*.rpm' \) -printf '%f\n' 2>/dev/null | sort >"${dist_before}" || true
  # shellcheck disable=SC2016
  pcsc_fido_run_bind_mount_container \
    --restore build dist -- \
    "${PLATFORM_ARGS[@]}" \
    -v "${REPO_ROOT}:/src" \
    -w /src \
    -e "HOST_UID=$(id -u)" \
    -e "HOST_GID=$(id -g)" \
    -e "AUTO_INSTALL_LINUX_DEPS=1" \
    debian:trixie-slim \
    bash -ceu '
      bash /src/.github/scripts/ci-bootstrap-container.sh
      bash /src/.github/scripts/release-build-package.sh --format "'"${fmt}"'" --arch "'"${arch}"'"
    '
  dist_after="$(mktemp)"
  find "${REPO_ROOT}/dist" -maxdepth 1 -type f \( -name '*.deb' -o -name '*.rpm' \) -printf '%f\n' 2>/dev/null | sort >"${dist_after}" || true
  while IFS= read -r artifact; do
    [[ -n ${artifact} ]] || continue
    if ! grep -Fxq "${artifact}" "${dist_before}"; then
      pcsc_fido_record_release_artifact "${REPO_ROOT}/dist/${artifact}"
    fi
  done <"${dist_after}"
  rm -f "${dist_before}" "${dist_after}"
}

run_cross_package() {
  local arch="$1"
  local fmt="$2"
  local dist_before dist_after artifact
  if ! pcsc_fido_is_cross_arch "${arch}"; then
    printf 'error: unsupported cross architecture: %s\n' "${arch}" >&2
    exit 2
  fi

  printf '\n── Release packages: cross %s %s (debian:trixie) ──\n' "${arch}" "${fmt}"
  dist_before="$(mktemp)"
  find "${REPO_ROOT}/dist" -maxdepth 1 -type f \( -name '*.deb' -o -name '*.rpm' \) -printf '%f\n' 2>/dev/null | sort >"${dist_before}" || true
  # shellcheck disable=SC2016
  pcsc_fido_run_bind_mount_container \
    --restore build dist -- \
    "${PLATFORM_ARGS[@]}" \
    -v "${REPO_ROOT}:/src" \
    -w /src \
    -e "HOST_UID=$(id -u)" \
    -e "HOST_GID=$(id -g)" \
    -e "AUTO_INSTALL_LINUX_DEPS=1" \
    debian:trixie \
    bash -ceu '
      bash /src/.github/scripts/release-build-package.sh --format "'"${fmt}"'" --arch "'"${arch}"'" --cross
    '
  dist_after="$(mktemp)"
  find "${REPO_ROOT}/dist" -maxdepth 1 -type f \( -name '*.deb' -o -name '*.rpm' \) -printf '%f\n' 2>/dev/null | sort >"${dist_after}" || true
  while IFS= read -r artifact; do
    [[ -n ${artifact} ]] || continue
    if ! grep -Fxq "${artifact}" "${dist_before}"; then
      pcsc_fido_record_release_artifact "${REPO_ROOT}/dist/${artifact}"
    fi
  done <"${dist_after}"
  rm -f "${dist_before}" "${dist_after}"
}

run_formats() {
  local kind="$1"
  local arch="$2"
  case "${FORMAT}" in
    deb) "${kind}" "${arch}" deb ;;
    rpm) "${kind}" "${arch}" rpm ;;
    both)
      "${kind}" "${arch}" deb
      "${kind}" "${arch}" rpm
      ;;
  esac
}

pcsc_fido_release_step=0
pcsc_fido_release_steps_expected() {
  case "${MODE}" in
    quick) printf '1\n' ;;
    native)
      case "${FORMAT}" in deb) printf '1\n' ;; rpm) printf '1\n' ;; both) printf '2\n' ;; esac
      ;;
    cross)
      case "${FORMAT}" in deb) printf '1\n' ;; rpm) printf '1\n' ;; both) printf '2\n' ;; esac
      ;;
    all-cross) printf '8\n' ;;
    all) printf '10\n' ;;
  esac
}

release_step_begin() {
  local label="$1"
  pcsc_fido_release_step=$((pcsc_fido_release_step + 1))
  local total
  total="$(pcsc_fido_release_steps_expected)"
  printf '\n[%s/%s] %s\n' "${pcsc_fido_release_step}" "${total}" "${label}"
}

run_native_package_wrapped() {
  release_step_begin "native ${2} ${1}"
  run_native_package "$@"
}

run_cross_package_wrapped() {
  release_step_begin "cross ${2} ${1}"
  run_cross_package "$@"
}

mkdir -p "${REPO_ROOT}/dist"

case "${MODE}" in
  all | all-cross) ;;
  *)
    if compgen -G "${REPO_ROOT}/dist/*.deb" >/dev/null 2>&1 ||
      compgen -G "${REPO_ROOT}/dist/*.rpm" >/dev/null 2>&1; then
      printf 'note: clearing dist/ before this run (previous release artifacts removed)\n'
      rm -f "${REPO_ROOT}/dist"/*.deb "${REPO_ROOT}/dist"/*.rpm 2>/dev/null || true
    fi
    ;;
esac

case "${MODE}" in
  quick)
    release_step_begin "native amd64 deb"
    run_native_package amd64 deb
    ;;
  native)
    run_formats run_native_package_wrapped "${NATIVE_ARCH}"
    ;;
  cross)
    run_formats run_cross_package_wrapped "${CROSS_ARCH}"
    ;;
  all-cross)
    for arch in "${PCSC_FIDO_CROSS_ARCHES[@]}"; do
      run_formats run_cross_package_wrapped "${arch}"
    done
    ;;
  all)
    run_formats run_native_package_wrapped amd64
    for arch in "${PCSC_FIDO_CROSS_ARCHES[@]}"; do
      run_formats run_cross_package_wrapped "${arch}"
    done
    ;;
esac

chown_outputs 2>/dev/null || true

printf '\n── Release package builds finished ──\n'
printf '  output dir: %s\n' "${REPO_ROOT}/dist"
if ((${#PCSC_FIDO_RELEASE_BUILT[@]} > 0)); then
  printf '  built this run (%s):\n' "${#PCSC_FIDO_RELEASE_BUILT[@]}"
  for artifact in "${PCSC_FIDO_RELEASE_BUILT[@]}"; do
    ls -la "${REPO_ROOT}/dist/${artifact}"
  done
else
  printf '  (no new artifacts recorded)\n'
  ls -la "${REPO_ROOT}/dist" 2>/dev/null || true
fi
