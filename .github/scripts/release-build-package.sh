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

# Build a native or cross-compiled release package with CPack.
# Native builds (amd64, arm64): run ctest before packaging.
# Cross builds (--cross): SKIP_CTEST=1, BUILD_TESTING=OFF — unit tests skipped.
#
# Usage:
#   bash .github/scripts/release-build-package.sh --format deb --arch amd64
#   bash .github/scripts/release-build-package.sh --format deb --arch armhf --cross
#   bash .github/scripts/release-build-package.sh --format rpm --arch riscv64 --cross

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=helper-cross-targets.sh
source "${SCRIPT_DIR}/helper-cross-targets.sh"
# shellcheck source=helper-container-bind-mount.sh
source "${SCRIPT_DIR}/helper-container-bind-mount.sh"

FORMAT=""
ARCH=""
CROSS=0
BUILD_DIR=""
DIST_DIR="${ROOT}/dist"

usage() {
  cat <<'EOF'
Usage: release-build-package.sh --format deb|rpm --arch ARCH [--cross] [--build-dir DIR]

Architectures:
  Native release builds: amd64, arm64
  Cross release builds:  armhf, ppc64el, riscv64, s390x (--cross required)

Environment:
  SKIP_CTEST=1     Skip ctest (forced for cross builds)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --format)
      FORMAT="${2:-}"
      shift 2
      ;;
    --arch)
      ARCH="${2:-}"
      shift 2
      ;;
    --cross)
      CROSS=1
      shift
      ;;
    --build-dir)
      BUILD_DIR="${2:-}"
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      printf 'error: unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z $FORMAT || -z $ARCH ]]; then
  usage >&2
  exit 2
fi

case "$FORMAT" in
  deb | rpm) ;;
  *)
    printf 'error: unsupported format: %s\n' "$FORMAT" >&2
    exit 2
    ;;
esac

if [[ $CROSS -eq 1 ]]; then
  if ! pcsc_fido_is_cross_arch "$ARCH"; then
    printf 'error: --cross requires armhf, ppc64el, riscv64, or s390x\n' >&2
    exit 2
  fi
else
  if ! pcsc_fido_is_native_release_arch "$ARCH"; then
    printf 'error: native release builds support amd64 and arm64 only (use --cross for %s)\n' "$ARCH" >&2
    exit 2
  fi
fi

if [[ -z $BUILD_DIR ]]; then
  BUILD_DIR="${ROOT}/build/release-${FORMAT}-${ARCH}"
fi

mkdir -p "$DIST_DIR"

if [[ $(id -u) -eq 0 && -n ${HOST_UID:-} && ${PCSC_FIDO_CI_AS_USER:-0} != 1 ]]; then
  if [[ $CROSS -eq 1 ]]; then
    bash "${SCRIPT_DIR}/install-cross-deps.sh" "$ARCH"
  else
    bash "${SCRIPT_DIR}/install-linux-deps.sh"
  fi
  if [[ $FORMAT == "rpm" ]] && command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get install -y rpm
  fi
  drop_args=(--format "$FORMAT" --arch "$ARCH")
  [[ $CROSS -eq 1 ]] && drop_args+=(--cross)
  [[ -n $BUILD_DIR ]] && drop_args+=(--build-dir "$BUILD_DIR")
  pcsc_fido_prepare_bind_mount_paths "${ROOT}"
  pcsc_fido_require_drop_to_host_user bash "${SCRIPT_DIR}/release-build-package.sh" "${drop_args[@]}"
fi

pcsc_fido_refuse_root_bind_mount_writes

if [[ $FORMAT == "rpm" ]] && command -v apt-get >/dev/null 2>&1 && ! command -v rpmbuild >/dev/null 2>&1; then
  if [[ ${EUID} -eq 0 ]]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get install -y rpm
  else
    printf 'error: rpmbuild missing; install rpm package or run in container\n' >&2
    exit 1
  fi
fi

CMAKE_ARGS=(
  -S "$ROOT"
  -B "$BUILD_DIR"
  -DCMAKE_BUILD_TYPE=Release
  -DCMAKE_INSTALL_PREFIX=/usr
)

if [[ $CROSS -eq 1 ]]; then
  if [[ ${PCSC_FIDO_CI_AS_USER:-0} == 1 ]]; then
    :
  else
    bash "${SCRIPT_DIR}/install-cross-deps.sh" "$ARCH"
  fi
  CMAKE_ARGS+=(
    -DCMAKE_TOOLCHAIN_FILE="${ROOT}/cmake/toolchains/linux-cross-${ARCH}.cmake"
    -DBUILD_TESTING=OFF
  )
  SKIP_CTEST=1
elif [[ ${AUTO_INSTALL_LINUX_DEPS:-1} != "0" ]]; then
  bash "${SCRIPT_DIR}/install-linux-deps.sh"
  CMAKE_ARGS+=(-DBUILD_TESTING=ON)
fi

cmake "${CMAKE_ARGS[@]}"
printf '── compiler: %s ──\n' "$("${CC:-gcc}" --version | head -n1)"
cmake --build "$BUILD_DIR" -j"$(nproc 2>/dev/null || echo 2)"

if [[ ${SKIP_CTEST:-0} != "1" ]]; then
  timeout 180 ctest --test-dir "$BUILD_DIR" --output-on-failure
fi

(
  cd "$BUILD_DIR"
  cpack -G "${FORMAT^^}"
)

mapfile -t artifacts < <(find "$BUILD_DIR" -maxdepth 1 -type f \( -name "*.deb" -o -name "*.rpm" \) -print)
if [[ ${#artifacts[@]} -eq 0 ]]; then
  printf 'error: no %s artifact produced under %s\n' "$FORMAT" "$BUILD_DIR" >&2
  exit 1
fi

cp -f "${artifacts[@]}" "$DIST_DIR/"

binary="${BUILD_DIR}/pcsc-fido"
if [[ ! -x $binary ]]; then
  printf 'error: expected binary at %s\n' "$binary" >&2
  exit 1
fi

if [[ $CROSS -eq 1 ]]; then
  pattern="$(pcsc_fido_cross_file_glob "$ARCH")"
  if ! file -b "$binary" | grep -Eiq "$pattern"; then
    printf 'error: %s does not look like a %s binary:\n  %s\n' "$binary" "$ARCH" "$(file -b "$binary")" >&2
    exit 1
  fi
fi

printf '── release-build-package: %s %s complete ──\n' "$FORMAT" "$ARCH"
printf '  artifacts: %s\n' "${artifacts[*]}"
