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

# Debian + Fedora container matrix (Debug unit tests + scan-build). Part of ``--main`` in
# run-local-ci-suite.sh; runnable alone when you only want the matrix.
#
# Usage:
#   bash .github/scripts/run-local-container-matrix.sh
#   bash .github/scripts/run-local-container-matrix.sh --debian-only
#   bash .github/scripts/run-local-container-matrix.sh --skip-openssf
#
set -euo pipefail

usage() {
  cat <<'EOF'
Reproduce the Main CI container matrix locally (Docker or Podman).

Usage:
  bash .github/scripts/run-local-container-matrix.sh [options]

Options:
  --all           Run Debian then Fedora (default)
  --debian-only   debian:trixie-slim only
  --fedora-only   fedora:43 only
  --skip-openssf  Skip OpenSSF Scorecard after the matrix
  -h, --help      Help

Environment:
  CONTAINER_ENGINE          docker (default) or podman
  CI_PLATFORM               Unset: linux/amd64 on x86_64, else linux/$host (e.g. arm64 on Pi).
                            Empty: native pull (no --platform). Set linux/amd64 to force amd64.
  PCSC_FIDO_LOCAL_CI_KEEP_BUILDS  Set to 1 to skip deleting build/ on the bind mount.
  SKIP_OPENSSF              Set to 1 to skip OpenSSF Scorecard (same as --skip-openssf)

Related:
  run-local-ci-suite.sh           Full presets (lint, matrix, coverage, release, …)
  run-local-line-coverage.sh      gcov/lcov HTML under build/coverage-html/
  run-local-release-packages.sh   Release .deb/.rpm builds into dist/

EOF
}

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=helper-container-bind-mount.sh
source "${SCRIPT_DIR}/helper-container-bind-mount.sh"

RUN_DEBIAN=1
RUN_FEDORA=1
SKIP_OPENSSF="${SKIP_OPENSSF:-0}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --all)
      RUN_DEBIAN=1
      RUN_FEDORA=1
      ;;
    --debian-only)
      RUN_DEBIAN=1
      RUN_FEDORA=0
      ;;
    --fedora-only)
      RUN_DEBIAN=0
      RUN_FEDORA=1
      ;;
    --skip-openssf)
      SKIP_OPENSSF=1
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      printf 'error: unknown option %q\n' "$1" >&2
      usage >&2
      exit 1
      ;;
  esac
  shift
done

ENGINE="${CONTAINER_ENGINE:-docker}"
if ! command -v "${ENGINE}" >/dev/null 2>&1; then
  printf 'error: %s not found (install or set CONTAINER_ENGINE)\n' "${ENGINE}" >&2
  exit 1
fi

PLATFORM_ARGS=()
pcsc_fido_load_ci_platform_args
_resolved_platform="$(pcsc_fido_resolve_ci_platform)"
case "$(uname -m)" in
  x86_64 | amd64) ;;
  *)
    if [[ -n ${_resolved_platform} ]]; then
      printf 'note: container platform %s (host %s); CI_PLATFORM=linux/amd64 only with QEMU\n' \
        "${_resolved_platform}" "$(uname -m)"
    else
      printf 'note: container platform native (host %s)\n' "$(uname -m)"
    fi
    ;;
esac

run_in_image() {
  local image="$1"
  local label="$2"
  printf '\n── %s (%s) ──\n' "${label}" "${image}"
  # shellcheck disable=SC2016
  pcsc_fido_run_bind_mount_container \
    -- \
    "${PLATFORM_ARGS[@]}" \
    -v "${REPO_ROOT}:/src" \
    -w /src \
    -e "HOST_UID=$(id -u)" \
    -e "HOST_GID=$(id -g)" \
    -e "AUTO_INSTALL_LINUX_DEPS=1" \
    "${image}" \
    bash -ceu '
      if [[ "${PCSC_FIDO_LOCAL_CI_KEEP_BUILDS:-0}" != "1" ]]; then
        rm -rf /src/build /src/scan-build-report 2>/dev/null || true
      fi
      bash /src/.github/scripts/ci-bootstrap-container.sh
      cd /src
      bash .github/scripts/ci-run-tests.sh
    '
}

if [[ ${RUN_DEBIAN} -eq 1 ]]; then
  run_in_image debian:trixie-slim "Debian trixie"
fi
if [[ ${RUN_FEDORA} -eq 1 ]]; then
  run_in_image fedora:43 "Fedora 43"
fi

if [[ ${SKIP_OPENSSF} -eq 0 ]]; then
  bash "${SCRIPT_DIR}/run-local-openssf.sh"
else
  printf '\n(skip OpenSSF Scorecard)\n'
fi

printf '\n── container matrix finished successfully ──\n'
