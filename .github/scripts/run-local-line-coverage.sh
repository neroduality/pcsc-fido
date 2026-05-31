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

# Build with gcov, run CTest, and emit an lcov HTML report under build/coverage-html/.
#
# Usage:
#   bash .github/scripts/run-local-line-coverage.sh
#   bash .github/scripts/run-local-line-coverage.sh --no-open
#   CONTAINER_ENGINE=podman bash .github/scripts/run-local-line-coverage.sh --in-container
#
set -euo pipefail

usage() {
  cat <<'EOF'
Generate gcov/lcov line coverage for pcsc-fido unit tests.

Usage:
  bash .github/scripts/run-local-line-coverage.sh [options]

Options:
  --in-container   Run inside debian:trixie-slim (default when lcov is missing)
  --host           Force host run (requires lcov + build deps on Linux)
  --no-open        Do not print xdg-open hint after success
  -h, --help       Help

Environment:
  CONTAINER_ENGINE          docker (default) or podman
  CI_PLATFORM               Unset: linux/amd64 on x86_64, else linux/$host (e.g. arm64 on Pi).
                            Empty (CI_PLATFORM=): native pull. Set to override.
  PCSC_FIDO_COVERAGE_DIR    HTML output (default: build/coverage-html)
  PCSC_FIDO_LOCAL_CI_KEEP_BUILDS  Set to 1 to keep build/coverage on bind mount
  AUTO_INSTALL_LINUX_DEPS   Default 0 (no sudo during local CI)

After a successful run:
  - Summary: printed to stdout (lcov --summary)
  - HTML report: build/coverage-html/index.html
  - Raw data: build/coverage/coverage.info

EOF
}

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=helper-container-bind-mount.sh
source "${SCRIPT_DIR}/helper-container-bind-mount.sh"

RUN_MODE=auto
OPEN_HINT=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --in-container)
      RUN_MODE=container
      ;;
    --host)
      RUN_MODE=host
      ;;
    --no-open)
      OPEN_HINT=0
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

pcsc_fido_run_coverage() {
  local repo_root="$1"
  local build_dir="${repo_root}/build/coverage"
  local coverage_dir="${PCSC_FIDO_COVERAGE_DIR:-${repo_root}/build/coverage-html}"
  local info_file="${build_dir}/coverage.info"
  local jobs
  jobs="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"

  if [[ $(id -u) -eq 0 && -n ${HOST_UID:-} && ${PCSC_FIDO_CI_AS_USER:-0} != 1 ]]; then
    export DEBIAN_FRONTEND=noninteractive
    if command -v apt-get >/dev/null 2>&1; then
      apt-get update -qq
      apt-get install -y --no-install-recommends lcov ca-certificates git util-linux
    fi
    bash "${repo_root}/.github/scripts/ci-bootstrap-container.sh"
    bash "${repo_root}/.github/scripts/install-linux-deps.sh"
    pcsc_fido_prepare_bind_mount_paths "${repo_root}"
    pcsc_fido_require_drop_to_host_user bash "${SCRIPT_DIR}/run-local-line-coverage.sh" --host --no-open
  fi

  pcsc_fido_refuse_root_bind_mount_writes

  if ! command -v lcov >/dev/null 2>&1; then
    printf 'error: lcov not found\n' >&2
    exit 1
  fi

  if [[ ${PCSC_FIDO_LOCAL_CI_KEEP_BUILDS:-0} != "1" ]]; then
    pcsc_fido_rm_repo_path "${repo_root}" "build/coverage"
    pcsc_fido_rm_repo_path "${repo_root}" "build/coverage-html"
    rm -rf "${repo_root}/coverage-html" 2>/dev/null || true
  fi

  cmake -S "${repo_root}" -B "${build_dir}" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DBUILD_TESTING=ON \
    -DPCSC_FIDO_ENABLE_COVERAGE=ON \
    -DPCSC_FIDO_DEBUG_SANITIZERS=OFF \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
  cmake --build "${build_dir}" --target pcsc_fido_unit_tests -j"${jobs}"
  ctest --test-dir "${build_dir}" --output-on-failure

  # gcov writes .gcda as execute-only on some hosts; lcov cannot read them without u+r.
  find "${build_dir}" -name '*.gcda' -exec chmod u+r {} + 2>/dev/null || true

  # lcov 2.x requires duplicated error names in --ignore-errors (e.g. unused,unused).
  lcov --quiet --ignore-errors inconsistent,inconsistent \
    --capture --directory "${build_dir}" --output-file "${info_file}.raw"
  lcov --quiet --ignore-errors inconsistent,inconsistent,unused,unused \
    --remove "${info_file}.raw" \
    '*/tests/*' \
    --output-file "${info_file}"

  genhtml --quiet "${info_file}" --output-directory "${coverage_dir}"

  printf '\n── Line coverage summary (src/ focus; tests excluded) ──\n'
  lcov --summary "${info_file}"

  printf '\n── Line coverage report ──\n'
  printf '  HTML: %s/index.html\n' "${coverage_dir}"
  printf '  lcov: %s\n' "${info_file}"
  if [[ ${OPEN_HINT} -eq 1 ]] && command -v xdg-open >/dev/null 2>&1; then
    printf '  open: xdg-open %s/index.html\n' "${coverage_dir}"
  fi
}

run_coverage_container() {
  local engine="${CONTAINER_ENGINE:-docker}"
  if ! command -v "${engine}" >/dev/null 2>&1; then
    printf 'error: %s not found\n' "${engine}" >&2
    return 1
  fi

  local platform_args=()
  pcsc_fido_load_ci_platform_args
  platform_args=("${PLATFORM_ARGS[@]}")

  pcsc_fido_run_bind_mount_container \
    --restore build -- \
    "${platform_args[@]}" \
    -v "${REPO_ROOT}:/src" \
    -w /src \
    -e "HOST_UID=$(id -u)" \
    -e "HOST_GID=$(id -g)" \
    -e "AUTO_INSTALL_LINUX_DEPS=1" \
    -e "PCSC_FIDO_LOCAL_CI_KEEP_BUILDS=${PCSC_FIDO_LOCAL_CI_KEEP_BUILDS:-0}" \
    debian:trixie-slim \
    bash /src/.github/scripts/run-local-line-coverage.sh --host --no-open
}

if [[ ${RUN_MODE} == host ]]; then
  AUTO_INSTALL_LINUX_DEPS="${AUTO_INSTALL_LINUX_DEPS:-0}" pcsc_fido_run_coverage "${REPO_ROOT}"
  exit 0
fi

if [[ ${RUN_MODE} == auto ]] && command -v "${CONTAINER_ENGINE:-docker}" >/dev/null 2>&1; then
  run_coverage_container
  if [[ ${OPEN_HINT} -eq 1 ]] && command -v xdg-open >/dev/null 2>&1; then
    printf '  open: xdg-open %s/build/coverage-html/index.html\n' "${REPO_ROOT}"
  fi
  exit 0
fi

if [[ ${RUN_MODE} == auto ]] && command -v lcov >/dev/null 2>&1 && [[ "$(uname -s)" == "Linux" ]]; then
  AUTO_INSTALL_LINUX_DEPS="${AUTO_INSTALL_LINUX_DEPS:-0}" pcsc_fido_run_coverage "${REPO_ROOT}"
  exit 0
fi

if [[ ${RUN_MODE} == container ]]; then
  run_coverage_container
  exit 0
fi

printf 'error: need docker/podman or host lcov\n' >&2
exit 1
