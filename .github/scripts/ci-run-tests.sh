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

# Shared CI entry: Debug unit tests (ASan+UBSan via PCSC_FIDO_DEBUG_SANITIZERS) and scan-build.
#
# Usage (from pcsc-fido root):
#   bash .github/scripts/ci-run-tests.sh
set -euo pipefail

repo_root="$(pwd)"
if [[ ! -f "${repo_root}/CMakeLists.txt" ]] || [[ ! -d "${repo_root}/src" ]]; then
  printf 'error: run from pcsc-fido root\n' >&2
  exit 1
fi

# shellcheck source=helper-container-bind-mount.sh
source "${repo_root}/.github/scripts/helper-container-bind-mount.sh"

if [[ $(id -u) -eq 0 && -n ${HOST_UID:-} && ${PCSC_FIDO_CI_AS_USER:-0} != 1 ]]; then
  bash "${repo_root}/.github/scripts/install-linux-deps.sh"
  pcsc_fido_prepare_bind_mount_paths "${repo_root}"
  pcsc_fido_require_drop_to_host_user bash "${repo_root}/.github/scripts/ci-run-tests.sh"
fi

pcsc_fido_refuse_root_bind_mount_writes

if [[ "$(uname -s)" == "Linux" ]]; then
  auto_install_linux_deps="${AUTO_INSTALL_LINUX_DEPS:-}"
  if [[ -z ${auto_install_linux_deps} ]]; then
    if [[ ${GITHUB_ACTIONS:-false} == true ]]; then
      auto_install_linux_deps=1
    else
      auto_install_linux_deps=0
    fi
  fi
  if [[ ${auto_install_linux_deps} != "0" ]]; then
    bash "${repo_root}/.github/scripts/install-linux-deps.sh"
  fi
fi

build_dir="${repo_root}/build/ci"
jobs="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"

if [[ ${PCSC_FIDO_LOCAL_CI_KEEP_BUILDS:-0} != "1" ]]; then
  pcsc_fido_rm_repo_path "${repo_root}" "build/ci"
fi

cmake -S "${repo_root}" -B "${build_dir}" \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -DBUILD_TESTING=ON
cmake --build "${build_dir}" --target pcsc_fido_unit_tests -j"${jobs}"
ctest --test-dir "${build_dir}" --output-on-failure

bash "${repo_root}/.github/scripts/ci-scan-build.sh"
