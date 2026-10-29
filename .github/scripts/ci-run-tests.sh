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

# Shared CI entry: Debug unit tests (ASan+UBSan via PCSC_FIDO_DEBUG_SANITIZERS), a from-scratch
# unsanitized Debug `make test` (ctest, then the scrub-mutant sweep on build/unit), the same
# tests again in Release (LTO on top of the kit's native -O2), and scan-build.
# Always wipes CMake trees first (``make/wipe-host-build-trees.sh ci``) -- no cache reuse.
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

bash "${repo_root}/make/wipe-host-build-trees.sh" ci

build_dir="${repo_root}/build/ci"
jobs="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"

cmake -S "${repo_root}" -B "${build_dir}" \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -DBUILD_TESTING=ON \
  -DPCSC_FIDO_DEBUG_SANITIZERS=ON
cmake --build "${build_dir}" --target pcsc_fido_unit_tests -j"${jobs}"
ctest --test-dir "${build_dir}" --output-on-failure

# Fresh unsanitized Debug tree. build/ci has ASan+UBSan, and a mutant that
# merely crashes under ASan must not count as a killed wipe. `make test`
# wipes build/unit, configures -DPCSC_FIDO_DEBUG_SANITIZERS=OFF, runs ctest,
# then verify-scrub-mutants.sh.
make -C "${repo_root}" test INSTALL_DEPS=0 CMAKE_BUILD_TYPE=Debug

# Release-config pass: identical tests against the LTO objects that ship.
# The Debug trees above build at -O0: Hardening.cmake adds -O2, -fhardened and
# _FORTIFY_SOURCE only to Release-family configs. Here the same
# scrub-audit tests (-Wl,--wrap=pcsc_fido_secure_clear) prove the LTO callers
# still invoke the wipe primitive with the full buffer length on every exit
# path (a guard the optimizer dropped would show up as a missing call).
# What they do not prove is the primitive's own body -- that erasure is
# guaranteed by memset_explicit / explicit_bzero themselves; the volatile-loop
# tier is covered directly by test_mem_util_fallback.
release_build_dir="${repo_root}/build/ci-release"
cmake -S "${repo_root}" -B "${release_build_dir}" \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTING=ON
bash "${repo_root}/.github/scripts/verify-release-compile-flags.sh" "${release_build_dir}"
cmake --build "${release_build_dir}" --target pcsc_fido_unit_tests -j"${jobs}"
ctest --test-dir "${release_build_dir}" --output-on-failure

bash "${repo_root}/.github/scripts/ci-scan-build.sh"
