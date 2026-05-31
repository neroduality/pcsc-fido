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

# Traced build for CodeQL: CMake configure + build of pcsc-fido.
set -euo pipefail

repo_root="${PCSC_FIDO_ROOT:-$(pwd)}"
if [[ ! -f "${repo_root}/CMakeLists.txt" ]]; then
  printf 'error: PCSC_FIDO_ROOT must point at pcsc-fido root\n' >&2
  exit 1
fi

if [[ "$(uname -s)" == "Linux" && ${CODEQL_INSTALL_LINUX_DEPS:-0} == "1" ]]; then
  bash "${repo_root}/.github/scripts/install-linux-deps.sh"
fi

build_dir="${repo_root}/build/codeql"
jobs="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"

rm -rf "${build_dir}"
cmake -S "${repo_root}" -B "${build_dir}" -DCMAKE_BUILD_TYPE=Release
cmake --build "${build_dir}" --parallel "${jobs}"

printf '── CodeQL traced build complete ──\n'
