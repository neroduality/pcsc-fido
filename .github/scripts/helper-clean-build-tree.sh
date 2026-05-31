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

# Remove build output; recover from root-owned container CI artifacts when needed.
#
# Usage (from pcsc-fido root):
#   bash .github/scripts/helper-clean-build-tree.sh [build-dir ...]
# With no args, removes build/ plus every repo-root build-* directory.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=helper-build-tree-ownership.sh
source "${SCRIPT_DIR}/helper-build-tree-ownership.sh"

paths=("$@")
if [[ ${#paths[@]} -eq 0 ]]; then
  paths=(build)
fi

pcsc_fido_refuse_root_make

pcsc_fido_remove_build_tree() {
  local build_dir="$1"
  local target="${REPO_ROOT}/${build_dir}"
  if [[ ! -e ${target} ]]; then
    return 0
  fi
  pcsc_fido_repair_tree_ownership "${target}"
  if rm -rf "${target}" 2>/dev/null; then
    return 0
  fi
  pcsc_fido_local_repair_tree_for_removal "${target}"
  if rm -rf "${target}" 2>/dev/null; then
    return 0
  fi
  if pcsc_fido_uses_container_ownership_restore "${build_dir}"; then
    printf 'warning: %s is not fully removable as %s; restoring ownership from container CI\n' \
      "${build_dir}" "$(id -un)" >&2
    bash "${SCRIPT_DIR}/helper-restore-bind-mount-ownership.sh" "${build_dir}"
    rm -rf "${target}"
    return 0
  fi
  printf 'error: cannot remove %s as %s (not a container CI tree; fix permissions manually)\n' \
    "${build_dir}" "$(id -un)" >&2
  return 1
}

declare -A pcsc_fido_clean_seen=()
pcsc_fido_queue_clean_path() {
  local rel="$1"
  [[ -n ${rel} ]] || return 0
  [[ -n ${pcsc_fido_clean_seen[${rel}]+x} ]] && return 0
  pcsc_fido_clean_seen["${rel}"]=1
}

for build_dir in "${paths[@]}"; do
  pcsc_fido_queue_clean_path "${build_dir}"
done

# Ad-hoc out-of-tree CMake dirs (e.g. BUILD_DIR=build-install-test from install smoke tests).
shopt -s nullglob
for extra in "${REPO_ROOT}"/build-*; do
  pcsc_fido_queue_clean_path "$(basename "${extra}")"
done
shopt -u nullglob

for build_dir in "${!pcsc_fido_clean_seen[@]}"; do
  pcsc_fido_remove_build_tree "${build_dir}"
done

rm -rf "${REPO_ROOT}/scan-build-report" 2>/dev/null || true
