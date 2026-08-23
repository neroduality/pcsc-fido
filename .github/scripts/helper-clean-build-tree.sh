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

# Remove build output and local tool caches (nero-nfc-style: plain rm -rf).
# Bind-mounted local container CI must drop to HOST_UID / restore on exit so
# these trees stay user-owned; this script does not paper over root leftovers.
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
  target="${REPO_ROOT}/${build_dir}"
  # Quiet one-shot restore for leftovers from older root container runs; no warnings.
  if [[ -e ${target} ]] &&
    pcsc_fido_uses_container_ownership_restore "${build_dir}" &&
    pcsc_fido_tree_has_root_owned "${target}"; then
    bash "${SCRIPT_DIR}/helper-restore-bind-mount-ownership.sh" "${build_dir}" >/dev/null 2>&1 || true
  fi
  # Never rm -rf .fuzz while make fuzz holds .fuzz/.lock (libFuzzer would lose corpus mid-REDUCE).
  if [[ (${build_dir} == .fuzz || ${build_dir} == */.fuzz) && -e ${target} ]] &&
    command -v flock >/dev/null 2>&1; then
    lock="${target}/.lock"
    exec 9>"${lock}"
    if ! flock --nonblock 9; then
      printf 'warning: skipping %s (make fuzz still running; finish fuzz or kill it, then re-run clean)\n' \
        "${build_dir}" >&2
      exec 9>&-
      continue
    fi
    rm -rf "${target}"
    exec 9>&-
    continue
  fi
  rm -rf "${target}"
done

rm -rf "${REPO_ROOT}/scan-build-report"
rm -rf \
  "${REPO_ROOT}/.mypy_cache" \
  "${REPO_ROOT}/.ruff_cache" \
  "${REPO_ROOT}/.pytest_cache" \
  "${REPO_ROOT}/.cache"
