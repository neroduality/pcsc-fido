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

# Pre-flight for make build/test/sanitizer targets: refuse root, repair root-owned trees.
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
# shellcheck source=helper-build-tree-ownership.sh
source "${script_dir}/helper-build-tree-ownership.sh"
# shellcheck source=helper-container-bind-mount.sh
source "${script_dir}/helper-container-bind-mount.sh"

pcsc_fido_refuse_root_make

# Resolve relative BUILD_TREES args against the repo root before repair.
repair_paths=()
for path in "$@"; do
  if [[ ${path} == /* ]]; then
    repair_paths+=("${path}")
  else
    repair_paths+=("${repo_root}/${path}")
  fi
done

# Quiet restore for nested root leftovers (no "repairing" spam); host chown first.
for rel in "${_PCSC_FIDO_BIND_MOUNT_RESTORE_PATHS[@]}"; do
  target="${repo_root}/${rel}"
  if [[ -e ${target} ]] && pcsc_fido_tree_has_root_owned "${target}"; then
    if ! chown -R "$(id -u):$(id -g)" "${target}" 2>/dev/null; then
      bash "${script_dir}/helper-restore-bind-mount-ownership.sh" "${rel}" >/dev/null 2>&1 || true
    fi
  fi
done

pcsc_fido_repair_tree_ownership "${repair_paths[@]}"
