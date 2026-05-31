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

# Restore host ownership on bind-mounted trees written as root by container CI.
#
# Usage (from pcsc-fido root):
#   bash .github/scripts/helper-restore-bind-mount-ownership.sh [path ...]
#
# Default paths: build scan-build-report dist .github/pinned/markdownlint/node_modules
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=helper-container-bind-mount.sh
source "${SCRIPT_DIR}/helper-container-bind-mount.sh"

ENGINE="${CONTAINER_ENGINE:-docker}"
if ! command -v "${ENGINE}" >/dev/null 2>&1; then
  printf 'error: %s not found (install or set CONTAINER_ENGINE)\n' "${ENGINE}" >&2
  exit 1
fi

PLATFORM_ARGS=()
pcsc_fido_load_ci_platform_args

HOST_UID="${HOST_UID:-$(id -u)}"
HOST_GID="${HOST_GID:-$(id -g)}"

paths=("$@")
if [[ ${#paths[@]} -eq 0 ]]; then
  paths=("${_PCSC_FIDO_BIND_MOUNT_RESTORE_PATHS[@]}")
fi

mount_targets=()
for rel in "${paths[@]}"; do
  if [[ -e "${REPO_ROOT}/${rel}" ]]; then
    mount_targets+=("/src/${rel}")
  fi
done

if [[ ${#mount_targets[@]} -eq 0 ]]; then
  exit 0
fi

restore_with_host_chown() {
  local rel target chown_cmd=(chown)
  if [[ ${EUID} -ne 0 ]] && sudo -n true 2>/dev/null; then
    chown_cmd=(sudo chown)
  elif [[ ${EUID} -ne 0 ]]; then
    return 1
  fi
  for rel in "${paths[@]}"; do
    target="${REPO_ROOT}/${rel}"
    if [[ -e ${target} ]]; then
      "${chown_cmd[@]}" -R "${HOST_UID}:${HOST_GID}" "${target}" || return 1
    fi
  done
}

if ! "${ENGINE}" run --rm \
  "${PLATFORM_ARGS[@]}" \
  -v "${REPO_ROOT}:/src" \
  -u 0 \
  --entrypoint chown \
  docker.io/library/alpine:3.21 \
  -R "${HOST_UID}:${HOST_GID}" \
  "${mount_targets[@]}" 2>/dev/null; then
  if ! restore_with_host_chown; then
    printf 'error: could not restore ownership on %s (docker chown failed; try: sudo chown -R %s:%s build)\n' \
      "${paths[*]}" "${HOST_UID}" "${HOST_GID}" >&2
    exit 1
  fi
fi
