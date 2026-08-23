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

# Shared helpers for build-tree ownership (avoid root-owned build/ after sudo make install).
#
# Usage:
#   bash .github/scripts/helper-build-tree-ownership.sh refuse-root-make
#   bash .github/scripts/helper-build-tree-ownership.sh repair [path ...]
#
set -euo pipefail

pcsc_fido_refuse_root_make() {
  # Ephemeral GHA job containers run as root on a disposable workspace (same as
  # nero-nfc Main CI lint). Bind-mounted local CI sets HOST_UID and must drop
  # to the host user before make -- refuse when that drop did not happen.
  if [[ $(id -u) -eq 0 ]]; then
    if [[ ${GITHUB_ACTIONS:-false} == true && -z ${HOST_UID:-} ]]; then
      return 0
    fi
    printf '%s\n' \
      'error: do not run `sudo make` for build, test, sanitizer, or clean targets (that root-owns build/).' \
      '  Build and test as your normal user: `make`, `make test`, `make verify`' \
      '  Install only: `sudo make install INSTALL_PREFIX=/usr`' \
      '  If build/ is root-owned: `make clean` then `make` as your normal user' >&2
    exit 1
  fi
}

# True if path itself or any descendant is root-owned (nested mkdir-as-root case).
pcsc_fido_tree_has_root_owned() {
  local path="$1"
  [[ -e ${path} ]] || return 1
  [[ -n $(find "${path}" -user root -print -quit 2>/dev/null) ]]
}

pcsc_fido_repair_tree_ownership() {
  local uid gid path
  uid="$(id -u)"
  gid="$(id -g)"

  for path in "$@"; do
    [[ -n ${path} ]] || continue
    [[ -e ${path} ]] || continue
    if pcsc_fido_tree_has_root_owned "${path}"; then
      # Best-effort; container restore is preferred for bind-mount leftovers.
      chown -R "${uid}:${gid}" "${path}" 2>/dev/null || true
    fi
  done
}

# Host-only repair before rm -rf (no container/docker). Use for local sanitizer/fuzz trees.
pcsc_fido_local_repair_tree_for_removal() {
  local uid gid path
  uid="$(id -u)"
  gid="$(id -g)"
  for path in "$@"; do
    [[ -n ${path} ]] || continue
    [[ -e ${path} ]] || continue
    chmod -R u+w "${path}" 2>/dev/null || true
    chown -R "${uid}:${gid}" "${path}" 2>/dev/null || true
  done
}

# Paths written as root by container CI on bind mounts -- docker chown is appropriate here.
pcsc_fido_uses_container_ownership_restore() {
  case "$1" in
    build | build/* | .lint-kit-org | scan-build-report | dist | .github/pinned/markdownlint/node_modules)
      return 0
      ;;
    *) return 1 ;;
  esac
}

if [[ ${BASH_SOURCE[0]} == "${0}" ]]; then
  case "${1:-}" in
    refuse-root-make)
      pcsc_fido_refuse_root_make
      ;;
    repair)
      shift
      pcsc_fido_refuse_root_make
      pcsc_fido_repair_tree_ownership "$@"
      ;;
    *)
      printf 'usage: %s refuse-root-make|repair [path ...]\n' "$0" >&2
      exit 2
      ;;
  esac
fi
