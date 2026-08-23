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

# Shared container-engine (docker/podman) resolution for the local CI and
# security helper scripts. Source this file; do not execute directly.

if [[ ${BASH_SOURCE[0]} == "${0}" ]]; then
  printf '%s\n' "error: source helper-container-engine.sh instead of executing it" >&2
  exit 1
fi

# Echo the configured container engine (CONTAINER_ENGINE, default "docker").
nero_container_engine() {
  printf '%s' "${CONTAINER_ENGINE:-docker}"
}

# Echo the engine name on stdout when it is installed; otherwise print an error
# to stderr and return 1.
# Usage: ENGINE="$(nero_require_container_engine)" || exit 1
nero_require_container_engine() {
  local engine
  engine="$(nero_container_engine)"
  if ! command -v "${engine}" >/dev/null 2>&1; then
    printf 'error: %s not found (install docker or podman, or set CONTAINER_ENGINE)\n' \
      "${engine}" >&2
    return 1
  fi
  printf '%s' "${engine}"
}
