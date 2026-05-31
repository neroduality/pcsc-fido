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

# Run OSV-Scanner against this checkout (same engine family as `.github/workflows/osv-scanner.yml`).
# Uses the official container image; requires network unless you pass OSV_EXTRA_ARGS=--offline ...
#
# Usage:
#   bash .github/scripts/run-local-osv-scanner.sh
#   OSV_IMAGE=ghcr.io/google/osv-scanner:latest bash .../run-local-osv-scanner.sh -- --format table
#
set -euo pipefail

usage() {
  cat <<'EOF'
Run OSV-Scanner locally via Docker or Podman.

Any arguments after `--` are forwarded to `osv-scanner scan source` (defaults: `-r /src --allow-no-lockfiles`).

Environment:
  CONTAINER_ENGINE   docker (default) or podman
  CI_PLATFORM        Unset: linux/amd64 on x86_64, else linux/$host. Empty (CI_PLATFORM=): native.
  OSV_IMAGE          Scanner image (default: ghcr.io/google/osv-scanner:latest).
                     Passes --allow-no-lockfiles unless you replace argv after `--`.

Examples:
  bash .github/scripts/run-local-osv-scanner.sh
  bash .github/scripts/run-local-osv-scanner.sh -- --format json

EOF
}

if [[ ${1:-} == "-h" ]] || [[ ${1:-} == "--help" ]]; then
  usage
  exit 0
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=helper-container-bind-mount.sh
source "${SCRIPT_DIR}/helper-container-bind-mount.sh"

ENGINE="${CONTAINER_ENGINE:-docker}"
if ! command -v "${ENGINE}" >/dev/null 2>&1; then
  printf 'error: %s not found (install or set CONTAINER_ENGINE)\n' "${ENGINE}" >&2
  exit 1
fi

OSV_IMAGE="${OSV_IMAGE:-ghcr.io/google/osv-scanner:latest}"

PLATFORM_ARGS=()
pcsc_fido_load_ci_platform_args

extra_args=(scan source -r /src --allow-no-lockfiles)
if (($# > 0)); then
  if [[ $1 == "--" ]]; then
    shift
    extra_args+=("$@")
  else
    extra_args+=("$@")
  fi
fi

printf '\n── OSV-Scanner (%s) ──\n' "${OSV_IMAGE}"
printf 'Repo mount: %s → /src\n\n' "${REPO_ROOT}"

exec "${ENGINE}" run --rm \
  "${PLATFORM_ARGS[@]}" \
  -v "${REPO_ROOT}:/src:ro" \
  "${OSV_IMAGE}" \
  "${extra_args[@]}"
