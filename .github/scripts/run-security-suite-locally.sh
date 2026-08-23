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

# Run host security checks in one shot (same family as individual ``run-*-locally.sh`` helpers).
#
# Order:
#   1. zizmor (GitHub Actions security audit)
#   2. actionlint (GitHub Actions workflow correctness + embedded shellcheck)
#   3. TruffleHog (secret scan)
#
# SPDX headers are enforced by ``make lint`` (see ci-lint.sh), not here.
# CodeQL runs via `.github/workflows/codeql.yml` only (not ``make lint`` / ``make verify``).
#
# Usage:
#   bash .github/scripts/run-security-suite-locally.sh
#   CONTAINER_ENGINE=podman bash .../run-security-suite-locally.sh
#
set -euo pipefail

usage() {
  cat <<'EOF'
Run zizmor, actionlint and TruffleHog locally.

Tools (in order):
  1. zizmor                      GitHub Actions workflow security audit
  2. actionlint                  GitHub Actions workflow correctness (+ shellcheck)
  3. TruffleHog                  Secret scan

Requires: docker or podman (zizmor/actionlint fall back to containers; TruffleHog needs one).

Usage:
  bash .github/scripts/run-security-suite-locally.sh [-h|--help]

Environment:
  CONTAINER_ENGINE   docker (default) or podman

EOF
}

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"

# shellcheck source=helper-container-engine.sh
source "${SCRIPT_DIR}/helper-container-engine.sh"

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
  usage
  exit 0
fi

if [[ $# -gt 0 ]]; then
  printf 'error: unknown option %q\n' "$1" >&2
  usage >&2
  exit 2
fi

# Inner width between the left and right border characters in banner().
readonly BOX_INNER_WIDTH=62

banner() {
  local title=$1
  local inner=${BOX_INNER_WIDTH}
  local len=${#title}

  if ((len > inner)); then
    title="${title:0:inner}"
    len=${#title}
  fi

  local left=$(((inner - len) / 2))
  local right=$((inner - len - left))

  printf '\n+'
  printf '%*s' "${inner}" '' | tr ' ' '-'
  printf '+\n'

  printf '|%*s%s%*s|\n' "${left}" '' "${title}" "${right}" ''

  printf '+'
  printf '%*s' "${inner}" '' | tr ' ' '-'
  printf '+\n'
}

cd "${REPO_ROOT}"

if ! nero_require_container_engine >/dev/null; then
  exit 1
fi

banner "zizmor (offline)"
bash "${SCRIPT_DIR}/run-zizmor-locally.sh" --offline --color=always

banner "actionlint"
bash "${SCRIPT_DIR}/run-actionlint-locally.sh" -color

banner "TruffleHog"
bash "${SCRIPT_DIR}/run-trufflehog-locally.sh"

printf '\n-- Security suite finished --\n'
