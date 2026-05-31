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

# Run host + container security checks in one shot (same family as individual
# ``run-local-*.sh`` helpers under this directory).
#
# Order: SPDX/license headers (Python) → zizmor → Syft/Grype → OSV-Scanner → TruffleHog.
#
# Usage:
#   bash .github/scripts/run-local-security-suite.sh
#   bash .../run-local-security-suite.sh --quick
#   SKIP_SUPPLY_CHAIN=1 bash .../run-local-security-suite.sh
#   CONTAINER_ENGINE=podman bash .../run-local-security-suite.sh
#
set -euo pipefail

usage() {
  cat <<'EOF'
Run license normalization, zizmor, and container supply-chain / secret scans locally.

Requires: python3; docker or podman for container-backed steps (skipped individually if missing when optional).

Usage:
  bash .github/scripts/run-local-security-suite.sh [options]

Options:
  --quick             Only license headers + zizmor (skip container pulls).
  --skip-license      Skip helper-license-headers.py
  --skip-zizmor       Skip zizmor
  --skip-supply-chain Skip Syft → Grype
  --skip-osv          Skip OSV-Scanner
  --skip-trufflehog   Skip TruffleHog
  -h, --help          Help

Environment:
  CONTAINER_ENGINE   docker (default) or podman
  CI_PLATFORM        Unset: linux/amd64 on x86_64, else linux/$host. Empty (CI_PLATFORM=): native.

Individual skips also honor:
  SKIP_LICENSE=1  SKIP_ZIZMOR=1  SKIP_SUPPLY_CHAIN=1  SKIP_OSV=1  SKIP_TRUFFLEHOG=1

EOF
}

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"

SKIP_LICENSE="${SKIP_LICENSE:-0}"
SKIP_ZIZMOR="${SKIP_ZIZMOR:-0}"
SKIP_SUPPLY_CHAIN="${SKIP_SUPPLY_CHAIN:-0}"
SKIP_OSV="${SKIP_OSV:-0}"
SKIP_TRUFFLEHOG="${SKIP_TRUFFLEHOG:-0}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --quick)
      SKIP_SUPPLY_CHAIN=1
      SKIP_OSV=1
      SKIP_TRUFFLEHOG=1
      ;;
    --skip-license) SKIP_LICENSE=1 ;;
    --skip-zizmor) SKIP_ZIZMOR=1 ;;
    --skip-supply-chain) SKIP_SUPPLY_CHAIN=1 ;;
    --skip-osv) SKIP_OSV=1 ;;
    --skip-trufflehog) SKIP_TRUFFLEHOG=1 ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      printf 'error: unknown option %q\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

# Inner width between corners (╔ + N×═ + ╗ and ║ … ║ must share the same N).
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

  printf '\n╔'
  printf '%*s' "${inner}" '' | tr ' ' '═'
  printf '╗\n'

  printf '║%*s%s%*s║\n' "${left}" '' "${title}" "${right}" ''

  printf '╚'
  printf '%*s' "${inner}" '' | tr ' ' '═'
  printf '╝\n'
}

have_engine() {
  local e="${CONTAINER_ENGINE:-docker}"
  command -v "${e}" >/dev/null 2>&1
}

cd "${REPO_ROOT}"

if [[ ${SKIP_LICENSE} -eq 0 ]]; then
  banner "License headers (SPDX / Apache-2.0)"
  python3 "${REPO_ROOT}/.github/linters/helper-license-headers.py" --repo-root "${REPO_ROOT}" --skip-dir-name patches
  python3 "${REPO_ROOT}/.github/linters/helper-license-headers.py" --repo-root "${REPO_ROOT}" --skip-dir-name patches --check
else
  printf '\n(skip license headers)\n'
fi

if [[ ${SKIP_ZIZMOR} -eq 0 ]]; then
  banner "zizmor (offline)"
  bash "${SCRIPT_DIR}/run-local-zizmor.sh" --offline --color=always
else
  printf '\n(skip zizmor)\n'
fi

if [[ ${SKIP_SUPPLY_CHAIN} -eq 0 ]]; then
  if have_engine; then
    banner "Supply chain (Syft → Grype)"
    bash "${SCRIPT_DIR}/run-local-supply-chain.sh"
  else
    printf '\n(skip supply chain: %s not found)\n' "${CONTAINER_ENGINE:-docker}" >&2
  fi
else
  printf '\n(skip supply chain)\n'
fi

if [[ ${SKIP_OSV} -eq 0 ]]; then
  if have_engine; then
    banner "OSV-Scanner"
    bash "${SCRIPT_DIR}/run-local-osv-scanner.sh"
  else
    printf '\n(skip OSV-Scanner: %s not found)\n' "${CONTAINER_ENGINE:-docker}" >&2
  fi
else
  printf '\n(skip OSV-Scanner)\n'
fi

if [[ ${SKIP_TRUFFLEHOG} -eq 0 ]]; then
  if have_engine; then
    banner "TruffleHog"
    bash "${SCRIPT_DIR}/run-local-trufflehog.sh"
  else
    printf '\n(skip TruffleHog: %s not found)\n' "${CONTAINER_ENGINE:-docker}" >&2
  fi
else
  printf '\n(skip TruffleHog)\n'
fi

printf '\n── Security suite finished ──\n'
