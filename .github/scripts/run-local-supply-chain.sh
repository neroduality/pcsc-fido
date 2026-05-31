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

# Reproduce the Syft → Grype pipeline locally using Docker or Podman (same family as CI:
# `.github/workflows/supply-chain-sbom.yml`).
#
# Usage (from anywhere):
#   bash /path/to/repo/.github/scripts/run-local-supply-chain.sh
#   SYFT_IMAGE=anchore/syft:v1.36.0 GRYPE_IMAGE=anchore/grype:v0.92.0 bash .../run-local-supply-chain.sh
#   CONTAINER_ENGINE=podman bash .../run-local-supply-chain.sh
#
set -euo pipefail

usage() {
  cat <<'EOF'
Generate an SPDX JSON SBOM with Syft, then scan it with Grype (container tools).

Requires: docker or podman.

Environment:
  CONTAINER_ENGINE            docker (default) or podman
  CI_PLATFORM                 Unset: linux/amd64 on x86_64, else linux/$host. Empty (CI_PLATFORM=): native.
  SYFT_IMAGE                  Syft image (default: anchore/syft:v1.36.0)
  GRYPE_IMAGE                 Grype image (default: anchore/grype:v0.92.0)
  SUPPLY_CHAIN_TOOL_CACHE     Host dir for Syft/Grype caches (default: ~/.cache/nero-supply-chain-tools)
  SUPPLY_CHAIN_VERBOSE=1      Pass -v into Syft and Grype (more progress on stderr)

Note: Grype downloads a vulnerability DB on first use (and whenever the cache volume is empty).
      Without a host-mounted cache, each ephemeral container run repeats that download — it can
      look \"stuck\" for several minutes with no output. This script mounts a persistent cache.

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
REPO_NAME="$(basename "${REPO_ROOT}")"

ENGINE="${CONTAINER_ENGINE:-docker}"
if ! command -v "${ENGINE}" >/dev/null 2>&1; then
  printf 'error: %s not found (install or set CONTAINER_ENGINE)\n' "${ENGINE}" >&2
  exit 1
fi

SYFT_IMAGE="${SYFT_IMAGE:-anchore/syft:v1.36.0}"
GRYPE_IMAGE="${GRYPE_IMAGE:-anchore/grype:v0.92.0}"

# Persist caches — otherwise every `docker run --rm` rebuilds Grype's DB download (minutes, often silent).
_chain_cache="${SUPPLY_CHAIN_TOOL_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/nero-supply-chain-tools}"
_syft_cache="${_chain_cache}/syft"
_grype_cache="${_chain_cache}/grype"
mkdir -p "${_syft_cache}" "${_grype_cache}"

PLATFORM_ARGS=()
pcsc_fido_load_ci_platform_args

syft_cfg="${REPO_ROOT}/.syft.yaml"
syft_mount=()
if [[ -f ${syft_cfg} ]]; then
  syft_mount=(-v "${syft_cfg}:/src/.syft.yaml:ro")
fi

sbom_tmp="$(mktemp)"
cleanup() { rm -f "${sbom_tmp}"; }
trap cleanup EXIT
touch "${sbom_tmp}"

syft_cli=(scan dir:. --source-name "${REPO_NAME}" --source-version local -o spdx-json=/out/sbom.spdx.json)
if [[ ${SUPPLY_CHAIN_VERBOSE:-0} == "1" ]]; then
  syft_cli=(-v "${syft_cli[@]}")
fi

grype_cli=(sbom:/sbom.spdx.json)
if [[ ${SUPPLY_CHAIN_VERBOSE:-0} == "1" ]]; then
  grype_cli=(-v "${grype_cli[@]}")
fi

printf '\n── Syft (%s) ──\n' "${SYFT_IMAGE}"
printf 'Repo: %s\n' "${REPO_ROOT}"
printf 'Tool cache (host → container): %s → /root/.cache/syft\n' "${_syft_cache}" >&2
if [[ ${SUPPLY_CHAIN_VERBOSE:-0} != "1" ]]; then
  printf 'hint: first Syft run may take a while; SUPPLY_CHAIN_VERBOSE=1 for details\n' >&2
fi
printf '\n'

"${ENGINE}" run --rm \
  "${PLATFORM_ARGS[@]}" \
  -v "${REPO_ROOT}:/src:ro" \
  "${syft_mount[@]}" \
  -v "${sbom_tmp}:/out/sbom.spdx.json:rw" \
  -v "${_syft_cache}:/root/.cache/syft:rw" \
  -w /src \
  "${SYFT_IMAGE}" \
  "${syft_cli[@]}"

if [[ ! -s ${sbom_tmp} ]]; then
  printf 'error: Syft produced an empty SBOM\n' >&2
  exit 1
fi

printf '\n── Grype (%s) ──\n' "${GRYPE_IMAGE}"
printf 'Tool cache (host → container): %s → /root/.cache/grype\n' "${_grype_cache}" >&2
if [[ ${SUPPLY_CHAIN_VERBOSE:-0} != "1" ]]; then
  printf 'hint: Grype may spend several minutes updating its vulnerability DB with little output;\n' >&2
  printf '      SUPPLY_CHAIN_VERBOSE=1 shows progress (subsequent runs reuse %s).\n' "${_grype_cache}" >&2
fi
printf '\n'

"${ENGINE}" run --rm \
  "${PLATFORM_ARGS[@]}" \
  -e GRYPE_CHECK_FOR_APP_UPDATE=false \
  -v "${sbom_tmp}:/sbom.spdx.json:ro" \
  -v "${_grype_cache}:/root/.cache/grype:rw" \
  "${GRYPE_IMAGE}" \
  "${grype_cli[@]}"

printf '\n── Supply chain scan finished ──\n'
