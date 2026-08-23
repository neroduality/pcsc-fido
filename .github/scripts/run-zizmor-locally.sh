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

# Run zizmor (GitHub Actions static analysis) against this repository checkout.
#
# CI runs the same audit as `.github/workflows/zizmor_actionlint.yml` (workflow_dispatch only).
#
# Prefers a host `zizmor` on PATH when present; otherwise uses Docker or Podman with the official
# ghcr.io/zizmorcore/zizmor image. Script flags must come before any zizmor CLI flags.
#
# Usage (from anywhere):
#   bash /path/to/repo/.github/scripts/run-zizmor-locally.sh
#   bash .../run-zizmor-locally.sh --pedantic
#   bash .../run-zizmor-locally.sh --container --offline
#   bash .../run-zizmor-locally.sh --format sarif > /tmp/zizmor.sarif
#   CONTAINER_ENGINE=podman bash .../run-zizmor-locally.sh
#
set -euo pipefail

usage() {
  cat <<'EOF'
Run zizmor locally against this repository's GitHub workflow and action files.

Uses `zizmor` on PATH when available unless `--container` is set. Otherwise runs the official
container image (Docker or Podman).

Requires: zizmor -- or docker/podman for `--container` / auto fallback.

Usage:
  bash /path/to/repo/.github/scripts/run-zizmor-locally.sh [script-options] [zizmor-args...]

Script options (must appear before zizmor flags):
  --container      Always run via Docker/Podman (ignore host zizmor).
  --host           Require host `zizmor` on PATH (fail if missing).
  --image IMG      Container image (default: digest-pinned ghcr.io/zizmorcore/zizmor:1.25.2).
  -h, --help       Help.

Environment:
  CONTAINER_ENGINE    docker (default) or podman.
  CI_PLATFORM         Default linux/amd64 when unset. Set empty (CI_PLATFORM=) for native arch.
  ZIZMOR_IMAGE        Same as --image.
  GH_TOKEN, GITHUB_TOKEN  Forwarded into the container when set (online audits / remote lookups).

Install zizmor: https://docs.zizmor.sh/installation/

EOF
}

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"

# shellcheck source=helper-container-engine.sh
source "${SCRIPT_DIR}/helper-container-engine.sh"

FORCE_CONTAINER=0
FORCE_HOST=0
IMAGE="${ZIZMOR_IMAGE:-ghcr.io/zizmorcore/zizmor:1.25.2@sha256:14ea7f5cc7c67933394a35b5a38a277397818d232602635edb2010b313afb110}"
ZIZMOR_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --container)
      FORCE_CONTAINER=1
      shift
      ;;
    --host)
      FORCE_HOST=1
      shift
      ;;
    --image)
      IMAGE="${2:?}"
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      ZIZMOR_ARGS+=("$@")
      break
      ;;
  esac
done

ZIZMOR_INPUTS=()
if [[ -d "${REPO_ROOT}/.github/workflows" ]]; then
  while IFS= read -r -d '' path; do
    ZIZMOR_INPUTS+=("${path}")
  done < <(find "${REPO_ROOT}/.github/workflows" -maxdepth 1 -type f \( -name '*.yml' -o -name '*.yaml' \) -print0 | sort -z)
fi
if [[ -d "${REPO_ROOT}/.github/actions" ]]; then
  while IFS= read -r -d '' path; do
    ZIZMOR_INPUTS+=("${path}")
  done < <(find "${REPO_ROOT}/.github/actions" -type f \( -name 'action.yml' -o -name 'action.yaml' \) -print0 | sort -z)
fi
if [[ ${#ZIZMOR_INPUTS[@]} -eq 0 ]]; then
  printf 'error: no GitHub workflow/action inputs found under %s/.github\n' "${REPO_ROOT}" >&2
  exit 1
fi

if [[ ${FORCE_CONTAINER} -eq 1 ]] && [[ ${FORCE_HOST} -eq 1 ]]; then
  printf 'error: --container and --host are mutually exclusive\n' >&2
  exit 1
fi

ENGINE="$(nero_container_engine)"
PLATFORM_ARGS=()
_resolved_platform="${CI_PLATFORM-linux/amd64}"
if [[ -n ${_resolved_platform} ]]; then
  PLATFORM_ARGS+=(--platform "${_resolved_platform}")
fi

run_host_zizmor() {
  printf '\n-- zizmor (host) --\n'
  printf 'Scan root: %s\n\n' "${REPO_ROOT}"
  exec zizmor "${ZIZMOR_ARGS[@]}" "${ZIZMOR_INPUTS[@]}"
}

run_container_zizmor() {
  if ! nero_require_container_engine >/dev/null; then
    exit 1
  fi

  local -a env_forward=()
  local -a container_inputs=()
  local input
  [[ -n ${GH_TOKEN:-} ]] && env_forward+=(-e "GH_TOKEN=${GH_TOKEN}")
  [[ -n ${GITHUB_TOKEN:-} ]] && env_forward+=(-e "GITHUB_TOKEN=${GITHUB_TOKEN}")
  for input in "${ZIZMOR_INPUTS[@]}"; do
    container_inputs+=("/src/${input#"${REPO_ROOT}/"}")
  done

  printf '\n-- zizmor (%s) --\n' "${IMAGE}"
  printf 'Repo mount: %s -> /src\n\n' "${REPO_ROOT}"

  exec "${ENGINE}" run --rm \
    "${PLATFORM_ARGS[@]}" \
    "${env_forward[@]}" \
    -v "${REPO_ROOT}:/src:ro" \
    -w /src \
    "${IMAGE}" \
    "${ZIZMOR_ARGS[@]}" \
    "${container_inputs[@]}"
}

if [[ ${FORCE_HOST} -eq 1 ]]; then
  if ! command -v zizmor >/dev/null 2>&1; then
    printf 'error: zizmor not found on PATH (--host requires a local install)\n' >&2
    exit 1
  fi
  run_host_zizmor
fi

if [[ ${FORCE_CONTAINER} -eq 1 ]]; then
  run_container_zizmor
fi

if command -v zizmor >/dev/null 2>&1; then
  run_host_zizmor
fi

run_container_zizmor
