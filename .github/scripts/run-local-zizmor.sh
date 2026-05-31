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
# CI runs the same audit as `.github/workflows/zizmor.yml` (workflow_dispatch only).
#
# Prefers a host `zizmor` on PATH when present; otherwise uses Docker or Podman with the official
# ghcr.io/zizmorcore/zizmor image. Script flags must come before any zizmor CLI flags.
#
# Usage (from anywhere):
#   bash /path/to/repo/.github/scripts/run-local-zizmor.sh
#   bash .../run-local-zizmor.sh --pedantic
#   bash .../run-local-zizmor.sh --container --offline
#   bash .../run-local-zizmor.sh --format sarif > /tmp/zizmor.sarif
#   CONTAINER_ENGINE=podman bash .../run-local-zizmor.sh
#
set -euo pipefail

usage() {
  cat <<'EOF'
Run zizmor locally against this repository root (directory containing `.github/`).

Uses `zizmor` on PATH when available unless `--container` is set. Otherwise runs the official
container image (Docker or Podman).

Requires: zizmor — or docker/podman for `--container` / auto fallback.

Usage:
  bash /path/to/repo/.github/scripts/run-local-zizmor.sh [script-options] [zizmor-args...]

Script options (must appear before zizmor flags):
  --container      Always run via Docker/Podman (ignore host zizmor).
  --host           Require host `zizmor` on PATH (fail if missing).
  --image IMG      Container image (default: ghcr.io/zizmorcore/zizmor:latest).
  -h, --help       Help.

Environment:
  CONTAINER_ENGINE    docker (default) or podman.
  CI_PLATFORM         Unset: linux/amd64 on x86_64, else linux/$host. Empty (CI_PLATFORM=): native.
  ZIZMOR_IMAGE        Same as --image.
  GH_TOKEN, GITHUB_TOKEN  Forwarded into the container when set (online audits / remote lookups).

Install zizmor: https://docs.zizmor.sh/installation/

EOF
}

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=helper-container-bind-mount.sh
source "${SCRIPT_DIR}/helper-container-bind-mount.sh"

FORCE_CONTAINER=0
FORCE_HOST=0
IMAGE="${ZIZMOR_IMAGE:-ghcr.io/zizmorcore/zizmor:latest}"
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

if [[ ${FORCE_CONTAINER} -eq 1 ]] && [[ ${FORCE_HOST} -eq 1 ]]; then
  printf 'error: --container and --host are mutually exclusive\n' >&2
  exit 1
fi

ENGINE="${CONTAINER_ENGINE:-docker}"
PLATFORM_ARGS=()
pcsc_fido_load_ci_platform_args

run_host_zizmor() {
  printf '\n── zizmor (host) ──\n'
  printf 'Scan root: %s\n\n' "${REPO_ROOT}"
  exec zizmor "${ZIZMOR_ARGS[@]}" "${REPO_ROOT}"
}

run_container_zizmor() {
  if ! command -v "${ENGINE}" >/dev/null 2>&1; then
    printf 'error: %s not found (install or set CONTAINER_ENGINE)\n' "${ENGINE}" >&2
    exit 1
  fi

  local -a env_forward=()
  [[ -n ${GH_TOKEN:-} ]] && env_forward+=(-e "GH_TOKEN=${GH_TOKEN}")
  [[ -n ${GITHUB_TOKEN:-} ]] && env_forward+=(-e "GITHUB_TOKEN=${GITHUB_TOKEN}")

  printf '\n── zizmor (%s) ──\n' "${IMAGE}"
  printf 'Repo mount: %s → /src\n\n' "${REPO_ROOT}"

  exec "${ENGINE}" run --rm \
    "${PLATFORM_ARGS[@]}" \
    "${env_forward[@]}" \
    -v "${REPO_ROOT}:/src" \
    -w /src \
    "${IMAGE}" \
    "${ZIZMOR_ARGS[@]}" \
    /src
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
