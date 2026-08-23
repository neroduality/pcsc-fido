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

# Run actionlint (GitHub Actions workflow linter) against this repository checkout.
#
# actionlint complements zizmor: zizmor audits Actions for security weaknesses, while
# actionlint checks workflow correctness (syntax, expression types, runner labels, and the
# embedded shellcheck of `run:` scripts). CI runs both in `.github/workflows/zizmor_actionlint.yml`.
#
# Prefers a host `actionlint` on PATH when present; otherwise uses Docker or Podman with the
# official rhysd/actionlint image. Script flags must come before any actionlint CLI flags.
#
# Usage (from anywhere):
#   bash /path/to/repo/.github/scripts/run-actionlint-locally.sh
#   bash .../run-actionlint-locally.sh -color
#   bash .../run-actionlint-locally.sh --container -color
#   CONTAINER_ENGINE=podman bash .../run-actionlint-locally.sh
#
set -euo pipefail

usage() {
  cat <<'EOF'
Run actionlint locally against this repository's GitHub workflow and action files.

Uses `actionlint` on PATH when available unless `--container` is set. Otherwise runs the
official container image (Docker or Podman).

Requires: actionlint -- or docker/podman for `--container` / auto fallback.

Usage:
  bash /path/to/repo/.github/scripts/run-actionlint-locally.sh [script-options] [actionlint-args...]

Script options (must appear before actionlint flags):
  --container      Always run via Docker/Podman (ignore host actionlint).
  --host           Require host `actionlint` on PATH (fail if missing).
  --image IMG      Container image (default: digest-pinned rhysd/actionlint:1.7.7).
  -h, --help       Help.

Environment:
  CONTAINER_ENGINE    docker (default) or podman.
  CI_PLATFORM         Default linux/amd64 when unset. Set empty (CI_PLATFORM=) for native arch.
  ACTIONLINT_IMAGE    Same as --image.

Install actionlint: https://github.com/rhysd/actionlint/blob/main/docs/install.md

EOF
}

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"

# shellcheck source=helper-container-engine.sh
source "${SCRIPT_DIR}/helper-container-engine.sh"

FORCE_CONTAINER=0
FORCE_HOST=0
IMAGE="${ACTIONLINT_IMAGE:-rhysd/actionlint:1.7.7@sha256:887a259a5a534f3c4f36cb02dca341673c6089431057242cdc931e9f133147e9}"
ACTIONLINT_ARGS=()

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
      ACTIONLINT_ARGS+=("$@")
      break
      ;;
  esac
done

ACTIONLINT_INPUTS=()
if [[ -d "${REPO_ROOT}/.github/workflows" ]]; then
  while IFS= read -r -d '' path; do
    ACTIONLINT_INPUTS+=("${path}")
  done < <(find "${REPO_ROOT}/.github/workflows" -maxdepth 1 -type f \( -name '*.yml' -o -name '*.yaml' \) -print0 | sort -z)
fi
if [[ ${#ACTIONLINT_INPUTS[@]} -eq 0 ]]; then
  printf 'error: no GitHub workflow inputs found under %s/.github/workflows\n' "${REPO_ROOT}" >&2
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

actionlint_ok_summary() {
  if ((${#ACTIONLINT_INPUTS[@]} == 1)); then
    printf 'actionlint: OK (1 workflow checked)\n'
  else
    printf 'actionlint: OK (%d workflows checked)\n' "${#ACTIONLINT_INPUTS[@]}"
  fi
}

run_host_actionlint() {
  local rc=0
  printf '\n-- actionlint (host) --\n'
  printf 'Scan root: %s\n\n' "${REPO_ROOT}"
  actionlint "${ACTIONLINT_ARGS[@]}" "${ACTIONLINT_INPUTS[@]}" || rc=$?
  ((rc == 0)) && actionlint_ok_summary
  exit "$rc"
}

run_container_actionlint() {
  local rc=0
  if ! nero_require_container_engine >/dev/null; then
    exit 1
  fi

  local -a container_inputs=()
  local input
  for input in "${ACTIONLINT_INPUTS[@]}"; do
    container_inputs+=("/src/${input#"${REPO_ROOT}/"}")
  done

  printf '\n-- actionlint (%s) --\n' "${IMAGE}"
  printf 'Repo mount: %s -> /src\n\n' "${REPO_ROOT}"

  "${ENGINE}" run --rm \
    "${PLATFORM_ARGS[@]}" \
    -v "${REPO_ROOT}:/src:ro" \
    -w /src \
    "${IMAGE}" \
    "${ACTIONLINT_ARGS[@]}" \
    "${container_inputs[@]}" || rc=$?
  ((rc == 0)) && actionlint_ok_summary
  exit "$rc"
}

if [[ ${FORCE_HOST} -eq 1 ]]; then
  if ! command -v actionlint >/dev/null 2>&1; then
    printf 'error: actionlint not found on PATH (--host requires a local install)\n' >&2
    exit 1
  fi
  run_host_actionlint
fi

if [[ ${FORCE_CONTAINER} -eq 1 ]]; then
  run_container_actionlint
fi

if command -v actionlint >/dev/null 2>&1; then
  run_host_actionlint
fi

run_container_actionlint
