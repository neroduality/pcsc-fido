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

# Run OpenSSF Scorecard against this checkout (same engine as CI publishes remotely).
#
# Uses Docker or Podman + gcr.io/openssf/scorecard:stable. The container runs as root so it can
# traverse bind-mounted trees where some directories are not world-readable (matches typical CI).
#
# Usage (from repo root):
#   bash .github/scripts/run-local-openssf.sh
#   bash .github/scripts/run-local-openssf.sh --format json --output /tmp/scorecard.json
#   CONTAINER_ENGINE=podman bash .github/scripts/run-local-openssf.sh
#
set -euo pipefail

usage() {
  cat <<'EOF'
Run OpenSSF Scorecard locally (Docker or Podman).

Requires: docker or podman; bash. Recommended: jq (pretty-prints --format json).

Usage:
  bash .github/scripts/run-local-openssf.sh [options]

Options:
  --format FMT     json | default | probe | intoto (default: json). SARIF is only used by the
                   GitHub Action with an online repo — not supported with --local.
  --output PATH    Write scorecard stdout to PATH (--format json is passed through jq when available).
  --show-details   Pass --show-details to scorecard
  --image IMG      Container image (default: gcr.io/openssf/scorecard:stable)
  -h, --help       Help

Environment:
  CONTAINER_ENGINE           docker (default) or podman
  CI_PLATFORM                Unset: linux/amd64 on x86_64, else linux/$host. Empty (CI_PLATFORM=): native.
  OSSF_SCORECARD_RAW_JSON    Set to 1 to skip jq pretty-printing when --format json
  OSSF_SCORECARD_IMAGE       Override container image (same as --image)

Note:
  Local scans use --local and do not publish to api.scorecard.dev. For badge / code scanning
  integration, rely on the GitHub workflow (.github/workflows/openssf-scorecard.yml).

  Scorecard --local walks the working tree (not just git-tracked files). Local CI leaves
  compiled artifacts under build/ on the bind mount, which fails Binary-Artifacts and depresses
  the aggregate score. This script stages a temporary copy that excludes build/ and
  scan-build-report/ so local results match GitHub (which scans the repository, not host build
  trees).

  Security-Policy: GitHub Scorecard resolves the organization default SECURITY.md from the
  org .github repository. --local cannot see that file, so Security-Policy may score 0 locally
  even when GitHub reports a pass. No per-repo SECURITY.md is required when the org policy exists.

  For --format json, output is passed through jq (if installed) for readability.

EOF
}

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=helper-container-bind-mount.sh
source "${SCRIPT_DIR}/helper-container-bind-mount.sh"

FORMAT="json"
OUTPUT_PATH=""
SHOW_DETAILS=0
IMAGE="${OSSF_SCORECARD_IMAGE:-gcr.io/openssf/scorecard:stable}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --format)
      FORMAT="${2:?}"
      shift 2
      ;;
    --output)
      OUTPUT_PATH="${2:?}"
      shift 2
      ;;
    --show-details)
      SHOW_DETAILS=1
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
      printf 'error: unknown option %q\n' "$1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

case "${FORMAT}" in
  json | default | probe | intoto) ;;
  sarif)
    printf 'error: --format sarif is not supported with --local (Scorecard CLI limitation). Use --format json.\n' >&2
    exit 1
    ;;
  *)
    printf 'error: unsupported --format %s\n' "${FORMAT}" >&2
    exit 1
    ;;
esac

ENGINE="${CONTAINER_ENGINE:-docker}"
if ! command -v "${ENGINE}" >/dev/null 2>&1; then
  printf 'error: %s not found (install or set CONTAINER_ENGINE)\n' "${ENGINE}" >&2
  exit 1
fi

PLATFORM_ARGS=()
pcsc_fido_load_ci_platform_args

SC_ARGS=(--local=/src "--format=${FORMAT}")
if [[ ${SHOW_DETAILS} -eq 1 ]]; then
  SC_ARGS+=(--show-details)
fi

prepare_scorecard_tree() {
  local stage
  stage="$(mktemp -d "${TMPDIR:-/tmp}/pcsc-fido-scorecard.XXXXXX")"
  if ! command -v rsync >/dev/null 2>&1; then
    printf 'error: rsync required to stage a scorecard tree (excludes build/)\n' >&2
    rm -rf "${stage}"
    return 1
  fi
  rsync -a \
    --exclude build/ \
    --exclude scan-build-report/ \
    "${REPO_ROOT}/" "${stage}/"
  printf '%s\n' "${stage}"
}

SCORECARD_STAGE="$(prepare_scorecard_tree)"
cleanup_scorecard_tree() {
  rm -rf "${SCORECARD_STAGE}"
}
trap cleanup_scorecard_tree EXIT

printf '\n── OpenSSF Scorecard (%s) ──\n' "${IMAGE}"
printf 'Source: %s (staged; build/ excluded)\n\n' "${REPO_ROOT}"

engine_run() {
  local mount_root="${SCORECARD_STAGE}"
  if [[ -n ${OUTPUT_PATH} ]]; then
    local full_out tmp_raw
    full_out="$(cd -- "$(dirname -- "${OUTPUT_PATH}")" && pwd)/$(basename -- "${OUTPUT_PATH}")"
    mkdir -p "$(dirname -- "${full_out}")"
    tmp_raw="$(mktemp)"
    if ! "${ENGINE}" run --rm \
      "${PLATFORM_ARGS[@]}" \
      --user 0 \
      -v "${mount_root}:/src" \
      "${IMAGE}" \
      "${SC_ARGS[@]}" >"${tmp_raw}"; then
      rm -f "${tmp_raw}"
      return 1
    fi

    if [[ ${FORMAT} == json ]] && [[ ${OSSF_SCORECARD_RAW_JSON:-0} != 1 ]] && command -v jq >/dev/null 2>&1; then
      if ! jq . "${tmp_raw}" >"${full_out}"; then
        rm -f "${tmp_raw}"
        printf 'error: jq could not parse scorecard JSON output\n' >&2
        return 1
      fi
      rm -f "${tmp_raw}"
    elif [[ ${FORMAT} == json ]] && [[ ${OSSF_SCORECARD_RAW_JSON:-0} != 1 ]]; then
      printf '%s\n' 'warning: jq not found; wrote compact JSON to output file.' >&2
      mv -f "${tmp_raw}" "${full_out}"
    else
      mv -f "${tmp_raw}" "${full_out}"
    fi
  else
    if [[ ${FORMAT} == json ]] && [[ ${OSSF_SCORECARD_RAW_JSON:-0} != 1 ]] && command -v jq >/dev/null 2>&1; then
      "${ENGINE}" run --rm \
        "${PLATFORM_ARGS[@]}" \
        --user 0 \
        -v "${mount_root}:/src" \
        "${IMAGE}" \
        "${SC_ARGS[@]}" | jq .
    elif [[ ${FORMAT} == json ]] && [[ ${OSSF_SCORECARD_RAW_JSON:-0} != 1 ]]; then
      printf '%s\n' 'warning: jq not found; printing unformatted JSON (one line).' >&2
      "${ENGINE}" run --rm \
        "${PLATFORM_ARGS[@]}" \
        --user 0 \
        -v "${mount_root}:/src" \
        "${IMAGE}" \
        "${SC_ARGS[@]}"
    else
      "${ENGINE}" run --rm \
        "${PLATFORM_ARGS[@]}" \
        --user 0 \
        -v "${mount_root}:/src" \
        "${IMAGE}" \
        "${SC_ARGS[@]}"
    fi
  fi
}

engine_run

printf '\n── Scorecard finished ──\n'
