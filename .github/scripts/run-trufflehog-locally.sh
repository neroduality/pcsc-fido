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

# Run TruffleHog OSS locally via Docker or Podman (same tool family as `.github/workflows/trufflehog.yml`).
#
# Usage:
#   bash .github/scripts/run-trufflehog-locally.sh
#   bash .../run-trufflehog-locally.sh -- git file:///repo --only-verified --json
#
# Without a git metadata dir under this repository root, defaults to `filesystem /repo`
# so subtree checkouts still scan (CI full clones still use `git file:///repo`).
#
set -euo pipefail

usage() {
  cat <<'EOF'
Run TruffleHog against this checkout using Docker or Podman.

Default CLI when /.git exists: `git file:///repo`.
Otherwise: `filesystem /repo` (mounted read-only at /repo).

Arguments after `--` replace the entire default TruffleHog command line.

Environment:
  CONTAINER_ENGINE      docker (default) or podman
  CI_PLATFORM           Default linux/amd64 when unset. Set empty (CI_PLATFORM=) for native arch.
  TRUFFLEHOG_IMAGE      Image (default: digest-pinned trufflesecurity/trufflehog:3.95.8)

EOF
}

if [[ ${1:-} == "-h" ]] || [[ ${1:-} == "--help" ]]; then
  usage
  exit 0
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"

ENGINE="${CONTAINER_ENGINE:-docker}"
if ! command -v "${ENGINE}" >/dev/null 2>&1; then
  printf 'error: %s not found (install or set CONTAINER_ENGINE)\n' "${ENGINE}" >&2
  exit 1
fi

TRUFFLEHOG_IMAGE="${TRUFFLEHOG_IMAGE:-trufflesecurity/trufflehog:3.95.8@sha256:d52e62fe0237bf0199cb79f94593051300b0989d9aeab8b431001d9f75e469c1}"

PLATFORM_ARGS=()
_resolved_platform="${CI_PLATFORM-linux/amd64}"
if [[ -n ${_resolved_platform} ]]; then
  PLATFORM_ARGS+=(--platform "${_resolved_platform}")
fi

hog_cmd=()
if (($# > 0)); then
  if [[ $1 == "--" ]]; then
    shift
    hog_cmd=("$@")
  else
    hog_cmd=("$@")
  fi
fi

if ((${#hog_cmd[@]} == 0)); then
  if [[ -e "${REPO_ROOT}/.git" ]]; then
    hog_cmd=(git file:///repo)
  else
    hog_cmd=(filesystem /repo)
  fi
fi

printf '\n-- TruffleHog (%s) --\n' "${TRUFFLEHOG_IMAGE}"
printf 'Repo mount: %s -> /repo\n\n' "${REPO_ROOT}"

exec "${ENGINE}" run --rm \
  "${PLATFORM_ARGS[@]}" \
  -v "${REPO_ROOT}:/repo:ro" \
  "${TRUFFLEHOG_IMAGE}" \
  "${hog_cmd[@]}"
