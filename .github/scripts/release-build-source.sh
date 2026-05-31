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

# Create a git-archive source tarball for a release tag (GNU-style prefix directory).
#
# Usage:
#   TAG=v0.1.0 bash .github/scripts/release-build-source.sh
#   bash .github/scripts/release-build-source.sh --tag v0.1.0 --output-dir dist

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

TAG=""
OUTPUT_DIR="${ROOT}/dist"

usage() {
  cat <<'EOF'
Usage: release-build-source.sh [--tag TAG] [--output-dir DIR]

Environment:
  TAG   Release tag (e.g. v0.1.0); required if --tag omitted

Writes: dist/pcsc-fido-VERSION.tar.gz  (VERSION = tag without leading v)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag)
      TAG="${2:-}"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="${2:-}"
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      printf 'error: unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

TAG="${TAG:-${GITHUB_REF_NAME:-}}"
if [[ -z ${TAG} ]]; then
  printf 'error: release tag required (--tag or TAG / GITHUB_REF_NAME)\n' >&2
  exit 2
fi

VERSION="${TAG#v}"
if [[ -z ${VERSION} ]]; then
  printf 'error: invalid tag: %s\n' "$TAG" >&2
  exit 2
fi

mkdir -p "${OUTPUT_DIR}"
archive="${OUTPUT_DIR}/pcsc-fido-${VERSION}.tar.gz"

git -C "${ROOT}" archive \
  --format=tar.gz \
  --prefix="pcsc-fido-${VERSION}/" \
  -o "${archive}" \
  "${TAG}"

printf '── release-build-source: %s ──\n' "${archive}"
