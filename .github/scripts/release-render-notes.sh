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

# Render .github/release-notes.md for gh release create --notes-file.
#
# Usage:
#   TAG=v0.1.0 bash .github/scripts/release-render-notes.sh [.github/release-notes.md]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TEMPLATE="${1:-${ROOT}/.github/release-notes.md}"

TAG="${TAG:-${GITHUB_REF_NAME:-}}"
if [[ -z ${TAG} ]]; then
  printf 'error: TAG or GITHUB_REF_NAME required\n' >&2
  exit 2
fi

if [[ ! -f ${TEMPLATE} ]]; then
  printf 'error: template not found: %s\n' "${TEMPLATE}" >&2
  exit 1
fi

VERSION="${TAG#v}"
# Escape sed replacement metacharacters in tag/version.
escape_sed() { printf '%s' "$1" | sed -e 's/[&/\]/\\&/g'; }
TAG_ESC="$(escape_sed "${TAG}")"
VERSION_ESC="$(escape_sed "${VERSION}")"

sed \
  -e "s/@TAG@/${TAG_ESC}/g" \
  -e "s/@VERSION@/${VERSION_ESC}/g" \
  "${TEMPLATE}"
