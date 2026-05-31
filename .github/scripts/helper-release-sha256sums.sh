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

# Write GNU sha256sum(1) checksums for release artifacts (GoReleaser / Linux convention).
# Verification: sha256sum -c SHA256SUMS
#
# Usage:
#   bash .github/scripts/helper-release-sha256sums.sh [dist-dir]

set -euo pipefail

DIST_DIR="${1:-dist}"
if [[ ! -d ${DIST_DIR} ]]; then
  printf 'error: directory not found: %s\n' "${DIST_DIR}" >&2
  exit 1
fi

mapfile -t files < <(
  find "${DIST_DIR}" -maxdepth 1 -type f ! -name 'SHA256SUMS' -printf '%f\n' | LC_ALL=C sort
)

if ((${#files[@]} == 0)); then
  printf 'error: no files to checksum under %s\n' "${DIST_DIR}" >&2
  exit 1
fi

(
  cd "${DIST_DIR}"
  sha256sum "${files[@]}" >SHA256SUMS
)

printf '── helper-release-sha256sums: %s (%s files) ──\n' "${DIST_DIR}/SHA256SUMS" "${#files[@]}"
