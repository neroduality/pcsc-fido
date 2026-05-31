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

# Fail if dist/ is missing expected Release workflow outputs before publish.
#
# Usage:
#   TAG=v0.1.0 bash .github/scripts/release-verify-artifacts.sh [dist-dir]

set -euo pipefail

DIST_DIR="${1:-dist}"
TAG="${TAG:-${GITHUB_REF_NAME:-}}"

if [[ ! -d ${DIST_DIR} ]]; then
  printf 'error: directory not found: %s\n' "${DIST_DIR}" >&2
  exit 1
fi

shopt -s nullglob
debs=("${DIST_DIR}"/*.deb)
rpms=("${DIST_DIR}"/*.rpm)
sources=("${DIST_DIR}"/pcsc-fido-*.tar.gz)
checksum=("${DIST_DIR}"/SHA256SUMS)

expected_debs=6
expected_rpms=6
expected_sources=1

# Filename suffixes CPack emits (must match release.yml matrices + toolchains).
expected_deb_suffixes=(amd64 arm64 armhf ppc64el riscv64 s390x)
expected_rpm_suffixes=(x86_64 aarch64 armv7hl ppc64le riscv64 s390x)

fail=0
check_count() {
  local label="$1"
  local expected="$2"
  local actual="$3"
  if [[ ${actual} -ne ${expected} ]]; then
    printf 'error: expected %s %s, found %s\n' "${expected}" "${label}" "${actual}" >&2
    fail=1
  else
    printf 'ok: %s %s\n' "${actual}" "${label}"
  fi
}

check_glob() {
  local label="$1"
  local pattern="$2"
  local matches=()
  mapfile -t matches < <(compgen -G "${pattern}" || true)
  if ((${#matches[@]} == 0)); then
    printf 'error: missing %s (pattern %s)\n' "${label}" "${pattern}" >&2
    fail=1
  else
    printf 'ok: %s (%s)\n' "${label}" "$(basename "${matches[0]}")"
  fi
}

check_count 'DEB packages' "${expected_debs}" "${#debs[@]}"
check_count 'RPM packages' "${expected_rpms}" "${#rpms[@]}"
check_count 'source tarballs (pcsc-fido-*.tar.gz)' "${expected_sources}" "${#sources[@]}"

for suffix in "${expected_deb_suffixes[@]}"; do
  check_glob "DEB ${suffix}" "${DIST_DIR}/*_${suffix}.deb"
done

for suffix in "${expected_rpm_suffixes[@]}"; do
  check_glob "RPM ${suffix}" "${DIST_DIR}/*.${suffix}.rpm"
done

if ((${#checksum[@]} != 1)); then
  printf 'error: expected exactly one SHA256SUMS, found %s\n' "${#checksum[@]}" >&2
  fail=1
else
  printf 'ok: SHA256SUMS present\n'
fi

if [[ -n ${TAG} ]]; then
  version="${TAG#v}"
  expected_source="pcsc-fido-${version}.tar.gz"
  if [[ ! -f ${DIST_DIR}/${expected_source} ]]; then
    printf 'error: missing source archive %s\n' "${expected_source}" >&2
    fail=1
  else
    printf 'ok: source archive %s\n' "${expected_source}"
  fi
fi

if ((fail != 0)); then
  printf '\ncontents of %s:\n' "${DIST_DIR}" >&2
  ls -la "${DIST_DIR}" >&2 || true
  exit 1
fi

printf '── release-verify-artifacts: dist/ ready to publish ──\n'
