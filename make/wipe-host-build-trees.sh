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

# Remove stale lint/test/verify build trees so those targets always see current sources.
#
# Usage: bash make/wipe-host-build-trees.sh {test|lint|verify|ci}
#
# Opt out (incremental dev rebuilds): PCSC_FIDO_KEEP_HOST_BUILDS=1 make test|lint|verify
# The ``ci`` scope always wipes (Main CI / ci-run-tests); PCSC_FIDO_KEEP_HOST_BUILDS is ignored.

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: bash make/wipe-host-build-trees.sh {test|lint|verify|ci}

Scopes:
  test   -- build/unit (plain unit-test CMake tree) + build-{asan,ubsan,valgrind,tsan}
  lint   -- build/lint, build/clang-tidy-compile-db
  verify -- test trees + scan-build-report
  ci     -- build/ci, scan-build-report, lint trees, test trees
           (always wipes; no opt-out)

Set PCSC_FIDO_KEEP_HOST_BUILDS=1 to skip wiping for test/lint/verify only (faster local iteration).
EOF
}

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
scope="${1:-}"

wipe_dir() {
  local dir="$1"
  if [[ -d ${dir} ]]; then
    printf -- '-- wiping %s --\n' "${dir#"${repo_root}/"}" >&2
    rm -rf "${dir}"
  fi
}

wipe_lint_build_trees() {
  wipe_dir "${repo_root}/build/lint"
  wipe_dir "${repo_root}/build/clang-tidy-compile-db"
}

wipe_test_build_trees() {
  # Dedicated unit-test tree (Makefile TEST_BUILD_DIR=build/unit), same role as
  # nero-nfc tests/build -- never wipe top-level build/ (package/release TryCompile).
  wipe_dir "${repo_root}/build/unit"
  wipe_dir "${repo_root}/build-asan"
  wipe_dir "${repo_root}/build-ubsan"
  wipe_dir "${repo_root}/build-valgrind"
  wipe_dir "${repo_root}/build-tsan"
}

wipe_ci_build_trees() {
  wipe_dir "${repo_root}/build/ci"
  wipe_dir "${repo_root}/scan-build-report"
  wipe_lint_build_trees
  wipe_test_build_trees
}

if [[ ${PCSC_FIDO_KEEP_HOST_BUILDS:-0} == "1" && ${scope} != ci ]]; then
  exit 0
fi

case "${scope}" in
  test)
    wipe_test_build_trees
    ;;
  lint)
    wipe_lint_build_trees
    ;;
  verify)
    wipe_test_build_trees
    wipe_dir "${repo_root}/scan-build-report"
    ;;
  ci)
    wipe_ci_build_trees
    ;;
  -h | --help)
    usage
    exit 0
    ;;
  *)
    printf 'error: unknown wipe scope: %s\n' "${scope}" >&2
    usage >&2
    exit 2
    ;;
esac
