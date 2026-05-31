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

# Clang static analyzer on the pcsc-fido tree.
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
build_dir="${repo_root}/build/scan"
report_dir="${repo_root}/scan-build-report"

resolve_scan_build() {
  local c v p
  if command -v scan-build >/dev/null 2>&1; then
    printf '%s' "scan-build"
    return 0
  fi
  for v in 21 20 19 18 17 16 15 14; do
    c="scan-build-${v}"
    if command -v "$c" >/dev/null 2>&1; then
      printf '%s' "$c"
      return 0
    fi
  done
  for p in /usr/lib64/llvm*/bin/scan-build /usr/lib/llvm*/bin/scan-build; do
    if [[ -x ${p} ]]; then
      printf '%s' "${p}"
      return 0
    fi
  done
  return 1
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
  cat <<'EOF'
Usage: bash .github/scripts/ci-scan-build.sh

Requires: cmake, Ninja or Make, clang scan-build (clang-tools / llvm packages).
EOF
  exit 0
fi

if ! command -v cmake >/dev/null 2>&1; then
  printf 'error: cmake not found\n' >&2
  exit 1
fi

scan_build="${PCSC_FIDO_SCAN_BUILD_CMD:-}"
if [[ -z $scan_build ]]; then
  if ! scan_build="$(resolve_scan_build)"; then
    printf 'error: scan-build not found (install clang-analyzer or clang-tools)\n' >&2
    exit 1
  fi
fi

generator="Unix Makefiles"
if command -v ninja >/dev/null 2>&1; then
  generator="Ninja"
fi

rm -rf "${build_dir}" "${report_dir}"
mkdir -p "${report_dir}"

cmake \
  -S "${repo_root}" \
  -B "${build_dir}" \
  -G "${generator}" \
  -DCMAKE_BUILD_TYPE=Debug

procs="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"

scan_status=0
if [[ ${generator} == "Ninja" ]]; then
  "${scan_build}" --status-bugs -o "${report_dir}" ninja -C "${build_dir}" -j "${procs}" || scan_status=$?
else
  "${scan_build}" --status-bugs -o "${report_dir}" cmake --build "${build_dir}" -j "${procs}" || scan_status=$?
fi

pcsc_fido_scan_build_write_summary() {
  local status="$1"
  local -a html_reports=()
  local report_html

  mkdir -p "${report_dir}"
  shopt -s nullglob
  html_reports=("${report_dir}"/*/index.html)
  shopt -u nullglob

  {
    printf 'completed_at: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'exit_status: %s\n' "${status}"
    printf 'bug_reports: %s\n' "${#html_reports[@]}"
    if ((${#html_reports[@]} > 0)); then
      printf 'html_reports:\n'
      for report_html in "${html_reports[@]}"; do
        printf '  - %s\n' "${report_html#"${repo_root}"/}"
      done
    else
      printf 'html_reports: none (scan-build removes empty report dirs when clean)\n'
    fi
  } >"${report_dir}/summary.txt"
}

pcsc_fido_scan_build_write_summary "${scan_status}"

if ((scan_status != 0)); then
  exit "${scan_status}"
fi

if compgen -G "${report_dir}/*/index.html" >/dev/null; then
  printf 'scan-build HTML: %s\n' "${report_dir}"/*/index.html
else
  printf 'scan-build: no bugs found (see %s/summary.txt)\n' "${report_dir}"
fi
