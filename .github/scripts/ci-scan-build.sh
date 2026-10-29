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

# Prefer clang beside scan-build, then clang-NN / llvm-NN (Debian may omit bare clang).
resolve_analyzer_cc() {
  local sb dir base ver p resolved_sb
  sb="$(command -v "$1" 2>/dev/null || true)"
  if [[ -n ${sb} ]]; then
    dir="$(dirname -- "$(readlink -f -- "${sb}")")"
    if [[ -x ${dir}/clang ]]; then
      printf '%s' "${dir}/clang"
      return 0
    fi
  fi
  base="${1##*/}"
  ver=""
  resolved_sb=""
  if [[ -n ${sb} ]]; then
    resolved_sb="$(readlink -f -- "${sb}" 2>/dev/null || true)"
  fi
  # Debian scan-build is /usr/bin/scan-build -> scan-build-N, and the real
  # path is /usr/share/clang/scan-build-N, which does not contain /llvm-N/.
  if [[ ${base} =~ ^scan-build-([0-9]+)$ ]]; then
    ver="${BASH_REMATCH[1]}"
  elif [[ ${resolved_sb} =~ scan-build-([0-9]+) ]]; then
    ver="${BASH_REMATCH[1]}"
  elif [[ ${resolved_sb} =~ /llvm-([0-9]+)/ ]]; then
    ver="${BASH_REMATCH[1]}"
  fi
  if [[ -n ${ver} ]]; then
    if command -v "clang-${ver}" >/dev/null 2>&1; then
      command -v "clang-${ver}"
      return 0
    fi
    if [[ -x /usr/lib/llvm-${ver}/bin/clang ]]; then
      printf '%s' "/usr/lib/llvm-${ver}/bin/clang"
      return 0
    fi
  fi
  if command -v clang >/dev/null 2>&1; then
    command -v clang
    return 0
  fi
  for p in /usr/lib/llvm-*/bin/clang /usr/lib64/llvm*/bin/clang; do
    if [[ -x ${p} ]]; then
      printf '%s' "${p}"
      return 0
    fi
  done
  for ver in 21 20 19 18 17 16 15 14; do
    if command -v "clang-${ver}" >/dev/null 2>&1; then
      command -v "clang-${ver}"
      return 0
    fi
  done
  return 1
}

# ccc-analyzer is not a compiler CMake recognizes, so CheckIPOSupported
# otherwise archives with CMAKE_C_COMPILER_AR-NOTFOUND and ranlibs with
# CMAKE_C_COMPILER_RANLIB-NOTFOUND. Pass the llvm-ar / llvm-ranlib that match
# --use-cc (Debian: llvm-ar-N from the llvm-N package, not clang-tools).
resolve_llvm_tool() {
  local cc="$1" tool="$2" dir ver base resolved dump p
  local -a found=()
  resolved="$(readlink -f -- "${cc}" 2>/dev/null || printf '%s' "${cc}")"
  dir="$(dirname -- "${resolved}")"
  if [[ -x ${dir}/${tool} ]]; then
    printf '%s' "${dir}/${tool}"
    return 0
  fi
  # /usr/bin/clang is usually a symlink to clang-N. The version is on the
  # target, and Debian ships llvm-ar-N with no unversioned llvm-ar.
  ver=""
  base="${resolved##*/}"
  if [[ ${base} =~ clang-([0-9]+) ]]; then
    ver="${BASH_REMATCH[1]}"
  elif [[ ${cc##*/} =~ clang-([0-9]+) ]]; then
    ver="${BASH_REMATCH[1]}"
  elif [[ ${resolved} =~ /llvm-([0-9]+)/ ]]; then
    ver="${BASH_REMATCH[1]}"
  fi
  if [[ -z ${ver} && -x ${cc} ]]; then
    dump="$("${cc}" -dumpversion 2>/dev/null || true)"
    if [[ ${dump} =~ ^([0-9]+) ]]; then
      ver="${BASH_REMATCH[1]}"
    fi
  fi
  if [[ -n ${ver} ]]; then
    if command -v "${tool}-${ver}" >/dev/null 2>&1; then
      command -v "${tool}-${ver}"
      return 0
    fi
    for p in \
      "/usr/lib/llvm-${ver}/bin/${tool}" \
      "/usr/lib64/llvm${ver}/bin/${tool}" \
      "/usr/lib64/llvm-${ver}/bin/${tool}"; do
      if [[ -x ${p} ]]; then
        printf '%s' "${p}"
        return 0
      fi
    done
  fi
  if command -v "${tool}" >/dev/null 2>&1; then
    command -v "${tool}"
    return 0
  fi
  shopt -s nullglob
  found=(/usr/bin/"${tool}"-* /usr/lib/llvm-*/bin/"${tool}" /usr/lib64/llvm*/bin/"${tool}")
  shopt -u nullglob
  if ((${#found[@]} > 0)); then
    printf '%s' "${found[-1]}"
    return 0
  fi
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

if ! analyzer_cc="$(resolve_analyzer_cc "${scan_build}")"; then
  printf 'error: no clang found for %s (install clang)\n' "${scan_build}" >&2
  exit 1
fi

generator="Unix Makefiles"
if command -v ninja >/dev/null 2>&1; then
  generator="Ninja"
fi

cmake_bin_args=()
if ! analyzer_ar="$(resolve_llvm_tool "${analyzer_cc}" llvm-ar)"; then
  printf 'warning: llvm-ar not found for %s; using system ar\n' "${analyzer_cc}" >&2
  analyzer_ar="$(command -v ar || true)"
fi
if [[ -z ${analyzer_ar} ]]; then
  printf 'error: no ar found for %s\n' "${analyzer_cc}" >&2
  exit 1
fi
if ! analyzer_ranlib="$(resolve_llvm_tool "${analyzer_cc}" llvm-ranlib)"; then
  printf 'warning: llvm-ranlib not found for %s; using system ranlib\n' "${analyzer_cc}" >&2
  analyzer_ranlib="$(command -v ranlib || true)"
fi
if [[ -z ${analyzer_ranlib} ]]; then
  printf 'error: no ranlib found for %s\n' "${analyzer_cc}" >&2
  exit 1
fi
cmake_bin_args+=(
  "-DCMAKE_C_COMPILER_AR=${analyzer_ar}"
  "-DCMAKE_C_COMPILER_RANLIB=${analyzer_ranlib}"
)

rm -rf "${build_dir}" "${report_dir}"
mkdir -p "${report_dir}"

# CMake caches the compiler at configure time, so the configure has to run under
# scan-build as well: that is what makes CMAKE_C_COMPILER ccc-analyzer. A plain
# configure caches the real compiler and the build below analyzes nothing.
# --use-cc makes ccc-analyzer compile with clang rather than its gcc default, so
# the hardening probes test the compiler whose flags the analyzer is handed.
"${scan_build}" --use-cc="${analyzer_cc}" -o "${report_dir}" cmake \
  -S "${repo_root}" \
  -B "${build_dir}" \
  -G "${generator}" \
  -DCMAKE_BUILD_TYPE=Debug \
  -DPCSC_FIDO_DEBUG_SANITIZERS=OFF \
  "${cmake_bin_args[@]}"

if ! grep -Eq '^CMAKE_C_COMPILER:[A-Z]+=.*ccc-analyzer$' "${build_dir}/CMakeCache.txt"; then
  printf 'error: %s/CMakeCache.txt does not use ccc-analyzer as CMAKE_C_COMPILER; the scan would analyze nothing\n' \
    "${build_dir}" >&2
  exit 1
fi

procs="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"

scan_status=0
if [[ ${generator} == "Ninja" ]]; then
  "${scan_build}" --use-cc="${analyzer_cc}" --status-bugs -o "${report_dir}" \
    ninja -C "${build_dir}" -j "${procs}" || scan_status=$?
else
  "${scan_build}" --use-cc="${analyzer_cc}" --status-bugs -o "${report_dir}" \
    cmake --build "${build_dir}" -j "${procs}" || scan_status=$?
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
