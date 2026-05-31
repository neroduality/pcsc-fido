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

# libFuzzer compiler probe for make fuzz / run-local-fuzz.sh.
#
# Usage (source from run-local-fuzz.sh):
#   pcsc_fido_resolve_fuzz_compiler probe.c probe.out
#   -> prints "compiler<TAB>sanitizer" on success
#
#   pcsc_fido_fuzz_install_hint
set -euo pipefail

if [[ ${BASH_SOURCE[0]} == "${0}" ]]; then
  printf '%s\n' "error: source helper-fuzz-probe.sh instead of executing it" >&2
  exit 1
fi

pcsc_fido_clang_major_version() {
  local compiler="${1:-clang}"
  local ver=""
  command -v "${compiler}" >/dev/null 2>&1 || return 1
  ver="$("${compiler}" --version 2>/dev/null | sed -n '1s/.*clang version \([0-9][0-9]*\).*/\1/p')"
  [[ -n ${ver} ]] || return 1
  printf '%s' "${ver}"
}

pcsc_fido_is_clang_compiler() {
  case "${1:-}" in
    clang | clang-[0-9]*) return 0 ;;
    *)
      case "$("${1}" --version 2>/dev/null | head -n1)" in
        *clang*) return 0 ;;
        *) return 1 ;;
      esac
      ;;
  esac
}

pcsc_fido_fuzz_compiler_candidates() {
  local -a seen=() out=() cand
  local cc_pref="${CC:-}"

  pcsc_fido_fuzz_candidate_add() {
    local name="$1"
    [[ -n ${name} ]] || return 0
    local x
    for x in "${seen[@]}"; do
      [[ ${x} == "${name}" ]] && return 0
    done
    command -v "${name}" >/dev/null 2>&1 || return 0
    seen+=("${name}")
    out+=("${name}")
  }

  if [[ -n ${cc_pref} ]] && pcsc_fido_is_clang_compiler "${cc_pref}"; then
    pcsc_fido_fuzz_candidate_add "${cc_pref}"
  fi
  pcsc_fido_fuzz_candidate_add clang
  shopt -s nullglob
  for cand in /usr/bin/clang-[0-9]*; do
    pcsc_fido_fuzz_candidate_add "$(basename "${cand}")"
  done
  shopt -u nullglob
  if [[ -n ${cc_pref} ]] && ! pcsc_fido_is_clang_compiler "${cc_pref}"; then
    pcsc_fido_fuzz_candidate_add "${cc_pref}"
  fi
  for cand in gcc g++ cc; do
    pcsc_fido_fuzz_candidate_add "${cand}"
  done

  printf '%s\n' "${out[@]}"
}

pcsc_fido_compiler_supports_libfuzzer() {
  local candidate="$1"
  local san="$2"
  local probe_src="$3"
  local probe_bin="$4"

  command -v "${candidate}" >/dev/null 2>&1 &&
    "${candidate}" -fsanitize="${san}" -fno-omit-frame-pointer "${probe_src}" -o "${probe_bin}" \
      >/dev/null 2>&1
}

pcsc_fido_resolve_fuzz_compiler() {
  local probe_src="$1"
  local probe_bin="$2"
  local candidate san

  while IFS= read -r candidate; do
    [[ -n ${candidate} ]] || continue
    for san in fuzzer,address,undefined fuzzer,address fuzzer; do
      if pcsc_fido_compiler_supports_libfuzzer "${candidate}" "${san}" "${probe_src}" \
        "${probe_bin}"; then
        printf '%s\t%s\n' "${candidate}" "${san}"
        return 0
      fi
    done
  done < <(pcsc_fido_fuzz_compiler_candidates)
  return 1
}

pcsc_fido_fuzz_install_hint() {
  local clang_ver="" deb_arch=""

  if command -v clang >/dev/null 2>&1; then
    clang_ver="$(pcsc_fido_clang_major_version clang || true)"
  fi
  if command -v dpkg-architecture >/dev/null 2>&1; then
    deb_arch="$(dpkg-architecture -qDEB_HOST_ARCH 2>/dev/null || true)"
  fi

  if command -v apt-get >/dev/null 2>&1; then
    if [[ -n ${clang_ver} ]]; then
      printf 'hint: Debian/Ubuntu: sudo apt-get install -y libclang-rt-%s-dev\n' "${clang_ver}" >&2
      if [[ -n ${deb_arch} ]]; then
        printf 'hint:   fallback: sudo apt-get install -y libclang-rt-dev-%s\n' "${deb_arch}" >&2
      fi
    else
      printf 'hint: Debian/Ubuntu: sudo apt-get install -y clang libclang-rt-*-dev\n' >&2
    fi
    printf 'hint:   or: sudo bash .github/scripts/install-linux-deps.sh\n' >&2
  elif command -v dnf >/dev/null 2>&1; then
    printf 'hint: Fedora: sudo dnf install -y clang compiler-rt\n' >&2
  else
    printf 'hint: install Clang with compiler-rt (libFuzzer runtime)\n' >&2
  fi
  if [[ -n ${CC:-} ]] && ! pcsc_fido_is_clang_compiler "${CC}"; then
    printf 'note: CC=%s is not Clang; libFuzzer needs clang + compiler-rt (unset CC or use CC=clang)\n' \
      "${CC}" >&2
  elif [[ -z ${CC:-} ]] && command -v cc >/dev/null 2>&1 && ! command -v clang >/dev/null 2>&1; then
    printf 'note: only gcc/cc found; install clang and libclang-rt-*-dev for libFuzzer\n' >&2
  fi
}
