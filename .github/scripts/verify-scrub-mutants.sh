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

# Prove the scrub-audit tests bite: delete one wipe site in src/ at a time,
# rebuild only the covering test, and require it to go red. A site whose
# deletion leaves its test green is a vacuous assertion (or a missing one).
#
# Sites: every `PCSC_FIDO_SCRUB_ON_EXIT(` guard and every direct
# `pcsc_fido_secure_clear(` call that opens a statement in src/ (mem_util.c,
# which defines the primitive, excluded; comments that merely mention the
# names are not sites). Higher-level reset calls such as
# pcsc_fido_daemon_pending_request_reset() at shutdown are out of scope.
# Also rejects `>=` / `>` (and leading `<` / `<=`) lower-bound assertions on
# scrub_hook counters in tests/: every count must be exact. The call's
# argument list may contain nested parentheses (`sizeof(...)`, another call).
#
# `make test` runs this on a from-scratch unsanitized build/unit after ctest
# is green. CI does the same via `make test`; it does not point this script
# at the ASan build/ci tree. ASan, UBSan, TSan, Valgrind, and package ctest
# do not run it.
#
# Usage (from pcsc-fido root, BUILD_DIR already configured with BUILD_TESTING=ON):
#   bash .github/scripts/verify-scrub-mutants.sh --build-dir build/unit
set -euo pipefail

# make captures this script on a pipe. Without line buffering the "killed"
# lines flush in one burst, then the next silent rebuild looks hung.
if [[ -z ${PCSC_FIDO_SCRUB_LINEBUF:-} ]] && command -v stdbuf >/dev/null 2>&1; then
  export PCSC_FIDO_SCRUB_LINEBUF=1
  exec stdbuf -oL -eL bash "${BASH_SOURCE[0]}" "$@"
fi

build_dir=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --build-dir)
      build_dir="${2:-}"
      shift 2
      ;;
    -h | --help)
      printf 'Usage: %s --build-dir DIR\n' "$(basename "$0")"
      exit 0
      ;;
    *)
      printf 'error: unexpected argument: %s\n' "$1" >&2
      exit 2
      ;;
  esac
done

repo_root="$(pwd)"
if [[ ! -f "${repo_root}/CMakeLists.txt" ]] || [[ ! -d "${repo_root}/src" ]]; then
  printf 'error: run from pcsc-fido root\n' >&2
  exit 1
fi
if [[ -z ${build_dir} || ! -f "${build_dir}/CMakeCache.txt" ]]; then
  printf 'error: --build-dir must be a configured CMake tree (BUILD_TESTING=ON)\n' >&2
  exit 2
fi
if ! grep -q '^BUILD_TESTING:BOOL=ON' "${build_dir}/CMakeCache.txt"; then
  printf 'error: %s was not configured with BUILD_TESTING=ON\n' "${build_dir}" >&2
  exit 2
fi
if grep -qE '^PCSC_FIDO_ENABLE_(ASAN|UBSAN|TSAN):BOOL=ON$|^PCSC_FIDO_DEBUG_SANITIZERS:BOOL=ON$' \
  "${build_dir}/CMakeCache.txt"; then
  printf 'error: %s has a sanitizer enabled; run the scrub sweep on a fresh unsanitized tree (make test)\n' \
    "${build_dir}" >&2
  exit 2
fi

# Which unit test audits the wipes in each source file. A source file that
# gains a wipe site but has no entry here fails the run: add the mapping and
# the assertion together.
declare -A covering_test=(
  ["src/apdu_chain.c"]=test_apdu_chain
  ["src/ctaphid.c"]=test_ctaphid
  ["src/daemon_request_handler.c"]=test_daemon_request_handler
  ["src/daemon_uhid_loop.c"]=test_daemon_uhid_loop
  ["src/exchange_orchestrator.c"]=test_exchange_orchestrator
  ["src/pcsc_bridge.c"]=test_pcsc_bridge
  ["src/pcsc_reader_ops.c"]=test_reader_ops
  ["src/pcsc_session.c"]=test_pcsc_bridge
  ["src/request_assembly.c"]=test_request_assembly
  ["src/uhid_transport.c"]=test_uhid_transport
)

# 1. No lower-bound assertions on the hook counters. Walk each call's
# parentheses so `scrub_hook_calls_with_len(sizeof(x)) >= 1` is caught; a
# `[^)]*` pattern stops at the inner `)` and would miss it.
scrub_lower_bounds=0
for scrub_file in "${repo_root}"/tests/*.c; do
  scrub_lineno=0
  while IFS= read -r scrub_line || [[ -n ${scrub_line} ]]; do
    scrub_lineno=$((scrub_lineno + 1))
    scrub_code="${scrub_line%%//*}"
    scrub_i=0
    scrub_len=${#scrub_code}
    while ((scrub_i < scrub_len)); do
      if [[ ${scrub_code:scrub_i} != scrub_hook_* ]]; then
        scrub_i=$((scrub_i + 1))
        continue
      fi
      if ((scrub_i > 0)) && [[ ${scrub_code:scrub_i-1:1} == [[:alnum:]_] ]]; then
        scrub_i=$((scrub_i + 1))
        continue
      fi
      [[ ${scrub_code:scrub_i} =~ ^(scrub_hook_[a-z_]+) ]] || {
        scrub_i=$((scrub_i + 1))
        continue
      }
      scrub_name="${BASH_REMATCH[1]}"
      scrub_start=${scrub_i}
      scrub_i=$((scrub_i + ${#scrub_name}))
      while ((scrub_i < scrub_len)) && [[ ${scrub_code:scrub_i:1} == [[:space:]] ]]; do
        scrub_i=$((scrub_i + 1))
      done
      if ((scrub_i >= scrub_len)) || [[ ${scrub_code:scrub_i:1} != '(' ]]; then
        continue
      fi
      scrub_depth=0
      while ((scrub_i < scrub_len)); do
        scrub_ch=${scrub_code:scrub_i:1}
        if [[ ${scrub_ch} == '(' ]]; then
          scrub_depth=$((scrub_depth + 1))
        elif [[ ${scrub_ch} == ')' ]]; then
          scrub_depth=$((scrub_depth - 1))
          if ((scrub_depth == 0)); then
            scrub_i=$((scrub_i + 1))
            break
          fi
        fi
        scrub_i=$((scrub_i + 1))
      done
      scrub_pre=${scrub_start}
      while ((scrub_pre > 0)) && [[ ${scrub_code:scrub_pre-1:1} == [[:space:]] ]]; do
        scrub_pre=$((scrub_pre - 1))
      done
      scrub_hit=0
      if ((scrub_pre >= 2)) && [[ ${scrub_code:scrub_pre-2:2} == '<=' ]]; then
        scrub_hit=1
      elif ((scrub_pre >= 1)) && [[ ${scrub_code:scrub_pre-1:1} == '<' ]]; then
        if ((scrub_pre < 2)) || [[ ${scrub_code:scrub_pre-2:1} != '<' ]]; then
          scrub_hit=1
        fi
      fi
      while ((scrub_i < scrub_len)) && [[ ${scrub_code:scrub_i:1} == [[:space:]] ]]; do
        scrub_i=$((scrub_i + 1))
      done
      if [[ ${scrub_code:scrub_i:2} == '>=' || ${scrub_code:scrub_i:1} == '>' ]]; then
        scrub_hit=1
      fi
      if ((scrub_hit)); then
        printf '%s:%s:%s\n' "${scrub_file#"${repo_root}/"}" "${scrub_lineno}" "${scrub_line}"
        scrub_lower_bounds=$((scrub_lower_bounds + 1))
      fi
    done
  done <"${scrub_file}"
done
if ((scrub_lower_bounds)); then
  printf 'error: scrub_hook assertions must be exact (==), not lower bounds\n' >&2
  exit 1
fi

# 2. Enumerate wipe sites (file:line) from the current sources. Anchored to a
# statement start (optional indent, optional `(void)`, then the identifier) so
# a comment or string that merely mentions the call is not treated as a site;
# a wipe written mid-line would be missed, and the sweep's site count in the
# summary is the check against that.
mapfile -t sites < <(
  grep -nE '^[[:space:]]*(\(void\)[[:space:]]*)?(PCSC_FIDO_SCRUB_ON_EXIT|pcsc_fido_secure_clear)\(' \
    "${repo_root}"/src/*.c |
    grep -v '^.*/src/mem_util\.c:' |
    sed "s|^${repo_root}/||" |
    cut -d: -f1,2
)
if [[ ${#sites[@]} -eq 0 ]]; then
  printf 'error: no wipe sites found under src/\n' >&2
  exit 1
fi

backup="$(mktemp)"
mutated=""
mutant_sum=""
keep_backup=0
# The sweep edits src/ in place. A file saved over the mutant meanwhile (an
# editor, a formatter) must not be overwritten with the pre-sweep copy.
restore() {
  if [[ -z ${mutated} ]]; then
    return 0
  fi
  if [[ "$(sha256sum <"${repo_root}/${mutated}")" != "${mutant_sum}" ]]; then
    printf 'error: %s changed during the scrub sweep; left as is (pre-sweep copy: %s)\n' \
      "${mutated}" "${backup}" >&2
    keep_backup=1
    mutated=""
    return 1
  fi
  cp "${backup}" "${repo_root}/${mutated}"
  mutated=""
}
on_exit() {
  restore || true
  if ((keep_backup == 0)); then
    rm -f "${backup}"
  fi
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# A mutant test that deadlocks must fail the sweep. "killed" only counts a
# finite non-zero exit; a timeout is a hang, not a caught mutant.
scrub_run() {
  if command -v timeout >/dev/null 2>&1; then
    timeout --foreground "$1" "${@:2}"
  else
    "${@:2}"
  fi
}

killed=0
problems=0
site_n=0
for site in "${sites[@]}"; do
  site_n=$((site_n + 1))
  file="${site%%:*}"
  line="${site##*:}"
  target="${covering_test[${file}]:-}"
  if [[ -z ${target} ]]; then
    printf 'UNMAPPED %s (no covering test in verify-scrub-mutants.sh)\n' "${site}"
    problems=$((problems + 1))
    continue
  fi
  text="$(sed -n "${line}p" "${repo_root}/${file}")"
  if [[ ${text} != *';'* ]]; then
    printf 'MULTILINE %s (wipe call must sit on one line to be mutable): %s\n' "${site}" "${text}"
    problems=$((problems + 1))
    continue
  fi
  printf 'scrub %d/%d %s -> %s\n' "${site_n}" "${#sites[@]}" "${site}" "${target}"
  cp "${repo_root}/${file}" "${backup}"
  mutated="${file}"
  sed -i "${line}d" "${repo_root}/${file}"
  mutant_sum="$(sha256sum <"${repo_root}/${file}")"
  build_status=0
  scrub_run 180 cmake --build "${build_dir}" --target "${target}" >/dev/null 2>&1 ||
    build_status=$?
  if [[ ${build_status} -eq 124 ]]; then
    printf 'BUILD-HANG %s -> %s\n' "${site}" "${target}"
    problems=$((problems + 1))
  elif [[ ${build_status} -ne 0 ]]; then
    printf 'BUILD-FAIL %s -> %s (mutant did not compile)\n' "${site}" "${target}"
    problems=$((problems + 1))
  else
    run_status=0
    scrub_run 60 "${build_dir}/${target}" >/dev/null 2>&1 || run_status=$?
    if [[ ${run_status} -eq 0 ]]; then
      printf 'SURVIVED %s -> %s (test stayed green)\n' "${site}" "${target}"
      problems=$((problems + 1))
    elif [[ ${run_status} -eq 124 ]]; then
      printf 'HANG %s -> %s (test still running after 60s)\n' "${site}" "${target}"
      problems=$((problems + 1))
    else
      printf 'killed   %s -> %s\n' "${site}" "${target}"
      killed=$((killed + 1))
    fi
  fi
  restore || exit 1
done

# Leave the tree built from pristine sources. A failed rebuild used to be
# ignored, which left the last mutant linked while the script exited 0.
rebuild_failed=0
if ! cmake --build "${build_dir}" --target pcsc_fido_unit_tests >/dev/null; then
  printf 'error: rebuild of pristine unit tests failed after the scrub sweep\n' >&2
  rebuild_failed=1
fi

printf 'scrub mutants: %d killed, %d problems (%d sites)\n' \
  "${killed}" "${problems}" "${#sites[@]}"
if [[ ${problems} -ne 0 || ${rebuild_failed} -ne 0 ]]; then
  exit 1
fi
