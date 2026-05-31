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

# Probe ThreadSanitizer compile + runtime (PIE, like unit-test binaries).
#
# Prints one line to stdout:
#   ok       TSan runs normally
#   setarch  TSan runs only with setarch(1) -R (ASLR disabled for the process)
#   skip     TSan unavailable (compile or runtime failure)
#
# Usage:
#   bash .github/scripts/helper-tsan-probe.sh

set -euo pipefail

tsan_runtime_failed() {
  local output="$1"
  if [[ -z $output ]]; then
    return 1
  fi
  grep -Eiq \
    'FATAL: ThreadSanitizer|ThreadSanitizer.*unsupported|unexpected memory mapping|unsupported VMA range' \
    <<<"$output"
}

run_tsan_probe() {
  local -a runner=("$@")
  local output
  local status=0

  set +e
  output="$("${runner[@]}" 2>&1)"
  status=$?
  set -e

  if [[ $status -eq 0 ]] && ! tsan_runtime_failed "$output"; then
    return 0
  fi
  if tsan_runtime_failed "$output"; then
    return 1
  fi
  return 1
}

tmp=""
cleanup() {
  if [[ -n $tmp ]]; then
    rm -rf "$tmp"
  fi
}
trap cleanup EXIT

tmp="$(mktemp -d)"
printf '%s\n' 'int main(void) { return 0; }' >"$tmp/tsan-probe.c"

cc="${CC:-cc}"
if ! "$cc" -fsanitize=thread -pie -fPIE "$tmp/tsan-probe.c" -o "$tmp/tsan-probe" >/dev/null 2>&1; then
  printf 'skip\n'
  exit 0
fi

if run_tsan_probe "$tmp/tsan-probe"; then
  printf 'ok\n'
  exit 0
fi

if command -v setarch >/dev/null 2>&1; then
  if run_tsan_probe setarch "$(uname -m)" -R "$tmp/tsan-probe"; then
    printf 'setarch\n'
    exit 0
  fi
fi

printf 'skip\n'
exit 0
