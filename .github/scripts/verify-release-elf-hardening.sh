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

set -euo pipefail

binary="${1:-}"

if [[ -z ${binary} || ! -x ${binary} ]]; then
  printf 'error: usage: %s /path/to/pcsc-fido\n' "$0" >&2
  exit 2
fi

for tool in file readelf grep; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    printf 'error: required tool missing: %s\n' "${tool}" >&2
    exit 1
  fi
done

file_output="$(file -b "${binary}")"
elf_header="$(readelf -h "${binary}")"
program_headers="$(readelf -W -l "${binary}")"
dynamic_tags="$(readelf -d "${binary}")"

if ! grep -q 'ELF' <<<"${file_output}"; then
  printf 'error: not an ELF binary: %s\n  %s\n' "${binary}" "${file_output}" >&2
  exit 1
fi

if grep -qi 'not stripped' <<<"${file_output}"; then
  printf 'error: Release binary is not stripped:\n  %s: %s\n' "${binary}" "${file_output}" >&2
  exit 1
fi

if ! grep -Eq 'Type:[[:space:]]+DYN[[:space:]]' <<<"${elf_header}"; then
  printf 'error: Release binary is not PIE (expected ELF Type DYN):\n%s\n' \
    "$(grep 'Type:' <<<"${elf_header}")" >&2
  exit 1
fi

if ! grep -q 'GNU_RELRO' <<<"${program_headers}"; then
  printf 'error: Release binary is missing GNU_RELRO\n' >&2
  exit 1
fi

if grep -Eq 'GNU_STACK.*RWE' <<<"${program_headers}"; then
  printf 'error: Release binary has an executable GNU_STACK\n' >&2
  exit 1
fi

if ! grep -q 'GNU_STACK' <<<"${program_headers}"; then
  printf 'error: Release binary is missing GNU_STACK header\n' >&2
  exit 1
fi

if ! grep -Eq 'BIND_NOW|FLAGS.*NOW' <<<"${dynamic_tags}"; then
  printf 'error: Release binary is missing BIND_NOW/NOW dynamic flag\n' >&2
  exit 1
fi

printf 'release ELF hardening verify: OK (%s)\n' "${binary}"
