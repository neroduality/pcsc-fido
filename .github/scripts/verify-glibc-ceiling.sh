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

# Fail if ELF needs GLIBC_* newer than the packaging floor (deb 2.41 / rpm 2.37).
# Usage: bash verify-glibc-ceiling.sh BINARY --format deb|rpm
set -euo pipefail

binary=""
format=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --format)
      format="${2:-}"
      shift 2
      ;;
    -h | --help)
      printf 'Usage: %s BINARY --format deb|rpm\n' "$(basename "$0")"
      exit 0
      ;;
    *)
      if [[ -z ${binary} ]]; then
        binary="$1"
      else
        printf 'error: unexpected argument: %s\n' "$1" >&2
        exit 2
      fi
      shift
      ;;
  esac
done

if [[ -z ${binary} || ! -e ${binary} ]]; then
  printf 'error: binary not found: %s\n' "${binary:-}" >&2
  exit 2
fi

case "${format}" in
  deb) ceiling="2.41" ;;
  rpm) ceiling="2.37" ;;
  *)
    printf 'error: usage: %s BINARY --format deb|rpm\n' "$(basename "$0")" >&2
    exit 2
    ;;
esac

if ! command -v readelf >/dev/null 2>&1; then
  printf 'error: readelf not found (install binutils)\n' >&2
  exit 1
fi

if ! verneed="$(readelf -V "${binary}" 2>/dev/null)" ||
  ! dynsyms="$(readelf -W --dyn-syms "${binary}" 2>/dev/null)"; then
  printf 'error: readelf cannot read %s (not an ELF file?)\n' "${binary}" >&2
  exit 1
fi
version_refs="${verneed}"$'\n'"${dynsyms}"

# GLIBC_ABI_DT_RELR is a verneed entry with a non-numeric version name that
# DT_RELR (-z pack-relative-relocs) binaries carry. Map it to 2.36 so a future lower ceiling would reject those
# binaries. Today's floors (deb 2.41 / rpm 2.37) are already above 2.36; the
# loader floor is enforced by HAVE_LIBC_DT_RELR + verify-release-elf-hardening.sh.
mapfile -t versions < <(
  {
    grep -oE 'GLIBC_[0-9]+(\.[0-9]+)+' <<<"${version_refs}" | sed 's/^GLIBC_//'
    if grep -q 'GLIBC_ABI_DT_RELR' <<<"${version_refs}"; then
      printf '2.36\n'
    fi
  } | sort -Vu
)

# The daemon is always dynamically linked against glibc, so no references
# means the wrong file (or a truncated one), not a binary that passes.
if [[ ${#versions[@]} -eq 0 ]]; then
  printf 'error: %s has no GLIBC_* version references\n' "${binary}" >&2
  exit 1
fi

max_needed="${versions[-1]}"
highest="$(printf '%s\n%s\n' "${ceiling}" "${max_needed}" | sort -V | tail -n1)"
if [[ ${highest} != "${ceiling}" ]]; then
  printf 'error: %s requires GLIBC_%s but %s floor ceiling is %s\n' \
    "${binary}" "${max_needed}" "${format}" "${ceiling}" >&2
  printf '  GLIBC_%s\n' "${versions[@]}" >&2
  exit 1
fi

printf 'glibc ceiling verify: OK (%s; max GLIBC_%s <= %s)\n' \
  "${binary}" "${max_needed}" "${ceiling}"
