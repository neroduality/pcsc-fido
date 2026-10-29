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

usage() {
  cat <<'EOF'
Usage: verify-release-elf-hardening.sh /path/to/pcsc-fido [--cmake-cache FILE]

Checks a stripped Release binary for PIE, GNU_RELRO, non-executable GNU_STACK,
BIND_NOW, DT_RELR, no DT_RPATH/DT_RUNPATH, only the expected DT_NEEDED libraries
and the dropped .comment section.

Point it at the install/CPack-staged copy, not the build-tree link output: CMake
gives the build-tree binary a build RUNPATH (on cross ports, into the sysroot)
and removes it at install, so only the staged copy is byte-for-byte what ships.

--cmake-cache FILE  CMakeCache.txt of the tree that linked the binary (default:
                    CMakeCache.txt next to the binary). Its kit probe results
                    (HAVE_LINK_Z_PACK_RELATIVE_RELOCS / HAVE_LIBC_DT_RELR) decide
                    whether DT_RELR is required: a target linker that ignores
                    -z pack-relative-relocs (no DT_RELR support for that arch)
                    cannot produce RELR. Without a cache DT_RELR is required.
EOF
}

binary=""
cmake_cache=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --cmake-cache)
      cmake_cache="${2:-}"
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      if [[ -n ${binary} ]]; then
        printf 'error: unexpected argument: %s\n' "$1" >&2
        usage >&2
        exit 2
      fi
      binary="$1"
      shift
      ;;
  esac
done

if [[ -z ${binary} || ! -x ${binary} ]]; then
  usage >&2
  exit 2
fi

if [[ -z ${cmake_cache} && -f "$(dirname "${binary}")/CMakeCache.txt" ]]; then
  cmake_cache="$(dirname "${binary}")/CMakeCache.txt"
fi
if [[ -n ${cmake_cache} && ! -f ${cmake_cache} ]]; then
  printf 'error: --cmake-cache not found: %s\n' "${cmake_cache}" >&2
  exit 2
fi

# CMake writes probe results as `NAME:INTERNAL=1` (true) or `NAME:INTERNAL=` (false).
cmake_cache_probe() {
  local name="$1" value
  value="$(grep -E "^${name}:[A-Z]+=" "${cmake_cache}" | head -n1 | cut -d= -f2- || true)"
  case "${value}" in
    1 | ON | TRUE | YES | on | true | yes) return 0 ;;
    *) return 1 ;;
  esac
}

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

# Packed relative relocations (DT_RELR, -z pack-relative-relocs). Every packaging
# floor (deb glibc 2.41 / rpm 2.37) and the trixie cross sysroots are >= 2.36, and
# the lint manifest opts the flag in for cross builds, so wherever the target
# linker implements DT_RELR the release binary must carry it. GNU ld only
# implements RELR for some targets (x86-64, aarch64 and ppc64 do; the trixie
# binutils 2.44 cross linkers for riscv64, s390x and 32-bit arm answer
# "-z pack-relative-relocs ignored"), so the requirement follows the kit's linker
# probe from the build that linked this binary rather than a hardcoded arch list:
# the probe asked the exact ld, and it flips to required the day ld gains support.
relr_required=1
relr_note=""
if [[ -n ${cmake_cache} ]]; then
  if ! grep -Eq '^HAVE_LINK_Z_PACK_RELATIVE_RELOCS:' "${cmake_cache}"; then
    printf 'error: %s has no HAVE_LINK_Z_PACK_RELATIVE_RELOCS probe (kit CompilerHardeningProbes.cmake not configured?)\n' \
      "${cmake_cache}" >&2
    exit 1
  fi
  if ! cmake_cache_probe HAVE_LIBC_DT_RELR; then
    # Release sysroots are all >= glibc 2.36; a false libc probe means the wrong
    # sysroot was linked, which the glibc ceiling check would also catch.
    printf 'error: HAVE_LIBC_DT_RELR is false in %s (release sysroot glibc must be >= 2.36)\n' \
      "${cmake_cache}" >&2
    exit 1
  fi
  if ! cmake_cache_probe HAVE_LINK_Z_PACK_RELATIVE_RELOCS; then
    relr_required=0
    relr_note=" (DT_RELR waived: target linker ignores -z pack-relative-relocs per ${cmake_cache})"
  fi
fi
if [[ ${relr_required} -eq 1 ]]; then
  if ! grep -Eq '\((RELR|RELRSZ)\)' <<<"${dynamic_tags}"; then
    printf 'error: Release binary is missing DT_RELR (expected -z pack-relative-relocs)\n' >&2
    exit 1
  fi
elif grep -Eq '\((RELR|RELRSZ)\)' <<<"${dynamic_tags}"; then
  # Cache says the probe failed but the ELF has RELR: the cache is not from this link.
  printf 'error: Release binary carries DT_RELR but %s reports HAVE_LINK_Z_PACK_RELATIVE_RELOCS false (stale or mismatched CMakeCache.txt)\n' \
    "${cmake_cache}" >&2
  exit 1
fi

# No DT_RPATH / DT_RUNPATH: the shipped binary must resolve libpcsclite from the
# system loader path only. CMake's build-tree link carries a build RUNPATH (on
# cross ports into /usr/lib/pcsc-fido/cross-sysroot/...) that install removes;
# a hit here means the build-tree copy was verified instead of the staged one, or
# an RPATH leaked into the install.
if grep -Eq '\((RPATH|RUNPATH)\)' <<<"${dynamic_tags}"; then
  printf 'error: Release binary carries a DT_RPATH/DT_RUNPATH (verify the CPack-staged copy, not the build tree):\n%s\n' \
    "$(grep -E '\((RPATH|RUNPATH)\)' <<<"${dynamic_tags}")" >&2
  exit 1
fi

# DT_NEEDED is limited to libraries the packages declare (libpcsclite) or that
# ship with glibc itself, so a new runtime dependency fails here instead of
# appearing silently. libgcc_s.so.1: native builds compile with -fexceptions,
# so the PCSC_FIDO_SCRUB_ON_EXIT cleanups get unwind landing pads that call
# _Unwind_Resume (glibc itself needs libgcc_s for pthread_cancel). The dynamic
# loader: targets whose stack-protector guard lives in ld.so (32-bit arm, riscv64).
allowed_needed=(libc.so.6 libpcsclite.so.1 libgcc_s.so.1)
if [[ ${program_headers} =~ Requesting\ program\ interpreter:\ ([^]]+)\] ]]; then
  allowed_needed+=("${BASH_REMATCH[1]##*/}")
fi
needed_libs=()
while IFS= read -r dynamic_line; do
  if [[ ${dynamic_line} =~ \(NEEDED\).*\[([^]]+)\] ]]; then
    needed_libs+=("${BASH_REMATCH[1]}")
  fi
done <<<"${dynamic_tags}"
for needed_lib in "${needed_libs[@]}"; do
  needed_ok=0
  for allowed_lib in "${allowed_needed[@]}"; do
    if [[ ${needed_lib} == "${allowed_lib}" ]]; then
      needed_ok=1
      break
    fi
  done
  if ((needed_ok == 0)); then
    printf 'error: Release binary needs %s, which is not an expected runtime dependency (allowed: %s)\n' \
      "${needed_lib}" "${allowed_needed[*]}" >&2
    exit 1
  fi
done

# Stripped Release builds drop the compiler-version `.comment` section
# (CMakeLists.txt post-build objcopy; /bin/ls parity).
section_headers="$(readelf -W -S "${binary}")"
if grep -Eq '[[:space:]]\.comment[[:space:]]' <<<"${section_headers}"; then
  printf 'error: Release binary still has a .comment section (expected objcopy -R .comment):\n%s\n' \
    "$(grep -E '[[:space:]]\.comment[[:space:]]' <<<"${section_headers}")" >&2
  exit 1
fi

# GNU ld records DF_1_NOOPEN only on shared objects. This daemon is a PIE
# executable: -z nodlopen is still passed (the link audit checks that) and ld
# accepts it, but FLAGS_1 stays "PIE" with no NOOPEN bit. Do not require the tag.

if grep -q '(TEXTREL)' <<<"${dynamic_tags}"; then
  printf 'error: Release binary has text relocations (expected -z text)\n' >&2
  exit 1
fi

if grep -Eq 'LOAD[[:space:]].*RWE' <<<"${program_headers}"; then
  printf 'error: Release binary has a writable executable LOAD segment\n' >&2
  exit 1
fi

dynsyms="$(readelf -W --dyn-syms "${binary}")"
if ! grep -q '__stack_chk_fail' <<<"${dynsyms}"; then
  printf 'error: Release binary does not call __stack_chk_fail (stack protector not linked)\n' >&2
  exit 1
fi

notes="$(readelf -n "${binary}")"
machine="$(grep -E 'Machine:' <<<"${elf_header}" || true)"
cross_compile=0
if [[ -n ${cmake_cache} ]] && grep -Eq '^CMAKE_CROSSCOMPILING:[A-Z]+=((1|ON|TRUE|YES|on|true|yes))' "${cmake_cache}"; then
  cross_compile=1
fi
# -fcf-protection is native x86_64 only. Branch protection is probed on AArch64,
# including cross compilers, so an AArch64 binary must carry BTI.
if [[ ${cross_compile} -eq 0 && ${machine} == *X86-64* ]]; then
  if ! grep -q 'IBT' <<<"${notes}" || ! grep -q 'SHSTK' <<<"${notes}"; then
    printf 'error: Release x86-64 binary is missing IBT and SHSTK notes (expected -fcf-protection=full)\n' >&2
    exit 1
  fi
fi
if [[ ${machine} == *AArch64* ]] && ! grep -q 'BTI' <<<"${notes}"; then
  printf 'error: Release AArch64 binary is missing a BTI note (expected -mbranch-protection=standard)\n' >&2
  exit 1
fi

printf 'release ELF hardening verify: OK (%s; needs %s)%s\n' "${binary}" "${needed_libs[*]}" "${relr_note}"
