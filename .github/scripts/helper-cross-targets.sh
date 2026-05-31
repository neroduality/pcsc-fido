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

# Cross-build metadata for Debian-based release packages.
# Source this file; do not execute directly.

if [[ ${BASH_SOURCE[0]} == "${0}" ]]; then
  printf '%s\n' "error: source helper-cross-targets.sh instead of executing it" >&2
  exit 1
fi

# shellcheck disable=SC2034
PCSC_FIDO_CROSS_ARCHES=(armhf ppc64el riscv64 s390x)
PCSC_FIDO_CROSS_SYSROOT_BASE="${PCSC_FIDO_CROSS_SYSROOT_BASE:-/usr/lib/pcsc-fido/cross-sysroot}"

pcsc_fido_cross_triplet() {
  case "$1" in
    armhf) printf '%s\n' arm-linux-gnueabihf ;;
    ppc64el) printf '%s\n' powerpc64le-linux-gnu ;;
    riscv64) printf '%s\n' riscv64-linux-gnu ;;
    s390x) printf '%s\n' s390x-linux-gnu ;;
    *) return 1 ;;
  esac
}

pcsc_fido_cross_dpkg_arch() {
  case "$1" in
    armhf | ppc64el | riscv64 | s390x) printf '%s\n' "$1" ;;
    *) return 1 ;;
  esac
}

pcsc_fido_cross_cmake_processor() {
  case "$1" in
    armhf) printf '%s\n' arm ;;
    ppc64el) printf '%s\n' ppc64le ;;
    riscv64) printf '%s\n' riscv64 ;;
    s390x) printf '%s\n' s390x ;;
    *) return 1 ;;
  esac
}

pcsc_fido_cross_gcc_packages() {
  case "$1" in
    armhf) printf '%s\n' gcc-arm-linux-gnueabihf ;;
    ppc64el) printf '%s\n' gcc-powerpc64le-linux-gnu ;;
    riscv64) printf '%s\n' gcc-riscv64-linux-gnu ;;
    s390x) printf '%s\n' gcc-s390x-linux-gnu ;;
    *) return 1 ;;
  esac
}

pcsc_fido_cross_libc_packages() {
  local dpkg_arch
  dpkg_arch="$(pcsc_fido_cross_dpkg_arch "$1")" || return 1
  printf '%s\n' "libc6-dev-${dpkg_arch}-cross" "linux-libc-dev-${dpkg_arch}-cross"
}

pcsc_fido_cross_lib_dir() {
  local triplet
  triplet="$(pcsc_fido_cross_triplet "$1")" || return 1
  printf '/usr/lib/%s\n' "$triplet"
}

pcsc_fido_cross_sysroot_extract() {
  printf '%s/%s\n' "$PCSC_FIDO_CROSS_SYSROOT_BASE" "$1"
}

pcsc_fido_cross_pkgconfig_libdir() {
  local extract_root lib_dir
  extract_root="$(pcsc_fido_cross_sysroot_extract "$1")" || return 1
  lib_dir="$(pcsc_fido_cross_lib_dir "$1")" || return 1
  printf '%s/usr/lib/%s/pkgconfig\n' "$extract_root" "$(basename "$lib_dir")"
}

pcsc_fido_cross_debian_arch() {
  pcsc_fido_cross_dpkg_arch "$1"
}

pcsc_fido_cross_rpm_arch() {
  case "$1" in
    armhf) printf '%s\n' armv7hl ;;
    ppc64el) printf '%s\n' ppc64le ;;
    riscv64) printf '%s\n' riscv64 ;;
    s390x) printf '%s\n' s390x ;;
    *) return 1 ;;
  esac
}

# Debian suite providing target libpcsclite .debs (trixie has all cross ports).
pcsc_fido_cross_pcsc_apt_suite() {
  printf '%s\n' trixie
}

pcsc_fido_debian_host_suite() {
  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    if [[ -n ${VERSION_CODENAME:-} ]]; then
      printf '%s\n' "${VERSION_CODENAME}"
      return 0
    fi
  fi
  printf '%s\n' trixie
}

pcsc_fido_cross_file_glob() {
  case "$1" in
    armhf) printf '%s\n' 'ARM.*EABI.*HF' ;;
    ppc64el) printf '%s\n' 'PowerPC|OpenPOWER' ;;
    riscv64) printf '%s\n' 'RISC-V' ;;
    s390x) printf '%s\n' 'IBM S/390' ;;
    *) return 1 ;;
  esac
}

pcsc_fido_is_cross_arch() {
  case "$1" in
    armhf | ppc64el | riscv64 | s390x) return 0 ;;
    *) return 1 ;;
  esac
}

pcsc_fido_is_native_release_arch() {
  case "$1" in
    amd64 | arm64) return 0 ;;
    *) return 1 ;;
  esac
}

pcsc_fido_is_release_arch() {
  pcsc_fido_is_native_release_arch "$1" || pcsc_fido_is_cross_arch "$1"
}
