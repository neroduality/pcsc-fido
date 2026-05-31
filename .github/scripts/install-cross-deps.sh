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

# Install Debian cross toolchains and target libpcsclite for pcsc-fido.
#
# Debian trixie hosts GCC 14+ cross toolchains for ISO C23 builds. Target libpcsclite
# sysroots are extracted from trixie (matches Release / ci-suite cross containers).
#
# Usage:
#   bash .github/scripts/install-cross-deps.sh [armhf|ppc64el|riscv64|s390x ...]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=helper-cross-targets.sh
source "${SCRIPT_DIR}/helper-cross-targets.sh"

if [[ "$(uname -s)" != "Linux" ]]; then
  printf '%s\n' "install-cross-deps: not Linux; skipping" >&2
  exit 0
fi

if ! command -v apt-get >/dev/null 2>&1; then
  printf '%s\n' "error: install-cross-deps requires apt-get (Debian trixie recommended)" >&2
  exit 1
fi

as_root() {
  if [[ ${EUID} -eq 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

ARCHES=("$@")
if [[ ${#ARCHES[@]} -eq 0 ]]; then
  ARCHES=("${PCSC_FIDO_CROSS_ARCHES[@]}")
fi

for arch in "${ARCHES[@]}"; do
  if ! pcsc_fido_is_cross_arch "$arch"; then
    printf '%s\n' "error: unsupported cross architecture: ${arch}" >&2
    exit 1
  fi
done

export DEBIAN_FRONTEND=noninteractive
as_root apt-get update
as_root apt-get install -y dpkg-dev debhelper pkg-config cmake gcc make ca-certificates

for arch in "${ARCHES[@]}"; do
  dpkg_arch="$(pcsc_fido_cross_dpkg_arch "$arch")"
  as_root dpkg --add-architecture "$dpkg_arch"
done

as_root apt-get update

for arch in "${ARCHES[@]}"; do
  mapfile -t host_packages < <(pcsc_fido_cross_gcc_packages "$arch")
  mapfile -t libc_packages < <(pcsc_fido_cross_libc_packages "$arch")
  as_root apt-get install -y "${host_packages[@]}" "${libc_packages[@]}"
done

pcsc_fido_ensure_apt_suite() {
  local suite="$1"
  local list="/etc/apt/sources.list.d/pcsc-fido-cross-${suite}.list"
  if [[ ! -f $list ]]; then
    as_root sh -c "printf '%s\n' 'deb http://deb.debian.org/debian ${suite} main' > '${list}'"
    as_root apt-get update
  fi
}

pcsc_fido_extract_pcsc_sysroot() {
  local arch="$1"
  local dpkg_arch extract_root download_dir deb host_suite pcsc_suite
  dpkg_arch="$(pcsc_fido_cross_dpkg_arch "$arch")"
  extract_root="$(pcsc_fido_cross_sysroot_extract "$arch")"
  download_dir="$(mktemp -d "/tmp/pcsc-fido-${arch}-debs.XXXXXX")"
  if [[ ${EUID} -eq 0 ]] && getent passwd _apt >/dev/null 2>&1; then
    chown _apt "$download_dir"
  fi
  host_suite="$(pcsc_fido_debian_host_suite)"
  pcsc_suite="$(pcsc_fido_cross_pcsc_apt_suite "$arch")"

  if [[ $pcsc_suite != "$host_suite" ]]; then
    pcsc_fido_ensure_apt_suite "$pcsc_suite"
  fi

  as_root mkdir -p "$extract_root"
  as_root rm -rf "${extract_root:?}/"*

  cd "$download_dir"
  if [[ $pcsc_suite == "$host_suite" ]]; then
    apt-get download "libpcsclite1:${dpkg_arch}" "libpcsclite-dev:${dpkg_arch}"
  else
    apt-get download -t "$pcsc_suite" "libpcsclite1:${dpkg_arch}" "libpcsclite-dev:${dpkg_arch}"
  fi

  for deb in ./*.deb; do
    dpkg-deb -x "$deb" "$extract_root"
  done

  rm -rf "$download_dir"

  if [[ ! -f "${extract_root}/usr/include/PCSC/winscard.h" ]]; then
    printf '%s\n' "error: libpcsclite headers missing in ${extract_root}" >&2
    return 1
  fi
}

for arch in "${ARCHES[@]}"; do
  pcsc_fido_extract_pcsc_sysroot "$arch"
done

printf '── install-cross-deps: complete (%s) ──\n' "${ARCHES[*]}"
