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

# Remove a source ``sudo make uninstall`` tree from the system prefix.
#
# Flow:
#   1. Stop and disable pcsc-fido.service
#   2. Remove files recorded in build/install_manifest.txt when present, else known paths
#   3. Reload systemd and udev
#
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
build_dir="${BUILD_DIR:-build}"
build_dir="${build_dir#/}"
if [[ ${build_dir} != /* ]]; then
  build_dir="${repo_root}/${build_dir}"
fi

install_prefix="${INSTALL_PREFIX:-/usr}"
cache="${build_dir}/CMakeCache.txt"
manifest="${build_dir}/install_manifest.txt"

read_cache_value() {
  local key="$1"
  if [[ ! -f ${cache} ]]; then
    printf ''
    return 0
  fi
  local line=""
  line="$(grep -E "^${key}:(PATH|STRING|INTERNAL)=" "${cache}" 2>/dev/null | head -n1 || true)"
  if [[ -z ${line} ]]; then
    printf ''
    return 0
  fi
  printf '%s' "${line#*=}"
}

prefix_path() {
  local rel="$1"
  if [[ ${rel} == /* ]]; then
    printf '%s\n' "${rel}"
  else
    printf '%s/%s\n' "${install_prefix%/}" "${rel#./}"
  fi
}

is_system_prefix() {
  case "${install_prefix}" in
    /usr | /usr/local) return 0 ;;
    *) return 1 ;;
  esac
}

if [[ -f ${cache} ]]; then
  cached_prefix="$(read_cache_value CMAKE_INSTALL_PREFIX)"
  if [[ -n ${cached_prefix} ]]; then
    install_prefix="${cached_prefix}"
  fi
fi

case "${install_prefix}" in
  /usr | /usr/local)
    if [[ ${EUID} -ne 0 ]]; then
      printf '%s\n' \
        "error: uninstall from ${install_prefix} requires \`sudo make uninstall\`" >&2
      exit 1
    fi
    ;;
esac

stop_bridge_service() {
  is_system_prefix || return 0
  if ! command -v systemctl >/dev/null 2>&1; then
    return 0
  fi
  if command -v timeout >/dev/null 2>&1; then
    timeout 10s systemctl stop pcsc-fido.service >/dev/null 2>&1 ||
      systemctl stop --no-block pcsc-fido.service >/dev/null 2>&1 || true
  else
    systemctl stop --no-block pcsc-fido.service >/dev/null 2>&1 || true
  fi
  systemctl disable pcsc-fido.service >/dev/null 2>&1 || true
}

remove_installed_path() {
  local path="$1"
  [[ -z ${path} ]] && return 0
  case "${path}" in
    "${install_prefix}"/*)
      rm -f -- "${path}"
      ;;
    *)
      printf 'skip: %s (outside install prefix %s)\n' "${path}" "${install_prefix}"
      ;;
  esac
}

remove_installed_tree() {
  local path="$1"
  [[ -z ${path} ]] && return 0
  case "${path}" in
    "${install_prefix}"/*)
      rm -rf -- "${path}"
      ;;
    *)
      printf 'skip: %s (outside install prefix %s)\n' "${path}" "${install_prefix}"
      ;;
  esac
}

remove_from_manifest() {
  local path removed=0
  while IFS= read -r path || [[ -n ${path} ]]; do
    [[ -z ${path} ]] && continue
    if [[ -e ${path} || -L ${path} ]]; then
      remove_installed_path "${path}"
      removed=1
    fi
  done <"${manifest}"
  [[ ${removed} -eq 1 ]]
}

remove_fallback_paths() {
  local bindir udevdir unitdir docdir sysusersdir
  bindir="$(read_cache_value CMAKE_INSTALL_BINDIR)"
  udevdir="$(read_cache_value CMAKE_INSTALL_UDEVRULESDIR)"
  unitdir="$(read_cache_value CMAKE_INSTALL_SYSTEMDUNITDIR)"
  docdir="$(read_cache_value CMAKE_INSTALL_DOCDIR)"
  sysusersdir="$(read_cache_value CMAKE_INSTALL_SYSUSERSDIR)"

  [[ -z ${bindir} ]] && bindir=bin
  [[ -z ${udevdir} ]] && udevdir=lib/udev/rules.d
  [[ -z ${unitdir} ]] && unitdir=lib/systemd/system
  [[ -z ${docdir} ]] && docdir=share/doc/pcsc-fido
  [[ -z ${sysusersdir} ]] && sysusersdir=lib/sysusers.d

  remove_installed_path "$(prefix_path "${bindir}/pcsc-fido")"
  remove_installed_path "$(prefix_path "${udevdir}/70-pcsc-fido.rules")"
  remove_installed_path "$(prefix_path "lib/modules-load.d/pcsc-fido-uhid.conf")"
  remove_installed_path "$(prefix_path "${unitdir}/pcsc-fido.service")"
  remove_installed_path "$(prefix_path "lib/systemd/system-preset/60-pcsc-fido.preset")"
  remove_installed_path "$(prefix_path "lib/systemd/system-preset/90-pcsc-fido.preset")"
  remove_installed_path "$(prefix_path "${sysusersdir}/pcsc-fido.conf")"
  remove_installed_path "$(prefix_path "lib/pcsc-fido/ensure-pcsc-fido-user.sh")"
  remove_installed_path "$(prefix_path "share/polkit-1/rules.d/50-pcsc-fido.rules")"
  remove_installed_path "$(prefix_path "${docdir}/README.md")"
  remove_installed_path "$(prefix_path "${docdir}/INSTALLATION.md")"
  remove_installed_path "$(prefix_path "${docdir}/NOTICE")"
  remove_installed_path "$(prefix_path "${docdir}/CHECKLIST.md")"
  remove_installed_path "$(prefix_path "${docdir}/ARCHITECTURE_ECOSYSTEM.md")"
  remove_installed_path "$(prefix_path "${docdir}/ECOSYSTEM.md")"
  remove_installed_path "$(prefix_path "${docdir}/DEBUGGING.md")"
  remove_installed_path "$(prefix_path "${docdir}/REMEDIATIONS.md")"

  rmdir "$(prefix_path "${docdir}")" 2>/dev/null || true
  remove_installed_tree "$(prefix_path "share/doc/pcsc-fido")"
  rmdir "$(prefix_path "lib/pcsc-fido")" 2>/dev/null || true
}

remove_stale_paths() {
  remove_installed_path "$(prefix_path "lib/systemd/system-preset/60-pcsc-fido.preset")"
  remove_installed_path "$(prefix_path "lib/systemd/system-preset/90-pcsc-fido.preset")"
  remove_installed_path "$(prefix_path "lib/sysusers.d/pcsc-fido.conf")"
  remove_installed_path "$(prefix_path "lib/pcsc-fido/ensure-pcsc-fido-user.sh")"
  remove_installed_path "$(prefix_path "share/polkit-1/rules.d/50-pcsc-fido.rules")"
  remove_installed_tree "$(prefix_path "share/doc/pcsc-fido")"
  rmdir "$(prefix_path "lib/pcsc-fido")" 2>/dev/null || true
}

purge_system_overrides() {
  is_system_prefix || return 0
  rm -rf -- /etc/systemd/system/pcsc-fido.service /etc/systemd/system/pcsc-fido.service.d
  rm -f -- /etc/systemd/system/multi-user.target.wants/pcsc-fido.service
  rm -f -- /etc/udev/rules.d/70-pcsc-fido.rules
  rm -f -- /etc/polkit-1/rules.d/50-pcsc-fido.rules
}

remove_system_identity() {
  is_system_prefix || return 0
  if getent passwd pcsc-fido >/dev/null 2>&1 && command -v userdel >/dev/null 2>&1; then
    userdel pcsc-fido >/dev/null 2>&1 || true
  fi
  if getent group pcsc-fido >/dev/null 2>&1 && command -v groupdel >/dev/null 2>&1; then
    groupdel pcsc-fido >/dev/null 2>&1 || true
  fi
}

reload_system_state() {
  is_system_prefix || return 0
  if command -v systemctl >/dev/null 2>&1; then
    systemctl unset-environment PCSC_FIDO_DEBUG >/dev/null 2>&1 || true
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl reset-failed pcsc-fido.service >/dev/null 2>&1 || true
  fi
  if command -v udevadm >/dev/null 2>&1; then
    udevadm control --reload-rules >/dev/null 2>&1 || true
  fi
}

audit_leftovers() {
  is_system_prefix || return 0
  local path leftovers=0
  local paths=(
    "$(prefix_path "bin/pcsc-fido")"
    "$(prefix_path "lib/udev/rules.d/70-pcsc-fido.rules")"
    "$(prefix_path "lib/modules-load.d/pcsc-fido-uhid.conf")"
    "$(prefix_path "lib/systemd/system/pcsc-fido.service")"
    "$(prefix_path "lib/systemd/system-preset/60-pcsc-fido.preset")"
    "$(prefix_path "lib/systemd/system-preset/90-pcsc-fido.preset")"
    "$(prefix_path "lib/sysusers.d/pcsc-fido.conf")"
    "$(prefix_path "lib/pcsc-fido/ensure-pcsc-fido-user.sh")"
    "$(prefix_path "share/polkit-1/rules.d/50-pcsc-fido.rules")"
    "$(prefix_path "share/doc/pcsc-fido")"
    "$(prefix_path "share/doc/pcsc-fido")"
    "/etc/systemd/system/pcsc-fido.service"
    "/etc/systemd/system/pcsc-fido.service.d"
    "/etc/systemd/system/multi-user.target.wants/pcsc-fido.service"
    "/etc/udev/rules.d/70-pcsc-fido.rules"
    "/etc/polkit-1/rules.d/50-pcsc-fido.rules"
  )
  for path in "${paths[@]}"; do
    if [[ -e ${path} || -L ${path} ]]; then
      printf 'warning: pcsc-fido artifact still present: %s\n' "${path}" >&2
      leftovers=1
    fi
  done
  if getent passwd pcsc-fido >/dev/null 2>&1; then
    printf 'warning: pcsc-fido system user still present\n' >&2
    leftovers=1
  fi
  if getent group pcsc-fido >/dev/null 2>&1; then
    printf 'warning: pcsc-fido system group still present\n' >&2
    leftovers=1
  fi
  if [[ ${leftovers} -ne 0 ]]; then
    printf 'error: pcsc-fido uninstall leftovers found\n' >&2
    exit 1
  fi
}

stop_bridge_service

if [[ -f ${manifest} ]]; then
  remove_from_manifest || true
else
  printf 'note: %s missing; removing known pcsc-fido install paths under %s\n' \
    "${manifest}" "${install_prefix}"
fi

remove_fallback_paths
remove_stale_paths
purge_system_overrides
remove_system_identity
reload_system_state
audit_leftovers

printf 'uninstalled pcsc-fido source install from %s\n' "${install_prefix}"
