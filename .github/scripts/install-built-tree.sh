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

# Install a production build into the system prefix.
#
# Flow:
#   1. ``make`` / ``make test`` (normal user) — optional dev build in build/
#   2. ``sudo make install`` — ensures INSTALL_BUILD_TYPE (default Release) with
#      BUILD_TESTING=OFF, builds only ``pcsc-fido``, stages with DESTDIR, rsyncs into
#      /usr, reloads udev/systemd metadata only (stops running bridge first; does not enable/start any unit)
#
# Configure/rebuild always runs as the build-directory owner so root never owns build/.
#
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
# shellcheck source=helper-build-tree-ownership.sh
source "${script_dir}/helper-build-tree-ownership.sh"
build_dir="${BUILD_DIR:-build}"
build_dir="${build_dir#/}"
if [[ ${build_dir} != /* ]]; then
  build_dir="${repo_root}/${build_dir}"
fi

install_build_type="${INSTALL_BUILD_TYPE:-Release}"
install_prefix="${INSTALL_PREFIX:-/usr}"
cache="${build_dir}/CMakeCache.txt"
binary="${build_dir}/pcsc-fido"
staging="${build_dir}/.install-staging"

build_uid=""
build_gid=""
build_owner=""

invoking_build_identity() {
  local uid gid user
  uid="$(id -u)"
  gid="$(id -g)"
  user="$(id -un)"
  if [[ ${uid} -eq 0 && -n ${SUDO_UID:-} && ${SUDO_UID} -ne 0 ]]; then
    uid="${SUDO_UID}"
    gid="${SUDO_GID:-$(id -g "${SUDO_UID}" 2>/dev/null || echo 0)}"
    user="${SUDO_USER:-#${SUDO_UID}}"
  fi
  printf '%s\n' "${uid}" "${gid}" "${user}"
}

resolve_build_owner() {
  local invoking_uid invoking_gid invoking_user
  mapfile -t _pcsc_fido_identity < <(invoking_build_identity)
  invoking_uid="${_pcsc_fido_identity[0]}"
  invoking_gid="${_pcsc_fido_identity[1]}"
  invoking_user="${_pcsc_fido_identity[2]}"

  if [[ -d ${build_dir} ]]; then
    build_uid="$(stat -c '%u' "${build_dir}")"
    build_gid="$(stat -c '%g' "${build_dir}")"
    build_owner="$(stat -c '%U' "${build_dir}")"
    if [[ ${build_uid} -eq 0 ]]; then
      if [[ ${invoking_uid} -ne 0 ]]; then
        pcsc_fido_repair_tree_ownership "${build_dir}"
        build_uid="${invoking_uid}"
        build_gid="${invoking_gid}"
        build_owner="${invoking_user}"
      else
        printf '%s\n' \
          'error: build/ is owned by root; run `make clean && make` as your normal user first.' >&2
        exit 1
      fi
    fi
    return
  fi

  build_uid="${invoking_uid}"
  build_gid="${invoking_gid}"
  build_owner="${invoking_user}"
  if [[ ${build_uid} -eq 0 ]]; then
    printf '%s\n' \
      'error: cannot create build/ as root; run `make` as your normal user first, then `sudo make install`.' >&2
    exit 1
  fi
}

as_build_owner() {
  if [[ ${EUID} -eq ${build_uid} ]]; then
    "$@"
  else
    sudo -u "#${build_uid}" -g "#${build_gid}" "$@"
  fi
}

read_cache_build_type() {
  if [[ ! -f ${cache} ]]; then
    printf ''
    return
  fi
  grep '^CMAKE_BUILD_TYPE:STRING=' "${cache}" | sed 's/^CMAKE_BUILD_TYPE:STRING=//'
}

read_cache_build_testing() {
  if [[ ! -f ${cache} ]]; then
    printf 'ON'
    return
  fi
  local value
  value="$(grep '^BUILD_TESTING:BOOL=' "${cache}" | sed 's/^BUILD_TESTING:BOOL=//')"
  if [[ -z ${value} ]]; then
    printf 'ON'
  else
    printf '%s' "${value}"
  fi
}

read_cache_prefix() {
  if [[ ! -f ${cache} ]]; then
    printf ''
    return
  fi
  grep '^CMAKE_INSTALL_PREFIX:PATH=' "${cache}" | sed 's/^CMAKE_INSTALL_PREFIX:PATH=//'
}

should_strip_install() {
  case "${install_build_type}" in
    Release | MinSizeRel)
      [[ ${PCSC_FIDO_STRIP_RELEASE:-1} != "0" ]]
      ;;
    *)
      return 1
      ;;
  esac
}

verify_staged_binary_stripped() {
  local staged_prefix
  local staged_binary
  local file_output
  staged_prefix="${prefix%/}"
  staged_binary="${staging}${staged_prefix}/bin/pcsc-fido"
  if [[ ! -x ${staged_binary} ]]; then
    printf 'error: staged pcsc-fido binary missing at %s\n' "${staged_binary}" >&2
    exit 1
  fi
  file_output="$(file -b "${staged_binary}")"
  if grep -qi 'not stripped' <<<"${file_output}"; then
    printf 'error: production install binary is not stripped:\n  %s: %s\n' \
      "${staged_binary}" "${file_output}" >&2
    exit 1
  fi
}

ensure_install_build() {
  local current_type
  local current_testing
  current_type="$(read_cache_build_type)"
  current_testing="$(read_cache_build_testing)"
  if [[ -f ${cache} ]]; then
    local cached_prefix
    cached_prefix="$(read_cache_prefix)"
    if [[ -n ${cached_prefix} ]]; then
      install_prefix="${cached_prefix}"
    fi
  fi

  if [[ -f ${cache} && -x ${binary} && ${current_type} == "${install_build_type}" &&
    ${current_testing} == "OFF" ]]; then
    return
  fi

  if [[ -n ${current_type} && ${current_type} != "${install_build_type}" ]]; then
    printf 'install: rebuilding %s as %s for system install (pcsc-fido only, no tests)\n' \
      "${build_dir}" "${install_build_type}"
  elif [[ ${current_testing} != "OFF" ]]; then
    printf 'install: reconfiguring %s for system install (BUILD_TESTING=OFF)\n' "${build_dir}"
  elif [[ ! -f ${cache} || ! -x ${binary} ]]; then
    printf 'install: configuring %s as %s for system install (pcsc-fido only, no tests)\n' \
      "${build_dir}" "${install_build_type}"
  fi

  as_build_owner cmake -S "${repo_root}" -B "${build_dir}" \
    -DCMAKE_BUILD_TYPE="${install_build_type}" \
    -DCMAKE_INSTALL_PREFIX="${install_prefix}" \
    -DBUILD_TESTING=OFF
  as_build_owner cmake --build "${build_dir}" --target pcsc-fido \
    -j"$(nproc 2>/dev/null || echo 2)"
}

resolve_build_owner

case "${install_prefix}" in
  /usr | /usr/local)
    if [[ ${EUID} -ne 0 ]]; then
      printf 'error: install to %s requires `sudo make install`\n' "${install_prefix}" >&2
      exit 1
    fi
    ;;
esac

ensure_install_build

if [[ ! -f ${cache} ]] || [[ ! -x ${binary} ]]; then
  printf '%s\n' 'error: install build failed; pcsc-fido binary missing' >&2
  exit 1
fi

prefix="$(read_cache_prefix)"
if [[ -z ${prefix} ]]; then
  printf 'error: CMAKE_INSTALL_PREFIX missing from %s\n' "${cache}" >&2
  exit 1
fi

# shellcheck source=helper-bridge-service-install.sh
source "${script_dir}/helper-bridge-service-install.sh"
if pcsc_fido_install_prefix_is_system "${prefix}"; then
  pcsc_fido_stop_bridge_for_install
fi

cd "${repo_root}"
as_build_owner rm -rf "${staging}"
install_args=(--install "${build_dir}")
if should_strip_install; then
  install_args+=(--strip)
fi
as_build_owner env DESTDIR="${staging}" cmake "${install_args[@]}"
if should_strip_install; then
  verify_staged_binary_stripped
fi
rsync -a --chown=0:0 "${staging}/" /
as_build_owner rm -rf "${staging}"

printf 'installed %s (%s) to %s (build/ owned by %s)\n' \
  "${binary}" "${install_build_type}" "${prefix}" "${build_owner}"
