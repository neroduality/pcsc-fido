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

# Shared helpers for container CI on bind-mounted repo trees.
# Source this file; do not execute directly.

if [[ ${BASH_SOURCE[0]} == "${0}" ]]; then
  printf '%s\n' "error: source helper-container-bind-mount.sh instead of executing it" >&2
  exit 1
fi

_PCSC_FIDO_BIND_MOUNT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Relative repo paths root may touch during bind-mounted local container CI.
_PCSC_FIDO_BIND_MOUNT_RESTORE_PATHS=(
  build
  scan-build-report
  dist
  .github/pinned/markdownlint/node_modules
)

pcsc_fido_bind_mount_ci_as_root() {
  [[ $(id -u) -eq 0 && -n ${HOST_UID:-} && ${PCSC_FIDO_CI_AS_USER:-0} != 1 ]]
}

pcsc_fido_can_sudo_noninteractive() {
  [[ ${EUID:-$(id -u)} -eq 0 ]] || sudo -n true 2>/dev/null
}

# Local installs require PCSC_FIDO_ALLOW_SUDO_DEPS=1; CI runners may use passwordless sudo.
pcsc_fido_may_use_sudo_for_deps() {
  [[ ${PCSC_FIDO_ALLOW_SUDO_DEPS:-0} == 1 || ${GITHUB_ACTIONS:-false} == true ]]
}

pcsc_fido_restore_bind_mount_ownership() {
  local paths=("$@")
  if [[ ${#paths[@]} -eq 0 ]]; then
    paths=("${_PCSC_FIDO_BIND_MOUNT_RESTORE_PATHS[@]}")
  fi
  bash "${_PCSC_FIDO_BIND_MOUNT_DIR}/helper-restore-bind-mount-ownership.sh" "${paths[@]}"
}

pcsc_fido_rm_repo_path() {
  local repo_root="$1"
  local rel="$2"
  local target="${repo_root}/${rel}"

  if [[ ! -e ${target} ]]; then
    return 0
  fi
  if rm -rf "${target}" 2>/dev/null; then
    return 0
  fi
  pcsc_fido_restore_bind_mount_ownership "${rel}"
  rm -rf "${target}"
}

pcsc_fido_prepare_bind_mount_paths() {
  local repo_root="${1:-.}"
  if [[ $(id -u) -ne 0 || -z ${HOST_UID:-} ]]; then
    return 0
  fi
  local uid="${HOST_UID}"
  local gid="${HOST_GID:-${uid}}"
  local rel
  mkdir -p "${repo_root}/dist" "${repo_root}/build"
  for rel in dist build .github/pinned/markdownlint/node_modules; do
    if [[ -e "${repo_root}/${rel}" ]]; then
      chown -R "${uid}:${gid}" "${repo_root}/${rel}" 2>/dev/null || true
    fi
  done
}

pcsc_fido_ensure_runuser() {
  if command -v runuser >/dev/null 2>&1; then
    return 0
  fi
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y --no-install-recommends util-linux
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y --setopt=install_weak_deps=False util-linux
    dnf clean all
  fi
}

pcsc_fido_ensure_host_user() {
  local uid="${HOST_UID:?HOST_UID required}"
  local gid="${HOST_GID:-${uid}}"

  if id -u "${uid}" >/dev/null 2>&1; then
    return 0
  fi
  if ! getent group "${gid}" >/dev/null 2>&1; then
    groupadd -o -g "${gid}" pcsc_fido_ci 2>/dev/null || groupadd -g "${gid}" pcsc_fido_ci
  fi
  useradd -o -u "${uid}" -g "${gid}" -M -s /bin/bash pcsc_fido_ci
}

# In a root container entry, install deps then re-exec the same script as HOST_UID.
pcsc_fido_drop_to_host_user() {
  if [[ $(id -u) -ne 0 || -z ${HOST_UID:-} || ${PCSC_FIDO_CI_AS_USER:-0} == 1 ]]; then
    return 1
  fi
  pcsc_fido_ensure_runuser
  if ! command -v runuser >/dev/null 2>&1; then
    printf 'error: runuser missing; cannot run bind-mount builds without root-owned output\n' >&2
    return 1
  fi
  pcsc_fido_ensure_host_user
  exec runuser -u pcsc_fido_ci -- env \
    PCSC_FIDO_CI_AS_USER=1 \
    AUTO_INSTALL_LINUX_DEPS=0 \
    HOST_UID="${HOST_UID}" \
    HOST_GID="${HOST_GID:-${HOST_UID}}" \
    HOME="${PCSC_FIDO_CI_HOME:-/tmp/pcsc-fido-ci}" \
    "$@"
}

# After pcsc_fido_drop_to_host_user in bind-mounted local CI: abort if still root.
pcsc_fido_require_drop_to_host_user() {
  if ! pcsc_fido_drop_to_host_user "$@"; then
    printf 'error: failed to re-exec as host UID %s (install util-linux / runuser?)\n' \
      "${HOST_UID}" >&2
    exit 1
  fi
}

pcsc_fido_refuse_root_bind_mount_writes() {
  if [[ $(id -u) -eq 0 && -n ${HOST_UID:-} && ${PCSC_FIDO_CI_AS_USER:-0} != 1 ]]; then
    printf 'error: refusing bind-mount writes as root (HOST_UID=%s); drop to host user failed\n' \
      "${HOST_UID}" >&2
    exit 1
  fi
}

# Run a container command on a bind-mounted repo; restore ownership even on failure.
pcsc_fido_run_bind_mount_container() {
  local engine="${CONTAINER_ENGINE:-docker}"
  local -a restore_paths=()
  local -a docker_args=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --restore)
        shift
        while [[ $# -gt 0 && $1 != -- ]]; do
          restore_paths+=("$1")
          shift
        done
        ;;
      --)
        shift
        docker_args=("$@")
        break
        ;;
      *)
        printf 'error: pcsc_fido_run_bind_mount_container: unexpected argument %q (use --restore … -- docker-args…)\n' \
          "$1" >&2
        return 2
        ;;
    esac
  done

  if [[ ${#restore_paths[@]} -eq 0 ]]; then
    restore_paths=("${_PCSC_FIDO_BIND_MOUNT_RESTORE_PATHS[@]}")
  fi
  if [[ ${#docker_args[@]} -eq 0 ]]; then
    printf 'error: pcsc_fido_run_bind_mount_container needs docker run arguments after --\n' >&2
    return 2
  fi

  local restore_done=0
  _pcsc_fido_restore_bind_mount_on_exit() {
    if [[ ${restore_done} -eq 0 ]]; then
      restore_done=1
      pcsc_fido_restore_bind_mount_ownership "${restore_paths[@]}"
    fi
  }
  trap _pcsc_fido_restore_bind_mount_on_exit EXIT

  "${engine}" run --rm "${docker_args[@]}"
  local ec=$?

  restore_done=1
  trap - EXIT
  pcsc_fido_restore_bind_mount_ownership "${restore_paths[@]}"
  return "${ec}"
}

# Docker --platform for local CI container pulls.
# - CI_PLATFORM unset: linux/amd64 on x86_64 (GitHub Actions default); else linux/$host arch.
# - CI_PLATFORM empty: native pull (no --platform; same as ``CI_PLATFORM= native``).
# - CI_PLATFORM set: use that value (e.g. linux/amd64 to force amd64 on ARM via QEMU).
pcsc_fido_default_ci_platform() {
  case "$(uname -m)" in
    x86_64 | amd64) printf '%s' 'linux/amd64' ;;
    aarch64 | arm64) printf '%s' 'linux/arm64' ;;
    armv7l | armv6l) printf '%s' 'linux/arm/v7' ;;
    riscv64) printf '%s' 'linux/riscv64' ;;
    ppc64le) printf '%s' 'linux/ppc64le' ;;
    s390x) printf '%s' 'linux/s390x' ;;
    *) printf '%s' '' ;;
  esac
}

pcsc_fido_resolve_ci_platform() {
  if [[ -v CI_PLATFORM ]]; then
    printf '%s' "${CI_PLATFORM}"
    return 0
  fi
  pcsc_fido_default_ci_platform
}

pcsc_fido_ci_platform_docker_args() {
  local platform
  platform="$(pcsc_fido_resolve_ci_platform)"
  if [[ -n ${platform} ]]; then
    printf '%s\n' "--platform" "${platform}"
  fi
}

# Populate the PLATFORM_ARGS bash array for docker/podman run.
pcsc_fido_load_ci_platform_args() {
  PLATFORM_ARGS=()
  mapfile -t PLATFORM_ARGS < <(pcsc_fido_ci_platform_docker_args)
}
