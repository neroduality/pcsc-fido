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

# Linux dependency installer for pcsc-fido -- build, test, lint, package, and CI tooling.
#
# Usage: bash .github/scripts/install-linux-deps.sh
#
# Environment:
#   AUTO_INSTALL_LINUX_DEPS=0   skip package install (default for local make; CI sets 1)
#   INSTALL_DEPS=0              alias for AUTO_INSTALL_LINUX_DEPS (nero-nfc style)
#   PCSC_FIDO_ALLOW_SUDO_DEPS=1 allow sudo apt/dnf when not root (local opt-in; auto in GITHUB_ACTIONS)
#   PCSC_FIDO_DEPS_SCOPE=build|package|verify|full
#     build   -- compile/test deps (make build/test)
#     package -- build + native CPack tools (make package)
#     verify  -- build + sanitizer runtime + valgrind (make verify/valgrind)
#     full    -- lint/CI toolchain (default when unset; make lint/deps)
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../linters/helper-cppcheck.sh
source "${SCRIPT_DIR}/../linters/helper-cppcheck.sh"
# shellcheck source=../linters/helper-codespell.sh
source "${SCRIPT_DIR}/../linters/helper-codespell.sh"
# shellcheck source=../linters/helper-markdownlint.sh
source "${SCRIPT_DIR}/../linters/helper-markdownlint.sh"
# shellcheck source=helper-container-bind-mount.sh
source "${SCRIPT_DIR}/helper-container-bind-mount.sh"
# shellcheck source=helper-fuzz-probe.sh
source "${SCRIPT_DIR}/helper-fuzz-probe.sh"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "-- install-linux-deps: not Linux; skipping --" >&2
  exit 0
fi

: "${AUTO_INSTALL_LINUX_DEPS:=${INSTALL_DEPS:-1}}"

if [[ ${AUTO_INSTALL_LINUX_DEPS} == "0" ]]; then
  echo "-- install-linux-deps: auto-install disabled; skipping --" >&2
  exit 0
fi

have() { command -v "$1" >/dev/null 2>&1; }

PCSC_FIDO_CLANG_TIDY_MIN_VERSION="${PCSC_FIDO_CLANG_TIDY_MIN_VERSION:-21.0.0}"
PCSC_FIDO_CLANG_FORMAT_MIN_VERSION="${PCSC_FIDO_CLANG_FORMAT_MIN_VERSION:-20.0.0}"
PCSC_FIDO_LLVM_PREFERRED_MAJOR="${PCSC_FIDO_LLVM_PREFERRED_MAJOR:-21}"
PCSC_FIDO_MARKDOWNLINT_MIN_VERSION="${PCSC_FIDO_MARKDOWNLINT_MIN_VERSION:-0.48.0}"

pcsc_fido_deps_scope() {
  case "${PCSC_FIDO_DEPS_SCOPE:-full}" in
    build | package | verify | full) printf '%s' "${PCSC_FIDO_DEPS_SCOPE:-full}" ;;
    *)
      printf 'error: PCSC_FIDO_DEPS_SCOPE must be build, package, verify, or full (got %s)\n' \
        "${PCSC_FIDO_DEPS_SCOPE}" >&2
      return 1
      ;;
  esac
}

pcsc_fido_verify_gcc_min() {
  if ! have gcc; then
    return 0
  fi
  gcc_major="$(gcc -dumpversion | cut -d. -f1)"
  if [[ ${gcc_major} -lt 13 ]]; then
    printf 'error: GCC 13+ required for ISO C23 (found GCC %s)\n' "$(gcc -dumpversion)" >&2
    return 1
  fi
}

pcsc_fido_build_tools_ok() {
  have cmake && have gcc && have make && have pkg-config && pkg-config --exists libpcsclite
}

pcsc_fido_package_tools_ok() {
  pcsc_fido_build_tools_ok && { have dpkg-deb || have rpmbuild; }
}

pcsc_fido_verify_tools_ok() {
  pcsc_fido_build_tools_ok && have valgrind
}

scan_build_ok() {
  local v p
  if have scan-build; then return 0; fi
  for v in 21 20 19 18 17 16 15 14; do
    have "scan-build-${v}" && return 0
  done
  for p in /usr/lib64/llvm*/bin/scan-build /usr/lib/llvm*/bin/scan-build; do
    [[ -x ${p} ]] && return 0
  done
  return 1
}

pcsc_fido_host_tools_ok() {
  have cmake && have gcc && have make && have pkg-config && pkg-config --exists libpcsclite &&
    have valgrind && pcsc_fido_ensure_clang_tidy && pcsc_fido_ensure_clang_format &&
    have cppcheck && have shellcheck && have codespell && have python3 &&
    pcsc_fido_ensure_scan_build
}

as_root() {
  if [[ ${EUID} -eq 0 ]]; then
    "$@"
  elif pcsc_fido_may_use_sudo_for_deps && pcsc_fido_can_sudo_noninteractive; then
    sudo -n "$@"
  else
    printf 'error: package install requires root or passwordless sudo\n' >&2
    printf 'hint: run once: sudo bash .github/scripts/install-linux-deps.sh\n' >&2
    printf '      or:   make deps PCSC_FIDO_ALLOW_SUDO_DEPS=1\n' >&2
    return 1
  fi
}

pcsc_fido_version_ge() {
  local want="$1"
  local have_ver="$2"
  [[ -n ${have_ver} ]] || return 1
  [[ "$(printf '%s\n%s\n' "${want}" "${have_ver}" | sort -V | head -n1)" == "${want}" ]]
}

pcsc_fido_lint_tool_install_dir() {
  if [[ ${EUID} -eq 0 ]]; then
    printf '/usr/local/bin\n'
  else
    printf '%s\n' "${HOME}/.local/bin"
  fi
}

pcsc_fido_export_tool_shim_dir() {
  local install_dir="$1"
  case ":${PATH}:" in
    *":${install_dir}:"*) ;;
    *)
      PATH="${install_dir}:${PATH}"
      export PATH
      ;;
  esac
}

pcsc_fido_clang_tidy_version_raw() {
  local bin="${1:-}"
  if [[ -z ${bin} ]]; then
    have clang-tidy || return 1
    bin="$(command -v clang-tidy)"
  fi
  [[ -x ${bin} ]] || return 1
  "${bin}" --version 2>/dev/null |
    sed -n \
      -e 's/.*LLVM version \([0-9][0-9.]*\).*/\1/p' \
      -e 's/.*clang-tidy version \([0-9][0-9.]*\).*/\1/p' |
    head -n1
}

pcsc_fido_find_clang_tidy() {
  local name candidate ver best="" best_ver=""
  for name in \
    "clang-tidy-${PCSC_FIDO_LLVM_PREFERRED_MAJOR}" \
    clang-tidy-21 clang-tidy-20 clang-tidy-19 clang-tidy-18 clang-tidy; do
    candidate="$(command -v "${name}" 2>/dev/null)" || continue
    [[ -x ${candidate} ]] || continue
    ver="$(pcsc_fido_clang_tidy_version_raw "${candidate}")" || continue
    pcsc_fido_version_ge "${PCSC_FIDO_CLANG_TIDY_MIN_VERSION}" "${ver}" || continue
    if [[ -z ${best_ver} ]] ||
      [[ "$(printf '%s\n%s\n' "${best_ver}" "${ver}" | sort -V | tail -n1)" == "${ver}" ]]; then
      best="${candidate}"
      best_ver="${ver}"
    fi
  done
  [[ -n ${best} ]] || return 1
  printf '%s\n' "${best}"
}

pcsc_fido_find_run_clang_tidy() {
  local tidy_bin="$1"
  local base="${tidy_bin##*/}"
  local candidate

  case "${base}" in
    clang-tidy-[0-9][0-9])
      for candidate in "run-${base}" "run-${base}.py"; do
        command -v "${candidate}" >/dev/null 2>&1 && {
          command -v "${candidate}"
          return 0
        }
      done
      ;;
  esac

  for candidate in run-clang-tidy run-clang-tidy.py; do
    command -v "${candidate}" >/dev/null 2>&1 && {
      command -v "${candidate}"
      return 0
    }
  done
  return 1
}

pcsc_fido_ensure_clang_tidy() {
  local tidy_bin run_bin install_dir
  tidy_bin="$(pcsc_fido_find_clang_tidy)" || return 1

  install_dir="$(pcsc_fido_lint_tool_install_dir)"
  mkdir -p "${install_dir}"
  [[ ${tidy_bin} == "${install_dir}/clang-tidy" ]] ||
    ln -sf "${tidy_bin}" "${install_dir}/clang-tidy"

  if run_bin="$(pcsc_fido_find_run_clang_tidy "${tidy_bin}")"; then
    [[ ${run_bin} == "${install_dir}/run-clang-tidy" ]] ||
      ln -sf "${run_bin}" "${install_dir}/run-clang-tidy"
  fi

  pcsc_fido_export_tool_shim_dir "${install_dir}"
  pcsc_fido_version_ge "${PCSC_FIDO_CLANG_TIDY_MIN_VERSION}" \
    "$(pcsc_fido_clang_tidy_version_raw)"
}

pcsc_fido_clang_format_version_raw() {
  local bin="${1:-}"
  if [[ -z ${bin} ]]; then
    have clang-format || return 1
    bin="$(command -v clang-format)"
  fi
  [[ -x ${bin} ]] || return 1
  "${bin}" --version 2>/dev/null |
    sed -n \
      -e 's/.*LLVM version \([0-9][0-9.]*\).*/\1/p' \
      -e 's/.*clang-format version \([0-9][0-9.]*\).*/\1/p' |
    head -n1
}

pcsc_fido_find_clang_format() {
  local name candidate ver best="" best_ver=""
  for name in \
    "clang-format-${PCSC_FIDO_LLVM_PREFERRED_MAJOR}" \
    clang-format-21 clang-format-20 clang-format; do
    candidate="$(command -v "${name}" 2>/dev/null)" || continue
    [[ -x ${candidate} ]] || continue
    ver="$(pcsc_fido_clang_format_version_raw "${candidate}")" || continue
    pcsc_fido_version_ge "${PCSC_FIDO_CLANG_FORMAT_MIN_VERSION}" "${ver}" || continue
    if [[ -z ${best_ver} ]] ||
      [[ "$(printf '%s\n%s\n' "${best_ver}" "${ver}" | sort -V | tail -n1)" == "${ver}" ]]; then
      best="${candidate}"
      best_ver="${ver}"
    fi
  done
  [[ -n ${best} ]] || return 1
  printf '%s\n' "${best}"
}

pcsc_fido_ensure_clang_format() {
  local format_bin install_dir
  format_bin="$(pcsc_fido_find_clang_format)" || return 1

  install_dir="$(pcsc_fido_lint_tool_install_dir)"
  mkdir -p "${install_dir}"
  [[ ${format_bin} == "${install_dir}/clang-format" ]] ||
    ln -sf "${format_bin}" "${install_dir}/clang-format"

  pcsc_fido_export_tool_shim_dir "${install_dir}"
  pcsc_fido_version_ge "${PCSC_FIDO_CLANG_FORMAT_MIN_VERSION}" \
    "$(pcsc_fido_clang_format_version_raw)"
}

pcsc_fido_scan_build_version_raw() {
  local bin="${1:?}"
  local ver base
  [[ -x ${bin} ]] || return 1
  ver="$("${bin}" --version 2>/dev/null |
    sed -n \
      -e 's/.*LLVM version \([0-9][0-9.]*\).*/\1/p' \
      -e 's/.*scan-build version \([0-9][0-9.]*\).*/\1/p' |
    head -n1)"
  if [[ -n ${ver} ]]; then
    printf '%s\n' "${ver}"
    return 0
  fi
  base="$(basename "${bin}")"
  if [[ ${base} =~ ^scan-build-([0-9]+)$ ]]; then
    printf '%s.0.0\n' "${BASH_REMATCH[1]}"
    return 0
  fi
  return 1
}

pcsc_fido_find_scan_build() {
  local name candidate ver best="" best_ver=""
  for name in \
    "scan-build-${PCSC_FIDO_LLVM_PREFERRED_MAJOR}" \
    scan-build-21 scan-build-20 scan-build-19 scan-build-18; do
    candidate="$(command -v "${name}" 2>/dev/null)" || continue
    [[ -x ${candidate} ]] || continue
    ver="$(pcsc_fido_scan_build_version_raw "${candidate}")" || continue
    pcsc_fido_version_ge "${PCSC_FIDO_CLANG_TIDY_MIN_VERSION}" "${ver}" || continue
    if [[ -z ${best_ver} ]] ||
      [[ "$(printf '%s\n%s\n' "${best_ver}" "${ver}" | sort -V | tail -n1)" == "${ver}" ]]; then
      best="${candidate}"
      best_ver="${ver}"
    fi
  done
  [[ -n ${best} ]] || return 1
  printf '%s\n' "${best}"
}

pcsc_fido_ensure_scan_build() {
  local scan_bin install_dir ver
  scan_bin="$(pcsc_fido_find_scan_build)" || return 1
  ver="$(pcsc_fido_scan_build_version_raw "${scan_bin}")" || return 1

  install_dir="$(pcsc_fido_lint_tool_install_dir)"
  mkdir -p "${install_dir}"
  [[ ${scan_bin} == "${install_dir}/scan-build" ]] ||
    ln -sf "${scan_bin}" "${install_dir}/scan-build"

  pcsc_fido_export_tool_shim_dir "${install_dir}"
  pcsc_fido_version_ge "${PCSC_FIDO_CLANG_TIDY_MIN_VERSION}" "${ver}"
}

pcsc_fido_install_llvm_tool_shims() {
  printf -- '-- LLVM tool shims (clang-tidy/clang-format/scan-build/run-clang-tidy) --\n' >&2
  pcsc_fido_ensure_clang_tidy &&
    pcsc_fido_ensure_clang_format &&
    pcsc_fido_ensure_scan_build
}

pcsc_fido_apt_pkg_installable() {
  local pkg
  for pkg in "$@"; do
    if ! apt-get install -y --dry-run "${pkg}" >/dev/null 2>&1; then
      return 1
    fi
  done
}

pcsc_fido_apt_codename() {
  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    if [[ -n ${VERSION_CODENAME:-} ]]; then
      printf '%s\n' "${VERSION_CODENAME}"
      return 0
    fi
  fi
  if have lsb_release; then
    lsb_release -sc 2>/dev/null
    return 0
  fi
  return 1
}

pcsc_fido_apt_is_debian() {
  [[ -f /etc/os-release ]] && grep -qE '^ID=debian' /etc/os-release
}

pcsc_fido_llvm_apt_codename_fallbacks() {
  local primary="$1"
  printf '%s\n' "${primary}"
  if pcsc_fido_apt_is_debian; then
    case "${primary}" in
      trixie | sid | unstable | testing)
        printf '%s\n' bookworm
        ;;
    esac
  fi
}

pcsc_fido_install_llvm_apt_repo_for_codename() {
  local ver="$1"
  local codename="$2"
  local repo_line key_file list_file

  repo_line="deb https://apt.llvm.org/${codename}/ llvm-toolchain-${codename}-${ver} main"
  list_file="/etc/apt/sources.list.d/llvm-toolchain-${codename}-${ver}.list"

  printf -- '-- apt.llvm.org: LLVM %s (%s) --\n' "${ver}" "${codename}" >&2
  as_root apt-get install -y --no-install-recommends curl ca-certificates gnupg lsb-release

  key_file="/etc/apt/trusted.gpg.d/apt.llvm.org.asc"
  if [[ ! -f ${key_file} ]]; then
    curl -fsSL --retry 3 https://apt.llvm.org/llvm-snapshot.gpg.key |
      as_root tee "${key_file}" >/dev/null
  fi

  if ! grep -rqF "llvm-toolchain-${codename}-${ver}" /etc/apt/sources.list.d/ 2>/dev/null; then
    printf '%s\n' "${repo_line}" | as_root tee "${list_file}" >/dev/null
  fi

  if ! as_root apt-get update -qq; then
    as_root rm -f "${list_file}" 2>/dev/null || true
    as_root apt-get update -qq >/dev/null 2>&1 || true
    return 1
  fi
  pcsc_fido_apt_pkg_installable "clang-tidy-${ver}"
}

pcsc_fido_install_llvm_apt_repo() {
  local ver="$1"
  local codename candidate

  if pcsc_fido_apt_pkg_installable "clang-tidy-${ver}"; then
    return 0
  fi

  codename="$(pcsc_fido_apt_codename)" || return 1
  while IFS= read -r candidate; do
    [[ -n ${candidate} ]] || continue
    if pcsc_fido_install_llvm_apt_repo_for_codename "${ver}" "${candidate}"; then
      return 0
    fi
  done < <(pcsc_fido_llvm_apt_codename_fallbacks "${codename}")

  printf 'error: clang-tidy-%s unavailable after apt.llvm.org setup\n' "${ver}" >&2
  apt-cache policy "clang-tidy-${ver}" >&2 || true
  return 1
}

pcsc_fido_install_clang_tidy_via_distro() {
  local ver="${PCSC_FIDO_LLVM_PREFERRED_MAJOR}"
  if ! pcsc_fido_apt_pkg_installable "clang-tidy-${ver}" "clang-tools-${ver}"; then
    return 1
  fi
  printf -- '-- apt-get: clang-tidy-%s + clang-tools-%s --\n' "${ver}" "${ver}" >&2
  as_root apt-get install -y --no-install-recommends "clang-tidy-${ver}" "clang-tools-${ver}"
}

pcsc_fido_install_clang_tidy_via_llvm_apt() {
  local ver="${PCSC_FIDO_LLVM_PREFERRED_MAJOR}"
  pcsc_fido_install_llvm_apt_repo "${ver}" || return 1
  printf -- '-- apt-get: clang-tidy-%s + clang-tools-%s (apt.llvm.org) --\n' "${ver}" "${ver}" >&2
  as_root apt-get install -y --no-install-recommends "clang-tidy-${ver}" "clang-tools-${ver}"
}

pcsc_fido_install_clang_format_via_distro() {
  local ver
  for ver in "${PCSC_FIDO_LLVM_PREFERRED_MAJOR}" 20; do
    if ! pcsc_fido_apt_pkg_installable "clang-format-${ver}"; then
      continue
    fi
    printf -- '-- apt-get: clang-format-%s --\n' "${ver}" >&2
    as_root apt-get install -y --no-install-recommends "clang-format-${ver}"
    return 0
  done
  return 1
}

pcsc_fido_install_clang_format_via_llvm_apt() {
  local ver="${PCSC_FIDO_LLVM_PREFERRED_MAJOR}"
  pcsc_fido_install_llvm_apt_repo "${ver}" || return 1
  if ! pcsc_fido_apt_pkg_installable "clang-format-${ver}"; then
    return 1
  fi
  printf -- '-- apt-get: clang-format-%s (apt.llvm.org) --\n' "${ver}" >&2
  as_root apt-get install -y --no-install-recommends "clang-format-${ver}"
}

install_clang_tidy() {
  if pcsc_fido_ensure_clang_tidy; then
    return 0
  fi
  if have apt-get; then
    pcsc_fido_install_clang_tidy_via_distro || true
    if pcsc_fido_ensure_clang_tidy; then
      return 0
    fi
    pcsc_fido_install_clang_tidy_via_llvm_apt || return 1
  elif have dnf; then
    as_root dnf install -y clang-tools-extra clang-tools clang
  fi
  if pcsc_fido_ensure_clang_tidy; then
    return 0
  fi
  if ! have clang-tidy; then
    printf 'warning: clang-tidy not installed\n' >&2
  else
    printf 'warning: clang-tidy >= %s required; found %s\n' \
      "${PCSC_FIDO_CLANG_TIDY_MIN_VERSION}" \
      "$(pcsc_fido_clang_tidy_version_raw 2>/dev/null || echo unknown)" >&2
  fi
  return 1
}

install_clang_format() {
  if pcsc_fido_ensure_clang_format; then
    return 0
  fi
  if have apt-get; then
    pcsc_fido_install_clang_format_via_distro || true
    if pcsc_fido_ensure_clang_format; then
      return 0
    fi
    pcsc_fido_install_clang_format_via_llvm_apt || true
  elif have dnf; then
    as_root dnf install -y clang-tools-extra clang
  fi
  if pcsc_fido_ensure_clang_format; then
    return 0
  fi
  if ! have clang-format; then
    printf 'warning: clang-format not installed\n' >&2
  else
    printf 'warning: clang-format >= %s required; found %s\n' \
      "${PCSC_FIDO_CLANG_FORMAT_MIN_VERSION}" \
      "$(pcsc_fido_clang_format_version_raw 2>/dev/null || echo unknown)" >&2
  fi
  return 1
}

# uv provides `uvx`, which the org lint kit's format job uses to run ruff + mypy
# (pinned via the kit's tool-versions.yaml). ruff/mypy are intentionally NOT
# distro packages here: the kit always invokes them through uvx, and ruff is not
# packaged in Ubuntu main (breaks apt on the Lima ubuntu-24.04 VM). Root installs
# land in /usr/local/bin so uvx stays on PATH after CI drops from root to the
# bind-mount host user (HOME becomes /tmp/...; ~/.local/bin would be lost).
install_uv() {
  if have uv && have uvx; then
    return 0
  fi
  if ! have curl && ! have wget; then
    printf 'warning: need curl or wget to install uv (ruff/mypy via uvx)\n' >&2
    return 1
  fi
  local install_dir
  if [[ ${EUID} -eq 0 ]]; then
    install_dir=/usr/local/bin
  else
    install_dir="${HOME}/.local/bin"
    mkdir -p "${install_dir}"
  fi
  printf -- '-- install uv (astral-sh) -- provides uvx for ruff/mypy -> %s --\n' "${install_dir}" >&2
  if have curl; then
    curl -LsSf https://astral.sh/uv/install.sh |
      env UV_INSTALL_DIR="${install_dir}" UV_NO_MODIFY_PATH=1 sh
  else
    wget -qO- https://astral.sh/uv/install.sh |
      env UV_INSTALL_DIR="${install_dir}" UV_NO_MODIFY_PATH=1 sh
  fi
  case ":${PATH}:" in
    *":${install_dir}:"*) : ;;
    *)
      PATH="${install_dir}:${PATH}"
      export PATH
      ;;
  esac
  have uv && have uvx
}

# markdownlint-cli (and its deps, e.g. string-width>=20) requires Node.js >= 20;
# the RegExp `v` flag it uses throws on Node 18. Ubuntu 24.04 apt ships Node 18,
# so upgrade via NodeSource. Debian sid / Fedora already ship Node >= 20 and skip
# straight through. As root, symlink /usr/local/bin/node so `node` (not just
# `nodejs`) is on PATH for npm wrappers.
PCSC_FIDO_NODE_MIN_MAJOR="${PCSC_FIDO_NODE_MIN_MAJOR:-20}"

pcsc_fido_node_major() {
  local ver=""
  if have node; then
    ver="$(node --version 2>/dev/null)"
  elif have nodejs; then
    ver="$(nodejs --version 2>/dev/null)"
  else
    return 1
  fi
  ver="${ver#v}"
  printf '%s' "${ver%%.*}"
}

pcsc_fido_node_ok() {
  local major
  major="$(pcsc_fido_node_major 2>/dev/null)" || return 1
  [[ -n ${major} && ${major} =~ ^[0-9]+$ && ${major} -ge ${PCSC_FIDO_NODE_MIN_MAJOR} ]]
}

pcsc_fido_ensure_node_symlink() {
  have node && return 0
  have nodejs || return 0
  if [[ ${EUID} -eq 0 ]]; then
    ln -sf "$(command -v nodejs)" /usr/local/bin/node 2>/dev/null || true
  else
    mkdir -p "${HOME}/.local/bin"
    ln -sf "$(command -v nodejs)" "${HOME}/.local/bin/node" 2>/dev/null || true
  fi
}

install_node() {
  if pcsc_fido_node_ok; then
    pcsc_fido_ensure_node_symlink
    return 0
  fi
  if have apt-get; then
    if ! have curl; then
      printf 'warning: need curl to add NodeSource (Node.js >= %s)\n' "${PCSC_FIDO_NODE_MIN_MAJOR}" >&2
      return 1
    fi
    if [[ ! -f /etc/apt/sources.list.d/nodesource.list &&
      ! -f /etc/apt/sources.list.d/nodesource.sources ]]; then
      printf -- '-- NodeSource: Node.js %s.x (markdownlint-cli) --\n' "${PCSC_FIDO_NODE_MIN_MAJOR}" >&2
      curl -fsSL "https://deb.nodesource.com/setup_${PCSC_FIDO_NODE_MIN_MAJOR}.x" | as_root bash -
    fi
    as_root apt-get install -y nodejs
    pcsc_fido_ensure_node_symlink
  elif have dnf; then
    as_root dnf install -y nodejs npm || true
    pcsc_fido_ensure_node_symlink
  fi
  pcsc_fido_node_ok
}

pcsc_fido_npm_global_bin() {
  local prefix
  have npm || return 1
  prefix="$(npm prefix -g 2>/dev/null || true)"
  [[ -n ${prefix} ]] || return 1
  printf '%s/bin\n' "${prefix}"
}

pcsc_fido_prepend_npm_global_bin() {
  local npm_bin
  npm_bin="$(pcsc_fido_npm_global_bin)" || return 0
  case ":${PATH}:" in
    *":${npm_bin}:"*) ;;
    *)
      PATH="${npm_bin}:${PATH}"
      export PATH
      ;;
  esac
}

pcsc_fido_markdownlint_version_raw() {
  local out ver
  pcsc_fido_prepend_npm_global_bin
  have markdownlint || return 1
  out="$(markdownlint --version 2>/dev/null | head -n1)" || return 1
  [[ -n ${out} ]] || return 1
  ver="$(printf '%s\n' "${out}" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)"
  [[ -n ${ver} ]] || return 1
  printf '%s\n' "${ver}"
}

pcsc_fido_markdownlint_version_ge() {
  local want="$1"
  local have_ver
  have_ver="$(pcsc_fido_markdownlint_version_raw)" || return 1
  pcsc_fido_version_ge "${want}" "${have_ver}"
}

pcsc_fido_install_markdownlint_shim() {
  local install_dir="$1"
  [[ -n ${PCSC_FIDO_MARKDOWNLINT:-} || -n ${PCSC_FIDO_MARKDOWNLINT_JS:-} ]] || return 1
  mkdir -p "${install_dir}"
  case "${PCSC_FIDO_MARKDOWNLINT_MODE:-}" in
    path | bin)
      ln -sf "${PCSC_FIDO_MARKDOWNLINT}" "${install_dir}/markdownlint"
      ;;
    js)
      cat >"${install_dir}/markdownlint" <<EOF
#!/usr/bin/env sh
exec "${PCSC_FIDO_NODE_BIN}" "${PCSC_FIDO_MARKDOWNLINT_JS}" "\$@"
EOF
      chmod 755 "${install_dir}/markdownlint"
      ;;
    *)
      return 1
      ;;
  esac
  pcsc_fido_export_tool_shim_dir "${install_dir}"
  pcsc_fido_markdownlint_version_ge "${PCSC_FIDO_MARKDOWNLINT_MIN_VERSION}"
}

install_libfuzzer_runtime() {
  local probe_src probe_bin clang_ver deb_arch

  if pcsc_fido_bind_mount_ci_as_root; then
    return 0
  fi

  probe_src="$(mktemp --suffix=.c)"
  probe_bin="$(mktemp --suffix=.out)"
  cat >"${probe_src}" <<'EOF'
#include <stddef.h>
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  (void)data;
  (void)size;
  return 0;
}
EOF
  if pcsc_fido_resolve_fuzz_compiler "${probe_src}" "${probe_bin}" >/dev/null 2>&1; then
    rm -f "${probe_src}" "${probe_bin}"
    return 0
  fi
  rm -f "${probe_src}" "${probe_bin}"

  if command -v apt-get >/dev/null 2>&1; then
    clang_ver="$(pcsc_fido_clang_major_version clang || true)"
    if [[ -n ${clang_ver} ]]; then
      as_root apt-get install -y "libclang-rt-${clang_ver}-dev" || true
    fi
    if command -v dpkg-architecture >/dev/null 2>&1; then
      deb_arch="$(dpkg-architecture -qDEB_HOST_ARCH 2>/dev/null || true)"
      if [[ -n ${deb_arch} ]]; then
        as_root apt-get install -y "libclang-rt-dev-${deb_arch}" 2>/dev/null || true
      fi
    fi
  elif command -v dnf >/dev/null 2>&1; then
    as_root dnf install -y compiler-rt 2>/dev/null || true
  fi

  probe_src="$(mktemp --suffix=.c)"
  probe_bin="$(mktemp --suffix=.out)"
  cat >"${probe_src}" <<'EOF'
#include <stddef.h>
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  (void)data;
  (void)size;
  return 0;
}
EOF
  if pcsc_fido_resolve_fuzz_compiler "${probe_src}" "${probe_bin}" >/dev/null 2>&1; then
    rm -f "${probe_src}" "${probe_bin}"
    return 0
  fi
  rm -f "${probe_src}" "${probe_bin}"
  printf 'warning: libFuzzer runtime still unavailable after package install\n' >&2
  pcsc_fido_fuzz_install_hint
  return 1
}

install_cppcheck() {
  if pcsc_fido_bind_mount_ci_as_root; then
    return 0
  fi
  if pcsc_fido_ensure_cppcheck; then
    return 0
  fi
  if ! command -v cppcheck >/dev/null 2>&1; then
    printf 'warning: cppcheck not installed\n' >&2
  else
    printf 'warning: cppcheck >= %s required; found %s\n' \
      "$PCSC_FIDO_CPPCHECK_MIN_VERSION" \
      "$(pcsc_fido_cppcheck_version_raw 2>/dev/null || echo unknown)" >&2
  fi
  pcsc_fido_cppcheck_hint
  return 1
}

install_codespell() {
  if pcsc_fido_bind_mount_ci_as_root; then
    return 0
  fi
  if pcsc_fido_ensure_codespell; then
    return 0
  fi
  if ! command -v codespell >/dev/null 2>&1; then
    printf 'warning: codespell not installed\n' >&2
  else
    printf 'warning: codespell >= 2.4.0 required (--ignore-multiline-regex); found %s\n' \
      "$(codespell --version 2>/dev/null | head -n1 || echo unknown)" >&2
  fi
  pcsc_fido_codespell_hint
  return 1
}

install_markdownlint() {
  local repo_root
  repo_root="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
  if pcsc_fido_markdownlint_version_ge "${PCSC_FIDO_MARKDOWNLINT_MIN_VERSION}"; then
    return 0
  fi
  install_node || return 1
  if have npm; then
    local markdownlint_bin
    pcsc_fido_ensure_node_symlink || true
    printf -- '-- npm: markdownlint-cli (>= %s) --\n' "${PCSC_FIDO_MARKDOWNLINT_MIN_VERSION}" >&2
    as_root npm install -g "markdownlint-cli@>=${PCSC_FIDO_MARKDOWNLINT_MIN_VERSION}"
    pcsc_fido_prepend_npm_global_bin
    if pcsc_fido_markdownlint_version_ge "${PCSC_FIDO_MARKDOWNLINT_MIN_VERSION}"; then
      markdownlint_bin="$(command -v markdownlint)"
      if [[ ${EUID} -eq 0 && ${markdownlint_bin} != /usr/local/bin/markdownlint ]]; then
        ln -sf "${markdownlint_bin}" /usr/local/bin/markdownlint 2>/dev/null || true
      fi
      return 0
    fi
  fi
  if pcsc_fido_ensure_markdownlint "${repo_root}" &&
    pcsc_fido_install_markdownlint_shim "$(pcsc_fido_lint_tool_install_dir)"; then
    return 0
  fi
  printf 'warning: markdownlint >= %s not installed (install nodejs/npm, then re-run install-linux-deps.sh)\n' \
    "${PCSC_FIDO_MARKDOWNLINT_MIN_VERSION}" >&2
  pcsc_fido_markdownlint_hint
  return 1
}

deps_scope="$(pcsc_fido_deps_scope)"

if [[ ${deps_scope} == build ]] && pcsc_fido_build_tools_ok; then
  pcsc_fido_verify_gcc_min
  printf -- '-- install-linux-deps: build tools already present --\n'
  exit 0
fi

if [[ ${deps_scope} == package ]] && pcsc_fido_package_tools_ok; then
  pcsc_fido_verify_gcc_min
  printf -- '-- install-linux-deps: package tools already present --\n'
  exit 0
fi

if [[ ${deps_scope} == verify ]] && pcsc_fido_verify_tools_ok; then
  pcsc_fido_verify_gcc_min
  printf -- '-- install-linux-deps: verify tools already present --\n'
  exit 0
fi

if [[ ${deps_scope} == full ]] && pcsc_fido_host_tools_ok; then
  install_cppcheck || true
  install_codespell || true
  install_clang_tidy || true
  install_clang_format || true
  pcsc_fido_install_llvm_tool_shims || true
  install_node || true
  install_markdownlint || true
  install_uv || true
  printf -- '-- install-linux-deps: host tools already present --\n'
  exit 0
fi

if [[ ${EUID} -ne 0 ]] && ! pcsc_fido_may_use_sudo_for_deps && ! pcsc_fido_can_sudo_noninteractive; then
  printf 'error: missing build/CI tools and non-interactive sudo is unavailable\n' >&2
  printf 'install once (requires root):\n' >&2
  printf '  sudo bash .github/scripts/install-linux-deps.sh\n' >&2
  if [[ ${deps_scope} == build ]]; then
    printf 'or on Fedora/RHEL:\n' >&2
    printf '  sudo dnf install cmake gcc make pkg-config pcsc-lite-devel libasan libubsan\n' >&2
    printf 'or on Debian/Ubuntu:\n' >&2
    printf '  sudo apt-get install cmake gcc make pkg-config libpcsclite-dev libasan8 libubsan1\n' >&2
  elif [[ ${deps_scope} == package ]]; then
    printf 'or on Fedora/RHEL:\n' >&2
    printf '  sudo dnf install cmake gcc make pkg-config pcsc-lite-devel libasan libubsan rpm-build\n' >&2
    printf 'or on Debian/Ubuntu:\n' >&2
    printf '  sudo apt-get install cmake gcc make pkg-config libpcsclite-dev libasan8 libubsan1 dpkg-dev debhelper\n' >&2
  elif [[ ${deps_scope} == verify ]]; then
    printf 'or on Fedora/RHEL:\n' >&2
    printf '  sudo dnf install cmake gcc make pkg-config pcsc-lite-devel libasan libubsan libtsan valgrind\n' >&2
    printf 'or on Debian/Ubuntu:\n' >&2
    printf '  sudo apt-get install cmake gcc make pkg-config libpcsclite-dev libasan8 libubsan1 libtsan2 valgrind\n' >&2
  else
    printf 'or on Fedora/RHEL:\n' >&2
    printf '  sudo dnf install cmake gcc make pkg-config pcsc-lite-devel clang-analyzer clang-tools-extra lcov valgrind\n' >&2
    printf 'or on Debian/Ubuntu:\n' >&2
    printf '  sudo apt-get install cmake gcc make pkg-config libpcsclite-dev clang-tools lcov valgrind nodejs npm shfmt libclang-rt-*-dev\n' >&2
  fi
  exit 1
fi

if [[ ${deps_scope} == build ]]; then
  if command -v dnf >/dev/null 2>&1; then
    as_root dnf install -y \
      cmake gcc make pkgconf-pkg-config pcsc-lite pcsc-lite-devel \
      libasan libubsan
  elif command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    as_root apt-get update
    as_root apt-get install -y \
      cmake gcc make pkg-config libpcsclite-dev
    as_root apt-get install -y libasan8 2>/dev/null || as_root apt-get install -y libasan6 2>/dev/null || true
    as_root apt-get install -y libubsan2 2>/dev/null || as_root apt-get install -y libubsan1 2>/dev/null || true
  else
    echo "Unsupported package manager; install cmake, gcc, make, pkg-config, libpcsclite-dev." >&2
    exit 1
  fi
  if have gcc; then
    printf -- '-- install-linux-deps: %s --\n' "$(gcc --version | head -n1)"
  fi
  pcsc_fido_verify_gcc_min
  printf -- '-- install-linux-deps: build tools ready --\n'
  exit 0
fi

if [[ ${deps_scope} == package ]]; then
  if ! pcsc_fido_build_tools_ok; then
    if command -v dnf >/dev/null 2>&1; then
      as_root dnf install -y \
        cmake gcc make pkgconf-pkg-config pcsc-lite pcsc-lite-devel \
        libasan libubsan
    elif command -v apt-get >/dev/null 2>&1; then
      export DEBIAN_FRONTEND=noninteractive
      as_root apt-get update
      as_root apt-get install -y \
        cmake gcc make pkg-config libpcsclite-dev
      as_root apt-get install -y libasan8 2>/dev/null || as_root apt-get install -y libasan6 2>/dev/null || true
      as_root apt-get install -y libubsan2 2>/dev/null || as_root apt-get install -y libubsan1 2>/dev/null || true
    else
      echo "Unsupported package manager; install cmake, gcc, make, pkg-config, libpcsclite-dev." >&2
      exit 1
    fi
  fi
  if ! have dpkg-deb && ! have rpmbuild; then
    if command -v dnf >/dev/null 2>&1; then
      as_root dnf install -y rpm-build
    elif command -v apt-get >/dev/null 2>&1; then
      export DEBIAN_FRONTEND=noninteractive
      as_root apt-get install -y dpkg-dev debhelper
    else
      printf 'error: install dpkg-deb or rpmbuild for CPack .deb/.rpm output\n' >&2
      exit 1
    fi
  fi
  if have gcc; then
    printf -- '-- install-linux-deps: %s --\n' "$(gcc --version | head -n1)"
  fi
  pcsc_fido_verify_gcc_min
  printf -- '-- install-linux-deps: package tools ready --\n'
  exit 0
fi

if [[ ${deps_scope} == verify ]]; then
  if command -v dnf >/dev/null 2>&1; then
    as_root dnf install -y \
      cmake gcc make pkgconf-pkg-config pcsc-lite pcsc-lite-devel \
      libasan libubsan libtsan valgrind
  elif command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    as_root apt-get update
    as_root apt-get install -y \
      cmake gcc make pkg-config libpcsclite-dev valgrind
    as_root apt-get install -y libasan8 2>/dev/null || as_root apt-get install -y libasan6 2>/dev/null || true
    as_root apt-get install -y libubsan2 2>/dev/null || as_root apt-get install -y libubsan1 2>/dev/null || true
    as_root apt-get install -y libtsan2 2>/dev/null || as_root apt-get install -y libtsan0 2>/dev/null || true
  else
    echo "Unsupported package manager; install cmake, gcc, make, pkg-config, libpcsclite-dev, valgrind." >&2
    exit 1
  fi
  if have gcc; then
    printf -- '-- install-linux-deps: %s --\n' "$(gcc --version | head -n1)"
  fi
  pcsc_fido_verify_gcc_min
  printf -- '-- install-linux-deps: verify tools ready --\n'
  exit 0
fi

if command -v dnf >/dev/null 2>&1; then
  as_root dnf install -y \
    cmake gcc make ninja-build pkgconf-pkg-config pcsc-lite pcsc-lite-devel systemd udev \
    libasan libubsan libtsan rpm-build lcov valgrind \
    clang clang-analyzer clang-tools-extra clang-format cppcheck shellcheck codespell shfmt \
    yamllint \
    git ca-certificates curl gnupg python3 python3-pip python3-pyyaml nodejs npm
elif command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  as_root apt-get update
  as_root apt-get install -y \
    cmake gcc g++ make ninja-build pkg-config pcscd libpcsclite-dev systemd udev \
    dpkg-dev debhelper lcov valgrind \
    clang-tools clang-format cppcheck shellcheck codespell shfmt \
    yamllint \
    git ca-certificates curl gnupg python3 python3-pip python3-yaml nodejs npm
  as_root apt-get install -y libasan8 2>/dev/null || as_root apt-get install -y libasan6 2>/dev/null || true
  as_root apt-get install -y libubsan2 2>/dev/null || as_root apt-get install -y libubsan1 2>/dev/null || true
  as_root apt-get install -y libtsan2 2>/dev/null || as_root apt-get install -y libtsan0 2>/dev/null || true
  if have nodejs && ! have node; then
    if [[ ${EUID} -eq 0 ]]; then
      ln -sf /usr/bin/nodejs /usr/local/bin/node 2>/dev/null || true
    else
      mkdir -p "${HOME}/.local/bin"
      ln -sf "$(command -v nodejs)" "${HOME}/.local/bin/node" 2>/dev/null || true
    fi
  fi
else
  echo "Unsupported package manager; install cmake, gcc, make, pkg-config, pcscd, libpcsclite-dev, clang-tools, cppcheck, shellcheck, codespell." >&2
  exit 1
fi

install_cppcheck
install_codespell
install_clang_tidy
install_clang_format
pcsc_fido_install_llvm_tool_shims
install_node || true
install_markdownlint
install_uv || true
install_libfuzzer_runtime || true

if ! scan_build_ok; then
  printf 'error: scan-build missing after install (Fedora: clang-analyzer; Debian: clang-tools)\n' >&2
  exit 1
fi

if have gcc; then
  printf -- '-- install-linux-deps: %s --\n' "$(gcc --version | head -n1)"
fi
pcsc_fido_verify_gcc_min

printf -- '-- install-linux-deps: complete --\n'
