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

# Linux dependency installer for pcsc-fido — build, test, lint, package, and CI tooling.
#
# Usage: bash .github/scripts/install-linux-deps.sh
#
# Environment:
#   AUTO_INSTALL_LINUX_DEPS=0   skip package install (default for local make ci-suite)
#   PCSC_FIDO_ALLOW_SUDO_DEPS=1 allow sudo apt/dnf when not root (local opt-in; auto in GITHUB_ACTIONS)
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
  echo "── install-linux-deps: not Linux; skipping ──" >&2
  exit 0
fi

if [[ ${AUTO_INSTALL_LINUX_DEPS:-1} == "0" ]]; then
  echo "── install-linux-deps: auto-install disabled; skipping ──" >&2
  exit 0
fi

have() { command -v "$1" >/dev/null 2>&1; }

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
    have valgrind && have clang-format && have cppcheck && have shellcheck && have codespell &&
    have python3 && scan_build_ok
}

as_root() {
  if [[ ${EUID} -eq 0 ]]; then
    "$@"
  elif pcsc_fido_may_use_sudo_for_deps && pcsc_fido_can_sudo_noninteractive; then
    sudo -n "$@"
  else
    printf 'error: package install requires root or passwordless sudo\n' >&2
    printf 'hint: run once: sudo bash .github/scripts/install-linux-deps.sh\n' >&2
    printf '      or:   make deps INSTALL_DEPS=1 PCSC_FIDO_ALLOW_SUDO_DEPS=1\n' >&2
    return 1
  fi
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
  if pcsc_fido_bind_mount_ci_as_root; then
    return 0
  fi
  if pcsc_fido_ensure_markdownlint "${repo_root}"; then
    if [[ ${PCSC_FIDO_MARKDOWNLINT} != markdownlint && ${EUID} -eq 0 ]]; then
      ln -sf "${PCSC_FIDO_MARKDOWNLINT}" /usr/local/bin/markdownlint 2>/dev/null || true
    elif [[ ${PCSC_FIDO_MARKDOWNLINT} != markdownlint && ${EUID} -ne 0 ]]; then
      mkdir -p "${HOME}/.local/bin"
      ln -sf "${PCSC_FIDO_MARKDOWNLINT}" "${HOME}/.local/bin/markdownlint" 2>/dev/null || true
    fi
    return 0
  fi
  printf 'warning: markdownlint not installed (install nodejs, then re-run install-linux-deps.sh)\n' >&2
  pcsc_fido_markdownlint_hint
  return 1
}

if pcsc_fido_host_tools_ok; then
  install_cppcheck || true
  install_codespell || true
  install_markdownlint || true
  install_libfuzzer_runtime || true
  printf '── install-linux-deps: host tools already present ──\n'
  exit 0
fi

if [[ ${EUID} -ne 0 ]] && ! pcsc_fido_may_use_sudo_for_deps && ! pcsc_fido_can_sudo_noninteractive; then
  printf 'error: missing build/CI tools and non-interactive sudo is unavailable\n' >&2
  printf 'install once (requires root):\n' >&2
  printf '  sudo bash .github/scripts/install-linux-deps.sh\n' >&2
  printf 'or on Fedora/RHEL:\n' >&2
  printf '  sudo dnf install cmake gcc make pkg-config pcsc-lite-devel clang-analyzer clang-tools-extra lcov valgrind\n' >&2
  printf 'or on Debian/Ubuntu:\n' >&2
  printf '  sudo apt-get install cmake gcc make pkg-config libpcsclite-dev clang-tools lcov valgrind nodejs npm shfmt libclang-rt-*-dev\n' >&2
  exit 1
fi

if command -v dnf >/dev/null 2>&1; then
  as_root dnf install -y \
    cmake gcc make ninja-build pkgconf-pkg-config pcsc-lite pcsc-lite-devel systemd udev \
    libasan libubsan libtsan rpm-build lcov valgrind \
    clang clang-analyzer clang-tools-extra clang-format cppcheck shellcheck codespell shfmt \
    git ca-certificates curl python3 python3-pyyaml nodejs npm
elif command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  as_root apt-get update
  as_root apt-get install -y \
    cmake gcc g++ make ninja-build pkg-config pcscd libpcsclite-dev systemd udev \
    dpkg-dev debhelper lcov valgrind \
    clang clang-tools clang-format cppcheck shellcheck codespell shfmt \
    git ca-certificates curl python3 python3-yaml nodejs npm
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
install_markdownlint
install_libfuzzer_runtime || true

if ! scan_build_ok; then
  printf 'error: scan-build missing after install (Fedora: clang-analyzer; Debian: clang-tools)\n' >&2
  exit 1
fi

if have gcc; then
  printf '── install-linux-deps: %s ──\n' "$(gcc --version | head -n1)"
  gcc_major="$(gcc -dumpversion | cut -d. -f1)"
  if [[ ${gcc_major} -lt 13 ]]; then
    printf 'error: GCC 13+ required for ISO C23 (found GCC %s)\n' "$(gcc -dumpversion)" >&2
    exit 1
  fi
fi

printf '── install-linux-deps: complete ──\n'
