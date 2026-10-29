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

# `make package`: Release .deb/.rpm for this host arch, on the host (no container),
# through the same release-build-package.sh the Release workflow and
# `make ci-local CI_LOCAL_FLAGS="--release-arch <host>"` use. Per format this means a
# fresh build/release-<fmt>-<arch> tree, CMAKE_BUILD_TYPE=Release (LTO, strip, no
# .comment), ctest, CPack, then verify-glibc-ceiling.sh and
# verify-release-elf-hardening.sh on the packaged binary. Artifacts land in dist/.
#
# Usage: PACKAGE_FORMAT=auto|deb|rpm|both bash make/package-host.sh
#
# PACKAGE_FORMAT=auto (default) builds every format whose packager is installed
# (dpkg-deb -> deb, rpmbuild -> rpm). PCSC_FIDO_LOCAL_CI_KEEP_BUILDS=1 keeps the
# previous build/release-* trees (probe results then come from the old CMakeCache).

set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
scripts_dir="${repo_root}/.github/scripts"

case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *)
    printf 'error: make package supports amd64/arm64 hosts only (got %s)\n' "$(uname -m)" >&2
    printf 'hint: cross ports: make ci-local CI_LOCAL_FLAGS="--release-arch armhf|ppc64el|riscv64|s390x"\n' >&2
    exit 2
    ;;
esac

have_deb=0
have_rpm=0
command -v dpkg-deb >/dev/null 2>&1 && have_deb=1
command -v rpmbuild >/dev/null 2>&1 && have_rpm=1

formats=()
case "${PACKAGE_FORMAT:-auto}" in
  auto)
    ((have_deb)) && formats+=(deb)
    ((have_rpm)) && formats+=(rpm)
    if ((${#formats[@]} == 0)); then
      printf 'error: neither dpkg-deb nor rpmbuild found; nothing to package\n' >&2
      printf 'hint: INSTALL_DEPS=1 make package (or: make deps PCSC_FIDO_DEPS_SCOPE=package)\n' >&2
      exit 1
    fi
    ;;
  deb) formats=(deb) ;;
  rpm) formats=(rpm) ;;
  both) formats=(deb rpm) ;;
  *)
    printf 'error: PACKAGE_FORMAT must be auto, deb, rpm, or both (got %s)\n' "${PACKAGE_FORMAT}" >&2
    exit 2
    ;;
esac

for fmt in "${formats[@]}"; do
  case "${fmt}" in
    deb)
      if ((have_deb == 0)); then
        printf 'error: dpkg-deb not found (needed for PACKAGE_FORMAT=%s)\n' "${PACKAGE_FORMAT:-auto}" >&2
        exit 1
      fi
      ;;
    rpm)
      if ((have_rpm == 0)); then
        printf 'error: rpmbuild not found (needed for PACKAGE_FORMAT=%s)\n' "${PACKAGE_FORMAT:-auto}" >&2
        exit 1
      fi
      ;;
  esac
done

built=()
step=0
for fmt in "${formats[@]}"; do
  step=$((step + 1))
  build_dir="${repo_root}/build/release-${fmt}-${arch}"
  printf '\n[%s/%s] host release package: %s %s\n' "${step}" "${#formats[@]}" "${arch}" "${fmt}"
  if [[ ${PCSC_FIDO_LOCAL_CI_KEEP_BUILDS:-0} != "1" && -e ${build_dir} ]]; then
    printf -- '-- wiping %s --\n' "${build_dir#"${repo_root}/"}" >&2
    rm -rf "${build_dir}"
  fi
  AUTO_INSTALL_LINUX_DEPS=0 bash "${scripts_dir}/release-build-package.sh" \
    --format "${fmt}" --arch "${arch}" --build-dir "${build_dir}"
  while IFS= read -r artifact; do
    [[ -n ${artifact} ]] || continue
    built+=("${repo_root}/dist/$(basename "${artifact}")")
  done < <(find "${build_dir}" -maxdepth 1 -type f \( -name '*.deb' -o -name '*.rpm' \) -print)
done

printf '\n-- make package: %s complete --\n' "${arch}"
for artifact in "${built[@]}"; do
  ls -la "${artifact}"
done
