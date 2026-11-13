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

# LLVM major for clang-format and clang-tidy under make lint, read from
# toolchain.llvm_major in .github/lint-c-cpp.yaml (the lint kit enforces the
# same key). Source this file. Do not copy the number into other scripts.
#
# Only make lint and the CI lint job pin it (PCSC_FIDO_LLVM_PIN=1). Everywhere
# else, including make deps, any distro LLVM is used as found.
# shellcheck shell=bash

PCSC_FIDO_LLVM_MAJOR="${PCSC_FIDO_LLVM_MAJOR:-$(
  sed -n "s/^[[:space:]]*llvm_major:[[:space:]]*[\"']\{0,1\}\([0-9][0-9]*\)[\"']\{0,1\}[[:space:]]*\(#.*\)\{0,1\}\$/\1/p" \
    "$(dirname -- "${BASH_SOURCE[0]}")/../lint-c-cpp.yaml" | head -n1
)}"
PCSC_FIDO_LLVM_PIN="${PCSC_FIDO_LLVM_PIN:-0}"

# Print every NAME-<major> command on PATH, newest major first.
pcsc_fido_llvm_versioned_tools() {
  local name="${1:?}"
  { compgen -c -- "${name}-" || true; } |
    sed -n "s/^${name}-\([0-9][0-9]*\)\$/\1/p" | sort -rnu | sed "s/^/${name}-/"
}

# NAME-<pinned major>, else a bare NAME of that major. Prints the resolved path.
pcsc_fido_find_pinned_llvm_tool() {
  local name="${1:?}" candidate path ver
  for candidate in "${name}-${PCSC_FIDO_LLVM_MAJOR}" "${name}"; do
    path="$(command -v "${candidate}" 2>/dev/null)" || continue
    ver="$("${path}" --version 2>/dev/null |
      sed -n 's/.*version \([0-9][0-9]*\)\..*/\1/p' | head -n1)"
    [[ ${ver} == "${PCSC_FIDO_LLVM_MAJOR}" ]] || continue
    readlink -f -- "${path}"
    return 0
  done
  return 1
}
