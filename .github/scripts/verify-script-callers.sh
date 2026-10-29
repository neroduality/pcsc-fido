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

# Every .github/scripts/*.sh must have an executing caller -- a non-comment
# `bash|sh|source <path>/NAME` line in the Makefile, make/, packaging/, a
# workflow, a Lima manifest, or another script. A script that is only
# mentioned in prose is either dead or an unenforced claim; delete it or wire
# it in.
#
# Usage (from pcsc-fido root): bash .github/scripts/verify-script-callers.sh
set -euo pipefail

repo_root="$(pwd)"
if [[ ! -d "${repo_root}/.github/scripts" ]] || [[ ! -f "${repo_root}/Makefile" ]]; then
  printf 'error: run from pcsc-fido root\n' >&2
  exit 1
fi

mapfile -t haystack < <(
  {
    printf '%s\n' "${repo_root}/Makefile"
    find "${repo_root}/make" "${repo_root}/packaging" "${repo_root}/.github/scripts" \
      "${repo_root}/.github/workflows" "${repo_root}/.github/lima" \
      -type f \( -name '*.sh' -o -name '*.yml' -o -name '*.yaml' -o -name 'post*' -o -name 'pre*' \) \
      2>/dev/null
  } | sort -u
)

missing=0
checked=0
for script in "${repo_root}"/.github/scripts/*.sh; do
  name="$(basename "${script}")"
  checked=$((checked + 1))
  # Executing reference: command word then an optional path prefix (may hold
  # quotes, $VARS, $(CURDIR)) ending in the script name; not on a comment line.
  # `(ba)?sh` covers `bash x.sh`, `sh x.sh` and `exec bash x.sh`. Both ends are
  # anchored: `publish x.sh` is not `sh x.sh`, and a caller of
  # uninstall-built-tree.sh does not count for install-built-tree.sh.
  if grep -lE "^([^#]*[^#[:alnum:]_./-])?((ba)?sh|source)[[:space:]]+([^[:space:]]*[/\"'])?${name//./\\.}([[:space:]\"']|\$)" \
    "${haystack[@]}" 2>/dev/null | grep -vqx "${script}"; then
    continue
  fi
  printf 'no executing caller: .github/scripts/%s\n' "${name}"
  missing=$((missing + 1))
done

if [[ ${missing} -ne 0 ]]; then
  printf 'error: %d of %d scripts have no caller (wire them in or delete them)\n' \
    "${missing}" "${checked}" >&2
  exit 1
fi
printf 'script callers: OK (%d scripts, each invoked from Makefile/workflow/script)\n' "${checked}"
