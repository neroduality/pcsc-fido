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

# Resolve markdownlint-cli: PATH, then hash-pinned npm bundle under .github/pinned/.
# Debian often ships /usr/bin/nodejs but not /usr/bin/node; npm wrappers need node.
#
# Usage (source from ci-lint.sh / install-linux-deps.sh):
#   pcsc_fido_ensure_markdownlint [repo_root]
#   pcsc_fido_run_markdownlint -- [markdownlint args...]
# On success sets PCSC_FIDO_MARKDOWNLINT_* and returns 0.

pcsc_fido_markdownlint_hint() {
  printf '%s\n' \
    'hint: Debian/Ubuntu: sudo apt-get install -y nodejs npm shfmt' \
    '      then: npm ci --prefix .github/pinned/markdownlint --omit=dev' \
    '      if env: node: No such file: ln -sf "$(command -v nodejs)" ~/.local/bin/node' \
    '      or:   sudo bash .github/scripts/install-linux-deps.sh' >&2
}

pcsc_fido_node_bin() {
  PCSC_FIDO_NODE_BIN=""
  if command -v node >/dev/null 2>&1; then
    PCSC_FIDO_NODE_BIN=node
    return 0
  fi
  if command -v nodejs >/dev/null 2>&1; then
    PCSC_FIDO_NODE_BIN=nodejs
    return 0
  fi
  return 1
}

pcsc_fido_markdownlint_js_ok() {
  local js_entry="$1"
  local node_bin="$2"

  [[ -f ${js_entry} ]] || return 1
  "${node_bin}" "${js_entry}" --version >/dev/null 2>&1
}

pcsc_fido_ensure_markdownlint() {
  local repo_root="${1:-}"
  local pinned_npm local_bin js_entry node_bin

  PCSC_FIDO_MARKDOWNLINT=""
  PCSC_FIDO_MARKDOWNLINT_JS=""
  PCSC_FIDO_MARKDOWNLINT_MODE=""

  if [[ -z ${repo_root} ]]; then
    repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
  fi

  pinned_npm="${repo_root}/.github/pinned/markdownlint"
  local_bin="${pinned_npm}/node_modules/.bin/markdownlint"
  js_entry="${pinned_npm}/node_modules/markdownlint-cli/markdownlint.js"

  if command -v markdownlint >/dev/null 2>&1 && markdownlint --version >/dev/null 2>&1; then
    PCSC_FIDO_MARKDOWNLINT=markdownlint
    PCSC_FIDO_MARKDOWNLINT_MODE=path
    return 0
  fi

  if command -v npm >/dev/null 2>&1 && [[ -f ${pinned_npm}/package-lock.json ]]; then
    # Local container CI runs install-linux-deps as root on a bind mount; npm ci there
    # root-owns node_modules and breaks host lint. Use host-installed bundle instead.
    if [[ $(id -u) -ne 0 || -z ${HOST_UID:-} ]]; then
      npm ci --prefix "${pinned_npm}" --omit=dev >/dev/null 2>&1 || true
    fi
  fi

  if ! pcsc_fido_node_bin; then
    return 1
  fi
  node_bin="${PCSC_FIDO_NODE_BIN}"

  if pcsc_fido_markdownlint_js_ok "${js_entry}" "${node_bin}"; then
    PCSC_FIDO_MARKDOWNLINT_MODE=js
    PCSC_FIDO_MARKDOWNLINT_JS="${js_entry}"
    return 0
  fi

  if [[ -x ${local_bin} ]] && head -n1 "${local_bin}" | grep -q '^#!.*node'; then
    if "${node_bin}" "${local_bin}" --version >/dev/null 2>&1; then
      PCSC_FIDO_MARKDOWNLINT="${local_bin}"
      PCSC_FIDO_MARKDOWNLINT_MODE=bin
      return 0
    fi
  fi

  return 1
}

pcsc_fido_run_markdownlint() {
  case "${PCSC_FIDO_MARKDOWNLINT_MODE:-}" in
    js)
      pcsc_fido_node_bin || return 1
      "${PCSC_FIDO_NODE_BIN}" "${PCSC_FIDO_MARKDOWNLINT_JS}" "$@"
      ;;
    path | bin)
      "${PCSC_FIDO_MARKDOWNLINT}" "$@"
      ;;
    *)
      return 1
      ;;
  esac
}
