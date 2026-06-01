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

# Typo detection via codespell — no hunspell / project wordlist maintenance.
#
# codespell flags common misspellings (teh, recieve, …), not unknown vocabulary.
# Markdown code fences and HTML license comments are stripped; URLs and hex literals
# are ignored so technical docs stay low-noise without a custom dictionary.
#
# Requires codespell >= 2.4.0 (--ignore-multiline-regex). Distro packages are often
# older (Ubuntu 24.04 ships 2.2.x); install-linux-deps.sh upgrades via pip when needed.
#
# Usage:
#   bash .github/linters/helper-codespell.sh [paths…]
#   bash .github/linters/helper-codespell.sh --check-config
#
# Sourceable helpers (install-linux-deps.sh):
#   pcsc_fido_ensure_codespell
set -euo pipefail

pcsc_fido_codespell_hint() {
  printf '%s\n' \
    'hint: bash .github/scripts/install-linux-deps.sh' \
    '      or: python3 -m pip install --require-hashes -r .github/pinned/codespell/requirements.txt --user' >&2
}

pcsc_fido_codespell_supports_multiline_regex() {
  command -v codespell >/dev/null 2>&1 &&
    codespell --help 2>&1 | grep -qF -- '--ignore-multiline-regex'
}

pcsc_fido_ensure_codespell() {
  local repo_root linter_dir pinned_req
  local -a pip_args

  if pcsc_fido_codespell_supports_multiline_regex; then
    return 0
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    return 1
  fi

  linter_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
  repo_root="$(cd -- "$linter_dir/../.." && pwd)"
  pinned_req="${repo_root}/.github/pinned/codespell/requirements.txt"
  if [[ ! -f ${pinned_req} ]]; then
    return 1
  fi

  pip_args=(
    --ignore-installed
    --break-system-packages
    --require-hashes
    -r "${pinned_req}"
  )
  if [[ ${EUID} -ne 0 ]]; then
    pip_args=(--user "${pip_args[@]}")
    mkdir -p "${HOME}/.local/bin"
    export PATH="${HOME}/.local/bin:${PATH}"
  fi

  if ! python3 -m pip install "${pip_args[@]}" >/dev/null 2>&1; then
    return 1
  fi

  pcsc_fido_codespell_supports_multiline_regex
}

pcsc_fido_codespell_main() {
  local check_config linter_dir repo_root
  local -a targets codespell_args

  usage() {
    cat <<'EOF'
Usage: .github/linters/helper-codespell.sh [OPTIONS] [PATH …]

Run codespell with repository-standard filters. Paths default to tracked Markdown
under the repo root when none are given.

Options:
  --check-config   Print effective codespell argv and exit 0
  -h, --help       Help

EOF
  }

  linter_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
  repo_root="$(cd -- "$linter_dir/../.." && pwd)"

  # License HTML blocks and fenced code (inline `code` stays checked — usually prose).
  # shellcheck disable=SC2016
  local IGNORE_MULTILINE_REGEX='(?s)<!--.*?-->|\`\`\`.*?(\`\`\`|$)'

  # URLs, hex, email-ish tokens, long uppercase acronyms, snake_case identifiers.
  # shellcheck disable=SC2016
  local IGNORE_REGEX='(\bhttps?://\S+\b|\b0x[0-9A-Fa-f]+\b|\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b|\b[A-Z][A-Z0-9_]{2,}\b|\b[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b)'

  local SKIP_GLOBS='*.png,*.jpg,*.jpeg,*.gif,*.webp,*.svg,*.ico,*.bin,*.hex,*.pdf,build,build-*,dist,third-party,_deps,node_modules,.git'
  local CODESPELL_BUILTINS='clear,rare'

  codespell_args=(
    --builtin "$CODESPELL_BUILTINS"
    --ignore-multiline-regex "$IGNORE_MULTILINE_REGEX"
    --ignore-regex "$IGNORE_REGEX"
    -S "$SKIP_GLOBS"
    -q 2
  )

  default_targets() {
    local -a out=(README.md INSTALLATION.md RELEASE.md .github/release-notes.md)
    shopt -s nullglob
    out+=("$repo_root"/docs/*.md)
    if [[ -d $repo_root/tutorials ]]; then
      out+=("$repo_root"/tutorials/*.md)
      out+=("$repo_root"/tutorials/*/*.md)
    fi
    if [[ -f $repo_root/tests/README.md ]]; then
      out+=("$repo_root/tests/README.md")
    fi
    printf '%s\n' "${out[@]}"
  }

  check_config=0
  targets=()
  while (($# > 0)); do
    case "$1" in
      --check-config) check_config=1 ;;
      -h | --help)
        usage
        exit 0
        ;;
      --)
        shift
        targets+=("$@")
        break
        ;;
      *)
        targets+=("$1")
        ;;
    esac
    shift
  done

  if ((${#targets[@]} == 0)); then
    mapfile -t targets < <(default_targets)
  fi

  if ((${#targets[@]} == 0)); then
    printf 'skip: no spell-check targets\n' >&2
    exit 0
  fi

  if ! command -v codespell >/dev/null 2>&1; then
    printf 'error: codespell not found\n' >&2
    pcsc_fido_codespell_hint
    exit 1
  fi

  if ! pcsc_fido_codespell_supports_multiline_regex; then
    printf 'error: codespell >= 2.4.0 required (--ignore-multiline-regex); found %s\n' \
      "$(codespell --version 2>/dev/null | head -n1 || echo unknown)" >&2
    pcsc_fido_codespell_hint
    exit 1
  fi

  if ((check_config == 1)); then
    printf 'codespell'
    printf ' %q' "${codespell_args[@]}"
    printf ' %q' "${targets[@]}"
    printf '\n'
    exit 0
  fi

  cd "$repo_root"
  exec codespell "${codespell_args[@]}" "${targets[@]}"
}

if [[ ${BASH_SOURCE[0]} == "${0}" ]]; then
  pcsc_fido_codespell_main "$@"
fi
