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

# Resolve and optionally clone the org lint kit (neroduality/.github -> lint-c-cpp).
#
# Config (consumer .github/lint-c-cpp.yaml):
#   toolchain.lint_kit.repository  (default: neroduality/.github)
#   toolchain.lint_kit.ref         (default: main)
#   toolchain.lint_kit.path        (default: lint-c-cpp)
#
# Env overrides: LINT_KIT_REPOSITORY, LINT_KIT_REF, LINT_KIT_SUBPATH
set -euo pipefail

LINT_KIT_REPOSITORY="${LINT_KIT_REPOSITORY:-}"
LINT_KIT_REF="${LINT_KIT_REF:-}"
LINT_KIT_SUBPATH="${LINT_KIT_SUBPATH:-lint-c-cpp}"
LINT_KIT_CONFIG_LOADED=0

lint_kit_manifest_path() {
  local repo_root="${1:?}"
  printf '%s/.github/lint-c-cpp.yaml\n' "${repo_root}"
}

lint_kit_load_config() {
  local repo_root="${1:?}"
  if [[ ${LINT_KIT_CONFIG_LOADED} -eq 1 ]]; then
    return 0
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    printf 'error: python3 required to read lint kit config from .github/lint-c-cpp.yaml\n' >&2
    return 1
  fi
  local manifest
  manifest="$(lint_kit_manifest_path "${repo_root}")"
  if [[ ! -f ${manifest} ]]; then
    printf 'error: missing lint manifest: %s\n' "${manifest}" >&2
    return 1
  fi
  local loaded
  loaded="$(
    python3 - "${manifest}" <<'PY'
import os
import sys

try:
    import yaml
except ImportError as exc:
    raise SystemExit("error: PyYAML required to read lint kit config") from exc

manifest = sys.argv[1]
with open(manifest, encoding="utf-8") as handle:
    data = yaml.safe_load(handle) or {}
toolchain = data.get("toolchain", {})
block = toolchain.get("lint_kit", {}) if isinstance(toolchain, dict) else {}
repo = os.environ.get("LINT_KIT_REPOSITORY") or block.get("repository") or "neroduality/.github"
ref = os.environ.get("LINT_KIT_REF") or block.get("ref") or "main"
path = os.environ.get("LINT_KIT_SUBPATH") or block.get("path") or "lint-c-cpp"
for value in (repo, ref, path):
    if not isinstance(value, str) or not value.strip():
        raise SystemExit("error: lint kit config values must be non-empty strings")
print(repo.strip())
print(ref.strip())
print(path.strip().strip("/"))
PY
  )"
  LINT_KIT_REPOSITORY="$(printf '%s\n' "${loaded}" | sed -n '1p')"
  LINT_KIT_REF="$(printf '%s\n' "${loaded}" | sed -n '2p')"
  LINT_KIT_SUBPATH="$(printf '%s\n' "${loaded}" | sed -n '3p')"
  LINT_KIT_CONFIG_LOADED=1
}

lint_kit_org_dir() {
  local repo_root="${1:?}"
  printf '%s/.lint-kit-org\n' "${repo_root}"
}

lint_kit_root() {
  local repo_root="${1:?}"
  lint_kit_load_config "${repo_root}"
  printf '%s/%s\n' "$(lint_kit_org_dir "${repo_root}")" "${LINT_KIT_SUBPATH}"
}

lint_kit_clone_url() {
  lint_kit_load_config "${1:?}"
  printf 'https://github.com/%s.git\n' "${LINT_KIT_REPOSITORY}"
}

lint_kit_emit_github_output() {
  local repo_root="${1:?}"
  lint_kit_load_config "${repo_root}"
  if [[ -n ${GITHUB_OUTPUT:-} ]]; then
    {
      printf 'repository=%s\n' "${LINT_KIT_REPOSITORY}"
      printf 'ref=%s\n' "${LINT_KIT_REF}"
      printf 'path=%s\n' "${LINT_KIT_SUBPATH}"
    } >>"${GITHUB_OUTPUT}"
  fi
}

lint_kit_org_dir_writable() {
  local org_dir="${1:?}"
  [[ -d ${org_dir} ]] || return 0
  if [[ ! -w ${org_dir} ]]; then
    return 1
  fi
  local probe="${org_dir}/.lint-kit-write-probe.$$"
  if ! touch "${probe}" 2>/dev/null; then
    return 1
  fi
  rm -f "${probe}"
}

# Fix root-owned .lint-kit-org left by prior container runs (bind-mount mkdir/chown gaps).
lint_kit_prepare_writable() {
  local org_dir="${1:?}"
  local uid gid
  if lint_kit_org_dir_writable "${org_dir}"; then
    return 0
  fi
  if [[ ! -e ${org_dir} ]]; then
    mkdir -p "${org_dir}"
    lint_kit_org_dir_writable "${org_dir}" && return 0
  fi
  uid="$(id -u)"
  gid="$(id -g)"
  if [[ ${uid} -eq 0 && -n ${HOST_UID:-} ]]; then
    chown -R "${HOST_UID}:${HOST_GID:-${HOST_UID}}" "${org_dir}"
    lint_kit_org_dir_writable "${org_dir}" && return 0
  fi
  if [[ ${uid} -ne 0 ]] && command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    sudo chown -R "${uid}:${gid}" "${org_dir}"
    lint_kit_org_dir_writable "${org_dir}" && return 0
  fi
  return 1
}

lint_kit_ensure_cloned() {
  local repo_root="${1:?}"
  local org_dir kit_root url
  lint_kit_load_config "${repo_root}"
  org_dir="$(lint_kit_org_dir "${repo_root}")"
  kit_root="$(lint_kit_root "${repo_root}")"
  url="$(lint_kit_clone_url "${repo_root}")"

  if [[ -x ${kit_root}/lint-c-cpp.sh ]]; then
    return 0
  fi

  if ! lint_kit_prepare_writable "${org_dir}"; then
    printf 'error: lint kit missing and %s is not writable (cannot clone)\n' "${org_dir}" >&2
    printf 'hint: sudo chown -R %s:%s %s\n' "$(id -u)" "$(id -g)" "${org_dir}" >&2
    return 1
  fi

  printf 'Fetching lint kit %s@%s -> %s\n' "${LINT_KIT_REPOSITORY}" "${LINT_KIT_REF}" "${org_dir}" >&2
  rm -rf "${org_dir}"
  git clone --depth 1 --branch "${LINT_KIT_REF}" "${url}" "${org_dir}"
  if [[ ! -x ${kit_root}/lint-c-cpp.sh ]]; then
    printf 'error: lint kit missing lint-c-cpp.sh after clone: %s\n' "${kit_root}" >&2
    return 1
  fi
}

lint_kit_usage() {
  cat <<'EOF'
Usage: lint-kit-config.sh --github-output REPO_ROOT
       lint-kit-config.sh --ensure-cloned REPO_ROOT
       lint-kit-config.sh --prepare-writable REPO_ROOT
       lint-kit-config.sh --print-root REPO_ROOT

Reads toolchain.lint_kit from .github/lint-c-cpp.yaml (env overrides:
LINT_KIT_REPOSITORY, LINT_KIT_REF, LINT_KIT_SUBPATH).
EOF
}

if [[ ${BASH_SOURCE[0]} == "${0}" ]]; then
  case "${1:-}" in
    --github-output)
      lint_kit_emit_github_output "${2:?repo root required}"
      ;;
    --ensure-cloned)
      lint_kit_ensure_cloned "${2:?repo root required}"
      ;;
    --prepare-writable)
      lint_kit_prepare_writable "$(lint_kit_org_dir "${2:?repo root required}")" || exit 1
      ;;
    --print-root)
      lint_kit_root "${2:?repo root required}"
      ;;
    -h | --help)
      lint_kit_usage
      ;;
    *)
      lint_kit_usage >&2
      exit 1
      ;;
  esac
fi
