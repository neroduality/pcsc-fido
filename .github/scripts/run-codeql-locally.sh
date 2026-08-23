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

# Reproduce GitHub Actions CodeQL locally: isolated work tree + debian:sid-slim
# + CodeQL database create around .github/scripts/ci-codeql-build.sh.
#
# Paths stay under build/ (make clean removes them) and stay disjoint so the
# traced CMake wipe cannot delete the CLI or database (matches GHA: tools/DB
# outside the project build tree).
set -euo pipefail

usage() {
  cat <<'USAGE'
Reproduce CodeQL locally (mirrors .github/workflows/codeql.yml).

Usage:
  bash .github/scripts/run-codeql-locally.sh [options]
  make codeql-local

Options:
  --db-only       Create the CodeQL database only (skip analyze)
  --no-summary    Do not print SARIF summary after analyze
  --open          Open SARIF on the host after the container exits
  --verify-gate   Exit non-zero on CodeQL error-level findings
  -h, --help      Help

Environment:
  CONTAINER_ENGINE              docker (default) or podman
  CODEQL_IMAGE                  Container image (default: debian:sid-slim digest)
  CI_PLATFORM                   Container platform (default: linux/amd64)
  CODEQL_CLI_VERSION            CodeQL CLI version (default: v2.26.3)
  CODEQL_QUERY_SUITE            Optional path or pack:suite override
  CODEQL_SUITE_FILE             Suite basename under cpp-queries (default: cpp-security-and-quality.qls)
  CODEQL_PACK_SCOPE             Pack to download (default: codeql/cpp-queries)
  PCSC_FIDO_CI_LOCAL_WORK_ROOT  Isolated work tree (default: build/codeql-local-work)
  PCSC_FIDO_CI_LOCAL_KEEP_WORK  Set to 1 to keep the work tree after exit

Layout under the work tree (all under build/; cleared by make clean):
  build/codeql-cli/     CodeQL CLI zip + extract (not wiped by traced build)
  build/codeql-cmake/   CMake tree for the traced build (ci-codeql-build.sh)
  build/codeql/         Database + SARIF results
USAGE
}

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"

# shellcheck source=helper-container-bind-mount.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/helper-container-bind-mount.sh"

pcsc_fido_container_engine() {
  printf '%s' "${CONTAINER_ENGINE:-docker}"
}

pcsc_fido_require_container_engine() {
  local engine
  engine="$(pcsc_fido_container_engine)"
  if ! command -v "${engine}" >/dev/null 2>&1; then
    printf 'error: %s not found (install docker or podman, or set CONTAINER_ENGINE)\n' \
      "${engine}" >&2
    return 1
  fi
  printf '%s' "${engine}"
}

print_codeql_sarif_summary() {
  local sarif="$1"
  printf '\n-- Results (SARIF) --\n'
  printf 'File: %s\n' "${sarif}"
  if [[ ! -s ${sarif} ]]; then
    printf 'warning: SARIF missing or empty\n' >&2
    return 0
  fi
  if ! command -v jq >/dev/null 2>&1; then
    printf 'hint: install jq for an alert summary.\n' >&2
    return 0
  fi
  local total limit
  total="$(jq '[.runs[].results[]] | length' "${sarif}")"
  printf 'Total findings: %s\n' "${total}"
  if [[ ${total} != "0" ]]; then
    printf '\nBy severity:\n'
    jq -r '[.runs[].results[] | (.level // "warning")] | group_by(.) | map("  \(.[0]): \(length)") | .[]' "${sarif}"
    printf '\nBy rule (top 25):\n'
    jq -r '[.runs[].results[] | .ruleId // "(no ruleId)"] | group_by(.) | map({id: .[0], n: length}) | sort_by(-.n) | .[:25] | .[] | "  \(.n)\t\(.id)"' "${sarif}"
    limit="${CODEQL_SARIF_LIST_LIMIT:-40}"
    [[ ${limit} =~ ^[0-9]+$ ]] || limit="40"
    printf '\nFindings (first %s):\n' "${limit}"
    jq -r --argjson lim "${limit}" '
      [.runs[].results[] | . as $r | {
        rule: ($r.ruleId // "?"),
        msg: (($r.message.text // "") | gsub("\\s+"; " ") | if length > 160 then .[0:157] + "..." else . end),
        uri: (($r.locations[0].physicalLocation.artifactLocation.uri // "?")),
        line: ($r.locations[0].physicalLocation.region.startLine // empty)
      }]
      | .[:$lim][]
      | "[\(.rule)] \(.uri)" + (if .line != null and .line != "" then ":\(.line)" else "" end) + "\n  \(.msg)\n"
    ' "${sarif}"
  fi
}

install_codeql_container_prereqs() {
  export DEBIAN_FRONTEND=noninteractive
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y --no-install-recommends ca-certificates curl git jq unzip
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y --setopt=install_weak_deps=False ca-certificates curl git jq unzip
    dnf clean all
  else
    printf 'error: need apt-get or dnf in CodeQL container\n' >&2
    exit 1
  fi
}

resolve_codeql() {
  # Cold container only -- no host CLI (matches a clean GHA runner tool cache).
  if [[ -n ${CODEQL_DIST:-} ]]; then
    printf 'error: CODEQL_DIST is not allowed in codeql-local (cold container only)\n' >&2
    exit 1
  fi
  if command -v codeql >/dev/null 2>&1; then
    printf 'error: host/path codeql is not allowed in codeql-local (cold container only)\n' >&2
    exit 1
  fi

  local version cache asset zip_path checksum_path expected_hash actual_hash extract_root
  # Must track registry packs (cpp-queries@1.8.1 needs CLI 2.26.3 OCI manifest support).
  version="${CODEQL_CLI_VERSION:-v2.26.3}"
  # Sibling of build/codeql-cmake and build/codeql -- never under a path the traced
  # build rm -rf's (GitHub database-create: keep tools/DB out of the build wipe dir).
  cache="${CODEQL_CACHE:-${PCSC_FIDO_ROOT}/build/codeql-cli}"
  asset="codeql-linux64.zip"
  zip_path="${cache}/${version}/${asset}"
  checksum_path="${zip_path}.checksum.txt"
  mkdir -p "$(dirname -- "${zip_path}")"

  if [[ ! -f ${zip_path} ]]; then
    printf '\n-- Downloading CodeQL CLI %s (%s) --\n' "${version}" "${asset}" >&2
    curl -fsSL --retry 3 --retry-delay 2 \
      -o "${zip_path}.part" \
      "https://github.com/github/codeql-cli-binaries/releases/download/${version}/${asset}"
    curl -fsSL --retry 3 --retry-delay 2 \
      -o "${checksum_path}" \
      "https://github.com/github/codeql-cli-binaries/releases/download/${version}/${asset}.checksum.txt"
    expected_hash="$(awk '{print $1}' "${checksum_path}")"
    actual_hash="$(sha256sum "${zip_path}.part" | awk '{print $1}')"
    if [[ ${actual_hash} != "${expected_hash}" ]]; then
      rm -f "${zip_path}.part" "${checksum_path}"
      printf 'error: SHA256 mismatch for %s\n' "${asset}" >&2
      exit 1
    fi
    mv -f "${zip_path}.part" "${zip_path}"
  fi

  extract_root="${cache}/${version}/extract-${asset%.zip}"
  if [[ ! -x ${extract_root}/codeql/codeql ]]; then
    printf '\n-- Extracting CodeQL CLI --\n' >&2
    rm -rf "${extract_root}"
    mkdir -p "${extract_root}"
    unzip -q "${zip_path}" -d "${extract_root}"
  fi
  printf '%s\n' "${extract_root}/codeql/codeql"
}

ensure_cpp_query_packs() {
  local codeql_bin="$1"
  local pack_scope="${CODEQL_PACK_SCOPE:-codeql/cpp-queries}"
  # Cold container: packs land in $HOME/.codeql (ephemeral; no host mount).
  printf '\n-- CodeQL pack download (%s) --\n' "${pack_scope}" >&2
  "${codeql_bin}" pack download "${pack_scope}" >&2
}

resolve_query_suite() {
  # Prefer an explicit filesystem path; otherwise resolve the suite file from the
  # downloaded pack (pack:suite notation needs packs present -- download first).
  if [[ -n ${CODEQL_QUERY_SUITE:-} && -f ${CODEQL_QUERY_SUITE} ]]; then
    printf '%s\n' "${CODEQL_QUERY_SUITE}"
    return 0
  fi
  if [[ -n ${CODEQL_QUERY_SUITE:-} && ${CODEQL_QUERY_SUITE} == /* ]]; then
    printf 'error: CODEQL_QUERY_SUITE=%s is not a readable file\n' "${CODEQL_QUERY_SUITE}" >&2
    exit 1
  fi
  local suite_file hits hit
  suite_file="${CODEQL_SUITE_FILE:-cpp-security-and-quality.qls}"
  if [[ -n ${CODEQL_QUERY_SUITE:-} && ${CODEQL_QUERY_SUITE} == *'/codeql-suites/'* ]]; then
    suite_file="${CODEQL_QUERY_SUITE##*/}"
  fi
  hits="$(find "${HOME}/.codeql/packages/codeql/cpp-queries" -path "*/codeql-suites/${suite_file}" 2>/dev/null | sort -V)"
  hit="$(printf '%s\n' "${hits}" | tail -n1)"
  if [[ -z ${hit} || ! -f ${hit} ]]; then
    printf 'error: could not find codeql-suites/%s under ~/.codeql/packages (run pack download)\n' \
      "${suite_file}" >&2
    exit 1
  fi
  printf '%s\n' "${hit}"
}

codeql_container_entry() {
  local -a entry_args=("$@")
  PCSC_FIDO_ROOT="${PCSC_FIDO_ROOT:-$(pwd)}"
  export PCSC_FIDO_ROOT
  if [[ ! -f ${PCSC_FIDO_ROOT}/CMakeLists.txt || ! -d ${PCSC_FIDO_ROOT}/src ]]; then
    printf 'error: PCSC_FIDO_ROOT must point at pcsc-fido root\n' >&2
    exit 1
  fi

  # shellcheck source=helper-container-bind-mount.sh
  # shellcheck disable=SC1091
  source "${PCSC_FIDO_ROOT}/.github/scripts/helper-container-bind-mount.sh"

  # Root -> install deps -> prepare/chown -> drop to HOST_UID (nero-nfc CodeQL recipe).
  if [[ $(id -u) -eq 0 && -n ${HOST_UID:-} && ${PCSC_FIDO_CI_AS_USER:-0} != 1 ]]; then
    install_codeql_container_prereqs
    AUTO_INSTALL_LINUX_DEPS=1 INSTALL_DEPS=1 PCSC_FIDO_DEPS_SCOPE=build \
      bash "${PCSC_FIDO_ROOT}/.github/scripts/install-linux-deps.sh"
    pcsc_fido_prepare_bind_mount_paths "${PCSC_FIDO_ROOT}"
    local ci_home codeql_cache
    ci_home="${PCSC_FIDO_CI_HOME:-/tmp/pcsc-fido-ci}"
    codeql_cache="${CODEQL_CACHE:-${PCSC_FIDO_ROOT}/build/codeql-cli}"
    mkdir -p "${ci_home}" "${codeql_cache}" "${PCSC_FIDO_ROOT}/build/codeql" \
      "${PCSC_FIDO_ROOT}/build/codeql-cmake"
    chown -R "${HOST_UID}:${HOST_GID:-${HOST_UID}}" "${ci_home}" "${codeql_cache}" \
      "${PCSC_FIDO_ROOT}/build/codeql" "${PCSC_FIDO_ROOT}/build/codeql-cmake"
    export CODEQL_CACHE="${codeql_cache}"
    pcsc_fido_require_drop_to_host_user \
      bash "${PCSC_FIDO_ROOT}/.github/scripts/run-codeql-locally.sh" \
      --container-entry "${entry_args[@]}"
  fi

  pcsc_fido_refuse_root_bind_mount_writes

  local db_only=0 verify_gate=0 summarize_sarif open_sarif query_suite
  summarize_sarif="${CODEQL_SUMMARIZE_SARIF:-1}"
  open_sarif="${CODEQL_OPEN_SARIF:-0}"
  query_suite="${CODEQL_QUERY_SUITE:-}"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --db-only) db_only=1 ;;
      --verify-gate) verify_gate=1 ;;
      --no-summary) summarize_sarif=0 ;;
      --open) open_sarif=1 ;;
      -h | --help)
        usage
        exit 0
        ;;
      *)
        printf 'error: unknown option %q\n' "$1" >&2
        exit 1
        ;;
    esac
    shift
  done
  export CODEQL_OPEN_SARIF="${open_sarif}"
  if [[ -n ${query_suite} ]]; then
    export CODEQL_QUERY_SUITE="${query_suite}"
  fi

  local codeql_bin db_path sarif_path build_cmd suite_path
  codeql_bin="$(resolve_codeql)"
  db_path="${CODEQL_DB_PATH:-${PCSC_FIDO_ROOT}/build/codeql/cpp-db}"
  sarif_path="${CODEQL_SARIF_PATH:-${PCSC_FIDO_ROOT}/build/codeql/results.sarif}"
  build_cmd="env PCSC_FIDO_ROOT=${PCSC_FIDO_ROOT} CODEQL_INSTALL_LINUX_DEPS=0 bash ${PCSC_FIDO_ROOT}/.github/scripts/ci-codeql-build.sh"

  rm -rf "${db_path}"
  mkdir -p "$(dirname -- "${db_path}")" "$(dirname -- "${sarif_path}")"

  printf '\n-- CodeQL database create -> %s --\n' "${db_path}"
  "${codeql_bin}" database create "${db_path}" \
    --language=cpp \
    --overwrite \
    --threads=0 \
    --source-root="${PCSC_FIDO_ROOT}" \
    --command="${build_cmd}"

  if [[ ${db_only} -eq 1 ]]; then
    printf '\n-- Database ready (--db-only); skipping analyze --\n'
    exit 0
  fi

  ensure_cpp_query_packs "${codeql_bin}"
  suite_path="$(resolve_query_suite)"

  printf '\n-- CodeQL analyze -> %s --\n' "${sarif_path}"
  printf 'Query suite: %s\n' "${suite_path}"
  "${codeql_bin}" database analyze "${db_path}" \
    --threads=0 \
    --sarif-category=cpp \
    --format=sarif-latest \
    --output="${sarif_path}" \
    "${suite_path}"

  if [[ ${summarize_sarif} == "1" ]]; then
    print_codeql_sarif_summary "${sarif_path}"
  fi

  if [[ ${verify_gate} -eq 1 ]]; then
    local fail_level count
    fail_level="${CODEQL_VERIFY_FAIL_LEVEL:-error}"
    count="$(jq --arg lvl "${fail_level}" \
      '[.runs[].results[] | select((.level // "warning") == $lvl)] | length' "${sarif_path}")"
    if [[ ${count} != "0" ]]; then
      printf 'error: CodeQL verify gate: %s %s-level finding(s)\n' \
        "${count}" "${fail_level}" >&2
      exit 1
    fi
    printf 'CodeQL verify gate: OK (0 %s-level findings)\n' "${fail_level}"
  fi
}

if [[ ${1:-} == "--container-entry" ]]; then
  shift
  codeql_container_entry "$@"
  exit 0
fi

DB_ONLY=0
VERIFY_GATE=0
SUMMARIZE_SARIF="${CODEQL_SUMMARIZE_SARIF:-1}"
OPEN_SARIF="${CODEQL_OPEN_SARIF:-0}"
FORWARD_ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --db-only)
      DB_ONLY=1
      FORWARD_ARGS+=("$1")
      ;;
    --verify-gate)
      VERIFY_GATE=1
      FORWARD_ARGS+=("$1")
      ;;
    --no-summary)
      SUMMARIZE_SARIF=0
      FORWARD_ARGS+=("$1")
      ;;
    --open)
      OPEN_SARIF=1
      FORWARD_ARGS+=("$1")
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      printf 'error: unknown option %q\n' "$1" >&2
      usage >&2
      exit 1
      ;;
  esac
  shift
done

if [[ ! -f ${SOURCE_ROOT}/CMakeLists.txt || ! -d ${SOURCE_ROOT}/src ]]; then
  printf 'error: unexpected pcsc-fido layout under %s\n' "${SOURCE_ROOT}" >&2
  exit 1
fi

if ! pcsc_fido_require_container_engine >/dev/null; then
  exit 1
fi
if ! command -v rsync >/dev/null 2>&1; then
  printf 'error: rsync required to seed CodeQL work tree\n' >&2
  exit 1
fi

if ! [[ -v CI_PLATFORM ]]; then
  export CI_PLATFORM=linux/amd64
fi
PLATFORM_ARGS=()
pcsc_fido_load_ci_platform_args

_CI_LOCAL_WORK_ROOT_TO_CLEAN=""
codeql_local_cleanup_worktree() {
  local root="${_CI_LOCAL_WORK_ROOT_TO_CLEAN}"
  [[ -n ${root} ]] || return 0
  if [[ ${PCSC_FIDO_CI_LOCAL_KEEP_WORK:-0} == 1 ]]; then
    printf -- '-- codeql-local: keeping work tree %s (PCSC_FIDO_CI_LOCAL_KEEP_WORK=1) --\n' "${root}" >&2
    return 0
  fi
  if [[ ! -d ${root} || ${root} == "${SOURCE_ROOT}" ]]; then
    return 0
  fi
  printf -- '-- codeql-local: removing work tree %s --\n' "${root}" >&2
  rm -rf "${root}"
}

WORK_ROOT="${PCSC_FIDO_CI_LOCAL_WORK_ROOT:-${SOURCE_ROOT}/build/codeql-local-work}"
rm -rf "${WORK_ROOT}"
mkdir -p "${WORK_ROOT}"
printf -- '-- codeql-local: seeding isolated work tree %s --\n' "${WORK_ROOT}"
rsync -a --delete \
  --exclude '/build/' \
  --exclude '/build-*/' \
  --exclude '/dist/' \
  --exclude '/.lint-kit-org/' \
  --exclude '/.fuzz/' \
  "${SOURCE_ROOT}/" "${WORK_ROOT}/"
_CI_LOCAL_WORK_ROOT_TO_CLEAN="${WORK_ROOT}"
trap codeql_local_cleanup_worktree EXIT

CODEQL_IMAGE="${CODEQL_IMAGE:-debian:sid-slim@sha256:54f7a23f03be1e9fe2849c61a7455588ea29b84c1659440f8ece2aea4c9871af}"
mkdir -p "${SOURCE_ROOT}/build/codeql"

printf '\n-- CodeQL: container %s (cold; no host CodeQL caches) --\n' "${CODEQL_IMAGE}"
# Default restore paths (build, .lint-kit-org, …) like nero-nfc codeql-local.
pcsc_fido_run_bind_mount_container \
  -- \
  "${PLATFORM_ARGS[@]}" \
  -v "${WORK_ROOT}:/src" \
  -w /src \
  -e "PCSC_FIDO_ROOT=/src" \
  -e "HOST_UID=$(id -u)" \
  -e "HOST_GID=$(id -g)" \
  -e "CODEQL_CLI_VERSION=${CODEQL_CLI_VERSION:-v2.26.3}" \
  -e "CODEQL_QUERY_SUITE=${CODEQL_QUERY_SUITE:-}" \
  -e "CODEQL_SUMMARIZE_SARIF=${SUMMARIZE_SARIF}" \
  -e "CODEQL_OPEN_SARIF=0" \
  -e "CODEQL_SARIF_LIST_LIMIT=${CODEQL_SARIF_LIST_LIMIT:-}" \
  -e "CODEQL_VERIFY_FAIL_LEVEL=${CODEQL_VERIFY_FAIL_LEVEL:-}" \
  "${CODEQL_IMAGE}" \
  bash /src/.github/scripts/run-codeql-locally.sh --container-entry "${FORWARD_ARGS[@]}"

if [[ -d ${WORK_ROOT}/build/codeql ]]; then
  mkdir -p "${SOURCE_ROOT}/build/codeql"
  cp -a "${WORK_ROOT}/build/codeql/." "${SOURCE_ROOT}/build/codeql/"
  printf -- '-- codeql-local: copied results -> %s/build/codeql/ --\n' "${SOURCE_ROOT}" >&2
fi

SARIF_PATH="${SOURCE_ROOT}/build/codeql/results.sarif"
if [[ ${OPEN_SARIF} == "1" && -s ${SARIF_PATH} ]]; then
  case "$(uname -s)" in
    Linux)
      if command -v xdg-open >/dev/null 2>&1; then
        xdg-open "${SARIF_PATH}" >/dev/null 2>&1 &
      fi
      ;;
    Darwin)
      if command -v open >/dev/null 2>&1; then
        open "${SARIF_PATH}"
      fi
      ;;
  esac
fi

if [[ ${VERIFY_GATE} -eq 1 && ${DB_ONLY} -eq 0 ]]; then
  printf 'CodeQL host verify gate completed in container.\n'
fi

printf '\n-- CodeQL local finished --\n'
