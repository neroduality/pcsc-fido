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

# Umbrella: reproduce GitHub Actions checks locally (``make ci-suite``).
#
# Usage:
#   bash .github/scripts/run-local-ci-suite.sh --quick
#   bash .github/scripts/run-local-ci-suite.sh --main --coverage
#   bash .github/scripts/run-local-ci-suite.sh --release-arch riscv64
#
# Standalone pieces (also invoked by presets above):
#   run-local-spec-coverage.sh      checklist symbol gate
#   run-local-container-matrix.sh   Debian + Fedora Debug tests + scan-build
#   run-local-line-coverage.sh      gcov/lcov HTML
#   run-local-release-packages.sh   Release .deb/.rpm into dist/
#   run-local-openssf.sh            OpenSSF Scorecard
#   run-local-security-suite.sh     supply-chain / secret scans (``make security-lint``)
#
set -euo pipefail

usage() {
  cat <<'EOF'
Local CI suite — reproduces GitHub Actions checks on your machine.

Usage:
  bash .github/scripts/run-local-ci-suite.sh [options]

Presets:
  --quick            Spec coverage + lint (Main CI host jobs; default)
  --main             --quick + container matrix (Debian + Fedora) + scan-build
  --full             --main + line coverage + release smoke (.deb amd64)

Optional add-ons (combine with presets):
  --coverage         gcov/lcov line coverage (build/coverage-html/)
  --release          Release packages (--quick-release unless --all-release or --release-arch)
  --quick-release    Native amd64 .deb only (Release workflow smoke)
  --all-release      Native amd64 deb+rpm + all cross deb+rpm (slow)
  --release-arch A   One release port: amd64|arm64 (native deb+rpm) or armhf|ppc64el|riscv64|s390x (cross deb+rpm)
                       Clears dist/ first (except --all / --all-release). Native RPM: *.x86_64.rpm
  --security         run-local-security-suite.sh --quick
  --openssf          OpenSSF Scorecard after container matrix

Skip flags:
  --skip-spec        Skip spec-coverage gate
  --skip-lint        Skip make lint / ci-lint.sh --strict-tools
  --skip-containers  Skip Debian/Fedora container matrix
  --skip-openssf     Skip OpenSSF Scorecard

Environment:
  CONTAINER_ENGINE, CI_PLATFORM (auto arm64 on Pi; linux/amd64 on x86_64), PCSC_FIDO_LOCAL_CI_KEEP_BUILDS
  (passed through to child scripts)

Standalone scripts (same directory):
  run-local-spec-coverage.sh      docs/spec-coverage.yaml gate
  run-local-container-matrix.sh     container matrix only
  run-local-line-coverage.sh        line coverage only
  run-local-release-packages.sh     release packages only
  run-local-openssf.sh              Scorecard only
  run-local-security-suite.sh       security suite only

Script naming (see .github/scripts/ and .github/linters/README.md):
  run-local-*   host entry points (``make ci-suite``, security-lint, etc.)
  ci-*          shared GitHub Actions / container steps and lint gate
  helper-*      sourced libraries and lint sub-steps
  install-*     deps and post-install of built tree
  release-*     .deb/.rpm packaging

make ci-suite [CI_SUITE_FLAGS="..."]

Presets:
  make ci-suite                                    # CI_SUITE_FLAGS=--quick
  make ci-suite CI_SUITE_FLAGS=--main
  make ci-suite CI_SUITE_FLAGS=--full

Add-ons (combine):
  make ci-suite CI_SUITE_FLAGS="--coverage"
  make ci-suite CI_SUITE_FLAGS="--release"
  make ci-suite CI_SUITE_FLAGS="--all-release"
  make ci-suite CI_SUITE_FLAGS="--release-arch riscv64"
  make ci-suite CI_SUITE_FLAGS="--security"
  make ci-suite CI_SUITE_FLAGS="--openssf"
  make ci-suite CI_SUITE_FLAGS="--main --coverage --release"

EOF
}

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=helper-cross-targets.sh
source "${SCRIPT_DIR}/helper-cross-targets.sh"
# shellcheck source=helper-container-bind-mount.sh
source "${SCRIPT_DIR}/helper-container-bind-mount.sh"

export AUTO_INSTALL_LINUX_DEPS="${AUTO_INSTALL_LINUX_DEPS:-0}"

RUN_SPEC=0
RUN_LINT=0
RUN_CONTAINERS=0
RUN_COVERAGE=0
RUN_RELEASE=0
RELEASE_MODE=""
RUN_SECURITY=0
RUN_OPENSSF=0
SKIP_OPENSSF=0

if [[ $# -eq 0 ]]; then
  set -- --quick
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --quick)
      RUN_SPEC=1
      RUN_LINT=1
      RUN_CONTAINERS=0
      ;;
    --main)
      RUN_SPEC=1
      RUN_LINT=1
      RUN_CONTAINERS=1
      ;;
    --full)
      RUN_SPEC=1
      RUN_LINT=1
      RUN_CONTAINERS=1
      RUN_COVERAGE=1
      RUN_RELEASE=1
      RELEASE_MODE=quick
      ;;
    --coverage)
      RUN_COVERAGE=1
      ;;
    --release)
      RUN_RELEASE=1
      if [[ $# -ge 2 && ${2:0:1} != '-' ]] && pcsc_fido_is_release_arch "$2"; then
        RELEASE_MODE="$2"
        shift
      else
        RELEASE_MODE=quick
      fi
      ;;
    --quick-release)
      RUN_RELEASE=1
      RELEASE_MODE=quick
      ;;
    --all-release)
      RUN_RELEASE=1
      RELEASE_MODE=all
      ;;
    --release-arch)
      RUN_RELEASE=1
      RELEASE_MODE="${2:-}"
      if [[ -z ${RELEASE_MODE} ]]; then
        printf 'error: --release-arch requires an architecture\n' >&2
        usage >&2
        exit 2
      fi
      if ! pcsc_fido_is_release_arch "${RELEASE_MODE}"; then
        printf 'error: unsupported release architecture: %s\n' "${RELEASE_MODE}" >&2
        printf 'hint: native amd64|arm64; cross armhf|ppc64el|riscv64|s390x\n' >&2
        exit 2
      fi
      shift
      ;;
    --security)
      RUN_SECURITY=1
      ;;
    --openssf)
      RUN_OPENSSF=1
      ;;
    --skip-spec) RUN_SPEC=0 ;;
    --skip-lint) RUN_LINT=0 ;;
    --skip-containers) RUN_CONTAINERS=0 ;;
    --skip-openssf) SKIP_OPENSSF=1 ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      printf 'error: unknown option %q\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

cd "${REPO_ROOT}"

if [[ ${RUN_SPEC} -eq 1 ]]; then
  printf '\n── Local CI: spec coverage ──\n'
  bash "${SCRIPT_DIR}/run-local-spec-coverage.sh"
fi

if [[ ${RUN_LINT} -eq 1 ]]; then
  printf '\n── Local CI: lint (strict tools) ──\n'
  bash "${REPO_ROOT}/.github/linters/ci-lint.sh" --strict-tools
fi

if [[ ${RUN_CONTAINERS} -eq 1 ]]; then
  printf '\n── Local CI: container matrix ──\n'
  ci_args=(--all)
  if [[ ${SKIP_OPENSSF} -eq 1 && ${RUN_OPENSSF} -eq 0 ]]; then
    ci_args+=(--skip-openssf)
  elif [[ ${RUN_OPENSSF} -eq 1 ]]; then
    SKIP_OPENSSF=0
  else
    ci_args+=(--skip-openssf)
  fi
  bash "${SCRIPT_DIR}/run-local-container-matrix.sh" "${ci_args[@]}"
  pcsc_fido_restore_bind_mount_ownership
elif [[ ${RUN_OPENSSF} -eq 1 && ${SKIP_OPENSSF} -eq 0 ]]; then
  bash "${SCRIPT_DIR}/run-local-openssf.sh"
fi

if [[ ${RUN_COVERAGE} -eq 1 ]]; then
  printf '\n── Local CI: line coverage ──\n'
  bash "${SCRIPT_DIR}/run-local-line-coverage.sh"
fi

if [[ ${RUN_RELEASE} -eq 1 ]]; then
  printf '\n── Local CI: release packages ──\n'
  if [[ ${RELEASE_MODE} == all ]]; then
    printf 'note: --all-release runs 10 container package builds (native deb+rpm + 4 cross × deb+rpm).\n'
    printf '      Each step can take several minutes; native Release builds also run ctest.\n'
  elif pcsc_fido_is_release_arch "${RELEASE_MODE}"; then
    if pcsc_fido_is_cross_arch "${RELEASE_MODE}"; then
      printf 'note: --release-arch %s runs cross deb + rpm container builds.\n' "${RELEASE_MODE}"
    else
      printf 'note: --release-arch %s runs native deb + rpm container builds (amd64 only on typical hosts).\n' \
        "${RELEASE_MODE}"
    fi
  fi
  case "${RELEASE_MODE}" in
    all)
      bash "${SCRIPT_DIR}/run-local-release-packages.sh" --all
      ;;
    quick | "")
      bash "${SCRIPT_DIR}/run-local-release-packages.sh" --quick
      ;;
    amd64 | arm64)
      bash "${SCRIPT_DIR}/run-local-release-packages.sh" --native --arch "${RELEASE_MODE}"
      ;;
    armhf | ppc64el | riscv64 | s390x)
      bash "${SCRIPT_DIR}/run-local-release-packages.sh" --cross "${RELEASE_MODE}"
      ;;
    *)
      printf 'error: unsupported release mode: %s\n' "${RELEASE_MODE}" >&2
      exit 2
      ;;
  esac
fi

if [[ ${RUN_SECURITY} -eq 1 ]]; then
  printf '\n── Local CI: security suite ──\n'
  bash "${SCRIPT_DIR}/run-local-security-suite.sh" --quick
fi

printf '\n── Local CI suite finished successfully ──\n'
