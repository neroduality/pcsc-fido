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

# Lint job container entry (after repo + .lint-kit-org checkout). Mirrors main-ci.yml lint job.
#
# GHA: run after checkouts with CI_SKIP_CHECKOUT_PREREQUISITES=1 and the org lint
#   kit checked out at .lint-kit-org (neroduality/.github -> lint-c-cpp).
# ci-local: bind-mounts the repo and lint kit, then runs the full entry.
#
# Usage (from pcsc-fido root):
#   LINT_KIT=.lint-kit-org/lint-c-cpp bash .github/scripts/ci-run-lint.sh
set -euo pipefail

repo_root="$(pwd)"
if [[ ! -f "${repo_root}/CMakeLists.txt" ]] || [[ ! -d "${repo_root}/src" ]]; then
  printf 'error: run from pcsc-fido root\n' >&2
  exit 1
fi

lint_kit="${LINT_KIT:-${repo_root}/.lint-kit-org/lint-c-cpp}"

# shellcheck source=helper-container-bind-mount.sh
source "${repo_root}/.github/scripts/helper-container-bind-mount.sh"

export LINT_KIT="${lint_kit}"

if [[ $(id -u) -eq 0 && -n ${HOST_UID:-} && ${PCSC_FIDO_CI_AS_USER:-0} != 1 ]]; then
  PCSC_FIDO_ALLOW_SUDO_DEPS=1 PCSC_FIDO_DEPS_SCOPE=full \
    bash "${repo_root}/.github/scripts/install-linux-deps.sh"
  pcsc_fido_prepare_bind_mount_paths "${repo_root}"
  pcsc_fido_require_drop_to_host_user bash "${repo_root}/.github/scripts/ci-run-lint.sh"
fi

pcsc_fido_refuse_root_bind_mount_writes

if [[ "$(uname -s)" == "Linux" ]]; then
  auto_install_linux_deps="${AUTO_INSTALL_LINUX_DEPS:-}"
  if [[ -z ${auto_install_linux_deps} ]]; then
    if [[ ${GITHUB_ACTIONS:-false} == true ]]; then
      auto_install_linux_deps=1
    else
      auto_install_linux_deps=0
    fi
  fi
  if [[ ${auto_install_linux_deps} != "0" ]]; then
    PCSC_FIDO_DEPS_SCOPE=full bash "${repo_root}/.github/scripts/install-linux-deps.sh"
  fi
fi

if [[ ! -x "${lint_kit}/lint-c-cpp.sh" ]]; then
  printf 'error: lint kit missing lint-c-cpp.sh: %s\n' "${lint_kit}" >&2
  printf 'hint: GHA checks out neroduality/.github to .lint-kit-org; ci-local mounts or clones it\n' >&2
  exit 1
fi

cd "${repo_root}"
make lint INSTALL_DEPS=0 "LINT_KIT=${lint_kit}"
