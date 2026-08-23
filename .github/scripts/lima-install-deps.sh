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

# CI deps install inside the Lima guest (root via sudo).
# The guest only orchestrates Docker-based CI; lint tools install inside the lint container.
set -euo pipefail

PCSC_FIDO_ROOT="${1:-/src}"

[[ -f ${PCSC_FIDO_ROOT}/.github/scripts/install-linux-deps.sh ]] || {
  printf 'error: %s/.github/scripts/install-linux-deps.sh missing\n' "${PCSC_FIDO_ROOT}" >&2
  exit 1
}

: "${LINT_KIT:=/opt/lint-kit}"
export LINT_KIT
if [[ ! -x ${LINT_KIT}/lint-c-cpp.sh ]]; then
  printf 'error: lint kit missing lint-c-cpp.sh: %s\n' "${LINT_KIT}" >&2
  exit 1
fi

export HOME=/root DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends ca-certificates curl git make rsync
export INSTALL_DEPS=1
export AUTO_INSTALL_LINUX_DEPS=1
export PCSC_FIDO_ALLOW_SUDO_DEPS=1
export PCSC_FIDO_DEPS_SCOPE=build
bash "${PCSC_FIDO_ROOT}/.github/scripts/install-linux-deps.sh"

cat >/etc/profile.d/pcsc-fido-ci-env.sh <<PROFILE
export LINT_KIT="${LINT_KIT}"
export CONTAINER_ENGINE="${CONTAINER_ENGINE:-docker}"
export CI_PLATFORM="${CI_PLATFORM:-linux/amd64}"
PROFILE
