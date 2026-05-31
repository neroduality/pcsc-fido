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

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
package_postinst="${repo_root}/packaging/scripts/postinst"

as_root() {
  if [[ ${EUID} -eq 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

if [[ ! -f ${package_postinst} ]]; then
  printf 'error: missing package postinst hook: %s\n' "${package_postinst}" >&2
  exit 1
fi

if [[ ${INSTALL_BUILD_TYPE:-Release} != "Debug" ]]; then
  as_root rm -f /etc/systemd/system/pcsc-fido.service.d/90-pcsc-fido-debug.conf
fi

as_root /bin/sh "${package_postinst}"

printf '%s\n' \
  'install: files, udev rules, systemd metadata, and polkit rules updated.' \
  '  systemd daemon-reload and udev rules reload completed.' \
  '  Re-run `sudo systemctl daemon-reload` after hand-editing pcsc-fido.service or drop-ins, then restart the service.' \
  '  polkit reloads rules from disk automatically; pcscd and pcsc-fido were not enabled or started.' \
  '  Enable PC/SC and the bridge yourself (see README quick start):' \
  '    sudo systemctl enable --now pcscd.socket' \
  '    sudo systemctl enable --now pcsc-fido.service'
