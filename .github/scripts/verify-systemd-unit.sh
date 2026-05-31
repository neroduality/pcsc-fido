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

# Validate required sandbox and ordering directives in packaging/systemd/pcsc-fido.service.
# No root required.

set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
unit_src="${repo_root}/packaging/systemd/pcsc-fido.service"

if [[ ! -f ${unit_src} ]]; then
  printf 'error: missing %s\n' "${unit_src}" >&2
  exit 1
fi

required_directives=(
  'User=pcsc-fido'
  'Group=pcsc-fido'
  'Wants=polkit.service'
  'After=systemd-udevd.service'
  'After=systemd-modules-load.service'
  'After=polkit.service'
  'ExecStart=/usr/bin/pcsc-fido'
  'StartLimitIntervalSec=60'
  'StartLimitBurst=5'
  'LimitNOFILE=256'
  'TasksMax=32'
  'MemoryMax=256M'
  'NoNewPrivileges=yes'
  'CapabilityBoundingSet='
  'PrivateUsers=identity'
  'KeyringMode=private'
  'ProtectSystem=strict'
  'ProtectProc=invisible'
  'ProcSubset=pid'
  'ProtectHostname=yes'
  'MemoryDenyWriteExecute=yes'
  'RemoveIPC=yes'
  'PrivateNetwork=yes'
  'RestrictAddressFamilies=AF_UNIX'
  'IPAddressDeny=any'
  'SystemCallFilter=@system-service'
  'SystemCallFilter=~@resources @privileged @swap'
)

for directive in "${required_directives[@]}"; do
  if ! grep -Fq "${directive}" "${unit_src}"; then
    printf 'error: pcsc-fido.service missing required directive: %s\n' "${directive}" >&2
    exit 1
  fi
done

modules_load="${repo_root}/packaging/modules-load/pcsc-fido-uhid.conf"
if [[ ! -f ${modules_load} ]] || ! grep -qx 'uhid' "${modules_load}"; then
  printf 'error: packaging/modules-load/pcsc-fido-uhid.conf must load uhid at boot\n' >&2
  exit 1
fi

if grep -Fq 'ConditionPathExists=/dev/uhid' "${unit_src}"; then
  printf 'error: pcsc-fido.service must not gate start on /dev/uhid\n' >&2
  exit 1
fi

forbidden_patterns=(
  '^[[:space:]]*PrivateDevices=yes'
  '^[[:space:]]*ConditionPathExists='
  '^[[:space:]]*DeviceAllow='
  '^[[:space:]]*DevicePolicy='
  '^[[:space:]]*SupplementaryGroups='
  '^[[:space:]]*PermissionsStartOnly='
  '^[[:space:]]*ExecStartPre='
)

for pattern in "${forbidden_patterns[@]}"; do
  if grep -Eq "${pattern}" "${unit_src}"; then
    printf 'error: pcsc-fido.service must not set active %s\n' "${pattern}" >&2
    exit 1
  fi
done

printf 'systemd unit verify: OK (%s)\n' "${unit_src}"
