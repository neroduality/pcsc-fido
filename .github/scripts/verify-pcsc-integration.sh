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

# Validate PC/SC integration lives in packaging companions, not pcsc-fido.service drop-ins.
# No root required.

set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
ensure_script="${repo_root}/packaging/scripts/ensure-pcsc-fido-user.sh"
polkit_rules="${repo_root}/packaging/polkit/50-pcsc-fido.rules"
udev_rules="${repo_root}/packaging/udev/70-pcsc-fido.rules"
unit_src="${repo_root}/packaging/systemd/pcsc-fido.service"

for path in "${ensure_script}" "${polkit_rules}" "${udev_rules}" "${unit_src}"; do
  if [[ ! -f ${path} ]]; then
    printf 'error: missing %s\n' "${path}" >&2
    exit 1
  fi
done

required_ensure_patterns=(
  'ensure_pcsc_fido_pcscd_client'
  'usermod -aG pcscd pcsc-fido'
  'set -eu'
  'must run as root'
  'unexpected arguments'
  'install time only'
  'not in SupplementaryGroups='
  'expected mode 700'
  'getent group pcsc-fido'
  'not ExecStartPre'
)

for pattern in "${required_ensure_patterns[@]}"; do
  if ! grep -Fq "${pattern}" "${ensure_script}"; then
    printf 'error: ensure-pcsc-fido-user.sh missing: %s\n' "${pattern}" >&2
    exit 1
  fi
done

required_polkit_patterns=(
  '// SPDX-License-Identifier: Apache-2.0'
  'polkit.addRule'
  'org.debian.pcsc-lite.access_pcsc'
  'org.debian.pcsc-lite.access_card'
  'subject.user == "pcsc-fido"'
  'return polkit.Result.YES'
)

for pattern in "${required_polkit_patterns[@]}"; do
  if ! grep -Fq "${pattern}" "${polkit_rules}"; then
    printf 'error: 50-pcsc-fido.rules missing: %s\n' "${pattern}" >&2
    exit 1
  fi
done

forbidden_polkit_patterns=(
  'subject.unit == "pcsc-fido.service"'
  'subject.system_unit == "pcsc-fido.service"'
)

for pattern in "${forbidden_polkit_patterns[@]}"; do
  if grep -Fq "${pattern}" "${polkit_rules}"; then
    printf 'error: 50-pcsc-fido.rules must not match unit subjects: %s\n' "${pattern}" >&2
    exit 1
  fi
done

if grep -Eq '^[[:space:]]*#' "${polkit_rules}"; then
  printf 'error: 50-pcsc-fido.rules must use JavaScript comments, not shell comments\n' >&2
  exit 1
fi

if ! grep -Fq 'OPTIONS+="static_node=uhid"' "${udev_rules}"; then
  printf 'error: 70-pcsc-fido.rules must apply permissions to the static /dev/uhid node\n' >&2
  exit 1
fi

if ! grep -Fq 'MODE="0600"' "${udev_rules}"; then
  printf 'error: 70-pcsc-fido.rules must keep virtual hidraw group/world bits closed\n' >&2
  exit 1
fi

if ! grep -Fq 'TAG+="uaccess"' "${udev_rules}"; then
  printf 'error: 70-pcsc-fido.rules must tag virtual hidraw with uaccess\n' >&2
  exit 1
fi

if grep -Fq 'GROUP="plugdev"' "${udev_rules}"; then
  printf 'error: 70-pcsc-fido.rules must not grant broad plugdev access to virtual hidraw\n' >&2
  exit 1
fi

if grep -Eq '^[[:space:]]*SupplementaryGroups=' "${unit_src}"; then
  printf 'error: pcsc-fido.service must not set SupplementaryGroups= (use ensure script at install)\n' >&2
  exit 1
fi

if grep -Eq '^[[:space:]]*ExecStartPre=' "${unit_src}"; then
  printf 'error: pcsc-fido.service must not use ExecStartPre (bootstrap via modules-load.d + postinst)\n' >&2
  exit 1
fi

if grep -Eq '^[[:space:]]*PermissionsStartOnly=' "${unit_src}"; then
  printf 'error: pcsc-fido.service must not use PermissionsStartOnly without ExecStartPre\n' >&2
  exit 1
fi

if [[ ! -f ${repo_root}/packaging/modules-load/pcsc-fido-uhid.conf ]]; then
  printf 'error: missing packaging/modules-load/pcsc-fido-uhid.conf\n' >&2
  exit 1
fi

if ! grep -Fq -- '--chown=0:0' "${repo_root}/.github/scripts/install-built-tree.sh"; then
  printf 'error: source install must copy polkit/systemd files as root-owned\n' >&2
  exit 1
fi

if ! grep -Fq 'modprobe -q uhid' "${repo_root}/packaging/scripts/postinst"; then
  printf 'error: packaging/scripts/postinst must load uhid and re-apply udev rules\n' >&2
  exit 1
fi

if grep -Fq '. "$ensure_user"' "${repo_root}/packaging/scripts/postinst" ||
  grep -Fq '. "$ensure_user"' "${repo_root}/packaging/scripts/postinst"; then
  printf 'error: postinst must execute ensure-pcsc-fido-user.sh, not source it\n' >&2
  exit 1
fi

if grep -Fq '/bin/sh "$ensure_user"' "${repo_root}/packaging/scripts/postinst"; then
  printf 'error: postinst must execute ensure-pcsc-fido-user.sh directly (shebang), not via /bin/sh\n' >&2
  exit 1
fi

if ! grep -Fq '"$ensure_user"' "${repo_root}/packaging/scripts/postinst"; then
  printf 'error: postinst must execute ensure-pcsc-fido-user.sh directly (shebang)\n' >&2
  exit 1
fi

if ! grep -Fq 'packaging/scripts/prerm' "${repo_root}/CMakeLists.txt"; then
  printf 'error: CPack DEB control scripts must include packaging/scripts/prerm\n' >&2
  exit 1
fi

if ! grep -Eq '0 \| remove \| deconfigure' "${repo_root}/packaging/scripts/prerm"; then
  printf 'error: prerm must handle both RPM erase and Debian remove/deconfigure actions\n' >&2
  exit 1
fi

if ! grep -Fq 'PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE' "${repo_root}/CMakeLists.txt"; then
  printf 'error: ensure-pcsc-fido-user.sh must install mode 0700 (root-only)\n' >&2
  exit 1
fi

for duplicate in \
  "${repo_root}/packaging/debian/postinst" \
  "${repo_root}/packaging/debian/postrm" \
  "${repo_root}/packaging/rpm/postinstall.sh" \
  "${repo_root}/packaging/rpm/postremove.sh" \
  "${repo_root}/packaging/rpm/preremove.sh"; do
  if [[ -f ${duplicate} ]]; then
    printf 'error: duplicate package hook (use packaging/scripts/ only): %s\n' "${duplicate}" >&2
    exit 1
  fi
done

if ! grep -Fq '%include ../scripts/postinst' "${repo_root}/packaging/rpm/pcsc-fido.spec"; then
  printf 'error: pcsc-fido.spec must %%include packaging/scripts/postinst\n' >&2
  exit 1
fi

if ! grep -Fq '%include ../scripts/prerm' "${repo_root}/packaging/rpm/pcsc-fido.spec"; then
  printf 'error: pcsc-fido.spec must %%include packaging/scripts/prerm\n' >&2
  exit 1
fi

printf 'pcsc integration verify: OK\n'
