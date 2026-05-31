#!/bin/sh
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

# Ensure the dedicated pcsc-fido system user exists before starting the service.
# PC/SC client integration (optional host groups, polkit) lives here and in
# packaging/polkit/ — not in SupplementaryGroups= or other pcsc-fido.service drop-ins.
# Invoked from packaging/scripts/postinst at install time only — not ExecStartPre.

set -eu
umask 077

if [ "$(id -u)" -ne 0 ]; then
  printf 'ensure-pcsc-fido-user: must run as root\n' >&2
  exit 1
fi

if [ "$#" -ne 0 ]; then
  printf 'ensure-pcsc-fido-user: unexpected arguments\n' >&2
  exit 1
fi

case "$0" in
  /usr/lib/pcsc-fido/ensure-pcsc-fido-user.sh | /lib/pcsc-fido/ensure-pcsc-fido-user.sh)
    script_mode="$(stat -c '%a' "$0" 2>/dev/null || printf '')"
    if [ "$script_mode" != '700' ]; then
      printf 'ensure-pcsc-fido-user: expected mode 700 on %s (got %s)\n' "$0" "$script_mode" >&2
      exit 1
    fi
    ;;
esac

ensure_pcsc_fido_user() {
  if command -v systemd-sysusers >/dev/null 2>&1; then
    for conf in /usr/lib/sysusers.d/pcsc-fido.conf /lib/sysusers.d/pcsc-fido.conf; do
      if [ -f "$conf" ]; then
        systemd-sysusers "$conf" || return 1
        getent group pcsc-fido >/dev/null 2>&1 || return 1
        getent passwd pcsc-fido >/dev/null 2>&1 || return 1
        return 0
      fi
    done
  fi

  if ! getent group pcsc-fido >/dev/null 2>&1; then
    if ! command -v groupadd >/dev/null 2>&1; then
      return 1
    fi
    groupadd --system pcsc-fido 2>/dev/null || groupadd -r pcsc-fido 2>/dev/null || return 1
  fi

  if getent passwd pcsc-fido >/dev/null 2>&1; then
    return 0
  fi

  if ! command -v useradd >/dev/null 2>&1; then
    return 1
  fi
  useradd --system --gid pcsc-fido --home-dir /usr/share/empty --shell /usr/sbin/nologin \
    pcsc-fido 2>/dev/null ||
    useradd -r -g pcsc-fido -d /usr/share/empty -s /sbin/nologin pcsc-fido 2>/dev/null ||
    return 1

  getent group pcsc-fido >/dev/null 2>&1 || return 1
  getent passwd pcsc-fido >/dev/null 2>&1 || return 1
}

# If the host defines a pcscd group (name used by some pcsc-lite/distro layouts),
# add pcsc-fido as a supplementary member. No-op when the group is absent.
ensure_pcsc_fido_pcscd_client() {
  if ! getent passwd pcsc-fido >/dev/null 2>&1; then
    return 0
  fi
  if ! getent group pcscd >/dev/null 2>&1; then
    return 0
  fi
  if id -nG pcsc-fido 2>/dev/null | tr ' ' '\n' | grep -qx pcscd; then
    return 0
  fi
  if ! command -v usermod >/dev/null 2>&1; then
    return 0
  fi
  usermod -aG pcscd pcsc-fido || return 1
}

ensure_pcsc_fido_user
ensure_pcsc_fido_pcscd_client
