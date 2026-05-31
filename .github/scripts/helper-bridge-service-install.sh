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

# Shared systemd helpers for pcsc-fido install scripts.
# Source install and packages do not enable or restart the bridge automatically.

pcsc_fido_install_prefix_is_system() {
  case "${1:-}" in
    /usr | /usr/local) return 0 ;;
    *) return 1 ;;
  esac
}

# Stop a running bridge before replacing unit/binary files. No-op when inactive.
pcsc_fido_stop_bridge_for_install() {
  if ! command -v systemctl >/dev/null 2>&1; then
    return 0
  fi
  if ! systemctl cat pcsc-fido.service >/dev/null 2>&1; then
    return 0
  fi
  if systemctl is-active --quiet pcsc-fido.service 2>/dev/null; then
    systemctl stop pcsc-fido.service || true
    printf 'install: stopped pcsc-fido.service before updating files\n'
  fi
}

# Reload systemd/udev metadata only — never enable, start, or restart systemd units here.
