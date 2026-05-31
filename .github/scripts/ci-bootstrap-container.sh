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

# Minimal bootstrap for Debian/Fedora CI images (TLS + git for checkout / FetchContent).
# Expects root in GitHub Actions container jobs or local docker --user 0.
#
# Usage: bash ci-bootstrap-container.sh
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  printf 'error: ci-bootstrap-container.sh must run as root (container entry)\n' >&2
  exit 1
fi

if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y --no-install-recommends ca-certificates git util-linux
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y --setopt=install_weak_deps=False ca-certificates git util-linux
  dnf clean all
else
  printf 'error: unsupported base image (need apt-get or dnf)\n' >&2
  exit 1
fi
