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

# Verify rootful Docker for the current user (lima): daemon reachable and optionally run a container.
# LIMA_DOCKER_SMOKE_MODE=full   -- docker info + docker run (provision, first boot)
# LIMA_DOCKER_SMOKE_MODE=quick  -- docker info only (guest CI entry after provision)
set -euo pipefail

DOCKER_SMOKE_IMAGE="${DOCKER_SMOKE_IMAGE:-docker.io/library/alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d}"
DOCKER_INFO_TIMEOUT="${DOCKER_INFO_TIMEOUT:-60s}"
DOCKER_RUN_TIMEOUT="${DOCKER_RUN_TIMEOUT:-180s}"
LIMA_DOCKER_SMOKE_MODE="${LIMA_DOCKER_SMOKE_MODE:-full}"

if ! command -v docker >/dev/null 2>&1; then
  printf 'error: docker CLI not found\n' >&2
  exit 127
fi

if ! timeout "${DOCKER_INFO_TIMEOUT}" bash -c 'until docker info >/dev/null 2>&1; do sleep 2; done'; then
  printf 'error: docker info failed for user %s (timeout %s)\n' "$(id -un)" "${DOCKER_INFO_TIMEOUT}" >&2
  docker info 2>&1 | head -5 >&2 || true
  exit 1
fi

if [[ ${LIMA_DOCKER_SMOKE_MODE} == quick ]]; then
  exit 0
fi

if ! timeout "${DOCKER_RUN_TIMEOUT}" docker run --rm "${DOCKER_SMOKE_IMAGE}" echo lima-docker-smoke-ok; then
  printf 'error: docker run smoke test failed (image %s, timeout %s)\n' \
    "${DOCKER_SMOKE_IMAGE}" "${DOCKER_RUN_TIMEOUT}" >&2
  exit 1
fi
