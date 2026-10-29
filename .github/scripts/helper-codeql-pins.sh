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

# Single source for CodeQL local + GHA pins. Source this file; do not copy the
# digest or CLI hash into other scripts. Workflow YAML cannot source bash, so
# .github/workflows/codeql.yml `container.image` and `tools:` must stay in
# lockstep with the values below (commented there).
#
# CODEQL_IMAGE: fully-qualified tag + digest (registry/name:tag@sha256:...),
# same form as the other local-CI images. The CodeQL job runs in this
# container; the CLI zip is fetched inside it and checked against
# CODEQL_CLI_SHA256 (not TOFU: upstream .checksum.txt is same-origin).

CODEQL_IMAGE_DEFAULT="docker.io/library/debian:sid-slim@sha256:5ac67a4d7c0de96e83873e4dd8f7ea3b507ba292fb2cce60a0c3f73322df5cae"
CODEQL_CLI_VERSION_DEFAULT="v2.27.3"
CODEQL_CLI_SHA256_DEFAULT="845075a2fa2fdf72629adc6cbde6264691b698d1f294bd27f10c6b579cd750a4"
CODEQL_BUNDLE_TAG_DEFAULT="codeql-bundle-v2.27.3"
CODEQL_BUNDLE_URL_DEFAULT="https://github.com/github/codeql-action/releases/download/${CODEQL_BUNDLE_TAG_DEFAULT}/codeql-bundle-linux64.tar.zst"

# Resolve CODEQL_CLI_VERSION / CODEQL_CLI_SHA256 from the environment and the
# defaults above. The SHA default applies only to the default version: an
# overridden version with no hash is an error here, before any download, on
# the host and inside the container alike (both call this).
codeql_pins_resolve_cli() {
  CODEQL_CLI_VERSION="${CODEQL_CLI_VERSION:-${CODEQL_CLI_VERSION_DEFAULT}}"
  if [[ -z ${CODEQL_CLI_SHA256:-} ]]; then
    if [[ ${CODEQL_CLI_VERSION} != "${CODEQL_CLI_VERSION_DEFAULT}" ]]; then
      printf 'error: CODEQL_CLI_VERSION=%s requires CODEQL_CLI_SHA256 (pinned codeql-linux64.zip hash)\n' \
        "${CODEQL_CLI_VERSION}" >&2
      return 1
    fi
    CODEQL_CLI_SHA256="${CODEQL_CLI_SHA256_DEFAULT}"
  fi
  export CODEQL_CLI_VERSION CODEQL_CLI_SHA256
}

# Workflow YAML cannot source this file, so assert the lockstep instead of
# trusting the comments: codeql.yml must carry the same container image and
# the same bundle URL. Run from `make codeql-local`; cheap enough for precheck.
codeql_pins_check_workflow() {
  local workflow="${1:?workflow path required}" rc=0
  if ! grep -Fq -- "image: ${CODEQL_IMAGE_DEFAULT}" "${workflow}"; then
    printf 'error: %s container.image is not CODEQL_IMAGE_DEFAULT (%s)\n' \
      "${workflow}" "${CODEQL_IMAGE_DEFAULT}" >&2
    rc=1
  fi
  if ! grep -Fq -- "tools: ${CODEQL_BUNDLE_URL_DEFAULT}" "${workflow}"; then
    printf 'error: %s tools: is not CODEQL_BUNDLE_URL_DEFAULT (%s)\n' \
      "${workflow}" "${CODEQL_BUNDLE_URL_DEFAULT}" >&2
    rc=1
  fi
  return "${rc}"
}
