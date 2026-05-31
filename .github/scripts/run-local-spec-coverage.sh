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

# Reproduce the spec-coverage gate locally (format check + symbol grep).
# ``make lint`` runs the same Python steps inline; CI and ``make ci-suite`` use this script.
#
# Usage:
#   bash .github/scripts/run-local-spec-coverage.sh
#   bash .github/scripts/run-local-spec-coverage.sh -- --manifest docs/spec-coverage.yaml
set -euo pipefail

usage() {
  cat <<'EOF'
Verify checklist-mapped symbols from docs/spec-coverage.yaml.

Usage:
  bash .github/scripts/run-local-spec-coverage.sh [-- --manifest PATH]

Requires PyYAML (python3-yaml). Runs helper-spec-coverage-format.py --check, then helper-spec-coverage-check.py.
EOF
}

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"

if [[ ${1:-} == "-h" ]] || [[ ${1:-} == "--help" ]]; then
  usage
  exit 0
fi

extra=()
if (($# > 0)); then
  if [[ $1 == "--" ]]; then
    shift
  fi
  extra=("$@")
fi

if ! python3 -c "import yaml" >/dev/null 2>&1; then
  printf 'error: PyYAML not found (install python3-yaml or: pip install pyyaml)\n' >&2
  exit 2
fi

python3 "${SCRIPT_DIR}/helper-spec-coverage-format.py" --repo-root "${REPO_ROOT}" --check
exec python3 "${SCRIPT_DIR}/helper-spec-coverage-check.py" --repo-root "${REPO_ROOT}" "${extra[@]}"
