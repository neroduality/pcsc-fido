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

# Fail if an SPDX SBOM does not meet the 2021 NTIA minimum elements.
# Runs after Syft and before Grype in the supply-chain workflow.
#
# Usage:
#   bash .github/scripts/verify-sbom-ntia.sh sbom.spdx.json
#
set -euo pipefail

usage() {
  cat <<'EOF'
Check an SPDX SBOM against the NTIA minimum elements.

Usage:
  bash .github/scripts/verify-sbom-ntia.sh SBOM.spdx.json

Requires ntia-checker (or sbomcheck) on PATH:
  python3 -m pip install --user --require-hashes -r .github/pinned/ntia/requirements.txt

EOF
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
  usage
  exit 0
fi
if [[ $# -ne 1 ]]; then
  usage >&2
  exit 1
fi

sbom="$1"
if [[ ! -s ${sbom} ]]; then
  printf 'error: SBOM not found or empty: %s\n' "${sbom}" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# Syft names the scanned directory "." and leaves its version and supplier
# unset. That package is this repository. The version is the CMake project
# version; the supplier is the copyright holder.
python3 - "${sbom}" "${repo_root}/CMakeLists.txt" <<'PY'
import json
import pathlib
import re
import sys

sbom_path, cmake_path = sys.argv[1:]
text = pathlib.Path(cmake_path).read_text(encoding="utf-8")
match = re.search(r"^project\(pcsc_fido VERSION ([0-9.]+)", text, re.M)
if match is None:
    sys.exit("error: project version not found in CMakeLists.txt")
version = match.group(1)
doc = json.loads(pathlib.Path(sbom_path).read_text(encoding="utf-8"))
changed = False
for package in doc.get("packages", []):
    is_root = package.get("name") == "." or str(package.get("SPDXID", "")).startswith(
        "SPDXRef-DocumentRoot-Directory-"
    )
    if not is_root:
        continue
    package["name"] = "pcsc-fido"
    package["versionInfo"] = version
    package["supplier"] = "Organization: Nero Duality, LLC"
    changed = True
if changed:
    pathlib.Path(sbom_path).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print(f"named the Syft directory package pcsc-fido {version}")
PY

checker=()
if command -v ntia-checker >/dev/null 2>&1; then
  checker=(ntia-checker)
elif command -v sbomcheck >/dev/null 2>&1; then
  checker=(sbomcheck)
else
  printf 'error: ntia-checker not found (python3 -m pip install --user --require-hashes -r .github/pinned/ntia/requirements.txt)\n' >&2
  exit 1
fi

printf '\n-- NTIA minimum elements (%s) --\n' "${checker[0]}"
if ! "${checker[@]}" --sbom-spec spdx2 --comply ntia "${sbom}"; then
  printf 'error: SPDX SBOM does not meet the NTIA minimum elements: %s\n' "${sbom}" >&2
  exit 1
fi
printf -- '-- NTIA minimum elements: passed --\n'
