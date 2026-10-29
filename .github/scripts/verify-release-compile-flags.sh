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

# Release (and the other optimized configs) are the only place -O2 and
# _FORTIFY_SOURCE=3 are passed. Lint configures Debug, so this checks a
# Release compile database directly. Last option wins, the same way the
# compiler applies them.
set -euo pipefail

if [[ $# -ne 1 || ! -f ${1}/compile_commands.json ]]; then
  printf 'usage: verify-release-compile-flags.sh BUILD_DIR\n' >&2
  exit 2
fi

python3 - "${1}/compile_commands.json" <<'PY'
import json
import shlex
import sys
from pathlib import Path

commands = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
sources = [
    entry
    for entry in commands
    if str(entry.get("file", "")).endswith(".c") and "/src/" in str(entry.get("file", ""))
]
if not sources:
    sys.exit("error: Release compile database has no src/*.c commands")

def tokens(entry: dict) -> list[str]:
    args = entry.get("arguments")
    if isinstance(args, list) and args:
        return [str(arg) for arg in args]
    return shlex.split(str(entry.get("command", "")))

FORTIFY_TOKENS = {
    "-U_FORTIFY_SOURCE",
    "-D_FORTIFY_SOURCE",
    "-D_FORTIFY_SOURCE=1",
    "-D_FORTIFY_SOURCE=2",
    "-D_FORTIFY_SOURCE=3",
}

def last_of(items: list[str], family) -> str | None:
    found = None
    for item in items:
        if family(item):
            found = item
    return found

failures = []
for entry in sources:
    got = tokens(entry)
    name = Path(str(entry["file"])).name
    optimization = last_of(got, lambda item: item in {"-O0", "-O1", "-O2", "-O3", "-Os", "-Oz", "-Og"})
    if optimization not in {"-O2", "-O3"}:
        failures.append(f"{name}: -O2 not in effect (last optimization is {optimization})")
    fortify = last_of(got, lambda item: item in FORTIFY_TOKENS)
    # -fhardened enables _FORTIFY_SOURCE=3, and Hardening.cmake omits the
    # explicit -D when that probe is true (the two together trip -Whardened).
    # A later -U or a lower level still wins, the same way the compiler applies it.
    if fortify != "-D_FORTIFY_SOURCE=3" and not (fortify is None and "-fhardened" in got):
        failures.append(f"{name}: _FORTIFY_SOURCE=3 not in effect (last is {fortify})")
    protector = last_of(
        got,
        lambda item: item.startswith("-fstack-protector") or item == "-fno-stack-protector",
    )
    if protector not in {"-fstack-protector-strong", "-fstack-protector-all"}:
        failures.append(f"{name}: stack protector not in effect (last is {protector})")

if failures:
    sys.exit("error: Release compile flags\n" + "\n".join(failures))
print(f"release compile flags: OK ({len(sources)} src files)")
PY
