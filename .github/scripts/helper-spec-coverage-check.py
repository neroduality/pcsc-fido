#!/usr/bin/env python3
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


from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("error: PyYAML is required", file=sys.stderr)
    sys.exit(2)

SOURCE_SUFFIXES = {"", ".c", ".h", ".txt", ".in", ".rules", ".service", ".yaml", ".yml", ".md", ".spec"}
SKIP_DIRS = {"build", "oss_sources", "tmp_input"}


def parse_args() -> argparse.Namespace:
    repo_root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=repo_root)
    parser.add_argument("--manifest", type=Path, default=repo_root / "docs/spec-coverage.yaml")
    return parser.parse_args()


def iter_files(root: Path):
    if root.is_file():
        yield root
        return
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix not in SOURCE_SUFFIXES:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        yield path


def present(repo_root: Path, paths: list[str], pattern: str) -> bool:
    regex = re.compile(pattern)
    for rel in paths:
        root = repo_root / rel
        if not root.exists():
            continue
        for path in iter_files(root):
            if regex.search(path.read_text(encoding="utf-8", errors="replace")):
                return True
    return False


def main() -> int:
    args = parse_args()
    data = yaml.safe_load(args.manifest.read_text(encoding="utf-8"))
    missing = 0
    checked = 0
    print(f"── Spec coverage ({args.manifest.name}) ──")
    for spec_id, spec in data.items():
        print(f"▸ {spec.get('summary', spec_id)} ({spec_id})")
        for req in spec["requirements"].values():
            checked += 1
            if present(args.repo_root, req["paths"], req["pattern"]):
                print(f"  ✓ {req['label']}")
            else:
                missing += 1
                print(f"  ✗ {req['label']} — pattern not found: {req['pattern']}")
        print()
    print(f"Summary: {checked - missing}/{checked} requirements satisfied")
    if missing:
        return 1
    print("spec coverage: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
