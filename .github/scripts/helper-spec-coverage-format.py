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

"""Normalize docs/spec-coverage.yaml spacing and field layout."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("error: PyYAML is required (install python3-yaml or pip install pyyaml)", file=sys.stderr)
    sys.exit(2)


def parse_args() -> argparse.Namespace:
    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parent.parent
    default_manifest = repo_root / "docs" / "spec-coverage.yaml"

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=default_manifest,
        help=f"Manifest to format (default: {default_manifest})",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=repo_root,
        help="Repository root (unused; reserved for symmetry with helper-spec-coverage-check.py)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit 1 if the manifest is not already formatted (do not write)",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="Rewrite the manifest in canonical form (default when --check is omitted)",
    )
    return parser.parse_args()


def split_preamble(text: str) -> tuple[list[str], str]:
    preamble: list[str] = []
    body_lines: list[str] = []
    in_preamble = True
    for line in text.splitlines():
        if in_preamble and (line.startswith("#") or line.strip() == ""):
            preamble.append(line.rstrip())
            continue
        in_preamble = False
        body_lines.append(line)
    while preamble and preamble[-1] == "":
        preamble.pop()
    return preamble, "\n".join(body_lines).strip("\n")


def yaml_quote_pattern(pattern: str) -> str:
    if pattern.startswith("'") and pattern.endswith("'"):
        return pattern
    if any(ch in pattern for ch in "|:#{}[]&*!?@`'\"\\"):
        escaped = pattern.replace("'", "''")
        return f"'{escaped}'"
    if pattern.startswith((" ", "-", "?", ">", "*", "&", "!", "%", "@", "`")):
        escaped = pattern.replace("'", "''")
        return f"'{escaped}'"
    return pattern


def render_manifest(data: dict, preamble: list[str]) -> str:
    lines: list[str] = list(preamble)
    lines.append("")

    first_spec = True
    for spec_id, spec_body in data.items():
        if not first_spec:
            lines.append("")
        first_spec = False

        if not isinstance(spec_body, dict):
            raise ValueError(f"{spec_id}: expected mapping")
        summary = spec_body.get("summary")
        requirements = spec_body.get("requirements")
        if not isinstance(summary, str):
            raise ValueError(f"{spec_id}: summary must be a string")
        if not isinstance(requirements, dict):
            raise ValueError(f"{spec_id}: requirements must be a mapping")

        lines.append(f"{spec_id}:")
        lines.append(f"  summary: {summary}")
        lines.append("  requirements:")

        first_req = True
        for req_id, req_body in requirements.items():
            if not first_req:
                lines.append("")
            first_req = False

            if not isinstance(req_body, dict):
                raise ValueError(f"{spec_id}.{req_id}: expected mapping")
            label = req_body.get("label")
            pattern = req_body.get("pattern")
            paths = req_body.get("paths")
            if not isinstance(label, str) or not label.strip():
                raise ValueError(f"{spec_id}.{req_id}: label must be a non-empty string")
            if not isinstance(pattern, str) or not pattern.strip():
                raise ValueError(f"{spec_id}.{req_id}: pattern must be a non-empty string")
            if not isinstance(paths, list) or not paths:
                raise ValueError(f"{spec_id}.{req_id}: paths must be a non-empty list")

            lines.append(f"    {req_id}:")
            lines.append(f"      label: {label}")
            lines.append(f"      pattern: {yaml_quote_pattern(pattern)}")
            lines.append("      paths:")
            for path in paths:
                if not isinstance(path, str) or not path.strip():
                    raise ValueError(f"{spec_id}.{req_id}: paths must be non-empty strings")
                lines.append(f"        - {path}")

    lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    manifest_path = args.manifest.resolve()
    if not manifest_path.is_file():
        print(f"error: manifest not found: {manifest_path}", file=sys.stderr)
        return 1

    raw = manifest_path.read_text(encoding="utf-8")
    preamble, _body = split_preamble(raw)
    try:
        data = yaml.safe_load(_body)
    except yaml.YAMLError as exc:
        print(f"error: invalid YAML: {exc}", file=sys.stderr)
        return 2

    if not isinstance(data, dict):
        print("error: manifest root must be a mapping", file=sys.stderr)
        return 2

    try:
        formatted = render_manifest(data, preamble)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    canonical = formatted.rstrip() + "\n"
    on_disk = raw.rstrip() + "\n"

    if args.check:
        if on_disk != canonical:
            print(f"error: {manifest_path} is not canonically formatted", file=sys.stderr)
            print("Run: python3 .github/scripts/helper-spec-coverage-format.py --write", file=sys.stderr)
            return 1
        return 0

    if not args.write and args.check is False:
        # Default: write when invoked without flags (format in place).
        args.write = True

    if args.write:
        manifest_path.write_text(canonical, encoding="utf-8", newline="\n")
        print(f"formatted: {manifest_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
