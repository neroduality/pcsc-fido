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

"""Ensure the repository-standard Apache-2.0 SPDX header at the top of source files."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

HOLDER = "Nero Duality, LLC."
SPDX_LINE = "SPDX-License-Identifier: Apache-2.0"
LICENSE_URL_LINE = "http://www.apache.org/licenses/LICENSE-2.0"
LAST_LINE = "limitations under the License."

SKIP_DIR_NAMES = frozenset(
    {
        ".git",
        "build",
        "dist",
        "patches",
        "third-party",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".cache",
        ".mypy_cache",
        ".pytest_cache",
        "scan-build-report",
    }
)

SKIP_PATH_SUBSTR = (
    "/_deps/",
    "/tests/build/",
    "/tests/build-scan/",
    "/tests/build-codeql/",
)

MD_HEADER_RX = re.compile(
    r"^<!-- SPDX-License-Identifier: Apache-2\.0 -->\s*\r?\n<!--\r?\n(.*?)\r?\n-->\s*",
    re.DOTALL,
)


def _year() -> int:
    return datetime.now(UTC).year


def hash_header_text(year: int) -> str:
    lines = [
        f"# {SPDX_LINE}",
        "#",
        f"# Copyright (C) {year} {HOLDER}",
        "#",
        '# Licensed under the Apache License, Version 2.0 (the "License");',
        "# you may not use this file except in compliance with the License.",
        "# You may obtain a copy of the License at",
        "#",
        f"#     {LICENSE_URL_LINE}",
        "#",
        "# Unless required by applicable law or agreed to in writing, software",
        '# distributed under the License is distributed on an "AS IS" BASIS,',
        "# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.",
        "# See the License for the specific language governing permissions and",
        f"# {LAST_LINE}",
        "",
        "",
    ]
    return "\n".join(lines)


def cpp_header_text(year: int) -> str:
    lines = [
        f"// {SPDX_LINE}",
        "//",
        f"// Copyright (C) {year} {HOLDER}",
        "//",
        '// Licensed under the Apache License, Version 2.0 (the "License");',
        "// you may not use this file except in compliance with the License.",
        "// You may obtain a copy of the License at",
        "//",
        f"//     {LICENSE_URL_LINE}",
        "//",
        "// Unless required by applicable law or agreed to in writing, software",
        '// distributed under the License is distributed on an "AS IS" BASIS,',
        "// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.",
        "// See the License for the specific language governing permissions and",
        f"// {LAST_LINE}",
        "",
        "",
    ]
    return "\n".join(lines)


def md_header_text(year: int) -> str:
    inner = f"""Copyright (C) {year} {HOLDER}

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    {LICENSE_URL_LINE}

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License."""
    return f"<!-- {SPDX_LINE} -->\n<!--\n{inner}\n-->\n\n"


@dataclass(frozen=True)
class FileKind:
    style: str


def classify(path: Path) -> FileKind | None:
    name = path.name
    suf = path.suffix.lower()
    parts = path.parts
    if name in {"Makefile", "GNUmakefile", "makefile"}:
        return FileKind("hash")
    if name == "CMakeLists.txt" or suf in {".cmake"}:
        return FileKind("hash")
    if name.startswith("Dockerfile") or name.endswith(".Dockerfile"):
        return FileKind("hash")
    if suf == ".rules" and "polkit" in parts:
        return FileKind("cpp")
    if suf in {".sh", ".bash", ".mk", ".yaml", ".yml", ".py", ".spec", ".service", ".rules"}:
        return FileKind("hash")
    if name in {"postinst", "postrm", "prerm"} and "scripts" in parts:
        return FileKind("hash")
    if name == "rules" and "debian" in parts:
        return FileKind("hash")
    if suf in {".cpp", ".hpp", ".h", ".cc", ".cxx", ".c", ".ino"}:
        return FileKind("cpp")
    if suf == ".md":
        return FileKind("md")
    return None


def should_skip(path: Path, repo_root: Path, skip_dir_names: frozenset[str]) -> bool:
    try:
        rel = path.relative_to(repo_root)
    except ValueError:
        return True
    for p in rel.parts:
        if p in skip_dir_names:
            return True
        if p.startswith("build-"):
            return True
        if p.startswith(".") and p != ".github":
            return True
    s = str(path).replace("\\", "/")
    for frag in SKIP_PATH_SUBSTR:
        if frag in s:
            return True
    return False


def _markers_ok_plain(text: str) -> bool:
    return (
        SPDX_LINE in text
        and "Copyright (C)" in text
        and HOLDER in text
        and "Licensed under the Apache License, Version 2.0" in text
        and LAST_LINE in text
    )


def _markers_ok_md_inner(text: str) -> bool:
    """Validate inner Markdown HTML comment (SPDX is only in the outer `<!-- SPDX ... -->`)."""
    return (
        "Copyright (C)" in text
        and HOLDER in text
        and "Licensed under the Apache License, Version 2.0" in text
        and LAST_LINE in text
    )


def _is_license_hash_inner(inner: str) -> bool:
    s = inner.strip()
    if s == "":
        return True
    return (
        s.startswith("SPDX-License-Identifier:")
        or s.startswith("Copyright (C)")
        or s.startswith("Licensed under the Apache License")
        or s.startswith("you may not use")
        or s.startswith("You may obtain")
        or s.startswith("http://www.apache.org/licenses")
        or s.startswith("Unless required")
        or "distributed under the License is distributed" in s
        or s.startswith("WITHOUT WARRANTIES")
        or s.startswith("See the License")
        or LAST_LINE in s
    )


def _is_license_cpp_inner(rest: str) -> bool:
    s = rest.strip()
    if s == "":
        return True
    return (
        s.startswith("SPDX-License-Identifier:")
        or s.startswith("Copyright (C)")
        or s.startswith("Licensed under the Apache License")
        or s.startswith("you may not use")
        or s.startswith("You may obtain")
        or s.startswith("http://www.apache.org/licenses")
        or s.startswith("Unless required")
        or "distributed under the License is distributed" in s
        or s.startswith("WITHOUT WARRANTIES")
        or s.startswith("See the License")
        or LAST_LINE in s
    )


def _hash_inner_ok(block: list[str]) -> bool:
    inner_lines: list[str] = []
    for ln in block:
        if not ln.startswith("#"):
            return False
        inner_lines.append(ln[1:].lstrip())
    return _markers_ok_plain("\n".join(inner_lines))


def _cpp_inner_ok(block: list[str]) -> bool:
    parts: list[str] = []
    for ln in block:
        s = ln.strip()
        if not s.startswith("//"):
            return False
        parts.append(s[2:].lstrip())
    return _markers_ok_plain("\n".join(parts))


def _scan_hash_license_extent(lines: list[str], spdx_idx: int) -> tuple[int, bool]:
    """Return (end_exclusive, complete_through_limitations_line)."""
    k = spdx_idx
    while k < len(lines) and lines[k].startswith("#"):
        inner = lines[k][1:].lstrip()
        if LAST_LINE in inner:
            return k + 1, True
        if _is_license_hash_inner(inner):
            k += 1
            continue
        break
    return k, False


def _scan_cpp_license_extent(lines: list[str], spdx_idx: int) -> tuple[int, bool]:
    k = spdx_idx
    while k < len(lines):
        raw = lines[k]
        if raw.strip() == "":
            break
        if not raw.lstrip().startswith("//"):
            break
        rest = raw.strip()[2:].lstrip()
        if LAST_LINE in raw:
            return k + 1, True
        if _is_license_cpp_inner(rest):
            k += 1
            continue
        break
    return k, False


def repair_hash(content: str, year: int) -> tuple[str, bool]:
    lines = content.splitlines()
    trailing_nl = content.endswith("\n") if content else True

    out_prefix: list[str] = []
    i = 0
    if lines and lines[0].startswith("#!"):
        out_prefix.append(lines[0])
        i = 1

    while i < len(lines) and lines[i].strip() == "":
        i += 1

    spdx_idx = None
    for j in range(i, min(len(lines), i + 40)):
        if lines[j].startswith("# SPDX-License-Identifier:"):
            spdx_idx = j
            break

    header_lines = hash_header_text(year).splitlines()

    if spdx_idx is None:
        merged = out_prefix + header_lines + lines[i:]
        text = "\n".join(merged)
        if trailing_nl or text == "":
            text += "\n"
        return text, True

    end_exclusive, complete = _scan_hash_license_extent(lines, spdx_idx)
    old_block = lines[spdx_idx:end_exclusive]
    if complete and _hash_inner_ok(old_block):
        return content, False

    merged = out_prefix + header_lines + lines[end_exclusive:]
    text = "\n".join(merged)
    if trailing_nl or text == "":
        text += "\n"
    return text, True


def repair_cpp(content: str, year: int) -> tuple[str, bool]:
    lines = content.splitlines()
    trailing_nl = content.endswith("\n") if content else True

    i = 0
    while i < len(lines) and lines[i].strip() == "":
        i += 1

    spdx_idx = None
    for j in range(i, min(len(lines), i + 40)):
        if lines[j].lstrip().startswith("// SPDX-License-Identifier:"):
            spdx_idx = j
            break

    header_lines = cpp_header_text(year).splitlines()

    if spdx_idx is None:
        merged = header_lines + lines[i:]
        text = "\n".join(merged)
        if trailing_nl or text == "":
            text += "\n"
        return text, True

    end_exclusive, complete = _scan_cpp_license_extent(lines, spdx_idx)
    old_block = lines[spdx_idx:end_exclusive]
    if complete and _cpp_inner_ok(old_block):
        return content, False

    merged = header_lines + lines[end_exclusive:]
    text = "\n".join(merged)
    if trailing_nl or text == "":
        text += "\n"
    return text, True


def repair_md(content: str, year: int) -> tuple[str, bool]:
    bom = ""
    if content.startswith("\ufeff"):
        bom = "\ufeff"
    body = content[len(bom) :]

    m = MD_HEADER_RX.match(body)
    if m is not None and _markers_ok_md_inner(m.group(1)):
        return content, False

    fresh = md_header_text(year)
    if m is not None:
        new_body = fresh + body[m.end() :].lstrip("\n")
    else:
        new_body = fresh + body.lstrip("\n")

    out = bom + new_body
    if content.endswith("\n") or not content:
        if not out.endswith("\n"):
            out += "\n"
    return out, True


def process_file(path: Path, year: int, dry_run: bool) -> bool:
    kind = classify(path)
    if kind is None:
        return False
    text = path.read_text(encoding="utf-8")
    if kind.style == "hash":
        new_text, changed = repair_hash(text, year)
    elif kind.style == "cpp":
        new_text, changed = repair_cpp(text, year)
    else:
        new_text, changed = repair_md(text, year)

    if not changed:
        return False
    if dry_run:
        print(f"would update: {path}", file=sys.stderr)
        return True
    path.write_text(new_text, encoding="utf-8", newline="\n")
    print(f"updated: {path}", file=sys.stderr)
    return True


def iter_targets(repo_root: Path, skip_dir_names: frozenset[str]) -> list[Path]:
    out: list[Path] = []
    for p in repo_root.rglob("*"):
        if not p.is_file():
            continue
        if should_skip(p, repo_root, skip_dir_names):
            continue
        if classify(p) is None:
            continue
        out.append(p)
    out.sort()
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--repo-root",
        type=Path,
        default=Path.cwd(),
        help="Repository root (default: cwd)",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Print paths that would change without writing",
    )
    ap.add_argument(
        "--skip-dir-name",
        action="append",
        default=[],
        help="Directory name to skip anywhere under the repo root (repeatable).",
    )
    ap.add_argument(
        "--check",
        action="store_true",
        help="Exit with status 1 if any file is missing or has a non-standard header (implies --dry-run).",
    )
    args = ap.parse_args()
    repo_root = args.repo_root.resolve()
    skip_dir_names = SKIP_DIR_NAMES | frozenset(args.skip_dir_name)
    year = _year()
    dry_run = args.dry_run or args.check
    changed_any = False
    for path in iter_targets(repo_root, skip_dir_names):
        if process_file(path, year, dry_run):
            changed_any = True
    if args.check and changed_any:
        print("error: one or more files need license header updates (run without --check to fix)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
