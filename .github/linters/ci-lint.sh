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

# Lint driver for the pcsc-fido repository.
#
# Checks (in order):
#   0. License headers — SPDX + Apache-2.0 boilerplate (Python helper)
#   1. Auto-format     — spec-coverage.yaml, clang-format -i, markdownlint --fix, shfmt -w (optional)
#   2. Unsafe API guard — fail on unbounded/high-risk C APIs in project code
#   3. clang-format    — drift detection (--dry-run --Werror)
#   4. shellcheck      — bash scripts under .github/
#   5. markdownlint    — Markdown style (check mode)
#   6. codespell       — common misspelling detection (Markdown/docs via helper-codespell.sh)
#   8. CMake build + CTest — compile_commands.json for static analysis
#   9. cppcheck        — project tree via compile_commands.json
#
# Usage:
#   bash .github/linters/ci-lint.sh [--strict-tools]
#   make lint
#
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: .github/linters/ci-lint.sh [OPTIONS]

Run all lint, format, static-analysis, and unit tests for pcsc-fido.

Options:
  --strict-tools   Fail if any recommended lint tool is missing (useful in CI)
  -h, --help       Show this help and exit

Requires:
  python3 (license header normalization)
EOF
}

strict_tools=0
while (($# > 0)); do
  case "$1" in
    --strict-tools) strict_tools=1 ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      printf 'error: unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

linter_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$linter_dir/../.." && pwd)"
cd "$repo_root"

# shellcheck source=helper-markdownlint.sh
source "$linter_dir/helper-markdownlint.sh"

scripts_dir="$repo_root/.github/scripts"
clang_format_config="$linter_dir/.clang-format"
markdownlint_config="$linter_dir/.markdownlint.json"
clang_format_style="file:$clang_format_config"
lint_build_dir="${LINT_BUILD_DIR:-build/lint}"

shopt -s nullglob

c_files=(include/pcsc_fido/*.h src/*.c tests/*.c)
sh_files=("$scripts_dir"/*.sh "$linter_dir"/*.sh packaging/rpm/*.sh packaging/scripts/*.sh)
# Source-only libraries (not executed); shellcheck them via callers with -x if needed.
sh_source_only=(helper-container-bind-mount.sh helper-cross-targets.sh)
sh_check=()
for f in "${sh_files[@]}"; do
  base="$(basename -- "$f")"
  skip=0
  for lib in "${sh_source_only[@]}"; do
    if [[ $base == "$lib" ]]; then
      skip=1
      break
    fi
  done
  ((skip)) || sh_check+=("$f")
done
md_files=(README.md INSTALLATION.md RELEASE.md .github/release-notes.md docs/*.md)

have_tool() { command -v "$1" >/dev/null 2>&1; }

require_tool() {
  if ! have_tool "$1"; then
    printf 'error: required tool not found: %s\n' "$1" >&2
    exit 1
  fi
}

want_tool() {
  local tool="$1" purpose="$2"
  if have_tool "$tool"; then return 0; fi
  if [[ $strict_tools -eq 1 ]]; then
    printf 'error: recommended tool not found in --strict-tools mode: %s (%s)\n' "$tool" "$purpose" >&2
    exit 1
  fi
  printf 'skip: %s not installed (%s)\n' "$tool" "$purpose"
  return 1
}

want_markdownlint() {
  local purpose="$1"
  if pcsc_fido_ensure_markdownlint "$repo_root"; then
    return 0
  fi
  if [[ $strict_tools -eq 1 ]]; then
    printf 'error: recommended tool not found in --strict-tools mode: markdownlint (%s)\n' "$purpose" >&2
    pcsc_fido_markdownlint_hint
    exit 1
  fi
  printf 'skip: markdownlint not installed (%s)\n' "$purpose"
  return 1
}

run_markdownlint() {
  pcsc_fido_run_markdownlint "$@"
}

section() { printf '\n── %s ──\n' "$1"; }
run() {
  printf '+'
  printf ' %q' "$@"
  printf '\n'
  "$@"
}

scan_unsafe_c_apis() {
  local pattern='(^|[^[:alnum:]_])(strcpy|strcat|sprintf|vsprintf|gets|scanf|sscanf|fscanf|popen|system)[[:space:]]*\('
  local matches
  matches=$(
    grep -RInE \
      --include='*.c' \
      --include='*.h' \
      --exclude-dir=build \
      --exclude-dir=build-* \
      "$pattern" \
      include src tests 2>/dev/null || true
  )
  if [[ -n $matches ]]; then
    printf 'error: unsafe/unbounded C API usage detected:\n%s\n' "$matches" >&2
    exit 1
  fi
  printf 'unsafe API guard: OK\n'
}

section "License headers (SPDX / Apache-2.0)"
require_tool python3
run python3 "$linter_dir/helper-license-headers.py" --repo-root "$repo_root"
run python3 "$linter_dir/helper-license-headers.py" --repo-root "$repo_root" --check

section "Auto-formatting"
if python3 -c "import yaml" >/dev/null 2>&1; then
  run python3 "$scripts_dir/helper-spec-coverage-format.py" --write --repo-root "$repo_root"
elif [[ $strict_tools -eq 1 ]]; then
  printf 'error: PyYAML not found (install python3-yaml or: pip install pyyaml)\n' >&2
  exit 1
else
  printf 'skip: PyYAML not installed (spec-coverage.yaml formatting)\n'
fi
if want_markdownlint "Markdown formatting"; then
  ((${#md_files[@]} > 0)) && run_markdownlint --config "$markdownlint_config" --fix "${md_files[@]}" || true
fi
if want_tool clang-format "C/C++ formatting"; then
  for file in "${c_files[@]}"; do
    clang-format -i --style="$clang_format_style" "$file"
  done
fi
if want_tool shfmt "shell formatting"; then
  ((${#sh_check[@]} > 0)) && shfmt -w -i 2 -ci -s "${sh_check[@]}" || true
fi

section "Spec coverage (spec-coverage.yaml)"
if python3 -c "import yaml" >/dev/null 2>&1; then
  run python3 "$scripts_dir/helper-spec-coverage-check.py" --repo-root "$repo_root"
elif [[ $strict_tools -eq 1 ]]; then
  printf 'error: PyYAML not found (install python3-yaml or: pip install pyyaml)\n' >&2
  exit 1
else
  printf 'skip: PyYAML not installed (spec coverage)\n'
fi

section "systemd unit (packaged service file)"
run bash "$scripts_dir/verify-systemd-unit.sh"
run bash "$scripts_dir/verify-pcsc-integration.sh"

section "Unsafe API guard"
scan_unsafe_c_apis

section "clang-format (drift check)"
if want_tool clang-format "format drift detection"; then
  for file in "${c_files[@]}"; do
    run clang-format --dry-run --Werror --style="$clang_format_style" "$file"
  done
fi

section "shellcheck"
if want_tool shellcheck "bash script linting"; then
  ((${#sh_check[@]} > 0)) && run shellcheck -S warning -x -P SCRIPTDIR "${sh_check[@]}"
fi

section "markdownlint"
if want_markdownlint "Markdown style"; then
  ((${#md_files[@]} > 0)) && run run_markdownlint --config "$markdownlint_config" "${md_files[@]}"
fi

section "codespell"
if want_tool codespell "common misspelling detection"; then
  run bash "$linter_dir/helper-codespell.sh"
fi

cppcheck_common=(
  --quiet
  "--enable=warning,style,performance,portability"
  --inconclusive
  --error-exitcode=1
  --inline-suppr
  --suppress=missingIncludeSystem
  --suppress=constParameterCallback
  --suppress=normalCheckLevelMaxBranches
)

section "CMake build + CTest"
require_tool cmake
require_tool ctest
lint_jobs="$(nproc 2>/dev/null || echo 2)"
release_lint_build_dir="${lint_build_dir}-release"
if [[ ${LINT_FRESH_BUILD:-0} == 1 ]]; then
  rm -rf "$lint_build_dir"
  rm -rf "$release_lint_build_dir"
fi
run cmake -S . -B "$lint_build_dir" \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -DBUILD_TESTING=ON
run cmake --build "$lint_build_dir" --target pcsc_fido_unit_tests -j"${lint_jobs}"
run ctest --test-dir "$lint_build_dir" --output-on-failure

section "Release ELF hardening"
release_dest="${release_lint_build_dir}/.install-hardening"
run cmake -S . -B "$release_lint_build_dir" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=/usr \
  -DBUILD_TESTING=OFF
run cmake --build "$release_lint_build_dir" --target pcsc-fido -j"${lint_jobs}"
rm -rf "$release_dest"
run env DESTDIR="$release_dest" cmake --install "$release_lint_build_dir" --strip
run bash "$scripts_dir/verify-release-elf-hardening.sh" "$release_dest/usr/bin/pcsc-fido"

section "cppcheck"
if want_tool cppcheck "static analysis"; then
  cc_json="$lint_build_dir/compile_commands.json"
  [[ -f $cc_json ]] || {
    printf 'error: compile_commands.json missing after configure\n' >&2
    exit 1
  }
  run cppcheck "${cppcheck_common[@]}" --project="$cc_json"
fi

printf '\nAll lint checks passed.\n'
