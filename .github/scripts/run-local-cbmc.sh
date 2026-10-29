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

# Bounded model checking for the APDU, CBOR, and CTAPHID reassembly parsers.
#
# Usage:
#   bash .github/scripts/run-local-cbmc.sh
#   CBMC=/usr/bin/cbmc bash .github/scripts/run-local-cbmc.sh
#
set -euo pipefail

usage() {
  cat <<'EOF'
Run CBMC on the APDU, CBOR, and CTAPHID reassembly parsers.

Usage:
  bash .github/scripts/run-local-cbmc.sh
  make cbmc

Requires cbmc on PATH plus the C library headers (Debian: cbmc libc6-dev).
CBMC is not installed by make deps.

Proofs (each bound is what finishes with --unwinding-assertions; a fully
nondeterministic 8192-byte buffer does not):
  cbmc_apdu              parse every input in the bridge buffer; pack every
                         payload up to CBMC_APDU_PAYLOAD_MAX (default 300,
                         short and extended Lc) and reject every claimed
                         length above the CTAPHID cap
  cbmc_cbor_read         every length and offset in CBMC_CBOR_READ_MAX
                         (default 16) bytes; a reader consumes at most one
                         byte plus an 8-byte argument
  cbmc_cbor_skip         every input up to CBMC_CBOR_SKIP_MAX (default 32)
                         bytes whose arrays and maps claim at most
                         CBMC_CBOR_SKIP_ITEMS (default 2) elements. Nesting
                         past CBMC_CBOR_SKIP_DEPTH (default 2) is rejected by
                         the proof model and not walked. Needs --object-bits
                         16 (the recursive unwind exceeds the default 256
                         object ids)
  cbmc_request_assembly  one-packet induction: copied length stays in the
                         pending buffer and an open request stays within the
                         7609-byte CTAPHID frame cap. The 8192-byte payload
                         copy is checked as a span, not expanded into SAT.

EOF
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
  usage
  exit 0
fi
if [[ $# -ne 0 ]]; then
  printf 'error: unexpected argument: %s\n' "$1" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cbmc_bin="${CBMC:-cbmc}"
if ! command -v "${cbmc_bin}" >/dev/null 2>&1; then
  printf 'error: cbmc not found (install the cbmc package)\n' >&2
  exit 1
fi

# Defaults match the #ifndef fallbacks in the harnesses and cbor_util.c.
# CBMC's unwinding assertion checks the iteration past the last one, so a
# container of N items needs a loop unwind of N+1. The map key/value loop
# runs exactly twice and needs the same +1.
apdu_payload_max="${CBMC_APDU_PAYLOAD_MAX:-300}"
read_max="${CBMC_CBOR_READ_MAX:-16}"
skip_max="${CBMC_CBOR_SKIP_MAX:-32}"
skip_items="${CBMC_CBOR_SKIP_ITEMS:-2}"
skip_depth="${CBMC_CBOR_SKIP_DEPTH:-2}"
skip_loop_unwind=$((skip_items + 1))

cd "${repo_root}"

common=(
  --bounds-check
  --pointer-check
  --pointer-overflow-check
  --signed-overflow-check
  --unsigned-overflow-check
  --unwinding-assertions
  --drop-unused-functions
  -I include
  -I tests/cbmc/stubs
  -DPCSC_FIDO_CBMC
)

run_proof() {
  local name="$1"
  shift
  printf '\n-- CBMC %s --\n' "${name}"
  if ! "${cbmc_bin}" "${common[@]}" "$@"; then
    printf 'error: CBMC proof failed: %s\n' "${name}" >&2
    exit 1
  fi
}

run_proof apdu --unwind 16 \
  -DPCSC_FIDO_CBMC_APDU_PAYLOAD_MAX="${apdu_payload_max}" \
  tests/cbmc/cbmc_apdu.c src/apdu.c src/mem_util.c

run_proof cbor-read --unwind 16 \
  -DPCSC_FIDO_CBMC_CBOR_READ_MAX="${read_max}" \
  tests/cbmc/cbmc_cbor_read.c src/cbor_util.c src/mem_util.c

# Recursion unwind is the depth cap (a deeper call returns before recursing).
# Loop unwind is items+1. --object-bits 16: the recursive copies exceed
# CBMC's default 256 object ids.
run_proof cbor-skip --object-bits 16 \
  --unwind "${skip_depth}" \
  --unwindset "cbor_skip_item_depth.0:${skip_loop_unwind},cbor_skip_item_depth.1:${skip_loop_unwind},cbor_skip_item_depth.2:${skip_loop_unwind}" \
  -DPCSC_FIDO_CBMC_CBOR_SKIP_MAX="${skip_max}" \
  -DPCSC_FIDO_CBMC_CBOR_SKIP_ITEMS="${skip_items}" \
  -DPCSC_FIDO_CBMC_CBOR_SKIP_DEPTH="${skip_depth}" \
  tests/cbmc/cbmc_cbor_skip.c src/cbor_util.c src/mem_util.c

run_proof request-assembly --unwind 4 \
  tests/cbmc/cbmc_request_assembly.c \
  src/request_assembly.c src/daemon_hid.c

printf '\n-- CBMC proofs passed --\n'
