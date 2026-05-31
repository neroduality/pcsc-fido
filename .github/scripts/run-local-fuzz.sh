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

# Build and run local libFuzzer harnesses for cbor_util, request_assembly, and apdu.
#
# Usage:
#   bash .github/scripts/run-local-fuzz.sh
#   FUZZ_SECONDS=600 bash .github/scripts/run-local-fuzz.sh
#   bash .github/scripts/run-local-fuzz.sh --build-only
#
set -euo pipefail

# CTAPHID payload cap (include/pcsc_fido/ctaphid.h) and max framed reassembly size
# (7609 = 57 + 128×59) as 129×64-byte HID reports (8256 bytes).
readonly PCSC_FIDO_CTAPHID_MAX_PAYLOAD=8192
readonly PCSC_FIDO_CTAPHID_MAX_FRAMED_PACKET_STREAM=8256

usage() {
  cat <<'EOF'
Run local libFuzzer harnesses (Clang recommended).

Usage:
  bash .github/scripts/run-local-fuzz.sh [options]

Options:
  --build-only     Configure and build fuzz targets; do not run libFuzzer
  -h, --help       Show this help

Environment:
  CC                       Clang recommended (CC=gcc/cc ignored until clang is tried)
  PCSC_FIDO_AUTO_FUZZ_DEPS Set to 1 to run install-linux-deps.sh once on probe failure
  FUZZ_BUILD_DIR           Default: .fuzz (host-only; not used by container CI)
  FUZZ_SECONDS             Per-target max wall time (default: 180)
  FUZZ_VERBOSITY           libFuzzer -verbosity (default: 1; use 0 for quiet)
  FUZZ_MAX_LEN_CBOR        Max input bytes for fuzz_cbor_util (default: 8192)
  FUZZ_MAX_LEN_CTAPHID     Max input bytes for fuzz_request_assembly (default: 8256)
  FUZZ_UNIT_TIMEOUT_SEC    Per-input timeout seconds (default: 10)
  FUZZ_ARTIFACT_DIR        Crashers/reproducers (default: .fuzz/fuzz-artifacts)

Targets:
  fuzz_cbor_util           CBOR skip/read bounds in cbor_util.c
  fuzz_request_assembly    CTAPHID packet reassembly in request_assembly.c
  fuzz_apdu                APDU parse/pack in apdu.c

On crash: ASan/UBSan report on stderr, non-zero exit, reproducer under FUZZ_ARTIFACT_DIR.
EOF
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=helper-fuzz-probe.sh
source "${repo_root}/.github/scripts/helper-fuzz-probe.sh"

build_dir="${FUZZ_BUILD_DIR:-${repo_root}/.fuzz}"
artifact_dir="${FUZZ_ARTIFACT_DIR:-${build_dir}/fuzz-artifacts}"
fuzz_seconds="${FUZZ_SECONDS:-180}"
fuzz_verbosity="${FUZZ_VERBOSITY:-1}"
fuzz_max_len_cbor="${FUZZ_MAX_LEN_CBOR:-${PCSC_FIDO_CTAPHID_MAX_PAYLOAD}}"
fuzz_max_len_ctaphid="${FUZZ_MAX_LEN_CTAPHID:-${PCSC_FIDO_CTAPHID_MAX_FRAMED_PACKET_STREAM}}"
fuzz_unit_timeout="${FUZZ_UNIT_TIMEOUT_SEC:-10}"
build_only=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --build-only)
      build_only=1
      shift
      ;;
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
done

if [[ "$(id -u)" -eq 0 ]]; then
  printf 'error: do not run fuzz builds as root (host-only; use your normal user)\n' >&2
  exit 1
fi

if [[ -n ${PCSC_FIDO_IN_CONTAINER:-} ]]; then
  printf 'error: fuzz runs on the host only, not inside container CI\n' >&2
  exit 1
fi

probe_src="$(mktemp --suffix=.c)"
probe_bin="$(mktemp --suffix=.out)"
cleanup() {
  rm -f "$probe_src" "$probe_bin"
}
trap cleanup EXIT

cat >"$probe_src" <<'EOF'
#include <stddef.h>
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  (void)data;
  (void)size;
  return 0;
}
EOF

if ! resolved="$(pcsc_fido_resolve_fuzz_compiler "${probe_src}" "${probe_bin}")"; then
  if [[ ${PCSC_FIDO_AUTO_FUZZ_DEPS:-0} == 1 ]]; then
    AUTO_INSTALL_LINUX_DEPS=1 PCSC_FIDO_ALLOW_SUDO_DEPS=1 \
      bash "${repo_root}/.github/scripts/install-linux-deps.sh" || true
    resolved="$(pcsc_fido_resolve_fuzz_compiler "${probe_src}" "${probe_bin}")" || resolved=""
  fi
  if [[ -z ${resolved} ]]; then
    printf 'error: no C compiler with libFuzzer (-fsanitize=fuzzer)\n' >&2
    pcsc_fido_fuzz_install_hint
    exit 1
  fi
fi
cc="${resolved%%$'\t'*}"
fuzz_sanitize="${resolved#*$'\t'}"

setup_corpus() {
  local corpus_root="$1"
  mkdir -p \
    "${corpus_root}/cbor" \
    "${corpus_root}/ctaphid" \
    "${corpus_root}/apdu" \
    "${artifact_dir}/cbor" \
    "${artifact_dir}/ctaphid" \
    "${artifact_dir}/apdu"

  # Seeds derived from tests/test_cbor_util.c vectors.
  printf '\x44test' >"${corpus_root}/cbor/bytes"
  printf '\x82\x01\x02' >"${corpus_root}/cbor/array"
  printf '\xA2\x01\x02\x03\x04' >"${corpus_root}/cbor/map"
  python3 - "${corpus_root}/cbor/nested_limit" <<'PY'
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
payload = bytes([0x81] * 32 + [0x00])
path.write_bytes(payload)
PY

  # Large in-bounds byte string header (length 8192) for max_len coverage.
  python3 - "${corpus_root}/cbor/large_bytes_header" "${PCSC_FIDO_CTAPHID_MAX_PAYLOAD}" <<'PY'
import pathlib
import struct
import sys
max_len = int(sys.argv[2])
path = pathlib.Path(sys.argv[1])
path.write_bytes(bytes([0x5A]) + struct.pack(">I", max_len))
PY

  # Single CTAPHID INIT (PING, 1-byte payload) — tests/test_request_assembly.c pattern.
  python3 - "${corpus_root}/ctaphid/single_ping" <<'PY'
import pathlib
import sys
packet = bytearray(64)
packet[0:4] = bytes([0x01, 0x02, 0x03, 0x04])
packet[4] = 0x80 | 0x01  # INIT + PING
packet[5] = 0x00
packet[6] = 0x01
packet[7] = 0x04
pathlib.Path(sys.argv[1]).write_bytes(packet)
PY

  # INIT + one continuation (80-byte logical payload).
  python3 - "${corpus_root}/ctaphid/multi_packet" <<'PY'
import pathlib
import sys
request = bytes([0x01]) + bytes([0xA5] * 79)
init = bytearray(64)
init[0:4] = bytes([0x01, 0x02, 0x03, 0x04])
init[4] = 0x80 | 0x90  # INIT + CBOR
init[5] = 0x00
init[6] = len(request)
init[7:7 + 57] = request[:57]
cont = bytearray(64)
cont[0:4] = bytes([0x01, 0x02, 0x03, 0x04])
cont[4] = 0x00
cont[5:5 + 23] = request[57:]
pathlib.Path(sys.argv[1]).write_bytes(init + cont)
PY

  # Max framed CTAPHID payload (7609 bytes) as a 64-byte packet stream.
  python3 - "${corpus_root}/ctaphid/multi_packet_max_framed" <<'PY'
import pathlib
import sys

FRAMED_MAX = 7609
INIT_PAYLOAD = 57
CONT_PAYLOAD = 59
request = bytes([0x01]) + bytes([0xA5] * (FRAMED_MAX - 1))
packets = bytearray()
init = bytearray(64)
init[0:4] = bytes([0x01, 0x02, 0x03, 0x04])
init[4] = 0x80 | 0x90
init[5] = (FRAMED_MAX >> 8) & 0xFF
init[6] = FRAMED_MAX & 0xFF
init[7:7 + INIT_PAYLOAD] = request[:INIT_PAYLOAD]
packets.extend(init)
remaining = request[INIT_PAYLOAD:]
seq = 0
while remaining:
    cont = bytearray(64)
    cont[0:4] = bytes([0x01, 0x02, 0x03, 0x04])
    cont[4] = seq & 0xFF
    chunk = remaining[:CONT_PAYLOAD]
    cont[5:5 + len(chunk)] = chunk
    packets.extend(cont)
    remaining = remaining[len(chunk):]
    seq += 1
pathlib.Path(sys.argv[1]).write_bytes(packets)
PY

  # SELECT and short CTAP APDUs — tests/test_apdu.c vectors.
  printf '\x00\xA4\x04\x00\x08\xA0\x00\x00\x06\x47\x2F\x00\x01' >"${corpus_root}/apdu/select_fido"
  printf '\x80\x10\x00\x00\x03\x04\xA1\x00\x00' >"${corpus_root}/apdu/short_ctap"
}

corpus_root="${build_dir}/corpus"
setup_corpus "$corpus_root"

printf '── fuzz configure (%s; -fsanitize=%s) ──\n' "$cc" "$fuzz_sanitize"
cmake -S "$repo_root" -B "$build_dir" \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_COMPILER="$cc" \
  -DBUILD_TESTING=OFF \
  -DPCSC_FIDO_BUILD_FUZZING=ON \
  -DPCSC_FIDO_DEBUG_SANITIZERS=OFF \
  -DPCSC_FIDO_ENABLE_ASAN=OFF \
  -DPCSC_FIDO_ENABLE_UBSAN=OFF \
  -DPCSC_FIDO_ENABLE_TSAN=OFF \
  -DPCSC_FIDO_ENABLE_COVERAGE=OFF

printf '── fuzz build ──\n'
cmake --build "$build_dir" --target pcsc_fido_fuzzers -j"$(nproc 2>/dev/null || echo 2)"

if [[ $build_only -eq 1 ]]; then
  printf 'fuzz build: OK (%s)\n' "$build_dir"
  exit 0
fi

run_fuzzer() {
  local name="$1"
  local corpus_subdir="$2"
  local max_len="$3"
  local bin="${build_dir}/${name}"
  local corpus="${corpus_root}/${corpus_subdir}"
  local artifacts="${artifact_dir}/${corpus_subdir}"

  printf '── %s (max_total_time=%ss, max_len=%s, timeout=%ss) ──\n' \
    "$name" "$fuzz_seconds" "$max_len" "$fuzz_unit_timeout"
  printf 'note: libFuzzer runs up to %ss per target; progress lines below (quick check: FUZZ_SECONDS=30 make fuzz)\n' \
    "$fuzz_seconds"
  if ! "$bin" "$corpus" -runs=0 -max_len="$max_len" -timeout="$fuzz_unit_timeout"; then
    printf 'error: %s corpus reload failed\n' "$name" >&2
    return 1
  fi
  if ! "$bin" "$corpus" \
    -artifact_prefix="${artifacts}/" \
    -max_total_time="$fuzz_seconds" \
    -max_len="$max_len" \
    -timeout="$fuzz_unit_timeout" \
    -print_final_stats=1 \
    -verbosity="$fuzz_verbosity" \
    -report_slow_units=1; then
    printf 'error: %s reported findings (see %s)\n' "$name" "${artifacts}/" >&2
    return 1
  fi
}

pcsc_fido_run_fuzz_targets() {
  local -a specs=(
    "fuzz_cbor_util|cbor|${fuzz_max_len_cbor}"
    "fuzz_request_assembly|ctaphid|${fuzz_max_len_ctaphid}"
    "fuzz_apdu|apdu|${fuzz_max_len_cbor}"
  )
  local spec name subdir max_len

  for spec in "${specs[@]}"; do
    IFS='|' read -r name subdir max_len <<<"${spec}"
    run_fuzzer "${name}" "${subdir}" "${max_len}"
  done
}

pcsc_fido_run_fuzz_targets

printf 'fuzz: OK (san=%s; artifacts under %s on crash)\n' "$fuzz_sanitize" "$artifact_dir"
