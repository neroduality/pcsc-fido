// SPDX-License-Identifier: Apache-2.0
//
// Copyright (C) 2026 Nero Duality, LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "pcsc_fido/apdu.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void expect_true(int condition, const char *message) {
  if (!condition) {
    fprintf(stderr, "FAIL: %s\n", message);
    failures++;
  }
}

static void parses_select(void) {
  const uint8_t apdu[] = {0x00u, 0xA4u, 0x04u, 0x00u, 0x08u, 0xA0u, 0x00u,
                          0x00u, 0x06u, 0x47u, 0x2Fu, 0x00u, 0x01u};
  const pcsc_fido_apdu_t parsed = pcsc_fido_parse_apdu(apdu, sizeof(apdu));
  expect_true(parsed.kind == PCSC_FIDO_APDU_SELECT, "SELECT FIDO AID parsed");
  expect_true(parsed.sw1 == 0x90u && parsed.sw2 == 0x00u, "SELECT status is 9000");
}

static void packs_select_fido(void) {
  const uint8_t expected_no_le[] = {0x00u, 0xA4u, 0x04u, 0x00u, 0x08u, 0xA0u, 0x00u,
                                    0x00u, 0x06u, 0x47u, 0x2Fu, 0x00u, 0x01u};
  const uint8_t expected_with_le[] = {0x00u, 0xA4u, 0x04u, 0x00u, 0x08u, 0xA0u, 0x00u,
                                      0x00u, 0x06u, 0x47u, 0x2Fu, 0x00u, 0x01u, 0x00u};
  uint8_t apdu[PCSC_FIDO_SELECT_APDU_MAX];
  size_t apdu_len = 0u;
  expect_true(pcsc_fido_pack_select_fido_apdu(apdu, sizeof(apdu), &apdu_len, false),
              "pack SELECT without Le");
  expect_true(apdu_len == sizeof(expected_no_le) &&
                memcmp(apdu, expected_no_le, sizeof(expected_no_le)) == 0,
              "SELECT without Le layout");
  expect_true(pcsc_fido_pack_select_fido_apdu(apdu, sizeof(apdu), &apdu_len, true),
              "pack SELECT with Le");
  expect_true(apdu_len == sizeof(expected_with_le) &&
                memcmp(apdu, expected_with_le, sizeof(expected_with_le)) == 0,
              "SELECT with Le layout");
  expect_true(!pcsc_fido_pack_select_fido_apdu(apdu, 5u, &apdu_len, false),
              "reject undersized SELECT buffer");
}

static void parses_short_ctap(void) {
  const uint8_t apdu[] = {0x80u, 0x10u, 0x00u, 0x00u, 0x03u, 0x04u, 0xA1u, 0x00u, 0x00u};
  const pcsc_fido_apdu_t parsed = pcsc_fido_parse_apdu(apdu, sizeof(apdu));
  expect_true(parsed.kind == PCSC_FIDO_APDU_CTAP, "short CTAP APDU parsed");
  expect_true(parsed.hid_cmd == PCSC_FIDO_CTAPHID_CBOR, "short CTAP maps to HID CBOR");
  expect_true(parsed.payload_len == 3u, "short CTAP payload length");
  expect_true(parsed.payload != nullptr && parsed.payload[0] == 0x04u, "short CTAP payload starts");
}

static void packs_short_ctap(void) {
  const uint8_t payload[] = {0x04u, 0xA1u, 0x00u};
  uint8_t apdu[16];
  size_t apdu_len = 0u;
  pcsc_fido_apdu_t parsed;
  expect_true(
    pcsc_fido_pack_ctap2_cbor_apdu(payload, sizeof(payload), apdu, sizeof(apdu), &apdu_len),
    "pack short CTAP APDU");
  expect_true(apdu_len == 9u && apdu[4] == sizeof(payload) && apdu[8] == 0x00u,
              "short CTAP APDU layout");
  parsed = pcsc_fido_parse_apdu(apdu, apdu_len);
  expect_true(parsed.kind == PCSC_FIDO_APDU_CTAP && parsed.payload_len == sizeof(payload),
              "packed short CTAP parses");
}

static void parses_extended_ctap(void) {
  const uint8_t apdu[] = {0x80u, 0x10u, 0x00u, 0x00u, 0x00u, 0x00u,
                          0x03u, 0x04u, 0xA1u, 0x00u, 0x00u, 0x00u};
  const pcsc_fido_apdu_t parsed = pcsc_fido_parse_apdu(apdu, sizeof(apdu));
  expect_true(parsed.kind == PCSC_FIDO_APDU_CTAP, "extended CTAP APDU parsed");
  expect_true(parsed.payload_len == 3u, "extended CTAP payload length");
}

static void packs_extended_ctap(void) {
  uint8_t payload[300];
  uint8_t apdu[320];
  size_t apdu_len = 0u;
  pcsc_fido_apdu_t parsed;
  memset(payload, 0xA5, sizeof(payload));
  payload[0] = 0x01u;
  expect_true(
    pcsc_fido_pack_ctap2_cbor_apdu(payload, sizeof(payload), apdu, sizeof(apdu), &apdu_len),
    "pack extended CTAP APDU");
  expect_true(apdu_len == sizeof(payload) + 9u && apdu[4] == 0x00u && apdu[5] == 0x01u &&
                apdu[6] == 0x2Cu && apdu[apdu_len - 2u] == 0x00u && apdu[apdu_len - 1u] == 0x00u,
              "extended CTAP APDU layout");
  parsed = pcsc_fido_parse_apdu(apdu, apdu_len);
  expect_true(parsed.kind == PCSC_FIDO_APDU_CTAP && parsed.payload_len == sizeof(payload),
              "packed extended CTAP parses");
}

static void packs_short_and_extended_boundaries(void) {
  uint8_t payload[256];
  uint8_t apdu[270];
  size_t apdu_len = 0u;
  memset(payload, 0xA5, sizeof(payload));
  payload[0] = 0x01u;

  expect_true(pcsc_fido_pack_ctap2_cbor_apdu(payload, 255u, apdu, sizeof(apdu), &apdu_len),
              "pack 255-byte short CTAP APDU");
  expect_true(apdu_len == 261u && apdu[4] == 255u, "255-byte payload uses short APDU");

  expect_true(pcsc_fido_pack_ctap2_cbor_apdu(payload, 256u, apdu, sizeof(apdu), &apdu_len),
              "pack 256-byte extended CTAP APDU");
  expect_true(apdu_len == 265u && apdu[4] == 0x00u && apdu[5] == 0x01u && apdu[6] == 0x00u,
              "256-byte payload uses extended APDU");
}

static void rejects_invalid_pack_arguments(void) {
  const uint8_t payload[] = {0x04u, 0xA1u, 0x00u};
  uint8_t apdu[4];
  size_t apdu_len = 0u;
  expect_true(
    !pcsc_fido_pack_ctap2_cbor_apdu(payload, sizeof(payload), apdu, sizeof(apdu), &apdu_len),
    "too-small APDU output rejected");
  expect_true(
    !pcsc_fido_pack_ctap2_cbor_apdu(nullptr, sizeof(payload), apdu, sizeof(apdu), &apdu_len),
    "nullptr payload rejected when length is nonzero");
}

static void appends_status(void) {
  uint8_t out[4] = {0xAAu, 0xBBu, 0x00u, 0x00u};
  size_t out_len = 0u;
  expect_true(pcsc_fido_append_status(out, sizeof(out), 2u, 0x90u, 0x00u, &out_len),
              "append status succeeds");
  expect_true(out_len == 4u && out[2] == 0x90u && out[3] == 0x00u, "status bytes appended");
}

static void rejects_unsupported_and_malformed_apdu(void) {
  pcsc_fido_apdu_t parsed;
  const uint8_t too_short[] = {0x00u, 0xA4u, 0x04u};
  const uint8_t bad_select[] = {0x00u, 0xA4u, 0x04u, 0x00u, 0x08u, 0x00u};
  const uint8_t bad_ctap_lc[] = {0x80u, 0x10u, 0x00u, 0x00u, 0x00u, 0x00u};
  const uint8_t bad_ctap_len[] = {0x80u, 0x10u, 0x00u, 0x00u, 0x02u, 0x04u, 0x00u};
  const uint8_t unsupported_ins[] = {0x00u, 0x11u, 0x00u, 0x00u, 0x00u};
  parsed = pcsc_fido_parse_apdu(nullptr, 4u);
  expect_true(parsed.kind == PCSC_FIDO_APDU_UNSUPPORTED && parsed.sw1 == 0x67u,
              "nullptr APDU returns wrong length");
  parsed = pcsc_fido_parse_apdu(too_short, sizeof(too_short));
  expect_true(parsed.kind == PCSC_FIDO_APDU_UNSUPPORTED && parsed.sw1 == 0x67u,
              "short APDU returns wrong length");
  parsed = pcsc_fido_parse_apdu(bad_select, sizeof(bad_select));
  expect_true(parsed.kind == PCSC_FIDO_APDU_UNSUPPORTED && parsed.sw1 == 0x6Du,
              "bad SELECT returns INS not supported");
  parsed = pcsc_fido_parse_apdu(bad_ctap_lc, sizeof(bad_ctap_lc));
  expect_true(parsed.kind == PCSC_FIDO_APDU_UNSUPPORTED && parsed.sw1 == 0x67u,
              "zero Lc CTAP rejected");
  parsed = pcsc_fido_parse_apdu(bad_ctap_len, sizeof(bad_ctap_len));
  expect_true(parsed.kind == PCSC_FIDO_APDU_UNSUPPORTED && parsed.sw1 == 0x67u,
              "length mismatch CTAP rejected");
  parsed = pcsc_fido_parse_apdu(unsupported_ins, sizeof(unsupported_ins));
  expect_true(parsed.kind == PCSC_FIDO_APDU_UNSUPPORTED && parsed.sw1 == 0x6Du,
              "unsupported INS rejected");
}

static void append_status_failures(void) {
  uint8_t out[3];
  size_t out_len = 0u;
  expect_true(!pcsc_fido_append_status(nullptr, sizeof(out), 0u, 0x90u, 0x00u, &out_len),
              "append status nullptr out rejected");
  expect_true(!pcsc_fido_append_status(out, sizeof(out), 2u, 0x90u, 0x00u, &out_len),
              "append status small buffer rejected");
  expect_true(!pcsc_fido_append_status(out, sizeof(out), (size_t)-1, 0x90u, 0x00u, &out_len),
              "append status overflow rejected");
}

static void packs_zero_length_and_rejects_oversize(void) {
  uint8_t apdu[16];
  size_t apdu_len = 0u;
  pcsc_fido_apdu_t parsed;
  const uint8_t empty_payload = 0u;
  expect_true(pcsc_fido_pack_ctap2_cbor_apdu(&empty_payload, 0u, apdu, sizeof(apdu), &apdu_len),
              "zero-length payload packs");
  parsed = pcsc_fido_parse_apdu(apdu, apdu_len);
  expect_true(parsed.kind == PCSC_FIDO_APDU_UNSUPPORTED && parsed.sw1 == 0x67u,
              "zero-length packed APDU rejected on parse");
  {
    uint8_t huge[65536];
    memset(huge, 0xA5, sizeof(huge));
    expect_true(!pcsc_fido_pack_ctap2_cbor_apdu(huge, sizeof(huge), apdu, sizeof(apdu), &apdu_len),
                "65536-byte payload rejected");
  }
}

int main(void) {
  parses_select();
  packs_select_fido();
  parses_short_ctap();
  packs_short_ctap();
  parses_extended_ctap();
  packs_extended_ctap();
  packs_short_and_extended_boundaries();
  rejects_invalid_pack_arguments();
  appends_status();
  rejects_unsupported_and_malformed_apdu();
  append_status_failures();
  packs_zero_length_and_rejects_oversize();
  return failures == 0 ? 0 : 1;
}
