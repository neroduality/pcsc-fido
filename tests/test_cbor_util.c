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

#include "pcsc_fido/cbor_util.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures;

static void expect_true(int condition, const char *message) {
  if (!condition) {
    fprintf(stderr, "FAIL: %s\n", message);
    failures++;
  }
}

static void null_argument_guards(void) {
  size_t off = 0u;
  size_t value = 0u;
  bool flag = false;
  bool matches = false;
  expect_true(!pcsc_fido_cbor_read_len(24u, nullptr, 1u, &off, &value), "read_len null data");
  expect_true(!pcsc_fido_cbor_read_type_len(nullptr, 1u, &off, 5u, &value), "type_len null data");
  expect_true(!pcsc_fido_cbor_skip_item(nullptr, 1u, &off), "skip null data");
  expect_true(!pcsc_fido_cbor_read_bool_value(nullptr, 1u, &off, &flag), "bool null data");
  expect_true(!pcsc_fido_cbor_read_text_key_matches(nullptr, 1u, &off, "up", &matches),
              "text key null data");
}

static void read_len_encodings(void) {
  const uint8_t one_byte[] = {0x18u};
  const uint8_t two_byte[] = {0x00u, 0x19u};
  const uint8_t four_byte[] = {0x00u, 0x00u, 0x00u, 0x1Au};
  size_t off = 0u;
  size_t value = 0u;
  expect_true(pcsc_fido_cbor_read_len(24u, one_byte, sizeof(one_byte), &off, &value) &&
                value == 0x18u,
              "additional 24");
  off = 0u;
  expect_true(pcsc_fido_cbor_read_len(25u, two_byte, sizeof(two_byte), &off, &value) &&
                value == 0x19u,
              "additional 25");
  off = 0u;
  expect_true(pcsc_fido_cbor_read_len(26u, four_byte, sizeof(four_byte), &off, &value) &&
                value == 0x1Au,
              "additional 26");
}

static void skip_major_types(void) {
  const uint8_t bytes[] = {0x44u, 't', 'e', 's', 't'};
  const uint8_t text[] = {0x64u, 't', 'e', 's', 't'};
  const uint8_t array[] = {0x82u, 0x01u, 0x02u};
  const uint8_t map[] = {0xA2u, 0x01u, 0x02u, 0x03u, 0x04u};
  const uint8_t tagged[] = {0xC2u, 0x01u};
  const uint8_t float64[] = {0xFBu, 0x40u, 0x09u, 0x21u, 0xFBu, 0x54u, 0x68u, 0x7Eu, 0x67u};
  size_t off;
  off = 0u;
  expect_true(pcsc_fido_cbor_skip_item(bytes, sizeof(bytes), &off) && off == sizeof(bytes),
              "skip byte string");
  off = 0u;
  expect_true(pcsc_fido_cbor_skip_item(text, sizeof(text), &off) && off == sizeof(text),
              "skip text string");
  off = 0u;
  expect_true(pcsc_fido_cbor_skip_item(array, sizeof(array), &off) && off == sizeof(array),
              "skip array");
  off = 0u;
  expect_true(pcsc_fido_cbor_skip_item(map, sizeof(map), &off) && off == sizeof(map), "skip map");
  off = 0u;
  expect_true(pcsc_fido_cbor_skip_item(tagged, sizeof(tagged), &off) && off == sizeof(tagged),
              "skip tag");
  off = 0u;
  expect_true(pcsc_fido_cbor_skip_item(float64, sizeof(float64), &off) && off == sizeof(float64),
              "skip float64");
}

static void read_bool_and_text_key(void) {
  const uint8_t bools[] = {0xF4u, 0xF5u};
  const uint8_t key[] = {0x62u, 'u', 'p'};
  size_t off = 0u;
  bool value = true;
  bool matches = false;
  expect_true(pcsc_fido_cbor_read_bool_value(bools, sizeof(bools), &off, &value) && !value,
              "read false");
  expect_true(pcsc_fido_cbor_read_bool_value(bools, sizeof(bools), &off, &value) && value,
              "read true");
  off = 0u;
  expect_true(pcsc_fido_cbor_read_text_key_matches(key, sizeof(key), &off, "up", &matches) &&
                matches,
              "text key matches");
  expect_true(!pcsc_fido_cbor_read_text_key_matches(key, sizeof(key), &off, "uv", &matches),
              "text key mismatch");
}

static void read_text_key_with_explicit_length(void) {
  const uint8_t key[] = {0x62u, 'u', 'p'};
  const char expected[] = {'u', 'p'};
  size_t off = 0u;
  bool matches = false;
  expect_true(pcsc_fido_cbor_read_text_key_matches_len(key, sizeof(key), &off, expected,
                                                       sizeof(expected), &matches) &&
                matches,
              "text key explicit length matches");
}

static void wide_map_header(void) {
  const uint8_t payload[] = {0xB9u, 0x00u, 0x02u, 0x01u, 0x02u, 0x03u, 0x04u};
  size_t off = 0u;
  size_t pairs = 0u;
  expect_true(pcsc_fido_cbor_read_type_len(payload, sizeof(payload), &off, 5u, &pairs) &&
                pairs == 2u,
              "16-bit map length");
  expect_true(pcsc_fido_cbor_skip_item(payload, sizeof(payload), &off), "skip map pair key");
  expect_true(pcsc_fido_cbor_skip_item(payload, sizeof(payload), &off), "skip map pair value");
}

static void nested_skip_failure(void) {
  const uint8_t bad_array[] = {0x81u, 0xFFu};
  size_t off = 0u;
  expect_true(!pcsc_fido_cbor_skip_item(bad_array, sizeof(bad_array), &off), "invalid nested item");
}

static void eight_byte_length_encoding(void) {
  const uint8_t payload[] = {0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x1Bu, 0x27u};
  size_t off = 0u;
  size_t value = 0u;
  expect_true(pcsc_fido_cbor_read_len(27u, payload, sizeof(payload), &off, &value) &&
                value == 0x1Bu,
              "additional 27 length decoded");
  expect_true(off == 8u, "eight-byte length consumed");
}

static void eight_byte_length_rejects_size_overflow(void) {
  const uint8_t payload[] = {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu};
  size_t off = 0u;
  size_t value = 0u;
  if (SIZE_MAX < UINT64_MAX) {
    expect_true(!pcsc_fido_cbor_read_len(27u, payload, sizeof(payload), &off, &value),
                "additional 27 rejects values larger than size_t");
  } else {
    expect_true(pcsc_fido_cbor_read_len(27u, payload, sizeof(payload), &off, &value) &&
                  value == SIZE_MAX,
                "additional 27 accepts size_t maximum");
  }
}

static void skip_major7_wide_additional(void) {
  const uint8_t float64[] = {0xFBu, 0x40u, 0x09u, 0x21u, 0xFBu, 0x54u, 0x68u, 0x7Eu, 0x67u};
  const uint8_t extra[] = {0xFBu, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u, 0x08u};
  size_t off = 0u;
  expect_true(pcsc_fido_cbor_skip_item(float64, sizeof(float64), &off) && off == sizeof(float64),
              "skip float64 simple");
  off = 0u;
  expect_true(pcsc_fido_cbor_skip_item(extra, sizeof(extra), &off) && off == sizeof(extra),
              "skip major7 additional 27 payload");
}

static void read_len_and_bool_failures(void) {
  const uint8_t empty[] = {0x00u};
  size_t off = 0u;
  size_t value = 0u;
  bool flag = false;
  expect_true(!pcsc_fido_cbor_read_len(24u, empty, 0u, &off, &value), "additional 24 at EOF");
  off = 0u;
  expect_true(!pcsc_fido_cbor_read_bool_value((const uint8_t[]){0x00u}, 1u, &off, &flag),
              "non-bool simple rejected");
  off = 0u;
  expect_true(!pcsc_fido_cbor_read_type_len((const uint8_t[]){0x00u}, 1u, &off, 1u, &value),
              "wrong major rejected");
}

static void reject_indefinite_and_reserved_lengths(void) {
  size_t off = 0u;
  size_t value = 0u;
  expect_true(!pcsc_fido_cbor_read_len(28u, (const uint8_t[]){0x00u}, 1u, &off, &value),
              "reserved additional 28 rejected");
  off = 0u;
  expect_true(!pcsc_fido_cbor_read_len(31u, (const uint8_t[]){0x00u}, 1u, &off, &value),
              "indefinite length rejected");
  off = 0u;
  expect_true(!pcsc_fido_cbor_skip_item((const uint8_t[]){0x5Fu}, 1u, &off),
              "indefinite byte string rejected");
  off = 0u;
  expect_true(!pcsc_fido_cbor_skip_item((const uint8_t[]){0x9Fu}, 1u, &off),
              "indefinite array rejected");
  off = 0u;
  expect_true(!pcsc_fido_cbor_skip_item((const uint8_t[]){0xBFu}, 1u, &off),
              "indefinite map rejected");
}

static void skip_array_and_map_bounds(void) {
  const uint8_t bad_map[] = {0xA1u, 0x01u};
  const uint8_t bad_array[] = {0x81u};
  size_t off = 0u;
  expect_true(!pcsc_fido_cbor_skip_item(bad_map, sizeof(bad_map), &off), "truncated map rejected");
  off = 0u;
  expect_true(!pcsc_fido_cbor_skip_item(bad_array, sizeof(bad_array), &off),
              "truncated array rejected");
}

static void skip_rejects_excessive_nesting(void) {
  uint8_t nested[40];
  size_t off = 0u;
  memset(nested, 0x81u, sizeof(nested));
  nested[31] = 0x00u;
  expect_true(pcsc_fido_cbor_skip_item(nested, 32u, &off) && off == 32u,
              "bounded nesting at limit accepted");
  off = 0u;
  memset(nested, 0x81u, sizeof(nested));
  nested[32] = 0x00u;
  expect_true(!pcsc_fido_cbor_skip_item(nested, 33u, &off), "excessive nesting rejected");
}

int main(void) {
  null_argument_guards();
  read_len_encodings();
  skip_major_types();
  read_bool_and_text_key();
  read_text_key_with_explicit_length();
  wide_map_header();
  nested_skip_failure();
  eight_byte_length_encoding();
  eight_byte_length_rejects_size_overflow();
  skip_major7_wide_additional();
  read_len_and_bool_failures();
  reject_indefinite_and_reserved_lengths();
  skip_array_and_map_bounds();
  skip_rejects_excessive_nesting();
  return failures == 0 ? 0 : 1;
}
