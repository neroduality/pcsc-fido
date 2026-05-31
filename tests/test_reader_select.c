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

#define _POSIX_C_SOURCE 200809L

#include "pcsc_fido/pcsc_bridge_limits.h"
#include "pcsc_fido/reader_select.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
  TEST_SCARD_STATE_PRESENT = 0x20u,
  TEST_SCARD_STATE_INUSE = 0x100u,
  TEST_SCARD_STATE_MUTE = 0x200u,
};

static int failures;

static void expect_true(int condition, const char *message) {
  if (!condition) {
    fprintf(stderr, "FAIL: %s\n", message);
    failures++;
  }
}

static void acs_dual_slot_auto_selects_picc(void) {
  const char readers[] = "ACS ACR1252 1S CL Reader SAM 00 00\0"
                         "ACS ACR1252 1S CL Reader PICC 00 00\0"
                         "\0";
  char selected[128];
  bool auto_selected = false;
  pcsc_fido_reader_pick_result_t result = pcsc_fido_pick_reader_from_list(
    readers, sizeof(readers), nullptr, true, selected, sizeof(selected), &auto_selected);
  expect_true(result == PCSC_FIDO_READER_PICK_OK, "ACS dual-slot auto-select succeeds");
  expect_true(auto_selected, "ACS PICC was auto-selected");
  expect_true(strcmp(selected, "ACS ACR1252 1S CL Reader PICC 00 00") == 0, "ACS PICC selected");
}

static void single_omnikey_selects_without_contactless_keyword(void) {
  const char readers[] =
    "HID Global OMNIKEY 5022 Smart Card Reader [OMNIKEY 5022 Smart Card Reader] 00 00\0"
    "\0";
  char selected[160];
  bool auto_selected = true;
  pcsc_fido_reader_pick_result_t result = pcsc_fido_pick_reader_from_list(
    readers, sizeof(readers), nullptr, true, selected, sizeof(selected), &auto_selected);
  expect_true(result == PCSC_FIDO_READER_PICK_OK, "single OMNIKEY select succeeds");
  expect_true(!auto_selected, "single reader selection is not contactless auto-selection");
  expect_true(strcmp(selected,
                     "HID Global OMNIKEY 5022 Smart Card Reader [OMNIKEY 5022 Smart Card Reader] "
                     "00 00") == 0,
              "OMNIKEY selected");
}

static void multiple_contactless_slots_stay_ambiguous(void) {
  const char readers[] = "Reader A PICC 00 00\0"
                         "Reader B NFC 00 00\0"
                         "\0";
  char selected[64];
  bool auto_selected = false;
  pcsc_fido_reader_pick_result_t result = pcsc_fido_pick_reader_from_list(
    readers, sizeof(readers), nullptr, true, selected, sizeof(selected), &auto_selected);
  expect_true(result == PCSC_FIDO_READER_PICK_AMBIGUOUS,
              "multiple contactless readers remain ambiguous");
  expect_true(!auto_selected, "ambiguous selection is not marked auto-selected");
}

static void acs_picc_and_generic_reader_stay_ambiguous(void) {
  const char readers[] = "ACS ACR1252 Dual Reader [ACR1252 Dual Reader PICC] 00 00\0"
                         "ACS ACR1252 Dual Reader [ACR1252 Dual Reader SAM] 01 00\0"
                         "Generic PC/SC Smart Card Reader 02 00\0"
                         "\0";
  char selected[192];
  bool auto_selected = false;
  pcsc_fido_reader_pick_result_t result = pcsc_fido_pick_reader_from_list(
    readers, sizeof(readers), nullptr, true, selected, sizeof(selected), &auto_selected);
  expect_true(result == PCSC_FIDO_READER_PICK_AMBIGUOUS,
              "ACS PICC plus a generic non-SAM reader waits for card presence");
  expect_true(!auto_selected, "generic multi-reader selection is not model-specific");
}

static void explicit_needle_selects_matching_reader(void) {
  const char readers[] = "Reader A PICC 00 00\0"
                         "Reader B NFC 00 00\0"
                         "\0";
  char selected[64];
  bool auto_selected = true;
  pcsc_fido_reader_pick_result_t result = pcsc_fido_pick_reader_from_list(
    readers, sizeof(readers), "Reader B", true, selected, sizeof(selected), &auto_selected);
  expect_true(result == PCSC_FIDO_READER_PICK_OK, "explicit reader needle selects one reader");
  expect_true(!auto_selected, "explicit selection is not contactless auto-selection");
  expect_true(strcmp(selected, "Reader B NFC 00 00") == 0, "explicit reader selected");
}

static void explicit_needle_is_case_insensitive(void) {
  const char readers[] = "ACS ACR1252 1S CL Reader SAM 00 00\0"
                         "ACS ACR1252 1S CL Reader PICC 00 00\0"
                         "\0";
  char selected[128];
  bool auto_selected = true;
  pcsc_fido_reader_pick_result_t result = pcsc_fido_pick_reader_from_list(
    readers, sizeof(readers), "picc", true, selected, sizeof(selected), &auto_selected);
  expect_true(result == PCSC_FIDO_READER_PICK_OK, "lowercase explicit reader needle selects PICC");
  expect_true(!auto_selected, "explicit case-insensitive selection is not auto-selection");
  expect_true(strcmp(selected, "ACS ACR1252 1S CL Reader PICC 00 00") == 0,
              "case-insensitive PICC selected");
}

static void no_match_cases(void) {
  const char empty[] = "\0";
  const char readers[] = "Reader A PICC 00 00\0"
                         "Reader B NFC 00 00\0"
                         "\0";
  char selected[64];
  bool auto_selected = false;
  expect_true(pcsc_fido_pick_reader_from_list(empty, sizeof(empty), nullptr, true, selected,
                                              sizeof(selected),
                                              &auto_selected) == PCSC_FIDO_READER_PICK_NO_MATCH,
              "empty reader list is NO_MATCH");
  expect_true(pcsc_fido_pick_reader_from_list(readers, sizeof(readers), "missing", true, selected,
                                              sizeof(selected),
                                              &auto_selected) == PCSC_FIDO_READER_PICK_NO_MATCH,
              "missing needle is NO_MATCH");
}

static void auto_select_disabled(void) {
  const char readers[] = "ACS ACR1252 1S CL Reader SAM 00 00\0"
                         "ACS ACR1252 1S CL Reader PICC 00 00\0"
                         "\0";
  char selected[128];
  bool auto_selected = false;
  pcsc_fido_reader_pick_result_t result = pcsc_fido_pick_reader_from_list(
    readers, sizeof(readers), nullptr, false, selected, sizeof(selected), &auto_selected);
  expect_true(result == PCSC_FIDO_READER_PICK_AMBIGUOUS, "auto-select disabled stays ambiguous");
}

static void nfc_and_contactless_keywords(void) {
  const char nfc_readers[] = "Vendor NFC Reader 00 00\0"
                             "Vendor SAM Slot SAM 01 00\0"
                             "\0";
  const char contactless_readers[] = "Vendor Contactless Reader 00 00\0"
                                     "Vendor SAM Slot SAM 01 00\0"
                                     "\0";
  char selected[128];
  bool auto_selected = false;
  expect_true(pcsc_fido_pick_reader_from_list(nfc_readers, sizeof(nfc_readers), nullptr, true,
                                              selected, sizeof(selected),
                                              &auto_selected) == PCSC_FIDO_READER_PICK_OK,
              "single NFC slot auto-selects");
  expect_true(auto_selected, "NFC auto-selection flagged");
  auto_selected = false;
  expect_true(pcsc_fido_pick_reader_from_list(contactless_readers, sizeof(contactless_readers),
                                              nullptr, true, selected, sizeof(selected),
                                              &auto_selected) == PCSC_FIDO_READER_PICK_OK,
              "single contactless slot auto-selects");
}

static void sam_only_reader_no_match(void) {
  const char readers[] = "ACS ACR1252 1S CL Reader SAM 00 00\0"
                         "ACS ACR1252 1S CL Reader SAM 01 00\0"
                         "\0";
  char selected[128];
  bool auto_selected = false;
  expect_true(pcsc_fido_pick_reader_from_list(readers, sizeof(readers), nullptr, true, selected,
                                              sizeof(selected),
                                              &auto_selected) == PCSC_FIDO_READER_PICK_AMBIGUOUS,
              "multiple SAM-only readers stay ambiguous");
}

static void truncates_output_buffer(void) {
  const char readers[] = "Very Long Reader Name That Will Not Fit 00 00\0\0";
  char selected[8];
  bool auto_selected = false;
  expect_true(pcsc_fido_pick_reader_from_list(readers, sizeof(readers), nullptr, true, selected,
                                              sizeof(selected), &auto_selected) ==
                PCSC_FIDO_READER_PICK_NAME_TOO_LONG,
              "undersized reader buffer rejects long name");
}

static void empty_needle_matches_all(void) {
  const char readers[] = "Reader A PICC 00 00\0"
                         "Reader B NFC 00 00\0"
                         "\0";
  char selected[64];
  bool auto_selected = false;
  expect_true(pcsc_fido_pick_reader_from_list(readers, sizeof(readers), "", true, selected,
                                              sizeof(selected),
                                              &auto_selected) == PCSC_FIDO_READER_PICK_AMBIGUOUS,
              "empty needle does not force a single reader");
}

static void reader_status_filters(void) {
  expect_true(!pcsc_fido_reader_status_has_card(0u), "empty state has no card");
  expect_true(pcsc_fido_reader_status_has_card((uint32_t)TEST_SCARD_STATE_PRESENT),
              "present state has card");
  expect_true(
    !pcsc_fido_reader_status_has_card((uint32_t)(TEST_SCARD_STATE_PRESENT | TEST_SCARD_STATE_MUTE)),
    "mute card rejected");
  expect_true(!pcsc_fido_reader_status_has_card(
                (uint32_t)(TEST_SCARD_STATE_PRESENT | TEST_SCARD_STATE_INUSE)),
              "in-use card rejected");
}

static void length_aware_reader_helpers(void) {
  const char reader[] = {'A', 'C', 'S', ' ', 'P', 'I', 'C', 'C'};
  const char needle[] = {'p', 'i', 'c', 'c'};
  expect_true(pcsc_fido_reader_name_contains_ci_len(reader, sizeof(reader), needle, sizeof(needle)),
              "length-aware contains handles unterminated buffers");
  expect_true(pcsc_fido_reader_name_is_contactless_slot_len(reader, sizeof(reader)),
              "length-aware contactless handles unterminated buffers");
}

static void reader_list_helpers_cover_edge_cases(void) {
  const char readers[] = "Reader A PICC 00 00\0\0";
  size_t off = 0u;
  const char *entry;
  size_t entry_len;
  pcsc_fido_reader_list_entry_result_t result;

  expect_true(pcsc_fido_reader_list_is_valid(readers, sizeof(readers)), "valid MSZ accepted");
  expect_true(!pcsc_fido_reader_list_is_valid(nullptr, sizeof(readers)), "null list invalid");
  expect_true(!pcsc_fido_reader_list_is_valid(readers, 0u), "zero length invalid");

  result = pcsc_fido_reader_list_next(readers, sizeof(readers), &off, &entry, &entry_len);
  expect_true(result == PCSC_FIDO_READER_LIST_ENTRY_OK, "first entry parsed");
  expect_true(strcmp(entry, "Reader A PICC 00 00") == 0, "first entry name");
  result = pcsc_fido_reader_list_next(readers, sizeof(readers), &off, &entry, &entry_len);
  expect_true(result == PCSC_FIDO_READER_LIST_ENTRY_END, "MSZ terminator ends iteration");
  expect_true(pcsc_fido_reader_list_next(nullptr, sizeof(readers), &off, &entry, &entry_len) ==
                PCSC_FIDO_READER_LIST_ENTRY_MALFORMED,
              "null list pointer malformed");
}

static void reader_env_needle_prefers_explicit_value(void) {
  unsetenv("PCSC_FIDO_READER");
  expect_true(strcmp(pcsc_fido_reader_env_needle("explicit"), "explicit") == 0,
              "explicit needle preserved");
  setenv("PCSC_FIDO_READER", "from-env", 1);
  expect_true(pcsc_fido_reader_env_needle(nullptr) != nullptr &&
                strcmp(pcsc_fido_reader_env_needle(nullptr), "from-env") == 0,
              "PCSC_FIDO_READER env used");
  unsetenv("PCSC_FIDO_READER");
}

static void pick_respects_readers_len_not_buffer_size(void) {
  char readers[PCSC_FIDO_READER_LIST_BUF_MAX];
  char selected[64];
  bool auto_selected = false;
  const size_t pcsc_list_len = sizeof("Reader A PICC 00 00"); /* name + first NUL only */

  memset(readers, 'X', sizeof(readers));
  memcpy(readers, "Reader A PICC 00 00", pcsc_list_len);
  memcpy(readers + pcsc_list_len, "Reader B NFC 00 00", sizeof("Reader B NFC 00 00"));
  readers[pcsc_list_len + sizeof("Reader B NFC 00 00")] = '\0';

  expect_true(pcsc_fido_pick_reader_from_list(readers, pcsc_list_len, nullptr, true, selected,
                                              sizeof(selected),
                                              &auto_selected) == PCSC_FIDO_READER_PICK_NO_MATCH,
              "truncated PC/SC list length does not scan trailing buffer bytes");

  auto_selected = false;
  expect_true(pcsc_fido_pick_reader_from_list(readers, sizeof(readers), nullptr, true, selected,
                                              sizeof(selected),
                                              &auto_selected) == PCSC_FIDO_READER_PICK_AMBIGUOUS,
              "scanning the full buffer sees the planted second reader");
}

static void malformed_reader_list_is_bounded(void) {
  char readers[PCSC_FIDO_READER_LIST_BUF_MAX];
  char selected[64];
  bool auto_selected = true;
  memset(readers, 'A', sizeof(readers));
  expect_true(pcsc_fido_pick_reader_from_list(readers, sizeof(readers), nullptr, true, selected,
                                              sizeof(selected),
                                              &auto_selected) == PCSC_FIDO_READER_PICK_NO_MATCH,
              "malformed reader list without terminator is rejected");
  expect_true(selected[0] == '\0', "malformed list leaves selection empty");
  expect_true(!auto_selected, "malformed list is not auto-selected");
  memset(readers, 'B', sizeof(readers));
  memcpy(readers, "Reader PICC 00 00", sizeof("Reader PICC 00 00"));
  readers[sizeof("Reader PICC 00 00") - 1u] = '\0';
  expect_true(pcsc_fido_pick_reader_from_list(readers, sizeof(readers), nullptr, true, selected,
                                              sizeof(selected),
                                              &auto_selected) == PCSC_FIDO_READER_PICK_NO_MATCH,
              "reader list missing final terminator is rejected");
}

int main(void) {
  expect_true(!pcsc_fido_reader_name_contains_ci(nullptr, "picc"), "nullptr reader rejected");
  expect_true(!pcsc_fido_reader_name_contains_ci("ACS PICC", nullptr), "nullptr needle rejected");
  expect_true(pcsc_fido_reader_name_contains_ci("ACS PICC", ""), "empty needle matches");
  expect_true(!pcsc_fido_reader_name_is_contactless_slot(nullptr), "nullptr contactless check");
  expect_true(pcsc_fido_reader_name_contains_ci("ACS PICC", "picc"), "case-insensitive contains");
  expect_true(pcsc_fido_reader_name_is_contactless_slot("ACS ACR1252 PICC 00 00"),
              "PICC is contactless");
  expect_true(!pcsc_fido_reader_name_is_contactless_slot("Generic PC/SC Smart Card Reader 02 00"),
              "generic reader is not hard-coded as contactless");
  expect_true(!pcsc_fido_reader_name_is_contactless_slot("ACS ACR1252 SAM 00 00"),
              "SAM is not contactless");
  expect_true(pcsc_fido_reader_name_is_sam_slot_len("ACS ACR1252 SAM 00 00",
                                                    sizeof("ACS ACR1252 SAM 00 00") - 1u),
              "SAM slot name detected");
  acs_dual_slot_auto_selects_picc();
  single_omnikey_selects_without_contactless_keyword();
  multiple_contactless_slots_stay_ambiguous();
  acs_picc_and_generic_reader_stay_ambiguous();
  explicit_needle_selects_matching_reader();
  explicit_needle_is_case_insensitive();
  no_match_cases();
  auto_select_disabled();
  nfc_and_contactless_keywords();
  sam_only_reader_no_match();
  truncates_output_buffer();
  empty_needle_matches_all();
  reader_status_filters();
  length_aware_reader_helpers();
  reader_list_helpers_cover_edge_cases();
  reader_env_needle_prefers_explicit_value();
  pick_respects_readers_len_not_buffer_size();
  malformed_reader_list_is_bounded();
  return failures == 0 ? 0 : 1;
}
