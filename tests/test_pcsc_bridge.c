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

#include "pcsc_fido/ctaphid.h"
#include "pcsc_fido/pcsc_bridge.h"

#include "mock_pcsc.h"

#include "pcsc_fido/attrs.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static time_t g_fake_time = 1000000;

// rem matches nanosleep(2); LD --wrap requires a non-const second parameter.
int __wrap_nanosleep(const struct timespec *req PCSC_FIDO_MAYBE_UNUSED,
                     // cppcheck-suppress constParameterPointer
                     struct timespec *rem PCSC_FIDO_MAYBE_UNUSED) {
  return 0;
}

time_t __wrap_time(time_t *t) {
  g_fake_time++;
  if (t != nullptr) {
    *t = g_fake_time;
  }
  return g_fake_time;
}

static int failures;

static void expect_true(int condition, const char *message) {
  if (!condition) {
    fprintf(stderr, "FAIL: %s\n", message);
    failures++;
  }
}

static void bridge_setup(void) {
  g_fake_time = 1000000;
  mock_pcsc_reset();
  mock_pcsc_set_readers("Test NFC Reader 00 00\0\0");
  pcsc_fido_bridge_reset();
  unsetenv("PCSC_FIDO_READER");
}

static void *cancel_bridge_main(void *arg) {
  (void)arg;
  pcsc_fido_bridge_cancel();
  return nullptr;
}

static void invalid_exchange_arguments(void) {
  uint8_t response[64];
  char err[128];
  bridge_setup();
  expect_true(!pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, nullptr, 1u, response,
                                         sizeof(response), nullptr, err, sizeof(err)),
              "nullptr response_len rejected");
  expect_true(!pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, nullptr, 1u, nullptr,
                                         sizeof(response), nullptr, err, sizeof(err)),
              "nullptr response rejected");
  {
    size_t response_len = 0u;
    expect_true(!pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, nullptr, 0u, response,
                                           sizeof(response), &response_len, err, sizeof(err)),
                "nullptr payload with zero length rejected");
  }
}

static void list_readers_success(void) {
  char err[128];
  bridge_setup();
  expect_true(pcsc_fido_bridge_list_readers(stdout, err, sizeof(err)), "list readers succeeds");
}

static void list_readers_invalid_output(void) {
  char err[128];
  bridge_setup();
  expect_true(!pcsc_fido_bridge_list_readers(nullptr, err, sizeof(err)), "nullptr out rejected");
}

static void list_readers_establish_failure(void) {
  char err[128];
  bridge_setup();
  mock_pcsc_set_establish_fail(SCARD_F_INTERNAL_ERROR);
  expect_true(!pcsc_fido_bridge_list_readers(stdout, err, sizeof(err)), "establish failure");
  expect_true(strstr(err, "SCardEstablishContext") != nullptr, "establish error message");
}

static void exchange_getinfo_via_session(void) {
  const uint8_t get_info[] = {0x04u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  const uint8_t mock_resp[] = {0x00u, 0xA1u, 0x01u, 0x02u, 0x90u, 0x00u};
  bridge_setup();
  mock_pcsc_set_transmit_response(mock_resp, sizeof(mock_resp));
  expect_true(pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, get_info, sizeof(get_info),
                                        response, sizeof(response), &response_len, err,
                                        sizeof(err)),
              "getInfo exchange succeeds");
  expect_true(response_len == 4u && response[0] == 0x00u, "CTAP payload stripped");
}

static void exchange_u2f_msg(void) {
  const uint8_t msg[] = {0x00u, 0x01u, 0x02u, 0x03u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  const uint8_t mock_resp[] = {0xAAu, 0xBBu, 0x90u, 0x00u};
  bridge_setup();
  mock_pcsc_set_transmit_response(mock_resp, sizeof(mock_resp));
  expect_true(pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_MSG, msg, sizeof(msg), response,
                                        sizeof(response), &response_len, err, sizeof(err)),
              "U2F MSG exchange succeeds");
  expect_true(response_len == 4u && response[0] == 0xAAu && response[1] == 0xBBu,
              "U2F MSG response includes body and status words");
}

static void exchange_unsupported_hid_command(void) {
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  const uint8_t payload[] = {0x01u};
  bridge_setup();
  expect_true(!pcsc_fido_bridge_exchange(nullptr, 0xEEu, payload, sizeof(payload), response,
                                         sizeof(response), &response_len, err, sizeof(err)),
              "unsupported HID command rejected");
}

static void exchange_select_fallback(void) {
  const uint8_t get_info[] = {0x04u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  bridge_setup();
  mock_pcsc_set_select_first_fail(true);
  expect_true(pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, get_info, sizeof(get_info),
                                        response, sizeof(response), &response_len, err,
                                        sizeof(err)),
              "select fallback succeeds");
}

static void exchange_connect_failure(void) {
  const uint8_t get_info[] = {0x04u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  bridge_setup();
  mock_pcsc_set_connect_fail(SCARD_E_NO_SMARTCARD);
  expect_true(!pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, get_info,
                                         sizeof(get_info), response, sizeof(response),
                                         &response_len, err, sizeof(err)),
              "connect failure surfaces");
}

static void exchange_connect_raw_protocol(void) {
  const uint8_t get_info[] = {0x04u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  bridge_setup();
  mock_pcsc_set_connect_proto_mismatch_once(true);
  mock_pcsc_set_connect_active_protocol(SCARD_PROTOCOL_RAW);
  expect_true(pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, get_info, sizeof(get_info),
                                        response, sizeof(response), &response_len, err,
                                        sizeof(err)),
              "RAW protocol connect succeeds");
}

static void exchange_connect_unknown_protocol(void) {
  const uint8_t get_info[] = {0x04u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  bridge_setup();
  mock_pcsc_set_connect_active_protocol(0u);
  expect_true(!pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, get_info,
                                         sizeof(get_info), response, sizeof(response),
                                         &response_len, err, sizeof(err)),
              "unknown negotiated protocol rejected");
}

static void exchange_transmit_reconnect(void) {
  const uint8_t get_info[] = {0x04u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  const uint8_t mock_resp[] = {0x00u, 0xA0u, 0x90u, 0x00u};
  bridge_setup();
  mock_pcsc_set_transmit_fail_once(true);
  mock_pcsc_set_transmit_response(mock_resp, sizeof(mock_resp));
  expect_true(pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, get_info, sizeof(get_info),
                                        response, sizeof(response), &response_len, err,
                                        sizeof(err)),
              "transmit reconnect succeeds");
  expect_true(mock_pcsc_transmit_call_count() >= 3u, "reconnect retransmits");
}

static void exchange_non_success_ctap_status_still_returns_body(void) {
  const uint8_t get_info[] = {0x04u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  const uint8_t mock_resp[] = {0x01u, 0x90u, 0x00u};
  bridge_setup();
  mock_pcsc_set_transmit_response(mock_resp, sizeof(mock_resp));
  expect_true(pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, get_info, sizeof(get_info),
                                        response, sizeof(response), &response_len, err,
                                        sizeof(err)),
              "non-zero CTAP status with SW=9000 still returns payload");
  expect_true(response_len == 1u && response[0] == 0x01u, "CTAP status byte preserved");
}

static void exchange_apdu_sw_failure(void) {
  const uint8_t get_info[] = {0x04u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  const uint8_t mock_resp[] = {0x6Au, 0x82u};
  bridge_setup();
  mock_pcsc_set_transmit_response(mock_resp, sizeof(mock_resp));
  expect_true(!pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, get_info,
                                         sizeof(get_info), response, sizeof(response),
                                         &response_len, err, sizeof(err)),
              "bad APDU SW fails");
}

static void exchange_response_buffer_too_small(void) {
  const uint8_t get_info[] = {0x04u};
  uint8_t response[1];
  size_t response_len = 0u;
  char err[256];
  const uint8_t mock_resp[] = {0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x90u, 0x00u};
  bridge_setup();
  mock_pcsc_set_transmit_response(mock_resp, sizeof(mock_resp));
  expect_true(!pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, get_info,
                                         sizeof(get_info), response, sizeof(response),
                                         &response_len, err, sizeof(err)),
              "small response buffer rejected");
}

static void exchange_with_specific_reader(void) {
  const uint8_t get_info[] = {0x04u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  bridge_setup();
  setenv("PCSC_FIDO_READER", "Test NFC", 1);
  expect_true(pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, get_info, sizeof(get_info),
                                        response, sizeof(response), &response_len, err,
                                        sizeof(err)),
              "needle reader match succeeds");
  unsetenv("PCSC_FIDO_READER");
}

static void exchange_reader_no_match(void) {
  const uint8_t get_info[] = {0x04u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  bridge_setup();
  setenv("PCSC_FIDO_READER", "Missing Reader", 1);
  expect_true(!pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, get_info,
                                         sizeof(get_info), response, sizeof(response),
                                         &response_len, err, sizeof(err)),
              "missing reader fails");
  unsetenv("PCSC_FIDO_READER");
}

static void exchange_get_assertion_and_debug(void) {
  const uint8_t payload[] = {0x02u, 0xA2u, 0x05u, 0xA1u, 0x62u, 0x75u, 0x70u, 0xF5u, 0x06u,
                             0x50u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
                             0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  const uint8_t mock_resp[] = {0x00u, 0xA0u, 0x90u, 0x00u};
  bridge_setup();
  setenv("PCSC_FIDO_DEBUG", "1", 1);
  mock_pcsc_set_transmit_response(mock_resp, sizeof(mock_resp));
  expect_true(pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, payload, sizeof(payload),
                                        response, sizeof(response), &response_len, err,
                                        sizeof(err)),
              "getAssertion exchange succeeds");
  unsetenv("PCSC_FIDO_DEBUG");
}

static void exchange_make_credential_logging(void) {
  const uint8_t payload[] = {0x01u, 0xA0u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  const uint8_t mock_resp[] = {0x00u, 0xA3u, 0x01u, 0x66u, 0x58u, 0x20u, 0x00u, 0x00u, 0x00u, 0x00u,
                               0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
                               0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
                               0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x02u, 0x62u,
                               0x69u, 0x64u, 0x41u, 0x00u, 0x90u, 0x00u};
  bridge_setup();
  setenv("PCSC_FIDO_DEBUG", "1", 1);
  mock_pcsc_set_transmit_response(mock_resp, sizeof(mock_resp));
  expect_true(pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, payload, sizeof(payload),
                                        response, sizeof(response), &response_len, err,
                                        sizeof(err)),
              "makeCredential exchange succeeds");
  unsetenv("PCSC_FIDO_DEBUG");
}

static void session_reuse(void) {
  const uint8_t get_info[] = {0x04u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  bridge_setup();
  expect_true(pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, get_info, sizeof(get_info),
                                        response, sizeof(response), &response_len, err,
                                        sizeof(err)),
              "first exchange opens session");
  expect_true(pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, get_info, sizeof(get_info),
                                        response, sizeof(response), &response_len, err,
                                        sizeof(err)),
              "second exchange reuses session");
}

static void list_readers_probe_error(void) {
  char err[128];
  bridge_setup();
  mock_pcsc_set_list_probe_fail(SCARD_F_INTERNAL_ERROR);
  expect_true(!pcsc_fido_bridge_list_readers(stdout, err, sizeof(err)), "list probe error");
}

static void get_status_error(void) {
  const uint8_t get_info[] = {0x04u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  bridge_setup();
  mock_pcsc_set_get_status_fail(SCARD_F_INTERNAL_ERROR);
  expect_true(!pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, get_info,
                                         sizeof(get_info), response, sizeof(response),
                                         &response_len, err, sizeof(err)),
              "get status error fails session");
}

static void list_readers_fill_fail(void) {
  char err[128];
  bridge_setup();
  mock_pcsc_set_list_fill_fail(SCARD_F_INTERNAL_ERROR);
  expect_true(!pcsc_fido_bridge_list_readers(stdout, err, sizeof(err)), "list fill error");
}

static void list_readers_too_many(void) {
  char err[128];
  bridge_setup();
  mock_pcsc_set_list_probe_needed(5000u);
  expect_true(!pcsc_fido_bridge_list_readers(stdout, err, sizeof(err)), "too many readers");
  expect_true(strstr(err, "too many PC/SC readers") != nullptr, "too many readers message");
}

static void list_readers_no_readers_timeout(void) {
  char err[128];
  bridge_setup();
  mock_pcsc_set_list_probe_always_no_readers(true);
  expect_true(!pcsc_fido_bridge_list_readers(stdout, err, sizeof(err)), "no readers timeout");
}

static void list_readers_contactless_suffix(void) {
  char err[128];
  bridge_setup();
  mock_pcsc_set_readers("ACR1252 PICC 00 00");
  expect_true(pcsc_fido_bridge_list_readers(stdout, err, sizeof(err)), "contactless list");
}

static void exchange_establish_system_fallback(void) {
  const uint8_t get_info[] = {0x04u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  bridge_setup();
  mock_pcsc_set_establish_fail_system_scope(true);
  expect_true(pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, get_info, sizeof(get_info),
                                        response, sizeof(response), &response_len, err,
                                        sizeof(err)),
              "SYSTEM scope fallback succeeds");
}

static void exchange_pcsc_fido_reader_env(void) {
  const uint8_t get_info[] = {0x04u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  bridge_setup();
  setenv("PCSC_FIDO_READER", "Test NFC", 1);
  expect_true(pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, get_info, sizeof(get_info),
                                        response, sizeof(response), &response_len, err,
                                        sizeof(err)),
              "PCSC_FIDO_READER needle succeeds");
  unsetenv("PCSC_FIDO_READER");
}

static void exchange_ambiguous_readers_card_present(void) {
  const uint8_t get_info[] = {0x04u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  bridge_setup();
  mock_pcsc_set_reader_pair("Reader Alpha 00 00", "Reader Beta 00 00");
  expect_true(pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, get_info, sizeof(get_info),
                                        response, sizeof(response), &response_len, err,
                                        sizeof(err)),
              "ambiguous readers selected by card presence");
}

static void exchange_ambiguous_reader_needle(void) {
  const uint8_t get_info[] = {0x04u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  bridge_setup();
  mock_pcsc_set_reader_pair("Reader Alpha 00 00", "Reader Beta 00 00");
  setenv("PCSC_FIDO_READER", "Alpha Beta", 1);
  expect_true(!pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, get_info,
                                         sizeof(get_info), response, sizeof(response),
                                         &response_len, err, sizeof(err)),
              "ambiguous needle rejected");
  unsetenv("PCSC_FIDO_READER");
}

static void exchange_contactless_auto_select(void) {
  const uint8_t get_info[] = {0x04u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  bridge_setup();
  mock_pcsc_set_readers("ACR1252 PICC 00 00");
  expect_true(pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, get_info, sizeof(get_info),
                                        response, sizeof(response), &response_len, err,
                                        sizeof(err)),
              "contactless auto-select succeeds");
}

static void exchange_preflight_forwarded_to_card(void) {
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  const uint8_t payload[] = {
    0x02u, 0xA4u, 0x02u, 0x58u, 0x20u, 0xE3u, 0xB0u, 0xC4u, 0x42u, 0x98u, 0xFCu, 0x1Cu,
    0x14u, 0x9Au, 0xFBu, 0xF4u, 0xC8u, 0x99u, 0x6Fu, 0xB9u, 0x24u, 0x27u, 0xAEu, 0x41u,
    0xE4u, 0x64u, 0x9Bu, 0x93u, 0x4Cu, 0xA4u, 0x95u, 0x99u, 0x1Bu, 0x78u, 0x52u, 0xB8u,
    0x55u, 0x03u, 0x81u, 0xA2u, 0x01u, 0x62u, 0x69u, 0x64u, 0x02u, 0x41u, 0x00u, 0x05u,
    0xA1u, 0x62u, 0x75u, 0x70u, 0xF4u, 0x06u, 0x50u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u};
  bridge_setup();
  expect_true(pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, payload, sizeof(payload),
                                        response, sizeof(response), &response_len, err,
                                        sizeof(err)),
              "preflight getAssertion is forwarded to the card");
  expect_true(mock_pcsc_transmit_call_count() > 0u,
              "preflight reaches card IO (no local synthesis)");
}

static void exchange_ctaphid_unframable_payload_too_large(void) {
  uint8_t *payload = calloc(PCSC_FIDO_CTAPHID_MAX_FRAMED_PAYLOAD + 1u, 1u);
  bridge_setup();
  if (payload != nullptr) {
    uint8_t response[128];
    size_t response_len = 0u;
    char err[256];
    expect_true(!pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, payload,
                                           PCSC_FIDO_CTAPHID_MAX_FRAMED_PAYLOAD + 1u, response,
                                           sizeof(response), &response_len, err, sizeof(err)),
                "unframable CTAPHID payload rejected");
    expect_true(strstr(err, "CTAPHID payload too large") != nullptr,
                "unframable CTAPHID payload error message");
    free(payload);
  } else {
    fprintf(stderr, "FAIL: CTAPHID unframable payload allocation\n");
    failures++;
  }
}

static void exchange_u2f_msg_too_large(void) {
  uint8_t *payload = calloc(65545u, 1u);
  bridge_setup();
  if (payload != nullptr) {
    uint8_t response[128];
    size_t response_len = 0u;
    char err[256];
    expect_true(!pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_MSG, payload, 65545u,
                                           response, sizeof(response), &response_len, err,
                                           sizeof(err)),
                "oversize U2F MSG rejected");
    free(payload);
  } else {
    fprintf(stderr, "FAIL: U2F oversize payload allocation\n");
    failures++;
  }
}

static void exchange_transmit_hard_fail(void) {
  const uint8_t get_info[] = {0x04u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  bridge_setup();
  mock_pcsc_set_transmit_fail(true);
  expect_true(!pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, get_info,
                                         sizeof(get_info), response, sizeof(response),
                                         &response_len, err, sizeof(err)),
              "persistent transmit failure rejected");
}

static void exchange_wait_for_card_timeout(void) {
  const uint8_t get_info[] = {0x04u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  bridge_setup();
  mock_pcsc_set_card_present_immediately(false);
  expect_true(!pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, get_info,
                                         sizeof(get_info), response, sizeof(response),
                                         &response_len, err, sizeof(err)),
              "card tap timeout fails");
  expect_true(strstr(err, "timed out waiting for FIDO NFC card") != nullptr, "tap timeout message");
}

static void exchange_cancelled_during_reader_enum(void) {
  const uint8_t get_info[] = {0x04u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  pthread_t cancel_thread;
  bridge_setup();
  mock_pcsc_set_list_probe_always_no_readers(true);
  expect_true(pthread_create(&cancel_thread, nullptr, cancel_bridge_main, nullptr) == 0,
              "cancel thread starts");
  expect_true(!pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, get_info,
                                         sizeof(get_info), response, sizeof(response),
                                         &response_len, err, sizeof(err)),
              "cancelled reader enum fails");
  (void)pthread_join(cancel_thread, nullptr);
}

static void exchange_get_assertion_authdata_logging(void) {
  uint8_t auth[37];
  uint8_t mock_resp[128];
  size_t mock_len = 0u;
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  const uint8_t payload[] = {0x02u, 0xA0u};
  bridge_setup();
  memset(auth, 0, sizeof(auth));
  auth[32] = 0x05u;
  mock_len = 0u;
  mock_resp[mock_len++] = 0x00u;
  mock_resp[mock_len++] = 0xA1u;
  mock_resp[mock_len++] = 0x02u;
  mock_resp[mock_len++] = 0x58u;
  mock_resp[mock_len++] = 0x25u;
  memcpy(mock_resp + mock_len, auth, sizeof(auth));
  mock_len += sizeof(auth);
  mock_resp[mock_len++] = 0x90u;
  mock_resp[mock_len++] = 0x00u;
  setenv("PCSC_FIDO_DEBUG", "1", 1);
  mock_pcsc_set_transmit_response(mock_resp, mock_len);
  expect_true(pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, payload, sizeof(payload),
                                        response, sizeof(response), &response_len, err,
                                        sizeof(err)),
              "getAssertion authData logging succeeds");
  unsetenv("PCSC_FIDO_DEBUG");
}

static void exchange_make_credential_attestation_logging(void) {
  uint8_t auth[37];
  uint8_t mock_resp[96];
  size_t mock_len = 0u;
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  const uint8_t payload[] = {0x01u, 0xA0u};
  bridge_setup();
  memset(auth, 0, sizeof(auth));
  auth[32] = 0x45u;
  auth[33] = 0x00u;
  auth[34] = 0x00u;
  auth[35] = 0x00u;
  auth[36] = 0x07u;
  mock_len = 0u;
  mock_resp[mock_len++] = 0x00u;
  mock_resp[mock_len++] = 0xA2u;
  mock_resp[mock_len++] = 0x01u;
  mock_resp[mock_len++] = 0x41u;
  mock_resp[mock_len++] = 0xAAu;
  mock_resp[mock_len++] = 0x02u;
  mock_resp[mock_len++] = 0xA1u;
  mock_resp[mock_len++] = 0x68u;
  memcpy(mock_resp + mock_len, "authData", 8u);
  mock_len += 8u;
  mock_resp[mock_len++] = 0x58u;
  mock_resp[mock_len++] = 0x25u;
  memcpy(mock_resp + mock_len, auth, sizeof(auth));
  mock_len += sizeof(auth);
  mock_resp[mock_len++] = 0x90u;
  mock_resp[mock_len++] = 0x00u;
  setenv("PCSC_FIDO_DEBUG", "1", 1);
  mock_pcsc_set_transmit_response(mock_resp, mock_len);
  expect_true(pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, payload, sizeof(payload),
                                        response, sizeof(response), &response_len, err,
                                        sizeof(err)),
              "makeCredential attestation logging succeeds");
  unsetenv("PCSC_FIDO_DEBUG");
}

static void exchange_ctap_request_options_logging(void) {
  const uint8_t payload[] = {0x02u, 0xA2u, 0x05u, 0xA2u, 0x62u, 0x75u, 0x70u, 0xF5u, 0x62u, 0x75u,
                             0x76u, 0xF4u, 0x06u, 0x50u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u,
                             0x07u, 0x08u, 0x09u, 0x0Au, 0x0Bu, 0x0Cu, 0x0Du, 0x0Eu, 0x0Fu, 0x10u,
                             0x11u, 0x12u, 0x13u, 0x14u, 0x15u, 0x16u, 0x17u, 0x18u, 0x19u, 0x1Au,
                             0x1Bu, 0x1Cu, 0x1Du, 0x1Eu, 0x1Fu, 0x20u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  const uint8_t mock_resp[] = {0x00u, 0xA0u, 0x90u, 0x00u};
  bridge_setup();
  setenv("PCSC_FIDO_DEBUG", "1", 1);
  mock_pcsc_set_transmit_response(mock_resp, sizeof(mock_resp));
  expect_true(pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, payload, sizeof(payload),
                                        response, sizeof(response), &response_len, err,
                                        sizeof(err)),
              "CTAP options logging succeeds");
  unsetenv("PCSC_FIDO_DEBUG");
}

static void exchange_apdu_hex_truncation_logging(void) {
  uint8_t mock_resp[240];
  size_t i;
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  const uint8_t get_info[] = {0x04u};
  bridge_setup();
  mock_resp[0] = 0x01u;
  for (i = 1u; i < 238u; i++) {
    mock_resp[i] = (uint8_t)(i & 0xFFu);
  }
  mock_resp[238] = 0x90u;
  mock_resp[239] = 0x00u;
  setenv("PCSC_FIDO_DEBUG", "1", 1);
  mock_pcsc_set_transmit_response(mock_resp, sizeof(mock_resp));
  expect_true(!pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, get_info,
                                         sizeof(get_info), response, sizeof(response),
                                         &response_len, err, sizeof(err)),
              "long non-success response logged");
  unsetenv("PCSC_FIDO_DEBUG");
}

static void exchange_t0_protocol(void) {
  const uint8_t get_info[] = {0x04u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  bridge_setup();
  mock_pcsc_set_connect_active_protocol(SCARD_PROTOCOL_T0);
  expect_true(pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, get_info, sizeof(get_info),
                                        response, sizeof(response), &response_len, err,
                                        sizeof(err)),
              "T=0 protocol connect succeeds");
}

static void *cancel_after_open_main(void *arg) {
  (void)arg;
  struct timespec ts = {.tv_sec = 0, .tv_nsec = 5000000L};
  (void)nanosleep(&ts, nullptr);
  pcsc_fido_bridge_cancel();
  return nullptr;
}

static void *cancel_when_transmit_waiting_main(void *arg) {
  (void)arg;
  (void)mock_pcsc_wait_for_transmit_waiting(1000u);
  pcsc_fido_bridge_cancel();
  return nullptr;
}

static void exchange_cancel_during_transmit(void) {
  const uint8_t get_info[] = {0x04u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  pthread_t cancel_thread;
  bridge_setup();
  mock_pcsc_set_transmit_fail(true);
  expect_true(pthread_create(&cancel_thread, nullptr, cancel_after_open_main, nullptr) == 0,
              "cancel thread starts");
  expect_true(!pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, get_info,
                                         sizeof(get_info), response, sizeof(response),
                                         &response_len, err, sizeof(err)),
              "cancelled transmit fails");
  (void)pthread_join(cancel_thread, nullptr);
}

static void exchange_cancel_interrupts_blocking_transmit(void) {
  const uint8_t get_info[] = {0x04u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  pthread_t cancel_thread;
  bridge_setup();
  mock_pcsc_set_transmit_wait_for_cancel(true);
  expect_true(pthread_create(&cancel_thread, nullptr, cancel_when_transmit_waiting_main, nullptr) ==
                0,
              "cancel thread starts for blocking transmit");
  expect_true(!pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, get_info,
                                         sizeof(get_info), response, sizeof(response),
                                         &response_len, err, sizeof(err)),
              "blocking transmit is cancelled");
  expect_true(mock_pcsc_cancel_during_transmit(), "cancel interrupts active transmit");
  (void)pthread_join(cancel_thread, nullptr);
}

static void exchange_malformed_ctap_debug_paths(void) {
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  const uint8_t bad_map[] = {0x02u, 0xFFu};
  const uint8_t bad_key[] = {0x02u, 0xA1u, 0x01u, 0x02u};
  const uint8_t bad_options[] = {0x02u, 0xA1u, 0x05u, 0x00u};
  const uint8_t bad_value[] = {0x02u, 0xA1u, 0x06u, 0xFFu};
  const uint8_t get_info[] = {0x06u};
  const uint8_t client_pin[] = {0x06u, 0xA0u};
  bridge_setup();
  setenv("PCSC_FIDO_DEBUG", "1", 1);
  mock_pcsc_set_transmit_response((const uint8_t[]){0x00u, 0xA0u, 0x90u, 0x00u}, 4u);
  (void)pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, bad_map, sizeof(bad_map),
                                  response, sizeof(response), &response_len, err, sizeof(err));
  (void)pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, bad_key, sizeof(bad_key),
                                  response, sizeof(response), &response_len, err, sizeof(err));
  (void)pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, bad_options, sizeof(bad_options),
                                  response, sizeof(response), &response_len, err, sizeof(err));
  (void)pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, bad_value, sizeof(bad_value),
                                  response, sizeof(response), &response_len, err, sizeof(err));
  expect_true(pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, get_info, sizeof(get_info),
                                        response, sizeof(response), &response_len, err,
                                        sizeof(err)),
              "non make/get CTAP command logged");
  expect_true(pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, client_pin,
                                        sizeof(client_pin), response, sizeof(response),
                                        &response_len, err, sizeof(err)),
              "clientPIN command logged");
  unsetenv("PCSC_FIDO_DEBUG");
}

static void exchange_make_credential_malformed_response_debug(void) {
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  const uint8_t payload[] = {0x01u, 0xA0u};
  const uint8_t bad_top[] = {0x00u, 0xFFu, 0x90u, 0x00u};
  const uint8_t no_att[] = {0x00u, 0xA1u, 0x01u, 0x41u, 0x00u, 0x90u, 0x00u};
  bridge_setup();
  setenv("PCSC_FIDO_DEBUG", "1", 1);
  mock_pcsc_set_transmit_response(bad_top, sizeof(bad_top));
  expect_true(pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, payload, sizeof(payload),
                                        response, sizeof(response), &response_len, err,
                                        sizeof(err)),
              "malformed makeCredential top map logged");
  mock_pcsc_set_transmit_response(no_att, sizeof(no_att));
  expect_true(pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, payload, sizeof(payload),
                                        response, sizeof(response), &response_len, err,
                                        sizeof(err)),
              "makeCredential without attestation logged");
  unsetenv("PCSC_FIDO_DEBUG");
}

static void exchange_get_assertion_authdata_59_encoding(void) {
  uint8_t auth[260];
  uint8_t mock_resp[280];
  size_t mock_len = 0u;
  uint8_t response[512];
  size_t response_len = 0u;
  char err[256];
  const uint8_t payload[] = {0x02u, 0xA0u};
  bridge_setup();
  memset(auth, 0, sizeof(auth));
  auth[32] = 0x05u;
  mock_len = 0u;
  mock_resp[mock_len++] = 0x00u;
  mock_resp[mock_len++] = 0xA1u;
  mock_resp[mock_len++] = 0x02u;
  mock_resp[mock_len++] = 0x59u;
  mock_resp[mock_len++] = 0x01u;
  mock_resp[mock_len++] = 0x04u;
  memcpy(mock_resp + mock_len, auth, sizeof(auth));
  mock_len += sizeof(auth);
  mock_resp[mock_len++] = 0x90u;
  mock_resp[mock_len++] = 0x00u;
  setenv("PCSC_FIDO_DEBUG", "1", 1);
  mock_pcsc_set_transmit_response(mock_resp, mock_len);
  expect_true(pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, payload, sizeof(payload),
                                        response, sizeof(response), &response_len, err,
                                        sizeof(err)),
              "getAssertion 0x59 authData encoding logged");
  unsetenv("PCSC_FIDO_DEBUG");
}

static void exchange_ambiguous_multi_present_readers(void) {
  const uint8_t get_info[] = {0x04u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  bridge_setup();
  mock_pcsc_set_reader_pair("Reader Alpha 00 00", "Reader Beta 00 00");
  mock_pcsc_set_multi_present_readers(true);
  expect_true(pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, get_info, sizeof(get_info),
                                        response, sizeof(response), &response_len, err,
                                        sizeof(err)),
              "multi-present reader pick succeeds");
}

static void exchange_wait_for_card_status_timeouts(void) {
  const uint8_t get_info[] = {0x04u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  bridge_setup();
  mock_pcsc_set_get_status_timeouts_before_present(2u);
  expect_true(pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, get_info, sizeof(get_info),
                                        response, sizeof(response), &response_len, err,
                                        sizeof(err)),
              "status timeouts before card present succeed");
}

static void bridge_cancel_with_active_session(void) {
  const uint8_t get_info[] = {0x04u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  bridge_setup();
  expect_true(pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, get_info, sizeof(get_info),
                                        response, sizeof(response), &response_len, err,
                                        sizeof(err)),
              "session opens");
  pcsc_fido_bridge_cancel();
}

static void exchange_get_status_change_hard_fail(void) {
  const uint8_t get_info[] = {0x04u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  bridge_setup();
  mock_pcsc_set_get_status_fail(SCARD_F_INTERNAL_ERROR);
  expect_true(!pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, get_info,
                                         sizeof(get_info), response, sizeof(response),
                                         &response_len, err, sizeof(err)),
              "get status hard failure");
}

static void exchange_debug_cbor_skip_branches(void) {
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  const uint8_t pin_array[] = {0x02u, 0xA2u, 0x06u, 0x81u, 0xA0u, 0x05u, 0xA2u, 0x62u,
                               0x75u, 0x70u, 0xF4u, 0x62u, 0x75u, 0x76u, 0xF5u};
  const uint8_t make_uv[] = {0x01u, 0xA2u, 0x07u, 0xA2u, 0x62u, 0x75u, 0x76u, 0xF5u, 0x62u, 0x75u,
                             0x70u, 0xF4u, 0x08u, 0x50u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u,
                             0x07u, 0x08u, 0x09u, 0x0Au, 0x0Bu, 0x0Cu, 0x0Du, 0x0Eu, 0x0Fu, 0x10u,
                             0x11u, 0x12u, 0x13u, 0x14u, 0x15u, 0x16u, 0x17u, 0x18u, 0x19u, 0x1Au,
                             0x1Bu, 0x1Cu, 0x1Du, 0x1Eu, 0x1Fu, 0x20u};
  const uint8_t get_info[] = {0x0Au, 0xA0u};
  const uint8_t wide_map[] = {0x02u, 0xB9u, 0x00u, 0x05u, 0x05u, 0xA2u, 0x62u, 0x75u, 0x70u,
                              0xF4u, 0x62u, 0x75u, 0x76u, 0xF5u, 0x06u, 0x50u, 0x01u, 0x02u,
                              0x03u, 0x04u, 0x05u, 0x06u, 0x07u, 0x08u, 0x09u, 0x0Au, 0x0Bu,
                              0x0Cu, 0x0Du, 0x0Eu, 0x0Fu, 0x10u, 0x11u, 0x12u, 0x13u, 0x14u,
                              0x15u, 0x16u, 0x04u, 0x01u, 0x03u, 0xC2u, 0x00u, 0x00u, 0x01u,
                              0x02u, 0x07u, 0xA1u, 0x63u, 0x66u, 0x6Fu, 0x6Fu, 0x01u};
  const uint8_t tagged_value[] = {0x02u, 0xA2u, 0x04u, 0xC0u, 0x00u, 0x05u, 0xA0u};
  bridge_setup();
  setenv("PCSC_FIDO_DEBUG", "1", 1);
  mock_pcsc_set_transmit_response((const uint8_t[]){0x00u, 0xA0u, 0x90u, 0x00u}, 4u);
  (void)pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, pin_array, sizeof(pin_array),
                                  response, sizeof(response), &response_len, err, sizeof(err));
  (void)pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, make_uv, sizeof(make_uv),
                                  response, sizeof(response), &response_len, err, sizeof(err));
  (void)pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, get_info, sizeof(get_info),
                                  response, sizeof(response), &response_len, err, sizeof(err));
  (void)pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, wide_map, sizeof(wide_map),
                                  response, sizeof(response), &response_len, err, sizeof(err));
  (void)pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, tagged_value,
                                  sizeof(tagged_value), response, sizeof(response), &response_len,
                                  err, sizeof(err));
  unsetenv("PCSC_FIDO_DEBUG");
}

static void exchange_make_credential_attestation_branches(void) {
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  const uint8_t payload[] = {0x01u, 0xA0u};
  const uint8_t bad_key[] = {0x00u, 0xA1u, 0xFFu, 0x00u, 0x90u, 0x00u};
  const uint8_t bad_att_key[] = {0x00u, 0xA2u, 0x01u, 0x41u, 0x00u, 0x02u, 0xA1u,
                                 0x63u, 0x66u, 0x6Fu, 0x6Fu, 0x00u, 0x90u, 0x00u};
  const uint8_t bad_auth[] = {0x00u, 0xA2u, 0x01u, 0x41u, 0x00u, 0x02u, 0xA1u, 0x68u, 0x61u, 0x75u,
                              0x74u, 0x68u, 0x44u, 0x61u, 0x74u, 0x61u, 0x01u, 0x90u, 0x00u};
  bridge_setup();
  setenv("PCSC_FIDO_DEBUG", "1", 1);
  mock_pcsc_set_transmit_response(bad_key, sizeof(bad_key));
  (void)pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, payload, sizeof(payload),
                                  response, sizeof(response), &response_len, err, sizeof(err));
  mock_pcsc_set_transmit_response(bad_att_key, sizeof(bad_att_key));
  (void)pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, payload, sizeof(payload),
                                  response, sizeof(response), &response_len, err, sizeof(err));
  mock_pcsc_set_transmit_response(bad_auth, sizeof(bad_auth));
  (void)pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, payload, sizeof(payload),
                                  response, sizeof(response), &response_len, err, sizeof(err));
  unsetenv("PCSC_FIDO_DEBUG");
}

static void exchange_get_assertion_authdata_58_encoding(void) {
  uint8_t auth[37];
  uint8_t mock_resp[64];
  size_t mock_len = 0u;
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  const uint8_t payload[] = {0x02u, 0xA0u};
  bridge_setup();
  memset(auth, 0, sizeof(auth));
  auth[32] = 0x05u;
  mock_len = 0u;
  mock_resp[mock_len++] = 0x00u;
  mock_resp[mock_len++] = 0xA1u;
  mock_resp[mock_len++] = 0x02u;
  mock_resp[mock_len++] = 0x58u;
  mock_resp[mock_len++] = 0x25u;
  memcpy(mock_resp + mock_len, auth, sizeof(auth));
  mock_len += sizeof(auth);
  mock_resp[mock_len++] = 0x90u;
  mock_resp[mock_len++] = 0x00u;
  setenv("PCSC_FIDO_DEBUG", "1", 1);
  mock_pcsc_set_transmit_response(mock_resp, mock_len);
  expect_true(pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, payload, sizeof(payload),
                                        response, sizeof(response), &response_len, err,
                                        sizeof(err)),
              "getAssertion 0x58 authData encoding logged");
  unsetenv("PCSC_FIDO_DEBUG");
}

static void exchange_sam_and_picc_contactless_auto_select(void) {
  const uint8_t get_info[] = {0x04u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  const uint8_t mock_resp[] = {0x00u, 0xA0u, 0x90u, 0x00u};
  bridge_setup();
  mock_pcsc_set_readers("ACS ACR1252 SAM 00 00\0ACS ACR1252 PICC 00 00\0\0");
  mock_pcsc_set_transmit_response(mock_resp, sizeof(mock_resp));
  expect_true(pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, get_info, sizeof(get_info),
                                        response, sizeof(response), &response_len, err,
                                        sizeof(err)),
              "SAM+PICC contactless auto-select exchange");
}

static void exchange_make_credential_uv_option_debug(void) {
  const uint8_t payload[] = {0x01u, 0xA1u, 0x07u, 0xA1u, 0x62u, 0x75u, 0x76u, 0xF5u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  const uint8_t mock_resp[] = {0x00u, 0xA0u, 0x90u, 0x00u};
  bridge_setup();
  setenv("PCSC_FIDO_DEBUG", "1", 1);
  mock_pcsc_set_transmit_response(mock_resp, sizeof(mock_resp));
  expect_true(pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, payload, sizeof(payload),
                                        response, sizeof(response), &response_len, err,
                                        sizeof(err)),
              "makeCredential uv option debug logging");
  unsetenv("PCSC_FIDO_DEBUG");
}

static void exchange_client_pin_command_debug(void) {
  const uint8_t payload[] = {0x06u, 0xA0u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  const uint8_t mock_resp[] = {0x00u, 0xA0u, 0x90u, 0x00u};
  bridge_setup();
  setenv("PCSC_FIDO_DEBUG", "1", 1);
  mock_pcsc_set_transmit_response(mock_resp, sizeof(mock_resp));
  expect_true(pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, payload, sizeof(payload),
                                        response, sizeof(response), &response_len, err,
                                        sizeof(err)),
              "clientPIN debug name logging");
  unsetenv("PCSC_FIDO_DEBUG");
}

static void exchange_transmit_reconnect_with_debug(void) {
  const uint8_t get_info[] = {0x04u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  const uint8_t mock_resp[] = {0x00u, 0xA0u, 0x90u, 0x00u};
  bridge_setup();
  setenv("PCSC_FIDO_DEBUG", "1", 1);
  mock_pcsc_set_transmit_fail_once(true);
  mock_pcsc_set_transmit_response(mock_resp, sizeof(mock_resp));
  expect_true(pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, get_info, sizeof(get_info),
                                        response, sizeof(response), &response_len, err,
                                        sizeof(err)),
              "debug reconnect exchange succeeds");
  unsetenv("PCSC_FIDO_DEBUG");
}

static void exchange_cancelled_reader_enum_message(void) {
  const uint8_t get_info[] = {0x04u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  pthread_t cancel_thread;
  bridge_setup();
  mock_pcsc_set_list_probe_always_no_readers(true);
  expect_true(pthread_create(&cancel_thread, nullptr, cancel_bridge_main, nullptr) == 0,
              "cancel thread starts for enum");
  expect_true(!pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, get_info,
                                         sizeof(get_info), response, sizeof(response),
                                         &response_len, err, sizeof(err)),
              "cancelled enum fails");
  (void)pthread_join(cancel_thread, nullptr);
}

static void exchange_wait_for_present_status_fail(void) {
  const uint8_t get_info[] = {0x04u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  bridge_setup();
  mock_pcsc_set_reader_pair("Reader Alpha 00 00", "Reader Beta 00 00");
  mock_pcsc_set_get_status_fail(SCARD_F_INTERNAL_ERROR);
  expect_true(!pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, get_info,
                                         sizeof(get_info), response, sizeof(response),
                                         &response_len, err, sizeof(err)),
              "wait-for-present status failure");
}

static void exchange_rate_limit_exceeded(void) {
  const uint8_t get_info[] = {0x04u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  bridge_setup();
  setenv("PCSC_FIDO_RATE_EXCHANGE", "1", 1);
  expect_true(pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, get_info, sizeof(get_info),
                                        response, sizeof(response), &response_len, err,
                                        sizeof(err)),
              "first exchange allowed");
  expect_true(!pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, get_info,
                                         sizeof(get_info), response, sizeof(response),
                                         &response_len, err, sizeof(err)),
              "second exchange blocked by rate limit");
  expect_true(strstr(err, "rate limit exceeded") != nullptr, "rate limit error message");
  unsetenv("PCSC_FIDO_RATE_EXCHANGE");
}

static void exchange_reconnect_failure_after_transmit_error(void) {
  const uint8_t get_info[] = {0x04u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  bridge_setup();
  mock_pcsc_set_transmit_fail_once(true);
  mock_pcsc_set_transmit_fail(true);
  expect_true(!pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, get_info,
                                         sizeof(get_info), response, sizeof(response),
                                         &response_len, err, sizeof(err)),
              "reconnect after transmit failure fails");
}

static void exchange_ensure_failure_after_session_reset(void) {
  const uint8_t get_info[] = {0x04u};
  uint8_t response[128];
  size_t response_len = 0u;
  char err[256];
  bridge_setup();
  expect_true(pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, get_info, sizeof(get_info),
                                        response, sizeof(response), &response_len, err,
                                        sizeof(err)),
              "first exchange opens session");
  pcsc_fido_bridge_reset();
  mock_pcsc_set_connect_fail(SCARD_E_NO_SMARTCARD);
  expect_true(!pcsc_fido_bridge_exchange(nullptr, PCSC_FIDO_HID_CMD_CBOR, get_info,
                                         sizeof(get_info), response, sizeof(response),
                                         &response_len, err, sizeof(err)),
              "reconnect failure after reset");
}

int main(void) {
  invalid_exchange_arguments();
  list_readers_success();
  list_readers_invalid_output();
  list_readers_establish_failure();
  list_readers_probe_error();
  exchange_getinfo_via_session();
  exchange_u2f_msg();
  exchange_unsupported_hid_command();
  exchange_select_fallback();
  exchange_connect_failure();
  exchange_connect_raw_protocol();
  exchange_connect_unknown_protocol();
  exchange_transmit_reconnect();
  exchange_non_success_ctap_status_still_returns_body();
  exchange_apdu_sw_failure();
  exchange_response_buffer_too_small();
  exchange_with_specific_reader();
  exchange_reader_no_match();
  exchange_get_assertion_and_debug();
  exchange_make_credential_logging();
  session_reuse();
  get_status_error();
  list_readers_fill_fail();
  list_readers_too_many();
  list_readers_no_readers_timeout();
  list_readers_contactless_suffix();
  exchange_establish_system_fallback();
  exchange_pcsc_fido_reader_env();
  exchange_ambiguous_readers_card_present();
  exchange_ambiguous_reader_needle();
  exchange_contactless_auto_select();
  exchange_preflight_forwarded_to_card();
  exchange_ctaphid_unframable_payload_too_large();
  exchange_u2f_msg_too_large();
  exchange_transmit_hard_fail();
  exchange_wait_for_card_timeout();
  exchange_cancelled_during_reader_enum();
  exchange_get_assertion_authdata_logging();
  exchange_make_credential_attestation_logging();
  exchange_ctap_request_options_logging();
  exchange_apdu_hex_truncation_logging();
  exchange_t0_protocol();
  exchange_cancel_during_transmit();
  exchange_cancel_interrupts_blocking_transmit();
  exchange_malformed_ctap_debug_paths();
  exchange_make_credential_malformed_response_debug();
  exchange_get_assertion_authdata_59_encoding();
  exchange_ambiguous_multi_present_readers();
  exchange_wait_for_card_status_timeouts();
  bridge_cancel_with_active_session();
  exchange_get_status_change_hard_fail();
  exchange_debug_cbor_skip_branches();
  exchange_make_credential_attestation_branches();
  exchange_get_assertion_authdata_58_encoding();
  exchange_sam_and_picc_contactless_auto_select();
  exchange_make_credential_uv_option_debug();
  exchange_client_pin_command_debug();
  exchange_transmit_reconnect_with_debug();
  exchange_cancelled_reader_enum_message();
  exchange_wait_for_present_status_fail();
  exchange_rate_limit_exceeded();
  exchange_reconnect_failure_after_transmit_error();
  exchange_ensure_failure_after_session_reset();
  return failures == 0 ? 0 : 1;
}
