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

#include "test_caps.h"

#include "mock_pcsc.h"

#include "pcsc_fido/pcsc_bridge_limits.h"
#include "pcsc_fido/pcsc_err.h"
#include "pcsc_fido/pcsc_reader_ops.h"
#include "pcsc_fido/pcsc_session.h"

#include <pthread.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pcsc_fido/pcsc_log.h"

static int failures;

static void expect_true(int condition, const char* message) {
  if (!condition) {
    pcsc_fido_log(PCSC_FIDO_LOG_ERROR, "FAIL: %s", message);
    failures++;
  }
}

static void establish_context_daemon_falls_back_to_user(void) {
  SCARDCONTEXT ctx = 0;
  char err[PCSC_FIDO_ERR_MSG_MAX];
  mock_pcsc_reset();
  mock_pcsc_set_establish_fail_system_scope(true);
  expect_true(pcsc_fido_reader_establish_context(
                  &ctx, PCSC_FIDO_READER_CTX_DAEMON, err, sizeof(err)),
              "daemon scope falls back to user context");
  expect_true(ctx != 0, "context handle assigned");
  (void)SCardReleaseContext(ctx);
}

static void establish_context_rejects_null(void) {
  char err[PCSC_FIDO_ERR_MSG_MAX];
  mock_pcsc_reset();
  expect_true(!pcsc_fido_reader_establish_context(
                  PCSC_FIDO_NULL, PCSC_FIDO_READER_CTX_USER, err, sizeof(err)),
              "null context rejected");
}

static void list_snapshot_and_fill_status_states(void) {
  SCARDCONTEXT ctx = 0;
  char readers[PCSC_FIDO_READER_LIST_BUF_MAX];
  DWORD readers_len = sizeof(readers);
  SCARD_READERSTATE states[PCSC_FIDO_BRIDGE_MAX_READERS];
  char err[PCSC_FIDO_ERR_MSG_MAX];
  size_t count;
  mock_pcsc_reset();
  mock_pcsc_set_readers("Ops Test PICC 00 00");
  expect_true(pcsc_fido_reader_establish_context(
                  &ctx, PCSC_FIDO_READER_CTX_USER, err, sizeof(err)),
              "establish for snapshot");
  expect_true(pcsc_fido_reader_list_snapshot(ctx, readers, &readers_len, err,
                                             sizeof(err)),
              "reader list snapshot succeeds");
  count = pcsc_fido_reader_fill_status_states(readers, readers_len, states,
                                              PCSC_FIDO_BRIDGE_MAX_READERS);
  expect_true(count == 1u, "one reader state filled");
  expect_true(states[0].szReader != PCSC_FIDO_NULL &&
                  states[0].dwCurrentState == SCARD_STATE_UNAWARE,
              "reader state initialized");
  (void)SCardReleaseContext(ctx);
}

static void list_snapshot_reports_no_readers(void) {
  SCARDCONTEXT ctx = 0;
  char readers[PCSC_FIDO_READER_LIST_BUF_MAX];
  DWORD readers_len = sizeof(readers);
  char err[PCSC_FIDO_ERR_MSG_MAX];
  mock_pcsc_reset();
  mock_pcsc_set_readers("");
  expect_true(pcsc_fido_reader_establish_context(
                  &ctx, PCSC_FIDO_READER_CTX_USER, err, sizeof(err)),
              "establish for empty snapshot");
  expect_true(!pcsc_fido_reader_list_snapshot(ctx, readers, &readers_len, err,
                                              sizeof(err)),
              "empty reader list snapshot fails");
  expect_true(strstr(err, "no PC/SC readers available") != PCSC_FIDO_NULL,
              "empty list error message");
  (void)SCardReleaseContext(ctx);
}

static void pci_for_protocol_maps_known_values(void) {
  expect_true(
      pcsc_fido_reader_pci_for_protocol(SCARD_PROTOCOL_T1) == SCARD_PCI_T1,
      "T=1 PCI");
  expect_true(
      pcsc_fido_reader_pci_for_protocol(SCARD_PROTOCOL_T0) == SCARD_PCI_T0,
      "T=0 PCI");
  expect_true(
      pcsc_fido_reader_pci_for_protocol(SCARD_PROTOCOL_RAW) == SCARD_PCI_RAW,
      "RAW PCI");
  expect_true(pcsc_fido_reader_pci_for_protocol(0u) == PCSC_FIDO_NULL,
              "unknown PCI rejected");
}

static void probe_fido_card_accepts_select_success(void) {
  SCARDCONTEXT ctx = 0;
  char err[PCSC_FIDO_ERR_MSG_MAX];
  mock_pcsc_reset();
  mock_pcsc_set_readers("Probe PICC 00 00");
  mock_pcsc_set_transmit_response((const uint8_t[]){TEST_LIT_0X90U, 0x00u},
                                  TEST_LIT_2U);
  expect_true(pcsc_fido_reader_establish_context(
                  &ctx, PCSC_FIDO_READER_CTX_USER, err, sizeof(err)),
              "establish for probe");
  expect_true(pcsc_fido_reader_probe_fido_card(ctx, "Probe PICC 00 00"),
              "FIDO probe succeeds");
  (void)SCardReleaseContext(ctx);
}

static void print_list_includes_contactless_suffix(void) {
  FILE* out = tmpfile();
  mock_pcsc_reset();
  mock_pcsc_set_readers("Listed PICC 00 00");
  if (out != PCSC_FIDO_NULL) {
    char err[PCSC_FIDO_ERR_MSG_MAX];
    char line[TEST_CAP_128];
    expect_true(pcsc_fido_reader_print_list(out, err, sizeof(err)),
                "print reader list");
    expect_true(fseek(out, 0, SEEK_SET) == 0, "rewind config stream");
    errno = 0;
    expect_true(fgets(line, sizeof(line), out) != PCSC_FIDO_NULL && errno == 0,
                "reader list line printed");
    expect_true(strstr(line, "[contactless]") != PCSC_FIDO_NULL,
                "contactless suffix printed");
    (void)fclose(out);
  } else {
    expect_true(false, "tmpfile for reader print list");
  }
}

static void select_and_wait_uses_env_reader(void) {
  SCARDCONTEXT ctx = 0;
  char reader[PCSC_FIDO_READER_NAME_MAX];
  char err[PCSC_FIDO_ERR_MSG_MAX];
  mock_pcsc_reset();
  mock_pcsc_set_reader_pair("Other Reader 00 00", "Needle PICC 00 00");
  expect_true(pcsc_fido_reader_establish_context(
                  &ctx, PCSC_FIDO_READER_CTX_USER, err, sizeof(err)),
              "establish for select");
  setenv("PCSC_FIDO_READER", "Needle", 1);
  expect_true(
      pcsc_fido_reader_select_and_wait(ctx, PCSC_FIDO_NULL, reader,
                                       sizeof(reader), err, sizeof(err)),
      "env needle selects matching reader");
  expect_true(strstr(reader, "Needle PICC") != PCSC_FIDO_NULL,
              "env needle reader chosen");
  unsetenv("PCSC_FIDO_READER");
  (void)SCardReleaseContext(ctx);
}

static void* cancel_card_wait_main(void* arg) {
  (void)arg;
  pcsc_fido_session_cancel();
  return PCSC_FIDO_NULL;
}

static void select_and_wait_cancelled_while_waiting_for_card(void) {
  SCARDCONTEXT ctx = 0;
  char reader[PCSC_FIDO_READER_NAME_MAX];
  char err[PCSC_FIDO_ERR_MSG_MAX];
  pthread_t cancel_thread;
  mock_pcsc_reset();
  mock_pcsc_set_readers("Wait Reader 00 00");
  mock_pcsc_set_card_present_immediately(false);
  pcsc_fido_session_clear_cancel();
  expect_true(pcsc_fido_reader_establish_context(
                  &ctx, PCSC_FIDO_READER_CTX_USER, err, sizeof(err)),
              "establish for card wait cancel");
  expect_true(pthread_create(&cancel_thread, PCSC_FIDO_NULL,
                             cancel_card_wait_main, PCSC_FIDO_NULL) == 0,
              "cancel thread starts");
  expect_true(
      !pcsc_fido_reader_select_and_wait(ctx, PCSC_FIDO_NULL, reader,
                                        sizeof(reader), err, sizeof(err)),
      "card wait cancelled");
  expect_true(
      strstr(err, PCSC_FIDO_ERR_MSG_CANCELLED_CARD_WAIT) != PCSC_FIDO_NULL,
      "cancel error message");
  (void)pthread_join(cancel_thread, PCSC_FIDO_NULL);
  (void)SCardReleaseContext(ctx);
}

static void select_and_wait_cancel_survives_session_reset(void) {
  SCARDCONTEXT ctx = 0;
  char reader[PCSC_FIDO_READER_NAME_MAX];
  char err[PCSC_FIDO_ERR_MSG_MAX];
  mock_pcsc_reset();
  mock_pcsc_set_readers("Wait Reader 00 00");
  mock_pcsc_set_card_present_immediately(false);
  pcsc_fido_session_clear_cancel();
  expect_true(pcsc_fido_reader_establish_context(
                  &ctx, PCSC_FIDO_READER_CTX_USER, err, sizeof(err)),
              "establish for reset-preserved card wait cancel");
  pcsc_fido_session_cancel();
  pcsc_fido_session_reset();
  expect_true(
      !pcsc_fido_reader_select_and_wait(ctx, PCSC_FIDO_NULL, reader,
                                        sizeof(reader), err, sizeof(err)),
      "card wait cancel survives reset");
  expect_true(
      strstr(err, PCSC_FIDO_ERR_MSG_CANCELLED_CARD_WAIT) != PCSC_FIDO_NULL,
      "reset-preserved cancel error message");
  pcsc_fido_session_clear_cancel();
  (void)SCardReleaseContext(ctx);
}

int main(void) {
  establish_context_daemon_falls_back_to_user();
  establish_context_rejects_null();
  list_snapshot_and_fill_status_states();
  list_snapshot_reports_no_readers();
  pci_for_protocol_maps_known_values();
  probe_fido_card_accepts_select_success();
  print_list_includes_contactless_suffix();
  select_and_wait_uses_env_reader();
  select_and_wait_cancelled_while_waiting_for_card();
  select_and_wait_cancel_survives_session_reset();
  pcsc_fido_session_reset();
  return failures == 0 ? 0 : 1;
}
