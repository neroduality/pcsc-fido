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

#include "pcsc_fido/apdu.h"
#include "pcsc_fido/ctaphid.h"
#include "pcsc_fido/daemon_policy.h"
#include "pcsc_fido/daemon_rate_limit.h"
#include "pcsc_fido/mem_util.h"
#include "pcsc_fido/pcsc_bridge.h"
#include "pcsc_fido/pcsc_bridge_debug.h"
#include "pcsc_fido/pcsc_bridge_limits.h"
#include "pcsc_fido/pcsc_err.h"
#include "pcsc_fido/pcsc_log.h"
#include "pcsc_fido/pcsc_reader_ops.h"
#include "pcsc_fido/pcsc_session.h"

#include <stdio.h>
#include <string.h>

bool pcsc_fido_bridge_list_readers(FILE *out, char *err, size_t err_cap) {
  return pcsc_fido_reader_print_list(out, err, err_cap);
}

void pcsc_fido_bridge_reset(void) {
  pcsc_fido_session_reset();
  pcsc_fido_rate_limit_reset();
}

void pcsc_fido_bridge_cancel(void) {
  pcsc_fido_session_cancel();
}

bool pcsc_fido_bridge_exchange(const char *reader_needle, uint8_t hid_cmd, const uint8_t *payload,
                               size_t payload_len, uint8_t *response, size_t response_cap,
                               size_t *response_len, char *err, size_t err_cap) {
  uint8_t capdu[PCSC_FIDO_BRIDGE_MAX_APDU];
  uint8_t rapdu[PCSC_FIDO_BRIDGE_MAX_RESPONSE];
  pcsc_fido_session_tx_t tx;
  size_t capdu_len = 0u;
  size_t rapdu_len = 0u;
  bool ok = false;
  bool session_error = false;
  if (response_len == nullptr || response == nullptr || (payload == nullptr && payload_len != 0u)) {
    pcsc_fido_set_err(err, err_cap, "invalid bridge exchange arguments");
    return false;
  }
  *response_len = 0u;
  if (payload_len > PCSC_FIDO_CTAPHID_MAX_FRAMED_PAYLOAD) {
    pcsc_fido_set_err(err, err_cap, "CTAPHID payload too large");
    return false;
  }
  if (!pcsc_fido_rate_limit_allow_exchange()) {
    pcsc_fido_set_err(err, err_cap, PCSC_FIDO_ERR_MSG_RATE_LIMIT);
    return false;
  }
  pcsc_fido_session_clear_cancel();
  if (!pcsc_fido_session_ensure(reader_needle, err, err_cap)) {
    return false;
  }
  if (!pcsc_fido_session_snapshot_tx(&tx, err, err_cap)) {
    return false;
  }
  if (!pcsc_fido_session_tx_is_current(&tx)) {
    pcsc_fido_set_err(err, err_cap, "PC/SC session changed before transmit");
    session_error = true;
    goto out;
  }
  pcsc_fido_bridge_log_ctap2_request_summary(hid_cmd, payload, payload_len);
  if (hid_cmd == PCSC_FIDO_HID_CMD_CBOR) {
    if (pcsc_fido_bridge_debug_enabled() &&
        pcsc_fido_daemon_is_get_assertion(hid_cmd, payload, payload_len)) {
      pcsc_fido_bridge_log_apdu_response_hex("getAssertion request", payload, payload_len);
    }
    if (!pcsc_fido_pack_ctap2_cbor_apdu(payload, payload_len, capdu, sizeof(capdu), &capdu_len)) {
      pcsc_fido_set_err(err, err_cap, "CTAP CBOR APDU too large");
      goto out;
    }
  } else if (hid_cmd == PCSC_FIDO_HID_CMD_MSG) {
    if (payload_len > sizeof(capdu)) {
      pcsc_fido_set_err(err, err_cap, "U2F MSG APDU too large");
      goto out;
    }
    if (!pcsc_fido_copy_bytes(capdu, sizeof(capdu), 0u, payload, payload_len)) {
      pcsc_fido_set_err(err, err_cap, "U2F MSG APDU too large");
      goto out;
    }
    capdu_len = payload_len;
  } else {
    pcsc_fido_set_err(err, err_cap, "unsupported HID command for PC/SC bridge");
    goto out;
  }
  if (pcsc_fido_bridge_debug_enabled()) {
    pcsc_fido_log(PCSC_FIDO_LOG_DEBUG,
                  "SCardTransmit start hid=0x%02X ctap=0x%02X payload=%zu apdu=%zu", hid_cmd,
                  (hid_cmd == PCSC_FIDO_HID_CMD_CBOR && payload_len > 0u) ? payload[0] : 0u,
                  payload_len, capdu_len);
  }
  if (!pcsc_fido_session_tx_is_current(&tx)) {
    pcsc_fido_set_err(err, err_cap, "PC/SC session changed before transmit");
    session_error = true;
    goto out;
  }
  if (!pcsc_fido_session_transmit_chained(&tx, capdu, capdu_len, rapdu, sizeof(rapdu), &rapdu_len,
                                          err, err_cap)) {
    if (pcsc_fido_session_cancel_requested()) {
      pcsc_fido_set_err(err, err_cap, PCSC_FIDO_ERR_MSG_CANCELLED);
      session_error = true;
      goto out;
    }
    pcsc_fido_log(PCSC_FIDO_LOG_DEBUG, "SCardTransmit failed; reconnecting PC/SC session once");
    pcsc_fido_session_reset();
    if (!pcsc_fido_session_ensure(reader_needle, err, err_cap) ||
        !pcsc_fido_session_snapshot_tx(&tx, err, err_cap) ||
        !pcsc_fido_session_tx_is_current(&tx) ||
        !pcsc_fido_session_transmit_chained(&tx, capdu, capdu_len, rapdu, sizeof(rapdu), &rapdu_len,
                                            err, err_cap) ||
        !pcsc_fido_session_tx_is_current(&tx)) {
      session_error = true;
      goto out;
    }
  }
  if (!pcsc_fido_session_tx_is_current(&tx)) {
    pcsc_fido_set_err(err, err_cap, "PC/SC session changed after transmit");
    session_error = true;
    goto out;
  }
  if (pcsc_fido_bridge_debug_enabled()) {
    pcsc_fido_log(PCSC_FIDO_LOG_DEBUG, "SCardTransmit done hid=0x%02X response=%zu sw=%04X",
                  hid_cmd, rapdu_len, pcsc_fido_apdu_status_word(rapdu, rapdu_len));
  }
  if (hid_cmd == PCSC_FIDO_HID_CMD_CBOR) {
    if (pcsc_fido_apdu_status_word(rapdu, rapdu_len) != 0x9000u || rapdu_len < 3u) {
      unsigned sw = pcsc_fido_apdu_status_word(rapdu, rapdu_len);
      unsigned ctap_status = rapdu_len >= 3u ? rapdu[0] : 0xFFu;
      pcsc_fido_log(PCSC_FIDO_LOG_INFO,
                    "CTAP2 NFC APDU non-success hid=0x%02X ctap=0x%02X response=%zu sw=%04X "
                    "ctap_status=0x%02X",
                    hid_cmd, payload_len > 0u ? payload[0] : 0u, rapdu_len, sw, ctap_status);
      pcsc_fido_bridge_log_apdu_response_hex("APDU non-success response", rapdu, rapdu_len);
      (void)pcsc_fido_format_err(err, err_cap,
                                 "CTAP2 NFC APDU returned non-success status (sw=%04X "
                                 "ctap_status=0x%02X)",
                                 sw, ctap_status);
      session_error = true;
      goto out;
    }
    if (pcsc_fido_bridge_debug_enabled()) {
      pcsc_fido_log(PCSC_FIDO_LOG_DEBUG, "CTAP2 response status=0x%02X payload=%zu", rapdu[0],
                    rapdu_len - 3u);
    }
    if (rapdu[0] != 0x00u || rapdu_len <= 8u) {
      pcsc_fido_bridge_log_apdu_response_hex("APDU non-success response", rapdu, rapdu_len);
    }
    if (payload_len > 0u && payload[0] == 0x02u) {
      pcsc_fido_bridge_log_get_assertion_summary(rapdu, rapdu_len);
      pcsc_fido_bridge_log_apdu_response_hex("getAssertion response", rapdu, rapdu_len);
    } else if (payload_len > 0u && payload[0] == 0x01u) {
      pcsc_fido_bridge_log_make_credential_summary(rapdu, rapdu_len);
    }
    rapdu_len -= 2u;
  }
  if (!pcsc_fido_copy_bytes(response, response_cap, 0u, rapdu, rapdu_len)) {
    pcsc_fido_set_err(err, err_cap, "response buffer too small");
    goto out;
  }
  *response_len = rapdu_len;
  ok = true;

out:
  pcsc_fido_secure_clear(capdu, sizeof(capdu));
  pcsc_fido_secure_clear(rapdu, sizeof(rapdu));
  if (session_error) {
    pcsc_fido_session_reset();
  }
  return ok;
}
