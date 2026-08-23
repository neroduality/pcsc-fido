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

#include "pcsc_fido/daemon_request_handler.h"

#include "pcsc_fido/daemon_policy.h"
#include "pcsc_fido/exchange_orchestrator.h"
#include "pcsc_fido/pcsc_bridge.h"
#include "pcsc_fido/pcsc_bridge_limits.h"
#include "pcsc_fido/pcsc_err.h"
#include "pcsc_fido/pcsc_log.h"
#include "pcsc_fido/uhid_transport.h"

#include "pcsc_fido/mem_util.h"

#include <string.h>

void pcsc_fido_daemon_handle_hid_request(
    const pcsc_fido_daemon_request_context_t* ctx, uint32_t request_cid,
    uint8_t cmd, const uint8_t* payload, size_t payload_len) {
  /* Local CTAPHID (INIT/PING/CANCEL/WINK/LOCK) vs CBOR/MSG via keepalive
   * exchange; map cancel/rate-limit to HID errors; scrub the response. */
  int uhid_fd;
  const uint32_t* assigned_cid;
  uint8_t response[PCSC_FIDO_DAEMON_PENDING_MAX];
  size_t response_len = 0u;
  char err[PCSC_FIDO_ERR_MSG_MAX];
  if (ctx == PCSC_FIDO_NULL || ctx->assigned_cid == PCSC_FIDO_NULL) {
    return;
  }
  uhid_fd = ctx->fd;
  assigned_cid = ctx->assigned_cid;
  pcsc_fido_zero_bytes(err, sizeof(err));
  if (cmd == PCSC_FIDO_HID_CMD_INIT) {
    uint8_t init_response[PCSC_FIDO_HID_INIT_RESP_LEN];
    const size_t info_off =
        PCSC_FIDO_HID_INIT_NONCE_LEN + PCSC_FIDO_HID_INIT_RESP_CID_LEN;
    if (payload == PCSC_FIDO_NULL ||
        payload_len != PCSC_FIDO_HID_INIT_NONCE_LEN) {
      (void)pcsc_fido_daemon_send_hid_error(uhid_fd, request_cid,
                                            PCSC_FIDO_DAEMON_ERR_INVALID_LEN);
      return;
    }
    if (!pcsc_fido_copy_bytes(init_response, sizeof(init_response), 0u, payload,
                              PCSC_FIDO_HID_INIT_NONCE_LEN)) {
      (void)pcsc_fido_daemon_send_hid_error(uhid_fd, request_cid,
                                            PCSC_FIDO_DAEMON_ERR_INVALID_LEN);
      return;
    }
    init_response[PCSC_FIDO_HID_INIT_NONCE_LEN + PCSC_FIDO_HID_OFF_CID_B0] =
        (uint8_t)((*assigned_cid >> PCSC_FIDO_U32_SHIFT_BYTE3) &
                  PCSC_FIDO_BYTE_MASK);
    init_response[PCSC_FIDO_HID_INIT_NONCE_LEN + PCSC_FIDO_HID_OFF_CID_B1] =
        (uint8_t)((*assigned_cid >> PCSC_FIDO_U32_SHIFT_BYTE2) &
                  PCSC_FIDO_BYTE_MASK);
    init_response[PCSC_FIDO_HID_INIT_NONCE_LEN + PCSC_FIDO_HID_OFF_CID_B2] =
        (uint8_t)((*assigned_cid >> PCSC_FIDO_U32_SHIFT_BYTE1) &
                  PCSC_FIDO_BYTE_MASK);
    init_response[PCSC_FIDO_HID_INIT_NONCE_LEN + PCSC_FIDO_HID_OFF_CID_B3] =
        (uint8_t)(*assigned_cid & PCSC_FIDO_BYTE_MASK);
    init_response[info_off + PCSC_FIDO_HID_INIT_RESP_INFO_OFF_PROTOCOL] =
        PCSC_FIDO_HID_INIT_RESP_PROTOCOL_VERSION;
    init_response[info_off + PCSC_FIDO_HID_INIT_RESP_INFO_OFF_MAJOR] =
        PCSC_FIDO_HID_INIT_RESP_MAJOR;
    init_response[info_off + PCSC_FIDO_HID_INIT_RESP_INFO_OFF_MINOR] =
        PCSC_FIDO_HID_INIT_RESP_MINOR;
    init_response[info_off + PCSC_FIDO_HID_INIT_RESP_INFO_OFF_BUILD] =
        PCSC_FIDO_HID_INIT_RESP_BUILD;
    init_response[info_off + PCSC_FIDO_HID_INIT_RESP_INFO_OFF_CAPABILITIES] =
        PCSC_FIDO_DAEMON_CAP_WINK | PCSC_FIDO_DAEMON_CAP_CBOR;
    (void)pcsc_fido_daemon_send_hid_response(
        uhid_fd, request_cid, PCSC_FIDO_HID_CMD_INIT, init_response,
        sizeof(init_response));
    return;
  }
  if (request_cid != *assigned_cid) {
    (void)pcsc_fido_daemon_send_hid_error(uhid_fd, request_cid,
                                          PCSC_FIDO_DAEMON_ERR_OTHER);
    return;
  }
  if (cmd == PCSC_FIDO_HID_CMD_PING) {
    if (payload_len > PCSC_FIDO_CTAPHID_MAX_FRAMED_PAYLOAD) {
      (void)pcsc_fido_daemon_send_hid_error(uhid_fd, request_cid,
                                            PCSC_FIDO_DAEMON_ERR_INVALID_LEN);
      return;
    }
    (void)pcsc_fido_daemon_send_hid_response(
        uhid_fd, request_cid, PCSC_FIDO_HID_CMD_PING, payload, payload_len);
    return;
  }
  if (cmd == PCSC_FIDO_HID_CMD_CANCEL) {
    pcsc_fido_log(PCSC_FIDO_LOG_DEBUG, "CTAPHID CANCEL received");
    pcsc_fido_bridge_reset();
    return;
  }
  if (cmd == PCSC_FIDO_HID_CMD_WINK || cmd == PCSC_FIDO_HID_CMD_LOCK) {
    (void)pcsc_fido_daemon_send_hid_response(uhid_fd, request_cid, cmd,
                                             PCSC_FIDO_NULL, 0u);
    return;
  }
  if (cmd != PCSC_FIDO_HID_CMD_CBOR && cmd != PCSC_FIDO_HID_CMD_MSG) {
    (void)pcsc_fido_daemon_send_hid_error(uhid_fd, request_cid,
                                          PCSC_FIDO_DAEMON_ERR_INVALID_CMD);
    return;
  }
  if (!pcsc_fido_daemon_run_exchange_with_keepalive(
          uhid_fd, request_cid, cmd, payload, payload_len, response,
          sizeof(response), &response_len, err, sizeof(err))) {
    if (strcmp(err, PCSC_FIDO_ERR_MSG_CANCELLED) == 0 &&
        cmd == PCSC_FIDO_HID_CMD_CBOR) {
      const uint8_t cancelled = PCSC_FIDO_DAEMON_CTAP2_ERR_KEEPALIVE_CANCEL;
      (void)pcsc_fido_daemon_send_hid_response(uhid_fd, request_cid, cmd,
                                               &cancelled, 1u);
      return;
    }
    if (strcmp(err, PCSC_FIDO_ERR_MSG_RATE_LIMIT) == 0) {
      (void)pcsc_fido_daemon_send_hid_error(uhid_fd, request_cid,
                                            PCSC_FIDO_DAEMON_ERR_CHANNEL_BUSY);
      return;
    }
    pcsc_fido_log(PCSC_FIDO_LOG_INFO, "PC/SC bridge failed: %s", err);
    (void)pcsc_fido_daemon_send_hid_error(uhid_fd, request_cid,
                                          PCSC_FIDO_DAEMON_ERR_OTHER);
    return;
  }
  (void)pcsc_fido_daemon_send_hid_response(uhid_fd, request_cid, cmd, response,
                                           response_len);
  if (pcsc_fido_daemon_is_terminal_webauthn_request(cmd, payload,
                                                    payload_len)) {
    pcsc_fido_log(PCSC_FIDO_LOG_DEBUG,
                  "completed WebAuthn operation; resetting PC/SC session");
    pcsc_fido_bridge_reset();
  }
  /* Scrub the assembled CTAP response (assertion / attestation material) from
   * the stack before returning; guaranteed-erase so it is not left resident. */
  pcsc_fido_secure_clear(response, sizeof(response));
}
