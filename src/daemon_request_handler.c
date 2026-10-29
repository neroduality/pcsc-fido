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

#include "pcsc_fido/apdu.h"
#include "pcsc_fido/ctaphid.h"
#include "pcsc_fido/daemon_policy.h"
#include "pcsc_fido/daemon_rate_limit.h"
#include "pcsc_fido/exchange_orchestrator.h"
#include "pcsc_fido/pcsc_bridge.h"
#include "pcsc_fido/pcsc_bridge_limits.h"
#include "pcsc_fido/pcsc_err.h"
#include "pcsc_fido/pcsc_log.h"
#include "pcsc_fido/uhid_transport.h"

#include "pcsc_fido/mem_util.h"

#include <string.h>

/* INIT on broadcast allocates a channel; INIT on a live channel
 * resynchronizes it and keeps its ID. The reply echoes the nonce. */
static void answer_init(int uhid_fd, pcsc_fido_daemon_channels_t* channels,
                        uint32_t request_cid, const uint8_t* payload,
                        size_t payload_len) {
  uint32_t channel_cid;
  uint8_t init_response[PCSC_FIDO_HID_INIT_RESP_LEN];
  /* Nonce echo + assigned CID; scope-exit scrub on every INIT return. */
  PCSC_FIDO_SCRUB_ON_EXIT(init_response, sizeof(init_response));
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
  if (request_cid == PCSC_FIDO_HID_BROADCAST_CID) {
    bool session_dropped = false;
    channel_cid =
        pcsc_fido_daemon_channels_allocate(channels, &session_dropped);
    /* The evicted owner can no longer send the CBOR/MSG that would have
     * abandoned its sequence, so drop the card now. */
    if (session_dropped) {
      pcsc_fido_bridge_reset();
    }
  } else if (pcsc_fido_daemon_channels_touch(channels, request_cid)) {
    channel_cid = request_cid;
  } else {
    (void)pcsc_fido_daemon_send_hid_error(uhid_fd, request_cid,
                                          PCSC_FIDO_DAEMON_ERR_INVALID_CHANNEL);
    return;
  }
  init_response[PCSC_FIDO_HID_INIT_NONCE_LEN + PCSC_FIDO_HID_OFF_CID_B0] =
      (uint8_t)((channel_cid >> PCSC_FIDO_U32_SHIFT_BYTE3) &
                PCSC_FIDO_BYTE_MASK);
  init_response[PCSC_FIDO_HID_INIT_NONCE_LEN + PCSC_FIDO_HID_OFF_CID_B1] =
      (uint8_t)((channel_cid >> PCSC_FIDO_U32_SHIFT_BYTE2) &
                PCSC_FIDO_BYTE_MASK);
  init_response[PCSC_FIDO_HID_INIT_NONCE_LEN + PCSC_FIDO_HID_OFF_CID_B2] =
      (uint8_t)((channel_cid >> PCSC_FIDO_U32_SHIFT_BYTE1) &
                PCSC_FIDO_BYTE_MASK);
  init_response[PCSC_FIDO_HID_INIT_NONCE_LEN + PCSC_FIDO_HID_OFF_CID_B3] =
      (uint8_t)(channel_cid & PCSC_FIDO_BYTE_MASK);
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
}

/* Whether a successful response ends the WebAuthn operation, so its PC/SC
 * session should be reset: makeCredential, or a non-probe getAssertion. A
 * getAssertion that reports numberOfCredentials > 1 hands out the rest through
 * getNextAssertion on the same session, so the reset waits for the last. */
static bool ends_webauthn_operation(pcsc_fido_daemon_channels_t* channels,
                                    uint8_t cmd, const uint8_t* payload,
                                    size_t payload_len, const uint8_t* response,
                                    size_t response_len) {
  size_t credentials = 0u;
  if (pcsc_fido_daemon_is_get_next_assertion(cmd, payload, payload_len)) {
    if (channels->next_assertions_left == 0u) {
      return false;
    }
    /* An error (say, the authenticator's own timer ran out) also ends it. */
    if (response_len == 0u || response[0] != PCSC_FIDO_CTAP2_OK) {
      channels->next_assertions_left = 0u;
    } else {
      channels->next_assertions_left--;
    }
    return channels->next_assertions_left == 0u;
  }
  if (!pcsc_fido_daemon_is_terminal_webauthn_request(cmd, payload,
                                                     payload_len)) {
    return false;
  }
  if (pcsc_fido_daemon_is_get_assertion(cmd, payload, payload_len)) {
    credentials =
        pcsc_fido_daemon_get_assertion_credential_count(response, response_len);
  }
  if (credentials > 1u) {
    size_t left = credentials - 1u;
    if (left > PCSC_FIDO_DAEMON_MAX_NEXT_ASSERTIONS) {
      left = PCSC_FIDO_DAEMON_MAX_NEXT_ASSERTIONS;
    }
    channels->next_assertions_left = left;
    return false;
  }
  return true;
}

void pcsc_fido_daemon_handle_hid_request(
    const pcsc_fido_daemon_request_context_t* ctx, uint32_t request_cid,
    uint8_t cmd, const uint8_t* payload, size_t payload_len) {
  /* Local CTAPHID (INIT/PING/CANCEL/WINK/LOCK) vs CBOR/MSG via keepalive
   * exchange; map cancel/rate-limit to HID errors; scrub the response. */
  int uhid_fd;
  pcsc_fido_daemon_channels_t* channels;
  uint8_t response[PCSC_FIDO_DAEMON_PENDING_MAX];
  size_t response_len = 0u;
  char err[PCSC_FIDO_ERR_MSG_MAX];
  /* Scope-exit scrub of the assembled CTAP response (assertion / attestation
   * material) and of the status text copied out of the exchange job. */
  PCSC_FIDO_SCRUB_ON_EXIT(response, sizeof(response));
  if (ctx == PCSC_FIDO_NULL || ctx->channels == PCSC_FIDO_NULL) {
    return;
  }
  uhid_fd = ctx->fd;
  channels = ctx->channels;
  pcsc_fido_zero_bytes(err, sizeof(err));
  if (cmd == PCSC_FIDO_HID_CMD_INIT) {
    answer_init(uhid_fd, channels, request_cid, payload, payload_len);
    return;
  }
  if (!pcsc_fido_daemon_channels_touch(channels, request_cid)) {
    (void)pcsc_fido_daemon_send_hid_error(uhid_fd, request_cid,
                                          PCSC_FIDO_DAEMON_ERR_INVALID_CHANNEL);
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
    /* Only the channel that last used the card may drop its session; another
     * client's CANCEL must not discard PIN/UV state mid-operation. */
    if (request_cid == channels->session_owner) {
      pcsc_fido_daemon_channels_release_session(channels);
      pcsc_fido_bridge_reset();
    }
    return;
  }
  /* LOCK is not implemented (and not advertised), so it falls through to
   * ERR_INVALID_CMD rather than claiming a lock that is never enforced. */
  if (cmd == PCSC_FIDO_HID_CMD_WINK) {
    (void)pcsc_fido_daemon_send_hid_response(uhid_fd, request_cid, cmd,
                                             PCSC_FIDO_NULL, 0u);
    return;
  }
  if (cmd != PCSC_FIDO_HID_CMD_CBOR && cmd != PCSC_FIDO_HID_CMD_MSG) {
    (void)pcsc_fido_daemon_send_hid_error(uhid_fd, request_cid,
                                          PCSC_FIDO_DAEMON_ERR_INVALID_CMD);
    return;
  }
  /* CTAP2 needs at least the command byte and U2F a full APDU header; a
   * shorter request would reach the card as a malformed APDU. */
  if (payload_len == 0u || (cmd == PCSC_FIDO_HID_CMD_MSG &&
                            payload_len < PCSC_FIDO_APDU_HEADER_LEN)) {
    (void)pcsc_fido_daemon_send_hid_error(uhid_fd, request_cid,
                                          PCSC_FIDO_DAEMON_ERR_INVALID_LEN);
    return;
  }
  /* Refuse before abandoning a getNextAssertion sequence or taking over
   * session_owner. A CHANNEL_BUSY reply means the host retries; the card
   * and the channel that last used it stay as they are. */
  if (!pcsc_fido_rate_limit_charge_exchange()) {
    (void)pcsc_fido_daemon_send_hid_error(uhid_fd, request_cid,
                                          PCSC_FIDO_DAEMON_ERR_CHANNEL_BUSY);
    return;
  }
  /* Another channel never inherits the open card (PIN/UV, getNext). The
   * owner's own non-getNext command abandons a pending sequence. Either way
   * the request then starts on a fresh session. A rate-limited exchange
   * returned above and did not get here. */
  if (channels->session_owner != 0u && request_cid != channels->session_owner) {
    pcsc_fido_log(PCSC_FIDO_LOG_DEBUG,
                  "another channel is starting a PC/SC operation; resetting "
                  "the previous session");
    pcsc_fido_daemon_channels_release_session(channels);
    pcsc_fido_bridge_reset();
  } else if (channels->next_assertions_left > 0u &&
             !pcsc_fido_daemon_is_get_next_assertion(cmd, payload,
                                                     payload_len)) {
    pcsc_fido_log(PCSC_FIDO_LOG_DEBUG,
                  "getNextAssertion sequence abandoned; resetting PC/SC "
                  "session");
    pcsc_fido_daemon_channels_release_session(channels);
    pcsc_fido_bridge_reset();
  }
  if (!pcsc_fido_daemon_run_exchange_with_keepalive(
          uhid_fd, request_cid, cmd, payload, payload_len, response,
          sizeof(response), &response_len, err, sizeof(err))) {
    const bool rate_limited = strcmp(err, PCSC_FIDO_ERR_MSG_RATE_LIMIT) == 0;
    const bool cancelled = strcmp(err, PCSC_FIDO_ERR_MSG_CANCELLED) == 0;
    const bool closed = strcmp(err, PCSC_FIDO_ERR_MSG_CLIENT_CLOSED) == 0;
    const bool resync = strcmp(err, PCSC_FIDO_ERR_MSG_RESYNC) == 0;
    /* These return before the worker enters the bridge. Resetting here would
     * drop a getNextAssertion quota the card still holds, and the in-progress
     * loser would SCardCancel the winner's transmit. */
    const bool not_started =
        strcmp(err, PCSC_FIDO_ERR_MSG_EXCHANGE_IN_PROGRESS) == 0 ||
        strcmp(err, PCSC_FIDO_ERR_MSG_EXCHANGE_MUTEX) == 0 ||
        strcmp(err, PCSC_FIDO_ERR_MSG_EXCHANGE_THREAD) == 0;
    if (not_started) {
      const uint8_t code =
          strcmp(err, PCSC_FIDO_ERR_MSG_EXCHANGE_IN_PROGRESS) == 0
              ? (uint8_t)PCSC_FIDO_DAEMON_ERR_CHANNEL_BUSY
              : (uint8_t)PCSC_FIDO_DAEMON_ERR_OTHER;
      (void)pcsc_fido_daemon_send_hid_error(uhid_fd, request_cid, code);
      return;
    }
    /* The charge above is the only rate-limit decision, and it happens
     * before the card is touched. A bridge-level rate limit (the charge mark
     * was lost) therefore leaves a getNextAssertion sequence valid. Every
     * other failure reached the card: the authenticator's remaining assertions
     * do not survive a disconnect, and a late CANCEL can land after a
     * successful transmit. */
    if (!rate_limited) {
      if (closed || resync) {
        pcsc_fido_log(PCSC_FIDO_LOG_INFO,
                      "%s during PC/SC exchange; resetting PC/SC session", err);
      } else if (!cancelled) {
        pcsc_fido_log(PCSC_FIDO_LOG_INFO, "PC/SC bridge failed: %s", err);
      }
      /* The hidraw client is gone, so its channel IDs are gone too. A resync
       * keeps the channel and answers the INIT below. */
      if (closed) {
        pcsc_fido_daemon_channels_drop_client(channels);
      } else {
        pcsc_fido_daemon_channels_release_session(channels);
      }
      pcsc_fido_bridge_reset();
    }
    if (resync) {
      answer_init(uhid_fd, channels, request_cid, response, response_len);
      return;
    }
    if (closed) {
      return;
    }
    if (cancelled) {
      if (cmd == PCSC_FIDO_HID_CMD_CBOR) {
        const uint8_t cancelled_status =
            PCSC_FIDO_DAEMON_CTAP2_ERR_KEEPALIVE_CANCEL;
        (void)pcsc_fido_daemon_send_hid_response(uhid_fd, request_cid, cmd,
                                                 &cancelled_status, 1u);
      }
      return;
    }
    if (rate_limited) {
      (void)pcsc_fido_daemon_send_hid_error(uhid_fd, request_cid,
                                            PCSC_FIDO_DAEMON_ERR_CHANNEL_BUSY);
      return;
    }
    (void)pcsc_fido_daemon_send_hid_error(uhid_fd, request_cid,
                                          PCSC_FIDO_DAEMON_ERR_OTHER);
    return;
  }
  if (response_len > PCSC_FIDO_CTAPHID_MAX_FRAMED_PAYLOAD) {
    /* The bridge accepts more than CTAPHID can frame. Nothing has been
     * written yet, so the client can still be told instead of timing out. */
    (void)pcsc_fido_daemon_send_hid_error(uhid_fd, request_cid,
                                          PCSC_FIDO_DAEMON_ERR_OTHER);
  }
  if (response_len > PCSC_FIDO_CTAPHID_MAX_FRAMED_PAYLOAD ||
      !pcsc_fido_daemon_send_hid_response(uhid_fd, request_cid, cmd, response,
                                          response_len)) {
    /* The card already ran the command. Without a delivered response the
     * client cannot continue a getNextAssertion sequence, so drop it. */
    pcsc_fido_log(PCSC_FIDO_LOG_INFO,
                  "failed to deliver CTAP response; resetting PC/SC session");
    pcsc_fido_daemon_channels_release_session(channels);
    pcsc_fido_bridge_reset();
    return;
  }
  /* Ownership follows a request that reached the card and the client.
   * A refused exchange never gets here, so it cannot CANCEL another
   * channel's session. */
  pcsc_fido_daemon_channels_hold_session(channels, request_cid);
  if (ends_webauthn_operation(channels, cmd, payload, payload_len, response,
                              response_len)) {
    pcsc_fido_log(PCSC_FIDO_LOG_DEBUG,
                  "completed WebAuthn operation; resetting PC/SC session");
    pcsc_fido_daemon_channels_release_session(channels);
    pcsc_fido_bridge_reset();
  }
}
