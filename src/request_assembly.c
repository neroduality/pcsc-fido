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

#include "pcsc_fido/request_assembly.h"

#include "pcsc_fido/mem_util.h"

#include <string.h>

void pcsc_fido_daemon_pending_request_reset(pcsc_fido_daemon_pending_request_t *pending) {
  if (pending != nullptr) {
    memset(pending, 0, sizeof(*pending));
  }
}

static void complete_request(pcsc_fido_daemon_pending_request_t *pending,
                             pcsc_fido_daemon_request_handler_fn handle_request, const void *ctx) {
  if (pending == nullptr || handle_request == nullptr) {
    return;
  }
  pending->active = false;
  handle_request(ctx, pending->cid, pending->cmd, pending->payload, pending->expected);
}

bool pcsc_fido_daemon_request_assembler_feed(int fd, pcsc_fido_daemon_pending_request_t *pending,
                                             const uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE],
                                             pcsc_fido_daemon_request_handler_fn handle_request,
                                             const void *ctx) {
  uint32_t cid;
  if (pending == nullptr || packet == nullptr || handle_request == nullptr) {
    return false;
  }
  cid = pcsc_fido_daemon_hid_packet_cid(packet);
  if ((packet[4] & 0x80u) != 0u) {
    size_t copied;
    pending->active = false;
    pending->cid = cid;
    pending->cmd = (uint8_t)(packet[4] & 0x7Fu);
    pending->expected = (uint16_t)(((uint16_t)packet[5] << 8u) | packet[6]);
    if (pending->expected > PCSC_FIDO_CTAPHID_MAX_FRAMED_PAYLOAD) {
      pending->active = false;
      (void)pcsc_fido_daemon_send_hid_error(fd, cid, PCSC_FIDO_DAEMON_ERR_INVALID_LEN);
      return true;
    }
    copied = pending->expected < PCSC_FIDO_HID_INIT_PAYLOAD_MAX ? pending->expected
                                                                : PCSC_FIDO_HID_INIT_PAYLOAD_MAX;
    if (copied != 0u && !pcsc_fido_copy_bytes(pending->payload, sizeof(pending->payload), 0u,
                                              packet + 7u, copied)) {
      pending->active = false;
      (void)pcsc_fido_daemon_send_hid_error(fd, cid, PCSC_FIDO_DAEMON_ERR_INVALID_LEN);
      return true;
    }
    pending->copied = (uint16_t)copied;
    pending->next_seq = 0u;
    if (pending->copied >= pending->expected) {
      complete_request(pending, handle_request, ctx);
    } else {
      pending->active = true;
    }
    return true;
  }
  if (!pending->active || cid != pending->cid || packet[4] != pending->next_seq) {
    (void)pcsc_fido_daemon_send_hid_error(fd, cid, PCSC_FIDO_DAEMON_ERR_INVALID_SEQ);
    pending->active = false;
    return true;
  }
  {
    const size_t remaining = (size_t)pending->expected - pending->copied;
    const size_t chunk =
      remaining < PCSC_FIDO_HID_CONT_PAYLOAD_MAX ? remaining : PCSC_FIDO_HID_CONT_PAYLOAD_MAX;
    uint16_t updated = 0u;
    if (!pcsc_fido_copy_bytes(pending->payload, sizeof(pending->payload), pending->copied,
                              packet + 5u, chunk)) {
      pending->active = false;
      (void)pcsc_fido_daemon_send_hid_error(fd, cid, PCSC_FIDO_DAEMON_ERR_INVALID_LEN);
      return true;
    }
    if (!pcsc_fido_try_add_u16(pending->copied, (uint16_t)chunk, &updated)) {
      pending->active = false;
      (void)pcsc_fido_daemon_send_hid_error(fd, cid, PCSC_FIDO_DAEMON_ERR_INVALID_LEN);
      return true;
    }
    pending->copied = updated;
    pending->next_seq++;
  }
  if (pending->copied >= pending->expected) {
    complete_request(pending, handle_request, ctx);
  }
  return true;
}
