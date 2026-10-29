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
#include "pcsc_fido/pcsc_bridge_limits.h"
#include "pcsc_fido/pcsc_util.h"

#include <limits.h>
#include <string.h>
#include <time.h>

static uint64_t saturating_add_u64(uint64_t a, uint64_t b) {
  return a > UINT64_MAX - b ? UINT64_MAX : a + b;
}

static uint64_t monotonic_ms(void) {
  struct timespec ts;
  uint64_t sec;
  /* Failure reads as "the deadline has passed" (UINT64_MAX), matching
   * pcsc_fido_monotonic_sec's fail-closed LONG_MAX. Returning 0 would keep a
   * stalled reassembly alive. */
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0 || ts.tv_sec < 0 ||
      ts.tv_nsec < 0) {
    return UINT64_MAX;
  }
  sec = (uint64_t)ts.tv_sec;
  if (sec > UINT64_MAX / (uint64_t)PCSC_FIDO_UTIL_MS_PER_SEC) {
    return UINT64_MAX;
  }
  return saturating_add_u64(
      sec * (uint64_t)PCSC_FIDO_UTIL_MS_PER_SEC,
      (uint64_t)ts.tv_nsec / (uint64_t)PCSC_FIDO_UTIL_NS_PER_MS);
}

static void arm_reassembly_deadline(
    pcsc_fido_daemon_pending_request_t* pending) {
  const uint64_t now_ms = monotonic_ms();
  /* UINT64_MAX is "the clock failed", which the timeout check treats as
   * already late. Stored as a deadline it means the opposite: a recovered
   * clock is less than UINT64_MAX, so the request would never expire. */
  if (now_ms == UINT64_MAX) {
    pending->deadline_ms = 0u;
    return;
  }
  pending->deadline_ms = saturating_add_u64(
      now_ms, (uint64_t)PCSC_FIDO_DAEMON_REASSEMBLY_TIMEOUT_MS);
}

void pcsc_fido_daemon_pending_request_reset(
    pcsc_fido_daemon_pending_request_t* pending) {
  if (pending != PCSC_FIDO_NULL) {
    /* The payload holds plaintext CTAP requests (clientDataHash and, for
     * authenticatorClientPIN, encrypted-PIN / key-agreement material). Wipe
     * with the guaranteed-erase helper so a hardened build's optimizer cannot
     * elide the scrub, matching the treatment of the PC/SC APDU buffers. */
    pcsc_fido_secure_clear(pending, sizeof(*pending));
  }
}

static void abort_pending(pcsc_fido_daemon_pending_request_t* pending) {
  pcsc_fido_daemon_pending_request_reset(pending);
}

bool pcsc_fido_daemon_pending_request_expire(
    int fd, pcsc_fido_daemon_pending_request_t* pending) {
  if (pending == PCSC_FIDO_NULL || !pending->active) {
    return false;
  }
  if (monotonic_ms() < pending->deadline_ms) {
    return false;
  }
  (void)pcsc_fido_daemon_send_hid_error(fd, pending->cid,
                                        PCSC_FIDO_DAEMON_ERR_MSG_TIMEOUT);
  abort_pending(pending);
  return true;
}

int pcsc_fido_daemon_pending_request_poll_timeout_ms(
    const pcsc_fido_daemon_pending_request_t* pending, int cap_ms) {
  uint64_t now_ms;
  uint64_t left_ms;
  if (cap_ms == 0 || pending == PCSC_FIDO_NULL || !pending->active) {
    return cap_ms;
  }
  now_ms = monotonic_ms();
  if (now_ms >= pending->deadline_ms) {
    return 0;
  }
  left_ms = pending->deadline_ms - now_ms;
  if (left_ms > (uint64_t)INT_MAX) {
    left_ms = (uint64_t)INT_MAX;
  }
  if (cap_ms < 0 || (int)left_ms < cap_ms) {
    return (int)left_ms;
  }
  return cap_ms;
}

static void complete_request(
    pcsc_fido_daemon_pending_request_t* pending,
    pcsc_fido_daemon_request_handler_fn_t handle_request, const void* ctx) {
  if (pending == PCSC_FIDO_NULL || handle_request == PCSC_FIDO_NULL) {
    return;
  }
  pending->active = false;
  handle_request(ctx, pending->cid, pending->cmd, pending->payload,
                 pending->expected);
  /* Erase the assembled request as soon as it has been dispatched so plaintext
   * CTAP payloads do not linger in the reassembly buffer between operations. */
  pcsc_fido_daemon_pending_request_reset(pending);
}

bool pcsc_fido_daemon_request_assembler_feed(
    int fd, pcsc_fido_daemon_pending_request_t* pending,
    const uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE],
    pcsc_fido_daemon_request_handler_fn_t handle_request, const void* ctx) {
  uint32_t cid;
  if (pending == PCSC_FIDO_NULL || packet == PCSC_FIDO_NULL ||
      handle_request == PCSC_FIDO_NULL) {
    return false;
  }
  cid = pcsc_fido_daemon_hid_packet_cid(packet);
  (void)pcsc_fido_daemon_pending_request_expire(fd, pending);
  /* One request at a time: another channel is told to retry and cannot
   * disturb the request being reassembled. */
  if (pending->active && cid != pending->cid) {
    if (pcsc_fido_daemon_hid_is_busy_answerable(packet)) {
      (void)pcsc_fido_daemon_send_hid_error(fd, cid,
                                            PCSC_FIDO_DAEMON_ERR_CHANNEL_BUSY);
    }
    return true;
  }
  if ((packet[PCSC_FIDO_HID_OFF_CMD] & PCSC_FIDO_HID_TYPE_INIT) != 0u) {
    size_t copied;
    /* Wipe any leftover from a previous partial/complete request before
     * accepting a new INIT, then abort+wipe again on a reject so rejected
     * length/copy failures cannot leave CTAP bytes in `pending`. */
    pcsc_fido_daemon_pending_request_reset(pending);
    pending->cid = cid;
    pending->cmd =
        (uint8_t)(packet[PCSC_FIDO_HID_OFF_CMD] & PCSC_FIDO_HID_CMD_MASK);
    pending->expected = (uint16_t)(((uint16_t)packet[PCSC_FIDO_HID_OFF_BCNTH]
                                    << PCSC_FIDO_U16_HIGH_BYTE_SHIFT) |
                                   packet[PCSC_FIDO_HID_OFF_BCNTL]);
    if (pending->expected > PCSC_FIDO_CTAPHID_MAX_FRAMED_PAYLOAD) {
      (void)pcsc_fido_daemon_send_hid_error(fd, cid,
                                            PCSC_FIDO_DAEMON_ERR_INVALID_LEN);
      abort_pending(pending);
      return true;
    }
    copied = pending->expected < PCSC_FIDO_HID_INIT_PAYLOAD_MAX
                 ? pending->expected
                 : PCSC_FIDO_HID_INIT_PAYLOAD_MAX;
    if (copied != 0u &&
        !pcsc_fido_copy_bytes(pending->payload, sizeof(pending->payload), 0u,
                              packet + PCSC_FIDO_HID_OFF_INIT_DATA, copied)) {
      (void)pcsc_fido_daemon_send_hid_error(fd, cid,
                                            PCSC_FIDO_DAEMON_ERR_INVALID_LEN);
      abort_pending(pending);
      return true;
    }
    pending->copied = (uint16_t)copied;
    pending->next_seq = 0u;
    if (pending->copied >= pending->expected) {
      complete_request(pending, handle_request, ctx);
    } else {
      pending->active = true;
      arm_reassembly_deadline(pending);
    }
    return true;
  }
  /* CTAPHID ignores spurious continuation frames. */
  if (!pending->active) {
    return true;
  }
  if (packet[PCSC_FIDO_HID_OFF_CMD] != pending->next_seq) {
    (void)pcsc_fido_daemon_send_hid_error(fd, cid,
                                          PCSC_FIDO_DAEMON_ERR_INVALID_SEQ);
    abort_pending(pending);
    return true;
  }
  {
    const size_t remaining = (size_t)pending->expected - pending->copied;
    const size_t chunk = remaining < PCSC_FIDO_HID_CONT_PAYLOAD_MAX
                             ? remaining
                             : PCSC_FIDO_HID_CONT_PAYLOAD_MAX;
    uint16_t updated = 0u;
    if (!pcsc_fido_copy_bytes(pending->payload, sizeof(pending->payload),
                              pending->copied,
                              packet + PCSC_FIDO_HID_OFF_CONT_DATA, chunk)) {
      (void)pcsc_fido_daemon_send_hid_error(fd, cid,
                                            PCSC_FIDO_DAEMON_ERR_INVALID_LEN);
      abort_pending(pending);
      return true;
    }
    if (!pcsc_fido_try_add_u16(pending->copied, (uint16_t)chunk, &updated)) {
      (void)pcsc_fido_daemon_send_hid_error(fd, cid,
                                            PCSC_FIDO_DAEMON_ERR_INVALID_LEN);
      abort_pending(pending);
      return true;
    }
    pending->copied = updated;
    pending->next_seq++;
    arm_reassembly_deadline(pending);
  }
  if (pending->copied >= pending->expected) {
    complete_request(pending, handle_request, ctx);
  }
  return true;
}
