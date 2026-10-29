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

#pragma once

#include "pcsc_fido/attrs.h"
#include "pcsc_fido/uhid_transport.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
  bool active;
  uint32_t cid;
  uint8_t cmd;
  uint16_t expected;
  uint16_t copied;
  uint8_t next_seq;
  uint64_t deadline_ms;
  uint8_t payload[PCSC_FIDO_DAEMON_PENDING_MAX];
} pcsc_fido_daemon_pending_request_t;

PCSC_FIDO_STATIC_ASSERT((unsigned)PCSC_FIDO_DAEMON_PENDING_MAX ==
                            (unsigned)PCSC_FIDO_CTAPHID_MAX_PAYLOAD,
                        "daemon pending buffer must match CTAPHID payload cap");

typedef void (*pcsc_fido_daemon_request_handler_fn_t)(const void* ctx,
                                                      uint32_t request_cid,
                                                      uint8_t cmd,
                                                      const uint8_t* payload,
                                                      size_t payload_len);

void pcsc_fido_daemon_pending_request_reset(
    pcsc_fido_daemon_pending_request_t* pending);

/* Drops an open reassembly whose inter-frame gap has elapsed and sends
 * ERR_MSG_TIMEOUT on `fd`. True when a request was dropped. */
PCSC_FIDO_NODISCARD bool pcsc_fido_daemon_pending_request_expire(
    int fd, pcsc_fido_daemon_pending_request_t* pending);

/* Poll wait that wakes in time to expire an open reassembly. `cap_ms` < 0
 * means no other cap. 0 means do not wait. */
PCSC_FIDO_NODISCARD int pcsc_fido_daemon_pending_request_poll_timeout_ms(
    const pcsc_fido_daemon_pending_request_t* pending, int cap_ms);

PCSC_FIDO_NODISCARD bool pcsc_fido_daemon_request_assembler_feed(
    int fd, pcsc_fido_daemon_pending_request_t* pending,
    const uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE],
    pcsc_fido_daemon_request_handler_fn_t handle_request, const void* ctx);
