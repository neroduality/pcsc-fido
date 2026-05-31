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
  uint8_t payload[PCSC_FIDO_DAEMON_PENDING_MAX];
} pcsc_fido_daemon_pending_request_t;

PCSC_FIDO_STATIC_ASSERT((unsigned)PCSC_FIDO_DAEMON_PENDING_MAX ==
                          (unsigned)PCSC_FIDO_CTAPHID_MAX_PAYLOAD,
                        "daemon pending buffer must match CTAPHID payload cap");

typedef void (*pcsc_fido_daemon_request_handler_fn)(const void *ctx, uint32_t request_cid,
                                                    uint8_t cmd, const uint8_t *payload,
                                                    size_t payload_len);

void pcsc_fido_daemon_pending_request_reset(pcsc_fido_daemon_pending_request_t *pending);

PCSC_FIDO_NODISCARD bool
pcsc_fido_daemon_request_assembler_feed(int fd, pcsc_fido_daemon_pending_request_t *pending,
                                        const uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE],
                                        pcsc_fido_daemon_request_handler_fn handle_request,
                                        const void *ctx);
