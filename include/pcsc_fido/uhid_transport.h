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
#include "pcsc_fido/daemon_hid.h"
#include "pcsc_fido/ctaphid.h"

#include <linux/uhid.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <limits.h>

enum {
  PCSC_FIDO_DAEMON_CAP_WINK = 0x01u,
  PCSC_FIDO_DAEMON_CAP_CBOR = 0x04u,
  PCSC_FIDO_DAEMON_ERR_INVALID_CMD = 0x01u,
  PCSC_FIDO_DAEMON_ERR_INVALID_LEN = 0x03u,
  PCSC_FIDO_DAEMON_ERR_INVALID_SEQ = 0x04u,
  PCSC_FIDO_DAEMON_ERR_CHANNEL_BUSY = 0x06u,
  PCSC_FIDO_DAEMON_ERR_OTHER = 0x7Fu,
  PCSC_FIDO_DAEMON_CTAP2_ERR_KEEPALIVE_CANCEL = 0x2Du,
  PCSC_FIDO_DAEMON_PENDING_MAX = PCSC_FIDO_CTAPHID_MAX_PAYLOAD,
};

PCSC_FIDO_STATIC_ASSERT(PCSC_FIDO_DAEMON_PENDING_MAX <= UINT16_MAX,
                        "daemon pending max must fit CTAPHID 16-bit length field");

PCSC_FIDO_NODISCARD bool pcsc_fido_daemon_send_hid_response(int fd, uint32_t cid, uint8_t cmd,
                                                            const uint8_t *payload,
                                                            size_t payload_len);
PCSC_FIDO_NODISCARD bool pcsc_fido_daemon_send_hid_error(int fd, uint32_t cid, uint8_t code);
PCSC_FIDO_NODISCARD bool pcsc_fido_daemon_send_keepalive(int fd, uint32_t cid);

PCSC_FIDO_NODISCARD bool pcsc_fido_daemon_create_uhid_device(int fd);
void pcsc_fido_daemon_destroy_uhid_device(int fd);

PCSC_FIDO_NODISCARD bool pcsc_fido_daemon_output_packet_data(const struct uhid_event *ev,
                                                             const uint8_t **data);
