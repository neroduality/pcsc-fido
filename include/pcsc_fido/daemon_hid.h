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
#include "pcsc_fido/ctaphid.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

uint32_t pcsc_fido_daemon_hid_packet_cid(const uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE]);

PCSC_FIDO_NODISCARD bool
pcsc_fido_daemon_hid_is_cancel_packet(const uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE],
                                      uint32_t cid);

PCSC_FIDO_NODISCARD bool
pcsc_fido_daemon_hid_decode_init_header(const uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE],
                                        uint32_t *cid, uint8_t *cmd, size_t *payload_len);
