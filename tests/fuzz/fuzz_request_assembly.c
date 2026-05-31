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

#include "pcsc_fido/ctaphid.h"
#include "pcsc_fido/request_assembly.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

static void noop_handler(const void *ctx, uint32_t request_cid, uint8_t cmd,
                         const uint8_t *payload, size_t payload_len) {
  (void)ctx;
  (void)request_cid;
  (void)cmd;
  (void)payload;
  (void)payload_len;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  pcsc_fido_daemon_pending_request_t pending;
  uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE];

  if (data == nullptr) {
    return 0;
  }

  pcsc_fido_daemon_pending_request_reset(&pending);

  for (size_t off = 0u; off + PCSC_FIDO_HID_PACKET_SIZE <= size;
       off += PCSC_FIDO_HID_PACKET_SIZE) {
    (void)pcsc_fido_daemon_request_assembler_feed(-1, &pending, data + off, noop_handler, nullptr);
  }

  {
    const size_t tail = size % PCSC_FIDO_HID_PACKET_SIZE;
    if (tail != 0u) {
      memset(packet, 0, sizeof(packet));
      memcpy(packet, data + (size - tail), tail);
      (void)pcsc_fido_daemon_request_assembler_feed(-1, &pending, packet, noop_handler, nullptr);
    }
  }

  return 0;
}
