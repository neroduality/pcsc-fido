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

#include "pcsc_fido/daemon_hid.h"
#include "pcsc_fido/pcsc_log.h"
#include "pcsc_fido/uhid_transport.h"

#include "pcsc_fido/attrs.h"
#include "pcsc_fido/mem_util.h"

#include <errno.h>
#include <linux/input.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const uint8_t k_fido_report_desc[] = {
  0x06u, 0xD0u, 0xF1u, /* Usage Page (FIDO Alliance) */
  0x09u, 0x01u,        /* Usage (Authenticator Device) */
  0xA1u, 0x01u,        /* Collection (Application) */
  0x09u, 0x20u,        /*   Usage (Input Report Data) */
  0x15u, 0x00u,        /*   Logical Minimum (0) */
  0x26u, 0xFFu, 0x00u, /*   Logical Maximum (255) */
  0x75u, 0x08u,        /*   Report Size (8) */
  0x95u, 0x40u,        /*   Report Count (64) */
  0x81u, 0x02u,        /*   Input (Data, Variable, Absolute) */
  0x09u, 0x21u,        /*   Usage (Output Report Data) */
  0x15u, 0x00u,        /*   Logical Minimum (0) */
  0x26u, 0xFFu, 0x00u, /*   Logical Maximum (255) */
  0x75u, 0x08u,        /*   Report Size (8) */
  0x95u, 0x40u,        /*   Report Count (64) */
  0x91u, 0x02u,        /*   Output (Data, Variable, Absolute) */
  0xC0u,               /* End Collection */
};

PCSC_FIDO_STATIC_ASSERT(PCSC_FIDO_HID_PACKET_SIZE == 64u, "FIDO HID report size must be 64 bytes");

static bool write_uhid_event(int fd, const struct uhid_event *ev) {
  const uint8_t *p = (const uint8_t *)ev;
  size_t remaining = sizeof(*ev);
  if (ev == nullptr) {
    return false;
  }
  while (remaining > 0u) {
    ssize_t wrote = write(fd, p, remaining);
    if (wrote < 0) {
      if (errno == EINTR) {
        continue;
      }
      pcsc_fido_log(PCSC_FIDO_LOG_ERROR, "UHID write failed: %s", strerror(errno));
      return false;
    }
    if (wrote == 0) {
      return false;
    }
    p += (size_t)wrote;
    remaining -= (size_t)wrote;
  }
  return true;
}

static bool send_packet(int fd, const uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE]) {
  struct uhid_event ev;
  if (packet == nullptr) {
    return false;
  }
  memset(&ev, 0, sizeof(ev));
  ev.type = UHID_INPUT2;
  ev.u.input2.size = PCSC_FIDO_HID_PACKET_SIZE;
  if (!pcsc_fido_copy_bytes(ev.u.input2.data, sizeof(ev.u.input2.data), 0u, packet,
                            PCSC_FIDO_HID_PACKET_SIZE)) {
    return false;
  }
  return write_uhid_event(fd, &ev);
}

bool pcsc_fido_daemon_send_hid_response(int fd, uint32_t cid, uint8_t cmd, const uint8_t *payload,
                                        size_t payload_len) {
  uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE];
  size_t copied;
  uint8_t seq = 0u;
  if (payload_len > PCSC_FIDO_CTAPHID_MAX_FRAMED_PAYLOAD ||
      (payload == nullptr && payload_len != 0u)) {
    return false;
  }
  copied =
    payload_len < PCSC_FIDO_HID_INIT_PAYLOAD_MAX ? payload_len : PCSC_FIDO_HID_INIT_PAYLOAD_MAX;
  if (!pcsc_fido_hid_encode_init_packet(cid, cmd, payload, copied, packet)) {
    return false;
  }
  packet[5] = (uint8_t)((payload_len >> 8u) & 0xFFu);
  packet[6] = (uint8_t)(payload_len & 0xFFu);
  if (!send_packet(fd, packet)) {
    return false;
  }
  while (copied < payload_len) {
    const size_t remaining = payload_len - copied;
    const size_t chunk =
      remaining < PCSC_FIDO_HID_CONT_PAYLOAD_MAX ? remaining : PCSC_FIDO_HID_CONT_PAYLOAD_MAX;
    if (!pcsc_fido_hid_encode_cont_packet(cid, seq, payload + copied, chunk, packet) ||
        !send_packet(fd, packet)) {
      return false;
    }
    copied += chunk;
    seq++;
  }
  return true;
}

bool pcsc_fido_daemon_send_hid_error(int fd, uint32_t cid, uint8_t code) {
  return pcsc_fido_daemon_send_hid_response(fd, cid, PCSC_FIDO_HID_CMD_ERROR, &code, 1u);
}

bool pcsc_fido_daemon_send_keepalive(int fd, uint32_t cid) {
  const uint8_t processing = 0x01u;
  return pcsc_fido_daemon_send_hid_response(fd, cid, PCSC_FIDO_HID_CMD_KEEPALIVE, &processing, 1u);
}

bool pcsc_fido_daemon_create_uhid_device(int fd) {
  struct uhid_event ev;
  memset(&ev, 0, sizeof(ev));
  ev.type = UHID_CREATE2;
  (void)pcsc_fido_copy_cstr((char *)ev.u.create2.name, sizeof(ev.u.create2.name),
                            "pcsc-fido virtual NFC bridge");
  (void)pcsc_fido_copy_cstr((char *)ev.u.create2.phys, sizeof(ev.u.create2.phys), "pcsc-fido/uhid");
  ev.u.create2.rd_size = sizeof(k_fido_report_desc);
  if (!pcsc_fido_copy_bytes(ev.u.create2.rd_data, sizeof(ev.u.create2.rd_data), 0u,
                            k_fido_report_desc, sizeof(k_fido_report_desc))) {
    return false;
  }
  ev.u.create2.bus = BUS_USB;
  ev.u.create2.vendor = 0x1209u;
  ev.u.create2.product = 0xF1D0u;
  ev.u.create2.version = 1u;
  ev.u.create2.country = 0u;
  return write_uhid_event(fd, &ev);
}

void pcsc_fido_daemon_destroy_uhid_device(int fd) {
  struct uhid_event ev;
  memset(&ev, 0, sizeof(ev));
  ev.type = UHID_DESTROY;
  (void)write_uhid_event(fd, &ev);
}

bool pcsc_fido_daemon_output_packet_data(const struct uhid_event *ev, const uint8_t **data) {
  const uint8_t *packet_data;
  size_t size;
  if (ev == nullptr || data == nullptr || ev->type != UHID_OUTPUT) {
    return false;
  }
  packet_data = ev->u.output.data;
  size = ev->u.output.size;
  if (size == PCSC_FIDO_HID_PACKET_SIZE + 1u && packet_data[0] == 0u) {
    packet_data++;
    size--;
  }
  if (size != PCSC_FIDO_HID_PACKET_SIZE) {
    return false;
  }
  *data = packet_data;
  return true;
}
