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

#include "pcsc_fido/daemon_channels.h"

#include "pcsc_fido/ctaphid.h"
#include "pcsc_fido/mem_util.h"
#include "pcsc_fido/pcsc_bridge_limits.h"
#include "pcsc_fido/pcsc_util.h"

enum {
  /* 0 and the broadcast ID. */
  PCSC_FIDO_DAEMON_RESERVED_CID_COUNT = 2u,
};

static bool cid_is_reserved(uint32_t cid) {
  return cid == 0u || cid == PCSC_FIDO_HID_BROADCAST_CID;
}

static int find_slot(const pcsc_fido_daemon_channels_t* channels,
                     uint32_t cid) {
  for (unsigned i = 0u; i < PCSC_FIDO_DAEMON_CHANNEL_SLOTS; i++) {
    if (channels->cids[i] == cid) {
      return (int)i;
    }
  }
  return -1;
}

static unsigned victim_slot(const pcsc_fido_daemon_channels_t* channels) {
  unsigned victim = 0u;
  for (unsigned i = 0u; i < PCSC_FIDO_DAEMON_CHANNEL_SLOTS; i++) {
    if (channels->cids[i] == 0u) {
      return i;
    }
    if (channels->last_used[i] < channels->last_used[victim]) {
      victim = i;
    }
  }
  return victim;
}

void pcsc_fido_daemon_channels_init(pcsc_fido_daemon_channels_t* channels) {
  if (channels == PCSC_FIDO_NULL) {
    return;
  }
  pcsc_fido_zero_bytes(channels, sizeof(*channels));
  channels->next_cid = PCSC_FIDO_DEFAULT_ASSIGNED_CID;
}

void pcsc_fido_daemon_channels_release_session(
    pcsc_fido_daemon_channels_t* channels) {
  if (channels == PCSC_FIDO_NULL) {
    return;
  }
  channels->session_owner = 0u;
  channels->next_assertions_left = 0u;
  channels->session_deadline = 0;
}

void pcsc_fido_daemon_channels_drop_client(
    pcsc_fido_daemon_channels_t* channels) {
  uint32_t next_cid;
  if (channels == PCSC_FIDO_NULL) {
    return;
  }
  next_cid = channels->next_cid;
  pcsc_fido_zero_bytes(channels, sizeof(*channels));
  channels->next_cid = next_cid;
}

void pcsc_fido_daemon_channels_hold_session(
    pcsc_fido_daemon_channels_t* channels, uint32_t cid) {
  if (channels == PCSC_FIDO_NULL || cid_is_reserved(cid)) {
    return;
  }
  channels->session_owner = cid;
  channels->session_deadline = pcsc_fido_add_seconds_saturating(
      pcsc_fido_monotonic_sec(), PCSC_FIDO_DAEMON_SESSION_IDLE_SEC);
}

bool pcsc_fido_daemon_channels_expire_session(
    pcsc_fido_daemon_channels_t* channels) {
  if (channels == PCSC_FIDO_NULL || channels->session_owner == 0u) {
    return false;
  }
  if (pcsc_fido_timeout_until_ms(channels->session_deadline) > 0) {
    return false;
  }
  pcsc_fido_daemon_channels_release_session(channels);
  return true;
}

int pcsc_fido_daemon_channels_poll_timeout_ms(
    const pcsc_fido_daemon_channels_t* channels, int cap_ms) {
  int remaining_ms;
  if (cap_ms == 0 || channels == PCSC_FIDO_NULL ||
      channels->session_owner == 0u) {
    return cap_ms;
  }
  remaining_ms = pcsc_fido_timeout_until_ms(channels->session_deadline);
  if (cap_ms < 0 || remaining_ms < cap_ms) {
    return remaining_ms;
  }
  return cap_ms;
}

uint32_t pcsc_fido_daemon_channels_allocate(
    pcsc_fido_daemon_channels_t* channels, bool* session_dropped) {
  uint32_t cid;
  unsigned slot;
  if (session_dropped != PCSC_FIDO_NULL) {
    *session_dropped = false;
  }
  if (channels == PCSC_FIDO_NULL) {
    return 0u;
  }
  /* At most SLOTS live IDs plus the reserved values can be skipped. */
  cid = channels->next_cid;
  for (unsigned tries = 0u; tries < PCSC_FIDO_DAEMON_CHANNEL_SLOTS +
                                        PCSC_FIDO_DAEMON_RESERVED_CID_COUNT;
       tries++) {
    if (!cid_is_reserved(cid) && find_slot(channels, cid) < 0) {
      break;
    }
    cid++;
  }
  channels->next_cid = cid + 1u;
  slot = victim_slot(channels);
  /* An empty slot has cid 0, which is also "no owner". Only a live channel
   * that owns the card drops the session; the caller disconnects it. */
  if (channels->cids[slot] != 0u &&
      channels->cids[slot] == channels->session_owner) {
    pcsc_fido_daemon_channels_release_session(channels);
    if (session_dropped != PCSC_FIDO_NULL) {
      *session_dropped = true;
    }
  }
  channels->cids[slot] = cid;
  channels->last_used[slot] = ++channels->use_clock;
  return cid;
}

bool pcsc_fido_daemon_channels_touch(pcsc_fido_daemon_channels_t* channels,
                                     uint32_t cid) {
  int slot;
  if (channels == PCSC_FIDO_NULL || cid_is_reserved(cid)) {
    return false;
  }
  slot = find_slot(channels, cid);
  if (slot < 0) {
    return false;
  }
  channels->last_used[slot] = ++channels->use_clock;
  return true;
}
