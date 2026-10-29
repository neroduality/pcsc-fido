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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

/* Spec prefixes for docs/spec-traceability.yaml: IMPL-POLICY
 * (cite in-file as [IMPL-POLICY]). */
enum {
  /* Channels kept live at once; the least recently used one is evicted and
   * its client recovers by re-sending CTAPHID_INIT. */
  PCSC_FIDO_DAEMON_CHANNEL_SLOTS = 8u, /* [IMPL-POLICY] */
  /* Idle PC/SC session (probe, clientPIN, getNextAssertion). Refreshed on
   * each command that keeps the card; then the session and its owner are
   * dropped so a client that went away cannot hold the reader. */
  PCSC_FIDO_DAEMON_SESSION_IDLE_SEC = 30u, /* [IMPL-POLICY] */
  /* getNextAssertion calls kept after one getAssertion. A larger
   * numberOfCredentials is clamped to this. */
  PCSC_FIDO_DAEMON_MAX_NEXT_ASSERTIONS = 32u, /* [IMPL-POLICY] */
};

/* CTAPHID channel IDs handed out by INIT on the broadcast channel. Each client
 * gets its own ID so replies, CHANNEL_BUSY and CANCEL apply to one client. */
typedef struct {
  uint32_t cids[PCSC_FIDO_DAEMON_CHANNEL_SLOTS];
  uint64_t last_used[PCSC_FIDO_DAEMON_CHANNEL_SLOTS];
  uint64_t use_clock;
  uint32_t next_cid;
  /* Channel whose CBOR/MSG request last used the PC/SC session; 0 if none. */
  uint32_t session_owner;
  /* getNextAssertion calls the owner can still make after a getAssertion that
   * reported numberOfCredentials > 1. The authenticator keeps the remaining
   * assertions only for as long as the PC/SC session stays connected. */
  size_t next_assertions_left;
  /* Monotonic deadline for session_owner. 0 if no session is held. */
  time_t session_deadline;
} pcsc_fido_daemon_channels_t;

void pcsc_fido_daemon_channels_init(pcsc_fido_daemon_channels_t* channels);
/* Forgets the session owner, its idle deadline, and any getNextAssertion
 * calls it had left. Does not disconnect the card; the caller does. */
void pcsc_fido_daemon_channels_release_session(
    pcsc_fido_daemon_channels_t* channels);
/* Drops every channel ID after the hidraw client goes away, and releases the
 * session. The next INIT gets a new ID. `next_cid` is kept so a just-used ID
 * is not handed out again. */
void pcsc_fido_daemon_channels_drop_client(
    pcsc_fido_daemon_channels_t* channels);
/* Records `cid` as the session owner and arms the idle deadline. */
void pcsc_fido_daemon_channels_hold_session(
    pcsc_fido_daemon_channels_t* channels, uint32_t cid);
/* Drops an idle session (owner, deadline, getNext quota). True when it did.
 * The caller disconnects the card. A deadline of 0, or a failed clock, is
 * already idle. */
PCSC_FIDO_NODISCARD bool pcsc_fido_daemon_channels_expire_session(
    pcsc_fido_daemon_channels_t* channels);
/* Poll wait that wakes when the held session goes idle. `cap_ms` < 0 means
 * no other cap. 0 means do not wait. */
PCSC_FIDO_NODISCARD int pcsc_fido_daemon_channels_poll_timeout_ms(
    const pcsc_fido_daemon_channels_t* channels, int cap_ms);
/* Returns a fresh channel ID (never 0 or broadcast), evicting the least
 * recently used channel when the table is full; 0 on invalid arguments.
 * When the evicted channel owns the PC/SC session, that ownership and any
 * getNextAssertion quota are cleared and `*session_dropped` is set (the
 * caller disconnects the card). `session_dropped` may be NULL. */
PCSC_FIDO_NODISCARD uint32_t pcsc_fido_daemon_channels_allocate(
    pcsc_fido_daemon_channels_t* channels, bool* session_dropped);
/* True if `cid` is a live channel; marks it most recently used. */
PCSC_FIDO_NODISCARD bool pcsc_fido_daemon_channels_touch(
    pcsc_fido_daemon_channels_t* channels, uint32_t cid);
