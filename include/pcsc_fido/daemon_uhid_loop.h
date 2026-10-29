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
#include "pcsc_fido/daemon_config.h"
#include "pcsc_fido/daemon_request_handler.h"
#include "pcsc_fido/request_assembly.h"

#include <linux/uhid.h>
#include <stdbool.h>

/* Drops a stalled reassembly (ERR_MSG_TIMEOUT) and an idle PC/SC session.
 * The card is disconnected when the session was idle. */
void pcsc_fido_daemon_expire_idle_state(
    int fd, pcsc_fido_daemon_pending_request_t* pending,
    pcsc_fido_daemon_channels_t* channels);

/* Earlier of `cap_ms`, the reassembly gap, and the session idle deadline. */
PCSC_FIDO_NODISCARD int pcsc_fido_daemon_idle_poll_timeout_ms(
    const pcsc_fido_daemon_pending_request_t* pending,
    const pcsc_fido_daemon_channels_t* channels, int cap_ms);

void pcsc_fido_daemon_handle_uhid_event(
    int fd, const struct uhid_event* ev,
    pcsc_fido_daemon_pending_request_t* pending,
    const pcsc_fido_daemon_request_context_t* request_ctx);

typedef struct {
  int uhid_fd;
  int poll_timeout_ms;
} pcsc_fido_daemon_uhid_poll_ctx_t;

// Poll the UHID fd (and the signal wake fd when installed). Returns:
//   0 -- handled an event or timed out cleanly (continue loop)
//   1 -- stop requested
//  -1 -- I/O error
PCSC_FIDO_NODISCARD int pcsc_fido_daemon_poll_uhid_event(
    const pcsc_fido_daemon_uhid_poll_ctx_t* ctx,
    pcsc_fido_daemon_pending_request_t* pending,
    const pcsc_fido_daemon_request_context_t* request_ctx);

PCSC_FIDO_NODISCARD int pcsc_fido_daemon_run_always_mode(int uhid_fd);
