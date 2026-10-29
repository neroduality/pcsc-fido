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

/* Runs one CBOR/MSG request on a PC/SC worker thread, sending keepalives on
 * `cid` until it finishes. On failure `err` holds the bridge error or one of:
 *   PCSC_FIDO_ERR_MSG_CANCELLED: CTAPHID_CANCEL on `cid`, or a daemon stop;
 *   PCSC_FIDO_ERR_MSG_CLIENT_CLOSED: UHID_CLOSE/STOP, nobody left to answer;
 *   PCSC_FIDO_ERR_MSG_RESYNC: CTAPHID_INIT on `cid` abandoned the request.
 *     `response` then holds the INIT's PCSC_FIDO_HID_INIT_NONCE_LEN-byte
 *     nonce, which the caller answers instead of the request. */
PCSC_FIDO_NODISCARD bool pcsc_fido_daemon_run_exchange_with_keepalive(
    int fd, uint32_t cid, uint8_t cmd, const uint8_t* payload,
    size_t payload_len, uint8_t* response, size_t response_cap,
    size_t* response_len, char* err, size_t err_cap);

#if defined(PCSC_FIDO_TESTING)
/* sizeof the private exchange job (response staging + err + sync state) so
 * the scrub-audit tests can assert the job wipe by exact length instead of a
 * size heuristic that the bridge CAPDU/RAPDU scrubs also satisfy. */
PCSC_FIDO_NODISCARD size_t pcsc_fido_daemon_exchange_job_size(void);
#endif
