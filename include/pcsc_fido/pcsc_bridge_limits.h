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

#include "pcsc_fido/apdu_chain.h"
#include "pcsc_fido/attrs.h"
#include "pcsc_fido/ctaphid.h"

/* Spec prefixes for docs/spec-traceability.yaml: IMPL-POLICY CTAPHID
 * (cite in-file as [IMPL-POLICY], [CTAPHID]). */
enum {
  PCSC_FIDO_BITS_PER_BYTE = 8u,
  PCSC_FIDO_BYTE_MASK = 0xFFu,
  PCSC_FIDO_BE_BYTE_INDEX_2 = 2u,
  PCSC_FIDO_BE_BYTE_INDEX_3 = 3u,
  PCSC_FIDO_BE_BYTE_INDEX_4 = 4u,
  PCSC_FIDO_BE_BYTE_INDEX_5 = 5u,
  PCSC_FIDO_BE_BYTE_INDEX_6 = 6u,
  PCSC_FIDO_BE_BYTE_INDEX_7 = 7u,
  PCSC_FIDO_U16_HIGH_BYTE_SHIFT = 8u,
  PCSC_FIDO_U32_SHIFT_BYTE1 = 8u,
  PCSC_FIDO_U32_SHIFT_BYTE2 = 16u,
  PCSC_FIDO_U32_SHIFT_BYTE3 = 24u,
  PCSC_FIDO_U64_SHIFT_BYTE1 = 8u,
  PCSC_FIDO_U64_SHIFT_BYTE2 = 16u,
  PCSC_FIDO_U64_SHIFT_BYTE3 = 24u,
  PCSC_FIDO_U64_SHIFT_BYTE4 = 32u,
  PCSC_FIDO_U64_SHIFT_BYTE5 = 40u,
  PCSC_FIDO_U64_SHIFT_BYTE6 = 48u,
  PCSC_FIDO_U64_SHIFT_BYTE7 = 56u,
  PCSC_FIDO_PIPE_FD_COUNT = 2,
  PCSC_FIDO_ATOMIC_LOCK_FREE_INDICATOR = 2,
  PCSC_FIDO_SIGNAL_DRAIN_BUF_LEN = 64u,
  PCSC_FIDO_READER_NAME_MAX = 256u, /* [IMPL-POLICY] */
  PCSC_FIDO_ERR_MSG_MAX = 256u,     /* [IMPL-POLICY] */
  PCSC_FIDO_PROBE_SELECT_RESPONSE_MAX = 258u,
  PCSC_FIDO_WAIT_SEC_DEFAULT = 60u, /* [IMPL-POLICY] */
  PCSC_FIDO_READER_LIST_BUF_MAX = 4096u,
  PCSC_FIDO_READER_STATUS_POLL_MS = 250u, /* [IMPL-POLICY] */
  PCSC_FIDO_READER_LIST_RETRY_MS = 200u,  /* [IMPL-POLICY] */
  /* [CTAPHID] CTAP 2.3 §11.2.9.1.7 -- KEEPALIVE at least every 100 ms while a
   * CTAPHID_MSG/CBOR request is being processed. */
  PCSC_FIDO_EXCHANGE_KEEPALIVE_INTERVAL_MS = 100u,
  PCSC_FIDO_BRIDGE_APDU_SLACK = 32u,
  PCSC_FIDO_BRIDGE_MAX_APDU =
      PCSC_FIDO_CTAPHID_MAX_PAYLOAD + PCSC_FIDO_BRIDGE_APDU_SLACK,
  PCSC_FIDO_BRIDGE_MAX_RESPONSE = PCSC_FIDO_APDU_CHAIN_MAX_RESPONSE,
  PCSC_FIDO_BRIDGE_READER_ENUM_TIMEOUT_SEC = 10, /* [IMPL-POLICY] */
  PCSC_FIDO_BRIDGE_MAX_READERS = 32,
  PCSC_FIDO_SELECT_PROBE_APDU_CAP = 32u,
  PCSC_FIDO_KEEPALIVE_LOG_EVERY = 50u,
  /* keepalive period is 100ms = 1/10 s; log elapsed ~= count / 10. */
  PCSC_FIDO_KEEPALIVE_ELAPSED_NUM = 1u,
  PCSC_FIDO_KEEPALIVE_ELAPSED_DEN = 10u,
  PCSC_FIDO_DECIMAL_BASE = 10,
  PCSC_FIDO_SECONDS_PER_DAY = 86400ul,
  PCSC_FIDO_WAKE_PIPE_DRAIN_BUF_LEN = 32u,
  PCSC_FIDO_UHID_POLL_TIMEOUT_MS = 1000,
  PCSC_FIDO_UHID_POLLFD_MAX = 2,
  PCSC_FIDO_TAP_ARM_POLLFD_MAX = 3,
};

PCSC_FIDO_STATIC_ASSERT((unsigned)PCSC_FIDO_BRIDGE_MAX_RESPONSE ==
                            (unsigned)PCSC_FIDO_APDU_CHAIN_MAX_RESPONSE,
                        "bridge response cap must match APDU chain cap");
PCSC_FIDO_STATIC_ASSERT(
    (unsigned)PCSC_FIDO_CTAPHID_MAX_FRAMED_PAYLOAD <=
        (unsigned)PCSC_FIDO_BRIDGE_MAX_APDU,
    "framed CTAPHID payload must fit in bridge APDU buffer");
