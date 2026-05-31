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

enum {
  PCSC_FIDO_READER_NAME_MAX = 256u,
  PCSC_FIDO_ERR_MSG_MAX = 256u,
  PCSC_FIDO_WAIT_SEC_DEFAULT = 60u,
  PCSC_FIDO_READER_LIST_BUF_MAX = 4096u,
  PCSC_FIDO_READER_STATUS_POLL_MS = 250u,
  PCSC_FIDO_READER_LIST_RETRY_MS = 200u,
  PCSC_FIDO_EXCHANGE_KEEPALIVE_INTERVAL_MS = 750u,
  PCSC_FIDO_BRIDGE_MAX_APDU = PCSC_FIDO_CTAPHID_MAX_PAYLOAD + 32u,
  PCSC_FIDO_BRIDGE_MAX_RESPONSE = PCSC_FIDO_APDU_CHAIN_MAX_RESPONSE,
  PCSC_FIDO_BRIDGE_READER_ENUM_TIMEOUT_SEC = 10,
  PCSC_FIDO_BRIDGE_MAX_READERS = 32,
};

PCSC_FIDO_STATIC_ASSERT((unsigned)PCSC_FIDO_BRIDGE_MAX_RESPONSE ==
                          (unsigned)PCSC_FIDO_APDU_CHAIN_MAX_RESPONSE,
                        "bridge response cap must match APDU chain cap");
