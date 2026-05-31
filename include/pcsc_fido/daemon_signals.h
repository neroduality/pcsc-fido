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

PCSC_FIDO_NODISCARD bool pcsc_fido_daemon_signals_init(void);
void pcsc_fido_daemon_signals_shutdown(void);
PCSC_FIDO_NODISCARD int pcsc_fido_daemon_signal_poll_fd(void);
void pcsc_fido_daemon_drain_signal_wake(void);
PCSC_FIDO_NODISCARD bool pcsc_fido_daemon_stop_requested(void);
void pcsc_fido_daemon_reset_stop_request(void);

#if defined(PCSC_FIDO_TESTING)
void pcsc_fido_daemon_test_request_stop(void);
#endif
