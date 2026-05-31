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

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>

typedef void (*pcsc_fido_card_monitor_wake_fn)(void *ctx);

typedef struct {
  pthread_t thread;
  atomic_bool stop;
  bool running;
  pcsc_fido_card_monitor_wake_fn wake;
  void *wake_ctx;
} pcsc_fido_card_monitor_t;

PCSC_FIDO_NODISCARD bool pcsc_fido_card_monitor_start(pcsc_fido_card_monitor_t *monitor,
                                                      pcsc_fido_card_monitor_wake_fn wake,
                                                      void *wake_ctx);
void pcsc_fido_card_monitor_stop(pcsc_fido_card_monitor_t *monitor);
