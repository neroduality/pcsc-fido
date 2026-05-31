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

#include <stdarg.h>

typedef enum {
  PCSC_FIDO_LOG_ERROR = 0,
  PCSC_FIDO_LOG_INFO,
  PCSC_FIDO_LOG_DEBUG,
} pcsc_fido_log_level_t;

void pcsc_fido_log(pcsc_fido_log_level_t level, const char *fmt, ...)
  __attribute__((format(printf, 2, 3)));
