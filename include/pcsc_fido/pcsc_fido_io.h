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

#include <stdarg.h>
#include <stdio.h>

enum {
  // 1-based argument indices for the printf format attribute below.
  PCSC_FIDO_IO_PRINTF_FMT_ARG_INDEX = 2,
  PCSC_FIDO_IO_PRINTF_VARARGS_INDEX = 3,
};

/** Bounded project stream printf (sole intentional fprintf sink). */
void pcsc_fido_io_printf(FILE* stream, const char* fmt, ...)
    __attribute__((format(printf, PCSC_FIDO_IO_PRINTF_FMT_ARG_INDEX,
                          PCSC_FIDO_IO_PRINTF_VARARGS_INDEX)));

void pcsc_fido_io_vprintf(FILE* stream, const char* fmt, va_list args);

void pcsc_fido_io_fputs(FILE* stream, const char* s);
void pcsc_fido_io_fputc(FILE* stream, int c);
