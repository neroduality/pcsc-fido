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

#include "pcsc_fido/pcsc_fido_io.h"

#include <stdio.h>

void pcsc_fido_io_vprintf(FILE* stream, const char* fmt, va_list args) {
  va_list args_copy;
  if (stream == PCSC_FIDO_NULL || fmt == PCSC_FIDO_NULL) {
    return;
  }
  va_copy(args_copy, args);
  /* fmt is checked against the arguments by the printf format attribute on
   * this function's declaration and on every variadic caller. */
  (void)vfprintf(stream, fmt, args_copy);
  va_end(args_copy);
}

void pcsc_fido_io_printf(FILE* stream, const char* fmt, ...) {
  va_list args;
  if (stream == PCSC_FIDO_NULL || fmt == PCSC_FIDO_NULL) {
    return;
  }
  va_start(args, fmt);
  pcsc_fido_io_vprintf(stream, fmt, args);
  va_end(args);
}

void pcsc_fido_io_fputs(FILE* stream, const char* s) {
  if (stream == PCSC_FIDO_NULL || s == PCSC_FIDO_NULL) {
    return;
  }
  (void)fputs(s, stream);
}

void pcsc_fido_io_fputc(FILE* stream, int c) {
  if (stream == PCSC_FIDO_NULL) {
    return;
  }
  (void)fputc(c, stream);
}

#if defined(PCSC_FIDO_TESTING)
void pcsc_fido_io_fflush(FILE* stream) {
  if (stream == PCSC_FIDO_NULL) {
    return;
  }
  (void)fflush(stream);
}
#endif
