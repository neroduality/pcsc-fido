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

#include "cbmc_cprover.h"
#include "pcsc_fido/cbor_util.h"
#include "pcsc_fido/ctaphid.h"

#include <stddef.h>
#include <stdint.h>

/* A reader consumes at most one initial byte plus an 8-byte argument, so a
 * buffer of PCSC_FIDO_CBMC_CBOR_READ_MAX nondeterministic bytes with every
 * length and offset in it covers each reader path, including every way of
 * running off the end. The CTAPHID payload cap only bounds the offsets; the
 * readers never index past what the length argument allows. */
#ifndef PCSC_FIDO_CBMC_CBOR_READ_MAX
#define PCSC_FIDO_CBMC_CBOR_READ_MAX 16u
#endif

int main(void) {
  uint8_t data[PCSC_FIDO_CBMC_CBOR_READ_MAX] PCSC_FIDO_CBMC_NONDET;
  size_t len = PCSC_FIDO_CBMC_NONDET_SIZE();
  size_t off = PCSC_FIDO_CBMC_NONDET_SIZE();
  size_t value = 0u;
  bool flag = false;
  bool matches = false;
  const uint8_t additional = PCSC_FIDO_CBMC_NONDET_U8();

  PCSC_FIDO_CBMC_ASSUME(len <= sizeof(data));
  PCSC_FIDO_CBMC_ASSUME(off <= len);

  const size_t off_in = off;
  (void)pcsc_fido_cbor_read_len(additional, data, len, &off, &value);
  PCSC_FIDO_CBMC_ASSERT(off <= len, "read_len stays inside the buffer");
  PCSC_FIDO_CBMC_ASSERT(off >= off_in, "read_len does not rewind");

  off = off_in;
  (void)pcsc_fido_cbor_read_uint_value(data, len, &off, &value);
  PCSC_FIDO_CBMC_ASSERT(off <= len, "uint read stays inside the buffer");

  off = off_in;
  (void)pcsc_fido_cbor_read_bool_value(data, len, &off, &flag);
  PCSC_FIDO_CBMC_ASSERT(off <= len, "bool read stays inside the buffer");

  static const char KEY_UP[] = "up";
  off = off_in;
  (void)pcsc_fido_cbor_read_text_key_matches(data, len, &off, KEY_UP, &matches);
  PCSC_FIDO_CBMC_ASSERT(off <= len, "text-key read stays inside the buffer");

  off = off_in;
  (void)pcsc_fido_cbor_read_text_key_matches_len(data, len, &off, KEY_UP,
                                                 sizeof(KEY_UP) - 1u, &matches);
  PCSC_FIDO_CBMC_ASSERT(off <= len,
                        "bounded text-key read stays inside the buffer");
  return 0;
}
