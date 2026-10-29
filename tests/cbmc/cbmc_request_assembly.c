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
#include "pcsc_fido/ctaphid.h"
#include "pcsc_fido/mem_util.h"
#include "pcsc_fido/request_assembly.h"
#include "pcsc_fido/uhid_transport.h"

#include <stddef.h>
#include <stdint.h>
#include <time.h>

static pcsc_fido_daemon_pending_request_t g_pending_obj;
static pcsc_fido_daemon_pending_request_t* g_pending;

/* UHID error replies are the write path. The sender is a stub.
 *
 * The production copy and wipe are memmove/memset of the 8192-byte payload.
 * Expanding those arrays makes the SAT problem not finish. These stand-ins
 * keep the scalar contract: copy_bytes still rejects a range that fails
 * span_ok, and a wipe of the pending object still clears the fields the
 * assembler reads back. The payload bytes themselves are not a proof variable.
 */
bool pcsc_fido_copy_bytes(void* dst, size_t dst_cap, size_t dst_off,
                          const void* src, size_t src_len) {
  if (dst == PCSC_FIDO_NULL || (src == PCSC_FIDO_NULL && src_len != 0u)) {
    return false;
  }
  if (!pcsc_fido_span_ok(dst_off, src_len, dst_cap)) {
    return false;
  }
  if (g_pending != PCSC_FIDO_NULL && dst == (void*)g_pending->payload) {
    PCSC_FIDO_CBMC_ASSERT(dst_cap == sizeof(g_pending->payload),
                          "reassembly copy uses the pending buffer");
  }
  if (src_len != 0u) {
    /* One byte of the real copy: CBMC's bounds check proves the span that
     * passed span_ok starts inside dst (the rest of the bytes are not a
     * proof variable). */
    ((uint8_t*)dst)[dst_off] = ((const uint8_t*)src)[0];
  }
  return true;
}

/* The assembler's only wipe is the whole pending object; clear the header
 * fields it reads back and leave the payload bytes out of the SAT problem.
 * Any other caller is a proof failure rather than a silent partial wipe. */
void pcsc_fido_secure_clear(void* ptr, size_t len) {
  pcsc_fido_daemon_pending_request_t* pending = ptr;
  if (ptr == PCSC_FIDO_NULL || len == 0u) {
    return;
  }
  PCSC_FIDO_CBMC_ASSERT(len == sizeof(*pending),
                        "secure_clear in the proof wipes the pending object");
  pending->active = false;
  pending->cid = 0u;
  pending->cmd = 0u;
  pending->expected = 0u;
  pending->copied = 0u;
  pending->next_seq = 0u;
  pending->deadline_ms = 0u;
}

#if defined(__CPROVER__)
long nondet_long(void);

/* tv_sec and tv_nsec are signed, so a negative clock is an input. A nonzero
 * return is a failed clock_gettime. Both make the deadline fail closed. */
int clock_gettime(clockid_t clock_id, struct timespec* ts) {
  (void)clock_id;
  if (ts == PCSC_FIDO_NULL) {
    return -1;
  }
  ts->tv_sec = (time_t)nondet_long();
  ts->tv_nsec = nondet_long();
  return PCSC_FIDO_CBMC_NONDET_U8() != 0u ? 0 : -1;
}
#endif

bool pcsc_fido_daemon_send_hid_error(int fd, uint32_t cid, uint8_t code) {
  (void)fd;
  (void)cid;
  (void)code;
  return true;
}

static void cbmc_handler(const void* ctx, uint32_t request_cid, uint8_t cmd,
                         const uint8_t* payload, size_t payload_len) {
  (void)ctx;
  (void)request_cid;
  (void)cmd;
  PCSC_FIDO_CBMC_ASSERT(payload_len <= PCSC_FIDO_CTAPHID_MAX_FRAMED_PAYLOAD,
                        "completed request stays within the CTAPHID frame cap");
  PCSC_FIDO_CBMC_ASSERT(payload_len <= sizeof(g_pending->payload),
                        "completed request fits the pending buffer");
  PCSC_FIDO_CBMC_ASSERT(payload_len == g_pending->expected,
                        "handler sees the declared length");
  if (payload != PCSC_FIDO_NULL) {
    PCSC_FIDO_CBMC_ASSERT(
        PCSC_FIDO_CBMC_SAME_OBJECT(payload, g_pending->payload),
        "handler payload is the pending buffer");
  }
}

/* One packet from every state that already obeys the cap. The all-zero
 * buffer is one of those states, so repeating the step covers every
 * sequence, including a full 7609-byte frame. */
int main(void) {
  uint8_t packet[PCSC_FIDO_HID_PACKET_SIZE] PCSC_FIDO_CBMC_NONDET;

  /* Static, then havoc: an uninitialized local is nondet under CBMC, but its
   * address must not be stored in g_pending. */
  PCSC_FIDO_CBMC_HAVOC(&g_pending_obj);
  PCSC_FIDO_CBMC_ASSUME(g_pending_obj.copied <= sizeof(g_pending_obj.payload));
  PCSC_FIDO_CBMC_ASSUME(!g_pending_obj.active ||
                        g_pending_obj.expected <=
                            PCSC_FIDO_CTAPHID_MAX_FRAMED_PAYLOAD);
  PCSC_FIDO_CBMC_ASSUME(!g_pending_obj.active ||
                        g_pending_obj.copied <= g_pending_obj.expected);

  g_pending = &g_pending_obj;
  (void)pcsc_fido_daemon_request_assembler_feed(-1, &g_pending_obj, packet,
                                                cbmc_handler, PCSC_FIDO_NULL);

  PCSC_FIDO_CBMC_ASSERT(g_pending_obj.copied <= sizeof(g_pending_obj.payload),
                        "copied stays inside the pending buffer");
  PCSC_FIDO_CBMC_ASSERT(
      !g_pending_obj.active ||
          g_pending_obj.expected <= PCSC_FIDO_CTAPHID_MAX_FRAMED_PAYLOAD,
      "an open request stays within the CTAPHID frame cap");
  PCSC_FIDO_CBMC_ASSERT(
      !g_pending_obj.active || g_pending_obj.copied <= g_pending_obj.expected,
      "copied does not pass the declared length");
  return 0;
}
