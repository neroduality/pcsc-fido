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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <winscard.h>

void mock_pcsc_reset(void);

void mock_pcsc_set_readers(const char *readers);
void mock_pcsc_set_reader_pair(const char *reader_a, const char *reader_b);
void mock_pcsc_set_list_probe_needed(DWORD needed);
void mock_pcsc_set_list_probe_no_readers_retries(unsigned retries);
void mock_pcsc_set_list_probe_always_no_readers(bool enabled);
void mock_pcsc_set_establish_fail_system_scope(bool enabled);
void mock_pcsc_set_establish_fail(LONG rv);
void mock_pcsc_set_list_probe_fail(LONG rv);
void mock_pcsc_set_list_fill_fail(LONG rv);
void mock_pcsc_set_get_status_fail(LONG rv);
void mock_pcsc_set_connect_fail(LONG rv);
void mock_pcsc_set_connect_proto_mismatch_once(bool enabled);
void mock_pcsc_set_connect_active_protocol(DWORD protocol);
void mock_pcsc_set_card_present_immediately(bool enabled);
void mock_pcsc_set_status_present_sequence(const bool *present, size_t len);
void mock_pcsc_set_get_status_timeouts_before_present(unsigned count);
void mock_pcsc_set_multi_present_readers(bool enabled);
void mock_pcsc_set_transmit_fail(bool enabled);
void mock_pcsc_set_transmit_fail_once(bool enabled);
void mock_pcsc_set_transmit_wait_for_cancel(bool enabled);
void mock_pcsc_set_transmit_response(const uint8_t *data, size_t len);
void mock_pcsc_set_select_first_fail(bool enabled);

unsigned mock_pcsc_transmit_call_count(void);
unsigned mock_pcsc_get_status_call_count(void);
bool mock_pcsc_cancel_during_transmit(void);
bool mock_pcsc_wait_for_transmit_waiting(unsigned timeout_ms);
