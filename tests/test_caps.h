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

// Named stack-buffer capacities and cross-test literals. File-local fixtures
// stay in each test .c (magic_literals placement policy).

#pragma once

enum {
  TEST_ASSIGNED_CID = 0x4E464301u,
  TEST_CAP_128 = 128,
  TEST_CAP_256 = 256,
  TEST_CAP_4096 = 4096,
  TEST_CID = 0x01020304u,
  TEST_CID_OTHER = 0xAABBCCDDu,
  TEST_LIT_0X02U = 0x02u,
  TEST_LIT_0X03U = 0x03u,
  TEST_LIT_0X04U = 0x04u,
  TEST_LIT_0X80U = 0x80u,
  TEST_LIT_0X90U = 0x90u,
  TEST_LIT_0XA5 = 0xA5,
  TEST_LIT_0XAAU = 0xAAu,
  TEST_LIT_0XBBU = 0xBBu,
  TEST_LIT_0XFFU = 0xFFu,
  TEST_LIT_15 = 15,
  TEST_LIT_16 = 16,
  TEST_LIT_16U = 16u,
  TEST_LIT_24U = 24u,
  TEST_LIT_2U = 2u,
  TEST_LIT_3 = 3,
  TEST_LIT_32 = 32,
  TEST_LIT_32U = 32u,
  TEST_LIT_3U = 3u,
  TEST_LIT_4 = 4,
  TEST_LIT_4U = 4u,
  TEST_LIT_5 = 5,
  TEST_LIT_5U = 5u,
  TEST_LIT_6 = 6,
  TEST_LIT_64 = 64,
  TEST_LIT_64U = 64u,
  TEST_LIT_7 = 7,
  TEST_LIT_8 = 8,
  TEST_LIT_80 = 80,
  TEST_LIT_8U = 8u,
  TEST_LIT_9 = 9,
  TEST_LIT_9U = 9u,
  TEST_SOCKETPAIR_FDS = 2,
};
