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

#include <stddef.h>

#if defined(__cplusplus)
#define PCSC_FIDO_NULL nullptr
#else
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 202311L
#define PCSC_FIDO_NULL nullptr
#else
#define PCSC_FIDO_NULL NULL
#endif
#endif
