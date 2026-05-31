# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2026 Nero Duality, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set(PCSC_FIDO_TARGET_ARCH armhf)
set(PCSC_FIDO_TARGET_TRIPLET arm-linux-gnueabihf)
set(PCSC_FIDO_TARGET_PROCESSOR arm)
set(PCSC_FIDO_DEBIAN_PACKAGE_ARCH armhf)
set(PCSC_FIDO_RPM_PACKAGE_ARCH armv7hl)
include("${CMAKE_CURRENT_LIST_DIR}/linux-cross-common.cmake")
