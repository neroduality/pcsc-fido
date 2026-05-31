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

# Shared Linux GNU cross toolchain logic (included by linux-cross-*.cmake).

cmake_minimum_required(VERSION 3.20)

if(NOT PCSC_FIDO_TARGET_ARCH OR NOT PCSC_FIDO_TARGET_TRIPLET OR NOT PCSC_FIDO_TARGET_PROCESSOR)
  message(FATAL_ERROR "linux-cross-common.cmake requires target variables to be preset")
endif()

if(NOT PCSC_FIDO_TARGET_SYSROOT_EXTRACT)
  set(PCSC_FIDO_TARGET_SYSROOT_EXTRACT "/usr/lib/pcsc-fido/cross-sysroot/${PCSC_FIDO_TARGET_ARCH}")
endif()

if(NOT PCSC_FIDO_TARGET_PKGCONFIG_LIBDIR)
  set(_pcsc_fido_triplet_basename "${PCSC_FIDO_TARGET_TRIPLET}")
  set(PCSC_FIDO_TARGET_PKGCONFIG_LIBDIR
      "${PCSC_FIDO_TARGET_SYSROOT_EXTRACT}/usr/lib/${_pcsc_fido_triplet_basename}/pkgconfig")
endif()

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR "${PCSC_FIDO_TARGET_PROCESSOR}")
set(CMAKE_C_COMPILER "${PCSC_FIDO_TARGET_TRIPLET}-gcc")
set(CMAKE_C_COMPILER_TARGET "${PCSC_FIDO_TARGET_TRIPLET}")
set(CMAKE_STRIP "${PCSC_FIDO_TARGET_TRIPLET}-strip")

set(_pcsc_fido_cross_host "/usr/${PCSC_FIDO_TARGET_TRIPLET}")
set(CMAKE_FIND_ROOT_PATH "${PCSC_FIDO_TARGET_SYSROOT_EXTRACT}" "${_pcsc_fido_cross_host}" "/usr")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY BOTH)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE BOTH)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE BOTH)

set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

set(ENV{PKG_CONFIG_PATH} "")
set(ENV{PKG_CONFIG_SYSROOT_DIR} "${PCSC_FIDO_TARGET_SYSROOT_EXTRACT}")
set(ENV{PKG_CONFIG_LIBDIR} "${PCSC_FIDO_TARGET_PKGCONFIG_LIBDIR}")

set(PCSC_FIDO_CROSS_BUILD ON CACHE BOOL "Cross-compiling pcsc-fido" FORCE)

if(PCSC_FIDO_DEBIAN_PACKAGE_ARCH)
  set(PCSC_FIDO_DEBIAN_PACKAGE_ARCHITECTURE "${PCSC_FIDO_DEBIAN_PACKAGE_ARCH}" CACHE STRING "" FORCE)
endif()
if(PCSC_FIDO_RPM_PACKAGE_ARCH)
  set(PCSC_FIDO_RPM_PACKAGE_ARCHITECTURE "${PCSC_FIDO_RPM_PACKAGE_ARCH}" CACHE STRING "" FORCE)
endif()
