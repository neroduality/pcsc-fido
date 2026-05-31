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

#define _POSIX_C_SOURCE 200809L

#include <stdlib.h>

#include "pcsc_fido/browser_daemon.h"

#include "mock_pcsc.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void expect_true(int condition, const char *message) {
  if (!condition) {
    fprintf(stderr, "FAIL: %s\n", message);
    failures++;
  }
}

int main(void) {
  char help0[] = "pcsc-fido";
  char help1[] = "--help";
  char bad0[] = "pcsc-fido";
  char bad1[] = "--unknown";
  char list0[] = "pcsc-fido";
  char list1[] = "--list-readers";
  char version0[] = "pcsc-fido";
  char version1[] = "--version";
  char config0[] = "pcsc-fido";
  char config1[] = "--print-config";
  char *help_ptrs[] = {help0, help1, nullptr};
  char *bad_ptrs[] = {bad0, bad1, nullptr};
  char *list_ptrs[] = {list0, list1, nullptr};
  char *version_ptrs[] = {version0, version1, nullptr};
  char *config_ptrs[] = {config0, config1, nullptr};

  expect_true(pcsc_fido_browser_daemon_main(2, help_ptrs) == 0, "--help exits zero");
  expect_true(pcsc_fido_browser_daemon_main(2, bad_ptrs) == 2, "unknown flag exits 2");
  expect_true(pcsc_fido_browser_daemon_main(2, version_ptrs) == 0, "--version exits zero");

  mock_pcsc_reset();
  mock_pcsc_set_readers("CLI Test Reader 00 00\0\0");
  expect_true(pcsc_fido_browser_daemon_main(2, list_ptrs) == 0, "--list-readers succeeds");

  mock_pcsc_reset();
  mock_pcsc_set_establish_fail(SCARD_F_INTERNAL_ERROR);
  expect_true(pcsc_fido_browser_daemon_main(2, list_ptrs) == 1, "--list-readers failure");

  expect_true(setenv("PCSC_FIDO_ARM_SEC", "45", 1) == 0, "set arm sec");
  expect_true(pcsc_fido_browser_daemon_main(2, config_ptrs) == 0, "--print-config succeeds");

  return failures == 0 ? 0 : 1;
}
