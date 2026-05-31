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

#include "pcsc_fido/daemon_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

static void expect_true(int condition, const char *message) {
  if (!condition) {
    fprintf(stderr, "FAIL: %s\n", message);
    failures++;
  }
}

static void config_defaults_to_tap_arm(void) {
  pcsc_fido_browser_config_t cfg;
  unsetenv("PCSC_FIDO_VIRTUAL_KEY");
  unsetenv("PCSC_FIDO_ARM_SEC");
  expect_true(pcsc_fido_load_browser_config(&cfg), "default config loads");
  expect_true(cfg.virtual_key_mode == PCSC_FIDO_VIRTUAL_KEY_TAP_ARM, "default mode tap-arm");
  expect_true(cfg.arm_sec == PCSC_FIDO_ARM_SEC_DEFAULT, "default arm_sec");
}

static void config_invalid_numeric_env_falls_back(void) {
  pcsc_fido_browser_config_t cfg;
  unsetenv("PCSC_FIDO_VIRTUAL_KEY");
  expect_true(setenv("PCSC_FIDO_ARM_SEC", "not-a-number", 1) == 0, "set invalid arm sec");
  expect_true(pcsc_fido_load_browser_config(&cfg), "invalid numeric env falls back");
  expect_true(cfg.arm_sec == PCSC_FIDO_ARM_SEC_DEFAULT, "invalid arm sec uses default");
}

static void config_mode_name_covers_all_values(void) {
  expect_true(strcmp(pcsc_fido_virtual_key_mode_name(PCSC_FIDO_VIRTUAL_KEY_TAP_ARM), "tap-arm") ==
                0,
              "tap-arm mode name");
  expect_true(strcmp(pcsc_fido_virtual_key_mode_name(PCSC_FIDO_VIRTUAL_KEY_ALWAYS), "always") == 0,
              "always mode name");
  expect_true(
    strcmp(pcsc_fido_virtual_key_mode_name((pcsc_fido_virtual_key_mode_t)99), "unknown") == 0,
    "unknown mode name");
}

static void config_print_rejects_null(void) {
  pcsc_fido_print_browser_config(nullptr, nullptr);
  expect_true(true, "null print is a no-op");
}

static void config_rejects_zero_arm_sec(void) {
  pcsc_fido_browser_config_t cfg;
  expect_true(setenv("PCSC_FIDO_ARM_SEC", "0", 1) == 0, "set zero arm");
  expect_true(!pcsc_fido_load_browser_config(&cfg), "zero arm rejected");
}

static void config_arm_sec_out_of_range_falls_back(void) {
  pcsc_fido_browser_config_t cfg;
  unsetenv("PCSC_FIDO_VIRTUAL_KEY");
  expect_true(setenv("PCSC_FIDO_ARM_SEC", "86401", 1) == 0, "set oob arm sec");
  expect_true(pcsc_fido_load_browser_config(&cfg), "oob arm sec loads with fallback");
  expect_true(cfg.arm_sec == PCSC_FIDO_ARM_SEC_DEFAULT, "oob arm sec uses default");
}

static void config_parses_always_mode(void) {
  pcsc_fido_browser_config_t cfg;
  expect_true(setenv("PCSC_FIDO_VIRTUAL_KEY", "always", 1) == 0, "set always");
  expect_true(setenv("PCSC_FIDO_ARM_SEC", "45", 1) == 0, "set arm");
  expect_true(pcsc_fido_load_browser_config(&cfg), "always config loads");
  expect_true(cfg.virtual_key_mode == PCSC_FIDO_VIRTUAL_KEY_ALWAYS, "always mode");
  expect_true(cfg.arm_sec == 45u, "arm sec parsed");
}

static void config_rejects_invalid_mode(void) {
  pcsc_fido_browser_config_t cfg;
  expect_true(setenv("PCSC_FIDO_VIRTUAL_KEY", "sometimes", 1) == 0, "set invalid mode");
  expect_true(setenv("PCSC_FIDO_ARM_SEC", "30", 1) == 0, "set valid arm");
  expect_true(!pcsc_fido_load_browser_config(&cfg), "invalid mode rejected");
}

static void config_print_includes_mode(void) {
  pcsc_fido_browser_config_t cfg;
  char line[128];
  FILE *out = tmpfile();
  if (out != nullptr) {
    expect_true(setenv("PCSC_FIDO_VIRTUAL_KEY", "tap-arm", 1) == 0, "set tap-arm");
    expect_true(setenv("PCSC_FIDO_ARM_SEC", "30", 1) == 0, "set arm");
    expect_true(pcsc_fido_load_browser_config(&cfg), "config loads");
    pcsc_fido_print_browser_config(out, &cfg);
    rewind(out);
    expect_true(fgets(line, sizeof(line), out) != nullptr, "first config line");
    expect_true(strstr(line, "PCSC_FIDO_VIRTUAL_KEY=tap-arm") != nullptr, "printed mode");
    fclose(out);
  } else {
    expect_true(false, "tmpfile");
  }
}

int main(void) {
  config_defaults_to_tap_arm();
  config_invalid_numeric_env_falls_back();
  config_mode_name_covers_all_values();
  config_print_rejects_null();
  config_rejects_zero_arm_sec();
  config_arm_sec_out_of_range_falls_back();
  config_parses_always_mode();
  config_rejects_invalid_mode();
  config_print_includes_mode();
  return failures == 0 ? 0 : 1;
}
