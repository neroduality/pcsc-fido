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
#include "pcsc_fido/pcsc_log.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned parse_unsigned_env(const char *name, unsigned default_value) {
  const char *raw = getenv(name);
  char *end = nullptr;
  unsigned long parsed;
  if (raw == nullptr || raw[0] == '\0') {
    return default_value;
  }
  errno = 0;
  parsed = strtoul(raw, &end, 10);
  if (errno != 0 || end == raw || *end != '\0' || parsed > 86400ul) {
    pcsc_fido_log(PCSC_FIDO_LOG_INFO, "invalid %s=%s; using %u", name, raw, default_value);
    return default_value;
  }
  return (unsigned)parsed;
}

const char *pcsc_fido_virtual_key_mode_name(pcsc_fido_virtual_key_mode_t mode) {
  switch (mode) {
  case PCSC_FIDO_VIRTUAL_KEY_TAP_ARM:
    return "tap-arm";
  case PCSC_FIDO_VIRTUAL_KEY_ALWAYS:
    return "always";
  }
  return "unknown";
}

bool pcsc_fido_load_browser_config(pcsc_fido_browser_config_t *cfg) {
  const char *mode;
  if (cfg == nullptr) {
    return false;
  }
  cfg->virtual_key_mode = PCSC_FIDO_VIRTUAL_KEY_TAP_ARM;
  cfg->arm_sec = parse_unsigned_env("PCSC_FIDO_ARM_SEC", PCSC_FIDO_ARM_SEC_DEFAULT);
  if (cfg->arm_sec == 0u) {
    pcsc_fido_log(PCSC_FIDO_LOG_ERROR, "PCSC_FIDO_ARM_SEC must be greater than zero");
    return false;
  }
  mode = getenv("PCSC_FIDO_VIRTUAL_KEY");
  if (mode == nullptr || mode[0] == '\0' || strcmp(mode, "tap-arm") == 0) {
    cfg->virtual_key_mode = PCSC_FIDO_VIRTUAL_KEY_TAP_ARM;
    return true;
  }
  if (strcmp(mode, "always") == 0) {
    cfg->virtual_key_mode = PCSC_FIDO_VIRTUAL_KEY_ALWAYS;
    return true;
  }
  pcsc_fido_log(PCSC_FIDO_LOG_ERROR, "invalid PCSC_FIDO_VIRTUAL_KEY=%s; expected tap-arm or always",
                mode);
  return false;
}

void pcsc_fido_print_browser_config(FILE *out, const pcsc_fido_browser_config_t *cfg) {
  if (out == nullptr || cfg == nullptr) {
    return;
  }
  fprintf(out, "PCSC_FIDO_VIRTUAL_KEY=%s\n",
          pcsc_fido_virtual_key_mode_name(cfg->virtual_key_mode));
  fprintf(out, "PCSC_FIDO_ARM_SEC=%u\n", cfg->arm_sec);
}
