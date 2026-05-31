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

#include "pcsc_fido/browser_daemon.h"
#include "pcsc_fido/daemon_config.h"
#include "pcsc_fido/daemon_signals.h"
#include "pcsc_fido/daemon_uhid_loop.h"
#include "pcsc_fido/pcsc_bridge.h"
#include "pcsc_fido/pcsc_bridge_limits.h"
#include "pcsc_fido/pcsc_log.h"
#include "pcsc_fido/tap_arm.h"
#include "pcsc_fido/version.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

static void print_usage(FILE *out) {
  if (out == nullptr) {
    return;
  }
  fprintf(out, "Usage: pcsc-fido [--list-readers|--print-config|--version|--help]\n"
               "\n"
               "Without arguments, start the virtual HID FIDO bridge daemon.\n"
               "  --list-readers   list PC/SC readers visible to pcscd\n"
               "  --print-config   print resolved daemon configuration from the environment\n"
               "  --version        print the package version\n"
               "  --help           show this help\n"
               "\n"
               "Exit status: 0 success, 1 runtime error, 2 usage error.\n");
}

static int handle_cli(int argc, char **argv) {
  char err[PCSC_FIDO_ERR_MSG_MAX];
  pcsc_fido_browser_config_t cfg;
  if (argc <= 1) {
    return -1;
  }
  if (argv == nullptr) {
    print_usage(stderr);
    return 2;
  }
  memset(err, 0, sizeof(err));
  if (argc == 2 && strcmp(argv[1], "--help") == 0) {
    print_usage(stdout);
    return 0;
  }
  if (argc == 2 && strcmp(argv[1], "--version") == 0) {
    fprintf(stdout, "pcsc-fido %s\n", PCSC_FIDO_VERSION);
    return 0;
  }
  if (argc == 2 && strcmp(argv[1], "--print-config") == 0) {
    if (!pcsc_fido_load_browser_config(&cfg)) {
      return 1;
    }
    pcsc_fido_print_browser_config(stdout, &cfg);
    return 0;
  }
  if (argc == 2 && strcmp(argv[1], "--list-readers") == 0) {
    if (!pcsc_fido_bridge_list_readers(stdout, err, sizeof(err))) {
      pcsc_fido_log(PCSC_FIDO_LOG_ERROR, "%s", err[0] != '\0' ? err : "failed to list readers");
      return 1;
    }
    return 0;
  }
  print_usage(stderr);
  return 2;
}

static int run_daemon(int uhid_fd) {
  pcsc_fido_browser_config_t cfg;
  int status;
  if (uhid_fd < 0) {
    pcsc_fido_log(PCSC_FIDO_LOG_ERROR, "invalid UHID file descriptor");
    return 1;
  }
  if (!pcsc_fido_daemon_signals_init()) {
    perror("pcsc-fido signal setup");
    return 1;
  }
  if (!pcsc_fido_load_browser_config(&cfg)) {
    pcsc_fido_daemon_signals_shutdown();
    return 1;
  }
  if (cfg.virtual_key_mode == PCSC_FIDO_VIRTUAL_KEY_ALWAYS) {
    status = pcsc_fido_daemon_run_always_mode(uhid_fd);
  } else {
    status = pcsc_fido_tap_arm_run(uhid_fd, &cfg);
  }
  pcsc_fido_daemon_signals_shutdown();
  return status;
}

#if defined(PCSC_FIDO_TESTING)
int pcsc_fido_browser_daemon_main_with_fd(int argc, char **argv, int uhid_fd) {
#else
static int browser_daemon_main_with_fd(int argc, char **argv, int uhid_fd) {
#endif
  int cli_status = handle_cli(argc, argv);
  if (cli_status >= 0) {
    return cli_status;
  }
  return run_daemon(uhid_fd);
}

int pcsc_fido_browser_daemon_main(int argc, char **argv) {
  int cli_status = handle_cli(argc, argv);
  int fd;
  int status;
  if (cli_status >= 0) {
    return cli_status;
  }
  fd = open("/dev/uhid", O_RDWR | O_CLOEXEC);
  if (fd < 0) {
    perror("open /dev/uhid");
    return 1;
  }
#if defined(PCSC_FIDO_TESTING)
  status = pcsc_fido_browser_daemon_main_with_fd(argc, argv, fd);
#else
  status = browser_daemon_main_with_fd(argc, argv, fd);
#endif
  close(fd);
  return status;
}

#ifndef PCSC_FIDO_TESTING
int main(int argc, char **argv) {
  return pcsc_fido_browser_daemon_main(argc, argv);
}
#endif
