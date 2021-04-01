/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * init.c
 *
 *  Created on: 18-Feb-2020
 *      Author: Arvind Rawat
 */

#include "common.h"
#include "logging.h"

char server_address[2048];
char server_port[6];
char client_certificate[PATH_MAX];
char client_key[PATH_MAX];
char ca_certificate[PATH_MAX];
FILE *log_fp;

int kmipw_init(const char *address, const char *port, const char *certificate, const char *key, const char *ca) {
    int result = RESULT_FAILED;
    log_fp = configure_logger();
    if (log_fp == NULL) {
          printf("Failed to configure logger\n");
          return RESULT_FAILED;
    }
    log_info("kmipw_init called");

    if (address == NULL) {
        log_error("KMIP server address is not provided.");
        goto final;
    }

    if (port == NULL) {
        log_error("KMIP server port is not provided.");
        goto final;
    }

    if (certificate == NULL) {
        log_error("KMIP client certificate is not provided.");
        goto final;
    }

    if (key == NULL) {
        log_error("KMIP client key is not provided.");
        goto final;
    }

    if (ca == NULL) {
        log_error("KMIP root certificate is not provided.");
        goto final;
    }

    strncpy(server_address, address, strnlen(address, sizeof(server_address)-1));
    strncpy(server_port, port, strnlen(port, sizeof(server_port)-1));
    strncpy(client_certificate, certificate, strnlen(certificate, sizeof(client_certificate)-1));
    strncpy(client_key, key, strnlen(key, sizeof(client_key)-1));
    strncpy(ca_certificate, ca, strnlen(ca, sizeof(ca_certificate)-1));
    result = RESULT_SUCCESS;

final:
    fclose(log_fp);
    return result;
}
