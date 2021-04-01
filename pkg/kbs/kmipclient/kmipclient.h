/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * kmipclient.h
 *
 *  Created on: 18-Feb-2020
 *      Author: Arvind Rawat
 */

#ifndef KMIPCLIENT_H_
#define KMIPCLIENT_H_

#include <stdio.h>
#include <kmip/kmip.h>
#include <kmip/kmip_bio.h>

int kmipw_init(const char *address, const char *port, const char *certificate, const char *key, const char *ca);
const char* kmipw_create(int alg_id, int alg_length,int kmip_version);
int kmipw_destroy(const char *id,int kmip_version);
int kmipw_get(const char *id, char *kbs_key,char *algorithm,int kmip_version);
int kmip_bio_get_key_with_context(KMIP *ctx, BIO *bio,char *uuid ,int uuid_size,char **key, int *key_size, char *algorithm);

#endif /* KMIPCLIENT_H_ */
