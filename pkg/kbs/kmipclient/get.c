/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * get.c
 *
 *  Created on: 18-Feb-2020
 *      Author: Arvind Rawat
 */

#include <kmip/kmip_memset.h>
#include <string.h>

#include "common.h"
#include "util.h"
#include "logging.h"

extern FILE *log_fp;

/*
* get:
*
* @id: unique identifier of the object to be retrieved
*
* @kbs_key: buffer which will contain the output key
*/
int kmipw_get(char *id, char *kbs_key, char *algorithm, int kmip_version)
{
    log_fp = configure_logger();
    if (log_fp == NULL)
    {
        printf("Failed to configure logger\n");
        return RESULT_FAILED;
    }
    log_info("kmipw_get called");
    log_debug("get key for id: %s", id);

    SSL_CTX *ctx = NULL;
    BIO *bio = NULL;
    bio = initialize_tls_connection(ctx);
    if (bio == NULL)
    {
        log_error("BIO_new_ssl_connect failed");
        ERR_print_errors_fp(log_fp);
        fclose(log_fp);
        return RESULT_FAILED;
    }
    /* Set up the KMIP context. */
    KMIP kmip_ctx = {0};

    kmip_init(&kmip_ctx, NULL, 0, kmip_version);

    char *key = NULL;
    int key_size = 0;
    size_t id_size = kmip_strnlen_s(id, ID_MAX_LENGTH);

    /* Send the request message. */
    int result = kmip_bio_get_key_with_context(&kmip_ctx, bio, id, id_size, &key, &key_size, algorithm);

    free_tls_connection(bio, ctx);

    /* Handle the response results. */
    if (result < RESULT_SUCCESS)
    {
        log_error("An error occurred while retrieving the  key.");
        log_error("Error Code: %d", result);
        kmip_print_error_string(log_fp, result);
        log_error("Context Error: %s", kmip_ctx.error_message);
        log_error("Stack trace:");
        kmip_print_stack_trace(log_fp, &kmip_ctx);
    }
    else if (result >= RESULT_SUCCESS)
    {
        log_info("The KMIP operation was executed with no errors.");
        log_info("Result: ");
        kmip_print_result_status_enum(log_fp, result);

        if (result == KMIP_STATUS_SUCCESS)
        {
            log_debug(" Key ID: %s", id);
            log_debug(" Key Size: %d bits", key_size * 8);
            log_debug(" Key: ");
            kmip_print_buffer(log_fp, key, key_size);
        }
    }

    kmip_memset(kbs_key, 0, key_size);
    kmip_memcpy(NULL, kbs_key, key, key_size);

    if (key != NULL)
    {
        kmip_memset(key, 0, key_size);
        kmip_free(NULL, key);
    }

    /* Clean up the KMIP context and return the results. */
    fclose(log_fp);
    kmip_destroy(&kmip_ctx);
    return result;
}

/*
 This method will constuct the request message and decode the response to get symmetric and asymmetric keys.
 Note : This method is added to override the method kmip_bio_get_symmetric_key_with_context 
 to include changes for retrieving asymmetric key
*/
int kmip_bio_get_key_with_context(KMIP *ctx, BIO *bio,
                                  char *uuid, int uuid_size,
                                  char **key, int *key_size, char *algorithm)
{
    log_info("kmip_bio_get_key_with_context called");

    if (ctx == NULL || bio == NULL || uuid == NULL || uuid_size <= 0 || key == NULL || key_size == NULL || algorithm == NULL)
    {
        return (KMIP_ARG_INVALID);
    }

    /* Set up the initial encoding buffer. */
    size_t buffer_blocks = 1;
    size_t buffer_block_size = 1024;
    size_t buffer_total_size = buffer_blocks * buffer_block_size;

    uint8 *encoding = ctx->calloc_func(
        ctx->state,
        buffer_blocks,
        buffer_block_size);
    if (encoding == NULL)
    {
        return (KMIP_MEMORY_ALLOC_FAILED);
    }
    kmip_set_buffer(ctx, encoding, buffer_total_size);

    /* Build the request message. */
    ProtocolVersion pv = {0};
    kmip_init_protocol_version(&pv, ctx->version);

    RequestHeader rh = {0};
    kmip_init_request_header(&rh);

    rh.protocol_version = &pv;
    rh.maximum_response_size = ctx->max_message_size;
    rh.time_stamp = time(NULL);
    rh.batch_count = 1;

    TextString id = {0};
    id.value = uuid;
    id.size = uuid_size;

    GetRequestPayload grp = {0};
    grp.unique_identifier = &id;

    RequestBatchItem rbi = {0};
    kmip_init_request_batch_item(&rbi);
    rbi.operation = KMIP_OP_GET;
    rbi.request_payload = &grp;

    RequestMessage rm = {0};
    rm.request_header = &rh;
    rm.batch_items = &rbi;
    rm.batch_count = 1;

    /* Add the context credential to the request message if it exists. */
    /* TODO (ph) Update this to add multiple credentials. */
    Authentication auth = {0};
    if (ctx->credential_list != NULL)
    {
        LinkedListItem *item = ctx->credential_list->head;
        if (item != NULL)
        {
            auth.credential = (Credential *)item->data;
            rh.authentication = &auth;
        }
    }

    /* Encode the request message. Dynamically resize the encoding buffer */
    /* if it's not big enough. Once encoding succeeds, send the request   */
    /* message.                                                           */
    int encode_result = kmip_encode_request_message(ctx, &rm);
    while (encode_result == KMIP_ERROR_BUFFER_FULL)
    {
        kmip_reset(ctx);
        ctx->free_func(ctx->state, encoding);

        buffer_blocks += 1;
        buffer_total_size = buffer_blocks * buffer_block_size;

        encoding = ctx->calloc_func(
            ctx->state,
            buffer_blocks,
            buffer_block_size);
        if (encoding == NULL)
        {
            return (KMIP_MEMORY_ALLOC_FAILED);
        }

        kmip_set_buffer(
            ctx,
            encoding,
            buffer_total_size);
        encode_result = kmip_encode_request_message(ctx, &rm);
    }

    if (encode_result != KMIP_OK)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        return (encode_result);
    }

    int sent = BIO_write(bio, ctx->buffer, ctx->index - ctx->buffer);
    if (sent != ctx->index - ctx->buffer)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        return (KMIP_IO_FAILURE);
    }

    kmip_free_buffer(ctx, encoding, buffer_total_size);
    encoding = NULL;

    /* Read the response message. Dynamically resize the encoding buffer  */
    /* to align with the message size advertised by the message encoding. */
    /* Reject the message if the message size is too large.               */
    buffer_blocks = 1;
    buffer_block_size = 8;
    buffer_total_size = buffer_blocks * buffer_block_size;

    encoding = ctx->calloc_func(ctx->state, buffer_blocks, buffer_block_size);
    if (encoding == NULL)
    {
        return (KMIP_MEMORY_ALLOC_FAILED);
    }

    int recv = BIO_read(bio, encoding, buffer_total_size);
    if ((size_t)recv != buffer_total_size)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        return (KMIP_IO_FAILURE);
    }

    kmip_set_buffer(ctx, encoding, buffer_total_size);
    ctx->index += 4;
    int length = 0;

    kmip_decode_int32_be(ctx, &length);
    kmip_rewind(ctx);

    if (length > ctx->max_message_size)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        return (KMIP_EXCEED_MAX_MESSAGE_SIZE);
    }

    kmip_set_buffer(ctx, NULL, 0);
    uint8 *extended = ctx->realloc_func(
        ctx->state,
        encoding,
        buffer_total_size + length);

    if (encoding != extended)
    {
        encoding = extended;
    }
    ctx->memset_func(encoding + buffer_total_size, 0, length);

    buffer_block_size += length;
    buffer_total_size = buffer_blocks * buffer_block_size;

    // Call BIO_Read till all the data is recieved and rescontruct the output buffer
    uint8 *output = ctx->calloc_func(
        ctx->state,
        *encoding,
        buffer_total_size + length);
    int total_recv = 0;
    while (total_recv != length)
    {
        recv = BIO_read(bio, encoding + 8, length);

        for (int i = 0; i < recv; i++)
        {
            output[i + total_recv] = encoding[i];
        }
        total_recv = total_recv + recv;
    }

    kmip_set_buffer(ctx, output, buffer_block_size);

    /* Decode the response message and retrieve the operation result status. */
    ResponseMessage resp_m = {0};
    int decode_result = kmip_decode_response_message(ctx, &resp_m);
    if (decode_result != KMIP_OK)
    {
        kmip_free_response_message(ctx, &resp_m);
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        return (decode_result);
    }

    kmip_free_buffer(ctx, encoding, buffer_total_size);
    encoding = NULL;

    if (resp_m.batch_count != 1 || resp_m.batch_items == NULL)
    {
        kmip_free_response_message(ctx, &resp_m);
        kmip_set_buffer(ctx, NULL, 0);
        return (KMIP_MALFORMED_RESPONSE);
    }

    ResponseBatchItem resp_item = resp_m.batch_items[0];
    enum result_status result = resp_item.result_status;

    if (result != KMIP_STATUS_SUCCESS)
    {
        kmip_free_response_message(ctx, &resp_m);
        kmip_set_buffer(ctx, NULL, 0);
        return (result);
    }

    GetResponsePayload *pld = (GetResponsePayload *)resp_item.response_payload;

    KeyBlock *block;

    if ((strcmp(algorithm, "AES") == 0) || (strcmp(algorithm, "aes") == 0))
    {
        if (pld->object_type == KMIP_OBJTYPE_SYMMETRIC_KEY)
        {
            SymmetricKey *symmetric_key = (SymmetricKey *)pld->object;
            block = symmetric_key->key_block;
            if ((block->key_format_type != KMIP_KEYFORMAT_RAW) || (block->key_wrapping_data != NULL))
            {
                kmip_free_response_message(ctx, &resp_m);
                kmip_set_buffer(ctx, NULL, 0);
                return (KMIP_OBJECT_MISMATCH);
            }
        }
        else
        {
            kmip_free_response_message(ctx, &resp_m);
            kmip_set_buffer(ctx, NULL, 0);
            return (KMIP_OBJECT_MISMATCH);
        }
    }
    else if (pld->object_type == KMIP_OBJTYPE_PUBLIC_KEY)
    {
        PublicKey *pubkey = (PublicKey *)pld->object;
        block = pubkey->key_block;

        if (((block->key_format_type != KMIP_KEYFORMAT_PKCS1) && (block->key_format_type != KMIP_KEYFORMAT_PKCS8)) || (block->key_wrapping_data != NULL))
        {
            kmip_free_response_message(ctx, &resp_m);
            kmip_set_buffer(ctx, NULL, 0);
            return (KMIP_OBJECT_MISMATCH);
        }
    }
    else if (pld->object_type == KMIP_OBJTYPE_PRIVATE_KEY)
    {
        PrivateKey *privatekey = (PrivateKey *)pld->object;
        block = privatekey->key_block;

        if ((block->key_format_type != KMIP_KEYFORMAT_PKCS8) || (block->key_wrapping_data != NULL))
        {
            kmip_free_response_message(ctx, &resp_m);
            kmip_set_buffer(ctx, NULL, 0);
            return (KMIP_OBJECT_MISMATCH);
        }
    }
    else
    {
        kmip_free_response_message(ctx, &resp_m);
        kmip_set_buffer(ctx, NULL, 0);
        return (KMIP_OBJECT_MISMATCH);
    }

    KeyValue *block_value = block->key_value;
    ByteString *material = (ByteString *)block_value->key_material;

    char *result_key = ctx->calloc_func(ctx->state, 1, material->size);
    *key_size = material->size;
    for (int i = 0; i < *key_size; i++)
    {
        result_key[i] = material->value[i];
    }
    *key = result_key;

    /* Clean up the response message, the encoding buffer, and the KMIP */
    /* context. */
    kmip_free_response_message(ctx, &resp_m);
    kmip_free_buffer(ctx, encoding, buffer_total_size);
    encoding = NULL;
    kmip_set_buffer(ctx, NULL, 0);

    return (result);
}